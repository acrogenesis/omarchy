import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(sys.argv.pop(1))


def load(name, file):
  spec = importlib.util.spec_from_file_location(name, ROOT / 'install/helpers' / file)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


m = load('tb_policy', 'thunderbolt-authorization.py')
setup = load('tb_setup', 'thunderbolt-setup.py')
review = load('tb_review', 'thunderbolt-review.py')


class Bolt:
  def __init__(self):
    self.owner = ':1.5'
    self.mode = 'disabled'
    self.device = {'Uid': 'device-1', 'Name': 'Dock', 'Vendor': 'Vendor',
                   'Parent': 'host', 'SysfsPath': '/sys/devices/test/0-1',
                   'ConnectTime': 1, 'Status': 'connected', 'Stored': False,
                   'Policy': 'default', 'AuthFlags': '', 'path': '/devices/1', 'inode': 1}
    self.domains = [{'Uid': 'host', 'SecurityLevel': 'user', 'IOMMU': True, 'BootACL': []}]
    self.operations = []
    self.authorize_effect = True
    self.enroll_effect = True
    self.fail_next_read = False

  def inventory(self):
    if self.fail_next_read:
      self.fail_next_read = False
      raise RuntimeError('inventory unavailable')
    return self.owner, {'AuthMode': self.mode}, copy.deepcopy(self.domains), [copy.deepcopy(self.device)]

  def authorize(self, owner, device):
    self.operations.append('authorize')
    assert self.mode == 'disabled'
    if self.authorize_effect:
      self.device['Status'] = 'authorized'

  def enroll(self, owner, device):
    self.operations.append('enroll')
    assert self.mode == 'disabled'
    if self.enroll_effect:
      self.device.update(Stored=True, Policy='manual')


class PolicyTest(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.path = Path(self.tmp.name) / 'policy.json'
    m.atomic_json(self.path, {'version': 1, 'enabled': True, 'trusted': {}})
    self.bolt = Bolt()
    self.policy = m.Policy(self.bolt, self.path)
    self.identity = self.policy.snapshot()['devices'][0]['identity']

  def test_iommu_is_not_consent(self):
    self.bolt.device.update(Stored=True, Policy='iommu')
    self.policy.reconcile()
    self.assertEqual(self.bolt.operations, [])
    self.assertFalse(self.policy.snapshot()['devices'][0]['trusted'])

  def test_once_is_not_saved(self):
    self.policy.approve(self.identity, False)
    self.assertEqual(self.policy.snapshot()['warnings'], [])
    self.assertEqual(m.load_policy(self.path)['trusted'], {})
    self.bolt.device['Status'] = 'connected'
    self.policy.reconcile()
    self.assertEqual(self.bolt.operations, ['authorize'])

  def test_always_survives_policy_and_bolt_restart(self):
    self.policy.approve(self.identity, True)
    self.bolt.owner = ':1.9'
    self.bolt.device.update(Status='connected', inode=2)
    self.policy = m.Policy(self.bolt, self.path)
    self.policy.reconcile()
    self.assertEqual(self.bolt.device['Status'], 'authorized')
    self.assertEqual(self.bolt.mode, 'disabled')

  def test_changed_identity_and_daemon_rejected(self):
    for field, value in [('inode', 2), ('Name', 'Replacement'), ('ConnectTime', 2)]:
      original = self.bolt.device[field]
      self.bolt.device[field] = value
      with self.assertRaises(RuntimeError):
        self.policy.approve(self.identity, True)
      self.bolt.device[field] = original
    self.bolt.owner = ':1.6'
    with self.assertRaises(RuntimeError):
      self.policy.approve(self.identity, True)
    self.assertEqual(self.bolt.operations, [])

  def test_false_success_keeps_device_untrusted(self):
    self.bolt.authorize_effect = False
    with self.assertRaises(RuntimeError):
      self.policy.approve(self.identity, True)
    self.assertEqual(m.load_policy(self.path)['trusted'], {})
    self.bolt.authorize_effect = True
    self.bolt.enroll_effect = False
    with self.assertRaises(RuntimeError):
      self.policy.approve(self.identity, True)
    self.assertEqual(m.load_policy(self.path)['trusted'], {})
    self.bolt.enroll_effect = True
    self.policy.approve(self.identity, True)
    self.assertTrue(self.policy.trusted(self.bolt.device))
    self.assertEqual(self.bolt.operations.count('authorize'), 2)

  def test_write_failure_does_not_claim_permanent_trust(self):
    with patch.object(self.policy, 'save', side_effect=OSError('disk full')):
      with self.assertRaises(OSError):
        self.policy.approve(self.identity, True)
    self.assertFalse(self.policy.trusted(self.bolt.device))
    self.policy.approve(self.identity, True)
    self.assertTrue(self.policy.trusted(self.bolt.device))
    self.assertEqual(self.bolt.operations.count('authorize'), 1)

  def test_firmware_bypass_reported_without_detaching_storage(self):
    self.bolt.domains[0]['SecurityLevel'] = 'none'
    self.bolt.device['Status'] = 'authorized'
    self.bolt.device['AuthFlags'] = 'boot'
    self.assertEqual(len(self.policy.snapshot()['warnings']), 2)
    self.assertEqual(self.bolt.operations, [])

  def test_unexpected_global_enable_is_not_reported_protected(self):
    self.bolt.mode = 'enabled'
    with self.assertRaises(RuntimeError):
      self.policy.snapshot()
    self.policy.reconcile()
    self.assertIn('not active', self.policy.error)

  def test_display_only_device_needs_no_pcie_approval(self):
    self.policy.state['trusted']['device-1'] = m.trust_identity(self.bolt.device)
    self.bolt.device['AuthFlags'] = 'nopcie'
    self.policy.reconcile()
    self.assertEqual(self.bolt.operations, [])
    self.assertEqual(self.policy.error, '')


class SetupTest(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    root = Path(self.tmp.name)
    self.state = root / 'policy.json'
    self.config = root / 'boltd.conf'
    self.marker = root / 'enabled'
    for target, attr, value in [(setup.policy, 'POLICY_PATH', self.state),
                                 (setup.policy, 'BOLT_CONFIG', self.config),
                                 (setup, 'MARKER', self.marker)]:
      handle = patch.object(target, attr, value)
      handle.start(); self.addCleanup(handle.stop)
    # Default arguments are bound at function definition time.
    original = setup.policy.load_policy
    handle = patch.object(setup.policy, 'load_policy', lambda: original(self.state))
    handle.start(); self.addCleanup(handle.stop)

  def test_empty_capture_is_initialized_and_reenable_preserves_it(self):
    with patch.object(setup, 'capture', return_value={}):
      setup.prepare()
    with patch.object(setup, 'capture', side_effect=AssertionError('must not capture again')):
      setup.prepare()
    self.assertEqual(json.loads(self.state.read_text())['trusted'], {})
    self.assertIn('AuthMode = disabled', self.config.read_text())

  def test_enumeration_failure_does_not_enable_or_publish(self):
    with patch.object(setup, 'capture', side_effect=OSError('device disappeared')):
      with self.assertRaises(OSError):
        setup.prepare()
    self.assertFalse(self.state.exists())
    self.assertFalse(self.marker.exists())

  def test_config_preserves_unrelated_settings(self):
    self.config.write_text('[config]\nAuthMode=enabled\nDefaultPolicy=manual\n')
    with patch.object(setup, 'capture', return_value={}):
      setup.prepare()
    self.assertEqual(setup.config(self.config).get('config','DefaultPolicy'), 'manual')
    self.assertEqual(json.loads(self.state.read_text())['original_authmode'],'enabled')

  def test_fresh_owner_replaces_trust_without_losing_original_settings(self):
    with patch.object(setup, 'capture', return_value={'old': {}}):
      setup.prepare()
    with patch.object(setup, 'capture', return_value={'new': {}}):
      setup.prepare(fresh=True)
    state = json.loads(self.state.read_text())
    self.assertEqual(state['trusted'], {'new': {}})
    self.assertEqual(state['original_authmode'], 'enabled')

  def test_failed_enable_restores_files_and_service_state(self):
    self.config.write_text('[config]\nAuthMode=enabled\nDefaultPolicy=manual\n')
    original = self.config.read_bytes()
    calls = []
    failed = False
    def run(*args):
      nonlocal failed
      calls.append(args)
      if args == ('systemctl', 'start', 'bolt.service') and not failed:
        failed = True
        raise RuntimeError('startup failed')
    with patch.object(setup, 'run', side_effect=run), patch.object(setup, 'capture', return_value={}), \
         patch.object(setup, 'unit_state', side_effect=lambda name, setting: name == 'bolt.service' and setting == 'is-active'):
      with self.assertRaisesRegex(RuntimeError, 'startup failed'):
        setup.enable()
    self.assertEqual(self.config.read_bytes(), original)
    self.assertFalse(self.state.exists())
    self.assertFalse(self.marker.exists())
    self.assertFalse(self.state.with_name('setup-recovery.json').exists())
    self.assertEqual(calls[-2:], [('systemctl','start','bolt.service'),
                                 ('systemctl','stop','omarchy-thunderbolt-authorization.service')])

  def test_failed_restore_keeps_checkpoint_and_requires_recovery(self):
    self.config.write_text('[config]\nAuthMode=enabled\n')
    original = self.config.read_bytes()
    with patch.object(setup, 'run', side_effect=RuntimeError('systemd unavailable')), \
         patch.object(setup, 'unit_state', return_value=False):
      with self.assertRaisesRegex(RuntimeError, 'restoration is incomplete'):
        setup.enable()
      backup = self.state.with_name('setup-recovery.json')
      self.assertTrue(backup.exists())
      with self.assertRaisesRegex(RuntimeError, 'previous setup change needs recovery'):
        setup.enable()
    self.config.write_text('partial change')
    with patch.object(setup, 'run'):
      setup.restore_configuration(json.loads(backup.read_text()))
    self.assertEqual(self.config.read_bytes(), original)

  def test_failed_disable_restores_matching_strict_boot_state(self):
    bolt = BootBolt()
    with patch.object(setup, 'capture', return_value={}):
      setup.prepare()
    # Use the real boot transaction with the simulated firmware API.
    original_load = m.load_policy
    with patch.object(setup.policy, 'load_policy', side_effect=lambda path=None: original_load(path or self.state)):
      setup.boot_policy(True, bolt, self.state)
      previous = self.state.read_bytes()
      def run(*args):
        if args == ('systemctl','disable','omarchy-thunderbolt-authorization.service'):
          raise RuntimeError('disable failed')
      with patch.object(setup.policy,'Bolt',return_value=bolt), patch.object(setup,'run',side_effect=run), \
           patch.object(setup,'unit_state',return_value=True):
        with self.assertRaisesRegex(RuntimeError,'disable failed'):
          setup.disable()
    self.assertEqual(self.state.read_bytes(), previous)
    self.assertTrue(self.marker.exists())
    self.assertEqual(bolt.device['Policy'],'manual')
    self.assertEqual(bolt.domains[0]['BootACL'], ['', ''])
    self.assertFalse(self.state.with_name('setup-recovery.json').exists())


class BootBolt(Bolt):
  def __init__(self):
    super().__init__()
    self.domains[0].update(SysfsPath='/sys/domain', BootACL=['device-1', ''], path='/domain')
    self.device.update(Stored=True, Policy='auto')
    self.bus = self
    self.writes = []
    self.failure = None

  def stored_devices(self, owner):
    return [copy.deepcopy(self.device)]

  def properties(self, owner, path, interface):
    return copy.deepcopy(self.device if path == self.device['path'] else self.domains[0])

  def set(self, owner, path, interface, key, value, signature='s'):
    self.writes.append((key, copy.deepcopy(value)))
    if self.failure:
      self.failure(key, value)
    target = self.device if path == self.device['path'] else self.domains[0]
    target[key] = copy.deepcopy(value)


class BootTransactionTest(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.path = Path(self.tmp.name) / 'policy.json'
    self.state = {'version':1, 'enabled':True, 'trusted':{}}
    m.atomic_json(self.path, self.state)
    self.bolt = BootBolt()

  def test_boot_control_and_reconnection_keep_firmware_denying(self):
    setup.boot_policy(True, self.bolt, self.path)
    self.assertEqual(self.bolt.domains[0]['BootACL'], ['', ''])
    self.assertEqual(self.bolt.device['Policy'], 'manual')
    current = m.load_policy(self.path)
    self.assertTrue(current['boot_protection'])
    self.assertIn('device-1', current['trusted'])
    self.bolt.domains[0]['BootACL'] = ['device-1', '']
    self.bolt.device['Policy'] = 'auto'
    policy = m.Policy(self.bolt, self.path)
    self.assertTrue(policy.snapshot()['warnings'])
    policy.reconcile()
    self.assertEqual(policy.error, '')
    self.assertEqual(self.bolt.domains[0]['BootACL'], ['', ''])
    self.assertEqual(self.bolt.device['Policy'], 'manual')
    setup.boot_policy(False, self.bolt, self.path)
    self.assertEqual(self.bolt.domains[0]['BootACL'], ['device-1', ''])
    self.assertEqual(self.bolt.device['Policy'], 'auto')

  def test_failed_boot_change_restores_policy_and_firmware(self):
    def fail_clear(key, value):
      if key == 'BootACL' and not any(value):
        raise RuntimeError('firmware rejected clearing')
    self.bolt.failure = fail_clear
    with self.assertRaisesRegex(RuntimeError, 'firmware rejected clearing'):
      setup.boot_policy(True, self.bolt, self.path)
    self.assertEqual(m.load_policy(self.path), self.state)
    self.assertEqual(self.bolt.device['Policy'], 'auto')
    self.assertEqual(self.bolt.domains[0]['BootACL'], ['device-1', ''])
    self.assertFalse(self.path.with_name('boot-recovery.json').exists())

  def test_failed_boot_restore_retains_recoverable_original(self):
    self.bolt.failure = lambda *args: (_ for _ in ()).throw(RuntimeError('disconnected'))
    with self.assertRaisesRegex(RuntimeError, 'recovery is incomplete'):
      setup.boot_policy(True, self.bolt, self.path)
    backup = self.path.with_name('boot-recovery.json')
    self.assertTrue(backup.exists())
    self.bolt.failure = None
    with patch.object(setup.policy, 'POLICY_PATH', self.path), patch.object(setup.policy, 'Bolt', return_value=self.bolt):
      setup.recover_boot()
    self.assertFalse(backup.exists())
    self.assertEqual(m.load_policy(self.path), self.state)

  def test_offline_or_unsupported_controller_cannot_report_success(self):
    for field, value in [('SysfsPath',''), ('SecurityLevel','none'), ('BootACL',[])]:
      previous = self.bolt.domains[0][field]
      self.bolt.domains[0][field] = value
      with self.assertRaises(RuntimeError):
        setup.boot_policy(True, self.bolt, self.path)
      self.bolt.domains[0][field] = previous
    self.assertEqual(self.bolt.writes, [])


class ResetTest(unittest.TestCase):
  def test_install_defers_enforcement_until_an_owner_exists(self):
    script = '''
set -euo pipefail
install() { echo install-policy; }
function /usr/bin/python3() { printf 'helper %s\\n' "$2"; }
systemctl() { printf 'unit %s\\n' "$*"; }
OMARCHY_PATH="$1"
OMARCHY_INSTALL_USER="$2"
source "$1/install/config/thunderbolt-authorization.sh"
'''
    deferred = subprocess.run(['bash','-c',script,'test',str(ROOT),''],check=True,capture_output=True,text=True).stdout
    self.assertNotIn('helper ',deferred)
    self.assertNotIn('unit ',deferred)
    owned = subprocess.run(['bash','-c',script,'test',str(ROOT),'lab'],check=True,capture_output=True,text=True).stdout
    self.assertIn('helper prepare',owned)
    self.assertIn('unit enable omarchy-thunderbolt-authorization.service',owned)

  def test_offline_reset_removes_old_trust_keys_and_recovery(self):
    with tempfile.TemporaryDirectory() as name:
      root = Path(name)
      unit = root/'etc/systemd/system/omarchy-thunderbolt-authorization.service'
      unit.parent.mkdir(parents=True)
      unit.write_text((ROOT/'etc/systemd/system/omarchy-thunderbolt-authorization.service').read_text())
      subprocess.run(['systemctl', '--root='+name, 'enable', unit.name], check=True, capture_output=True)
      marker = root/setup.MARKER.relative_to('/')
      marker.parent.mkdir(parents=True)
      marker.touch()
      state = root/m.POLICY_PATH.relative_to('/')
      m.atomic_json(state, {'version':1, 'trusted':{'old':{}}, 'enabled':True})
      m.atomic_json(state.with_name('setup-recovery.json'), {'previous-owner':'secret'})
      for kind in ('devices','keys','domains'):
        path = root/'var/lib/boltd'/kind/'old-device'
        path.parent.mkdir(parents=True)
        path.write_text('old-owner')
      setup.reset_root(name)
      self.assertFalse(marker.exists())
      self.assertFalse(state.parent.exists())
      self.assertFalse((root/'etc/systemd/system/multi-user.target.wants'/unit.name).exists())
      self.assertEqual(list((root/'var/lib/boltd').iterdir()), [root/'var/lib/boltd/boltd.conf'])
      self.assertEqual(setup.config(root/'var/lib/boltd/boltd.conf').get('config','AuthMode'), 'enabled')

  def test_live_root_reset_refused(self):
    with self.assertRaises(ValueError):
      setup.reset_root('/')


class NotificationTest(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.env = patch.dict(os.environ, {'HOME': self.tmp.name})
    self.env.start(); self.addCleanup(self.env.stop)
    self.requests = review.requests_dir()
    self.device = {'identity': {'Uid': '1', 'Name': '$(touch /tmp/untrusted)\x1b[2J',
                                'Vendor': 'Test', 'owner': ':1.5', 'generation': 'a'},
                   'trusted': False, 'status': 'connected', 'stored': False,
                   'policy': 'default', 'flags': ''}
    self.snapshot = {'generation':'a','owner':':1.5','warnings':[], 'error':'',
                     'devices':[self.device]}
    self.calls = []
    self.handle = patch.object(review, 'call', side_effect=self.call)
    self.handle.start(); self.addCleanup(self.handle.stop)
    self.delivery = patch.object(review, 'notify', return_value=True)
    self.notify = self.delivery.start(); self.addCleanup(self.delivery.stop)

  def call(self, method, signature=None, values=()):
    self.calls.append((method, values))
    return copy.deepcopy(self.snapshot)

  def token(self):
    return next(self.requests.glob('request-*.json')).stem

  def test_trusted_reconnection_does_not_alert(self):
    self.device['trusted'] = True
    review.scan(self.requests, 'watch1')
    self.notify.assert_not_called()

  def test_unavailable_policy_warns_after_retries_without_spamming(self):
    with patch.object(review,'scan',side_effect=RuntimeError('policy unavailable')), \
         patch.object(review,'attention',return_value=True) as alert, \
         patch.object(review.time,'sleep',side_effect=[None,None,None,KeyboardInterrupt]):
      with self.assertRaises(KeyboardInterrupt):
        review.watch()
      alert.assert_called_once()

  def test_failed_delivery_retries_and_continues_other_devices(self):
    other = copy.deepcopy(self.device)
    other['identity']['Uid'] = '2'
    self.snapshot['devices'].append(other)
    self.notify.side_effect = [False, True, True]
    review.scan(self.requests, 'watch1')
    self.assertEqual(len(list(self.requests.glob('request-*.json'))),1)
    review.scan(self.requests, 'watch1')
    self.assertEqual(len(list(self.requests.glob('request-*.json'))),2)
    self.assertEqual(self.notify.call_count,3)

  def test_daemon_and_watcher_restarts_restore_requests(self):
    review.scan(self.requests, 'watch1')
    first = self.token()
    review.scan(self.requests, 'watch1')
    self.assertEqual(self.notify.call_count,1)
    self.device['identity']['owner'] = ':1.9'
    review.scan(self.requests, 'watch1')
    self.assertNotEqual(self.token(),first)
    review.scan(self.requests, 'watch2')
    self.assertEqual(self.notify.call_count,3)
    self.assertEqual(len(list(self.requests.glob('request-*.json'))),1)

  def test_transient_inventory_failure_preserves_pending_request(self):
    review.scan(self.requests, 'watch1')
    path = next(self.requests.glob('request-*.json'))
    with patch.object(review, 'call', side_effect=RuntimeError('unavailable')):
      with self.assertRaises(RuntimeError):
        review.scan(self.requests, 'watch1')
    self.assertTrue(path.exists())

  def test_replacement_during_dialog_cannot_inherit_approval(self):
    review.scan(self.requests, 'watch1')
    def choose(args, **kwargs):
      if args[1] == 'choose':
        self.device['identity']['Uid'] = 'replacement'
        return subprocess.CompletedProcess(args,0,'Always allow this device\n')
      return subprocess.CompletedProcess(args,0)
    with patch.object(review.subprocess, 'run', side_effect=choose):
      with self.assertRaises(RuntimeError):
        review.review(self.token())
    self.assertFalse(any(name == 'Approve' for name,_ in self.calls))

  def test_lost_reply_preserves_intent_for_retry_while_allowed(self):
    review.scan(self.requests, 'watch1')
    token = self.token()
    responses = [subprocess.CompletedProcess([],0), subprocess.CompletedProcess([],0,'Always allow this device\n')]
    def reply(method, signature=None, values=()):
      if method == 'Approve':
        self.device.update(status='authorized',trusted=True,stored=True,policy='manual')
        raise RuntimeError('reply lost')
      return copy.deepcopy(self.snapshot)
    with patch.object(review.subprocess, 'run', side_effect=responses), patch.object(review, 'call', side_effect=reply):
      with self.assertRaises(RuntimeError):
        review.review(token)
    path = self.requests / (token+'.json')
    self.assertEqual(review.read_request(path)['approval'],'Always allow this device')
    review.scan(self.requests,'watch1')
    self.assertTrue(path.exists())
    self.assertEqual(self.notify.call_count, 2)
    review.scan(self.requests,'watch2')
    self.assertFalse(path.exists())
    token = self.token()
    path = self.requests / (token+'.json')
    self.assertEqual(review.read_request(path)['approval'],'Always allow this device')
    self.assertEqual(self.notify.call_count, 3)
    with patch.object(review.subprocess,'run',side_effect=AssertionError('must resume saved approval')):
      review.review(token)
    self.assertFalse(path.exists())

  def test_disconnect_removes_request_and_descriptors_stay_data(self):
    review.scan(self.requests,'watch1')
    token = self.token()
    self.assertRegex(token,r'^request-[0-9a-f]{64}$')
    self.assertNotIn('\x1b',review.safe_text(self.device['identity']['Name']))
    self.snapshot['devices'] = []
    review.scan(self.requests,'watch1')
    self.assertFalse(list(self.requests.glob('request-*.json')))


unittest.main(verbosity=2)
