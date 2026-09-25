"""Exercise the policy against installed boltd and upstream's UMockdev fixture.

BOLT_TEST_SOURCE points to bolt's source checkout (tested with 0.9.11).
Run under umockdev-wrapper with python-dbusmock, python-gobject, and umockdev.
All D-Bus traffic, sysfs devices, Bolt state, and Omarchy policy are disposable.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import time
import unittest

root = Path(sys.argv.pop(1))
loader = importlib.machinery.SourceFileLoader('bolt_upstream', str(Path(os.environ['BOLT_TEST_SOURCE']) / 'tests/test-integration'))
spec = importlib.util.spec_from_loader(loader.name, loader)
u = importlib.util.module_from_spec(spec)
loader.exec_module(u)
spec = importlib.util.spec_from_file_location('omarchy_bolt', root / 'install/helpers/thunderbolt-authorization.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location('omarchy_setup', root / 'install/helpers/thunderbolt-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class ApprovalIntegration(u.BoltTest):
  def exercise(self, security):
    self.user_config(AuthMode='disabled', DefaultPolicy='manual')
    _, host = self.add_domain_host(security=security, iommu='1')
    path, uid = self.add_device(host, 1, 'Dock', 'Example', authorized=0, key='' if security == 'secure' else None, boot='0')
    _, other_uid = self.add_device(host, 2, 'Unknown', 'Example', authorized=0, key=None, boot='0')
    self.daemon_start()
    self.polkitd_start()
    self.polkitd.SetAllowed(['org.freedesktop.bolt.authorize', 'org.freedesktop.bolt.enroll', 'org.freedesktop.bolt.manage'])
    state = Path(self.rundir) / 'policy.json'
    m.atomic_json(state, {'version': 1, 'enabled': True, 'trusted': {}})
    policy = m.Policy(m.Bolt(m.Bus(self.dbus)), state)
    devices = policy.snapshot()['devices']
    self.assertTrue(all(d['status'] == 'connected' and not d['stored'] for d in devices))
    identity = next(d['identity'] for d in devices if d['identity']['Uid'] == uid)
    policy.approve(identity, True)
    self.assertEqual(self.client.auth_mode, 'disabled')
    devices = policy.snapshot()['devices']
    approved = next(d for d in devices if d['identity']['Uid'] == uid)
    self.assertTrue(approved['trusted'])
    self.assertEqual(approved['status'], 'authorized')
    self.assertEqual(approved['policy'], 'manual')
    self.assertEqual(next(d['status'] for d in devices if d['identity']['Uid'] == other_uid), 'connected')
    self.assertFalse(any(policy.snapshot()['domains'][0]['BootACL']))

    # Test the actual Bolt firmware-ACL API with a populated simulated allowlist.
    owner, _, domains, connected = policy.bolt.inventory()
    stored = policy.bolt.stored_devices(owner)
    target = next(d for d in stored if d['Uid'] == uid)
    policy.bolt.bus.set(owner, target['path'], m.DEVICE, 'Policy', 'auto')
    original_acl = [uid] + [''] * (len(domains[0]['BootACL']) - 1)
    policy.bolt.bus.set(owner, domains[0]['path'], m.DOMAIN, 'BootACL', original_acl, 'as')
    setup.boot_policy(True, policy.bolt, state)
    self.assertTrue(m.load_policy(state)['boot_protection'])
    self.assertFalse(any(policy.bolt.inventory()[2][0]['BootACL']))
    self.assertEqual(policy.bolt.stored_devices(owner)[0]['Policy'], 'manual')
    setup.boot_policy(False, policy.bolt, state)
    self.assertEqual(policy.bolt.inventory()[2][0]['BootACL'], original_acl)
    self.assertEqual(policy.bolt.stored_devices(owner)[0]['Policy'], 'auto')
    self.assertFalse(m.load_policy(state)['boot_protection'])

    # Restore the exact consent used for the independent restart check below.
    state_data = m.load_policy(state)
    state_data['trusted'].pop(other_uid)
    m.atomic_json(state, state_data)
    policy.bolt.bus.set(owner, target['path'], m.DEVICE, 'Policy', 'manual')
    policy.bolt.bus.set(owner, domains[0]['path'], m.DOMAIN, 'BootACL', [''] * len(original_acl), 'as')


    # A daemon restart must not interpret its iommu policy as permission, or
    # make an old dialog's connection generation valid again.
    self.daemon_stop()
    self.testbed.set_attribute(path, 'authorized', '0')
    self.daemon_start()
    policy = m.Policy(m.Bolt(m.Bus(self.dbus)), state)
    with self.assertRaises(RuntimeError):
      policy.approve(identity, True)
    policy.reconcile()
    devices = policy.snapshot()['devices']
    self.assertEqual(next(d['status'] for d in devices if d['identity']['Uid'] == uid), 'authorized')
    self.assertEqual(next(d['status'] for d in devices if d['identity']['Uid'] == other_uid), 'connected')
    self.assertEqual(self.client.auth_mode, 'disabled')
    self.daemon_stop()

  def test_service_permissions_and_real_approval(self):
    self.user_config(AuthMode='disabled')
    _, host = self.add_domain_host(security='user', iommu='1')
    _, uid = self.add_device(host, 1, 'Dock', 'Example', authorized=0, key=None, boot='0')
    self.daemon_start()
    self.polkitd_start()
    self.polkitd.SetAllowed(['org.freedesktop.bolt.authorize', 'org.freedesktop.bolt.enroll'])
    state = Path(self.rundir) / 'policy.json'
    m.atomic_json(state, {'version': 1, 'enabled': True, 'trusted': {}})
    code = "import importlib.util,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('tb',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.serve(m.Policy(path=Path(sys.argv[2])))"
    env = os.environ.copy()
    env['UMOCKDEV_DIR'] = self.testbed.get_root_dir()
    with open(Path(self.rundir) / 'omarchy-service.log', 'w') as log:
      child = subprocess.Popen(['/usr/bin/python3', '-c', code, str(root / 'install/helpers/thunderbolt-authorization.py'), str(state)], env=env, stdout=log, stderr=log)
      try:
        bus = m.Bus(self.dbus)
        for _ in range(50):
          try:
            owner = bus.owner(m.SERVICE)
            break
          except Exception:
            time.sleep(0.1)
        else:
          self.fail('Omarchy service did not start')
        snapshot = json.loads(bus.call(owner,m.SERVICE_PATH,m.SERVICE,'Snapshot')[0])
        identity = snapshot['devices'][0]['identity']
        with self.assertRaises(u.GLib.GError):
          bus.call(owner,m.SERVICE_PATH,m.SERVICE,'Approve','(sb)',(json.dumps(identity),True))
        self.assertEqual(m.Bolt(bus).inventory()[3][0]['Status'],'connected')
        self.polkitd.SetAllowed(['org.freedesktop.bolt.authorize','org.freedesktop.bolt.enroll','org.omarchy.thunderbolt.approve'])
        result = json.loads(bus.call(owner,m.SERVICE_PATH,m.SERVICE,'Approve','(sb)',(json.dumps(identity),True))[0])
        self.assertTrue(result['devices'][0]['trusted'])
        self.assertEqual(result['devices'][0]['status'],'authorized')
        self.assertEqual(self.client.auth_mode,'disabled')
      finally:
        child.terminate()
        child.wait(timeout=5)

  def test_user_approval(self):
    self.exercise('user')

  def test_secure_approval(self):
    self.exercise('secure')


# Run only these cases; the inherited upstream suite is its own project.
suite = unittest.TestSuite(ApprovalIntegration(name) for name in ('test_user_approval', 'test_secure_approval', 'test_service_permissions_and_real_approval'))
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
