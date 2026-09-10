#!/bin/bash

set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/base-test.sh"

python3 - <<'PY'
import copy
import importlib.util
import os
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('migration', os.path.join(os.environ['ROOT'], 'default/podman/migrate-databases.py'))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

container = {
    'Name': '/redis', 'Id': 'a' * 64, 'State': {'Running': True},
    'Config': {'Image': 'redis:7', 'Healthcheck': {'Test': ['CMD', 'redis-cli', 'ping'], 'Interval': 5000000000, 'Timeout': 2000000000, 'Retries': 3}},
    'HostConfig': {
        'NetworkMode': 'default', 'IpcMode': 'private', 'ShmSize': 64 * 1024 * 1024,
        'PortBindings': {'6379/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '6379'}]},
        'RestartPolicy': {'Name': 'unless-stopped'},
    },
    'NetworkSettings': {'Networks': {'bridge': {}}},
    'Mounts': [{'Type': 'volume', 'Driver': 'local', 'Name': 'old-data', 'Destination': '/data', 'RW': True}],
}
assert migration.validate(container) == 'redis'
stopped = copy.deepcopy(container)
stopped['State']['Running'] = False
stopped['HostConfig']['NetworkMode'] = 'bridge'
stopped['HostConfig']['Mounts'] = []
assert migration.validate(stopped) == 'redis'
for field, value in [('Privileged', True), ('Binds', ['/etc:/data']), ('Memory', 1024), ('NetworkMode', 'host')]:
    changed = copy.deepcopy(container)
    changed['HostConfig'][field] = value
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f'custom {field} was silently discarded')
changed = copy.deepcopy(container)
changed['Config']['Image'] = 'unrelated/image:7'
try:
    migration.validate(changed)
except ValueError:
    pass
else:
    raise AssertionError('a familiar name hid a custom image')
print('ok - database preflight accepts stock settings and rejects custom privileges, resources, networking and images')

calls = []
migration.run = lambda *args, **kwargs: calls.append(args)
migration.subprocess.run = lambda args, **kwargs: SimpleNamespace(returncode=1)
migration.inspect = lambda engine, kind, name: {'State': {'Running': False, 'ExitCode': 0}} if kind == 'container' else {'Mountpoint': '/var/lib/docker/volumes/old-data/_data', 'Options': None}
migration.pipe = lambda producer, consumer: calls.append((tuple(producer), tuple(consumer)))

# Run the entire batch preflight with a valid database first. Neither check-only
# nor actual migration may stop that database before rejecting the second one.
custom_cases = []
for networks in ({'bridge': {}, 'project_net': {'Aliases': ['db']}}, {'project_net': {}}, {}):
    changed = copy.deepcopy(container)
    changed['NetworkSettings']['Networks'] = networks
    custom_cases.append(('network attachments', changed))
for size in (1024 * 1024 * 1024, 32 * 1024 * 1024, 0, None):
    changed = copy.deepcopy(container)
    changed['HostConfig']['ShmSize'] = size
    custom_cases.append(('ShmSize', changed))
changed = copy.deepcopy(container)
changed['HostConfig']['Mounts'] = [{
    'Type': 'volume', 'Source': 'postgres-data', 'Target': '/data',
    'VolumeOptions': {'Subpath': 'production'},
}]
custom_cases.append(('Mounts', changed))
inspect_volume = migration.inspect
for expected_error, changed in custom_cases:
    changed['Name'] = '/postgres18'
    changed['Config']['Image'] = 'postgres:18'
    changed['Id'] = 'b' * 64
    changed['Mounts'][0]['Name'] = 'postgres-data'
    records = {'redis': container, 'postgres18': changed}
    migration.inspect = lambda engine, kind, name: records[name] if kind == 'container' else inspect_volume(engine, kind, name)
    for options in ([], ['--check']):
        sys.argv = ['migrate-databases.py', *options, 'redis', 'postgres18']
        try:
            migration.main()
        except ValueError as error:
            assert expected_error in str(error), error
            assert 'postgres18' in str(error), error
        else:
            raise AssertionError(f'custom {expected_error} passed batch preflight')
        assert not calls, f'workloads changed before rejecting custom {expected_error}: {calls}'
migration.inspect = inspect_volume
print('ok - additional, replacement and disconnected networks fail preflight before any workload changes')
print('ok - nondefault shared-memory sizes fail preflight before any workload changes')
print('ok - volume subpaths fail preflight before any workload changes')

migration.migrate(container)
create = next(call for call in calls if call[:2] == ('podman', 'create'))
assert '127.0.0.1:6379:6379/tcp' in create
assert 'omarchy-migrated-old-data:/data:rw,nocopy' in create
assert '--pids-limit=-1' in create
assert create[create.index('--health-cmd') + 1] == '["CMD", "redis-cli", "ping"]'
assert create[create.index('--health-interval') + 1] == '5000000000ns'
assert ('sudo', 'docker', 'stop', '-t', '120', 'a' * 64) in calls
assert ('podman', 'start', 'redis') in calls
assert not any(call[:3] == ('sudo', 'docker', 'rm') for call in calls)
assert any(call[0][:2] == ('sudo', 'tar') and call[1][:3] == ('podman', 'unshare', 'tar')
           for call in calls if isinstance(call[0], tuple))
print('ok - database transfer preserves ports, restart policy, image snapshot and numeric volume ownership without removing Docker data')

calls.clear()
inspect_clean = migration.inspect
migration.inspect = lambda engine, kind, name: {'State': {'Running': False, 'ExitCode': 137}} if kind == 'container' else inspect_clean(engine, kind, name)
try:
    migration.migrate(container)
except RuntimeError as error:
    assert 'stop cleanly' in str(error)
else:
    raise AssertionError('SIGKILL shutdown was accepted')
assert not any(call[:3] == ('sudo', 'docker', 'commit') for call in calls)
assert ('sudo', 'docker', 'start', 'a' * 64) in calls
migration.inspect = inspect_clean
print('ok - forced shutdown aborts before copying and restarts the source')

calls.clear()
def broken_pipe(producer, consumer):
    raise RuntimeError('transfer failed')
migration.pipe = broken_pipe
try:
    migration.migrate(container)
except RuntimeError:
    pass
else:
    raise AssertionError('failed transfer was reported successful')
assert ('sudo', 'docker', 'start', 'a' * 64) in calls
assert not any(call[:2] == ('podman', 'create') for call in calls)
print('ok - failed transfer restores the previously running Docker database')

calls.clear()
migration.subprocess.run = lambda args, **kwargs: SimpleNamespace(returncode=0)
migration.inspect = lambda *args: {'Config': {'Labels': {migration.LABEL: 'a' * 64}}}
migration.migrate(container)
assert not calls
migration.inspect = lambda *args: {'Config': {'Labels': {migration.LABEL: 'different'}}}
try:
    migration.migrate(container)
except ValueError:
    pass
else:
    raise AssertionError('unrelated destination container was overwritten')
assert not calls
print('ok - retries recognize the original Docker identity and refuse destination collisions')
PY
