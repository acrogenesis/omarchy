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
    'Config': {'Image': 'redis:7'},
    'HostConfig': {
        'NetworkMode': 'default', 'IpcMode': 'private',
        'PortBindings': {'6379/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '6379'}]},
        'RestartPolicy': {'Name': 'unless-stopped'},
    },
    'Mounts': [{'Type': 'volume', 'Driver': 'local', 'Name': 'old-data', 'Destination': '/data', 'RW': True}],
}
assert migration.validate(container) == 'redis'
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
migration.inspect = lambda engine, kind, name: {'Mountpoint': '/var/lib/docker/volumes/old-data/_data', 'Options': None}
migration.pipe = lambda producer, consumer: calls.append((tuple(producer), tuple(consumer)))
migration.migrate(container)
create = next(call for call in calls if call[:2] == ('podman', 'create'))
assert '127.0.0.1:6379:6379/tcp' in create
assert 'omarchy-migrated-old-data:/data:rw' in create
assert ('sudo', 'docker', 'stop', '-t', '120', 'a' * 64) in calls
assert ('podman', 'start', 'redis') in calls
assert not any(call[:3] == ('sudo', 'docker', 'rm') for call in calls)
assert any(call[0][:2] == ('sudo', 'tar') and call[1][:3] == ('podman', 'volume', 'import')
           for call in calls if isinstance(call[0], tuple))
print('ok - database transfer preserves ports, restart policy, image snapshot and numeric volume ownership without removing Docker data')

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
