#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

python3 - <<'PY'
import copy
import importlib.util
import os
import sys
import tempfile


sys.dont_write_bytecode = True
path = os.path.join(os.environ["ROOT"], "default/docker/rootless/migrate.py")
spec = importlib.util.spec_from_file_location("rootless_docker_migration", path)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

source_security = ["name=seccomp,profile=builtin", "name=cgroupns"]
target_security = ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"]
migration.validate_source_daemon(source_security)
migration.validate_target_daemon(target_security)
for options in (None, [], ["name=rootless"], ["name=userns"], ["name=no-new-privileges"]):
    try:
        migration.validate_source_daemon(options)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsafe rootful daemon policy passed: {options}")
for options in (None, [], source_security, target_security + ["name=apparmor"]):
    try:
        migration.validate_target_daemon(options)
    except ValueError:
        pass
    else:
        raise AssertionError(f"destination was not proven rootless: {options}")
print("ok - migration pins known source confinement and proves the destination daemon is rootless")

container = {
    "Name": "/project-worker",
    "Id": "a" * 64,
    "State": {"Running": True, "StartedAt": "start", "FinishedAt": "finish"},
    "Config": {
        "Image": "local/project-worker:v1", "Hostname": "worker", "Domainname": "",
        "User": "1000", "Env": ["PRIVATE=not-logged"], "Labels": {"project": "fixture"},
        "Tty": False, "OpenStdin": False,
    },
    "HostConfig": {
        "NetworkMode": "bridge", "IpcMode": "private", "ShmSize": 128 * 1024 * 1024,
        "Binds": ["project-data:/data:rw"], "Memory": 128 * 1024 * 1024,
        "MemorySwap": 256 * 1024 * 1024, "PidsLimit": 64, "NanoCpus": 500000000,
        "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
        "MaskedPaths": sorted(migration.MASKED_PATHS),
        "ReadonlyPaths": sorted(migration.READONLY_PATHS),
        "Runtime": "runc", "CgroupnsMode": "private", "ConsoleSize": [0, 0],
        "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
        "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "5"}},
    },
    "NetworkSettings": {"Networks": {"bridge": {}}},
    "Mounts": [{"Type": "volume", "Driver": "local", "Name": "project-data",
                "Destination": "/data", "RW": True}],
}
assert migration.validate(container) == "project-worker"
arguments = migration.runtime_arguments(container)
for flag, value in (("--pids-limit=64", None), ("--shm-size", "134217728"),
                    ("--memory", "134217728"), ("--memory-swap", "268435456"),
                    ("--cpus", "0.5"), ("--cap-drop", "ALL")):
    if value is None:
        assert flag in arguments
    else:
        assert arguments[arguments.index(flag) + 1] == value
assert "--cap-add" not in arguments
assert migration.destination_volume(container, container["Mounts"][0]) == "project-data"
unlimited = copy.deepcopy(container)
unlimited["HostConfig"]["PidsLimit"] = 0
assert not any(argument.startswith("--pids-limit=") for argument in migration.runtime_arguments(unlimited))
modern_mount = copy.deepcopy(container)
modern_mount["HostConfig"]["Binds"] = []
modern_mount["HostConfig"]["Mounts"] = [{
    "Type": "volume", "Source": "project-data", "Target": "/data",
    "ReadOnly": False, "VolumeOptions": {"NoCopy": True},
}]
assert migration.validate(modern_mount) == "project-worker"
assert migration.destination_volume(modern_mount, modern_mount["Mounts"][0]) == "project-data"
print("ok - compatible custom workloads retain resources, private volumes, ports and restrictive capabilities")

blocked = (
    ("Privileged", True), ("CapAdd", ["SYS_ADMIN"]),
    ("Devices", [{"PathOnHost": "/dev/kvm"}]),
    ("DeviceRequests", [{"Driver": "nvidia"}]),
    ("DeviceCgroupRules", ["a *:* rwm"]), ("NetworkMode", "host"),
    ("Runtime", "nvidia"), ("CgroupnsMode", "host"),
    ("SecurityOpt", ["seccomp=unconfined"]),
    ("Binds", ["/home/example/project:/data:rw"]),
    ("Mounts", [{"Type": "bind", "Source": "/home/example", "Target": "/data"}]),
    ("FuturePrivilegeOption", {"enabled": True}),
)
for field, value in blocked:
    changed = copy.deepcopy(container)
    changed["HostConfig"][field] = value
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsupported {field} passed preflight")
for networks in ({"bridge": {}, "project": {}}, {"project": {}}, {}):
    changed = copy.deepcopy(container)
    changed["NetworkSettings"]["Networks"] = networks
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsupported networks passed: {networks}")
print("ok - privileged, device, host-path, custom-network and unknown settings fail closed")

records = {}
for index, field in enumerate(("Privileged", "Runtime"), 1):
    changed = copy.deepcopy(container)
    changed["Name"] = f"/blocked-{index}"
    changed["Id"] = str(index) * 64
    changed["HostConfig"][field] = True if field == "Privileged" else "nvidia"
    records[changed["Name"].lstrip("/")] = changed
migration.daemon_security = lambda engine: source_security if engine == migration.SOURCE else target_security
migration.inspect = lambda engine, kind, name: records[name]
migration.run = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("preflight changed a workload"))
sys.argv = ["migrate.py", "--check", *records]
try:
    migration.main()
except ValueError as error:
    message = str(error)
    assert all(name in message for name in records)
    assert "PRIVATE" not in message and "not-logged" not in message
else:
    raise AssertionError("blocked batch passed preflight")
print("ok - complete-batch preflight reports every blocker without exposing container secrets")

stopped = copy.deepcopy(container)
stopped["State"] = {"Running": False, "StartedAt": "start", "FinishedAt": "finish", "ExitCode": 0}
stopped["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
target = copy.deepcopy(stopped)
target["Id"] = "b" * 64
target["Config"]["Labels"][migration.LABEL] = stopped["Id"]
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.inspect = lambda engine, kind, name: copy.deepcopy(target)
    migration.record_completion(stopped, stopped["State"], False)
    assert migration.completed(stopped, target)
    stopped["RestartCount"] = 4
    stopped["NetworkSettings"]["SandboxID"] = "changed-by-daemon-restart"
    target["RestartCount"] = 2
    target["State"]["StartedAt"] = "later-start"
    target["NetworkSettings"]["Networks"]["bridge"]["EndpointID"] = "later-endpoint"
    assert migration.completed(stopped, target)
    changed = copy.deepcopy(stopped)
    changed["Config"]["Hostname"] = "changed-after-transfer"
    assert not migration.completed(changed, target)
    target["State"]["Running"] = True
    assert not migration.completed(stopped, target)
print("ok - completion receipts bind both immutable workload snapshots and lifecycle state")


def exercise_failed_transfer(after_start):
    source = copy.deepcopy(container)
    source["Id"] = ("d" if after_start else "c") * 64
    source["Name"] = "/post-start" if after_start else "/pre-start"
    source["Mounts"] = []
    source["HostConfig"]["Binds"] = []
    current_source = copy.deepcopy(source)
    current_target = {"State": {"Running": False}}
    calls = []

    def fake_inspect(engine, kind, name):
        return copy.deepcopy(current_source if engine == migration.SOURCE else current_target)

    def fake_run(*args, **kwargs):
        calls.append(args)
        if args[:2] == (migration.SOURCE, "stop"):
            current_source["State"] = {
                "Running": False, "StartedAt": "start", "FinishedAt": "finish", "ExitCode": 0,
            }
        elif args[:2] == (migration.SOURCE, "update"):
            current_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
        elif args[:2] == (migration.SOURCE, "start"):
            current_source["State"]["Running"] = True

    migration.inspect = fake_inspect
    migration.run = fake_run
    migration.exists = lambda kind, name: False
    migration.pipe = lambda producer, consumer: None
    if after_start:
        migration.verify_runtime = lambda value: None
    else:
        migration.verify_runtime = lambda value: (_ for _ in ()).throw(RuntimeError("verification failed"))

    with tempfile.TemporaryDirectory() as directory:
        os.environ["XDG_STATE_HOME"] = directory
        try:
            migration.migrate(source)
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed transfer was reported as complete")
    return calls, current_source


calls, source = exercise_failed_transfer(False)
assert (migration.TARGET, "rm", "--force", "pre-start") in calls
assert (migration.TARGET, "image", "rm", "omarchy-migrated:" + "c" * 64) in calls
assert (migration.SOURCE, "start", "c" * 64) in calls
assert source["State"]["Running"]
print("ok - verification failure before first start removes the destination and restores the source")

calls, source = exercise_failed_transfer(True)
assert (migration.TARGET, "start", "post-start") in calls
assert not any(call[:2] == (migration.TARGET, "rm") for call in calls)
assert not any(call[:3] == (migration.TARGET, "image", "rm") for call in calls)
assert not any(call[:2] == (migration.SOURCE, "start") for call in calls)
assert source["HostConfig"]["RestartPolicy"]["Name"] == "no"
assert not source["State"]["Running"]
print("ok - any destination start attempt retains both copies and keeps the source stopped")
PY
