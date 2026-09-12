#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

python3 - <<'PY'
import copy
import importlib.util
import os
import re
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
path = os.path.join(os.environ["ROOT"], "default/docker/rootless/migrate.py")
spec = importlib.util.spec_from_file_location("rootless_docker_migration", path)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
manifest_path = os.path.join(os.environ["ROOT"], "default/docker/rootless/volume-manifest.py")
manifest_spec = importlib.util.spec_from_file_location("rootless_docker_volume_manifest", manifest_path)
manifest = importlib.util.module_from_spec(manifest_spec)
manifest_spec.loader.exec_module(manifest)
assert migration.TRUSTED_MANIFEST == "/usr/share/omarchy/default/docker/rootless/volume-manifest.py"
assert migration.local_command([migration.SOURCE, "info"])[:2] == ["/usr/bin/sudo", "/usr/bin/docker"]
print("ok - privileged migration helpers resolve only through packaged absolute paths")

with tempfile.TemporaryDirectory() as directory:
    volume = os.path.join(directory, "volume")
    outside = os.path.join(directory, "outside")
    os.makedirs(os.path.join(volume, "nested"))
    os.makedirs(outside)
    with open(os.path.join(volume, "stale"), "w") as output:
        output.write("old")
    with open(os.path.join(volume, "nested", "old"), "w") as output:
        output.write("old")
    with open(os.path.join(outside, "keep"), "w") as output:
        output.write("safe")
    os.symlink(outside, os.path.join(volume, "outside-link"))
    manifest.clear(volume)
    assert not os.listdir(volume)
    assert open(os.path.join(outside, "keep")).read() == "safe"
print("ok - retained-volume reset removes stale entries without following symlinks")

source_security = ["name=seccomp,profile=builtin", "name=cgroupns"]
target_security = ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"]
migration.validate_source_daemon(source_security)
migration.validate_target_daemon(target_security)
for options in (None, [], ["name=rootless"], ["name=userns"], ["name=no-new-privileges"],
                ["name=cgroupns"], ["name=seccomp,profile=builtin"]):
    try:
        migration.validate_source_daemon(options)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsafe rootful daemon policy passed: {options}")
for options in (None, [], source_security, target_security + ["name=apparmor"],
                ["name=rootless", "name=cgroupns"],
                ["name=rootless", "name=seccomp,profile=builtin"]):
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
        "Tty": False, "OpenStdin": False, "StopTimeout": 300,
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

numeric_root = copy.deepcopy(container)
numeric_root["Config"]["User"] = "00:1000"
numeric_root["HostConfig"]["CapDrop"] = []
assert migration.allowed_capabilities(numeric_root) == migration.DOCKER_CAPABILITIES
non_root_default_caps = copy.deepcopy(container)
non_root_default_caps["HostConfig"]["CapDrop"] = []
try:
    migration.validate(non_root_default_caps)
except ValueError:
    pass
else:
    raise AssertionError("non-root image user with an unreproducible capability ceiling passed")
for named_user in ("root", "daemon", "root:root", "\u0660"):
    changed = copy.deepcopy(container)
    changed["Config"]["User"] = named_user
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"ambiguous named user passed preflight: {named_user}")
print("ok - numeric UID zero keeps its capabilities and ambiguous named users fail closed")

paused = copy.deepcopy(container)
paused["State"]["Paused"] = True
try:
    migration.validate(paused)
except ValueError:
    pass
else:
    raise AssertionError("a paused source passed automatic lifecycle migration")
exited = copy.deepcopy(container)
exited["State"] = {
    "Status": "exited", "Running": False, "StartedAt": "start", "FinishedAt": "finish", "ExitCode": 7,
}
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    try:
        migration.validate(exited)
    except ValueError:
        pass
    else:
        raise AssertionError("an exited source with unreproducible state passed automatic migration")
created = copy.deepcopy(exited)
created["State"] = {
    "Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z",
    "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0,
}
assert migration.validate(created) == "project-worker"
assert migration.target_never_started(created)
ran_target = copy.deepcopy(created)
ran_target["State"] = {
    "Status": "exited", "Running": False, "StartedAt": "target-start",
    "FinishedAt": "target-stop", "ExitCode": 0,
}
assert not migration.target_never_started(ran_target)
print("ok - paused, exited, and unreproducible non-root capability states fail closed")

for stop_timeout in (None, -1, 0, 300):
    changed = copy.deepcopy(container)
    changed["Config"]["StopTimeout"] = stop_timeout
    assert migration.validate(changed) == "project-worker"
for stop_timeout in (True, -2, "300"):
    changed = copy.deepcopy(container)
    changed["Config"]["StopTimeout"] = stop_timeout
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsupported stop timeout passed preflight: {stop_timeout!r}")
print("ok - stop timeouts are type checked and larger application grace periods are retained")

for field, value in (("Labels", {migration.LABEL: "old"}),
                     ("Env", ["DUPLICATE=one", "DUPLICATE=two"])):
    changed = copy.deepcopy(container)
    changed["Config"][field] = value
    try:
        migration.validate(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"ambiguous {field} passed preflight")
print("ok - reserved labels and duplicate environment keys fail before transfer")

windows = copy.deepcopy(container)
windows["Name"] = "/omarchy-windows"
windows["Id"] = "f" * 64
windows["Config"]["Image"] = "dockurr/windows"
windows["Config"]["Env"] = ["VERSION=11", "PROTECT=Y"]
windows["Config"]["Labels"] = {
    "com.docker.compose.project": "windows",
    "com.docker.compose.service": "windows",
}
windows["HostConfig"]["Privileged"] = False
windows["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
windows["HostConfig"]["CapDrop"] = []
windows["HostConfig"]["DeviceRequests"] = []
windows["HostConfig"]["DeviceCgroupRules"] = []
windows["HostConfig"]["SecurityOpt"] = []
windows["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
windows["HostConfig"]["NetworkMode"] = "windows_default"
windows["HostConfig"]["Devices"] = [
    {"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"},
    {"PathOnHost": "/dev/net/tun", "PathInContainer": "/dev/net/tun"},
]
windows["HostConfig"]["PortBindings"] = {
    "8006/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8006"}],
    "3389/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3389"}],
    "3389/udp": [{"HostIp": "127.0.0.1", "HostPort": "3389"}],
}
uid = os.getuid()
windows["Mounts"] = [
    {"Type": "bind", "Source": f"/var/lib/omarchy/windows/mounts/users/{uid}/storage",
     "Destination": "/storage", "RW": True},
    {"Type": "bind", "Source": f"/var/lib/omarchy/windows/mounts/users/{uid}/shared",
     "Destination": "/shared", "RW": True},
]
windows["NetworkSettings"]["Networks"] = {"windows_default": {}}
assert migration.validate_windows_exception(windows) == "omarchy-windows"
legacy_windows = copy.deepcopy(windows)
legacy_windows["Mounts"][0]["Source"] = f"{Path.home()}/.windows"
legacy_windows["Mounts"][1]["Source"] = f"{Path.home()}/Windows"
for mutation in ("image", "labels", "devices", "extra-device", "device-rules", "security-opt",
                 "mounts", "mount-source", "restart", "network-mode", "extra-network", "autoremove",
                 "missing-protect", "duplicate-protect"):
    changed = copy.deepcopy(windows)
    if mutation == "image":
        changed["Config"]["Image"] = "example/custom"
    elif mutation == "labels":
        changed["Config"]["Labels"] = {}
    elif mutation == "devices":
        changed["HostConfig"]["Devices"] = []
    elif mutation == "extra-device":
        changed["HostConfig"]["Devices"].append({"PathOnHost": "/dev/null", "PathInContainer": "/dev/null"})
    elif mutation == "device-rules":
        changed["HostConfig"]["DeviceCgroupRules"] = ["a *:* rwm"]
    elif mutation == "security-opt":
        changed["HostConfig"]["SecurityOpt"] = ["seccomp=unconfined"]
    elif mutation == "mounts":
        changed["Mounts"] = []
    elif mutation == "mount-source":
        changed["Mounts"][0]["Source"] = "/tmp/unmanaged-windows"
    elif mutation == "restart":
        changed["HostConfig"]["RestartPolicy"] = {"Name": "always", "MaximumRetryCount": 0}
    elif mutation == "network-mode":
        changed["HostConfig"]["NetworkMode"] = "host"
    elif mutation == "extra-network":
        changed["NetworkSettings"]["Networks"]["unexpected"] = {}
    elif mutation == "missing-protect":
        changed["Config"]["Env"] = ["VERSION=11"]
    elif mutation == "duplicate-protect":
        changed["Config"]["Env"] += ["PROTECT=N"]
    else:
        changed["HostConfig"]["AutoRemove"] = True
    try:
        migration.validate_windows_exception(changed)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unmanaged Windows exception passed: {mutation}")
try:
    migration.validate_windows_exception(legacy_windows)
except ValueError:
    pass
else:
    raise AssertionError("legacy home-mounted Windows runtime passed the protected exception")
print("ok - only Omarchy's managed Windows runtime qualifies for the rootful exception")

source_volume = {"Name": "project-data", "Driver": "local", "Options": None,
                 "Labels": {"project": "fixture"}}
ownership = migration.volume_identity(container, container["Mounts"][0])
assert ownership != migration.volume_identity(container, container["Mounts"][0])
raced_volume = copy.deepcopy(source_volume)
raced_volume["Labels"] = {"project": "fixture"}
migration.inspect = lambda engine, kind, name: copy.deepcopy(raced_volume)
try:
    migration.verify_volume_definition(source_volume, "project-data", ownership)
except RuntimeError:
    pass
else:
    raise AssertionError("an independently created destination volume was claimed")
owned_volume = copy.deepcopy(source_volume)
owned_volume["Labels"][migration.VOLUME_LABEL] = ownership
migration.inspect = lambda engine, kind, name: copy.deepcopy(owned_volume)
migration.verify_volume_definition(source_volume, "project-data", ownership)
real_run = migration.run
migration.run = lambda *args, **kwargs: "f" * 64
assert migration.volume_users("project-data") == ["f" * 64]
migration.run = lambda *args, **kwargs: "short-id"
try:
    migration.volume_users("project-data")
except RuntimeError:
    pass
else:
    raise AssertionError("an ambiguous destination-volume attachment passed validation")
migration.run = real_run
reserved_source = copy.deepcopy(source_volume)
reserved_source["Labels"][migration.VOLUME_LABEL] = "foreign"
try:
    migration.validate_source_volume(container, reserved_source)
except ValueError:
    pass
else:
    raise AssertionError("a source volume with the migration ownership label was accepted")
print("ok - destination volumes require unpredictable ownership and no attachments before cleanup")

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
target["State"] = {
    "Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z",
    "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0,
}
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.inspect = lambda engine, kind, name: copy.deepcopy(stopped if engine == migration.SOURCE else target)
    migration.record_completion(stopped, stopped["State"], False)
    assert migration.validate(stopped) == "project-worker"
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

with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    overlap_original = copy.deepcopy(container)
    overlap_original["Mounts"] = []
    overlap_original["HostConfig"]["Binds"] = []
    overlap_source = copy.deepcopy(overlap_original)
    overlap_source["State"] = {
        "Status": "exited", "Running": False, "StartedAt": "start",
        "FinishedAt": "completed-stop", "ExitCode": 0,
    }
    overlap_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    overlap_target = copy.deepcopy(overlap_original)
    overlap_target["Id"] = "b" * 64
    overlap_target["Config"]["Labels"][migration.LABEL] = overlap_source["Id"]
    overlap_target["State"] = {
        "Status": "running", "Running": True, "StartedAt": "target-start",
        "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0,
    }
    overlap_intent = migration.record_migration_intent(overlap_original)
    overlap_intent = migration.record_migration_intent(
        overlap_source, overlap_source["State"], overlap_intent, restart_disabled=True,
    )
    overlap_intent["start_attempted"] = True
    migration.persist_migration_intent(overlap_source, overlap_intent)
    migration.inspect = lambda engine, kind, name: copy.deepcopy(
        overlap_source if engine == migration.SOURCE else overlap_target
    )
    migration.record_completion(overlap_source, overlap_source["State"], True)
    migration.exists = lambda kind, name: kind == "container" and name == "project-worker"
    migration.migrate(overlap_source)
    assert not migration.intent_path(overlap_source["Id"]).exists()

    migration.persist_migration_intent(overlap_source, overlap_intent)
    migration.daemon_security = lambda engine: source_security if engine == migration.SOURCE else target_security
    sys.argv = ["migrate.py", "--check", overlap_source["Name"].lstrip("/")]
    migration.main()
    assert migration.intent_path(overlap_source["Id"]).exists()
    sys.argv = ["migrate.py", "--quiesce-all", "-", overlap_source["Name"].lstrip("/")]
    migration.main()
    assert not migration.intent_path(overlap_source["Id"]).exists()
print("ok - a valid completion receipt clears its stale journal in check, transfer, and quiesce phases")

restarted = copy.deepcopy(stopped)
restarted["State"]["Running"] = True
migration.inspect = lambda engine, kind, name: copy.deepcopy(restarted if engine == migration.SOURCE else target)
try:
    migration.record_completion(stopped, stopped["State"], False)
except ValueError:
    pass
else:
    raise AssertionError("a restarted source received a completion receipt")
print("ok - completion re-inspects the source and refuses a stale stopped state")

intent_source = copy.deepcopy(container)
intent_source["Mounts"] = []
intent_source["HostConfig"]["Binds"] = []
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    intent = migration.record_migration_intent(intent_source)
    assert migration.migration_intent(intent_source) == intent
    stopped_intent_source = copy.deepcopy(intent_source)
    stopped_intent_source["State"] = {
        "Running": False, "StartedAt": "start", "FinishedAt": "stopped", "ExitCode": 0,
    }
    intent = migration.record_migration_intent(stopped_intent_source, stopped_intent_source["State"], intent)
    intent = migration.record_migration_intent(stopped_intent_source, stopped_intent_source["State"], intent,
                                               restart_disabled=True)
    disabled_source = copy.deepcopy(stopped_intent_source)
    disabled_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    loaded = migration.migration_intent(disabled_source)
    restored_plan = migration.planned_source(disabled_source, loaded)
    assert restored_plan["HostConfig"]["RestartPolicy"] == intent_source["HostConfig"]["RestartPolicy"]
    assert migration.snapshot_digest(restored_plan) == migration.snapshot_digest(stopped_intent_source)
    changed = copy.deepcopy(disabled_source)
    changed["Config"]["Hostname"] = "changed-during-interruption"
    try:
        migration.migration_intent(changed)
    except ValueError:
        pass
    else:
        raise AssertionError("interrupted source configuration drift was accepted")
    assert migration.intent_path(intent_source["Id"]).stat().st_mode & 0o777 == 0o600
print("ok - durable migration intent restores lifecycle and restart policy after interruption")

quiesce_source = copy.deepcopy(intent_source)
quiesce_calls = []
restore_markers = []

def quiesce_inspect(engine, kind, name):
    return copy.deepcopy(quiesce_source)

def quiesce_run(*args, **kwargs):
    quiesce_calls.append(args)
    if args[:2] == (migration.SOURCE, "stop"):
        quiesce_source["State"] = {
            "Running": False, "StartedAt": "start", "FinishedAt": "quiesced", "ExitCode": 0,
        }
    elif args[:2] == (migration.SOURCE, "update"):
        value = args[2].split("=", 1)[1]
        if value != "no":
            restore_markers.append(migration.migration_intent(quiesce_source)["restore_started"])
        quiesce_source["HostConfig"]["RestartPolicy"] = {
            "Name": value, "MaximumRetryCount": 0,
        }
    elif args[:2] == (migration.SOURCE, "start"):
        quiesce_source["State"]["Running"] = True
        quiesce_source["State"]["StartedAt"] = "restored"

with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.inspect = quiesce_inspect
    migration.run = quiesce_run
    migration.quiesce(quiesce_source)
    quiesced_intent = migration.migration_intent(quiesce_source)
    assert quiesced_intent["target_running"] is True
    assert quiesced_intent["restart_disabled"] is True
    assert (migration.SOURCE, "stop", "-t", "300", quiesce_source["Id"]) in quiesce_calls
    assert (migration.SOURCE, "update", "--restart=no", quiesce_source["Id"]) in quiesce_calls
    assert quiesce_calls.index((migration.SOURCE, "update", "--restart=no", quiesce_source["Id"])) < \
        quiesce_calls.index((migration.SOURCE, "stop", "-t", "300", quiesce_source["Id"]))
    migration.restore_source(quiesce_source["Id"])
    assert quiesce_source["State"]["Running"] is True
    assert quiesce_source["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert restore_markers == [True]
    assert not migration.intent_path(quiesce_source["Id"]).exists()
print("ok - batch quiesce durably disables restart and restores the exact source lifecycle")

with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    power_intent = migration.record_migration_intent(intent_source)
    power_intent = migration.record_migration_intent(intent_source, saved=power_intent,
                                                     restart_disabled=True)
    power_intent["quiesce_started"] = True
    migration.persist_migration_intent(intent_source, power_intent)
    restarted_before_update = copy.deepcopy(intent_source)
    restarted_before_update["State"]["StartedAt"] = "restarted-after-power-loss"
    assert migration.migration_intent(restarted_before_update) == power_intent
print("ok - restart-disable intent recovers a daemon restart before Docker applies the update")

with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    always_source = copy.deepcopy(intent_source)
    always_source["HostConfig"]["RestartPolicy"] = {"Name": "always", "MaximumRetryCount": 0}
    always_intent = migration.record_migration_intent(always_source)
    always_stopped = copy.deepcopy(always_source)
    always_stopped["State"] = {
        "Running": False, "StartedAt": "start", "FinishedAt": "restore-window", "ExitCode": 0,
    }
    always_stopped["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    always_intent = migration.record_migration_intent(always_stopped, always_stopped["State"],
                                                      always_intent, restart_disabled=True)
    always_intent["restore_started"] = True
    migration.persist_migration_intent(always_stopped, always_intent)
    restarted_during_restore = copy.deepcopy(always_source)
    restarted_during_restore["State"]["StartedAt"] = "daemon-restart-during-restore"
    assert migration.migration_intent(restarted_during_restore) == always_intent
print("ok - durable restore intent recognizes an always source restarted after policy restoration")

quiesce_source = copy.deepcopy(intent_source)
quiesce_calls = []
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.quiesce(quiesce_source)
    artifact_intent = migration.migration_intent(quiesce_source)
    artifact_intent["volumes"]["retained-data"] = {
        "source": "source-data", "ownership": f'{quiesce_source["Id"]}:source-data:{"e" * 64}',
    }
    migration.persist_migration_intent(quiesce_source, artifact_intent)
    migration.restore_source(quiesce_source["Id"])
    assert quiesce_source["State"]["Running"] is True
    assert migration.intent_path(quiesce_source["Id"]).exists()
    assert migration.migration_intent(quiesce_source)["volumes"] == artifact_intent["volumes"]
print("ok - batch recovery retains ownership journals for interrupted destination artifacts")


def exercise_failed_transfer(after_start, mutate_source=False, preexisting_image=False, replace_target=False):
    source = copy.deepcopy(container)
    source["Id"] = ("d" if after_start else "c") * 64
    source["Name"] = "/post-start" if after_start else "/pre-start"
    source["Mounts"] = []
    source["HostConfig"]["Binds"] = []
    current_source = copy.deepcopy(source)
    current_target = None
    calls = []
    pipes = []

    def fake_inspect(engine, kind, name):
        if engine == migration.SOURCE:
            return copy.deepcopy(current_source)
        if current_target is None:
            raise migration.subprocess.CalledProcessError(1, ["docker", "inspect"])
        return copy.deepcopy(current_target)

    def fake_run(*args, **kwargs):
        nonlocal current_target
        calls.append(args)
        if args[:2] == (migration.SOURCE, "stop"):
            current_source["State"] = {
                "Running": False, "StartedAt": "start", "FinishedAt": "finish", "ExitCode": 0,
            }
            if mutate_source:
                current_source["HostConfig"]["Memory"] += 4096
        elif args[:2] == (migration.SOURCE, "update"):
            value = args[2].split("=", 1)[1]
            policy, _, retry_count = value.partition(":")
            current_source["HostConfig"]["RestartPolicy"] = {
                "Name": policy, "MaximumRetryCount": int(retry_count or 0),
            }
        elif args[:2] == (migration.SOURCE, "start"):
            current_source["State"]["Running"] = True
        elif args[:2] == (migration.SOURCE, "commit"):
            return "sha256:" + ("f" if after_start else "e") * 64
        elif args[:2] == (migration.TARGET, "create"):
            labels = {}
            for index, argument in enumerate(args):
                if argument == "--label":
                    key, value = args[index + 1].split("=", 1)
                    labels[key] = value
            current_target = {"Id": "b" * 64, "Config": {"Labels": labels},
                              "State": {"Status": "created", "Running": False,
                                        "StartedAt": "0001-01-01T00:00:00Z",
                                        "FinishedAt": "0001-01-01T00:00:00Z"}}
        elif args[:3] == (migration.TARGET, "rm", "--force"):
            current_target = None
        elif args[:2] == (migration.TARGET, "start"):
            current_target["State"]["Running"] = True

    migration.inspect = fake_inspect
    migration.run = fake_run
    migration.exists = lambda kind, name: (
        (kind == "container" and current_target is not None and
         name in (current_target.get("Id"), current_target.get("Name", "").lstrip("/"))) or
        (preexisting_image and kind == "image")
    )
    migration.pipe = lambda producer, consumer: pipes.append((producer, consumer))
    if after_start:
        migration.verify_runtime = lambda value, ownership=None: None
    else:
        def fail_verification(value, ownership=None):
            nonlocal current_target
            if replace_target:
                current_target = {"Id": "6" * 64, "Config": {"Labels": {}},
                                  "State": {"Running": False}}
            raise RuntimeError("verification failed")
        migration.verify_runtime = fail_verification
    migration.record_completion = lambda source, state, running: (_ for _ in ()).throw(RuntimeError("receipt failed"))

    with tempfile.TemporaryDirectory() as directory:
        os.environ["XDG_STATE_HOME"] = directory
        try:
            migration.migrate(source)
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed transfer was reported as complete")
        intent_retained = migration.intent_path(source["Id"]).exists()
    return calls, current_source, pipes, intent_retained


calls, source, pipes, intent_retained = exercise_failed_transfer(False)
create_call = next(call for call in calls if call[:2] == (migration.TARGET, "create"))
assert create_call[create_call.index("--runtime") + 1] == "runc"
assert (migration.TARGET, "rm", "--force", "b" * 64) in calls
assert (migration.TARGET, "image", "rm", "sha256:" + "e" * 64) in calls
assert (migration.SOURCE, "stop", "-t", "300", "c" * 64) in calls
assert (migration.SOURCE, "start", "c" * 64) in calls
assert source["State"]["Running"]
assert not intent_retained
print("ok - verification failure before first start removes the destination and restores the source")

calls, source, pipes, intent_retained = exercise_failed_transfer(False, mutate_source=True)
assert not any(call[:2] == (migration.SOURCE, "commit") for call in calls)
assert (migration.SOURCE, "start", "c" * 64) in calls
assert source["State"]["Running"]
assert intent_retained
print("ok - source configuration changes during stop abort before image transfer")

calls, source, pipes, intent_retained = exercise_failed_transfer(True)
assert (migration.TARGET, "start", "post-start") in calls
assert not any(call[:2] == (migration.TARGET, "rm") for call in calls)
assert not any(call[:3] == (migration.TARGET, "image", "rm") for call in calls)
assert not any(call[:2] == (migration.SOURCE, "start") for call in calls)
assert source["HostConfig"]["RestartPolicy"]["Name"] == "no"
assert not source["State"]["Running"]
assert intent_retained
print("ok - any destination start attempt retains both copies and keeps the source stopped")

calls, source, pipes, intent_retained = exercise_failed_transfer(False, preexisting_image=True)
assert not pipes
assert not any(call[:3] == (migration.TARGET, "image", "rm") for call in calls)
assert (migration.SOURCE, "image", "rm", "sha256:" + "e" * 64) in calls
print("ok - a preexisting target image digest is reused without claiming or deleting it")

calls, source, pipes, intent_retained = exercise_failed_transfer(False, replace_target=True)
assert not any(call[:3] == (migration.TARGET, "rm", "--force") for call in calls)
assert not source["State"]["Running"]
assert intent_retained
print("ok - a concurrently replaced destination is retained without restarting its rootful source")

retry_original = copy.deepcopy(container)
retry_original["Id"] = "9" * 64
retry_original["Name"] = "/interrupted-retry"
retry_original["Mounts"] = []
retry_original["HostConfig"]["Binds"] = []
retry_source = copy.deepcopy(retry_original)
retry_source["State"] = {
    "Running": False, "StartedAt": "start", "FinishedAt": "power-loss-stop", "ExitCode": 0,
}
retry_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
retry_state = {"target": None}
retry_calls = []
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    retry_intent = migration.record_migration_intent(retry_original)
    retry_intent = migration.record_migration_intent(retry_original, retry_source["State"], retry_intent,
                                                     restart_disabled=True)

    def retry_inspect(engine, kind, name):
        return copy.deepcopy(retry_source if engine == migration.SOURCE else retry_state["target"])

    def retry_run(*args, **kwargs):
        retry_calls.append(args)
        if args[:2] == (migration.SOURCE, "commit"):
            return "sha256:" + "8" * 64
        if args[:2] == (migration.TARGET, "create"):
            labels = {}
            for index, argument in enumerate(args):
                if argument == "--label":
                    key, value = args[index + 1].split("=", 1)
                    labels[key] = value
            retry_state["target"] = {"Id": "7" * 64, "Config": {"Labels": labels},
                                     "State": {"Status": "created", "Running": False,
                                               "StartedAt": "0001-01-01T00:00:00Z",
                                               "FinishedAt": "0001-01-01T00:00:00Z"}}
        if args[:2] == (migration.TARGET, "start"):
            retry_state["target"]["State"]["Running"] = True

    migration.inspect = retry_inspect
    migration.run = retry_run
    migration.exists = lambda kind, name: False
    migration.pipe = lambda producer, consumer: None
    migration.verify_runtime = lambda value, ownership=None: None
    migration.record_completion = lambda source, state, running: None
    migration.migrate(retry_source)
    create_call = next(call for call in retry_calls if call[:2] == (migration.TARGET, "create"))
    assert create_call[create_call.index("--restart") + 1] == "unless-stopped"
    assert (migration.TARGET, "start", "interrupted-retry") in retry_calls
    assert not migration.intent_path(retry_source["Id"]).exists()
print("ok - a fresh process resumes a stopped migration with the original running and restart intent")

resume_original = copy.deepcopy(retry_original)
resume_source = copy.deepcopy(retry_source)
resume_target = copy.deepcopy(retry_state["target"])
resume_target["State"]["Running"] = False
resume_calls = []
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    resume_intent = migration.record_migration_intent(resume_original)
    resume_intent = migration.record_migration_intent(resume_source, resume_source["State"], resume_intent,
                                                      restart_disabled=True)
    resume_target["Config"]["Labels"][migration.OWNERSHIP_LABEL] = resume_intent["target_ownership"]
    resume_intent["destination"] = {
        "id": resume_target["Id"], "snapshot": migration.snapshot_digest(resume_target),
    }
    migration.persist_migration_intent(resume_source, resume_intent)

    def resume_inspect(engine, kind, name):
        return copy.deepcopy(resume_source if engine == migration.SOURCE else resume_target)

    def resume_run(*args, **kwargs):
        resume_calls.append(args)
        if args[:2] == (migration.TARGET, "start"):
            resume_target["State"]["Running"] = True

    migration.inspect = resume_inspect
    migration.run = resume_run
    migration.verify_runtime = lambda value, ownership=None: None
    migration.record_completion = lambda source, state, running: None
    unexpected_running = copy.deepcopy(resume_target)
    unexpected_running["State"]["Running"] = True
    try:
        migration.verify_resumable_migration(resume_source, unexpected_running, resume_intent)
    except ValueError:
        pass
    else:
        raise AssertionError("an unexpectedly running interrupted destination passed preflight")
    ran_and_stopped = copy.deepcopy(resume_target)
    ran_and_stopped["State"] = {
        "Status": "exited", "Running": False, "StartedAt": "outside-start",
        "FinishedAt": "outside-stop", "ExitCode": 0,
    }
    try:
        migration.verify_resumable_migration(resume_source, ran_and_stopped, resume_intent)
    except ValueError:
        pass
    else:
        raise AssertionError("an externally started and stopped destination passed automatic retry")
    post_start_intent = copy.deepcopy(resume_intent)
    post_start_intent["start_attempted"] = True
    try:
        migration.verify_resumable_migration(resume_source, resume_target, post_start_intent)
    except ValueError:
        pass
    else:
        raise AssertionError("a stopped destination that already ran passed automatic retry")
    restored_source_intent = copy.deepcopy(resume_intent)
    restored_source_intent["restore_started"] = True
    try:
        migration.verify_resumable_migration(resume_source, resume_target, restored_source_intent)
    except ValueError:
        pass
    else:
        raise AssertionError("a destination older than a restored source passed automatic retry")
    migration.persist_migration_intent(resume_source, post_start_intent)
    try:
        migration.restore_source(resume_source["Id"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("post-start recovery restarted the rootful source")
    assert not resume_source["State"]["Running"]
    try:
        migration.migrate(resume_source)
    except ValueError:
        pass
    else:
        raise AssertionError("a missing post-start destination allowed automatic recreation")
    migration.persist_migration_intent(resume_source, resume_intent)
    migration.resume_verified_migration(resume_source, resume_target, resume_intent)
    assert (migration.TARGET, "start", "interrupted-retry") in resume_calls
    assert not migration.intent_path(resume_source["Id"]).exists()
print("ok - a verified destination resumes safely across interruption before its first start")

for unsafe_kind in ("destination", "guard"):
    unsafe_original = copy.deepcopy(retry_original)
    unsafe_original["Id"] = ("a" if unsafe_kind == "destination" else "b") * 64
    unsafe_original["Name"] = f"/{unsafe_kind}-race"
    unsafe_source = copy.deepcopy(unsafe_original)
    unsafe_source["State"] = {
        "Status": "exited", "Running": False, "StartedAt": unsafe_original["State"]["StartedAt"],
        "FinishedAt": "source-stop", "ExitCode": 0,
    }
    unsafe_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    with tempfile.TemporaryDirectory() as directory:
        os.environ["XDG_STATE_HOME"] = directory
        unsafe_intent = migration.record_migration_intent(unsafe_original)
        unsafe_intent = migration.record_migration_intent(
            unsafe_source, unsafe_source["State"], unsafe_intent, restart_disabled=True,
        )
        unsafe_name = (unsafe_source["Name"].lstrip("/") if unsafe_kind == "destination"
                       else migration.volume_guard_name(unsafe_intent))
        unsafe_target = {
            "Id": "c" * 64, "Name": f"/{unsafe_name}",
            "Config": {"Labels": {
                migration.LABEL: unsafe_source["Id"],
                migration.OWNERSHIP_LABEL: unsafe_intent["target_ownership"],
            }},
            "State": {"Status": "exited", "Running": False, "StartedAt": "outside-start",
                      "FinishedAt": "outside-stop", "ExitCode": 0},
        }

        def unsafe_inspect(engine, kind, name):
            if engine == migration.SOURCE:
                return copy.deepcopy(unsafe_source)
            if name in (unsafe_target["Id"], unsafe_name):
                return copy.deepcopy(unsafe_target)
            raise migration.subprocess.CalledProcessError(1, ["docker", "inspect"])

        migration.inspect = unsafe_inspect
        migration.exists = lambda kind, name: kind == "container" and name == unsafe_name
        try:
            migration.migrate(unsafe_source)
        except ValueError:
            pass
        else:
            raise AssertionError(f"a raced {unsafe_kind} allowed automatic migration")
        assert migration.migration_intent(unsafe_source)["start_attempted"] is True
        try:
            migration.restore_source(unsafe_source["Id"])
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"a raced {unsafe_kind} allowed rootful source restart")
print("ok - a destination or guard run after preflight durably blocks rootful source restart")

pinned_source = copy.deepcopy(container)
pinned_source["Name"] = "/pinned-volume"
pinned_source["Id"] = "5" * 64
current_pinned_source = copy.deepcopy(pinned_source)
source_volume = {
    "Name": "project-data", "Driver": "local", "Options": None,
    "Labels": {"project": "fixture"}, "Mountpoint": "/source-volume",
}
target_volume = None
pinned_target = None
pinned_guard = None
pin_events = []


def pin_inspect(engine, kind, name):
    if engine == migration.SOURCE and kind == "container":
        return copy.deepcopy(current_pinned_source)
    if engine == migration.SOURCE and kind == "volume":
        return copy.deepcopy(source_volume)
    if engine == migration.TARGET and kind == "volume":
        if target_volume is None:
            raise migration.subprocess.CalledProcessError(1, ["docker", "inspect"])
        return copy.deepcopy(target_volume)
    for candidate in (pinned_target, pinned_guard):
        if candidate is not None and name in (candidate["Id"], candidate["Name"].lstrip("/")):
            return copy.deepcopy(candidate)
    raise migration.subprocess.CalledProcessError(1, ["docker", "inspect"])


def pin_run(*args, **kwargs):
    global target_volume, pinned_target, pinned_guard
    pin_events.append(args)
    if args[:2] == (migration.SOURCE, "update"):
        current_pinned_source["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    elif args[:2] == (migration.SOURCE, "stop"):
        current_pinned_source["State"] = {
            "Status": "exited", "Running": False, "StartedAt": "start",
            "FinishedAt": "pinned-stop", "ExitCode": 0,
        }
    elif args[:2] == (migration.SOURCE, "commit"):
        return "sha256:" + "4" * 64
    elif args[:3] == (migration.TARGET, "volume", "create"):
        labels = {}
        for index, argument in enumerate(args):
            if argument == "--label":
                key, value = args[index + 1].split("=", 1)
                labels[key] = value
        target_volume = {
            "Name": args[-1], "Driver": "local", "Options": None,
            "Labels": labels, "Mountpoint": "/target-volume",
        }
    elif args[:2] == (migration.TARGET, "create"):
        labels = {}
        for index, argument in enumerate(args):
            if argument == "--label":
                key, value = args[index + 1].split("=", 1)
                labels[key] = value
        created_name = args[args.index("--name") + 1]
        created = {
            "Id": ("8" if created_name.startswith("omarchy-volume-guard-") else "6") * 64,
            "Name": f"/{created_name}", "Config": {"Labels": labels},
            "State": {"Status": "created", "Running": False,
                      "StartedAt": "0001-01-01T00:00:00Z",
                      "FinishedAt": "0001-01-01T00:00:00Z"},
        }
        if created_name.startswith("omarchy-volume-guard-"):
            pinned_guard = created
        else:
            pinned_target = created
    elif args[:3] == (migration.TARGET, "container", "ls"):
        return "\n".join(candidate["Id"] for candidate in (pinned_guard, pinned_target)
                         if candidate is not None)
    elif args[:3] == (migration.TARGET, "rm", "--force"):
        if pinned_guard is not None and args[3] == pinned_guard["Id"]:
            pinned_guard = None
        elif pinned_target is not None and args[3] == pinned_target["Id"]:
            pinned_target = None
    elif args[:2] == (migration.TARGET, "start"):
        pinned_target["State"]["Status"] = "running"
        pinned_target["State"]["Running"] = True


def pin_exists(kind, name):
    if kind == "volume":
        return target_volume is not None
    return any(candidate is not None and name in (candidate["Id"], candidate["Name"].lstrip("/"))
               for candidate in (pinned_guard, pinned_target))


with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.inspect = pin_inspect
    migration.run = pin_run
    migration.exists = pin_exists
    migration.pipe = lambda producer, consumer: pin_events.append(("pipe",))
    migration.verify_runtime = lambda value, ownership=None: None
    migration.verify_volume = lambda target, digest: None
    migration.source_volume_digest = lambda volume: "7" * 64
    migration.clear_volume = lambda target: pin_events.append(("clear", target))
    migration.transfer_volume = lambda volume, target: (pin_events.append(("transfer", target)) or "7" * 64)
    migration.record_completion = lambda source, state, running: None
    migration.migrate(pinned_source)

create_indexes = [index for index, event in enumerate(pin_events)
                  if event[:2] == (migration.TARGET, "create")]
assert len(create_indexes) == 2
guard_index, create_index = create_indexes
clear_index = pin_events.index(("clear", "project-data"))
transfer_index = pin_events.index(("transfer", "project-data"))
assert guard_index < clear_index < transfer_index < create_index
guard_call = pin_events[guard_index]
create_call = pin_events[create_index]
assert "--network=none" in guard_call
assert "--read-only" in guard_call and "--cap-drop" in guard_call
guard_entrypoint = guard_call[guard_call.index("--entrypoint") + 1]
assert re.fullmatch(r"/\.omarchy-volume-guard-[a-f0-9]{64}", guard_entrypoint)
assert create_call[create_call.index("--runtime") + 1] == "runc"
assert any(event[:3] == (migration.TARGET, "container", "ls")
           for event in pin_events[guard_index + 1:clear_index])
guard_remove_index = next(index for index, event in enumerate(pin_events)
                          if event[:3] == (migration.TARGET, "rm", "--force") and event[3] == "8" * 64)
start_index = pin_events.index((migration.TARGET, "start", "pinned-volume"))
assert create_index < guard_remove_index < start_index
print("ok - an inert random guard pins volumes while the application container does not yet exist")

batch = []
for index in (1, 2):
    member = copy.deepcopy(container)
    member["Name"] = f"/batch-{index}"
    member["Id"] = str(index) * 64
    member["Mounts"] = []
    member["HostConfig"]["Binds"] = []
    batch.append(member)
batch_by_name = {member["Name"].lstrip("/"): member for member in batch}
restored_batch = []
with tempfile.TemporaryDirectory() as directory:
    os.environ["XDG_STATE_HOME"] = directory
    migration.daemon_security = lambda engine: source_security if engine == migration.SOURCE else target_security
    migration.inspect = lambda engine, kind, name: copy.deepcopy(batch_by_name[name])
    migration.exists = lambda kind, name: False
    migration.migrate = lambda member: (_ for _ in ()).throw(RuntimeError("first transfer failed"))
    migration.restore_source = lambda identity, validator=migration.validate: restored_batch.append(identity)
    sys.argv = ["migrate.py", *batch_by_name]
    try:
        migration.main()
    except RuntimeError:
        pass
    else:
        raise AssertionError("a failed batch transfer was reported as complete")
assert restored_batch == [batch[1]["Id"], batch[0]["Id"]]
print("ok - transfer failure restores every remaining quiesced workload in reverse order")
PY
