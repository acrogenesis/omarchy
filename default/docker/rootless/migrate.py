"""Move compatible rootful containers into the desktop user's rootless Docker store."""

import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
from copy import deepcopy
from decimal import Decimal
from pathlib import Path


LABEL = "io.omarchy.rootless-docker.source-id"
OWNERSHIP_LABEL = "io.omarchy.rootless-docker.ownership"
VOLUME_LABEL = "io.omarchy.rootless-docker.source-volume"
SOURCE = "source"
TARGET = "target"
TRUSTED_MANIFEST = "/usr/share/omarchy/default/docker/rootless/volume-manifest.py"
SECCOMP_OPTIONS = {"name=seccomp,profile=builtin", "name=seccomp,profile=default"}
MASKED_PATHS = {
    "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
    "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware",
}
READONLY_PATHS = {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
DOCKER_CAPABILITIES = {
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
    "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}
RESOURCE_FLAGS = {
    "Memory": "--memory", "MemoryReservation": "--memory-reservation",
    "MemorySwap": "--memory-swap", "CpuShares": "--cpu-shares",
    "CpuQuota": "--cpu-quota", "CpuPeriod": "--cpu-period",
    "CpusetCpus": "--cpuset-cpus", "CpusetMems": "--cpuset-mems",
}


def daemon_security(engine):
    return json.loads(run(engine, "info", "--format", "{{json .SecurityOptions}}", capture=True))


def validate_source_daemon(options):
    # Daemon defaults (including no-new-privileges and seccomp profiles) need
    # not appear in individual HostConfig records. Userns remapping also changes
    # the meaning of numeric volume ownership. Do not guess these policies.
    defaults = {*SECCOMP_OPTIONS, "name=cgroupns"}
    configured = set(options) if isinstance(options, list) else set()
    if (not configured or configured - defaults or "name=cgroupns" not in configured or
            len(configured & SECCOMP_OPTIONS) != 1):
        raise ValueError("rootful Docker daemon confinement or user mapping needs an explicit migration")


def validate_target_daemon(options):
    allowed = {
        "name=rootless", "name=cgroupns", "name=seccomp,profile=builtin",
        "name=seccomp,profile=default",
    }
    configured = set(options) if isinstance(options, list) else set()
    if "name=rootless" not in configured:
        raise ValueError("the destination Docker daemon is not running rootlessly")
    if (configured - allowed or "name=cgroupns" not in configured or
            len(configured & SECCOMP_OPTIONS) != 1):
        raise ValueError("rootless Docker daemon confinement needs an explicit migration")


def validate_volumes(container):
    name = container["Name"].lstrip("/")
    host = container["HostConfig"]
    mounts = container.get("Mounts", [])
    for mount in mounts:
        if mount.get("Type") != "volume" or mount.get("Driver") != "local":
            raise ValueError(f"{name}: host mounts or custom storage need an explicit transfer")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", mount["Name"]):
            raise ValueError(f"{name}: unsupported volume name")
        if not mount["Destination"].startswith("/") or ":" in mount["Destination"]:
            raise ValueError(f"{name}: unsupported volume destination")
    # -v also records named volumes in Binds. Accept only an exact match to a
    # local volume; never treat a host directory or socket as a named volume.
    for binding in host.get("Binds") or []:
        fields = binding.split(":")
        if (len(fields) not in (2, 3) or (len(fields) == 3 and fields[2] not in ("rw", "ro")) or
                not any(fields[:2] == [mount["Name"], mount["Destination"]] and
                        (len(fields) == 2 or (fields[2] == "rw") == mount.get("RW"))
                        for mount in mounts)):
            raise ValueError(f"{name}: custom Binds need an explicit volume transfer")
    for requested in host.get("Mounts") or []:
        allowed = {"Type", "Source", "Target", "ReadOnly", "Consistency", "VolumeOptions"}
        options = requested.get("VolumeOptions") or {}
        if (set(requested) - allowed or requested.get("Type") != "volume" or
                requested.get("Consistency") not in (None, "") or
                set(options) - {"NoCopy"} or
                options.get("NoCopy") not in (None, False, True)):
            raise ValueError(f"{name}: custom mount options need an explicit volume transfer")
        matching = [mount for mount in mounts
                    if mount["Destination"] == requested.get("Target") and
                    (not requested.get("Source") or mount["Name"] == requested["Source"])]
        if (len(matching) != 1 or matching[0].get("Type") != "volume" or
                bool(matching[0].get("RW")) == bool(requested.get("ReadOnly"))):
            raise ValueError(f"{name}: Docker mount configuration does not match its private volume")


def validate_security(container):
    name = container["Name"].lstrip("/")
    host = container["HostConfig"]
    if host.get("Privileged"):
        raise ValueError(f"{name}: privileged containers require a manual migration")
    if host.get("CapAdd"):
        raise ValueError(f"{name}: added Linux capabilities require a manual migration")
    if host.get("Devices") or host.get("DeviceRequests") or host.get("DeviceCgroupRules"):
        raise ValueError(f"{name}: host device access requires a manual migration")
    if container.get("AppArmorProfile") or container.get("ProcessLabel"):
        raise ValueError(f"{name}: mandatory access-control profiles need an explicit migration")
    if host.get("Runtime") not in (None, "", "runc"):
        raise ValueError(f"{name}: custom Runtime needs an explicit migration")
    if host.get("CgroupnsMode") not in (None, "", "private"):
        raise ValueError(f"{name}: host cgroup access needs an explicit migration")
    for key, expected in (("MaskedPaths", MASKED_PATHS), ("ReadonlyPaths", READONLY_PATHS)):
        if key in host and set(host[key] or []) != expected:
            raise ValueError(f"{name}: custom {key} must not be silently changed")
    if any(option not in ("no-new-privileges", "no-new-privileges=true", "no-new-privileges:true")
           for option in host.get("SecurityOpt") or []):
        raise ValueError(f"{name}: custom SecurityOpt needs an explicit migration")
    handled = {
        "NetworkMode", "IpcMode", "ShmSize", "PortBindings", "RestartPolicy", "Binds",
        "PidsLimit", "Runtime", "CgroupnsMode", "MaskedPaths", "ReadonlyPaths",
        "SecurityOpt", "CapDrop", "LogConfig", "NanoCpus", "Mounts", *RESOURCE_FLAGS,
    }
    for key, value in host.items():
        if key in handled or value in (None, False, "", [], {}):
            continue
        if key == "ConsoleSize" and value == [0, 0]:
            continue
        # Unknown nondefault settings fail closed, including future Docker
        # device, namespace, runtime, mount and resource options.
        raise ValueError(f"{name}: custom {key} needs an explicit rootless Docker configuration")
    log = host.get("LogConfig") or {}
    if (log.get("Type") not in (None, "", "json-file") or
            (log.get("Config") or {}) not in ({}, {"max-size": "10m", "max-file": "5"})):
        raise ValueError(f"{name}: custom logging needs an explicit migration")


def runtime_arguments(container):
    host = container["HostConfig"]
    arguments = ["--shm-size", str(host["ShmSize"])]
    if host.get("PidsLimit") not in (None, 0, -1):
        arguments.append(f'--pids-limit={host["PidsLimit"]}')
    for key, flag in RESOURCE_FLAGS.items():
        if host.get(key):
            arguments += [flag, str(host[key])]
    if host.get("NanoCpus"):
        arguments += ["--cpus", format(Decimal(host["NanoCpus"]) / 1_000_000_000, "f")]
    arguments += ["--cap-drop", "ALL"]
    for capability in sorted(allowed_capabilities(container)):
        arguments += ["--cap-add", capability]
    if host.get("SecurityOpt"):
        arguments += ["--security-opt", "no-new-privileges"]
    return arguments


def allowed_capabilities(container):
    # Explicit --cap-add gives even non-root processes capabilities. Docker's
    # default non-root process has none, so keep that source boundary.
    user = (container["Config"].get("User") or "").split(":", 1)[0]
    if user and not re.fullmatch(r"[0-9]+", user):
        raise ValueError(f'{container["Name"].lstrip("/")}: named image users need an explicit migration')
    if user and int(user) != 0:
        dropped = {capability.upper().removeprefix("CAP_")
                   for capability in container["HostConfig"].get("CapDrop") or []}
        if "ALL" not in dropped:
            raise ValueError(f'{container["Name"].lstrip("/")}: non-root image users need cap-drop ALL for an exact migration')
        return set()
    # Docker API clients can retain mixed-case names in inspected CapDrop.
    dropped = {capability.upper().removeprefix("CAP_") for capability in container["HostConfig"].get("CapDrop") or []}
    return set() if "ALL" in dropped else DOCKER_CAPABILITIES - dropped


def verify_environment(container, values):
    # The committed image contains the source environment exactly. A temporary
    # empty DOCKER_CONFIG prevents the destination CLI from injecting proxy
    # variables from the user's client configuration.
    def mapping(entries):
        if not isinstance(entries, list) or any(not isinstance(entry, str) or "=" not in entry for entry in entries):
            raise RuntimeError("Cannot verify container environment")
        result = dict(entry.split("=", 1) for entry in entries)
        if len(result) != len(entries):
            raise RuntimeError("Cannot verify duplicate container environment variables")
        return result
    source = mapping(container["Config"].get("Env") or [])
    target = mapping(values)
    if target != source:
        # Environment names and values may contain secrets. Never print them.
        raise RuntimeError("rootless Docker did not preserve the source environment; application was not started")


def verify_runtime(container, ownership=None):
    name = container["Name"].lstrip("/")
    target = inspect(TARGET, "container", name)
    verify_environment(container, target["Config"].get("Env"))
    source_host, target_host = container["HostConfig"], target["HostConfig"]
    if target_host.get("Privileged") is not False:
        raise RuntimeError(f"{name}: refusing privileged destination")
    if target_host.get("Devices") or target_host.get("DeviceRequests") or target_host.get("DeviceCgroupRules"):
        raise RuntimeError(f"{name}: refusing destination device access")
    private_modes = {
        "NetworkMode": "bridge", "IpcMode": "private", "PidMode": "",
        "UTSMode": "", "CgroupnsMode": "private",
    }
    if any(target_host.get(key, "") != value for key, value in private_modes.items()):
        raise RuntimeError(f"{name}: rootless Docker changed a private namespace boundary")
    expected_mounts = sorted((mount["Destination"], destination_volume(container, mount), bool(mount.get("RW")))
                             for mount in container.get("Mounts", []))
    actual_mounts = target.get("Mounts") or []
    if (any(mount.get("Type") != "volume" for mount in actual_mounts) or
            sorted((mount["Destination"], mount["Name"], bool(mount.get("RW"))) for mount in actual_mounts) != expected_mounts):
        raise RuntimeError(f"{name}: destination mounts differ from the validated private volumes")
    expected = {"ShmSize": source_host["ShmSize"]}
    expected.update({key: source_host[key] for key in RESOURCE_FLAGS if source_host.get(key)})
    for key, value in expected.items():
        if target_host.get(key) != value:
            raise RuntimeError(f"{name}: rootless Docker did not preserve {key}; application was not started")
    source_pids = source_host.get("PidsLimit")
    target_pids = target_host.get("PidsLimit")
    if (-1 if source_pids in (None, 0, -1) else source_pids) != (-1 if target_pids in (None, 0, -1) else target_pids):
        raise RuntimeError(f"{name}: rootless Docker did not preserve PidsLimit; application was not started")
    if target_host.get("NanoCpus") != source_host.get("NanoCpus"):
        raise RuntimeError(f"{name}: rootless Docker did not preserve the CPU limit; application was not started")
    if source_host.get("SecurityOpt") and not any(
            option in ("no-new-privileges", "no-new-privileges=true")
            for option in target_host.get("SecurityOpt") or []):
        raise RuntimeError(f"{name}: rootless Docker did not preserve no-new-privileges")
    expected_add = sorted(allowed_capabilities(container))
    actual_add = sorted(capability.upper().removeprefix("CAP_")
                        for capability in target_host.get("CapAdd") or [])
    actual_drop = {capability.upper().removeprefix("CAP_")
                   for capability in target_host.get("CapDrop") or []}
    if actual_add != expected_add or "ALL" not in actual_drop:
        raise RuntimeError(f"{name}: rootless Docker changed the capability ceiling")
    expected_labels = dict(container["Config"].get("Labels") or {})
    expected_labels[LABEL] = container["Id"]
    if ownership is not None:
        expected_labels[OWNERSHIP_LABEL] = ownership
    if target["Config"].get("Labels") != expected_labels:
        raise RuntimeError(f"{name}: rootless Docker changed the container labels")
    source_config = dict(container["Config"])
    target_config = dict(target["Config"])
    for config in (source_config, target_config):
        config.pop("Image", None)
        config.pop("Labels", None)
        # A committed Docker image causes a later `docker create` to report
        # stdout/stderr attachment even when its detached source did not. These
        # flags describe the original create client's stream attachment; they
        # do not change the stored logs or a later `docker attach` operation.
        config.pop("AttachStdout", None)
        config.pop("AttachStderr", None)
    if target_config != source_config:
        changed = sorted(key for key in source_config.keys() | target_config.keys()
                         if source_config.get(key) != target_config.get(key))
        raise RuntimeError(f'{name}: rootless Docker changed application fields: {", ".join(changed)}')
    if target_host.get("PortBindings") != source_host.get("PortBindings"):
        raise RuntimeError(f"{name}: rootless Docker changed the published ports")
    if target_host.get("RestartPolicy") != source_host.get("RestartPolicy"):
        raise RuntimeError(f"{name}: rootless Docker changed the restart policy")
    if target_host.get("LogConfig") != source_host.get("LogConfig"):
        raise RuntimeError(f"{name}: rootless Docker changed the logging policy")


def local_command(args):
    if args[0] == SOURCE:
        return ["/usr/bin/sudo", "/usr/bin/docker", "--host", "unix:///run/docker.sock", *args[1:]]
    if args[0] == TARGET:
        runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        return ["/usr/bin/docker", "--host", f"unix://{runtime}/docker.sock", *args[1:]]
    if args[0] == "target-namespace":
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
        child_pid = (runtime / "dockerd-rootless/child_pid").read_text().strip()
        if not child_pid.isdigit() or int(child_pid) <= 1:
            raise RuntimeError("cannot identify the rootless Docker namespace")
        return ["/usr/bin/nsenter", "-U", "--preserve-credentials", "-m", "-t", child_pid, *args[1:]]
    return args


def run(*args, capture=False):
    environment = os.environ.copy()
    if args[0] == TARGET:
        runtime = environment.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        config = Path(runtime) / "omarchy-rootless-docker-migration-client"
        config.mkdir(mode=0o700, exist_ok=True)
        environment["DOCKER_CONFIG"] = str(config)
        environment.pop("DOCKER_CONTEXT", None)
    result = subprocess.run(local_command(args), check=True, text=True, capture_output=capture, env=environment)
    return result.stdout.strip() if capture else None


def inspect(engine, kind, name):
    return json.loads(run(engine, kind, "inspect", name, capture=True))[0]


def exists(kind, name):
    result = subprocess.run(local_command([TARGET, kind, "inspect", name]),
                            text=True, capture_output=True)
    if result.returncode == 0:
        return True
    subprocess.run(local_command([TARGET, "info"]), check=True,
                   text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return False


def destination_volume(container, mount):
    explicit = any(binding.split(":")[0] == mount["Name"]
                   for binding in container["HostConfig"].get("Binds") or [])
    explicit = explicit or any(requested.get("Source") == mount["Name"]
                               for requested in container["HostConfig"].get("Mounts") or [])
    return mount["Name"] if explicit else f'omarchy-migrated-{mount["Name"]}'


def volume_identity(container, mount):
    # Docker volume create is idempotent rather than exclusive. An unpredictable
    # token lets us prove that the volume returned by that call is the one this
    # migration just requested, even if another client races the predictable
    # destination name between the existence check and creation.
    return f'{container["Id"]}:{mount["Name"]}:{secrets.token_hex(32)}'


def completion_path(identity):
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise ValueError("Unsupported Docker container identity")
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "omarchy/rootless-docker-migration" / identity


def intent_path(identity):
    receipt = completion_path(identity)
    return receipt.with_name(f"{receipt.name}.in-progress")


def write_private_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(payload, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def record_migration_intent(container, stopped_state=None, saved=None, restart_disabled=False):
    state = container["State"]
    if saved is None:
        payload = {
            "source": container["Id"],
            "source_snapshot": snapshot_digest(container),
            "source_snapshot_ignore_restart": snapshot_digest(container, ignore_restart=True),
            "source_restart_policy": deepcopy(container["HostConfig"].get("RestartPolicy") or {}),
            "started_at": state["StartedAt"],
            "target_running": bool(state["Running"]),
            "restart_disabled": False,
            "restore_started": False,
            "start_attempted": False,
            "target_ownership": secrets.token_hex(32),
            "volumes": {},
        }
        if not state["Running"]:
            payload["stopped"] = stopped_identity(state)
    else:
        payload = deepcopy(saved)
    if stopped_state is not None:
        payload["stopped"] = stopped_identity(stopped_state)
        payload["restore_started"] = False
    if restart_disabled:
        payload["restart_disabled"] = True
    write_private_json(intent_path(container["Id"]), payload)
    return payload


def migration_intent(container):
    path = intent_path(container["Id"])
    if not path.exists():
        return None
    try:
        saved = json.loads(path.read_text())
        restart_policy = saved["source_restart_policy"]
        if (saved["source"] != container["Id"] or
                not isinstance(saved["target_running"], bool) or
                not isinstance(saved["restart_disabled"], bool) or
                not isinstance(saved["restore_started"], bool) or
                not isinstance(saved["start_attempted"], bool) or
                not re.fullmatch(r"[a-f0-9]{64}", saved["target_ownership"]) or
                not isinstance(saved["volumes"], dict) or
                not isinstance(restart_policy, dict) or
                not isinstance(saved["started_at"], str)):
            raise ValueError
        exact_snapshot = saved["source_snapshot"] == snapshot_digest(container)
        disabled_snapshot = (
            saved["restart_disabled"] is True and
            (container["HostConfig"].get("RestartPolicy") or {}).get("Name") == "no" and
            saved["source_snapshot_ignore_restart"] == snapshot_digest(container, ignore_restart=True)
        )
        if not exact_snapshot and not disabled_snapshot:
            raise ValueError
        if container["State"]["Running"]:
            resumed_restore = (saved["restore_started"] is True and
                               saved["target_running"] is True and exact_snapshot)
            if (saved["target_running"] is not True or
                    ("stopped" in saved and not resumed_restore) or
                    (saved["started_at"] != container["State"]["StartedAt"] and not resumed_restore)):
                raise ValueError
        else:
            if saved["started_at"] != container["State"]["StartedAt"]:
                raise ValueError
            current_stopped = stopped_identity(container["State"])
            if "stopped" in saved and saved["stopped"] != current_stopped:
                raise ValueError
        return saved
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f'{container["Name"].lstrip("/")}: interrupted migration state changed; inspect both engines') from error


def planned_source(container, intent):
    if intent is None:
        return container
    planned = deepcopy(container)
    planned["HostConfig"]["RestartPolicy"] = deepcopy(intent["source_restart_policy"])
    if snapshot_digest(planned) != intent["source_snapshot"]:
        raise ValueError(f'{container["Name"].lstrip("/")}: interrupted migration cannot reconstruct the source configuration')
    return planned


def clear_migration_intent(identity):
    path = intent_path(identity)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def persist_migration_intent(container, intent):
    write_private_json(intent_path(container["Id"]), intent)
    return intent


def target_owned(container, target, intent):
    labels = target["Config"].get("Labels") or {}
    return (labels.get(LABEL) == container["Id"] and
            labels.get(OWNERSHIP_LABEL) == intent["target_ownership"])


def completed(container, target):
    if (target["Config"].get("Labels") or {}).get(LABEL) != container["Id"]:
        return False
    receipt = completion_path(container["Id"])
    if not receipt.is_file():
        return False
    try:
        saved = json.loads(receipt.read_text())
        return (saved["target"] == target.get("Id") and
                saved["source"] == stopped_identity(container["State"]) and
                isinstance(saved["target_running"], bool) and
                saved["target_running"] == bool(target["State"]["Running"]) and
                saved["source_snapshot"] == snapshot_digest(container) and
                saved["target_snapshot"] == snapshot_digest(target))
    except (ValueError, KeyError, TypeError):
        # Older identity-only receipts cannot prove the source stayed stopped.
        return False


def stopped_identity(state):
    if state["Running"] or not state.get("StartedAt") or not state.get("FinishedAt"):
        raise ValueError("Docker source was restarted or its stopped state cannot be verified")
    return {key: state[key] for key in ("StartedAt", "FinishedAt")}


def record_completion(container, source_state, target_running):
    latest_source = inspect(SOURCE, "container", container["Id"])
    if (stopped_identity(latest_source["State"]) != stopped_identity(source_state) or
            snapshot_digest(latest_source) != snapshot_digest(container)):
        raise RuntimeError(f'{container["Name"].lstrip("/")}: Docker source changed before completion; inspect both engines')
    container = latest_source
    target = inspect(TARGET, "container", container["Name"].lstrip("/"))
    write_private_json(completion_path(container["Id"]), {
        "target": target["Id"], "source": stopped_identity(source_state),
        "target_running": target_running,
        "source_snapshot": snapshot_digest(container),
        "target_snapshot": snapshot_digest(target),
    })


def validate(container):
    name = container["Name"].lstrip("/")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name):
        raise ValueError("Unsupported container name")
    if not re.fullmatch(r"[a-f0-9]{64}", container["Id"]):
        raise ValueError("Unsupported Docker container identity")
    labels = container["Config"].get("Labels") or {}
    if labels.keys() & {LABEL, OWNERSHIP_LABEL}:
        raise ValueError(f"{name}: reserved Omarchy migration labels need an explicit migration")
    state = container["State"]
    if (state.get("Paused") or state.get("Restarting") or state.get("Dead") or
            state.get("RemovalInProgress")):
        raise ValueError(f"{name}: paused or transitional lifecycle state requires an explicit migration")
    allowed_capabilities(container)
    stop_timeout = container["Config"].get("StopTimeout")
    if (stop_timeout is not None and
            (isinstance(stop_timeout, bool) or not isinstance(stop_timeout, int) or stop_timeout < -1)):
        raise ValueError(f"{name}: unsupported stop timeout")
    environment = container["Config"].get("Env") or []
    if (not isinstance(environment, list) or
            any(not isinstance(entry, str) or "=" not in entry for entry in environment) or
            len({entry.split("=", 1)[0] for entry in environment}) != len(environment)):
        raise ValueError(f"{name}: ambiguous container environment needs an explicit migration")
    validate_security(container)
    if container["Config"].get("Domainname"):
        raise ValueError(f"{name}: custom domain names require an explicit rootless Docker configuration")
    health = container["Config"].get("Healthcheck") or {}
    if health.get("StartInterval"):
        raise ValueError(f"{name}: custom health start intervals require an explicit configuration")
    host = container["HostConfig"]
    if host.get("NetworkMode") not in ("default", "bridge"):
        raise ValueError(f"{name}: custom networking requires its original Compose definition")
    # Connecting another network does not update HostConfig.NetworkMode.
    # Only the stock bridge attachment can be recreated without losing intent.
    networks = container.get("NetworkSettings", {}).get("Networks") or {}
    if set(networks) != {"bridge"}:
        raise ValueError(f"{name}: custom network attachments require its original Compose definition")
    if any(networks["bridge"].get(key) for key in ("IPAMConfig", "Links", "DriverOpts", "Aliases")):
        raise ValueError(f"{name}: custom network addressing or aliases need an explicit migration")
    if not isinstance(host.get("ShmSize"), int) or host["ShmSize"] <= 0:
        raise ValueError(f"{name}: unsupported ShmSize")
    if (host.get("PidsLimit") not in (None, 0, -1) and
            (not isinstance(host["PidsLimit"], int) or host["PidsLimit"] <= 0)):
        raise ValueError(f"{name}: unsupported PidsLimit")
    if host.get("PidMode") or host.get("UTSMode") or host.get("UsernsMode"):
        raise ValueError(f"{name}: custom namespaces need an explicit rootless Docker configuration")
    if host.get("IpcMode") not in (None, "", "private"):
        raise ValueError(f"{name}: custom IPC requires its original Compose definition")
    for port, bindings in (host.get("PortBindings") or {}).items():
        if not re.fullmatch(r"\d+/(tcp|udp)", port):
            raise ValueError(f"{name}: unsupported port {port}")
        for binding in bindings or []:
            if binding.get("HostIp") != "127.0.0.1" or not binding.get("HostPort", "").isdigit():
                raise ValueError(f"{name}: only the stock localhost port bindings can migrate automatically")
            minimum = int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text())
            if not max(1, minimum) <= int(binding["HostPort"]) <= 65535:
                raise ValueError(f"{name}: published port needs explicit handling; host policy will not be weakened")
    validate_volumes(container)
    return name


def validate_windows_exception(container):
    name = container["Name"].lstrip("/")
    config = container["Config"]
    host = container["HostConfig"]
    labels = config.get("Labels") or {}
    devices = {(device.get("PathOnHost"), device.get("PathInContainer"))
               for device in host.get("Devices") or []}
    ports = host.get("PortBindings") or {}
    expected_ports = {
        "8006/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8006"}],
        "3389/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3389"}],
        "3389/udp": [{"HostIp": "127.0.0.1", "HostPort": "3389"}],
    }
    mounts = container.get("Mounts") or []
    mounts_by_destination = {mount.get("Destination"): mount for mount in mounts}
    storage = mounts_by_destination.get("/storage") or {}
    shared = mounts_by_destination.get("/shared") or {}
    account = pwd.getpwuid(os.getuid())
    protected = f"/var/lib/omarchy/windows/mounts/users/{account.pw_uid}"
    legacy = account.pw_dir
    previous = f'{Path(account.pw_dir).parent}/.omarchy-windows/users/{account.pw_uid}'
    allowed_mounts = {
        (f"{protected}/storage", f"{protected}/shared"),
        (f"{legacy}/.windows", f"{legacy}/Windows"),
        (f"{previous}/storage", f"{previous}/shared"),
    }
    networks = container.get("NetworkSettings", {}).get("Networks") or {}
    if (name != "omarchy-windows" or
            not re.fullmatch(r"[a-f0-9]{64}", container["Id"]) or
            config.get("Image") not in ("dockurr/windows", "dockurr/windows:latest") or
            labels.get("com.docker.compose.project") != "windows" or
            labels.get("com.docker.compose.service") != "windows" or
            host.get("Privileged") is not False or
            host.get("AutoRemove") not in (None, False) or host.get("ReadonlyRootfs") not in (None, False) or
            {capability.upper().removeprefix("CAP_") for capability in host.get("CapAdd") or []} != {"NET_ADMIN"} or
            host.get("CapDrop") or host.get("DeviceRequests") or host.get("DeviceCgroupRules") or
            host.get("SecurityOpt") or host.get("PidMode") or host.get("UTSMode") or host.get("UsernsMode") or
            host.get("NetworkMode") != "windows_default" or
            host.get("IpcMode") not in (None, "", "private") or
            host.get("CgroupnsMode") not in (None, "", "private") or
            host.get("Runtime") not in (None, "", "runc") or
            devices != {("/dev/kvm", "/dev/kvm"), ("/dev/net/tun", "/dev/net/tun")} or
            len(host.get("Devices") or []) != 2 or
            ports != expected_ports or
            (host.get("RestartPolicy") or {}).get("Name") != "no" or
            len(mounts) != 2 or any(mount.get("Type") != "bind" for mount in mounts) or
            any(mount.get("RW") is not True for mount in mounts) or
            (storage.get("Source"), shared.get("Source")) not in allowed_mounts or
            set(networks) != {"windows_default"}):
        raise ValueError("omarchy-windows: the rootful exception does not match Omarchy's managed Windows VM")
    return name


def pipe(producer, consumer):
    with subprocess.Popen(local_command(producer), stdout=subprocess.PIPE) as source:
        try:
            destination = subprocess.run(local_command(consumer), stdin=source.stdout, check=False)
            source.stdout.close()
            source_code = source.wait()
        except BaseException:
            source.kill()
            source.wait()
            raise
        if source_code or destination.returncode:
            raise RuntimeError("Container image or volume transfer failed; Docker data was retained")


def transfer_volume(volume, target):
    destination = inspect(TARGET, "volume", target)["Mountpoint"]
    # Native tar inside RootlessKit's user/mount namespace preserves numeric
    # container ownership, root mode, PAX timestamps, ACLs and xattrs.
    pipe(["/usr/bin/sudo", "/usr/bin/tar", "--format=pax", "--numeric-owner", "--sparse", "--acls", "--xattrs",
          "--xattrs-include=*", "-C", volume["Mountpoint"], "-cpf", "-", "."],
         ["target-namespace", "/usr/bin/tar", "--numeric-owner", "--same-owner", "--same-permissions",
          "--sparse", "--acls", "--xattrs", "--xattrs-include=*", "-C", destination, "-xpf", "-"])
    source_digest = source_volume_digest(volume)
    verify_volume(target, source_digest)
    return source_digest


def source_volume_digest(volume):
    return run("/usr/bin/sudo", "/usr/bin/python3", TRUSTED_MANIFEST,
               volume["Mountpoint"], capture=True)


def validate_source_volume(container, volume):
    name = container["Name"].lstrip("/")
    if (volume.get("Driver") != "local" or volume.get("Options") or
            VOLUME_LABEL in (volume.get("Labels") or {})):
        raise ValueError(f"{name}: custom volume configuration requires an explicit transfer")


def verify_volume_definition(volume, target, ownership):
    expected_labels = dict(volume.get("Labels") or {})
    expected_labels[VOLUME_LABEL] = ownership
    actual = inspect(TARGET, "volume", target)
    if (actual.get("Name") != target or actual.get("Driver") != "local" or
            actual.get("Options") not in (None, {}) or actual.get("Labels") != expected_labels):
        raise RuntimeError("Destination volume ownership or configuration changed; retained it for inspection")


def validate_volume_record(container, mount, record):
    expected = rf'{container["Id"]}:{re.escape(mount["Name"])}:[a-f0-9]{{64}}'
    if (not isinstance(record, dict) or record.get("source") != mount["Name"] or
            not re.fullmatch(expected, record.get("ownership") or "")):
        raise ValueError(f'{container["Name"].lstrip("/")}: interrupted destination volume record changed')
    return record["ownership"]


def validate_trusted_manifest():
    path = Path(TRUSTED_MANIFEST)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("the packaged rootless Docker volume verifier is missing") from error
    if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
            metadata.st_mode & 0o022):
        raise ValueError("the packaged rootless Docker volume verifier is not trusted")
    for parent in path.parents:
        metadata = parent.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("the packaged rootless Docker volume verifier path is not trusted")


def verify_volume(target, expected):
    destination = inspect(TARGET, "volume", target)["Mountpoint"]
    target_digest = run("target-namespace", "/usr/bin/python3", TRUSTED_MANIFEST,
                        destination, capture=True)
    if expected != target_digest:
        raise RuntimeError("Volume content or metadata verification failed; Docker data was retained")


def source_snapshot(container):
    # Health probes and process IDs are observations, not workload settings.
    # Keep lifecycle timestamps/flags, complete creation/runtime configuration,
    # attachments and security labels so a batch cannot use an obsolete plan.
    fields = ("Id", "Name", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings",
              "AppArmorProfile", "ProcessLabel", "MountLabel", "RestartCount")
    snapshot = {field: container.get(field) for field in fields}
    snapshot["State"] = {key: value for key, value in container["State"].items() if key not in ("Health", "Pid")}
    return snapshot


def snapshot_digest(container, ignore_restart=False):
    fields = ("Id", "Name", "Image", "Config", "HostConfig", "Mounts",
              "AppArmorProfile", "ProcessLabel", "MountLabel")
    snapshot = {field: container.get(field) for field in fields}
    # Docker can rewrite top-level API defaults across a daemon restart (for
    # example HostConfig.Dns changes from null to []). These representations
    # have the same runtime meaning and must not invalidate a durable journal.
    snapshot["HostConfig"] = {
        key: value for key, value in (snapshot["HostConfig"] or {}).items()
        if not (value is None or value is False or value == "" or value == [] or value == {})
    }
    snapshot["Mounts"] = sorted(snapshot["Mounts"] or [],
                                key=lambda mount: json.dumps(mount, sort_keys=True, separators=(",", ":")))
    if ignore_restart:
        snapshot["HostConfig"].pop("RestartPolicy", None)
    networks = container.get("NetworkSettings", {}).get("Networks") or {}
    snapshot["Networks"] = {
        name: {key: network.get(key) for key in ("IPAMConfig", "Links", "Aliases", "DriverOpts")}
        for name, network in networks.items()
    }
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def refresh_source(container, validator=validate):
    latest = inspect(SOURCE, "container", container["Id"])
    if source_snapshot(latest) != source_snapshot(container):
        raise ValueError(f'{container["Name"].lstrip("/")}: Docker source changed after preflight; rerun migration after workloads are stable')
    validator(latest)
    return latest


def configured_stop_timeout(container):
    configured = container["Config"].get("StopTimeout")
    return -1 if configured == -1 else max(120, configured or 0)


def restart_policy_argument(container):
    restart = container["HostConfig"].get("RestartPolicy") or {}
    policy = restart.get("Name") or "no"
    if policy == "on-failure" and restart.get("MaximumRetryCount"):
        policy += f':{restart["MaximumRetryCount"]}'
    return policy


def restore_source(identity, validator=validate):
    current = inspect(SOURCE, "container", identity)
    validator(current)
    intent = migration_intent(current)
    if intent is None:
        return
    planned = planned_source(current, intent)
    desired_restart = planned["HostConfig"].get("RestartPolicy") or {}
    if (current["HostConfig"].get("RestartPolicy") or {}) != desired_restart:
        run(SOURCE, "update", f"--restart={restart_policy_argument(planned)}", identity)
        current = inspect(SOURCE, "container", identity)
    if intent["target_running"]:
        if not current["State"]["Running"]:
            intent["restore_started"] = True
            persist_migration_intent(current, intent)
            run(SOURCE, "start", identity)
    elif current["State"]["Running"]:
        raise RuntimeError(f'{current["Name"].lstrip("/")}: stopped source restarted during recovery')
    restored = inspect(SOURCE, "container", identity)
    validator(restored)
    if (bool(restored["State"]["Running"]) != intent["target_running"] or
            snapshot_digest(restored) != snapshot_digest(planned)):
        raise RuntimeError(f'{restored["Name"].lstrip("/")}: source lifecycle could not be restored')
    # A retry can enter batch quiescing with destination artifacts from an
    # earlier interrupted transfer. If a later workload then fails to quiesce,
    # restore this source without discarding the ownership needed to resume or
    # inspect those artifacts safely.
    if not intent["volumes"] and intent.get("destination") is None and not intent["start_attempted"]:
        clear_migration_intent(identity)


def quiesce(container, validator=validate):
    container = refresh_source(container, validator)
    intent = migration_intent(container)
    planned = planned_source(container, intent)
    if intent is None:
        intent = record_migration_intent(container)
    if container["State"]["Running"]:
        run(SOURCE, "stop", "-t", str(configured_stop_timeout(planned)), container["Id"])
        stopped = inspect(SOURCE, "container", container["Id"])
        state = stopped["State"]
        if state["Running"] or state.get("ExitCode") in (137, 139):
            raise RuntimeError(f'{container["Name"].lstrip("/")}: container did not stop cleanly; migration aborted')
        if snapshot_digest(stopped) != snapshot_digest(container):
            raise RuntimeError(f'{container["Name"].lstrip("/")}: Docker source changed while stopping; migration aborted')
        container = stopped
    state = container["State"]
    stopped_identity(state)
    intent = record_migration_intent(container, state, intent)
    if (container["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no":
        intent = record_migration_intent(container, state, intent, restart_disabled=True)
        run(SOURCE, "update", "--restart=no", container["Id"])
    disabled = inspect(SOURCE, "container", container["Id"])
    validator(disabled)
    if (stopped_identity(disabled["State"]) != stopped_identity(state) or
            snapshot_digest(disabled, ignore_restart=True) != snapshot_digest(planned, ignore_restart=True) or
            (disabled["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no"):
        raise RuntimeError(f'{container["Name"].lstrip("/")}: source changed while being quiesced')
    print(f'{container["Name"].lstrip("/")}: quiesced before rootful Docker access revocation')


def verify_resumable_migration(container, target, intent):
    name = container["Name"].lstrip("/")
    planned = planned_source(container, intent)
    destination = intent.get("destination")
    if (not isinstance(destination, dict) or destination.get("id") != target.get("Id") or
            destination.get("snapshot") != snapshot_digest(target) or
            not target_owned(container, target, intent)):
        raise ValueError(f"{name}: interrupted rootless destination changed; inspect both engines")
    if target["State"]["Running"]:
        if not (intent["target_running"] and intent["start_attempted"]):
            raise ValueError(f"{name}: interrupted rootless destination has an unexpected lifecycle")
    verify_runtime(planned, intent["target_ownership"])

    expected_volumes = {destination_volume(planned, mount): mount
                        for mount in planned.get("Mounts", [])}
    if set(intent["volumes"]) != set(expected_volumes):
        raise ValueError(f"{name}: interrupted destination volume inventory changed")
    for target_name, mount in expected_volumes.items():
        record = intent["volumes"][target_name]
        ownership = validate_volume_record(planned, mount, record)
        if not re.fullmatch(r"[a-f0-9]{64}", record.get("digest") or ""):
            raise ValueError(f"{name}: interrupted destination volume record is incomplete")
        source_volume = inspect(SOURCE, "volume", mount["Name"])
        validate_source_volume(planned, source_volume)
        verify_volume_definition(source_volume, target_name, ownership)
        verify_volume(target_name, record["digest"])
        if source_volume_digest(source_volume) != record["digest"]:
            raise RuntimeError(f"{name}: source volume changed after interruption; inspect both engines")

    state = container["State"]
    if (stopped_identity(state) != intent.get("stopped") or
            snapshot_digest(container, ignore_restart=True) != snapshot_digest(planned, ignore_restart=True)):
        raise RuntimeError(f"{name}: rootful source changed after interruption; inspect both engines")
    return planned, state


def resume_verified_migration(container, target, intent):
    name = container["Name"].lstrip("/")
    planned, state = verify_resumable_migration(container, target, intent)
    if (container["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no":
        intent = record_migration_intent(container, state, intent, restart_disabled=True)
        run(SOURCE, "update", "--restart=no", container["Id"])
    source_after = inspect(SOURCE, "container", container["Id"])
    if (stopped_identity(source_after["State"]) != stopped_identity(state) or
            snapshot_digest(source_after, ignore_restart=True) != snapshot_digest(planned, ignore_restart=True) or
            (source_after["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no"):
        raise RuntimeError(f"{name}: rootful source changed during resumed finalization")

    if intent["target_running"] and not target["State"]["Running"]:
        intent["start_attempted"] = True
        persist_migration_intent(source_after, intent)
        run(TARGET, "start", name)
    target = inspect(TARGET, "container", name)
    if bool(target["State"]["Running"]) != intent["target_running"]:
        raise RuntimeError(f"{name}: resumed destination lifecycle differs from the source")
    verify_runtime(planned, intent["target_ownership"])
    record_completion(source_after, state, intent["target_running"])
    clear_migration_intent(container["Id"])
    print(f"{name}: completed the interrupted rootless Docker migration")


def migrate(container):
    container = refresh_source(container)
    name = container["Name"].lstrip("/")
    identity = container["Id"]
    intent = migration_intent(container)
    if exists("container", name):
        target = inspect(TARGET, "container", name)
        container = refresh_source(container)
        if completed(container, target):
            clear_migration_intent(identity)
            print(f"{name}: already migrated")
            return
        if intent is None or not target_owned(container, target, intent):
            raise ValueError(f"{name}: an existing rootless Docker container needs review; no owned transfer matches it")
        if intent.get("destination") is not None:
            resume_verified_migration(container, target, intent)
            return
        if target["State"]["Running"] or intent["start_attempted"]:
            raise ValueError(f"{name}: an incomplete rootless destination may have run; inspect both engines")
        owned_id = target["Id"]
        run(TARGET, "rm", "--force", owned_id)
        if exists("container", name):
            raise ValueError(f"{name}: rootless destination name was replaced during recovery")
    if completion_path(identity).exists():
        raise ValueError(f"{name}: a previously migrated destination is missing; inspect retained data before retrying")

    container = refresh_source(container)
    intent = migration_intent(container)
    planned = planned_source(container, intent)
    running = intent["target_running"] if intent is not None else bool(container["State"]["Running"])
    created_id = None
    image = None
    image_committed = False
    image_loaded = False
    start_attempted = False
    restart_changed = False
    verified_volumes = {}
    restart = planned["HostConfig"].get("RestartPolicy") or {}
    policy = restart_policy_argument(planned)
    try:
        if intent is None:
            intent = record_migration_intent(container)
        expected_volume_names = {destination_volume(planned, mount) for mount in planned.get("Mounts", [])}
        if set(intent["volumes"]) - expected_volume_names:
            raise ValueError(f"{name}: interrupted destination volume inventory changed")
        run(SOURCE, "stop", "-t", str(configured_stop_timeout(planned)), identity)
        stopped_source = inspect(SOURCE, "container", identity)
        state = stopped_source["State"]
        if state["Running"] or (running and state["ExitCode"] in (137, 139)):
            raise RuntimeError(f"{name}: container did not stop cleanly; transfer aborted")
        stopped_identity(state)
        if snapshot_digest(stopped_source) != snapshot_digest(container):
            raise RuntimeError(f"{name}: Docker source configuration changed while stopping; rerun after workloads are stable")
        container = stopped_source
        intent = record_migration_intent(container, state, intent)
        # Commit includes writable-layer changes and the exact image config.
        # Volume data is copied separately while the source container is stopped.
        image = run(SOURCE, "commit", identity, capture=True)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image or ""):
            raise RuntimeError(f"{name}: Docker did not return a transferable committed image")
        image_committed = True
        if not exists("image", image):
            pipe([SOURCE, "image", "save", image], [TARGET, "image", "load", "--quiet"])
            image_loaded = True
        run(SOURCE, "image", "rm", image)
        image_committed = False
        arguments = [TARGET, "create", "--pull=never", "--name", name,
                     "--label", f"{LABEL}={identity}",
                     "--label", f'{OWNERSHIP_LABEL}={intent["target_ownership"]}', "--privileged=false",
                     "--ipc=private", "--cgroupns=private", "--network=bridge"]
        arguments += runtime_arguments(planned)
        config = planned["Config"]
        if config.get("Hostname"):
            arguments += ["--hostname", config["Hostname"]]
        if config.get("StopTimeout") is not None:
            arguments += ["--stop-timeout", str(config["StopTimeout"])]
        for field, stream in (("AttachStdin", "stdin"), ("AttachStdout", "stdout"), ("AttachStderr", "stderr")):
            if config.get(field):
                arguments += ["--attach", stream]
        if config.get("Tty"):
            arguments += ["--tty"]
        if config.get("OpenStdin"):
            arguments += ["--interactive"]
        arguments += ["--restart", policy]
        for port, bindings in (planned["HostConfig"].get("PortBindings") or {}).items():
            for binding in bindings or []:
                arguments += ["--publish", f'127.0.0.1:{binding["HostPort"]}:{port}']
        for mount in planned.get("Mounts", []):
            volume = inspect(SOURCE, "volume", mount["Name"])
            validate_source_volume(container, volume)
            target = destination_volume(planned, mount)
            record = intent["volumes"].get(target)
            if record is None:
                if exists("volume", target):
                    raise ValueError(f"{name}: destination volume already exists; retained it for inspection")
                ownership = volume_identity(planned, mount)
                record = {"source": mount["Name"], "ownership": ownership}
                intent["volumes"][target] = record
                persist_migration_intent(container, intent)
            else:
                ownership = validate_volume_record(planned, mount, record)
            volume_arguments = [TARGET, "volume", "create"]
            for key, value in (volume.get("Labels") or {}).items():
                volume_arguments += ["--label", f"{key}={value}"]
            volume_arguments += ["--label", f"{VOLUME_LABEL}={ownership}"]
            if not exists("volume", target):
                run(*volume_arguments, target)
            verify_volume_definition(volume, target, ownership)
            digest = transfer_volume(volume, target)
            record["digest"] = digest
            persist_migration_intent(container, intent)
            verified_volumes[target] = (volume, ownership, digest)
            mount_arg = f'type=volume,src={target},dst={mount["Destination"]},volume-nocopy'
            if not mount.get("RW"):
                mount_arg += ",readonly"
            arguments += ["--mount", mount_arg]
        arguments.append(image)
        run(*arguments)
        created_target = inspect(TARGET, "container", name)
        if (not re.fullmatch(r"[a-f0-9]{64}", created_target.get("Id") or "") or
                created_target["State"]["Running"] or not target_owned(planned, created_target, intent)):
            raise RuntimeError(f"{name}: rootless destination ownership could not be proven")
        created_id = created_target["Id"]
        # The container has not started, and volume-nocopy prevents image data
        # from replacing the restored volume contents.
        verify_runtime(planned, intent["target_ownership"])
        for target, expected in verified_volumes.items():
            volume, ownership, digest = expected
            verify_volume_definition(volume, target, ownership)
            verify_volume(target, digest)
            if source_volume_digest(volume) != digest:
                raise RuntimeError(f"{name}: source volume changed during transfer; inspect both engines")
        latest_source = inspect(SOURCE, "container", identity)
        if (stopped_identity(latest_source["State"]) != stopped_identity(state) or
                snapshot_digest(latest_source) != snapshot_digest(container)):
            raise RuntimeError(f"{name}: Docker source changed during transfer; inspect both engines")
        target = inspect(TARGET, "container", created_id)
        if not target_owned(planned, target, intent):
            raise RuntimeError(f"{name}: rootless destination ownership changed during transfer")
        intent["destination"] = {"id": created_id, "snapshot": snapshot_digest(target)}
        persist_migration_intent(container, intent)
        # A later workload may fail, leaving Docker installed. Prevent a daemon
        # restart from reviving this stale source alongside its migrated copy.
        intent = record_migration_intent(container, state, intent, restart_disabled=True)
        restart_changed = True
        run(SOURCE, "update", "--restart=no", identity)
        source_after = inspect(SOURCE, "container", identity)
        if (stopped_identity(source_after["State"]) != stopped_identity(state) or
                snapshot_digest(source_after, ignore_restart=True) != snapshot_digest(planned, ignore_restart=True) or
                (source_after["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no"):
            raise RuntimeError(f"{name}: Docker source changed during finalization; inspect both engines")
        if running:
            # Even a failed start command may have launched an application that
            # accepted writes. From this point the destination is recovery data.
            start_attempted = True
            intent["start_attempted"] = True
            persist_migration_intent(source_after, intent)
            run(TARGET, "start", name)
        # A crash before this receipt leaves the destination for review. Its
        # label alone must never turn a partial transfer into a successful retry.
        target_state = inspect(TARGET, "container", name)["State"]
        if bool(target_state["Running"]) != bool(running):
            raise RuntimeError(f"{name}: destination lifecycle differs from the source")
        verify_runtime(planned, intent["target_ownership"])
        record_completion(source_after, state, bool(running))
        clear_migration_intent(identity)
        print(f"{name}: migrated to rootless Docker; rootful copy retained for recovery")
    except BaseException:
        if intent is None:
            raise
        if start_attempted:
            print(f"{name}: destination start was attempted; both copies were retained for recovery. "
                  "Inspect rootless Docker before resuming the rootful copy or retrying migration.", file=sys.stderr)
            raise
        recovery_failed = False
        try:
            owned_target = inspect(TARGET, "container", created_id or name)
            if not target_owned(planned, owned_target, intent):
                raise RuntimeError("rootless destination ownership changed")
            run(TARGET, "rm", "--force", owned_target["Id"])
        except subprocess.CalledProcessError:
            pass
        except Exception:
            recovery_failed = True
            print(f"{name}: destination cleanup was not ownership-safe; retained it for inspection", file=sys.stderr)
        recovery = []
        if image_loaded:
            recovery.append((TARGET, "image", "rm", image))
        if image_committed:
            recovery.append((SOURCE, "image", "rm", image))
        if restart_changed or (container["HostConfig"].get("RestartPolicy") or {}) != restart:
            recovery.append((SOURCE, "update", f"--restart={policy}", identity))
        if running:
            try:
                intent["restore_started"] = True
                persist_migration_intent(container, intent)
            except Exception:
                recovery_failed = True
                print(f"{name}: source recovery intent could not be saved", file=sys.stderr)
            recovery.append((SOURCE, "start", identity))
        for command in recovery:
            try:
                run(*command)
            except Exception:
                # A failed cleanup must not prevent trying to restart Docker.
                recovery_failed = True
                print(f"{name}: a recovery step failed; inspect both engines before retrying", file=sys.stderr)
        retained_volume = False
        for target in intent["volumes"]:
            try:
                retained_volume = retained_volume or exists("volume", target)
            except Exception:
                recovery_failed = True
                retained_volume = True
        if not recovery_failed and not retained_volume:
            try:
                restored = inspect(SOURCE, "container", identity)
                if (bool(restored["State"]["Running"]) == bool(running) and
                        snapshot_digest(restored) == snapshot_digest(planned)):
                    clear_migration_intent(identity)
            except Exception:
                pass
        raise


def main():
    if os.geteuid() == 0:
        raise ValueError("Run the migration as the desktop user; the destination is always rootless")
    os.environ.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    quiesce_all_mode = sys.argv[1:2] == ["--quiesce-all"]
    if quiesce_all_mode:
        if len(sys.argv) < 3:
            raise ValueError("Expected a Windows identity placeholder before container names")
        windows_identity = sys.argv[2]
        names = sys.argv[3:]
        validate_source_daemon(daemon_security(SOURCE))
        containers = [inspect(SOURCE, "container", name) for name in names]
        volumes = set()
        blockers = []
        for container in containers:
            try:
                validate(container)
            except ValueError as error:
                blockers.append(str(error))
                continue
            for mount in container.get("Mounts", []):
                volume = inspect(SOURCE, "volume", mount["Name"])
                try:
                    validate_source_volume(container, volume)
                except ValueError as error:
                    blockers.append(str(error))
                if mount["Name"] in volumes:
                    blockers.append(f'{container["Name"].lstrip("/")}: custom or shared volumes require an explicit transfer')
                volumes.add(mount["Name"])
        windows = None
        if windows_identity != "-":
            windows = inspect(SOURCE, "container", windows_identity)
            try:
                validate_windows_exception(windows)
            except ValueError as error:
                blockers.append(str(error))
        if blockers:
            raise ValueError("\n".join(blockers))
        if volumes:
            validate_trusted_manifest()
        quiesced = []
        try:
            for container in containers:
                quiesced.append((container["Id"], validate))
                quiesce(container)
            if windows is not None:
                quiesced.append((windows["Id"], validate_windows_exception))
                quiesce(windows, validate_windows_exception)
        except BaseException:
            for identity, validator in reversed(quiesced):
                try:
                    restore_source(identity, validator)
                except Exception:
                    print("A quiesced rootful workload could not be restored; inspect Docker before retrying", file=sys.stderr)
            raise
        return
    restore_windows = sys.argv[1:2] == ["--restore-windows"]
    if restore_windows:
        if len(sys.argv) != 3:
            raise ValueError("Expected one Windows container identity")
        validate_source_daemon(daemon_security(SOURCE))
        restore_source(sys.argv[2], validate_windows_exception)
        print("omarchy-windows: restored after rootful Docker access revocation")
        return
    check_windows = sys.argv[1:2] == ["--check-windows"]
    if check_windows:
        if len(sys.argv) != 3:
            raise ValueError("Expected one Windows container identity")
        validate_source_daemon(daemon_security(SOURCE))
        validate_windows_exception(inspect(SOURCE, "container", sys.argv[2]))
        print("omarchy-windows: verified managed rootful exception")
        return
    check_completed = sys.argv[1:2] == ["--check-completed"]
    check_only = check_completed or sys.argv[1:2] == ["--check"]
    names = sys.argv[2:] if check_only else sys.argv[1:]
    if names:
        validate_source_daemon(daemon_security(SOURCE))
        validate_target_daemon(daemon_security(TARGET))
    containers = [inspect(SOURCE, "container", name) for name in names]
    volumes = set()
    blockers = []
    for container in containers:
        try:
            validate(container)
        except ValueError as error:
            blockers.append(str(error))
            continue
        for mount in container.get("Mounts", []):
            volume = inspect(SOURCE, "volume", mount["Name"])
            try:
                validate_source_volume(container, volume)
            except ValueError as error:
                blockers.append(str(error))
            if mount["Name"] in volumes:
                blockers.append(f'{container["Name"].lstrip("/")}: custom or shared volumes require an explicit transfer')
            volumes.add(mount["Name"])
    if blockers:
        raise ValueError("\n".join(blockers))
    if volumes:
        validate_trusted_manifest()
    if check_completed:
        for container in containers:
            name = container["Name"].lstrip("/")
            if (not exists("container", name) or
                    not completed(container, inspect(TARGET, "container", name)) or
                    (container["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no"):
                raise ValueError(f"{name}: completed transfer changed; Docker must remain available for recovery")
        return
    if not check_completed:
        # Check all destination names before stopping the first source.
        for container in containers:
            name = container["Name"].lstrip("/")
            intent = migration_intent(container)
            if exists("container", name):
                target = inspect(TARGET, "container", name)
                if not completed(container, target):
                    if intent is None or not target_owned(container, target, intent):
                        raise ValueError(f"{name}: an existing rootless Docker container needs review; no owned transfer matches it")
                    if intent.get("destination") is not None:
                        verify_resumable_migration(container, target, intent)
                    elif target["State"]["Running"] or intent["start_attempted"]:
                        raise ValueError(f"{name}: an incomplete rootless destination may have run; inspect both engines")
                continue
            if completion_path(container["Id"]).exists():
                raise ValueError(f"{name}: a previously migrated destination is missing; inspect retained data before retrying")
            for mount in container.get("Mounts", []):
                target = destination_volume(container, mount)
                if exists("volume", target):
                    record = intent["volumes"].get(target) if intent is not None else None
                    source_volume = inspect(SOURCE, "volume", mount["Name"])
                    if record is None:
                        raise ValueError(f"{name}: destination volume already exists; retained it for inspection")
                    ownership = validate_volume_record(container, mount, record)
                    verify_volume_definition(source_volume, target, ownership)
    if check_only:
        for container in containers:
            print(f'{container["Name"].lstrip("/")}: ready for rootless Docker migration')
    if not check_only:
        for container in containers:
            migrate(container)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        # Do not print argv: health commands and volume labels can hold secrets.
        print(f"Rootless Docker migration command failed (exit {error.returncode}); rootful Docker data was retained", file=sys.stderr)
        sys.exit(1)
    except (ValueError, RuntimeError) as error:
        print(f"Rootless Docker migration stopped: {error}", file=sys.stderr)
        sys.exit(1)
