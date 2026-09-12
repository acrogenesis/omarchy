"""Move compatible rootful containers into the desktop user's rootless Docker store."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from decimal import Decimal
from pathlib import Path


LABEL = "io.omarchy.rootless-docker.source-id"
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
    if user and not user.isdecimal():
        raise ValueError(f'{container["Name"].lstrip("/")}: named image users need an explicit migration')
    if user and int(user) != 0:
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


def verify_runtime(container):
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


def completion_path(identity):
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise ValueError("Unsupported Docker container identity")
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "omarchy/rootless-docker-migration" / identity


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
    receipt = completion_path(container["Id"])
    receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = receipt.with_suffix(f".tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump({"target": target["Id"], "source": stopped_identity(source_state),
                       "target_running": target_running,
                       "source_snapshot": snapshot_digest(container),
                       "target_snapshot": snapshot_digest(target)}, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(receipt)
    finally:
        temporary.unlink(missing_ok=True)


def validate(container):
    name = container["Name"].lstrip("/")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name):
        raise ValueError("Unsupported container name")
    if not re.fullmatch(r"[a-f0-9]{64}", container["Id"]):
        raise ValueError("Unsupported Docker container identity")
    labels = container["Config"].get("Labels") or {}
    if LABEL in labels:
        raise ValueError(f"{name}: reserved Omarchy migration labels need an explicit migration")
    allowed_capabilities(container)
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
    storage_match = re.fullmatch(r"/var/lib/omarchy/windows/mounts/users/([1-9][0-9]*)/storage",
                                 storage.get("Source") or "")
    if (name != "omarchy-windows" or
            not re.fullmatch(r"[a-f0-9]{64}", container["Id"]) or
            config.get("Image") not in ("dockurr/windows", "dockurr/windows:latest") or
            labels.get("com.docker.compose.project") != "windows" or
            labels.get("com.docker.compose.service") != "windows" or
            host.get("Privileged") is not False or
            {capability.upper().removeprefix("CAP_") for capability in host.get("CapAdd") or []} != {"NET_ADMIN"} or
            devices != {("/dev/kvm", "/dev/kvm"), ("/dev/net/tun", "/dev/net/tun")} or
            ports != expected_ports or
            (host.get("RestartPolicy") or {}).get("Name") != "no" or
            len(mounts) != 2 or any(mount.get("Type") != "bind" for mount in mounts) or
            any(mount.get("RW") is not True for mount in mounts) or
            not storage_match or
            shared.get("Source") != f"/var/lib/omarchy/windows/mounts/users/{storage_match.group(1)}/shared"):
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
    if ignore_restart:
        snapshot["HostConfig"] = dict(snapshot["HostConfig"] or {})
        snapshot["HostConfig"].pop("RestartPolicy", None)
    networks = container.get("NetworkSettings", {}).get("Networks") or {}
    snapshot["Networks"] = {
        name: {key: network.get(key) for key in ("IPAMConfig", "Links", "Aliases", "DriverOpts")}
        for name, network in networks.items()
    }
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def refresh_source(container):
    latest = inspect(SOURCE, "container", container["Id"])
    if source_snapshot(latest) != source_snapshot(container):
        raise ValueError(f'{container["Name"].lstrip("/")}: Docker source changed after preflight; rerun migration after workloads are stable')
    validate(latest)
    return latest


def migrate(container):
    container = refresh_source(container)
    name = container["Name"].lstrip("/")
    identity = container["Id"]
    if exists("container", name):
        target = inspect(TARGET, "container", name)
        container = refresh_source(container)
        if completed(container, target):
            print(f"{name}: already migrated")
            return
        raise ValueError(f"{name}: an existing rootless Docker container needs review; no completed transfer matches it")
    if completion_path(identity).exists():
        raise ValueError(f"{name}: a previously migrated destination is missing; inspect retained data before retrying")

    container = refresh_source(container)
    running = container["State"]["Running"]
    created = False
    image = None
    image_loaded = False
    start_attempted = False
    restart_changed = False
    new_volumes = []
    verified_volumes = {}
    try:
        run(SOURCE, "stop", "-t", "120", identity)
        stopped_source = inspect(SOURCE, "container", identity)
        state = stopped_source["State"]
        if state["Running"] or (running and state["ExitCode"] in (137, 139)):
            raise RuntimeError(f"{name}: container did not stop cleanly; transfer aborted")
        stopped_identity(state)
        if snapshot_digest(stopped_source) != snapshot_digest(container):
            raise RuntimeError(f"{name}: Docker source configuration changed while stopping; rerun after workloads are stable")
        container = stopped_source
        # Commit includes writable-layer changes and the exact image config.
        # Volume data is copied separately while the source container is stopped.
        image = run(SOURCE, "commit", identity, capture=True)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image or ""):
            raise RuntimeError(f"{name}: Docker did not return a transferable committed image")
        pipe([SOURCE, "image", "save", image], [TARGET, "image", "load", "--quiet"])
        image_loaded = True
        run(SOURCE, "image", "rm", image)
        arguments = [TARGET, "create", "--pull=never", "--name", name,
                     "--label", f"{LABEL}={identity}", "--privileged=false",
                     "--ipc=private", "--cgroupns=private", "--network=bridge"]
        arguments += runtime_arguments(container)
        config = container["Config"]
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
        restart = container["HostConfig"].get("RestartPolicy") or {}
        policy = restart.get("Name") or "no"
        if policy == "on-failure" and restart.get("MaximumRetryCount"):
            policy += f':{restart["MaximumRetryCount"]}'
        arguments += ["--restart", policy]
        for port, bindings in (container["HostConfig"].get("PortBindings") or {}).items():
            for binding in bindings or []:
                arguments += ["--publish", f'127.0.0.1:{binding["HostPort"]}:{port}']
        for mount in container.get("Mounts", []):
            volume = inspect(SOURCE, "volume", mount["Name"])
            if volume.get("Options"):
                raise ValueError(f"{name}: volume driver options require an explicit transfer")
            target = destination_volume(container, mount)
            if exists("volume", target):
                raise ValueError(f"{name}: destination volume already exists; retained it for inspection")
            volume_arguments = [TARGET, "volume", "create"]
            for key, value in (volume.get("Labels") or {}).items():
                volume_arguments += ["--label", f"{key}={value}"]
            run(*volume_arguments, target)
            new_volumes.append(target)
            verified_volumes[target] = (volume, transfer_volume(volume, target))
            mount_arg = f'type=volume,src={target},dst={mount["Destination"]},volume-nocopy'
            if not mount.get("RW"):
                mount_arg += ",readonly"
            arguments += ["--mount", mount_arg]
        arguments.append(image)
        run(*arguments)
        created = True
        # The container has not started, and volume-nocopy prevents image data
        # from replacing the restored volume contents.
        verify_runtime(container)
        for target, expected in verified_volumes.items():
            volume, digest = expected
            verify_volume(target, digest)
            if source_volume_digest(volume) != digest:
                raise RuntimeError(f"{name}: source volume changed during transfer; inspect both engines")
        latest_source = inspect(SOURCE, "container", identity)
        if (stopped_identity(latest_source["State"]) != stopped_identity(state) or
                snapshot_digest(latest_source) != snapshot_digest(container)):
            raise RuntimeError(f"{name}: Docker source changed during transfer; inspect both engines")
        # A later workload may fail, leaving Docker installed. Prevent a daemon
        # restart from reviving this stale source alongside its migrated copy.
        restart_changed = True
        run(SOURCE, "update", "--restart=no", identity)
        source_after = inspect(SOURCE, "container", identity)
        if (stopped_identity(source_after["State"]) != stopped_identity(state) or
                snapshot_digest(source_after, ignore_restart=True) != snapshot_digest(container, ignore_restart=True) or
                (source_after["HostConfig"].get("RestartPolicy") or {}).get("Name") != "no"):
            raise RuntimeError(f"{name}: Docker source changed during finalization; inspect both engines")
        if running:
            # Even a failed start command may have launched an application that
            # accepted writes. From this point the destination is recovery data.
            start_attempted = True
            run(TARGET, "start", name)
        # A crash before this receipt leaves the destination for review. Its
        # label alone must never turn a partial transfer into a successful retry.
        target_state = inspect(TARGET, "container", name)["State"]
        if bool(target_state["Running"]) != bool(running):
            raise RuntimeError(f"{name}: destination lifecycle differs from the source")
        verify_runtime(container)
        record_completion(source_after, state, bool(running))
        print(f"{name}: migrated to rootless Docker; rootful copy retained for recovery")
    except BaseException:
        if start_attempted:
            print(f"{name}: destination start was attempted; both copies were retained for recovery. "
                  "Inspect rootless Docker before resuming the rootful copy or retrying migration.", file=sys.stderr)
            raise
        recovery = []
        if created:
            recovery.append((TARGET, "rm", "--force", name))
        for volume in new_volumes:
            recovery.append((TARGET, "volume", "rm", volume))
        if image_loaded:
            recovery.append((TARGET, "image", "rm", image))
        if restart_changed:
            recovery.append((SOURCE, "update", f"--restart={policy}", identity))
        if running:
            recovery.append((SOURCE, "start", identity))
        for command in recovery:
            try:
                run(*command)
            except Exception:
                # A failed cleanup must not prevent trying to restart Docker.
                print(f"{name}: a recovery step failed; inspect both engines before retrying", file=sys.stderr)
        raise


def main():
    if os.geteuid() == 0:
        raise ValueError("Run the migration as the desktop user; the destination is always rootless")
    os.environ.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
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
            if volume.get("Options") or mount["Name"] in volumes:
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
    if not check_only:
        # Check all destination names before stopping the first source.
        for container in containers:
            name = container["Name"].lstrip("/")
            if exists("container", name):
                target = inspect(TARGET, "container", name)
                if not completed(container, target):
                    raise ValueError(f"{name}: an existing rootless Docker container needs review; no completed transfer matches it")
                continue
            if completion_path(container["Id"]).exists():
                raise ValueError(f"{name}: a previously migrated destination is missing; inspect retained data before retrying")
            for mount in container.get("Mounts", []):
                if exists("volume", destination_volume(container, mount)):
                    raise ValueError(f"{name}: destination volume already exists; retained it for inspection")
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
