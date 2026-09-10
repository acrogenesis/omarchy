"""Move Omarchy's local development databases into the desktop user's Podman store."""

import json
import re
import subprocess
import sys
from pathlib import Path


LABEL = "io.omarchy.docker-id"


def run(*args, capture=False):
    result = subprocess.run(args, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def inspect(engine, kind, name):
    command = ["sudo", "docker"] if engine == "docker" else ["podman"]
    return json.loads(run(*command, kind, "inspect", name, capture=True))[0]


def validate(container):
    name = container["Name"].lstrip("/")
    images = {
        r"mysql\d+": "mysql",
        r"postgres\d+": "postgres",
        r"mariadb\d+": "mariadb",
        r"redis": "redis",
        r"mongodb": "mongo",
        r"mssql": "mcr.microsoft.com/mssql/server",
    }
    expected = next((image for pattern, image in images.items() if re.fullmatch(pattern, name)), None)
    image = container["Config"]["Image"].removeprefix("docker.io/").removeprefix("library/")
    if expected is None or image.split(":")[0] != expected:
        raise ValueError(f"{name}: migrate this custom workload with its original Compose definition")
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
    # Docker's stock /dev/shm allocation is 64 MiB. Larger or smaller sizes
    # must not silently become Podman's default during the transfer.
    if host.get("ShmSize") != 64 * 1024 * 1024:
        raise ValueError(f"{name}: custom ShmSize needs an explicit Podman configuration")
    # The stock database installer sets none of these. Refuse custom privileges,
    # mounts and resource constraints rather than silently discarding them.
    # HostConfig.Mounts retains --mount options (including volume subpaths)
    # that the summarized container Mounts list does not describe.
    for key in ("Privileged", "CapAdd", "CapDrop", "Devices", "DeviceRequests", "Binds", "Mounts",
                "Links", "VolumesFrom", "SecurityOpt", "ReadonlyRootfs", "ExtraHosts",
                "Dns", "DnsOptions", "DnsSearch", "GroupAdd", "Tmpfs", "Sysctls",
                "Memory", "MemoryReservation", "MemorySwap", "NanoCpus", "CpuQuota",
                "CpuPeriod", "CpuShares", "CpusetCpus", "CpusetMems", "PidsLimit",
                "PublishAllPorts", "AutoRemove", "Ulimits", "StorageOpt", "Init"):
        if host.get(key):
            raise ValueError(f"{name}: custom {key} needs an explicit Podman configuration")
    if host.get("PidMode") or host.get("UTSMode") or host.get("UsernsMode"):
        raise ValueError(f"{name}: custom namespaces need an explicit Podman configuration")
    if host.get("IpcMode") not in (None, "", "private"):
        raise ValueError(f"{name}: custom IPC requires its original Compose definition")
    for port, bindings in (host.get("PortBindings") or {}).items():
        if not re.fullmatch(r"\d+/(tcp|udp)", port):
            raise ValueError(f"{name}: unsupported port {port}")
        for binding in bindings or []:
            if binding.get("HostIp") != "127.0.0.1" or not binding.get("HostPort", "").isdigit():
                raise ValueError(f"{name}: only the stock localhost port bindings can migrate automatically")
    for mount in container.get("Mounts", []):
        if mount.get("Type") != "volume" or mount.get("Driver") != "local":
            raise ValueError(f"{name}: custom storage requires an explicit volume transfer")
    return name


def pipe(producer, consumer):
    with subprocess.Popen(producer, stdout=subprocess.PIPE) as source:
        try:
            destination = subprocess.run(consumer, stdin=source.stdout, check=False)
            source.stdout.close()
            source_code = source.wait()
        except BaseException:
            source.kill()
            source.wait()
            raise
        if source_code or destination.returncode:
            raise RuntimeError("Container image or volume transfer failed; Docker data was retained")


def health_arguments(config):
    health = config.get("Healthcheck") or {}
    test = health.get("Test") or []
    if not test:
        return []
    if test == ["NONE"]:
        return ["--no-healthcheck"]
    arguments = ["--health-cmd", json.dumps(test)]
    for field, flag in (("Interval", "--health-interval"), ("Timeout", "--health-timeout"),
                        ("StartPeriod", "--health-start-period")):
        if health.get(field):
            arguments += [flag, f"{health[field]}ns"]
    if health.get("Retries"):
        arguments += ["--health-retries", str(health["Retries"])]
    return arguments


def transfer_volume(volume, target):
    destination = inspect("podman", "volume", target)["Mountpoint"]
    # Native tar in the destination user namespace preserves the volume root's
    # mode too; volume import can reset it. PAX retains subsecond timestamps.
    pipe(["sudo", "tar", "--format=pax", "--numeric-owner", "--sparse", "--acls", "--xattrs",
          "--xattrs-include=*", "-C", volume["Mountpoint"], "-cpf", "-", "."],
         ["podman", "unshare", "tar", "--numeric-owner", "--same-owner", "--same-permissions",
          "--sparse", "--acls", "--xattrs", "--xattrs-include=*", "-C", destination, "-xpf", "-"])
    manifest = str(Path(__file__).with_name("volume-manifest.py"))
    source_digest = run("sudo", "python3", manifest, volume["Mountpoint"], capture=True)
    target_digest = run("podman", "unshare", "python3", manifest, destination, capture=True)
    if source_digest != target_digest:
        raise RuntimeError("Volume content or metadata verification failed; Docker data was retained")


def migrate(container):
    name = validate(container)
    identity = container["Id"]
    if subprocess.run(["podman", "container", "exists", name]).returncode == 0:
        target = inspect("podman", "container", name)
        if (target["Config"].get("Labels") or {}).get(LABEL) == identity:
            print(f"{name}: already migrated")
            return
        raise ValueError(f"{name}: a different Podman container already has that name")

    running = container["State"]["Running"]
    created = False
    new_volumes = []
    try:
        run("sudo", "docker", "stop", "-t", "120", identity)
        state = inspect("docker", "container", identity)["State"]
        if state["Running"] or (running and state["ExitCode"] in (137, 139)):
            raise RuntimeError(f"{name}: database did not stop cleanly; transfer aborted")
        image = f"localhost/omarchy-migrated/{name}:{identity[:12]}"
        # Commit includes writable-layer changes and the exact image config.
        # Volume data is copied separately while the source database is stopped.
        run("sudo", "docker", "commit", identity, image)
        pipe(["sudo", "docker", "image", "save", image], ["podman", "image", "load", "--quiet"])
        arguments = ["podman", "create", "--name", name, "--label", f"{LABEL}={identity}"]
        # Podman's default PID limit differs from Docker's unlimited default.
        arguments += ["--pids-limit=-1", "--log-driver", "k8s-file", "--log-opt", "max-size=10mb"]
        config = container["Config"]
        if config.get("Hostname"):
            arguments += ["--hostname", config["Hostname"]]
        if config.get("Tty"):
            arguments += ["--tty"]
        if config.get("OpenStdin"):
            arguments += ["--interactive"]
        # commit/load does not reliably retain runtime health-check overrides.
        arguments += health_arguments(config)
        restart = container["HostConfig"].get("RestartPolicy") or {}
        policy = restart.get("Name") or "no"
        if policy == "on-failure" and restart.get("MaximumRetryCount"):
            policy += f':{restart["MaximumRetryCount"]}'
        arguments += ["--restart", policy]
        for port, bindings in (container["HostConfig"].get("PortBindings") or {}).items():
            for binding in bindings or []:
                arguments += ["--publish", f'127.0.0.1:{binding["HostPort"]}:{port}']
        for mount in container.get("Mounts", []):
            volume = inspect("docker", "volume", mount["Name"])
            if volume.get("Options"):
                raise ValueError(f"{name}: volume driver options require an explicit transfer")
            target = f'omarchy-migrated-{mount["Name"]}'
            if subprocess.run(["podman", "volume", "exists", target]).returncode == 0:
                raise ValueError(f"{name}: destination volume already exists; retained it for inspection")
            run("podman", "volume", "create", target)
            new_volumes.append(target)
            transfer_volume(volume, target)
            access = "rw" if mount.get("RW") else "ro"
            arguments += ["--volume", f'{target}:{mount["Destination"]}:{access},nocopy']
        arguments.append(image)
        run(*arguments)
        created = True
        if running:
            run("podman", "start", name)
        print(f"{name}: migrated to rootless Podman; Docker copy retained for recovery")
    except BaseException:
        if created:
            run("podman", "rm", "--force", name)
        for volume in new_volumes:
            run("podman", "volume", "rm", volume)
        if running:
            run("sudo", "docker", "start", identity)
        raise


def main():
    check_only = sys.argv[1:2] == ["--check"]
    names = sys.argv[2:] if check_only else sys.argv[1:]
    containers = [inspect("docker", "container", name) for name in names]
    volumes = set()
    for container in containers:
        validate(container)
        for mount in container.get("Mounts", []):
            volume = inspect("docker", "volume", mount["Name"])
            if volume.get("Options") or mount["Name"] in volumes:
                raise ValueError("Custom or shared volumes require an explicit transfer before migration")
            volumes.add(mount["Name"])
    if not check_only:
        for container in containers:
            migrate(container)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Podman database migration stopped: {error}", file=sys.stderr)
        sys.exit(1)
