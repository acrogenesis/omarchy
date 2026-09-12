"""Verify that rootful Docker accepts API connections only through its protected Unix socket."""

import json
import os
from pathlib import Path
import re
import sys


EXPECTED_SOCKET = "/run/docker.sock"
INTERNAL_UNIX_SOCKETS = re.compile(
    r"/(?:var/)?run/docker/(?:metrics\.sock|libnetwork/[a-f0-9]+\.sock)"
)


def process_socket_inodes(pid, proc=Path("/proc")):
    if not isinstance(pid, int) or pid <= 1:
        raise RuntimeError("rootful Docker has no valid main process")
    inodes = set()
    try:
        descriptors = (proc / str(pid) / "fd").iterdir()
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)]", target)
            if match:
                inodes.add(match.group(1))
    except FileNotFoundError as error:
        raise RuntimeError("rootful Docker process disappeared while its listeners were checked") from error
    return inodes


def unix_listeners(inodes, proc=Path("/proc")):
    listeners = []
    for line in (proc / "net/unix").read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if (len(fields) >= 7 and fields[3] == "00010000" and fields[4] == "0001" and
                fields[6] in inodes):
            listeners.append(fields[7] if len(fields) == 8 else "")
    return listeners


def has_tcp_listener(inodes, proc=Path("/proc")):
    for table in ("net/tcp", "net/tcp6"):
        for line in (proc / table).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A" and fields[9] in inodes:
                return True
    return False


def configured_hosts(pid, proc=Path("/proc"), filesystem=Path("/")):
    arguments = (proc / str(pid) / "cmdline").read_bytes().split(b"\0")
    arguments = [argument.decode() for argument in arguments if argument]
    hosts = []
    config_path = "/etc/docker/daemon.json"
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument in ("-H", "--host"):
            index += 1
            if index >= len(arguments):
                raise RuntimeError("rootful Docker has an incomplete host option")
            hosts.append(arguments[index])
        elif argument.startswith("-H=") or argument.startswith("--host="):
            hosts.append(argument.split("=", 1)[1])
        elif argument in ("--config-file",):
            index += 1
            if index >= len(arguments):
                raise RuntimeError("rootful Docker has an incomplete config-file option")
            config_path = arguments[index]
        elif argument.startswith("--config-file="):
            config_path = argument.split("=", 1)[1]
        index += 1

    path = filesystem / config_path.lstrip("/")
    configured = json.loads(path.read_text()) if path.exists() else {}
    file_hosts = configured.get("hosts") or []
    if not isinstance(file_hosts, list) or any(not isinstance(host, str) for host in file_hosts):
        raise RuntimeError("rootful Docker has an invalid hosts configuration")
    if hosts and file_hosts:
        raise RuntimeError("rootful Docker has conflicting host configuration")
    return hosts or file_hosts or ["unix:///var/run/docker.sock"]


def verify(pid, proc=Path("/proc"), filesystem=Path("/")):
    inodes = process_socket_inodes(pid, proc)
    listeners = unix_listeners(inodes, proc)
    hosts = configured_hosts(pid, proc, filesystem)
    safe_hosts = (["fd://"], ["unix:///run/docker.sock"], ["unix:///var/run/docker.sock"])
    if (hosts not in safe_hosts or has_tcp_listener(inodes, proc) or
            listeners.count(EXPECTED_SOCKET) != 1 or
            any(path != EXPECTED_SOCKET and not INTERNAL_UNIX_SOCKETS.fullmatch(path)
                for path in listeners)):
        raise RuntimeError("rootful Docker has a custom API listener; remove it before automatic migration")


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        raise SystemExit("usage: rootful-listeners.py DOCKER_PID")
    try:
        verify(int(sys.argv[1]))
    except (OSError, RuntimeError) as error:
        print(f"Rootful Docker listener verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
