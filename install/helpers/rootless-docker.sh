rootless_docker_ensure_subids() {
  local account="$1"

  /usr/bin/python3 - "$account" <<'PY'
import fcntl
import os
import pwd
import stat
import subprocess
import sys


account = pwd.getpwnam(sys.argv[1])
if account.pw_uid == 0:
    raise SystemExit("rootless Docker cannot be configured for root")

lock_path = "/run/lock/omarchy-rootless-docker-subids.lock"
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as lock:
    metadata = os.fstat(lock.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise SystemExit(f"unsafe subordinate-ID lock: {lock_path}")
    fcntl.flock(lock, fcntl.LOCK_EX)

    for path, option in (("/etc/subuid", "--add-subuids"), ("/etc/subgid", "--add-subgids")):
        ranges = []
        try:
            with open(path, encoding="utf-8") as source:
                for number, line in enumerate(source, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        name, start, count = line.split(":")
                        start, count = int(start), int(count)
                    except ValueError as error:
                        raise SystemExit(f"cannot parse {path}:{number}") from error
                    if start < 0 or count <= 0 or start + count - 1 > 4294967295:
                        raise SystemExit(f"invalid subordinate-ID range in {path}:{number}")
                    ranges.append((name, start, count))
        except FileNotFoundError:
            pass

        identities = {account.pw_name, str(account.pw_uid)}
        owned = [(start, count) for name, start, count in ranges if name in identities]
        for owned_start, owned_count in owned:
            if any(other_name not in identities and
                   max(owned_start, other_start) < min(owned_start + owned_count, other_start + other_count)
                   for other_name, other_start, other_count in ranges):
                raise SystemExit(f"overlapping subordinate-ID range for {account.pw_name} in {path}")
        if any(count >= 65536 for _, count in owned):
            continue

        start = max([100000, *(range_start + count for _, range_start, count in ranges)])
        end = start + 65535
        if end > 4294967295:
            raise SystemExit(f"no subordinate-ID range is available in {path}")
        subprocess.run(["/usr/bin/usermod", option, f"{start}-{end}", account.pw_name], check=True)
PY
}
