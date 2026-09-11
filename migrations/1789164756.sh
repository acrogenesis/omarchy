echo "Move development containers to rootless Docker"

migration_uid=$(id -u)
migration_user=$(id -un)
if (( migration_uid == 0 )); then
  echo "Run this migration as the desktop user" >&2
  exit 1
fi

export XDG_RUNTIME_DIR="/run/user/$migration_uid"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
if ! systemctl --user show-environment >/dev/null; then
  echo "Log in as $migration_user and rerun omarchy-migrate. Rootful Docker has not been changed." >&2
  exit 1
fi

omarchy-pkg-add docker-rootless-extras rootlesskit slirp4netns fuse-overlayfs

# Allocate a nonoverlapping subordinate-ID range before the rootless daemon can
# open its store. The root lock also serializes simultaneous user migrations.
sudo /usr/bin/bash -euo pipefail -c '
  # This absolute path is intentional: privileged migration code must come
  # from the root-owned package tree, never a caller-controlled checkout.
  source /usr/share/omarchy/install/helpers/rootless-docker.sh
  rootless_docker_ensure_subids "$1"
' bash "$migration_user"

rootless_state="$HOME/.local/state/omarchy/rootless-docker"
mkdir -p "$HOME/.config/docker" "$rootless_state"
if [[ ! -e $HOME/.config/docker/daemon.json ]]; then
  install -m 0644 "$OMARCHY_PATH/config/docker/daemon.json" "$HOME/.config/docker/daemon.json"
fi

systemctl --user daemon-reload
systemctl --user enable --now docker.service
target_host="unix://$XDG_RUNTIME_DIR/docker.sock"
if ! /usr/bin/docker --host "$target_host" info >/dev/null; then
  echo "Rootless Docker did not start. Rootful Docker has not been changed." >&2
  exit 1
fi

# Completion of the shared rootful-store migration is machine-wide. Later
# accounts only need their own rootless daemon and marker; they must never
# inspect or claim the retained recovery copies owned by the first account.
machine_state=/var/lib/omarchy/rootless-docker
if sudo /usr/bin/test -f "$machine_state/enabled"; then
  sudo /usr/bin/systemctl --global enable docker.service
  touch "$rootless_state/enabled"
  chmod 0600 "$rootless_state/enabled"
  export DOCKER_HOST="$target_host"
  systemctl --user set-environment DOCKER_HOST="$DOCKER_HOST"
  dbus-update-activation-environment --systemd DOCKER_HOST
  echo "Rootless Docker is ready for $migration_user. The machine-wide rootful recovery store was left untouched."
  exit 0
fi

# The rootful store is machine-wide. The first user to begin its transfer owns
# the recovery copies until the migration completes, so another account cannot
# split one source inventory across two private stores.
sudo /usr/bin/python3 - "$migration_uid" "$migration_user" <<'PY'
import fcntl
import os
from pathlib import Path
import stat
import sys


uid, name = int(sys.argv[1]), sys.argv[2]
root = Path("/var/lib/omarchy/rootless-docker")
root.mkdir(mode=0o755, parents=True, exist_ok=True)
lock_fd = os.open("/run/lock/omarchy-rootless-docker-owner.lock",
                  os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
with os.fdopen(lock_fd, "w") as lock:
    metadata = os.fstat(lock.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise SystemExit("unsafe rootless Docker owner lock")
    fcntl.flock(lock, fcntl.LOCK_EX)
    owner = root / "migration-owner"
    expected = f"{uid}:{name}\n"
    if owner.exists():
        if owner.is_symlink() or owner.read_text() != expected:
            raise SystemExit("another user owns the rootful Docker migration; finish it from that account")
    else:
        temporary = root / f".migration-owner.{os.getpid()}"
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(expected)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(owner)
PY

sudo /usr/bin/systemctl start docker.socket
source_host="unix:///run/docker.sock"
docker_inventory=$(sudo /usr/bin/docker --host "$source_host" ps -a --no-trunc --format '{{.ID}} {{.Names}}' | sort)
mapfile -t container_names < <(printf '%s\n' "$docker_inventory" | awk '$2 != "omarchy-windows" { print $2 }')

migrator="$OMARCHY_PATH/default/docker/rootless/migrate.py"
if (( ${#container_names[@]} )); then
  if ! /usr/bin/python3 "$migrator" --check "${container_names[@]}"; then
    echo "Rootful Docker and its data have been retained. This migration remains pending." >&2
    exit 1
  fi
  /usr/bin/python3 "$migrator" "${container_names[@]}"
  /usr/bin/python3 "$migrator" --check-completed "${container_names[@]}"
fi

latest_inventory=$(sudo /usr/bin/docker --host "$source_host" ps -a --no-trunc --format '{{.ID}} {{.Names}}' | sort)
if [[ $latest_inventory != "$docker_inventory" ]]; then
  echo "Rootful Docker containers changed during migration. Both stores were retained; review them and rerun." >&2
  exit 1
fi

# Remove direct access to the rootful Windows daemon immediately, including for
# a login that still carries an old docker supplementary group. The packaged
# socket drop-in preserves this root-only mode after later socket activation.
sudo /usr/bin/systemctl daemon-reload
if sudo /usr/bin/test -S /run/docker.sock; then
  sudo /usr/bin/setfacl -b /run/docker.sock
  sudo /usr/bin/chown root:root /run/docker.sock
  sudo /usr/bin/chmod 0600 /run/docker.sock
fi
socket_owner=$(sudo /usr/bin/stat -Lc '%u:%g:%a' /run/docker.sock)
if [[ $socket_owner != "0:0:600" ]]; then
  echo "The rootful Docker socket could not be restricted to root. This migration remains pending." >&2
  exit 1
fi

if id -nG "$migration_user" | grep -qw docker; then
  sudo /usr/bin/gpasswd -d "$migration_user" docker >/dev/null
  omarchy-state set reboot-required
fi

sudo /usr/bin/systemctl --global enable docker.service
sudo /usr/bin/touch /var/lib/omarchy/rootless-docker/enabled
sudo /usr/bin/chown root:root /var/lib/omarchy/rootless-docker/enabled
sudo /usr/bin/chmod 0644 /var/lib/omarchy/rootless-docker/enabled
touch "$rootless_state/enabled"
chmod 0600 "$rootless_state/enabled"

export DOCKER_HOST="$target_host"
systemctl --user set-environment DOCKER_HOST="$DOCKER_HOST"
dbus-update-activation-environment --systemd DOCKER_HOST

echo "Rootless Docker is ready. Rootful development containers remain stopped as recovery copies; Windows stays on authenticated rootful Docker."
