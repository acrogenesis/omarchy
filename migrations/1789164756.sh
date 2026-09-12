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

remove_legacy_docker_group() {
  if id -nG "$migration_user" | grep -qw docker; then
    sudo /usr/bin/gpasswd -d "$migration_user" docker >/dev/null
    omarchy-state set reboot-required
  fi
}

# A second invocation by the same account could otherwise race destination
# creation and let one rollback disturb the other's transfer.
exec {migration_lock_fd}>"$XDG_RUNTIME_DIR/omarchy-rootless-docker-migration.lock"
if ! /usr/bin/flock -n "$migration_lock_fd"; then
  echo "Another rootless Docker migration is already running for $migration_user." >&2
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
  remove_legacy_docker_group
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

# Migrate any legacy user-side definition, pin its data into the protected root
# anchors, and rewrite the credential-bearing Compose file to root:root 0600.
# This performs no Docker lifecycle action.
/usr/bin/omarchy-windows-vm __migration-secure

sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl start docker.socket
source_host="unix:///run/docker.sock"

restrict_rootful_socket() {
  local socket_owner
  if sudo /usr/bin/test -S /run/docker.sock; then
    sudo /usr/bin/setfacl -b /run/docker.sock
    sudo /usr/bin/chown root:root /run/docker.sock
    sudo /usr/bin/chmod 0600 /run/docker.sock
  fi
  socket_owner=$(sudo /usr/bin/stat -Lc '%u:%g:%a' /run/docker.sock)
  if [[ $socket_owner != "0:0:600" ]]; then
    echo "The rootful Docker socket could not be restricted to root. This migration remains pending." >&2
    return 1
  fi
}

# Load the packaged socket policy and prevent new unprivileged rootful clients
# before taking the source inventory. Existing accepted connections are closed
# by the daemon restart after every workload has been safely quiesced below.
restrict_rootful_socket
remove_legacy_docker_group

docker_inventory=$(sudo /usr/bin/docker --host "$source_host" ps -a --no-trunc --format '{{.ID}} {{.Names}}' | sort)
migrator="$OMARCHY_PATH/default/docker/rootless/migrate.py"
container_names=()
windows_id=""
while read -r container_id container_name; do
  [[ -n $container_id ]] || continue
  if [[ $container_name == "omarchy-windows" ]]; then
    windows_id="$container_id"
  else
    container_names+=("$container_name")
  fi
done <<<"$docker_inventory"

# A container is exempt from rootless transfer only when its immutable runtime
# identity matches the Windows VM Omarchy manages through authenticated actions.
if [[ -n $windows_id ]]; then
  /usr/bin/python3 "$migrator" --check-windows "$windows_id"
fi

if (( ${#container_names[@]} )); then
  if ! /usr/bin/python3 "$migrator" --check "${container_names[@]}"; then
    echo "Rootful Docker and its data have been retained. This migration remains pending." >&2
    exit 1
  fi
fi

if [[ -n $windows_id ]]; then
  windows_arg=$windows_id
else
  windows_arg="-"
fi
/usr/bin/python3 "$migrator" --quiesce-all "$windows_arg" "${container_names[@]}"

# All source restart policies and lifecycle intent are durable before this
# restart. Stopping the daemon closes rootful connections accepted before the
# socket became root-only; those clients cannot reconnect afterward.
sudo /usr/bin/systemctl restart docker.service
sudo /usr/bin/systemctl start docker.socket
restrict_rootful_socket

revoked_inventory=$(sudo /usr/bin/docker --host "$source_host" ps -a --no-trunc --format '{{.ID}} {{.Names}}' | sort)
if [[ $revoked_inventory != "$docker_inventory" ]]; then
  echo "Rootful Docker containers changed while access was being revoked. Workloads remain journaled for recovery." >&2
  exit 1
fi

if [[ -n $windows_id ]]; then
  /usr/bin/python3 "$migrator" --check-windows "$windows_id"
  /usr/bin/python3 "$migrator" --restore-windows "$windows_id"
fi

if (( ${#container_names[@]} )); then
  /usr/bin/python3 "$migrator" --check "${container_names[@]}"
  /usr/bin/python3 "$migrator" "${container_names[@]}"
  /usr/bin/python3 "$migrator" --check-completed "${container_names[@]}"
fi

latest_inventory=$(sudo /usr/bin/docker --host "$source_host" ps -a --no-trunc --format '{{.ID}} {{.Names}}' | sort)
if [[ $latest_inventory != "$docker_inventory" ]]; then
  echo "Rootful Docker containers changed during migration. Both stores were retained; review them and rerun." >&2
  exit 1
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
