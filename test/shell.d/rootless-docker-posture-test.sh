#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

for package in docker docker-buildx docker-compose docker-rootless-extras rootlesskit slirp4netns fuse-overlayfs lazydocker; do
  grep -qx "$package" "$ROOT/install/omarchy-base.packages" || fail "rootless Docker dependency is in the base install: $package"
done
pass "the base install keeps Docker tooling and adds the rootless runtime"

grep -q 'systemctl --global enable docker.service' "$ROOT/install/config/enable-services.sh" ||
  fail "fresh installs globally enable the rootless Docker user service"
grep -q 'docker.service' "$ROOT/install/user/first-run/enable-user-units.sh" ||
  fail "first login starts the rootless Docker user service"
grep -q 'rootless_docker_ensure_subids' "$ROOT/install/config/docker.sh" ||
  fail "fresh installs allocate subordinate IDs before rootless Docker starts"
grep -q 'rootless_docker_ensure_subids' "$ROOT/bin/omarchy-provision-owner" ||
  fail "deferred provisioning allocates subordinate IDs"
pass "fresh and deferred installs prepare the rootless user daemon"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
home="$test_dir/home"
mkdir -p "$home/.local/state/omarchy/rootless-docker"
touch "$home/.local/state/omarchy/rootless-docker/enabled"
generator="$ROOT/default/systemd/user-environment-generators/60-omarchy-rootless-docker"
expected="DOCKER_HOST=unix://$test_dir/runtime/docker.sock"
actual=$(HOME="$home" XDG_RUNTIME_DIR="$test_dir/runtime" "$generator")
[[ $actual == "$expected" ]] || fail "the rootless Docker API endpoint is exported" "$actual"
rm "$home/.local/state/omarchy/rootless-docker/enabled"
[[ -z $(HOME="$home" XDG_RUNTIME_DIR="$test_dir/runtime" "$generator") ]] ||
  fail "the API endpoint stays unchanged before migration completes"
pass "the Docker endpoint activates only after rootless setup completes"

migration="$ROOT/migrations/1789164756.sh"
grep -q 'migration_user=$(id -un)' "$migration" || fail "migration trusts the USER environment instead of the current account"
lock_line=$(grep -n '/usr/bin/flock -n' "$migration" | cut -d: -f1)
package_line=$(grep -n '^omarchy-pkg-add docker-rootless-extras' "$migration" | cut -d: -f1)
[[ -n $lock_line && -n $package_line ]] && (( lock_line < package_line )) ||
  fail "same-account migrations are not serialized before any setup or transfer"
completion_line=$(grep -n 'test -f "$machine_state/enabled"' "$migration" | cut -d: -f1)
inventory_line=$(grep -n 'docker_inventory=' "$migration" | cut -d: -f1)
[[ -n $completion_line && -n $inventory_line ]] && (( completion_line < inventory_line )) ||
  fail "later accounts can reach the machine-wide retained rootful store"
grep -q 'machine-wide rootful recovery store was left untouched' "$migration" ||
  fail "later accounts do not have an explicit rootful-store no-op path"
completion_return=$(grep -n 'machine-wide rootful recovery store was left untouched' "$migration" | cut -d: -f1)
later_group_drop=$(sed -n "${completion_line},${completion_return}p" "$migration" | grep -n '^  remove_legacy_docker_group' | cut -d: -f1)
[[ -n $later_group_drop ]] || fail "later accounts retain legacy docker-group membership"
socket_line=$(grep -n "socket_owner=" "$migration" | cut -d: -f1)
[[ -n $socket_line && -n $inventory_line ]] && (( socket_line < inventory_line )) ||
  fail "the legacy group socket remains writable during source migration"
listener_line=$(grep -n '^verify_rootful_listeners$' "$migration" | head -n1 | cut -d: -f1)
[[ -n $listener_line ]] && (( socket_line < listener_line && listener_line < inventory_line )) ||
  fail "custom rootful Docker listeners are not rejected before source migration"
grep -q -- '--check-windows "$windows_id"' "$migration" ||
  fail "the name-based Windows exception is not authenticated against its managed runtime"
windows_secure_line=$(grep -n '^/usr/bin/omarchy-windows-vm __migration-secure$' "$migration" | cut -d: -f1)
[[ -n $windows_secure_line && -n $inventory_line ]] && (( windows_secure_line < inventory_line )) ||
  fail "legacy Windows credentials and mounts are not secured before rootful inventory"
windows_check_line=$(grep -n -- '--check-windows "$windows_id"' "$migration" | head -n1 | cut -d: -f1)
owner_claim_line=$(grep -n 'owner = root / "migration-owner"' "$migration" | cut -d: -f1)
[[ -n $windows_check_line && -n $owner_claim_line ]] && (( windows_check_line < owner_claim_line )) ||
  fail "the machine migration owner is claimed before proving ownership of an existing Windows VM"
quiesce_line=$(grep -n -- '--quiesce-all "$windows_arg"' "$migration" | cut -d: -f1)
restart_line=$(grep -n 'systemctl restart docker.service' "$migration" | cut -d: -f1)
transfer_line=$(grep -n '^  /usr/bin/python3 "$migrator" "${container_names\[@\]}"' "$migration" | cut -d: -f1)
[[ -n $quiesce_line && -n $restart_line && -n $transfer_line ]] &&
  (( inventory_line < quiesce_line && quiesce_line < restart_line && restart_line < transfer_line )) ||
  fail "rootful connections are not revoked between durable quiesce and transfer"
(( $(grep -c '^restrict_rootful_socket$' "$migration") == 2 )) ||
  fail "rootful socket policy is not rechecked after daemon restart"
(( $(grep -c '^verify_rootful_listeners$' "$migration") == 2 )) ||
  fail "rootful Docker listeners are not rechecked after daemon restart"
(( $(grep -c '^verify_rootful_socket_unit$' "$migration") == 2 )) ||
  fail "the effective rootful socket unit is not rechecked after daemon restart"
for property in SocketUser SocketGroup SocketMode Listen; do
  grep -q -- "--property=$property" "$migration" ||
    fail "migration does not verify effective docker.socket $property"
done
grep -q -- '--restore-windows "$windows_id"' "$migration" ||
  fail "a running Windows VM is not restored after rootful connection revocation"
pass "migration serializes ownership, secures Windows, and revokes existing rootful connections"

listener_verifier="$ROOT/default/docker/rootless/rootful-listeners.py"
python3 - "$listener_verifier" <<'PY'
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

spec = importlib.util.spec_from_file_location("rootful_listeners", sys.argv[1])
listeners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(listeners)

with tempfile.TemporaryDirectory() as directory:
    proc = Path(directory)
    descriptors = proc / "4242/fd"
    descriptors.mkdir(parents=True)
    (proc / "net").mkdir()
    (proc / "4242/cmdline").write_bytes(b"/usr/bin/dockerd\0-H\0fd://\0")
    os.symlink("socket:[101]", descriptors / "3")
    (proc / "net/unix").write_text(
        "Num RefCount Protocol Flags Type St Inode Path\n"
        "00000000: 00000002 00000000 00010000 0001 01 101 /run/docker.sock\n"
    )
    tcp_header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    (proc / "net/tcp").write_text(tcp_header)
    (proc / "net/tcp6").write_text(tcp_header)
    listeners.verify(4242, proc, proc)

    os.symlink("socket:[102]", descriptors / "4")
    (proc / "net/tcp").write_text(
        tcp_header +
        "0: 0100007F:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 102\n"
    )
    try:
        listeners.verify(4242, proc, proc)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a rootful TCP API listener was accepted")
print("ok - listener verification accepts only the protected rootful Unix socket")
PY
pass "rootful Docker listener verification rejects extra API endpoints"

grep -q "alias d='docker'" "$ROOT/default/bash/aliases" || fail "the d alias remains Docker"
! rg -q 'sudo[[:space:]]+docker' "$ROOT/bin/omarchy-install-docker-dbs" ||
  fail "development database installs still use rootful Docker"
! rg -q 'pkexec|omarchy-sudo-docker' "$ROOT/bin/omarchy-launch-docker-tui" ||
  fail "lazydocker still crosses a root boundary"
[[ ! -e $ROOT/bin/omarchy-sudo-docker && ! -e $ROOT/bin/omarchy-setup-security-sudoless-docker && ! -e $ROOT/bin/omarchy-remove-security-sudoless-docker ]] ||
  fail "the obsolete docker-group toggle remains installed"
! rg -q 'sudoless-docker|Sudoless Docker' "$ROOT/default/omarchy/omarchy-menu.jsonc" ||
  fail "the obsolete docker-group toggle remains in the menu"
pass "Docker CLI, Compose, Buildx, databases and lazydocker use the user daemon directly"

socket_policy="$ROOT/default/systemd/system/docker.socket.d/10-omarchy-rootful.conf"
grep -qx 'SocketUser=root' "$socket_policy" || fail "the Windows Docker socket is root-owned"
grep -qx 'SocketGroup=root' "$socket_policy" || fail "the Windows Docker socket has no docker-group access"
grep -qx 'SocketMode=0600' "$socket_policy" || fail "the Windows Docker socket is root-only"
grep -q -- '--host unix:///run/docker.sock' "$ROOT/bin/omarchy-windows-vm" ||
  fail "Windows is not pinned to the rootful Docker socket"
grep -q 'sudo "$target" __priv' "$ROOT/bin/omarchy-windows-vm" ||
  fail "terminal Windows operations do not authenticate"
grep -q 'pkexec "$target" __priv' "$ROOT/bin/omarchy-windows-vm" ||
  fail "graphical Windows operations do not authenticate"
pass "Windows remains on an authenticated root-only Docker daemon"
