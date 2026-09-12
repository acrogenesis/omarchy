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
grep -q -- '--check-windows "$windows_id"' "$migration" ||
  fail "the name-based Windows exception is not authenticated against its managed runtime"
windows_secure_line=$(grep -n '^/usr/bin/omarchy-windows-vm __migration-secure$' "$migration" | cut -d: -f1)
[[ -n $windows_secure_line && -n $inventory_line ]] && (( windows_secure_line < inventory_line )) ||
  fail "legacy Windows credentials and mounts are not secured before rootful inventory"
pass "migration serializes ownership, restricts the source socket, and validates the Windows exception"

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
