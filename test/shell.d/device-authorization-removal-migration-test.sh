#!/bin/bash

set -euo pipefail

source "$(dirname "$0")/base-test.sh"

if (( EUID != 0 )); then
  if unshare --user --map-root-user true 2>/dev/null; then
    exec unshare --user --map-root-user bash "$0"
  fi
  skip "no unprivileged user namespace; skipping removal checkpoint ownership"
  exit 0
fi

shipped_migration="$ROOT/migrations/1791769486.sh"
[[ -f $shipped_migration ]] || fail "the device authorization removal migration exists"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

root="$test_dir/root"
home="$test_dir/home"
migration="$test_dir/migration.sh"
export CALLS="$test_dir/calls" FAKE_ROOT="$root"

# Run a scratch copy whose machine paths all live under the fake root.
sed -e "s#/etc/#$root/etc/#g" -e "s#/var/#$root/var/#g" -e "s#/run/#$root/run/#g" \
  -e "s#/sys/#$root/sys/#g" -e "s#:-/boot}#:-$root/boot}#" -e "s#/usr/share/polkit-1/#$root/usr/share/polkit-1/#g" \
  "$shipped_migration" >"$migration"

mkdir -p "$test_dir/bin"

cat >"$test_dir/bin/sudo" <<'STUB'
#!/bin/bash
printf 'sudo %s\n' "$*" >>"$CALLS"
if [[ ${PUBLISH_FAIL:-0} == 1 && $1 == "mv" && ${!#} == "$FAKE_ROOT/var/lib/omarchy/usb-authorization-removal/daemon.conf" ]]; then exit 73; fi
exec "$@"
STUB

cat >"$test_dir/bin/systemctl" <<'STUB'
#!/bin/bash
printf 'systemctl %s\n' "$*" >>"$CALLS"
if [[ $* == "restart usbguard.service" ]]; then
  config=$FAKE_ROOT/var/lib/omarchy/usb-authorization-removal
  [[ $(<"$config/rules.conf") == "allow" ]] || exit 1
  grep -qx 'PresentDevicePolicy=apply-policy' "$config/daemon.conf" || exit 1
  grep -Fq "$config/daemon.conf" "$FAKE_ROOT/etc/systemd/system/usbguard.service.d/omarchy-removal.conf" || exit 1
  echo 1 | tee "$FAKE_ROOT"/sys/bus/usb/devices/{usb1,usb2}/authorized_default "$FAKE_ROOT"/sys/bus/usb/devices/1-1/authorized >/dev/null
fi
STUB

# Bolt: devices/<uid>/<Property> and domains/<uid>/BootACL hold JSON values.
cat >"$test_dir/bin/busctl" <<'STUB'
#!/bin/bash
args=()
for arg in "$@"; do [[ $arg == --* ]] || args+=("$arg"); done
object=${args[2]#/org/freedesktop/bolt/}
uid=${object#*/}
file="$FAKE_ROOT/bolt/${object%%/*}/${uid//_/-}/${args[4]}"
case ${args[0]} in
  call)
    kind=devices
    [[ ${args[4]} == "ListDevices" ]] || kind=domains
    for dir in "$FAKE_ROOT/bolt/$kind"/*/; do
      dir=${dir%/}
      uid=${dir##*/}
      printf '/org/freedesktop/bolt/%s/%s\n' "$kind" "${uid//-/_}"
    done | jq -Rnc '{type:"ao",data:[[inputs]]}'
    ;;
  get-property)
    [[ -f $file && -z ${BOLT_READ_FAILS:-} ]] || exit 1
    printf '{"type":"x","data":%s}\n' "$(<"$file")"
    ;;
  set-property)
    [[ -f $file ]] || exit 1
    value=$(printf '%s\n' "${args[@]:7}" | jq -Rnc '[inputs]')
    (( args[6] > 0 )) || value='[]'
    # Like Bolt, refuse a BootACL write that changes nothing.
    [[ $value != "$(jq -c . "$file")" ]] || exit 1
    printf '%s\n' "$value" >"$file"
    ;;
esac
STUB

cat >"$test_dir/bin/boltctl" <<'STUB'
#!/bin/bash
printf 'boltctl %s\n' "$*" >>"$CALLS"
case $2 in
  device.policy) printf '"%s"\n' "$4" >"$FAKE_ROOT/bolt/devices/$3/Policy" ;;
  global.auth-mode) printf '%s\n' "$3" >"$FAKE_ROOT/bolt/authmode" ;;
esac
STUB

# Rebuilds the current entries from the drop-in. Old snapshot entries keep the
# parameter. MKINITCPIO=fail fails; MKINITCPIO=stale "succeeds" without
# rebuilding, like a kernel image that failed inside the Limine hook.
cat >"$test_dir/bin/limine-mkinitcpio" <<'STUB'
#!/bin/bash
printf 'limine-mkinitcpio\n' >>"$CALLS"
[[ ${MKINITCPIO:-} != "fail" ]] || exit 1
[[ ${MKINITCPIO:-} != "stale" ]] || exit 0
parameter=""
[[ ! -e $FAKE_ROOT/etc/limine-entry-tool.d/usb-authorization.conf ]] || parameter=" usbcore.authorized_default=0"
esp=$(sed -n 's/^ESP_PATH="\(.*\)"$/\1/p' "$FAKE_ROOT/etc/default/limine")
esp=${esp:-$FAKE_ROOT/boot}
mkdir -p "$esp/EFI/Linux"
printf 'MZ...cmdline root=x%s...initrd' "$parameter" >"$esp/EFI/Linux/omarchy_linux.efi"
cat >"$esp/limine.conf" <<EOF
/+Omarchy
  comment: machine-id=abc
  //linux
  comment: kernel-id=linux
  path: boot():/EFI/Linux/omarchy_linux.efi#0123
  cmdline: root=x quiet$parameter
     //Snapshots
     ///1
     ////linux
     path: boot():/abc/limine_history/omarchy_linux.efi#4567
     cmdline: root=x usbcore.authorized_default=0
EOF
STUB

cat >"$test_dir/bin/omarchy-pkg-present" <<'STUB'
#!/bin/bash
[[ -e $FAKE_ROOT/packages/$1 ]]
STUB

cat >"$test_dir/bin/omarchy-pkg-drop" <<'STUB'
#!/bin/bash
printf 'omarchy-pkg-drop %s\n' "$*" >>"$CALLS"
rm -f "$FAKE_ROOT/packages/$1" "$FAKE_ROOT/etc/usbguard/rules.conf"
STUB

cat >"$test_dir/bin/pacman" <<'STUB'
#!/bin/bash
exit 1
STUB

chmod +x "$test_dir/bin/"*

grant=$'Devices=list,modify,listen\nPolicy=list\nExceptions=listen'
dock=b8f58780-002a-50c4-ffff-ffffffffffff
other=aaaaaaaa-0000-0000-0000-000000000001
domain=895a5509-000a-3075-ffff-ffffffffffff
gone_domain=895a5509-010a-3075-ffff-ffffffffffff

# A machine that never had the feature, with Bolt in its default mode.
reset_machine() {
  rm -rf "$root" "$home"
  mkdir -p "$root"/{etc/default,var/log,var/lib/omarchy,run,packages,usr/share/polkit-1/actions} \
    "$root/sys/bus/usb/devices"/{usb1,usb2,1-1} "$root/bolt/devices"/{$dock,$other} "$root/bolt/domains/$domain" \
    "$home/.config/systemd/user/graphical-session.target.wants" "$home/.config/systemd/user/graphical-session.target.requires" "$home/.local/state/omarchy"
  echo 'KERNEL_CMDLINE[default]+="quiet"' >"$root/etc/default/limine"
  echo enabled >"$root/bolt/authmode"
  echo '"auto"' >"$root/bolt/devices/$dock/Policy"
  echo 1791668776 >"$root/bolt/devices/$dock/StoreTime"
  echo '"manual"' >"$root/bolt/devices/$other/Policy"
  echo 1700000000 >"$root/bolt/devices/$other/StoreTime"
  echo '["",""]' >"$root/bolt/domains/$domain/BootACL"
  echo 1 | tee "$root"/sys/bus/usb/devices/{usb1,usb2}/authorized_default "$root"/sys/bus/usb/devices/{usb1,usb2,1-1}/authorized >/dev/null
  echo '[2026-01-02T03:04:05-0500] [ALPM] installed jq (1.8)' >"$root/var/log/pacman.log"
  MKINITCPIO=ok "$test_dir/bin/limine-mkinitcpio"
}

# What #11874's default setup left behind on the author's machine.
enable_feature() {
  touch "$root/packages/usbguard"
  echo '[2026-10-10T17:44:55-0400] [ALPM] installed usbguard (1.1.4-11)' >>"$root/var/log/pacman.log"
  mkdir -p "$root/etc/usbguard/IPCAccessControl.d" "$root/etc/omarchy" "$root/var/lib/omarchy/thunderbolt-authorization" \
    "$root/etc/systemd/system/multi-user.target.wants" "$home/.local/state/omarchy/usb-authorization/requests"
  echo 'allow id 1d6b:0002' >"$root/etc/usbguard/rules.conf"
  printf '%s\n' "$grant" >"$root/etc/usbguard/IPCAccessControl.d/tester"
  echo 0 | tee "$root"/sys/bus/usb/devices/{usb1,usb2}/authorized_default >/dev/null
  echo 0 >"$root/sys/bus/usb/devices/1-1/authorized"
  touch "$home/.local/state/omarchy/usb-authorization/policy-generated-by-omarchy"
  touch "$root/usr/share/polkit-1/actions"/org.omarchy.{usb,thunderbolt}.policy
  touch "$home/.config/systemd/user/omarchy-usb-authorization.service"
  ln -s ../omarchy-usb-authorization.service "$home/.config/systemd/user/graphical-session.target.wants/omarchy-usb-authorization.service"
  ln -s ../omarchy-usb-authorization.service "$home/.config/systemd/user/graphical-session.target.requires/omarchy-usb-authorization.service"
  ln -s /usr/lib/systemd/user/omarchy-thunderbolt-authorization.service "$home/.config/systemd/user/graphical-session.target.wants/omarchy-thunderbolt-authorization.service"
  ln -s /etc/systemd/system/omarchy-thunderbolt-authorization.service "$root/etc/systemd/system/multi-user.target.wants/omarchy-thunderbolt-authorization.service"
  touch "$root/etc/omarchy/thunderbolt-authorization.enabled"
  echo disabled >"$root/bolt/authmode"
  echo '"manual"' >"$root/bolt/devices/$dock/Policy"
  cat >"$root/var/lib/omarchy/thunderbolt-authorization/policy.json" <<EOF
{"enabled":true,"original_authmode":"enabled","version":1,
 "enrolled":{"$dock":{"Name":"TS4","StoreTime":1791668776,"Uid":"$dock","Vendor":"CalDigit, Inc."}},
 "trusted":{"$dock":{"Name":"TS4","Uid":"$dock","Vendor":"CalDigit, Inc."}}}
EOF
}

enable_usb_at_boot() {
  mkdir -p "$root/etc/limine-entry-tool.d"
  echo 'KERNEL_CMDLINE[default]+=" usbcore.authorized_default=0"' >"$root/etc/limine-entry-tool.d/usb-authorization.conf"
  printf '%s\n' '# Omarchy USB authorization begin' 'SNAPSHOT_KERNEL_PARAMETERS+=usbcore.authorized_default=0' \
    '# Omarchy USB authorization end' >>"$root/etc/default/limine"
  MKINITCPIO=ok "$test_dir/bin/limine-mkinitcpio"
}

run_migration() {
  : >"$CALLS"
  HOME="$home" USER="${migration_user:-tester}" PATH="$test_dir/bin:$PATH" bash -euo pipefail "$migration" >"$test_dir/output" 2>&1
}

value() { tr -d '\n' <"$root/bolt/$1"; }

reset_machine
run_migration || fail "migration fails on a machine that never had the feature" "$(cat "$test_dir/output")"
! grep -q '^sudo' "$CALLS" || fail "migration asks for sudo on a machine that never had the feature" "$(cat "$CALLS")"
pass "a machine that never had the feature is left alone without sudo"

reset_machine
touch "$root/packages/usbguard"
printf '%s\n' '[2025-03-01T10:00:00-0500] [ALPM] installed usbguard (1.1.3-1)' \
  '[2026-10-10T17:44:55-0400] [ALPM] upgraded usbguard (1.1.3-1 -> 1.1.4-11)' >>"$root/var/log/pacman.log"
run_migration || fail "migration fails beside the user's own USBGuard" "$(cat "$test_dir/output")"
[[ -e $root/packages/usbguard ]] || fail "migration removes a USBGuard installed before Omarchy shipped it"
! grep -q '^sudo' "$CALLS" || fail "migration asks for sudo for a USBGuard it does not own" "$(cat "$CALLS")"
pass "a USBGuard installed before Omarchy shipped it is kept, even after an upgrade"

reset_machine
touch "$root/packages/usbguard"
echo '[2026-10-10T09:00:00-0400] [ALPM] installed usbguard (1.1.4-11)' >>"$root/var/log/pacman.log"
run_migration || fail "migration fails beside a USBGuard without Omarchy's grant" "$(cat "$test_dir/output")"
[[ -e $root/packages/usbguard ]] || fail "migration removes a USBGuard without Omarchy's ownership evidence"
pass "a USBGuard without Omarchy's marker or grant is kept"

reset_machine
enable_feature
run_migration || fail "migration fails on a machine with the feature" "$(cat "$test_dir/output")"
[[ ! -e $root/packages/usbguard ]] || fail "migration keeps the USBGuard Omarchy installed"
[[ $(cat "$root"/sys/bus/usb/devices/*/authorized_default "$root"/sys/bus/usb/devices/*/authorized | sort -u) == "1" ]] ||
  fail "migration leaves USB devices denied after USBGuard exits"
[[ ! -e $root/etc/usbguard ]] || fail "migration leaves Omarchy's USBGuard grants behind" "$(find "$root/etc/usbguard")"
[[ $(value authmode) == "enabled" && $(value devices/$dock/Policy) == '"auto"' ]] ||
  fail "migration does not hand Thunderbolt back to Bolt" "$(value authmode) $(value devices/$dock/Policy)"
[[ $(value devices/$other/Policy) == '"manual"' ]] || fail "migration changes a manual policy Omarchy did not set"
for path in "$root/var/lib/omarchy/thunderbolt-authorization" "$root/etc/omarchy/thunderbolt-authorization.enabled" \
  "$root/etc/systemd/system/multi-user.target.wants/omarchy-thunderbolt-authorization.service" \
  "$root/usr/share/polkit-1/actions/org.omarchy.usb.policy" "$root/usr/share/polkit-1/actions/org.omarchy.thunderbolt.policy" \
  "$home/.local/state/omarchy/usb-authorization" "$home/.config/systemd/user/omarchy-usb-authorization.service" \
  "$home/.config/systemd/user/graphical-session.target.wants/omarchy-usb-authorization.service" \
  "$home/.config/systemd/user/graphical-session.target.wants/omarchy-thunderbolt-authorization.service"; do
  [[ ! -e $path && ! -L $path ]] || fail "migration leaves $path behind"
done
pass "the default feature is removed and devices connect as before"

run_migration || fail "a second run fails" "$(cat "$test_dir/output")"
! grep -q '^sudo' "$CALLS" || fail "a second run asks for sudo" "$(cat "$CALLS")"
pass "a second run is a no-op"

# A deferred install that never finished setup left only the pending marker,
# without changing Bolt's mode; an administrator's own setting stays.
reset_machine
mkdir -p "$root/etc/omarchy"
touch "$root/etc/omarchy/thunderbolt-authorization.pending"
echo disabled >"$root/bolt/authmode"
run_migration || fail "migration fails with only the pending marker" "$(cat "$test_dir/output")"
[[ $(value authmode) == "disabled" ]] || fail "migration enables Bolt authorization it never changed"
[[ ! -e $root/etc/omarchy/thunderbolt-authorization.pending ]] || fail "migration leaves the pending marker"
pass "Bolt's mode is untouched when Omarchy never saved one"

# A first setup failed and its undo deleted policy.json before restoring
# boltd.conf: Bolt's original config survives only in the setup journal.
for original in "$(printf '[config]\nAuthMode = enabled\n' | base64 -w0)" ""; do
  reset_machine
  mkdir -p "$root/etc/omarchy" "$root/var/lib/omarchy/thunderbolt-authorization"
  touch "$root/etc/omarchy/thunderbolt-authorization.enabled"
  echo disabled >"$root/bolt/authmode"
  if [[ -n $original ]]; then
    saved="{\"data\":\"$original\",\"mode\":\"600\"}"
  else
    saved=null
  fi
  echo "{\"files\":{\"/var/lib/boltd/boltd.conf\":$saved},\"units\":{}}" \
    >"$root/var/lib/omarchy/thunderbolt-authorization/setup-recovery.json"
  run_migration || fail "migration fails with only the setup journal" "$(cat "$test_dir/output")"
  [[ $(value authmode) == "enabled" ]] || fail "migration leaves Bolt off when its original config is only in the setup journal"
done
pass "Bolt's original mode is recovered from the setup journal"

# Turning on Thunderbolt Boot was interrupted: the originals are only in the
# recovery journal. One controller's list already matches; another is gone.
reset_machine
enable_feature
echo '"manual"' >"$root/bolt/devices/$other/Policy"
echo '["",""]' >"$root/bolt/domains/$domain/BootACL"
cat >"$root/var/lib/omarchy/thunderbolt-authorization/boot-recovery.json" <<EOF
{"policies":{"$other":"iommu","$dock":"manual"},"acls":{"$domain":["$dock",""]},"state":{}}
EOF
run_migration || fail "migration fails while recovering Thunderbolt Boot" "$(cat "$test_dir/output")"
[[ $(value devices/$other/Policy) == '"iommu"' ]] || fail "migration ignores the Thunderbolt Boot recovery journal"
[[ $(value domains/$domain/BootACL) == "[\"$dock\",\"\"]" ]] || fail "migration does not restore the firmware boot allowlist"
[[ $(value devices/$dock/Policy) == '"auto"' ]] || fail "migration does not hand the enrolled dock back after recovery"
[[ ! -e $root/var/lib/omarchy/thunderbolt-authorization ]] || fail "migration keeps fully restored Thunderbolt state"
pass "an interrupted Thunderbolt Boot is recovered from its journal"

reset_machine
enable_feature
jq --arg d "$domain" --arg g "$gone_domain" --arg dock "$dock" \
  '.boot_protection=true | .boot_original={policies:{($dock):"manual"},acls:{($d):["",""],($g):[""]}}' \
  "$root/var/lib/omarchy/thunderbolt-authorization/policy.json" >"$test_dir/policy.json"
mv "$test_dir/policy.json" "$root/var/lib/omarchy/thunderbolt-authorization/policy.json"
run_migration || fail "migration fails when a list already matches or a controller is gone" "$(cat "$test_dir/output")"
[[ -f $root/var/lib/omarchy/thunderbolt-authorization.unrestored/policy.json ]] ||
  fail "migration discards settings it could not restore"
grep -q "$gone_domain is not present" "$test_dir/output" || fail "migration does not say which controller was skipped"
[[ $(value devices/$dock/Policy) == '"auto"' ]] || fail "migration stops before handing back the dock"
pass "unrestorable firmware settings are kept aside, and matching lists are not rewritten"

# A Bolt read that fails, unlike a record Bolt no longer has, must leave the
# saved settings in place and the migration pending.
reset_machine
enable_feature
BOLT_READ_FAILS=1 run_migration && fail "migration succeeds although Bolt could not be read"
[[ -f $root/var/lib/omarchy/thunderbolt-authorization/policy.json ]] || fail "a failed Bolt read discards the saved settings"
[[ $(<"$root/sys/bus/usb/devices/1-1/authorized") == 1 ]] || fail "failed Bolt restoration must not strand USB devices without approval"
run_migration || fail "migration does not finish once Bolt can be read" "$(cat "$test_dir/output")"
[[ $(value devices/$dock/Policy) == '"auto"' ]] || fail "the retry does not hand back the dock"
pass "a failed Bolt read keeps the saved settings and retries"

# USB at Boot: a failed rebuild, then one that silently leaves the parameter,
# must both keep USBGuard and retry, even though the settings are already gone.
reset_machine
enable_feature
enable_usb_at_boot
MKINITCPIO=fail run_migration && fail "migration succeeds although the boot rebuild failed"
[[ -e $root/packages/usbguard && -e $root/var/lib/omarchy/usb-authorization-boot.removing ]] ||
  fail "a failed rebuild removes USBGuard or forgets to retry"
[[ $(<"$root/sys/bus/usb/devices/1-1/authorized") == 1 ]] || fail "failed cleanup must leave connected USB usable without approval tools"
[[ $(<"$root/etc/usbguard/rules.conf") == 'allow id 1d6b:0002' ]] || fail "recovery must preserve the original policy"
grep -Fqx 'systemctl enable usbguard.service' "$CALLS" || fail "permissive recovery must survive reboot with a restrictive boot image"
PATH="$test_dir/bin:$PATH" systemctl restart usbguard.service || fail "reboot must be able to reuse the persisted permissive config"
[[ ! -L $home/.config/systemd/user/graphical-session.target.requires/omarchy-usb-authorization.service ]] || fail "removed watchers must not retain dangling requires links"
cp "$root/var/lib/omarchy/usb-authorization-removal/daemon.conf" "$test_dir/recovery-config"
PUBLISH_FAIL=1 run_migration && fail "failed config publication must leave migration pending"
cmp "$test_dir/recovery-config" "$root/var/lib/omarchy/usb-authorization-removal/daemon.conf" || fail "failed publication must preserve the previous boot recovery config"
MKINITCPIO=stale run_migration && fail "migration trusts a rebuild that left the parameter" "$(cat "$test_dir/output")"
[[ -e $root/packages/usbguard ]] || fail "migration removes USBGuard while a boot entry still denies USB"
grep -q 'limine-mkinitcpio' "$CALLS" || fail "a retry skips the rebuild once the settings are gone"
MKINITCPIO=ok run_migration || fail "migration fails once the rebuild succeeds" "$(cat "$test_dir/output")"
[[ ! -e $root/packages/usbguard && ! -e $root/var/lib/omarchy/usb-authorization-boot.removing ]] ||
  fail "migration does not finish after a successful rebuild"
[[ ! -e $root/etc/systemd/system/usbguard.service.d/omarchy-removal.conf &&
   ! -e $root/var/lib/omarchy/usb-authorization-removal ]] || fail "successful cleanup must remove its temporary policy override"
grep -q 'usbcore' "$root/etc/default/limine" && fail "migration leaves the snapshot parameter in /etc/default/limine"
pass "USB at Boot is removed only once the rebuilt entries are verified"

# A different user's migration must finish the machine-wide recovery even
# though their home and USBGuard IPC grant contain no legacy ownership evidence.
reset_machine
enable_feature
enable_usb_at_boot
MKINITCPIO=fail run_migration && fail "initial boot cleanup must fail"
rm -f "$home/.local/state/omarchy/usb-authorization/policy-generated-by-omarchy"
migration_user=second run_migration || fail "another user cannot complete the removal checkpoint" "$(cat "$test_dir/output")"
[[ ! -e $root/packages/usbguard && ! -e $root/var/lib/omarchy/usb-authorization-removal &&
   ! -e $root/etc/systemd/system/usbguard.service.d/omarchy-removal.conf &&
   ! -e $root/var/lib/omarchy/usb-authorization-boot.removing ]] || fail "another user's cleanup left permissive USBGuard behind"
grep -Fqx 'systemctl disable --now usbguard.service' "$CALLS" || fail "recovery left the vendor service enabled before default lock setup"
pass "another user completes removal recovery without a legacy marker or IPC grant"

for checkpoint in shared linked; do
  reset_machine
  touch "$root/packages/usbguard"
  if [[ $checkpoint == "shared" ]]; then
    mkdir -m755 "$root/var/lib/omarchy/usb-authorization-removal"
  else
    mkdir -m700 "$root/var/lib/omarchy/unrelated"
    ln -s unrelated "$root/var/lib/omarchy/usb-authorization-removal"
  fi
  run_migration || fail "migration fails beside an independent USBGuard with a $checkpoint recovery path"
  [[ -e $root/packages/usbguard ]] || fail "$checkpoint recovery path claimed an independent USBGuard"
  ! grep -q '^sudo' "$CALLS" || fail "$checkpoint recovery path triggered privileged cleanup"
done
pass "shared or linked recovery directories cannot claim independent USBGuard ownership"

# A boot partition mounted somewhere other than /boot, named by ESP_PATH.
reset_machine
rm -rf "${root:?}/boot"
echo "ESP_PATH=\"$root/efi\"" >>"$root/etc/default/limine"
enable_feature
enable_usb_at_boot
MKINITCPIO=stale run_migration && fail "migration trusts a stale rebuild on a boot partition outside /boot"
MKINITCPIO=ok run_migration || fail "migration does not check the boot partition named by ESP_PATH" "$(cat "$test_dir/output")"
[[ ! -e $root/packages/usbguard ]] || fail "migration keeps USBGuard after a verified rebuild outside /boot"
pass "boot entries are verified on the boot partition named by ESP_PATH"

# Under Secure Boot the signed image's own command line is what boots.
reset_machine
enable_feature
enable_usb_at_boot
mkdir -p "$root/sys/firmware/efi/efivars"
printf '\x06\x00\x00\x00\x01' >"$root/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
sed -i 's/ usbcore.authorized_default=0$//' "$root/boot/limine.conf"
MKINITCPIO=stale run_migration && fail "migration trusts Limine's command line over the signed image's"
MKINITCPIO=ok run_migration || fail "migration fails under Secure Boot after a clean rebuild" "$(cat "$test_dir/output")"
pass "Secure Boot images are checked for the parameter too"

for mode in enabled disabled; do
  reset_machine
  enable_feature
  mkdir -m700 "$root/var/lib/omarchy/usb-authorization-removal"
  touch "$root/etc/omarchy/usb-lock.$mode"
  run_migration || fail "another user's legacy cleanup must preserve the new USB policy"
  [[ -e $root/packages/usbguard && -e $root/etc/omarchy/usb-lock.$mode ]] || fail "legacy cleanup removed the new daemon or mode"
  ! grep -q 'restart usbguard.service\|omarchy-pkg-drop usbguard\|disable --now usbguard.service' "$CALLS" || fail "legacy marker overrode current USB policy ownership"
done
pass "another user's stale legacy marker cannot remove the new lock policy or opt-out"
