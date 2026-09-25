# Shared by the root controller and session commands. These paths are fixed at
# privileged entrypoints; tests may source the functions in an isolated fixture.
TB_STATE=/var/lib/omarchy/thunderbolt-authorization/policy.json
TB_CONFIG=/var/lib/boltd/boltd.conf
TB_MARKER=/etc/omarchy/thunderbolt-authorization.enabled
TB_RUNTIME=/run/omarchy-thunderbolt-authorization
TB_LOCK=/run/lock/omarchy-thunderbolt-authorization.lock
TB_SERVICE=omarchy-thunderbolt-authorization.service
TB_BOLT=org.freedesktop.bolt
TB_MANAGER=org.freedesktop.bolt1.Manager
TB_DEVICE=org.freedesktop.bolt1.Device
TB_DOMAIN=org.freedesktop.bolt1.Domain
TB_PATH=/org/freedesktop/bolt
TB_SYSFS=/sys/bus/thunderbolt/devices

tb_fail() { printf '%s\n' "$*" >&2; return 1; }

tb_json_write() {
  local target=$1 mode=${2:-600} temporary
  temporary=$(mktemp "${target%/*}/.thunderbolt.XXXXXX") || return 1
  if jq -cS . > "$temporary" && chmod "$mode" "$temporary" && sync "$temporary" &&
    mv -fT -- "$temporary" "$target" && sync "${target%/*}"; then
    return 0
  else
    rm -f -- "$temporary"
    return 1
  fi
}

tb_state() {
  jq -ce 'select(.version == 1 and (.trusted | type == "object") and (.enabled | type == "boolean"))' "$TB_STATE"
}

tb_bus() {
  busctl --system --auto-start=no --timeout=10 --json=short "$@"
}

tb_owner() {
  tb_bus call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s "$TB_BOLT" | jq -er '.data[0]'
}

tb_properties() {
  tb_bus call "$1" "$2" org.freedesktop.DBus.Properties GetAll s "$3" | jq -ce '.data[0] | map_values(.data)'
}

tb_set() {
  local owner=$1 path=$2 interface=$3 key=$4 value=$5 signature=${6:-s} current
  local -a values=()
  current=$(tb_properties "$owner" "$path" "$interface") || return 1
  if ! jq -e --arg key "$key" --argjson value "$value" '.[$key] == $value' <<< "$current" >/dev/null; then
    if [[ $signature == "as" ]]; then
      mapfile -t values < <(jq -r '.[]' <<< "$value")
      tb_bus set-property "$owner" "$path" "$interface" "$key" as "${#values[@]}" "${values[@]}" >/dev/null || return 1
    else
      tb_bus set-property "$owner" "$path" "$interface" "$key" s "$(jq -r . <<< "$value")" >/dev/null || return 1
    fi
  fi
  # Bolt rejects no-op BootACL writes; even skipped writes are read back.
  current=$(tb_properties "$owner" "$path" "$interface") || return 1
  jq -e --arg key "$key" --argjson value "$value" '.[$key] == $value' <<< "$current" >/dev/null ||
    tb_fail "Bolt did not retain the requested $key"
}

tb_inventory() {
  local owner manager paths path item inode domains='[]' devices='[]' stored='[]'
  owner=$(tb_owner) || return 1
  manager=$(tb_properties "$owner" "$TB_PATH" "$TB_MANAGER") || return 1
  paths=$(tb_bus call "$owner" "$TB_PATH" "$TB_MANAGER" ListDomains | jq -cer '.data[0]') || return 1
  while IFS= read -r path; do
    item=$(tb_properties "$owner" "$path" "$TB_DOMAIN" | jq -c --arg path "$path" '. + {path:$path}') || return 1
    domains=$(jq -c --argjson item "$item" '. + [$item]' <<< "$domains") || return 1
  done < <(jq -r '.[]' <<< "$paths")
  paths=$(tb_bus call "$owner" "$TB_PATH" "$TB_MANAGER" ListDevices | jq -cer '.data[0]') || return 1
  while IFS= read -r path; do
    item=$(tb_properties "$owner" "$path" "$TB_DEVICE" | jq -c --arg path "$path" '. + {path:$path}') || return 1
    [[ $(jq -r .Type <<< "$item") == "peripheral" ]] || continue
    if jq -e .Stored <<< "$item" >/dev/null; then
      stored=$(jq -c --argjson item "$item" '. + [$item]' <<< "$stored") || return 1
    fi
    [[ $(jq -r .Status <<< "$item") != "disconnected" ]] || continue
    inode=$(stat -Lc '%i' -- "$(jq -r .SysfsPath <<< "$item")") || return 1
    item=$(jq -c --arg inode "$inode" '. + {inode:$inode}' <<< "$item") || return 1
    devices=$(jq -c --argjson item "$item" '. + [$item]' <<< "$devices") || return 1
  done < <(jq -r '.[]' <<< "$paths")
  [[ $(tb_owner) == "$owner" ]] || { tb_fail "Bolt restarted while reading its inventory"; return 1; }
  jq -cn --arg owner "$owner" --argjson manager "$manager" --argjson domains "$domains" \
    --argjson devices "$devices" --argjson stored "$stored" '{owner:$owner,manager:$manager,domains:$domains,devices:$devices,stored:$stored}'
}

tb_read_inventory() {
  local inventory
  inventory=$(tb_inventory) || return 1
  jq -e '.manager.AuthMode == "disabled"' <<< "$inventory" >/dev/null || {
    tb_fail "Bolt automatic authorization is enabled; protection is not active"
    return 1
  }
  printf '%s\n' "$inventory"
}

tb_identity() {
  jq -c --arg owner "$1" --arg generation "$2" \
    '{owner:$owner,generation:$generation,path,inode,Uid,Name,Vendor,Parent,SysfsPath,ConnectTime}'
}

tb_snapshot() {
  local state inventory generation recovery=false
  state=$(tb_state) || return 1
  inventory=$(tb_read_inventory) || return 1
  generation=$(< "$TB_RUNTIME/generation") || return 1
  [[ -f ${TB_STATE%/*}/boot-recovery.json ]] && recovery=true
  jq -c --argjson state "$state" --arg generation "$generation" --argjson recovery "$recovery" \
    --arg error "${1:-}" --argjson time "$(date +%s)" '
    .owner as $owner |
    [.devices[] | . as $d | {
      identity: ({owner:$owner,generation:$generation} + ($d | {path,inode,Uid,Name,Vendor,Parent,SysfsPath,ConnectTime})),
      trusted: ($state.trusted[$d.Uid] == ($d | {Uid,Name,Vendor})),
      status:.Status,stored:.Stored,policy:.Policy,flags:.AuthFlags
    }] as $devices |
    {available:true,time:$time,owner:$owner,generation:$generation,devices:$devices,error:$error,
     boot_protection:($state.boot_protection // false),
     domains:[.domains[] | {Uid,SecurityLevel,IOMMU,BootACL}],
     warnings: ([
       (if $recovery then "A firmware boot-access change needs recovery. Boot protection is not confirmed." else empty end),
       (.domains[] | if .SecurityLevel == "none" then
         "This controller allows PCIe connections in firmware. Select user authorization in firmware settings; Omarchy cannot block its devices before their drivers load."
         else empty end),
       (.domains[] | .SecurityLevel as $level | select(["none","user","secure","dponly","usbonly","nopcie"] | index($level) | not) |
         "The controller authorization mode could not be verified."),
       (.domains[] | select($state.boot_protection and (.SysfsPath == "" or
         (.SecurityLevel != "user" and .SecurityLevel != "secure") or (.BootACL | length == 0) or any(.BootACL[]; . != ""))) |
         "The firmware boot allowlist is not confirmed empty on every controller. Check Thunderbolt Boot before relying on boot protection."),
       ($devices[] | select((.status | startswith("authorized")) and (.trusted | not) and (.flags | contains("boot"))) |
         "An untrusted device was authorized by firmware before Linux started. Disconnect it safely to apply approval on its next connection.")
     ] | unique)}' <<< "$inventory"
}

tb_current() {
  local expected=$1 inventory owner generation device identity
  inventory=$(tb_read_inventory) || return 1
  owner=$(jq -r .owner <<< "$inventory")
  generation=$(< "$TB_RUNTIME/generation") || return 1
  while IFS= read -r device; do
    identity=$(tb_identity "$owner" "$generation" <<< "$device") || return 1
    if jq -e --argjson expected "$expected" '. == $expected' <<< "$identity" >/dev/null; then
      jq -cn --arg owner "$owner" --argjson device "$device" '{owner:$owner,device:$device}'
      return 0
    fi
  done < <(jq -c '.devices[]' <<< "$inventory")
  tb_fail "That Thunderbolt device was removed or changed. Open its latest notification."
}

tb_approve() {
  local identity=$1 permanent=$2 current owner path status state
  state=$(tb_state) || return 1
  jq -e .enabled <<< "$state" >/dev/null || { tb_fail "Thunderbolt protection is disabled"; return 1; }
  current=$(tb_current "$identity") || return 1
  owner=$(jq -r .owner <<< "$current")
  path=$(jq -r .device.path <<< "$current")
  status=$(jq -r .device.Status <<< "$current")
  case "$status" in
    connected|auth-error) tb_bus call "$owner" "$path" "$TB_DEVICE" Authorize s '' >/dev/null || return 1 ;;
    authorized|authorized-newkey|authorized-secure) ;;
    *) tb_fail "Device authorization is still in progress; try again"; return 1 ;;
  esac
  current=$(tb_current "$identity") || return 1
  jq -e '.device.Status | IN("authorized","authorized-newkey","authorized-secure")' <<< "$current" >/dev/null || {
    tb_fail "Could not confirm device authorization; try again"; return 1;
  }
  if [[ $permanent == "true" ]]; then
    if ! jq -e .device.Stored <<< "$current" >/dev/null; then
      tb_bus call "$owner" "$TB_PATH" "$TB_MANAGER" EnrollDevice sss "$(jq -r .device.Uid <<< "$current")" manual '' >/dev/null || return 1
    fi
    current=$(tb_current "$identity") || return 1
    jq -e .device.Stored <<< "$current" >/dev/null || { tb_fail "Could not confirm saved device information; try again"; return 1; }
    jq --argjson device "$(jq -c .device <<< "$current")" '.trusted[$device.Uid] = ($device | {Uid,Name,Vendor})' <<< "$state" |
      tb_json_write "$TB_STATE" || return 1
  fi
  tb_snapshot
}

tb_boot_apply() {
  local saved=$1 inventory owner item uid policies acls value path
  inventory=$(tb_inventory) || return 1
  owner=$(jq -r .owner <<< "$inventory")
  jq -e --argjson saved "$saved" '
    (($saved.policies | keys) - [.stored[].Uid] | length == 0) and
    (($saved.acls | keys) - [.domains[] | select(.SysfsPath != "") | .Uid] | length == 0)' <<< "$inventory" >/dev/null || {
    tb_fail "Reconnect the original controllers and restore missing Bolt records before recovery"; return 1;
  }
  while IFS= read -r item; do
    uid=$(jq -r .Uid <<< "$item")
    value=$(jq -c --arg uid "$uid" '.policies[$uid] // empty' <<< "$saved") || return 1
    [[ -n $value ]] || continue
    tb_set "$owner" "$(jq -r .path <<< "$item")" "$TB_DEVICE" Policy "$value" || return 1
  done < <(jq -c '.stored[]' <<< "$inventory")
  # Changing a device policy can update firmware ACLs, so restore ACLs last.
  while IFS= read -r item; do
    uid=$(jq -r .Uid <<< "$item")
    value=$(jq -c --arg uid "$uid" '.acls[$uid] // empty' <<< "$saved") || return 1
    [[ -n $value ]] || continue
    [[ $(jq length <<< "$value") == "$(jq '.BootACL | length' <<< "$item")" ]] || {
      tb_fail "Firmware boot allowlist capacity changed"; return 1;
    }
    tb_set "$owner" "$(jq -r .path <<< "$item")" "$TB_DOMAIN" BootACL "$value" as || return 1
  done < <(jq -c '.domains[]' <<< "$inventory")
}

tb_reconcile() {
  local inventory state owner generation device identity error='' saved
  state=$(tb_state) || return 1
  inventory=$(tb_read_inventory) || return 1
  owner=$(jq -r .owner <<< "$inventory")
  generation=$(< "$TB_RUNTIME/generation") || return 1
  if jq -e .boot_protection <<< "$state" >/dev/null; then
    saved=$(jq -c '{policies:(.stored | map({key:.Uid,value:"manual"}) | from_entries),
      acls:(.domains | map(select(.SysfsPath != "" and (.SecurityLevel == "user" or .SecurityLevel == "secure") and (.BootACL|length>0))) |
        map({key:.Uid,value:(.BootACL | map(""))}) | from_entries)}' <<< "$inventory") || return 1
    tb_boot_apply "$saved" || return 1
  fi
  while IFS= read -r device; do
    identity=$(tb_identity "$owner" "$generation" <<< "$device") || return 1
    if ! tb_approve "$identity" true >/dev/null; then
      error='A trusted Thunderbolt device could not be restored. Check the system service log.'
    fi
  done < <(jq -c --argjson state "$state" '.devices | sort_by(.SysfsPath | length)[] |
    select((.Status == "connected" or .Status == "auth-error") and (.AuthFlags | contains("nopcie") | not)) |
    select($state.trusted[.Uid] == {Uid,Name,Vendor})' <<< "$inventory")
  tb_snapshot "$error"
}

tb_daemon() {
  local snapshot error
  install -d -m 755 "$TB_RUNTIME"
  cat /proc/sys/kernel/random/uuid > "$TB_RUNTIME/generation"
  chmod 644 "$TB_RUNTIME/generation"
  while [[ -f $TB_MARKER ]]; do
    (
      flock -x 9
      if snapshot=$(tb_reconcile 2> "$TB_RUNTIME/error"); then
        tb_json_write "$TB_RUNTIME/snapshot.json" 644 <<< "$snapshot"
      else
        cat "$TB_RUNTIME/error" >&2
        error=$(< "$TB_RUNTIME/error")
        jq -cn --arg error "$error" --argjson time "$(date +%s)" '{available:false,time:$time,error:$error}' |
          tb_json_write "$TB_RUNTIME/snapshot.json" 644
      fi
    ) 9> "$TB_LOCK"
    sleep 2
  done
}

tb_public_snapshot() {
  local snapshot generation
  snapshot=$(cat "$TB_RUNTIME/snapshot.json") || return 1
  generation=$(< "$TB_RUNTIME/generation") || return 1
  jq -e --argjson now "$(date +%s)" --arg generation "$generation" \
    '.available and .generation == $generation and .time <= $now and $now - .time < 20' <<< "$snapshot" >/dev/null || {
    tb_fail 'Thunderbolt policy is unavailable or could not be verified.'; return 1;
  }
  printf '%s\n' "$snapshot"
}
