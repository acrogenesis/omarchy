#!/bin/bash

# Real busctl/boltd calls on a private test bus. Python only supplies UMockdev
# hardware; policy behavior and assertions are Bash.
set -euo pipefail
source "$ROOT/install/helpers/thunderbolt-lock.sh"
source "$ROOT/install/helpers/thunderbolt-lock-setup.sh"
TB_STATE=$TB_TEST_DIR/policy.json TB_RUNTIME=$TB_TEST_DIR/runtime
TB_MARKER=$TB_TEST_DIR/enabled TB_APPROVAL=$TB_TEST_DIR/approval TB_LOCK=$TB_TEST_DIR/lock
# The private fixture has no systemd unit; all device and policy operations are real.
systemctl() { [[ $1 == "is-active" || ( $1 == "start" && $2 == "bolt.service" ) ]]; }
[[ $1 != "daemon" ]] || { tb_lock_daemon; exit; }
exec 9>"$TB_LOCK"
flock 9
case $1 in
  initial)
    printf '%s\n' '{"version":1,"enabled":true,"trusted":{},"enrolled":{},"original_authmode":"enabled"}' >"$TB_STATE"
    touch "$TB_MARKER"
    tb_runtime_prepare
    tb_lock_publish
    tb_inventory | jq -e 'all(.devices[]; .Status | startswith("authorized"))' >/dev/null
    ;;
  lock|unlock) tb_lock_change "$1" ;;
  optional) touch "$TB_APPROVAL"; tb_lock_change unlock ;;
  approve)
    identity=$(tb_snapshot | jq -ce --arg uid "$TB_TEST_UID" '.devices[] | select(.identity.Uid==$uid) | .identity')
    tb_lock_approve "$identity" >/dev/null
    tb_inventory | jq -e --arg uid "$TB_TEST_UID" '.devices[] | select(.Uid==$uid) | .Stored and .Policy=="manual" and (.Status | startswith("authorized"))' >/dev/null
    if [[ $TB_TEST_SECURITY == "secure" ]]; then
      tb_inventory | jq -e --arg uid "$TB_TEST_UID" '.devices[] | select(.Uid==$uid) | .Key=="have"' >/dev/null
      if [[ ! -e $TB_TEST_DIR/key-checksum ]]; then sha256sum "$TB_TEST_KEYS/$TB_TEST_UID" >"$TB_TEST_DIR/key-checksum"; fi
    fi
    ;;
  secure)
    tb_inventory | jq -e --arg uid "$TB_TEST_UID" '.devices[] | select(.Uid==$uid) | (.AuthFlags | contains("secure"))' >/dev/null
    sha256sum --status -c "$TB_TEST_DIR/key-checksum"
    ;;
  forget)
    identity=$(jq -ce --arg uid "$TB_TEST_UID" '.trusted[$uid]' "$TB_STATE")
    tb_lock_forget "$identity" >/dev/null
    ;;
  allowed|blocked)
    inventory=$(tb_inventory)
    jq -e --arg uid "$TB_TEST_UID" --arg desired "$1" '
      .devices[] | select(.Uid==$uid) | if $desired=="allowed" then (.Status | startswith("authorized")) else .Status=="connected" end' <<<"$inventory" >/dev/null
    ;;
  temporary)
    jq -e --arg uid "$TB_TEST_UID" '.trusted[$uid]==null' "$TB_STATE" >/dev/null
    ;;
  runtime-trusted)
    tb_inventory | jq -e --arg uid "$TB_TEST_UID" --argjson runtime "$(tb_runtime)" '
      .devices[] | select(.Uid==$uid) | $runtime.trusted[$uid]=={Uid,Name,Vendor,Secure}' >/dev/null
    ;;
  snapshot)
    snapshot=$(tb_public_snapshot)
    jq -e --arg owner "$(tb_owner)" '.owner==$owner' <<<"$snapshot" >/dev/null
    ;;
  restart-policy)
    rm "$TB_RUNTIME/policy.json"
    tb_runtime_prepare
    tb_lock_change unlock
    ;;
  *) exit 64 ;;
esac
