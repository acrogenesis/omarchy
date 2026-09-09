#!/bin/bash

set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/base-test.sh"

set -- help
source "$ROOT/bin/omarchy-windows-vm" >/dev/null

assert_mounts_safe() { :; }
dc() { fail "running container should not be recreated"; }
sleep() { :; }

state=running
rdp_checks=0
podman() {
  case "$1:$2" in
    inspect:*Status*) printf '%s\n' "$state" ;;
    inspect:*StartedAt*)
      [[ $2 == *'json .State.StartedAt'* ]] || fail "Podman timestamp must be encoded as JSON"
      echo '"2026-09-09T12:00:00Z"' ;;
    logs:--since) echo 'Windows started successfully' ;;
    *) fail "unexpected Podman command: $*" ;;
  esac
}
nc() {
  [[ $* == '-z -w 1 127.0.0.1 3389' ]] || fail "readiness must probe the local RDP listener"
  ((++rdp_checks >= 3))
}
__priv_up_wait || fail "ready Windows VM failed to launch"
((rdp_checks == 3)) || fail "QEMU startup log was mistaken for Windows readiness"
pass "launch waits for RDP after QEMU announces startup"

state=exited
dc() { :; }
__priv_up_wait 2>/dev/null && fail "an exited installer was reported ready"
pass "launch reports a stopped installer without waiting for the full deadline"

state=running
nc() { return 1; }
__priv_up_wait 2>/dev/null && fail "launch succeeded without RDP"
pass "unavailable RDP reaches a bounded failure"
