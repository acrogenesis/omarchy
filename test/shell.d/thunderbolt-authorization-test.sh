#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

/usr/bin/python3 "$ROOT/test/shell.d/fixtures/thunderbolt/policy-test.py" "$ROOT"

if [[ -n ${BOLT_TEST_SOURCE:-} ]]; then
  /usr/bin/python3 "$ROOT/test/shell.d/fixtures/thunderbolt/bolt-integration.py" "$ROOT"
else
  skip "real boltd integration needs BOLT_TEST_SOURCE and an UMockdev environment"
fi
