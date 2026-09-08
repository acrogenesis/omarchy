#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

python3 - <<'PY'
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest


class ObserverTest(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.env = os.environ.copy()
    self.env.update(PATH=str(self.root) + ':' + self.env['PATH'], OMARCHY_PATH=str(self.root))
    self.command = [sys.executable, os.environ['ROOT'] + '/shell/launch.py']
    self.stub = self.root / 'quickshell'
    self.stub.write_text('''#!/bin/bash
case $CASE in
  fragmented)
    printf ' FATAL: Failed to initialize graphics '
    sleep 0.05
    printf 'backend for OpenGL.' >&2
    exit 1
    ;;
  reexec)
    printf ' FATAL: Failed to initialize graphics backend for OpenGL.\\n'
    export CASE=reexec-done
    exec "$0" "$@"
    ;;
  reexec-done) printf 're-exec finished\\n'; exit "$FINAL_STATUS" ;;
  recovered-then-unrelated)
    printf ' FATAL: Failed to initialize graphics backend for OpenGL.\\n'
    printf '  INFO: Launching config: "/tmp/test/shell.qml"\\n'
    printf 'display connection closed\\n'
    exit 255
    ;;
  inherited)
    sleep 30 &
    printf '%s' "$!" >"$OMARCHY_PATH/descendant"
    printf ' FATAL: Failed to initialize graphics backend for OpenGL.\\n'
    exit 1
    ;;
  large)
    head -c 2097152 /dev/zero | tr '\\0' x
    printf '\\n FATAL: Failed to initialize graphics backend for OpenGL.\\n'
    exit 1
    ;;
  other)
    printf 'qml: FATAL: Failed to initialize graphics backend for OpenGL.\\n'
    printf ' FATAL: Failed to initialize graphics backend for Vulkan.\\n' >&2
    exit 1
    ;;
  signal)
    trap 'printf stopped >"$OMARCHY_PATH/stopped"; exit 143' TERM
    printf ready >"$OMARCHY_PATH/ready"
    while true; do sleep 0.02; done
    ;;
esac
''')
    self.stub.chmod(0o755)

  def run_case(self, case, **env):
    return subprocess.run(self.command, env=self.env | {'CASE': case} | env,
                          capture_output=True, timeout=5)

  def test_fragmented_stdout_stderr_and_no_final_newline(self):
    result = self.run_case('fragmented')
    self.assertEqual(result.returncode, 78)
    self.assertEqual(result.stdout.strip(), b'FATAL: Failed to initialize graphics backend for OpenGL.')

  def test_fatal_survives_internal_exec(self):
    result = self.run_case('reexec', FINAL_STATUS='1')
    self.assertEqual(result.returncode, 78)
    self.assertIn(b're-exec finished', result.stdout)

  def test_internally_recovered_clean_stop(self):
    self.assertEqual(self.run_case('reexec', FINAL_STATUS='0').returncode, 0)

  def test_new_generation_clears_stale_fatal(self):
    self.assertEqual(self.run_case('recovered-then-unrelated').returncode, 255)

  def test_descendant_cannot_hold_observer_open(self):
    try:
      result = self.run_case('inherited')
      self.assertEqual(result.returncode, 78)
    finally:
      pidfile = self.root / 'descendant'
      if pidfile.exists():
        os.kill(int(pidfile.read_text()), signal.SIGTERM)

  def test_long_unterminated_log_does_not_hide_next_fatal(self):
    result = self.run_case('large')
    self.assertEqual(result.returncode, 78)
    self.assertGreater(len(result.stdout), 2097152)

  def test_other_backends_and_qml_text_are_not_fatal_opengl(self):
    self.assertEqual(self.run_case('other').returncode, 1)

  def test_signal_reaches_child(self):
    import time
    child = subprocess.Popen(self.command, env=self.env | {'CASE': 'signal'},
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
      deadline = time.monotonic() + 5
      while not (self.root / 'ready').exists() and time.monotonic() < deadline:
        time.sleep(0.02)
      self.assertTrue((self.root / 'ready').exists())
      child.terminate()
      child.communicate(timeout=5)
      self.assertEqual(child.returncode, 143)
      self.assertEqual((self.root / 'stopped').read_text(), 'stopped')
    finally:
      if child.poll() is None:
        child.kill()
      child.communicate()


unittest.main(verbosity=2)
PY

pass "the graphics observer follows Quickshell exec, drains logs and forwards signals"
