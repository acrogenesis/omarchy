"""Observe Quickshell's fatal graphics errors without retaining its log in RAM.

Quickshell can re-exec itself from a crash handler. Keep observing that PID and
only ask the launcher for a different renderer when the process actually exits.
An internally recovered shell and a deliberate clean stop are left alone.
"""

import os
import selectors
import signal
import subprocess
import sys


GRAPHICS_FAILURE = 78
FATAL_OPENGL = b"FATAL: Failed to initialize graphics backend for OpenGL."
MESA_VENDOR = "/usr/share/glvnd/egl_vendor.d/50_mesa.json"


def launch(software=False):
  env = os.environ.copy()
  if software:
    env.update(
      LIBGL_ALWAYS_SOFTWARE="1",
      __EGL_VENDOR_LIBRARY_FILENAMES=MESA_VENDOR,
      __GLX_VENDOR_LIBRARY_NAME="mesa",
      QSG_RHI_BACKEND="opengl",
    )

  child = None
  stopping = False

  def stop(signum, _frame):
    nonlocal stopping
    stopping = True
    if child is not None:
      child.send_signal(signum)

  for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(signum, stop)

  graphics_failed = False
  pending = b""

  def forward(chunk):
    nonlocal graphics_failed, pending
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    lines = (pending + chunk).split(b"\n")
    pending = lines.pop()[-4096:]
    for line in lines:
      line = line.strip()
      # A successful internal restart must not poison an unrelated later exit.
      if line.startswith(b"INFO: Launching config:"):
        graphics_failed = False
      elif line == FATAL_OPENGL:
        graphics_failed = True

  try:
    if stopping:
      return 0
    child = subprocess.Popen(
      ["quickshell", "-n", "-p", env["OMARCHY_PATH"] + "/shell", "--no-color"],
      env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    # A signal can arrive while Popen is returning, before child is assigned.
    if stopping:
      child.terminate()
    os.set_blocking(child.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
      selector.register(child.stdout, selectors.EVENT_READ)
      while child.poll() is None:
        for key, _ in selector.select(timeout=0.1):
          chunk = os.read(key.fd, 4096)
          if chunk:
            forward(chunk)
          else:
            selector.unregister(key.fileobj)

    # Reap by PID, not pipe EOF: a crash reporter or launched application can
    # retain the log pipe after Quickshell exits. Drain only a bounded amount that
    # is already available, including a fatal printed just before exit.
    for _ in range(64):
      try:
        chunk = os.read(child.stdout.fileno(), 4096)
      except BlockingIOError:
        break
      if not chunk:
        break
      forward(chunk)
    graphics_failed |= pending.strip() == FATAL_OPENGL
    status = child.wait()
    if status != 0 and graphics_failed and not stopping:
      return GRAPHICS_FAILURE
    # Reserve the protocol status; an unrelated exit(78) must not switch GPUs.
    if status == GRAPHICS_FAILURE:
      return 1
    return 128 - status if status < 0 else status
  finally:
    if child is not None:
      if child.poll() is None:
        child.terminate()
        try:
          child.wait(timeout=2)
        except subprocess.TimeoutExpired:
          child.kill()
          child.wait()
      child.stdout.close()


if __name__ == "__main__":
  sys.exit(launch(software="--software" in sys.argv[1:]))
