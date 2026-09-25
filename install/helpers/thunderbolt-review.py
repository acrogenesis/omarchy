"""Session-side Thunderbolt notifications and approval dialogs."""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location("thunderbolt_policy", Path(__file__).with_name("thunderbolt-authorization.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def call(method, signature=None, values=()):
  bus = policy.Bus()
  # Bind to one daemon incarnation; a restart must invalidate pending approvals.
  owner = bus.owner(policy.SERVICE)
  return json.loads(bus.call(owner, policy.SERVICE_PATH, policy.SERVICE, method, signature, values)[0])


def requests_dir():
  root = Path(os.environ["HOME"]) / ".local/state/omarchy/thunderbolt-authorization"
  root.mkdir(parents=True, exist_ok=True, mode=0o700)
  root.chmod(0o700)
  requests = root / "requests"
  requests.mkdir(exist_ok=True, mode=0o700)
  requests.chmod(0o700)
  return requests


def lock(requests):
  stream = (requests / ".lock").open("a")
  fcntl.flock(stream, fcntl.LOCK_EX)
  return stream


def read_request(path):
  if path.is_symlink():
    raise ValueError("Invalid Thunderbolt request")
  return json.loads(path.read_text())


def notify(token):
  try:
    if subprocess.run(["omarchy-notification-wait", "1"], timeout=3, stdout=subprocess.DEVNULL).returncode:
      return False
    result = subprocess.run([
      "omarchy-notification-send", "--app-name", "omarchy-action", "--urgency", "critical",
      "--glyph", "󱐋", "Thunderbolt accessory blocked",
      "Click to review it. Keep it blocked unless you recognize the device.",
      "--exec", "omarchy-launch-floating-terminal-with-presentation",
      "omarchy-thunderbolt-authorization-review", token], timeout=10)
    return result.returncode == 0
  except (OSError, subprocess.TimeoutExpired):
    return False


def attention():
  if subprocess.run(["omarchy-notification-wait", "1"], timeout=3).returncode:
    return False
  return subprocess.run([
    "omarchy-notification-send", "--app-name", "omarchy-action", "--urgency", "critical",
    "Thunderbolt protection needs attention", "The approval or firmware policy could not be confirmed. Click for details.",
    "--exec", "omarchy-launch-floating-terminal-with-presentation",
    "omarchy-setup-security-thunderbolt-authorization", "status"], timeout=10).returncode == 0


def request_token(identity, watch_id):
  encoded = json.dumps(identity, sort_keys=True)
  return "request-" + hashlib.sha256((watch_id + encoded).encode()).hexdigest()


def scan(requests, watch_id):
  snapshot = call("Snapshot")
  with lock(requests):
    identities = {json.dumps(d["identity"], sort_keys=True): d for d in snapshot["devices"]}
    for path in requests.glob("request-*.json"):
      try:
        request = read_request(path)
        device = identities.get(json.dumps(request["identity"], sort_keys=True))
        # Preserve saved approval intent after a successful authorization whose
        # response/verification failed. Retry can finish persistent enrollment.
        if device is None or (
          device["status"] not in policy.PENDING and not request.get("approval")):
          path.unlink()
          continue
        if request["watch"] != watch_id:
          path.unlink()
          if not request.get("approval"):
            continue
          # Preserve an unfinished approval across a watcher restart only for
          # the exact same connection and policy-service incarnation.
          request.update(watch=watch_id, retry=True)
          path = requests / (request_token(request["identity"], watch_id) + ".json")
          policy.atomic_json(path, request)
        if request.get("retry") and notify(path.stem):
          request.pop("retry")
          policy.atomic_json(path, request)
      except (ValueError, KeyError):
        path.unlink()
    for device in snapshot["devices"]:
      if device["trusted"] or device["status"] not in policy.PENDING or "nopcie" in device["flags"]:
        continue
      token = request_token(device["identity"], watch_id)
      path = requests / (token + ".json")
      if path.exists():
        continue
      policy.atomic_json(path, {"identity": device["identity"], "watch": watch_id})
      if not notify(token):
        path.unlink(missing_ok=True)
  return snapshot


def watch():
  requests = requests_dir()
  watch_id = str(uuid.uuid4())
  last_error = None
  warned = None
  failures = 0
  while True:
    try:
      snapshot = scan(requests, watch_id)
      last_error = None
      failures = 0
      # A blocked notification must never stand in for a firmware bypass warning.
      if snapshot["error"]:
        snapshot["warnings"].append(snapshot["error"])
      warning = (snapshot["generation"], tuple(snapshot["warnings"]))
      if snapshot["warnings"] and warning != warned:
        if attention():
          warned = warning
      elif not snapshot["warnings"]:
        warned = None
    except Exception as error:
      if str(error) != last_error:
        print(f"Thunderbolt watcher will retry: {error}", file=sys.stderr)
        last_error = str(error)
      failures += 1
      if failures >= 3 and warned != ("unavailable", last_error):
        try:
          if attention():
            warned = ("unavailable", last_error)
        except (OSError, subprocess.TimeoutExpired):
          pass
    time.sleep(2)


def find_device(identity):
  snapshot = call("Snapshot")
  for device in snapshot["devices"]:
    if device["identity"] == identity:
      return device
  raise RuntimeError("That Thunderbolt device was removed or changed. Open its latest notification.")


def safe_text(text):
  return "".join(c if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else "?" for c in str(text))


def review(token):
  if not re.fullmatch(r"request-[0-9a-f]{64}", token):
    raise ValueError("Invalid or expired Thunderbolt request")
  requests = requests_dir()
  path = requests / (token + ".json")
  with lock(requests):
    request = read_request(path)
    device = find_device(request["identity"])
    choice = request.get("approval")
    if choice is None and device["status"] not in policy.PENDING:
      raise RuntimeError("This device is no longer blocked")
  if choice is None:
    subprocess.run(["gum", "style", "--foreground", "212", "--bold", "Blocked Thunderbolt accessory"], check=True)
    print("\nThese details come from the device and can be forged:")
    for key in ("Name", "Vendor", "Uid"):
      print(f"{key}: {safe_text(request['identity'][key])}")
    print("\nApproval gives this accessory access to its PCIe drivers.\n", flush=True)
    result = subprocess.run(["gum", "choose", "Allow once", "Always allow this device", "Keep blocked"], stdout=subprocess.PIPE, text=True)
    if result.returncode:
      return
    choice = result.stdout.strip()
  if choice not in {"Allow once", "Always allow this device", "Keep blocked"}:
    raise ValueError("Invalid approval choice")
  with lock(requests):
    if read_request(path) != request:
      raise RuntimeError("This request changed. Open the latest notification.")
    device = find_device(request["identity"])
    if choice == "Keep blocked":
      # Retain the request to avoid repeatedly asking until this connection ends.
      print("Thunderbolt accessory remains blocked.")
      return
    if not request.get("approval") and device["status"] not in policy.PENDING:
      raise RuntimeError("This device changed while the dialog was open")
    request["approval"] = choice
    policy.atomic_json(path, request)
    try:
      snapshot = call("Approve", "(sb)", (json.dumps(request["identity"]), choice == "Always allow this device"))
      matches = [d for d in snapshot["devices"] if d["identity"] == request["identity"]]
      if not matches or matches[0]["status"] not in policy.AUTHORIZED or (
        choice == "Always allow this device" and not matches[0]["trusted"]):
        raise RuntimeError("Could not confirm approval. The request was kept; try again.")
    except Exception:
      request["retry"] = True
      policy.atomic_json(path, request)
      raise
    path.unlink()
    print("Thunderbolt accessory trusted." if choice == "Always allow this device" else "Thunderbolt accessory allowed for this connection.")


if __name__ == "__main__":
  try:
    if sys.argv[1] == "watch":
      watch()
    elif sys.argv[1] == "review" and len(sys.argv) == 3:
      review(sys.argv[2])
    elif sys.argv[1] == "boot-enabled":
      sys.exit(0 if call("Snapshot")["boot_protection"] else 1)
    elif sys.argv[1] == "status":
      snapshot = call("Snapshot")
      print("Thunderbolt device approval is enabled.")
      print("Trusted accessories reconnect automatically; new accessories require approval.")
      if not snapshot["domains"]:
        print("No Thunderbolt controller is currently visible. Its firmware policy will be checked when it appears.")
      for warning in snapshot["warnings"]:
        print("Attention: " + warning)
      if snapshot["error"]:
        print("Attention: " + safe_text(snapshot["error"]))
      print("Firmware boot access is separate; see the Security manual before relying on pre-boot protection.")
    else:
      raise ValueError("Expected watch, review TOKEN, or status")
  except Exception as error:
    print(safe_text(error), file=sys.stderr)
    sys.exit(1)
