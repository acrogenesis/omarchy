"""Root-only setup and offline reset support for Thunderbolt authorization."""

import base64
import configparser
from contextlib import contextmanager
import fcntl
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("thunderbolt_policy", Path(__file__).with_name("thunderbolt-authorization.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
MARKER = Path("/etc/omarchy/thunderbolt-authorization.enabled")


def config(path):
  parser = configparser.ConfigParser(interpolation=None)
  parser.optionxform = str
  if path.exists():
    with path.open() as stream:
      parser.read_file(stream)
  if not parser.has_section("config"):
    parser.add_section("config")
  return parser


def write_authmode(path, value):
  parser = config(path)
  parser.set("config", "AuthMode", value)
  output = io.StringIO()
  parser.write(output)
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  fd, name = tempfile.mkstemp(prefix=".omarchy-", dir=path.parent)
  try:
    with os.fdopen(fd, "w") as stream:
      stream.write(output.getvalue())
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(name, path)
  finally:
    if os.path.exists(name):
      os.unlink(name)


def guard():
  if MARKER.exists():
    state = policy.load_policy()
    if not state.get("enabled"):
      raise RuntimeError("Thunderbolt policy and enable marker disagree")
    write_authmode(policy.BOLT_CONFIG, "disabled")


def capture(sysfs=Path("/sys/bus/thunderbolt/devices")):
  trusted = {}
  for path in sorted(sysfs.glob("*")):
    # Domain objects have no unique_id; host routers have no parent router.
    if not (path / "unique_id").exists() or path.name.endswith("-0"):
      continue
    uid = (path / "unique_id").read_text().strip()
    if not uid:
      raise RuntimeError("A connected Thunderbolt device has no identity")
    trusted[uid] = {"Uid": uid, "Name": (path / "device_name").read_text().strip(),
                    "Vendor": (path / "vendor_name").read_text().strip()}
  # Empty hardware inventory is a valid initialized policy, never a reason to
  # trust devices arriving during a future enable/retry.
  return trusted


def prepare(fresh=False):
  existing = policy.load_policy() if policy.POLICY_PATH.exists() else None
  if existing is None or fresh:
    state = {**(existing or {}), "version": 1, "enabled": True, "trusted": capture(),
             "original_authmode": existing["original_authmode"] if existing else config(policy.BOLT_CONFIG).get("config", "AuthMode", fallback="enabled")}
  else:
    state = existing
    state["enabled"] = True
  if state["original_authmode"] not in {"enabled", "disabled"}:
    raise ValueError("Unsupported existing Bolt authorization mode")
  # Publish consent first, then the persistent disabled mode. The marker is
  # last; the startup guard must never see a partially prepared policy.
  policy.atomic_json(policy.POLICY_PATH, state)
  write_authmode(policy.BOLT_CONFIG, "disabled")
  MARKER.parent.mkdir(parents=True, exist_ok=True)
  MARKER.touch(mode=0o644)


def run(*args):
  subprocess.run(args, check=True)


def unit_state(unit, setting):
  return subprocess.run(["systemctl", setting, "--quiet", unit], stdout=subprocess.DEVNULL).returncode == 0


@contextmanager
def configuration_transaction():
  if policy.POLICY_PATH.with_name("boot-recovery.json").exists():
    raise RuntimeError("Recover the pending firmware boot-access change first")
  files = [policy.POLICY_PATH, policy.BOLT_CONFIG, MARKER]
  before = {str(path): {"data": base64.b64encode(path.read_bytes()).decode(),
                       "mode": path.stat().st_mode & 0o777} if path.exists() else None for path in files}
  units = {name: {"active": unit_state(name, "is-active"), "enabled": unit_state(name, "is-enabled")}
           for name in ("bolt.service", "omarchy-thunderbolt-authorization.service")}
  backup = policy.POLICY_PATH.with_name("setup-recovery.json")
  if backup.exists():
    raise RuntimeError(f"A previous setup change needs recovery from {backup}")
  saved = {"files": before, "units": units}
  if policy.POLICY_PATH.exists() and policy.load_policy().get("boot_protection"):
    bolt = policy.Bolt()
    owner, _, domains, _ = bolt.inventory()
    if any(not d.get("SysfsPath") for d in domains):
      raise RuntimeError("Reconnect all controllers before changing boot protection")
    saved["firmware"] = {"policies": {d["Uid"]: d["Policy"] for d in bolt.stored_devices(owner)},
                         "acls": {d["Uid"]: d["BootACL"] for d in domains}}
  policy.atomic_json(backup, saved)
  try:
    yield
  except Exception as error:
    try:
      restore_configuration(saved)
      backup.unlink()
    except Exception as restore_error:
      raise RuntimeError(f"Setup failed ({error}); restoration is incomplete ({restore_error}). Recovery data retained at {backup}") from error
    raise
  backup.unlink()


def restore_configuration(saved):
  run("systemctl", "stop", "omarchy-thunderbolt-authorization.service", "bolt.service")
  for name, original in saved["files"].items():
    path = Path(name)
    if original is None:
      path.unlink(missing_ok=True)
    else:
      path.parent.mkdir(parents=True, exist_ok=True)
      fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=path.parent)
      try:
        with os.fdopen(fd, "wb") as stream:
          stream.write(base64.b64decode(original["data"]))
          stream.flush()
          os.fsync(stream.fileno())
        os.chmod(temporary, original["mode"])
        os.replace(temporary, path)
      finally:
        if os.path.exists(temporary):
          os.unlink(temporary)
  if "firmware" in saved:
    run("systemctl", "start", "bolt.service")
    bolt = policy.Bolt()
    owner, _, domains, _ = bolt.inventory()
    apply_boot_state(bolt, owner, bolt.stored_devices(owner), domains,
                     saved["firmware"]["policies"], saved["firmware"]["acls"])
  # Any nested boot recovery checkpoint is superseded only after verified restore.
  policy.POLICY_PATH.with_name("boot-recovery.json").unlink(missing_ok=True)
  # bolt.service is static/udev activated; only our service has an enable state.
  service = "omarchy-thunderbolt-authorization.service"
  run("systemctl", "enable" if saved["units"][service]["enabled"] else "disable", service)
  for name, unit in saved["units"].items():
    if unit["active"]:
      run("systemctl", "start", name)
    else:
      run("systemctl", "stop", name)


def enable(fresh=False):
  with configuration_transaction():
    run("systemctl", "stop", "omarchy-thunderbolt-authorization.service")
    run("systemctl", "stop", "bolt.service")
    # While Bolt is stopped, no automatic IOMMU enrollment can race the capture.
    # Already-connected disks are never deauthorized or detached.
    prepare(fresh)
    run("systemctl", "daemon-reload")
    run("systemctl", "start", "bolt.service")
    bolt = policy.Bolt()
    if bolt.inventory()[1]["AuthMode"] != "disabled":
      raise RuntimeError("Bolt did not apply its authorization policy")
    run("systemctl", "enable", "--now", "omarchy-thunderbolt-authorization.service")


def disable():
  with configuration_transaction():
    if policy.POLICY_PATH.with_name("boot-recovery.json").exists():
      raise RuntimeError("Recover the pending firmware boot-access change before removing protection")
    run("systemctl", "stop", "omarchy-thunderbolt-authorization.service")
    boot_policy(False)
    state = policy.load_policy()
    run("systemctl", "stop", "bolt.service")
    # Removing the marker permits the original policy on the next Bolt start.
    # If restarting fails, report failure; retain all explicit trust for retry.
    write_authmode(policy.BOLT_CONFIG, state["original_authmode"])
    MARKER.unlink(missing_ok=True)
    state["enabled"] = False
    policy.atomic_json(policy.POLICY_PATH, state)
    run("systemctl", "disable", "omarchy-thunderbolt-authorization.service")
    run("systemctl", "start", "bolt.service")
    if policy.Bolt().inventory()[1]["AuthMode"] != state["original_authmode"]:
      raise RuntimeError("Could not confirm restored Bolt policy")


def boot_policy(enabled, bolt=None, path=None):
  bolt = bolt or policy.Bolt()
  path = path or policy.POLICY_PATH
  state = policy.load_policy(path)
  if not state.get("enabled"):
    raise RuntimeError("Enable Thunderbolt device authorization first")
  if not enabled and not state.get("boot_protection"):
    return
  owner, manager, domains, devices = bolt.inventory()
  if manager["AuthMode"] != "disabled":
    raise RuntimeError("Bolt automatic authorization must be disabled")
  if not domains or any(not d.get("SysfsPath") for d in domains):
    raise RuntimeError("Connect every Thunderbolt controller before changing firmware boot access")
  if enabled and any(d["SecurityLevel"] not in {"user", "secure"} or not d["BootACL"] for d in domains):
    raise RuntimeError("This controller has no supported firmware boot allowlist. Disable Thunderbolt pre-boot/PCIe boot support in firmware settings instead; Omarchy cannot verify that setting.")
  stored = bolt.stored_devices(owner)
  backup = path.with_name("boot-recovery.json")
  if backup.exists():
    raise RuntimeError("A previous boot-access change needs recovery. Run the boot recovery command before retrying.")
  before = {"version": 1, "state": state,
            "policies": {d["Uid"]: d["Policy"] for d in stored},
            "acls": {d["Uid"]: d["BootACL"] for d in domains}}
  after = json.loads(json.dumps(state))
  if enabled:
    if not state.get("boot_protection"):
      after["boot_original"] = {"policies": before["policies"], "acls": before["acls"]}
    after["trusted"].update({d["Uid"]: policy.trust_identity(d) for d in devices})
    policies = {d["Uid"]: "manual" for d in stored}
    acls = {d["Uid"]: [""] * len(d["BootACL"]) for d in domains}
  else:
    if not state.get("boot_protection"):
      return
    policies = state["boot_original"]["policies"]
    acls = state["boot_original"]["acls"]
    if not set(acls).issubset({d["Uid"] for d in domains}):
      raise RuntimeError("Reconnect the original controllers before restoring firmware boot access")
    after.pop("boot_original", None)
  after["boot_protection"] = enabled
  policy.atomic_json(backup, before)
  try:
    apply_boot_state(bolt, owner, stored, domains, policies, acls)
    policy.atomic_json(path, after)
  except Exception as error:
    try:
      apply_boot_state(bolt, owner, stored, domains, before["policies"], before["acls"])
      policy.atomic_json(path, state)
      backup.unlink()
    except Exception as restore_error:
      raise RuntimeError(f"Boot-access change failed ({error}); recovery is incomplete ({restore_error}). Recovery data retained at {backup}") from error
    raise
  backup.unlink()


def apply_boot_state(bolt, owner, devices, domains, policies, acls):
  if not set(policies).issubset({d["Uid"] for d in devices}):
    raise RuntimeError("Saved device policies are missing from Bolt; recovery cannot be verified")
  if not set(acls).issubset({d["Uid"] for d in domains}):
    raise RuntimeError("A required controller is missing; recovery cannot be verified")
  if any(not d.get("SysfsPath") for d in domains if d["Uid"] in acls):
    raise RuntimeError("Reconnect the original controllers; offline firmware changes cannot be verified")
  for device in devices:
    if device["Uid"] in policies:
      bolt.bus.set(owner, device["path"], policy.DEVICE, "Policy", policies[device["Uid"]])
      if bolt.bus.properties(owner, device["path"], policy.DEVICE)["Policy"] != policies[device["Uid"]]:
        raise RuntimeError("Bolt did not save the requested device policy")
  # Policy changes can modify the boot ACL. Write and verify ACLs last.
  for domain in domains:
    if domain["Uid"] in acls:
      requested = acls[domain["Uid"]]
      if len(domain["BootACL"]) != len(requested):
        raise RuntimeError("Firmware boot allowlist capacity changed")
      bolt.bus.set(owner, domain["path"], policy.DOMAIN, "BootACL", requested, "as")
      if bolt.bus.properties(owner, domain["path"], policy.DOMAIN)["BootACL"] != requested:
        raise RuntimeError("Firmware did not retain the requested boot allowlist")


def recover_boot():
  backup = policy.POLICY_PATH.with_name("boot-recovery.json")
  saved = json.loads(backup.read_text())
  bolt = policy.Bolt()
  owner, manager, domains, devices = bolt.inventory()
  if not set(saved["acls"]).issubset({d["Uid"] for d in domains}):
    raise RuntimeError("Reconnect the original controllers before recovery")
  apply_boot_state(bolt, owner, bolt.stored_devices(owner), domains, saved["policies"], saved["acls"])
  policy.atomic_json(policy.POLICY_PATH, saved["state"])
  backup.unlink()


def reset_root(target):
  root = Path(target).resolve(strict=True)
  if root == Path("/"):
    raise ValueError("Refusing to reset the running system's Thunderbolt policy")
  marker = root / MARKER.relative_to("/")
  state = root / policy.POLICY_PATH.relative_to("/")
  if not marker.exists() and not state.parent.exists():
    return
  run("systemctl", "--root=" + str(root), "disable", "omarchy-thunderbolt-authorization.service")
  marker.unlink(missing_ok=True)
  # Recovery checkpoints contain the previous owner's inventory as well.
  if state.parent.is_symlink():
    state.parent.unlink()
  elif state.parent.exists():
    shutil.rmtree(state.parent)
  # A new owner must not inherit stored accessory identities or secure keys.
  store = root / "var/lib/boltd"
  for name in ("devices", "keys", "domains"):
    path = store / name
    if path.is_symlink():
      path.unlink()
    elif path.exists():
      shutil.rmtree(path)
  write_authmode(store / "boltd.conf", "enabled")


if __name__ == "__main__":
  try:
    if os.geteuid() != 0:
      raise PermissionError("Thunderbolt setup must run as root")
    action = sys.argv[1]
    if action != "guard":
      setup_lock = open("/run/lock/omarchy-thunderbolt-authorization.lock", "a")
      fcntl.flock(setup_lock, fcntl.LOCK_EX)
    if action == "guard":
      guard()
    elif action == "recover":
      backup = policy.POLICY_PATH.with_name("setup-recovery.json")
      restore_configuration(json.loads(backup.read_text()))
      backup.unlink()
    elif action == "prepare":
      prepare()
    elif action == "enable":
      enable()
    elif action == "migrate":
      if not policy.POLICY_PATH.exists() or policy.load_policy().get("enabled"):
        enable()
    elif action == "owner":
      enable(fresh=True)
    elif action == "disable":
      disable()
    elif action in {"boot-enable", "boot-disable", "boot-recover"}:
      run("systemctl", "stop", "omarchy-thunderbolt-authorization.service")
      try:
        if action == "boot-recover":
          recover_boot()
        else:
          boot_policy(action == "boot-enable")
      finally:
        run("systemctl", "start", "omarchy-thunderbolt-authorization.service")
    elif action == "reset-root" and len(sys.argv) == 3:
      reset_root(sys.argv[2])
    else:
      raise ValueError("Unknown setup action")
  except Exception as error:
    print(error, file=sys.stderr)
    sys.exit(1)
