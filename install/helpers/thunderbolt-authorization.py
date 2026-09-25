"""Thunderbolt approval policy. Device strings are data, never shell commands."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

from gi.repository import Gio, GLib

BOLT = "org.freedesktop.bolt"
BOLT_PATH = "/org/freedesktop/bolt"
MANAGER = "org.freedesktop.bolt1.Manager"
DEVICE = "org.freedesktop.bolt1.Device"
DOMAIN = "org.freedesktop.bolt1.Domain"
PROPERTIES = "org.freedesktop.DBus.Properties"
SERVICE = "org.omarchy.Thunderbolt1"
SERVICE_PATH = "/org/omarchy/Thunderbolt1"
POLICY_PATH = Path("/var/lib/omarchy/thunderbolt-authorization/policy.json")
BOLT_CONFIG = Path("/var/lib/boltd/boltd.conf")
PENDING = {"connected", "auth-error"}
AUTHORIZED = {"authorized", "authorized-newkey", "authorized-secure"}
IDENTITY_FIELDS = ("Uid", "Name", "Vendor", "Parent", "SysfsPath", "ConnectTime")


def atomic_json(path, value):
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  fd, name = tempfile.mkstemp(prefix=".policy-", dir=path.parent)
  try:
    with os.fdopen(fd, "w") as stream:
      json.dump(value, stream, sort_keys=True)
      stream.write("\n")
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(name, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
      os.fsync(directory)
    finally:
      os.close(directory)
  finally:
    if os.path.exists(name):
      os.unlink(name)


def load_policy(path=POLICY_PATH):
  with path.open() as stream:
    state = json.load(stream)
  if state.get("version") != 1 or not isinstance(state.get("trusted"), dict):
    raise ValueError("Invalid Thunderbolt policy; restore its backup before continuing")
  return state


class Bus:
  def __init__(self, connection=None):
    self.connection = connection or Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

  def call(self, name, path, interface, method, signature=None, values=()):
    result = self.connection.call_sync(
      name, path, interface, method,
      GLib.Variant(signature, values) if signature else None, None,
      Gio.DBusCallFlags.NO_AUTO_START, 10000, None)
    return result.unpack()

  def owner(self, name):
    return self.call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                     "org.freedesktop.DBus", "GetNameOwner", "(s)", (name,))[0]

  def properties(self, owner, path, interface):
    return self.call(owner, path, PROPERTIES, "GetAll", "(s)", (interface,))[0]

  def set(self, owner, path, interface, key, value, signature="s"):
    # Bolt reports a generic error for an unchanged BootACL. Read the current
    # value before setting it; callers still verify the complete result.
    if self.properties(owner, path, interface)[key] == value:
      return
    self.call(owner, path, PROPERTIES, "Set", "(ssv)",
              (interface, key, GLib.Variant(signature, value)))


class Bolt:
  def __init__(self, bus=None):
    self.bus = bus or Bus()

  def inventory(self):
    owner = self.bus.owner(BOLT)
    manager = self.bus.properties(owner, BOLT_PATH, MANAGER)
    domains = []
    for path in self.bus.call(owner, BOLT_PATH, MANAGER, "ListDomains")[0]:
      domain = self.bus.properties(owner, path, DOMAIN)
      domain["path"] = path
      domains.append(domain)
    devices = []
    for path in self.bus.call(owner, BOLT_PATH, MANAGER, "ListDevices")[0]:
      device = self.bus.properties(owner, path, DEVICE)
      if device["Type"] != "peripheral" or device["Status"] == "disconnected":
        continue
      device["path"] = path
      # ConnectTime only has second resolution. The sysfs inode also changes
      # when an otherwise identical device reconnects within that second.
      device["inode"] = os.stat(device["SysfsPath"]).st_ino
      devices.append(device)
    if owner != self.bus.owner(BOLT):
      raise RuntimeError("Bolt restarted while reading its inventory")
    return owner, manager, domains, devices

  def stored_devices(self, owner):
    devices = []
    for path in self.bus.call(owner, BOLT_PATH, MANAGER, "ListDevices")[0]:
      device = self.bus.properties(owner, path, DEVICE)
      if device["Stored"] and device["Type"] == "peripheral":
        devices.append({**device, "path": path})
    return devices

  def authorize(self, owner, device):
    self.bus.call(owner, device["path"], DEVICE, "Authorize", "(s)", ("",))

  def enroll(self, owner, device):
    # AuthMode stays disabled. Bolt can enroll an already-authorized device;
    # manual policy prevents it from implicitly adding a firmware BootACL entry.
    self.bus.call(owner, BOLT_PATH, MANAGER, "EnrollDevice", "(sss)",
                  (device["Uid"], "manual", ""))


def trust_identity(device):
  return {field: device[field] for field in ("Uid", "Name", "Vendor")}


def connection_identity(owner, device, generation):
  return {"owner": owner, "generation": generation, "path": device["path"],
          "inode": device["inode"], **{field: device[field] for field in IDENTITY_FIELDS}}


class Policy:
  def __init__(self, bolt=None, path=POLICY_PATH):
    self.bolt = bolt or Bolt()
    self.path = path
    self.generation = str(uuid.uuid4())
    self.state = load_policy(path)
    self.error = ""

  def read(self):
    owner, manager, domains, devices = self.bolt.inventory()
    if manager["AuthMode"] != "disabled":
      raise RuntimeError("Bolt automatic authorization is enabled; protection is not active")
    return owner, manager, domains, devices

  def save(self):
    atomic_json(self.path, self.state)

  def trusted(self, device):
    return self.state["trusted"].get(device["Uid"]) == trust_identity(device)

  def snapshot(self):
    owner, manager, domains, devices = self.read()
    warnings = []
    if self.path.with_name("boot-recovery.json").exists():
      warnings.append("A firmware boot-access change needs recovery. Boot protection is not confirmed; run the Thunderbolt boot recovery command.")
    for domain in domains:
      if domain["SecurityLevel"] == "none":
        warnings.append("This controller allows PCIe connections in firmware. Select user authorization in firmware settings; Omarchy cannot block its devices before their drivers load.")
      elif domain["SecurityLevel"] not in {"user", "secure", "dponly", "usbonly", "nopcie"}:
        warnings.append("The controller's authorization mode could not be verified.")
      if self.state.get("boot_protection") and (
        not domain.get("SysfsPath") or domain["SecurityLevel"] not in {"user", "secure"}
        or not domain["BootACL"] or any(domain["BootACL"])):
        warnings.append("The firmware boot allowlist is not confirmed empty on every controller. Check Thunderbolt at Boot before relying on boot protection.")
    result = []
    for device in devices:
      trusted = self.trusted(device)
      if device["Status"] in AUTHORIZED and not trusted and "boot" in device["AuthFlags"]:
        warnings.append("An untrusted device was authorized by firmware before Linux started. Disconnect it safely to apply approval on its next connection.")
      result.append({"identity": connection_identity(owner, device, self.generation),
                     "trusted": trusted, "status": device["Status"],
                     "stored": device["Stored"], "policy": device["Policy"],
                     "flags": device["AuthFlags"]})
    return {"generation": self.generation, "owner": owner, "devices": result,
            "warnings": sorted(set(warnings)), "error": self.error,
            "boot_protection": self.state.get("boot_protection", False),
            "domains": [{k: d[k] for k in ("Uid", "SecurityLevel", "IOMMU", "BootACL")} for d in domains]}

  def current(self, identity):
    owner, _, domains, devices = self.read()
    for device in devices:
      if connection_identity(owner, device, self.generation) == identity:
        return owner, device
    raise RuntimeError("That Thunderbolt device was removed or changed. Open its latest notification.")

  def approve(self, identity, permanent):
    owner, device = self.current(identity)
    if device["Status"] in PENDING:
      self.bolt.authorize(owner, device)
    elif device["Status"] not in AUTHORIZED:
      raise RuntimeError("Device authorization is still in progress; try again")
    # Read back real properties, never infer authorization from method success.
    owner, device = self.current(identity)
    if device["Status"] not in AUTHORIZED:
      raise RuntimeError("Could not confirm device authorization; try again")
    if permanent:
      if not device["Stored"]:
        self.bolt.enroll(owner, device)
      owner, device = self.current(identity)
      if not device["Stored"]:
        raise RuntimeError("Could not confirm saved device information; try again")
      # Persist consent only after Bolt has stored the device and verified it.
      # A failed response can be retried against this same authorized identity.
      previous = self.state["trusted"].copy()
      self.state["trusted"][device["Uid"]] = trust_identity(device)
      try:
        self.save()
      except Exception:
        self.state["trusted"] = previous
        raise
    return self.snapshot()

  def reconcile(self):
    try:
      owner, manager, domains, devices = self.read()
      errors = []
      if self.state.get("boot_protection"):
        # Firmware imports and newly reconnected controllers must not silently
        # restore pre-boot access after the user opted out of it.
        for stored in self.bolt.stored_devices(owner):
          self.bolt.bus.set(owner, stored["path"], DEVICE, "Policy", "manual")
          if self.bolt.bus.properties(owner, stored["path"], DEVICE)["Policy"] != "manual":
            raise RuntimeError("Could not prevent a saved device from receiving firmware boot access")
        for domain in domains:
          if domain.get("SysfsPath") and domain["SecurityLevel"] in {"user", "secure"} and domain["BootACL"]:
            empty = [""] * len(domain["BootACL"])
            self.bolt.bus.set(owner, domain["path"], DOMAIN, "BootACL", empty, "as")
            if self.bolt.bus.properties(owner, domain["path"], DOMAIN)["BootACL"] != empty:
              raise RuntimeError("Could not confirm the firmware boot allowlist is empty")
      for device in sorted(devices, key=lambda d: len(d["SysfsPath"])):
        if self.trusted(device) and device["Status"] in PENDING and "nopcie" not in device["AuthFlags"]:
          try:
            self.approve(connection_identity(owner, device, self.generation), True)
          except Exception as error:
            # A failing parent/device must not suppress other approvals/prompts.
            errors.append(f"Trusted Thunderbolt device could not be restored: {error}")
      self.error = "\n".join(errors)
    except Exception as error:
      self.error = str(error)
    return True


INTERFACE = '''<node><interface name="org.omarchy.Thunderbolt1">
<method name="Snapshot"><arg type="s" direction="out"/></method>
<method name="Approve"><arg type="s" direction="in"/><arg type="b" direction="in"/>
<arg type="s" direction="out"/></method>
</interface></node>'''


def check_permission(bus, sender):
  subject = ("system-bus-name", {"name": GLib.Variant("s", sender)})
  result = bus.call("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                    "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
                    "((sa{sv})sa{ss}us)",
                    (subject, "org.omarchy.thunderbolt.approve", {}, 1, ""))[0]
  if not result[0]:
    raise PermissionError("Thunderbolt approval requires an active local administrator")


def serve(policy=None):
  policy = policy or Policy()
  if not policy.state.get("enabled"):
    return
  bus = policy.bolt.bus
  loop = GLib.MainLoop()

  def invoke(connection, sender, path, interface, method, parameters, invocation):
    try:
      if method == "Snapshot":
        result = policy.snapshot()
      elif method == "Approve":
        check_permission(bus, sender)
        data, permanent = parameters.unpack()
        if len(data) > 16384:
          raise ValueError("Invalid approval request")
        result = policy.approve(json.loads(data), permanent)
      else:
        raise ValueError("Unknown method")
      invocation.return_value(GLib.Variant("(s)", (json.dumps(result),)))
    except Exception as error:
      invocation.return_dbus_error(SERVICE + ".Error", str(error))

  info = Gio.DBusNodeInfo.new_for_xml(INTERFACE)
  bus.connection.register_object(SERVICE_PATH, info.interfaces[0], invoke, None, None)
  # Do not replace another controller: a second instance would invalidate requests.
  result = bus.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                    "RequestName", "(su)", (SERVICE, 4))[0]
  if result != 1:
    raise RuntimeError("Thunderbolt policy service is already running")
  policy.reconcile()
  GLib.timeout_add_seconds(1, policy.reconcile)
  loop.run()


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("action", choices=["serve"])
  args = parser.parse_args()
  try:
    if args.action == "serve":
      serve()
  except Exception as error:
    print(error, file=sys.stderr)
    sys.exit(1)
