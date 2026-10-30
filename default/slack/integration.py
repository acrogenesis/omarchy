"""Opt-in Slack theme loader. All changes stay in the user's home directory."""

import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import palette


SLACK = Path("/usr/lib/slack")
SOURCE = Path(os.environ["OMARCHY_PATH"]) / "default/slack"
STATE = Path.home() / ".local/state/omarchy/slack"
CACHE = Path.home() / ".cache/omarchy/slack"


def publish(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def patch_archive(source, target, loader):
    """Append to the entry point without moving any of the other ASAR entries."""
    raw = source.read_bytes()
    header_size = struct.unpack_from("<I", raw, 4)[0]
    json_size = struct.unpack_from("<I", raw, 12)[0]
    header = json.loads(raw[16:16 + json_size])
    data = raw[8 + header_size:]

    def entry(path):
        node = header
        for part in Path(path).parts:
            if part != ".":
                node = node["files"][part]
        return node

    package = entry("package.json")
    offset = int(package["offset"])
    main = json.loads(data[offset:offset + package["size"]])["main"]
    boot = entry(main)
    offset = int(boot["offset"])
    script = data[offset:offset + boot["size"]] + b"\n;" + loader + b"\n"
    boot.update(offset=str(len(data)), size=len(script))
    if "integrity" in boot:
        block_size = boot["integrity"]["blockSize"]
        boot["integrity"].update(
            hash=hashlib.sha256(script).hexdigest(),
            blocks=[hashlib.sha256(script[i:i + block_size]).hexdigest()
                    for i in range(0, len(script), block_size)],
        )
    encoded = json.dumps(header, separators=(",", ":")).encode()
    padding = -len(encoded) % 4
    pickle = struct.pack("<II", 4 + len(encoded) + padding, len(encoded)) + encoded + b"\0" * padding
    target.write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + data + script)


def runtime():
    archive = SLACK / "resources/app.asar"
    binary = SLACK / "slack"
    loader = (SOURCE / "loader.cjs").read_bytes()
    # A new Slack package or loader gets its own runtime. A running instance
    # keeps its old archive available for modules it has not loaded yet.
    identity = [(str(p), p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
                for p in (binary, archive)]
    key = hashlib.sha256(repr(identity).encode() + loader).hexdigest()[:20]
    CACHE.mkdir(parents=True, exist_ok=True)
    with (CACHE / "build.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        target = CACHE / key
        if not target.exists():
            # Never disable an Electron integrity policy. If a future package
            # enables it, the launcher falls back to the unmodified Slack.
            with binary.open("rb") as executable, mmap.mmap(executable.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                # v1 wire: 32-byte sentinel, version, count, then fuse states.
                marker = mapped.find(b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX")
                known_wire = marker >= 0 and marker + 39 <= len(mapped) and mapped[marker + 32] == 1 and mapped[marker + 33] >= 5
                if not known_wire or mapped[marker + 38] != ord("0"):
                    raise RuntimeError("This Slack build does not allow a private themed archive.")
            staging = Path(tempfile.mkdtemp(dir=CACHE))
            try:
                for item in SLACK.iterdir():
                    if item.name == "slack":
                        subprocess.run(["cp", "--reflink=auto", str(item), str(staging / item.name)], check=True)
                    elif item.name == "resources":
                        resources = staging / item.name
                        resources.mkdir()
                        for asset in item.iterdir():
                            if asset.name == "app.asar":
                                patch_archive(asset, resources / asset.name, loader)
                            else:
                                (resources / asset.name).symlink_to(asset)
                    else:
                        (staging / item.name).symlink_to(item)
                staging.rename(target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
    return target / "slack"


def theme():
    # The normal template renderer already resolved colours and legacy aliases
    # while staging this theme. Read one snapshot, never re-resolve a live theme.
    source = Path.home() / ".local/state/omarchy/current/theme/slack.json"
    try:
        css = palette.build(json.loads(source.read_text()))
    except (ValueError, KeyError, TypeError) as error:
        print(f"Skipping Slack theme: {error}", file=sys.stderr)
        return
    publish(STATE / "slack.css", css.encode())


def setup():
    desktop = Path("/usr/share/applications/slack.desktop")
    if not (SLACK / "resources/app.asar").is_file() or not desktop.is_file():
        raise RuntimeError("Install Slack Desktop before running omarchy setup slack.")
    runtime()

    # Keep the package's flags, icon and URL handler. Resolve the current
    # Omarchy launcher on PATH rather than retaining a copy of its code.
    lines = desktop.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("Exec="):
            match = re.match(r"Exec=(?:/usr/bin/)?slack(?=\s|$)", line)
            if not match:
                raise RuntimeError("Slack's desktop launcher has changed; refusing to replace it.")
            lines[i] = "Exec=omarchy-launch-slack" + line[match.end():]
    override = Path.home() / ".local/share/applications/slack.desktop"
    if override.exists() and "Exec=omarchy-launch-slack" not in override.read_text():
        backup = override.with_suffix(".desktop.before-omarchy")
        if backup.exists():
            raise RuntimeError(f"An earlier launcher backup already exists: {backup}")
        shutil.copy2(override, backup)
    publish(override, ("\n".join(lines) + "\n").encode())
    publish(STATE / "enabled", b"")
    subprocess.run(["update-desktop-database", str(override.parent)], check=True)
    print("Slack theme sync enabled. Fully quit Slack and reopen it from the launcher once.")
    print("Future Omarchy theme changes will recolor open Slack windows automatically.")


if __name__ == "__main__":
    try:
        action = sys.argv[1]
        if action == "setup":
            setup()
        elif action == "theme":
            theme()
        elif action == "launch":
            try:
                binary = runtime()
            except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
                print(f"Slack theme sync: {error} Starting packaged Slack.", file=sys.stderr)
                binary = SLACK / "slack"
            os.execv(binary, [str(binary), *sys.argv[2:]])
        else:
            raise RuntimeError(f"Unknown Slack integration action: {action}")
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Slack theme sync: {error}", file=sys.stderr)
        sys.exit(1)
