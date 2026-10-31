"""Opt-in Slack theme loader. All changes stay in the user's home directory."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import palette


SLACK = Path("/usr/bin/slack")
STATE = Path.home() / ".local/state/omarchy/slack"


def publish(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


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
    if not SLACK.is_file() or not desktop.is_file():
        raise RuntimeError("Install Slack Desktop before running omarchy setup slack.")

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


def remove():
    # Called only after package removal succeeds. Keep the Slack profile and
    # any pre-existing launcher backup; remove only our generated override.
    override = Path.home() / ".local/share/applications/slack.desktop"
    if override.is_file() and re.search(r"^Exec=omarchy-launch-slack(?:\s|$)", override.read_text(), re.M):
        override.unlink()
        subprocess.run(["update-desktop-database", str(override.parent)], check=True)
    if STATE.exists():
        shutil.rmtree(STATE)


if __name__ == "__main__":
    try:
        action = sys.argv[1]
        if action == "setup":
            setup()
        elif action == "theme":
            theme()
        elif action == "remove":
            remove()
        elif action == "launch":
            if (STATE / "enabled").exists():
                from launcher import Slack
                sys.exit(Slack(STATE).run(sys.argv[2:]))
            else:
                os.execv(SLACK, [str(SLACK), *sys.argv[2:]])
        else:
            raise RuntimeError(f"Unknown Slack integration action: {action}")
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Slack theme sync: {error}", file=sys.stderr)
        sys.exit(1)
