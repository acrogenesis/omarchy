#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

/usr/bin/python "$ROOT/test/shell.d/fixtures/slack-pipe.py"

# Exercise the real resolver and contrast adjustment.
# No installed Slack or desktop session is needed.
PATH="$ROOT/bin:$PATH" python - <<'PY'
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

root = Path(os.environ['ROOT'])
sys.path.insert(0, str(root / 'default/slack'))
import integration
import palette

def render_palette(colors_file):
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        staged = home / '.local/state/omarchy/current/next-theme'
        staged.mkdir(parents=True)
        shutil.copy2(colors_file, staged / 'colors.toml')
        subprocess.run(['omarchy-theme-set-templates'], env={**os.environ, 'HOME': str(home)}, check=True)
        return json.loads((staged / 'slack.json').read_text())

modes = set()
palettes = []
for theme in sorted((root / 'themes').glob('*/colors.toml')):
    colors = render_palette(theme)
    modes.add(colors['mode'])
    css = palette.build(colors)
    palettes.append({'name': theme.parent.name, 'css': css})
    assert '{{' not in css and 'color-scheme: ' + colors['mode'] in css, theme
    background, foreground = map(palette.rgb, (colors['background'], colors['foreground']))
    if palette.contrast(background, foreground) >= 4.5:
        for key in ('muted', 'dark_foreground', 'accent'):
            adjusted = palette.fit(palette.rgb(colors[key]), background, foreground)
            assert palette.contrast(adjusted, background) >= 4.5, (theme, key)
        button = palette.fit(palette.rgb(colors['accent']), foreground, background)
        assert palette.contrast(button, foreground) >= 4.5, theme
assert modes == {'dark', 'light'}
print('ok - stock dark and light palettes produce readable secondary text, links and buttons')

with tempfile.TemporaryDirectory() as scratch:
    scratch = Path(scratch)
    # Exercise the CSS cascade over Slack's accent backdrop and translucent
    # chrome, which can disagree with otherwise readable semantic tokens.
    fixture = (root / 'test/shell.d/fixtures/slack-theme-header.html').read_text()
    page = scratch / 'header.html'
    page.write_text(fixture.replace('PALETTES_JSON', json.dumps(palettes)))
    browser = subprocess.run(['chromium', '--headless', '--disable-gpu', '--no-first-run',
                              '--disable-background-networking', '--disable-extensions',
                              *(['--no-sandbox'] if os.geteuid() == 0 else []),
                              '--user-data-dir=' + str(scratch / 'chromium'),
                              '--dump-dom', page.as_uri()], capture_output=True, text=True, timeout=45)
    assert browser.returncode == 0, browser.stderr
    result = re.search(r'<pre id="result">(.*?)</pre>', browser.stdout, re.S)
    assert result, browser.stdout[-2000:]
    failures = json.loads(html.unescape(result[1]))
    assert failures == [], failures[:10]
    print('ok - rendered headers and workspace names retain contrast across stock themes')

    # A legacy theme still goes through Omarchy's resolver before CSS generation.
    legacy = scratch / 'colors.toml'
    legacy.write_text('bg = "#101010"\nfg = "#eeeeee"\n' + '\n'.join(
        f'color{i} = "{color}"' for i, color in enumerate(
            ['#101010', '#ff5555', '#55ff55', '#ffff55', '#00aaff', '#ff55ff', '#55ffff', '#eeeeee'])))
    css = palette.build(render_palette(legacy))
    assert '--dt_color-base-pry: #101010' in css
    assert '--dt_color-plt-aubergine-50: 0,170,255' in css
    print('ok - legacy theme aliases and ANSI accent colours reach Slack')


PY

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
HOME="$scratch" bash "$ROOT/bin/omarchy-theme-set-slack"
[[ ! -e $scratch/.local ]] || fail "theme sync leaves unconfigured machines alone"
pass "theme sync leaves unconfigured machines alone"

mkdir -p "$scratch/.local/state/omarchy/slack" "$scratch/.local/state/omarchy/current/theme"
touch "$scratch/.local/state/omarchy/slack/enabled"
HOME="$scratch" OMARCHY_THEME_HEADLESS=1 OMARCHY_THEME_SKIP_BACKGROUND=1 PATH="$ROOT/bin:$PATH" \
  bash "$ROOT/bin/omarchy-theme-set" catppuccin-latte
HOME="$scratch" bash "$ROOT/bin/omarchy-theme-set-slack"
[[ -s $scratch/.local/state/omarchy/slack/slack.css ]] || fail "the native adapter publishes the staged Slack palette"
pass "the native adapter publishes the staged Slack palette"
cp "$scratch/.local/state/omarchy/slack/slack.css" "$scratch/before.css"
printf '{"mode":"dark; invalid CSS"}\n' >"$scratch/.local/state/omarchy/current/theme/slack.json"
HOME="$scratch" bash "$ROOT/bin/omarchy-theme-set-slack" 2>"$scratch/skip.log"
cmp -s "$scratch/before.css" "$scratch/.local/state/omarchy/slack/slack.css" || fail "invalid theme data leaves the last palette intact"
pass "invalid theme data leaves the last palette intact"

python - <<'PY'
from pathlib import Path
import os
import subprocess
import tempfile
import time

root = Path(os.environ['ROOT'])
with tempfile.TemporaryDirectory() as directory:
    scratch = Path(directory)
    home, commands = scratch / 'home', scratch / 'bin'
    home.mkdir()
    commands.mkdir()
    log, launched = scratch / 'packages', scratch / 'launched'
    for name, body in {
        'omarchy-pkg-add': 'echo "add:$*" >>"$TEST_PACKAGES"\nexit "${TEST_PACKAGE_EXIT:-0}"',
        'omarchy-pkg-drop': 'echo "drop:$*" >>"$TEST_PACKAGES"\nexit "${TEST_PACKAGE_EXIT:-0}"',
        'omarchy-setup-slack': 'exit "${TEST_SETUP_EXIT:-0}"',
        'uwsm-app': 'printf "%s\\n" "$*" >"$TEST_LAUNCHED"',
        'update-desktop-database': 'exit 0',
    }.items():
        command = commands / name
        command.write_text('#!/bin/bash\n' + body + '\n')
        command.chmod(0o755)
    env = {**os.environ, 'HOME': str(home), 'PATH': str(commands) + ':' + os.environ['PATH'],
           'TEST_PACKAGES': str(log), 'TEST_LAUNCHED': str(launched)}
    for setup_exit, expected in [('0', '-- gtk-launch slack'),
                                 ('1', '-- gio launch /usr/share/applications/slack.desktop')]:
        launched.unlink(missing_ok=True)
        subprocess.run([root / 'bin/omarchy-install-service-slack'],
                       env={**env, 'TEST_SETUP_EXIT': setup_exit}, check=True)
        deadline = time.monotonic() + 3
        while not launched.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert launched.read_text().strip() == expected
    launched.unlink()
    assert subprocess.run([root / 'bin/omarchy-install-service-slack'],
                          env={**env, 'TEST_PACKAGE_EXIT': '1'}).returncode != 0
    assert not launched.exists()
    assert log.read_text().splitlines() == ['add:slack-desktop'] * 3
    print('ok - installation opens packaged Slack when theme setup fails, but stops on package failure')

    override = home / '.local/share/applications/slack.desktop'
    override.parent.mkdir(parents=True)
    override.write_text('[Desktop Entry]\nExec=omarchy-launch-slack %U\n')
    backup = override.with_suffix('.desktop.before-omarchy')
    backup.write_text('original launcher')
    state, profile = (home / relative for relative in (
        '.local/state/omarchy/slack', '.config/Slack'))
    for target in (state, profile):
        target.mkdir(parents=True)
        (target / 'keep').touch()
    (state / 'enabled').touch()
    remove = [root / 'bin/omarchy-remove-service-slack']
    assert subprocess.run(remove, env={**env, 'TEST_PACKAGE_EXIT': '1'}).returncode != 0
    assert override.exists() and (state / 'enabled').exists()
    subprocess.run(remove, env=env, check=True)
    assert not override.exists() and not state.exists()
    assert (profile / 'keep').exists() and backup.read_text() == 'original launcher'
    assert log.read_text().splitlines()[-2:] == ['drop:slack-desktop'] * 2
    override.write_text('[Desktop Entry]\nExec=custom-slack\n')
    subprocess.run(remove, env=env, check=True)
    assert 'Exec=custom-slack' in override.read_text()
    print('ok - uninstall cleans integration only after package success and retains profiles and custom launchers')
PY
