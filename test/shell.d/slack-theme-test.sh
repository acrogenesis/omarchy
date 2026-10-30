#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

# Exercise the real resolver, contrast adjustment, archive writer and cache.
# No installed Slack or desktop session is needed.
PATH="$ROOT/bin:$PATH" python - <<'PY'
import hashlib
import html
import json
import os
from pathlib import Path
import re
import struct
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

    # The entry point deliberately has a different name from Slack's current
    # bundle. A hard-coded filename would break after an upstream rename.
    files = {
        'package.json': json.dumps({'main': './dist/start.cjs'}).encode(),
        'dist/start.cjs': b'console.log("original");',
        'asset.txt': b'unchanged asset',
    }
    header, data = {'files': {}}, b''
    for name, content in files.items():
        node = header
        parts = name.split('/')
        for part in parts[:-1]:
            node = node['files'].setdefault(part, {'files': {}})
        node['files'][parts[-1]] = {'offset': str(len(data)), 'size': len(content),
                                  'integrity': {'algorithm': 'SHA256', 'blockSize': 8}}
        data += content
    encoded = json.dumps(header).encode()
    padding = -len(encoded) % 4
    pickle = struct.pack('<II', 4 + len(encoded) + padding, len(encoded)) + encoded + b'\0' * padding
    original = struct.pack('<II', 4, len(pickle)) + pickle + data
    source, patched = scratch / 'source.asar', scratch / 'patched.asar'
    source.write_bytes(original)
    loader = b'console.log("theme loader");'
    integration.patch_archive(source, patched, loader)
    raw = patched.read_bytes()
    metadata = json.loads(raw[16:16 + struct.unpack_from('<I', raw, 12)[0]])
    body = raw[8 + struct.unpack_from('<I', raw, 4)[0]:]
    for name, content in files.items():
        node = metadata
        for part in name.split('/'):
            node = node['files'][part]
        offset = int(node['offset'])
        actual = body[offset:offset + node['size']]
        if name.endswith('start.cjs'):
            assert actual.startswith(content) and actual.count(loader) == 1
            assert node['integrity']['hash'] == hashlib.sha256(actual).hexdigest()
            assert node['integrity']['blocks'] == [hashlib.sha256(actual[i:i + 8]).hexdigest()
                                                    for i in range(0, len(actual), 8)]
        else:
            assert actual == content
    assert source.read_bytes() == original
    print('ok - archive patch follows the manifest, preserves assets and updates integrity blocks')

    integration.SOURCE, integration.CACHE = scratch / 'source', scratch / 'cache'
    integration.SOURCE.mkdir()
    (integration.SOURCE / 'loader.cjs').write_bytes(loader)
    integration.SLACK = scratch / 'slack'
    integration.SLACK.mkdir()
    fuses = b'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX\x01\x09010001001'
    (integration.SLACK / 'slack').write_bytes(b'packaged executable' + fuses)
    resources = integration.SLACK / 'resources'
    resources.mkdir()
    (resources / 'app.asar').write_bytes(original)
    (resources / 'app.asar.unpacked').mkdir()
    first = integration.runtime()
    assert first.exists() and integration.runtime() == first
    (integration.SLACK / 'slack').write_bytes(b'updated packaged executable' + fuses)
    second = integration.runtime()
    assert second != first and first.exists()
    assert second.read_bytes() == b'updated packaged executable' + fuses
    assert (second.parent / 'resources/app.asar.unpacked').resolve() == resources / 'app.asar.unpacked'
    print('ok - Slack upgrades rebuild the private runtime and retain the running version')

    (integration.SLACK / 'slack').write_bytes(b'package with archive integrity enabled' + fuses.replace(b'010001001', b'010011001'))
    try:
        integration.runtime()
    except RuntimeError:
        pass
    else:
        raise AssertionError('archive integrity policy was ignored')
    print('ok - a Slack build requiring archive integrity is left unmodified')

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
