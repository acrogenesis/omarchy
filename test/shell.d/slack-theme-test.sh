#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

/usr/bin/python "$ROOT/test/shell.d/fixtures/slack-pipe.py"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export HOME="$scratch"
state="$HOME/.local/state/omarchy/slack"
theme="$HOME/.local/state/omarchy/current/theme/slack.json"
override="$HOME/.local/share/applications/slack.desktop"

"$ROOT/bin/omarchy-theme-set-slack"
[[ ! -e $HOME/.local ]] || fail "theme sync leaves unconfigured machines alone"
pass "theme sync leaves unconfigured machines alone"

mkdir -p "$state" "${theme%/*}"
touch "$state/enabled"
printf '%s\n' '{"mode":"light","background":"#eff1f5","accent":"#1e66f5","green":"#40a02b","red":"#d20f39"}' >"$theme"
"$ROOT/bin/omarchy-theme-set-slack"
jq -se '.[0] == .[1]' "$theme" "$state/theme.json" >/dev/null || fail "theme sync publishes the staged colors"
pass "theme sync publishes the staged colors"

jq '.background = "#112233" | .green = "#445566" | .red = "#778899"' "$state/theme.json" >"$scratch/rgb.json"
jq 'with_entries(if .key == "mode" then . else .value += "80" end)' "$scratch/rgb.json" >"$theme"
"$ROOT/bin/omarchy-theme-set-slack"
jq -se '.[0] == .[1]' "$scratch/rgb.json" "$state/theme.json" >/dev/null || fail "RGBA colors publish their RGB values"
pass "RGBA colors publish their RGB values"

cp "$state/theme.json" "$scratch/before.json"
jq '.background = "invalid"' "$state/theme.json" >"$theme"
"$ROOT/bin/omarchy-theme-set-slack" 2>"$scratch/skip.log"
cmp -s "$scratch/before.json" "$state/theme.json" || fail "invalid colors leave the previous theme intact"
pass "invalid colors leave the previous theme intact"

mkdir "$scratch/bin"
cat >"$scratch/bin/stub" <<'STUB'
#!/bin/bash
case ${0##*/} in
  omarchy-pkg-*)
    [[ $* == "slack-desktop" ]] || exit 1
    exit "${TEST_PACKAGE_EXIT:-0}"
    ;;
  omarchy-setup-slack) exit 1 ;;
  uwsm-app) timeout 3 bash -c 'printf "%s\n" "$*" >"$HOME/launch"' bash "$@" ;;
esac
STUB
chmod +x "$scratch/bin/stub"
for command in omarchy-pkg-add omarchy-pkg-drop omarchy-setup-slack uwsm-app update-desktop-database; do
  ln -s stub "$scratch/bin/$command"
done
export PATH="$scratch/bin:$PATH"
mkfifo "$HOME/launch"

"$ROOT/bin/omarchy-install-service-slack" 2>"$scratch/install.log"
[[ $(timeout 3 cat "$HOME/launch") == "-- gio launch /usr/share/applications/slack.desktop" ]] || fail "failed theme setup opens packaged Slack"
pass "failed theme setup opens packaged Slack"
if TEST_PACKAGE_EXIT=1 "$ROOT/bin/omarchy-install-service-slack"; then
  fail "failed package installation stops the installer"
fi
pass "failed package installation stops the installer"

mkdir -p "${override%/*}" "$HOME/.config/Slack"
printf 'Exec=omarchy-launch-slack %%U\n' >"$override"
printf 'original launcher\n' >"$override.before-omarchy"
touch "$HOME/.config/Slack/keep"
if TEST_PACKAGE_EXIT=1 "$ROOT/bin/omarchy-remove-service-slack"; then
  fail "canceled package removal preserves the integration"
fi
[[ -f $override && -f $state/enabled ]] || fail "canceled package removal preserves the integration"
pass "canceled package removal preserves the integration"

"$ROOT/bin/omarchy-remove-service-slack"
[[ ! -e $override && ! -e $state ]] || fail "successful removal cleans the integration"
[[ -f $HOME/.config/Slack/keep && -f $override.before-omarchy ]] || fail "removal keeps the profile and original launcher backup"
pass "successful removal cleans the integration and keeps user data"

printf 'Exec=custom-slack\n' >"$override"
"$ROOT/bin/omarchy-remove-service-slack"
[[ $(<"$override") == "Exec=custom-slack" ]] || fail "removal keeps custom launchers"
pass "removal keeps custom launchers"
