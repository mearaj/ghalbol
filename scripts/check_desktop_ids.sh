#!/usr/bin/env bash
# Regression checks for scripts/desktop-ids.sh (no cargo build).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
# shellcheck source=desktop-ids.sh
source "$ROOT/scripts/desktop-ids.sh"

fail() {
  echo "check_desktop_ids: $*" >&2
  exit 1
}

tmpdir=""
cleanup() {
  [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
}
trap cleanup EXIT
tmpdir="$(mktemp -d)"

good="$tmpdir/good.env"
cat >"$good" <<'EOF'
GHALBOL_ENV=production
GHALBOL_APP_ID=com.ghalbol
GHALBOL_APP_LABEL=Ghal Bol
INSTALL_SLUG=ghalbol
BIN_NAME=ghalbol-app
ENTRY_ID=com.ghalbol
EOF
desktop_load_manifest "$good" || fail "expected good manifest to load"

bad_id="$tmpdir/bad-id.env"
sed 's/com.ghalbol/com.ghalbol;rm/' "$good" >"$bad_id"
if desktop_load_manifest "$bad_id" 2>/dev/null; then
  fail "expected hostile APP_ID to be rejected"
fi

bad_label="$tmpdir/bad-label.env"
sed 's/Ghal Bol/Ghal\/Bol/' "$good" >"$bad_label"
if desktop_load_manifest "$bad_label" 2>/dev/null; then
  fail "expected path-like LABEL to be rejected"
fi

desktop_assert_safe_id "t" "com.ghalbol.debug" || fail "safe id rejected"
if desktop_assert_safe_id "t" "../evil" 2>/dev/null; then
  fail "expected ../evil to fail desktop_assert_safe_id"
fi

quoted="$(desktop_exec_quoted '/tmp/has space/bin')"
[[ "$quoted" == '"/tmp/has space/bin"' ]] || fail "Exec quoting broken: $quoted"

export HOME="$tmpdir/fakehome"
mkdir -p "$HOME/.local/lib/ghalbol"
desktop_assert_linux_install_dest "$HOME/.local/lib/ghalbol" \
  || fail "expected normal install dest to pass"
if desktop_assert_linux_install_dest "$HOME" 2>/dev/null; then
  fail "expected HOME itself to be rejected as DEST"
fi
if desktop_assert_linux_install_dest "/" 2>/dev/null; then
  fail "expected / to be rejected as DEST"
fi
if desktop_assert_linux_install_dest "$HOME/Desktop/evil" 2>/dev/null; then
  fail "expected path outside .local/lib to be rejected"
fi

desktop_assert_linux_data_dir "$HOME/.local/share/com.ghalbol" \
  || fail "expected normal data dir to pass"
if desktop_assert_linux_data_dir "/tmp/evil" 2>/dev/null; then
  fail "expected data dir outside XDG_DATA_HOME to be rejected"
fi

echo "check_desktop_ids: OK"
