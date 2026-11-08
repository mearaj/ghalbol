#!/usr/bin/env bash
# Regression checks for scripts/stage-desktop-package.sh (no cargo build).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GHALBOL_ROOT="$ROOT"
export GHALBOL_APP_DIR="$ROOT/apps/ghalbol"
export GHALBOL_ENV_DIR="$GHALBOL_APP_DIR/env"
# shellcheck source=load-ghalbol-env.sh
source "$ROOT/scripts/load-ghalbol-env.sh"
# shellcheck source=desktop-ids.sh
source "$ROOT/scripts/desktop-ids.sh"
# shellcheck source=stage-desktop-package.sh
source "$ROOT/scripts/stage-desktop-package.sh"

fail() {
  echo "check_stage_desktop_package: $*" >&2
  exit 1
}

tmpdir=""
cleanup() {
  [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
}
trap cleanup EXIT
tmpdir="$(mktemp -d)"

load_ghalbol_env production >/dev/null
empty="$tmpdir/empty"
mkdir -p "$empty"
if stage_desktop_package "$empty" linux 2>/dev/null; then
  fail "expected stage to fail without binary"
fi

pkg="$tmpdir/pkg"
mkdir -p "$pkg"
touch "$pkg/$(desktop_bin_name)"
if ! stage_desktop_package "$pkg" linux; then
  fail "expected stage to succeed with stub binary"
fi
[[ -f "$pkg/install-manifest.env" ]] || fail "manifest not written"
[[ -x "$pkg/install.sh" ]] || fail "install.sh not staged"

echo "check_stage_desktop_package: OK"
