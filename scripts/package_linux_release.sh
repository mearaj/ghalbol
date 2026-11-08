#!/usr/bin/env bash
# Production Linux x86_64 package for https://ghalbol.com/download/linux.
# Writes web/downloads/ghalbol-linux-x64.tar.gz: extract, then ./install.sh (or ./run.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export GHALBOL_ROOT="$ROOT"
export GHALBOL_APP_DIR="$ROOT/apps/ghalbol"
export GHALBOL_ENV_DIR="$GHALBOL_APP_DIR/env"

source "$ROOT/scripts/load-ghalbol-env.sh"
source "$ROOT/scripts/desktop-resources.sh"
source "$ROOT/scripts/desktop-ids.sh"
source "$ROOT/scripts/stage-desktop-package.sh"
source "$ROOT/scripts/cargo-target-dir.sh"

load_ghalbol_env production
makepad_enable_package_dir
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

cargo build -p ghalbol_app --release

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/ghalbol"
mkdir -p "$PKG" "$ROOT/web/downloads"
LINUX_BIN="$PKG/$(desktop_bin_name)"
BUILT="$(cargo_target_dir)/release/ghalbol_app"
if [[ ! -f "$BUILT" ]]; then
  echo "Built binary not found: $BUILT" >&2
  exit 1
fi
cp -f "$BUILT" "$LINUX_BIN"
chmod +x "$LINUX_BIN"
makepad_copy_desktop_resources "$PKG"
stage_desktop_package "$PKG" linux

TARBALL="$ROOT/web/downloads/ghalbol-linux-x64.tar.gz"
TARBALL_TMP="$(mktemp "${TMPDIR:-/tmp}/ghalbol-linux-x64.XXXXXX.tar.gz")"
trap 'rm -rf "$STAGE"; [[ -f "$TARBALL_TMP" ]] && rm -f "$TARBALL_TMP"' EXIT
tar -C "$STAGE" -czf "$TARBALL_TMP" ghalbol
mv -f "$TARBALL_TMP" "$TARBALL"
TARBALL_TMP=""
trap 'rm -rf "$STAGE"' EXIT
echo "Wrote web/downloads/ghalbol-linux-x64.tar.gz ($(du -h "$TARBALL" | awk '{print $1}'))"
