#!/usr/bin/env bash
# Production Windows x86_64 package for GhalBol.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export GHALBOL_APP_DIR="$ROOT/apps/ghalbol"
export GHALBOL_ENV_DIR="$GHALBOL_APP_DIR/env"

source "$ROOT/scripts/load-ghalbol-env.sh"
source "$ROOT/scripts/windows-env.sh"
source "$ROOT/scripts/desktop-resources.sh"
source "$ROOT/scripts/desktop-ids.sh"
source "$ROOT/scripts/stage-desktop-package.sh"

export GHALBOL_ROOT="$ROOT"
load_ghalbol_env production
makepad_enable_package_dir
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

OUT="$ROOT/dist/windows"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/ghalbol-windows.XXXXXX")"
trap '[[ -n "${STAGE:-}" ]] && rm -rf "$STAGE"' EXIT
TARGET="$(windows_default_target)"

if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
  if rustup target list --installed 2>/dev/null | grep -qx 'x86_64-pc-windows-msvc'; then
    TARGET=x86_64-pc-windows-msvc
  fi
else
  windows_ensure_toolchain
fi

cargo build -p ghalbol_app --release --target "$TARGET"

source "$ROOT/scripts/cargo-target-dir.sh"
TARGET_DIR="$(cargo_target_dir)"
EXE=""
for cand in \
  "$TARGET_DIR/$TARGET/release/ghalbol_app.exe" \
  "$TARGET_DIR/$TARGET/release/ghalbol_app" \
  "$TARGET_DIR/release/ghalbol_app.exe"
do
  if [[ -f "$cand" ]]; then
    EXE="$cand"
    break
  fi
done
if [[ -z "$EXE" ]]; then
  echo "Built binary not found under $TARGET_DIR/$TARGET/release/" >&2
  exit 1
fi

WIN_EXE="$(desktop_bin_name).exe"
cp -f "$EXE" "$STAGE/$WIN_EXE"
makepad_copy_desktop_resources "$STAGE"
stage_desktop_package "$STAGE" windows

SIZE="$(du -h "$STAGE/$WIN_EXE" | awk '{print $1}')"

cat >"$STAGE/README.txt" <<EOF
GhalBol Chat Windows (production)
=================================
App id:   ${GHALBOL_APP_ID}
Label:    ${GHALBOL_APP_LABEL}
Exe size: ${SIZE}
Target:   $TARGET (x86_64 — Windows 10 and 11)

Install (recommended):
  Double-click Setup.bat
→ %LOCALAPPDATA%\\Programs\\Ghal Bol\\

Portable run (no install):
  .\\${WIN_EXE}

Uninstall:
  Start Menu → Uninstall Ghal Bol
  or double-click Uninstall.bat
EOF

rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
mv "$STAGE" "$OUT"
STAGE=""
trap - EXIT

echo "Windows production package: $OUT/"
