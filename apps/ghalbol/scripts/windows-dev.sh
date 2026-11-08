#!/usr/bin/env bash
# GhalBol Chat — development Windows x86_64 package (debug app id).
# Uses --release so the .exe stays sane (~tens of MB). Cargo debug PE with
# Makepad was ~400MB — unusable to copy. Identity still comes from
# development.env → com.ghalbol.debug (separate install/data from prod).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

export GHALBOL_APP_DIR="$ROOT/apps/ghalbol"
export GHALBOL_ENV_DIR="$GHALBOL_APP_DIR/env"

source "$ROOT/scripts/load-ghalbol-env.sh"
source "$ROOT/scripts/windows-env.sh"
source "$ROOT/scripts/desktop-resources.sh"
source "$ROOT/scripts/desktop-ids.sh"
source "$ROOT/scripts/stage-desktop-package.sh"

export GHALBOL_ROOT="$ROOT"
load_ghalbol_env development
makepad_enable_package_dir

OUT="$ROOT/dist/windows-dev"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/ghalbol-windows-dev.XXXXXX")"
trap '[[ -n "${STAGE:-}" ]] && rm -rf "$STAGE"' EXIT
TARGET="$(windows_default_target)"

if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
  if rustup target list --installed 2>/dev/null | grep -qx 'x86_64-pc-windows-msvc'; then
    TARGET=x86_64-pc-windows-msvc
  fi
else
  windows_ensure_toolchain
fi

# Release binary + development.env (console stays — GHALBOL_ENV).
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
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
GhalBol Chat Windows (development)
===================================
App id:   ${GHALBOL_APP_ID}
Label:    ${GHALBOL_APP_LABEL}
Cargo:    --release (optimized). "Dev" means debug app id / data dir, not a 400MB debug PE.
Exe size: ${SIZE}
Target:   $TARGET

Install:
  Double-click Setup.bat
→ %LOCALAPPDATA%\\Programs\\Ghal Bol Dev\\
→ data: $(desktop_data_dir_windows_hint)

Uninstall:
  Start Menu → Uninstall Ghal Bol Dev
  or double-click Uninstall.bat

Prod:   scripts/package-windows.sh      → dist/windows/
Dev:    tools/ghalbol-windows-dev/main.rs → dist/windows-dev/
EOF

rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
mv "$STAGE" "$OUT"
STAGE=""
trap - EXIT

echo "Windows Dev package: $OUT/  (exe ${SIZE})"
echo "Copy the whole folder to Windows (exe + ghalbol_app/resources + Setup.bat)."
