#!/usr/bin/env bash
# Ghal Bol — per-user Linux uninstall. Run from the install dir (~/.local/lib/<slug>/).
# Removes the install, launcher, menu entry, autostart and icon; asks before deleting data.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SRC/desktop-ids.sh"
desktop_load_manifest "$SRC/install-manifest.env"

DEST="$(desktop_install_dir_linux)"
BIN_DIR="$(desktop_bin_dir_linux)"
APPS_DIR="$(desktop_applications_dir_linux)"
ICON="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/128x128/apps/$ENTRY_ID.png"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/$ENTRY_ID.desktop"

desktop_assert_linux_install_dest "$DEST" || exit 1
SRC_CANON="$(cd "$SRC" && pwd)"
DEST_CANON="$(cd "$DEST" && pwd)"
if [[ "$SRC_CANON" != "$DEST_CANON" ]]; then
  echo "Refusing uninstall: run uninstall.sh from the install directory ($DEST_CANON)" >&2
  exit 1
fi
if [[ ! -f "$DEST/install-manifest.env" || ! -f "$DEST/$BIN_NAME" ]]; then
  echo "Refusing uninstall: install directory looks incomplete" >&2
  exit 1
fi

pkill -f "^$DEST/$BIN_NAME" 2>/dev/null || true

DATA_DIR="$(desktop_data_dir_linux)"
desktop_assert_linux_data_dir "$DATA_DIR" || exit 1
if desktop_prompt_remove_data "$DATA_DIR"; then
  rm -rf "$DATA_DIR"
  echo "Data removed: $DATA_DIR"
fi

if [[ -L "$BIN_DIR/$BIN_NAME" ]]; then
  rm -f "$BIN_DIR/$BIN_NAME"
fi
rm -f "$APPS_DIR/$ENTRY_ID.desktop" "$AUTOSTART" "$ICON"
command -v update-desktop-database >/dev/null 2>&1 \
  && update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
if [[ -d "$DEST" && -f "$DEST/install-manifest.env" ]]; then
  rm -rf "$DEST"
fi
echo "$GHALBOL_APP_LABEL uninstalled."
