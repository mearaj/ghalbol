#!/usr/bin/env bash
# Regression checks for scripts/load-ghalbol-env.sh (no cargo build).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-ghalbol-env.sh
source "$ROOT/scripts/load-ghalbol-env.sh"

fail() {
  echo "check_load_ghalbol_env: $*" >&2
  exit 1
}

tmpdir=""
cleanup() {
  [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
}
trap cleanup EXIT
tmpdir="$(mktemp -d)"

export GHALBOL_ROOT="$ROOT"
export GHALBOL_APP_DIR="$ROOT/apps/ghalbol"
export GHALBOL_ENV_DIR="$tmpdir/env"
mkdir -p "$GHALBOL_ENV_DIR"

# Stale shell exports must not satisfy a file that omits GHALBOL_APP_ID.
export GHALBOL_APP_ID=com.stale.from.shell
export GHALBOL_APP_LABEL="Stale label"
printf '%s\n' 'GHALBOL_APP_LABEL="Only label"' >"$GHALBOL_ENV_DIR/development.env"
if load_ghalbol_env development 2>/dev/null; then
  fail "expected load to fail when env file omits GHALBOL_APP_ID"
fi
unset GHALBOL_APP_ID GHALBOL_APP_LABEL

# Wrong GHALBOL_ENV line in the file must fail.
printf '%s\n' \
  'GHALBOL_ENV=production' \
  'GHALBOL_APP_ID=com.ghalbol.debug' \
  'GHALBOL_APP_LABEL="Ghal Bol Dev"' \
  >"$GHALBOL_ENV_DIR/development.env"
if load_ghalbol_env development 2>/dev/null; then
  fail "expected load to fail on GHALBOL_ENV profile mismatch"
fi

# Shipped development.env loads cleanly (keys come from the file, not the shell).
cp -f "$GHALBOL_APP_DIR/env/development.env" "$GHALBOL_ENV_DIR/development.env"
export GHALBOL_APP_ID=com.stale.from.shell
load_ghalbol_env development >/dev/null
[[ "${GHALBOL_APP_ID}" == "com.ghalbol.debug" ]] \
  || fail "APP_ID should come from env file, got ${GHALBOL_APP_ID}"

echo "check_load_ghalbol_env: OK"
