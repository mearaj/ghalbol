#!/usr/bin/env bash
set -euo pipefail
# Source from other scripts:  source "$ROOT/scripts/load-ghalbol-env.sh" development
# Exports keys from GhalBol's env file and sets GHALBOL_ENV.
#
# Product env files live with each app crate (apps/<app>/env/, not the
# workspace root) so every GhalBol product owns its own ids/labels.
# Which app: GHALBOL_ENV_DIR wins, else GHALBOL_APP_DIR, else apps/ghalbol.
load_ghalbol_env() {
  local name="${1:?usage: load_ghalbol_env development|production}"
  case "$name" in
    development|production) ;;
    *)
      echo "Invalid GhalBol env profile: $name (want development|production)" >&2
      return 1
      ;;
  esac
  local root="${GHALBOL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  local file="${GHALBOL_ENV_DIR:-${GHALBOL_APP_DIR:-$root/apps/ghalbol}/env}/${name}.env"
  if [[ ! -f "$file" ]]; then
    echo "Missing GhalBol env file: $file" >&2
    return 1
  fi
  # Do not inherit product ids from the caller shell — a stale export must not
  # satisfy required-key checks when the env file omits or misnames them.
  unset GHALBOL_APP_ID GHALBOL_APP_LABEL GHALBOL_COORD_URLS GHALBOL_DELIVERY_URL \
    GHALBOL_VERBOSE_LOG GHALBOL_ENV
  local -A _ghalbol_env_from_file=()
  local file_ghalbol_env=""
  # Parse KEY=VALUE (don't `source` — unquoted spaces break bash, e.g. Ghal Bol Dev).
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue
    local key="${line%%=*}"
    local value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    # Reject non-identifier keys so a malformed env line cannot `export` arbitrary shell.
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"
    export "$key=$value"
    _ghalbol_env_from_file["$key"]=1
    if [[ "$key" == GHALBOL_ENV ]]; then
      file_ghalbol_env="$value"
    fi
  done <"$file"
  if [[ -n "$file_ghalbol_env" && "$file_ghalbol_env" != "$name" ]]; then
    echo "GHALBOL_ENV in $file is '$file_ghalbol_env' but load_ghalbol_env was called with '$name'" >&2
    return 1
  fi
  export GHALBOL_ENV="$name"
  for req in GHALBOL_APP_ID GHALBOL_APP_LABEL; do
    if [[ -z "${_ghalbol_env_from_file[$req]:-}" ]]; then
      echo "Missing ${req} in $file" >&2
      return 1
    fi
  done
  echo "GhalBol env: $name (APP_ID=${GHALBOL_APP_ID} LABEL=${GHALBOL_APP_LABEL})"
}
