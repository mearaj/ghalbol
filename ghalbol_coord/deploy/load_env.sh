# shellcheck shell=bash
# Source from run_server.sh — do not execute directly.
load_server_env() {
  local server_dir="$1"
  local env_name="$2"
  local env_file="${server_dir}/${env_name}"
  local example="${server_dir}/${env_name}.example"

  if [[ ! -f "${env_file}" ]]; then
    if [[ -f "${example}" ]]; then
      cp "${example}" "${env_file}"
      echo "created ${env_file} from ${example} — edit it, then re-run." >&2
      exit 1
    fi
    echo "error: missing ${env_file}" >&2
    exit 1
  fi

  # Parse KEY=VALUE — do not `source` (malformed lines must not run shell).
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue
    local key="${line%%=*}"
    local value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"
    export "$key=$value"
  done <"${env_file}"
}
