#!/usr/bin/env bash
# One-shot GoDaddy A record update for delivery.ghalbol.com (manual / emergency).
#
# Normal path: DDNS runs inside ghalbol_delivery (see install_delivery_home.sh).
#
#   ./ghalbol_delivery/deploy/godaddy-ddns.sh
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDS="${DEPLOY_DIR}/godaddy-ddns-delivery.credentials"
STATE="${DEPLOY_DIR}/.godaddy-ddns-delivery.last_ip"
V3_BASE="https://api.godaddy.com/v3"

print_credentials_template() {
  cat <<'EOF'
# GoDaddy API v3 — Personal Access Token (not legacy API key/secret).
# Create at https://developer.godaddy.com/ — scopes: domains.domain:read, domains.dns:update
GODADDY_PAT=paste_pat_here
GODADDY_DOMAIN=ghalbol.com
GODADDY_HOST=delivery
GODADDY_TTL=600
EOF
}

MAX_PUBLIC_IP_BODY_BYTES=64
MAX_LIST_BODY_BYTES=$((256 * 1024))
MAX_DNS_BODY_BYTES=512

write_state_locked() {
  local ip="$1"
  local lockfile="${STATE}.lock"
  exec {STATE_LOCK_FD}>"${lockfile}"
  if ! flock -w 30 "${STATE_LOCK_FD}"; then
    echo "error: could not acquire lock for ${STATE}" >&2
    exit 1
  fi
  printf '%s\n' "${ip}" >"${STATE}"
}

is_publishable_ipv4() {
  local ip="$1" o1 o2 rest
  if [[ ! "$ip" =~ ^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}$ ]]; then
    return 1
  fi
  case "$ip" in
    0.*|10.*|127.*|169.254.*|192.168.*|255.255.255.255) return 1 ;;
  esac
  o1="${ip%%.*}"
  rest="${ip#*.}"
  o2="${rest%%.*}"
  if [[ "$o1" == "100" && "$o2" -ge 64 && "$o2" -le 127 ]]; then
    return 1
  fi
  if [[ "$o1" -ge 224 ]]; then
    return 1
  fi
  if [[ "$o1" == "172" && "$o2" -ge 16 && "$o2" -le 31 ]]; then
    return 1
  fi
  return 0
}

load_godaddy_creds() {
  local file="$1" line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue
    key="${line%%=*}"
    val="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    val="${val#\"}"
    val="${val%\"}"
    val="${val#\'}"
    val="${val%\'}"
    case "$key" in
      GODADDY_PAT|GODADDY_DOMAIN|GODADDY_HOST|GODADDY_TTL)
        printf -v "$key" '%s' "$val"
        export "$key"
        ;;
      *)
        echo "error: unsupported key ${key} in ${file} (only GODADDY_PAT|DOMAIN|HOST|TTL)" >&2
        exit 1
        ;;
    esac
  done < "$file"
}

if [[ ! -f "$CREDS" ]]; then
  echo "missing ${CREDS}" >&2
  print_credentials_template >&2
  exit 1
fi

load_godaddy_creds "$CREDS"

for var in GODADDY_PAT GODADDY_DOMAIN GODADDY_HOST; do
  if [[ -z "${!var:-}" ]] || [[ "${!var}" == *paste_* ]]; then
    echo "error: set ${var} in ${CREDS}" >&2
    exit 1
  fi
done

TTL="${GODADDY_TTL:-600}"
if ! [[ "$TTL" =~ ^[0-9]+$ ]] || [[ "$TTL" -lt 600 ]]; then
  TTL=600
fi
AUTH="Authorization: Bearer ${GODADDY_PAT}"
LIST_URL="${V3_BASE}/domains/zones/${GODADDY_DOMAIN}/dns-records?type=A&name=${GODADDY_HOST}"
FQDN="${GODADDY_HOST}.${GODADDY_DOMAIN}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq required (pacman -S jq)" >&2
  exit 1
fi

CURRENT="$(curl -fsS -4 --max-filesize "$MAX_PUBLIC_IP_BODY_BYTES" --no-keepalive -H 'Cache-Control: no-cache' \
  "https://api.ipify.org?$(date +%s)" 2>/dev/null \
  || curl -fsS -4 --max-filesize "$MAX_PUBLIC_IP_BODY_BYTES" --no-keepalive https://ifconfig.me/ip)"
CURRENT="${CURRENT//$'\n'/}"
CURRENT="${CURRENT//$'\r'/}"
if ! is_publishable_ipv4 "$CURRENT"; then
  echo "error: refusing to publish non-global IPv4: ${CURRENT:-<empty>}" >&2
  exit 1
fi

LIST_JSON="$(curl -fsS --max-filesize "$MAX_LIST_BODY_BYTES" -H "$AUTH" -H 'Cache-Control: no-cache' "$LIST_URL")"
if [[ "${#LIST_JSON}" -gt "$MAX_LIST_BODY_BYTES" ]]; then
  echo "error: GoDaddy list response too large" >&2
  exit 1
fi
REMOTE="$(jq -r '.items[0].data // empty' <<< "$LIST_JSON")"
RECORD_ID="$(jq -r '.items[0].recordId // empty' <<< "$LIST_JSON")"

if [[ "$REMOTE" == "$CURRENT" ]]; then
  write_state_locked "$CURRENT"
  exit 0
fi

BODY="$(jq -nc --arg name "$GODADDY_HOST" --arg data "$CURRENT" --argjson ttl "$TTL" \
  '{name: $name, type: "A", data: $data, ttl: $ttl}')"
if [[ "${#BODY}" -gt "$MAX_DNS_BODY_BYTES" ]]; then
  echo "error: DNS update body too large" >&2
  exit 1
fi

if [[ -n "$RECORD_ID" ]]; then
  curl -fsS -X PUT \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    "${V3_BASE}/domains/zones/${GODADDY_DOMAIN}/dns-records/${RECORD_ID}" \
    -d "$BODY"
else
  curl -fsS -X POST \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    "${V3_BASE}/domains/zones/${GODADDY_DOMAIN}/dns-records" \
    -d "$BODY"
fi

write_state_locked "$CURRENT"
if command -v logger >/dev/null 2>&1; then
  logger -t godaddy-ddns "${FQDN} -> ${CURRENT}"
fi
echo "${FQDN} -> ${CURRENT}"
