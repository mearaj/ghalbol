#!/usr/bin/env bash
# Print SHA-256 cert fingerprints for Android App Links (assetlinks.json).
# Usage:
#   ./scripts/print_android_assetlinks_sha.sh                 # debug keystore default
#   ./scripts/print_android_assetlinks_sha.sh /path/to.jks alias
set -euo pipefail

KEYSTORE="${1:-$HOME/.android/debug.keystore}"
ALIAS="${2:-androiddebugkey}"
STOREPASS="${STOREPASS:-android}"
KEYPASS="${KEYPASS:-android}"

if [[ ! -f "$KEYSTORE" ]]; then
  echo "keystore not found: $KEYSTORE" >&2
  echo "Pass a release/upload keystore path and alias, or create the Android debug keystore." >&2
  exit 1
fi

echo "keystore=$KEYSTORE alias=$ALIAS"
echo "--- SHA-256 (colon-separated, for web/.well-known/assetlinks.json) ---"
keytool -list -v -keystore "$KEYSTORE" -alias "$ALIAS" -storepass "$STOREPASS" -keypass "$KEYPASS" 2>/dev/null \
  | awk -F': ' '/SHA256:/{print $2; exit}'

echo
echo "Debug package entry template (com.ghalbol.debug):"
cat <<'EOF'
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.ghalbol.debug",
      "sha256_cert_fingerprints": ["PASTE_SHA256_HERE"]
    }
  }
EOF
