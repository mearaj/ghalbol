#!/usr/bin/env bash
# Run a command with the same Android NDK env as `source scripts/android-ndk-env.sh`.
# Example:
#   scripts/with-android-env.sh cargo check -p ghalbol_core --target aarch64-linux-android

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT}/scripts/android-ndk-env.sh"
if [[ $# -eq 0 ]]; then
  echo "usage: $(basename "$0") command [args…]" >&2
  echo "  example: $(basename "$0") cargo check -p ghalbol_core --target aarch64-linux-android" >&2
  exit 1
fi
exec "$@"
