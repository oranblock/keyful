#!/usr/bin/env bash
# QVault Mobile — release build wrapper.
set -o pipefail
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env PROJECT_DIR="$PROJ" "$PROJ/../../platform/scripts/release_build.sh" "$@"
