#!/usr/bin/env bash
# QVault Mobile — debug build wrapper.
set -o pipefail
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env PROJECT_DIR="$PROJ" "$PROJ/../../platform/scripts/debug_build.sh" "$@"
