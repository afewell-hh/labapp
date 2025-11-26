#!/bin/bash
# install.sh - thin wrapper for hh-lab-installer
# Usage: curl -fsSL <raw-url>/install.sh | bash -s -- --ghcr-user USER --ghcr-token TOKEN

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/scripts/hh-lab-installer"

if [ ! -x "$INSTALLER" ]; then
    echo "ERROR: hh-lab-installer not found at ${INSTALLER}" >&2
    exit 1
fi

exec "$INSTALLER" "$@"
