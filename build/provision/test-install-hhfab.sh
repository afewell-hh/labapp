#!/usr/bin/env bash
# Host-only installer proof. Same bounds/dependencies/ownership as offline runner.
# No environment overrides; two isolated Ubuntu 24.04 containers; no cloud access.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/test-hhfab-offline.sh" install
