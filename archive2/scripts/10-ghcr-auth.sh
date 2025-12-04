#!/bin/bash
# 10-ghcr-auth.sh
# Authenticate to GitHub Container Registry for Hedgehog Lab pulls

set -euo pipefail

log() {
    local level="${1:-INFO}"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

# Accept credentials from file (preferred), command-line arguments, or environment variables
if [ -n "${GHCR_CREDS_FILE:-}" ] && [ -f "${GHCR_CREDS_FILE}" ]; then
    log INFO "Reading GHCR credentials from ${GHCR_CREDS_FILE}"
    GHCR_USER=$(sed -n '1p' "$GHCR_CREDS_FILE")
    GHCR_TOKEN=$(sed -n '2p' "$GHCR_CREDS_FILE")
else
    # Fallback to command-line arguments or environment variables
    GHCR_USER="${1:-${GHCR_USER:-}}"
    GHCR_TOKEN="${2:-${GHCR_TOKEN:-}}"
fi

if [ -z "$GHCR_USER" ] || [ -z "$GHCR_TOKEN" ]; then
    log ERROR "GHCR_USER and GHCR_TOKEN must be provided via GHCR_CREDS_FILE, arguments, or environment variables"
    log ERROR "Usage: $0 <ghcr-user> <ghcr-token>"
    log ERROR "   OR: GHCR_CREDS_FILE=/path/to/creds $0"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    log INFO "Docker not installed yet; skipping GHCR login. Will be handled post-install-base."
    exit 0
fi

log INFO "Authenticating to ghcr.io as ${GHCR_USER}..."
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin >/dev/null
log INFO "Docker login succeeded."

# Propagate Docker credentials to hhlab user for hhfab pulls
if [ -f /root/.docker/config.json ]; then
    log INFO "Propagating Docker credentials to /home/hhlab/.docker"
    mkdir -p /home/hhlab/.docker
    cp /root/.docker/config.json /home/hhlab/.docker/config.json
    chown -R hhlab:hhlab /home/hhlab/.docker
    chmod 600 /home/hhlab/.docker/config.json
fi

log INFO "Writing credentials marker at /var/lib/hedgehog-lab/ghcr-authenticated"
mkdir -p /var/lib/hedgehog-lab
cat > /var/lib/hedgehog-lab/ghcr-authenticated <<EOF
{
  "authenticated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "username": "$GHCR_USER",
  "registry": "ghcr.io"
}
EOF

# Clear sensitive env vars
GHCR_TOKEN=""
unset GHCR_TOKEN
log INFO "GHCR token cleared from environment."
