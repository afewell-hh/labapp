#!/bin/bash
# 10-ghcr-auth.sh
# Authenticate to GitHub Container Registry for Hedgehog Lab pulls

set -euo pipefail

log() {
    local level="${1:-INFO}"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

GHCR_USER="${GHCR_USER:-}"
GHCR_TOKEN="${GHCR_TOKEN:-}"

if [ -z "$GHCR_USER" ] || [ -z "$GHCR_TOKEN" ]; then
    log ERROR "GHCR_USER and GHCR_TOKEN must be set before running 10-ghcr-auth.sh"
    exit 1
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
