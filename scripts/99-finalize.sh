#!/bin/bash
# 99-finalize.sh
# Final validation + helpful access info for Hedgehog Lab installer

set -euo pipefail

log() {
    local level="${1:-INFO}"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

print_access_info() {
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

    cat <<EOF

================================================================
 Hedgehog Lab installation complete
================================================================
Grafana:    http://${host_ip}:3000   (admin / prom-operator)
Prometheus: http://${host_ip}:9090
ArgoCD:     http://${host_ip}:8080   (see argocd-initial-admin-secret)
Gitea:      http://${host_ip}:3001   (gitea_admin / admin123)

Helpful commands:
  hh-lab status
  hh-lab logs -f
  hh-lab info
  tmux attach -t hhfab-vlab   # view VLAB init session
  hhfab vlab inspect          # verify virtual fabric
EOF
}

validate_services() {
    log INFO "Running quick validation checks..."

    if systemctl is-active --quiet hhfab-vlab.service; then
        log INFO "hhfab-vlab.service active."
    else
        log WARN "hhfab-vlab.service not active yet (may still be initializing)."
    fi

    if command -v kubectl >/dev/null 2>&1; then
        if kubectl --context k3d-k3d-observability get pods -A >/dev/null 2>&1; then
            log INFO "k3d-observability cluster reachable."
        else
            log WARN "k3d-observability cluster not reachable yet."
        fi
    else
        log WARN "kubectl not found in PATH."
    fi
}

validate_services
print_access_info
