#!/bin/bash
# validate-lab.sh
# Post-install health check for Hedgehog Lab (VLAB + EMC)

set -euo pipefail

ctx="k3d-k3d-observability"

log() {
    local level="${1:-INFO}"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

require_cmd() {
    for c in "$@"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            log ERROR "Missing command: $c"
            exit 1
        fi
    done
}

require_cmd kubectl jq hhfab

log INFO "Checking kubectl context: $ctx"
kubectl --context "$ctx" cluster-info >/dev/null

log INFO "Inspecting VLAB topology"
hhfab vlab inspect >/dev/null

log INFO "Checking EMC workloads"
kubectl --context "$ctx" get pods -A

log INFO "Checking ArgoCD application hedgehog-fabric"
kubectl --context "$ctx" -n argocd get application hedgehog-fabric -o jsonpath='{.status.sync.status}{" "}{.status.health.status}{"\n"}'

log INFO "Counting telemetry samples (Prometheus up{env=\"vlab\"})"
prom_pod=$(kubectl --context "$ctx" -n monitoring get pods -l app.kubernetes.io/name=kube-prometheus-stack-prometheus -o jsonpath='{.items[0].metadata.name}')
count=$(kubectl --context "$ctx" -n monitoring exec "$prom_pod" -c prometheus -- \
    wget -qO- 'http://localhost:9090/api/v1/query?query=up%7Benv%3D"vlab"%7D' | jq '.data.result | length')
log INFO "Telemetry series count: $count"

if [ "$count" -lt 21 ]; then
    log ERROR "Expected 21 telemetry series; got $count"
    exit 1
fi

host_ip=$(hostname -I | awk '{print $1}')

cat <<EOF

Access URLs:
  Grafana:    http://${host_ip}:3000  (admin / prom-operator)
  Prometheus: http://${host_ip}:9090
  ArgoCD:     http://${host_ip}:8080  (password from argocd-initial-admin-secret)
  Gitea:      http://${host_ip}:3001  (gitea_admin / admin123)

Validation: SUCCESS
EOF
