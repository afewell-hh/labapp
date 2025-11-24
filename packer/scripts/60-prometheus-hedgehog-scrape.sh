#!/bin/bash
# 60-prometheus-hedgehog-scrape.sh
# Validate Prometheus ingestion of Hedgehog Alloy telemetry via remote_write
#
# This module:
# - Ensures Prometheus is exposed on the host (k3d load balancer)
# - Verifies Fabricator.defaultAlloyConfig has a Prometheus target
# - Waits for remote_write metrics (env=vlab, cluster=emc) to arrive
#
# Prerequisites:
# - VLAB must be initialized (/var/lib/hedgehog-lab/vlab-initialized)
# - Prometheus running in k3d-observability

set -euo pipefail

# Module metadata
MODULE_NAME="prometheus-hedgehog-scrape"
MODULE_DESCRIPTION="Verify Hedgehog telemetry landing in Prometheus"
MODULE_VERSION="2.0.0"

# Configuration
PROMETHEUS_NAMESPACE="${PROMETHEUS_NAMESPACE:-monitoring}"
PROMETHEUS_REMOTE_PORT="${PROMETHEUS_REMOTE_PORT:-9090}"
PROM_QUERY_TIMEOUT="${PROM_QUERY_TIMEOUT:-300}"  # seconds
FAB_NAMESPACE="${FAB_NAMESPACE:-fab}"
PROM_QUERY='up{env="vlab",cluster="emc"}'

LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/prometheus-scrape.log}"

# Ensure log directory exists with correct ownership
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chown hhlab:hhlab "$LOG_FILE" 2>/dev/null || true

# Logging helpers
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl command not found"
        return 1
    fi

    if [ ! -f "/var/lib/hedgehog-lab/vlab-initialized" ]; then
        log_error "VLAB not initialized. This module requires VLAB first."
        return 1
    fi

    if ! kubectl config use-context k3d-k3d-observability >> "$LOG_FILE" 2>&1; then
        log_error "Failed to switch to k3d-observability context"
        return 1
    fi

    log_info "Prerequisites satisfied"
    return 0
}

wait_for_prometheus() {
    log_info "Waiting for Prometheus components to be ready..."

    if ! kubectl get prometheus -n "$PROMETHEUS_NAMESPACE" kube-prometheus-stack-prometheus >> "$LOG_FILE" 2>&1; then
        log_error "Prometheus custom resource not found in ${PROMETHEUS_NAMESPACE}"
        return 1
    fi

    if ! kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/name=prometheus" \
        -l "prometheus=kube-prometheus-stack-prometheus" \
        -n "$PROMETHEUS_NAMESPACE" \
        --timeout=180s >> "$LOG_FILE" 2>&1; then
        log_warn "Prometheus pods did not become ready within timeout"
    fi

    log_info "Prometheus pods reported ready (or timeout reached)"
    return 0
}

verify_alloy_config_present() {
    log_info "Checking Fabricator defaultAlloyConfig..."

    local alloy_json
    alloy_json=$(kubectl -n "$FAB_NAMESPACE" get fabricator -o json 2>/dev/null || true)

    if [ -z "$alloy_json" ]; then
        log_warn "Could not read Fabricator in namespace ${FAB_NAMESPACE}; skipping Alloy check"
        return 0
    fi

    local has_target
    has_target=$(python3 - <<'PY' "$alloy_json"
import json, sys
doc=json.loads(sys.argv[1])
items=doc.get("items",[])
for item in items:
    dac=item.get("spec",{}).get("config",{}).get("fabric",{}).get("defaultAlloyConfig",{})
    targets=dac.get("prometheusTargets",{})
    if targets:
        print("yes")
        sys.exit(0)
print("no")
PY
    )

    if [ "$has_target" = "yes" ]; then
        log_info "defaultAlloyConfig contains prometheusTargets"
    else
        log_warn "defaultAlloyConfig missing prometheusTargets; remote_write may be disabled"
    fi
}

port_forward_prometheus() {
    kubectl port-forward -n "$PROMETHEUS_NAMESPACE" \
        svc/kube-prometheus-stack-prometheus \
        9091:"${PROMETHEUS_REMOTE_PORT}" >> "$LOG_FILE" 2>&1 &
    echo $!
}

query_prometheus_for_alloy() {
    local deadline=$(( $(date +%s) + PROM_QUERY_TIMEOUT ))
    local pf_pid
    pf_pid=$(port_forward_prometheus)
    sleep 3

    local found="no"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local response
        response=$(curl -s -G --data-urlencode "query=${PROM_QUERY}" "http://localhost:9091/api/v1/query" 2>/dev/null || true)

        local count
        count=$(python3 - <<'PY' "$response"
import json, sys
try:
    data=json.loads(sys.argv[1])
    results=data.get("data",{}).get("result",[])
    print(len(results))
except Exception:
    print(0)
PY
        )

        if [ "$count" -gt 0 ]; then
            found="yes"
            log_info "Received ${count} remote_write time series matching ${PROM_QUERY}"
            break
        fi

        log_debug "No Alloy metrics yet; waiting..."
        sleep 10
    done

    kill "$pf_pid" 2>/dev/null || true

    if [ "$found" = "yes" ]; then
        return 0
    else
        log_warn "Timed out waiting for Alloy metrics (${PROM_QUERY_TIMEOUT}s)"
        log_warn "Check control-proxy connectivity and fab.yaml telemetry settings."
        return 0
    fi
}

get_config_summary() {
    log_info ""
    log_info "Prometheus Hedgehog Telemetry Summary:"
    log_info "  Prometheus namespace: ${PROMETHEUS_NAMESPACE}"
    log_info "  Remote write port (host LB): ${PROMETHEUS_REMOTE_PORT}"
    log_info "  Verification query: ${PROM_QUERY}"
    log_info "  k3d load balancer expects host port ${PROMETHEUS_REMOTE_PORT} mapped (see 20-k3d-observability-init.sh)"
    log_info ""
    log_info "Manual verification:"
    log_info "  kubectl config use-context k3d-k3d-observability"
    log_info "  kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090:${PROMETHEUS_REMOTE_PORT}"
    log_info "  curl -G --data-urlencode \"query=${PROM_QUERY}\" http://localhost:9090/api/v1/query"
}

main() {
    log_info "=================================================="
    log_info "Prometheus Hedgehog Telemetry Validation Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${PROM_QUERY_TIMEOUT}s"
    log_info ""

    local overall_start
    overall_start=$(date +%s)

    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! wait_for_prometheus; then
        log_error "Prometheus readiness check failed"
        return 1
    fi

    verify_alloy_config_present
    query_prometheus_for_alloy

    local overall_end
    overall_end=$(date +%s)
    local total_time=$((overall_end - overall_start))

    get_config_summary

    log_info ""
    log_info "=================================================="
    log_info "Prometheus Hedgehog Telemetry Validation Complete!"
    log_info "=================================================="
    log_info "Total time: ${total_time}s"
    log_info ""

    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
    exit $?
fi

# Module interface functions for orchestrator integration
module_run() {
    main "$@"
}

module_validate() {
    kubectl config use-context k3d-k3d-observability &> /dev/null
    kubectl get svc -n "$PROMETHEUS_NAMESPACE" kube-prometheus-stack-prometheus &> /dev/null
}

module_cleanup() {
    log_info "No cleanup required"
}

module_get_metadata() {
    cat <<EOF
{
  "name": "$MODULE_NAME",
  "description": "$MODULE_DESCRIPTION",
  "version": "$MODULE_VERSION",
  "timeout": $PROM_QUERY_TIMEOUT,
  "dependencies": ["vlab", "k3d", "prometheus"]
}
EOF
}
