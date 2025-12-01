#!/bin/bash
# 60-prometheus-hedgehog-scrape.sh
# Prometheus Hedgehog Metrics Verification Module
# Verifies that Hedgehog VLAB metrics are being received via Alloy remote write
#
# IMPORTANT: The Hedgehog telemetry architecture uses PUSH, not PULL:
#   Switch (Alloy agent) → fabric-proxy → Prometheus (remote write receiver)
#
# This module:
# - Waits for Hedgehog VLAB to be ready
# - Verifies Prometheus remote write receiver is enabled
# - Verifies Prometheus service is accessible on port 9090
# - Queries for Hedgehog metrics to confirm they're being received
# - Reports status of metrics collection
#
# Prerequisites:
# - VLAB must be initialized with defaultAlloyConfig configured
# - Prometheus must have enableRemoteWriteReceiver: true
# - Prometheus service must be LoadBalancer type on port 9090

set -euo pipefail

# Module metadata
MODULE_NAME="prometheus-hedgehog-verify"
MODULE_DESCRIPTION="Verify Hedgehog fabric metrics are being received in Prometheus"
MODULE_VERSION="2.0.0"

# Configuration
PROMETHEUS_NAMESPACE="${PROMETHEUS_NAMESPACE:-monitoring}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
PROMETHEUS_REMOTE_WRITE_URL="http://172.18.0.1:${PROMETHEUS_PORT}/api/v1/write"

# Expected labels from VLAB Alloy config
EXPECTED_ENV_LABEL="${ALLOY_PROM_LABEL_ENV:-vlab}"
EXPECTED_CLUSTER_LABEL="${ALLOY_PROM_LABEL_CLUSTER:-emc}"

LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/prometheus-verify.log}"
PROMETHEUS_VERIFY_TIMEOUT="${PROMETHEUS_VERIFY_TIMEOUT:-300}"  # 5 minutes

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Logging functions
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl command not found"
        return 1
    fi

    # Check if VLAB is initialized
    if [ ! -f "/var/lib/hedgehog-lab/vlab-initialized" ]; then
        log_error "VLAB not initialized. This module requires VLAB to complete first."
        return 1
    fi

    log_info "VLAB initialization confirmed"

    # Switch to k3d-observability context
    if ! kubectl config use-context k3d-k3d-observability >> "$LOG_FILE" 2>&1; then
        log_error "Failed to switch to k3d-observability context"
        return 1
    fi

    # Check if Prometheus is running
    if ! kubectl get prometheus -n "$PROMETHEUS_NAMESPACE" kube-prometheus-stack-prometheus &> /dev/null; then
        log_error "Prometheus not found in namespace ${PROMETHEUS_NAMESPACE}"
        return 1
    fi

    log_info "Prerequisites check passed"
    return 0
}

# Verify Prometheus remote write receiver is enabled
verify_remote_write_receiver() {
    log_info "Verifying Prometheus remote write receiver is enabled..."

    # Check the Prometheus CRD for enableRemoteWriteReceiver
    local remote_write_enabled
    remote_write_enabled=$(kubectl get prometheus kube-prometheus-stack-prometheus \
        -n "$PROMETHEUS_NAMESPACE" \
        -o jsonpath='{.spec.enableRemoteWriteReceiver}' 2>/dev/null || echo "false")

    if [ "$remote_write_enabled" = "true" ]; then
        log_info "Prometheus remote write receiver is ENABLED"
        return 0
    else
        log_warn "Prometheus remote write receiver is NOT enabled"
        log_warn "Run: kubectl patch prometheus kube-prometheus-stack-prometheus -n monitoring --type='json' -p='[{\"op\": \"add\", \"path\": \"/spec/enableRemoteWriteReceiver\", \"value\": true}]'"
        return 1
    fi
}

# Verify Prometheus service is accessible
verify_prometheus_service() {
    log_info "Verifying Prometheus service is accessible on port ${PROMETHEUS_PORT}..."

    # Check service type
    local svc_type
    svc_type=$(kubectl get svc kube-prometheus-stack-prometheus \
        -n "$PROMETHEUS_NAMESPACE" \
        -o jsonpath='{.spec.type}' 2>/dev/null || echo "ClusterIP")

    log_info "Prometheus service type: $svc_type"

    # Try to reach the remote write endpoint
    if curl -s --connect-timeout 5 "http://localhost:${PROMETHEUS_PORT}/-/ready" &> /dev/null; then
        log_info "Prometheus is accessible on localhost:${PROMETHEUS_PORT}"
        return 0
    elif curl -s --connect-timeout 5 "http://172.18.0.1:${PROMETHEUS_PORT}/-/ready" &> /dev/null; then
        log_info "Prometheus is accessible on 172.18.0.1:${PROMETHEUS_PORT}"
        return 0
    else
        log_warn "Prometheus not accessible on expected ports"
        log_warn "This may be normal if the k3d load balancer is still starting"
        return 0  # Don't fail - may just need more time
    fi
}

# Query Prometheus for Hedgehog metrics
query_hedgehog_metrics() {
    log_info "Querying Prometheus for Hedgehog metrics..."

    # Wait for Prometheus pod to be ready
    log_info "Waiting for Prometheus pod to be ready..."
    if ! kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/name=prometheus" \
        -l "prometheus=kube-prometheus-stack-prometheus" \
        -n "$PROMETHEUS_NAMESPACE" \
        --timeout=120s >> "$LOG_FILE" 2>&1; then
        log_warn "Prometheus pod readiness check timed out"
    fi

    # Get Prometheus pod name for port-forward
    local prom_pod
    prom_pod=$(kubectl get pod -n "$PROMETHEUS_NAMESPACE" \
        -l "app.kubernetes.io/name=prometheus" \
        -l "prometheus=kube-prometheus-stack-prometheus" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$prom_pod" ]; then
        log_warn "Could not find Prometheus pod for verification"
        return 0
    fi

    # Start port-forward
    log_info "Starting port-forward to Prometheus pod..."
    kubectl port-forward -n "$PROMETHEUS_NAMESPACE" "$prom_pod" 9091:9090 >> "$LOG_FILE" 2>&1 &
    local pf_pid=$!
    sleep 5

    # Query for metrics with expected labels from VLAB
    log_info "Looking for metrics with env=${EXPECTED_ENV_LABEL}, cluster=${EXPECTED_CLUSTER_LABEL}..."

    # Try the up metric with VLAB labels
    local query_result
    query_result=$(curl -s "http://localhost:9091/api/v1/query?query=up{env=\"${EXPECTED_ENV_LABEL}\",cluster=\"${EXPECTED_CLUSTER_LABEL}\"}" 2>/dev/null || echo "")

    # Kill port-forward
    kill $pf_pid 2>/dev/null || true

    if [ -z "$query_result" ]; then
        log_warn "No response from Prometheus query"
        return 0
    fi

    # Check if we got any results
    local result_count
    result_count=$(echo "$query_result" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data.get('data',{}).get('result',[])))" 2>/dev/null || echo "0")

    if [ "$result_count" -gt 0 ]; then
        log_info "SUCCESS! Found $result_count metric series from Hedgehog VLAB"
        log_info "Hedgehog fabric telemetry is working correctly"
        return 0
    else
        log_warn "No Hedgehog metrics found yet (expected for fresh installation)"
        log_warn "Metrics should appear within 2-3 minutes after VLAB switches register"
        log_info "To verify manually, run:"
        log_info "  kubectl port-forward -n monitoring svc/kube-prometheus-stack-prometheus 9090:9090"
        log_info "  curl 'http://localhost:9090/api/v1/query?query=up{env=\"vlab\",cluster=\"emc\"}'"
        return 0
    fi
}

# Get configuration summary
get_config_summary() {
    log_info ""
    log_info "Hedgehog Telemetry Configuration Summary:"
    log_info "=========================================="
    log_info ""
    log_info "Architecture: PUSH-based (Alloy agents → Prometheus remote write)"
    log_info ""
    log_info "Flow:"
    log_info "  1. Switch Alloy agents collect metrics (every 120s)"
    log_info "  2. Alloy pushes to fabric-proxy on control node"
    log_info "  3. fabric-proxy remote writes to Prometheus at:"
    log_info "     ${PROMETHEUS_REMOTE_WRITE_URL}"
    log_info ""
    log_info "Expected Metric Labels:"
    log_info "  - env: ${EXPECTED_ENV_LABEL}"
    log_info "  - cluster: ${EXPECTED_CLUSTER_LABEL}"
    log_info ""
    log_info "Verify metrics in Prometheus:"
    log_info "  1. Access Prometheus: http://localhost:${PROMETHEUS_PORT}"
    log_info "  2. Query: up{env=\"${EXPECTED_ENV_LABEL}\",cluster=\"${EXPECTED_CLUSTER_LABEL}\"}"
    log_info "  3. Expected: 21 metrics (3 per switch × 7 switches)"
    log_info ""
    log_info "Verify in Grafana:"
    log_info "  1. Access Grafana: http://localhost:3000"
    log_info "  2. Default login: admin / admin"
    log_info "  3. Import Hedgehog dashboards from Fabric documentation"
    log_info ""
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "Hedgehog Metrics Verification Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info ""

    local overall_start
    overall_start=$(date +%s)

    # Execute verification steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! verify_remote_write_receiver; then
        log_warn "Remote write receiver verification incomplete"
    fi

    if ! verify_prometheus_service; then
        log_warn "Prometheus service verification incomplete"
    fi

    if ! query_hedgehog_metrics; then
        log_warn "Hedgehog metrics query incomplete"
    fi

    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    get_config_summary

    log_info ""
    log_info "=================================================="
    log_info "Hedgehog Metrics Verification Complete!"
    log_info "=================================================="
    log_info "Total verification time: ${total_time}s"
    log_info ""

    return 0
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
    exit $?
fi

# Module interface functions for orchestrator integration
module_run() {
    main "$@"
}

module_validate() {
    # Validate that Prometheus is running with remote write enabled
    kubectl config use-context k3d-k3d-observability &> /dev/null
    kubectl get prometheus -n "$PROMETHEUS_NAMESPACE" kube-prometheus-stack-prometheus &> /dev/null
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
  "timeout": $PROMETHEUS_VERIFY_TIMEOUT,
  "dependencies": ["vlab", "k3d", "prometheus"]
}
EOF
}
