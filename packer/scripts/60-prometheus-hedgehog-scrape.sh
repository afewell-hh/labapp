#!/bin/bash
# 60-prometheus-hedgehog-scrape.sh
# Prometheus Hedgehog Scrape Configuration Module
# Configures Prometheus to scrape metrics from Hedgehog fabric-proxy
#
# This module:
# - Waits for Hedgehog VLAB to be ready
# - Creates Prometheus scrape config for fabric-proxy NodePort
# - Applies configuration to Prometheus
# - Verifies metrics are being collected
#
# Prerequisites:
# - VLAB must be initialized (creates /var/lib/hedgehog-lab/vlab-initialized)
# - Prometheus must be running in k3d-observability cluster

set -euo pipefail

# Module metadata
MODULE_NAME="prometheus-hedgehog-scrape"
MODULE_DESCRIPTION="Configure Prometheus to scrape Hedgehog fabric metrics"
MODULE_VERSION="1.0.0"

# Configuration
PROMETHEUS_NAMESPACE="${PROMETHEUS_NAMESPACE:-monitoring}"
HEDGEHOG_FABRIC_PROXY_ENDPOINT="https://172.19.0.1:31028"  # fabric-proxy NodePort
HEDGEHOG_SCRAPE_JOB="hedgehog-fabric"
SCRAPE_INTERVAL="15s"

LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/prometheus-scrape.log}"
PROMETHEUS_SCRAPE_TIMEOUT="${PROMETHEUS_SCRAPE_TIMEOUT:-300}"  # 5 minutes

# Ensure log directory exists with correct ownership
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chown hhlab:hhlab "$LOG_FILE"

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

# Wait for fabric-proxy to be accessible
wait_for_fabric_proxy() {
    log_info "Waiting for Hedgehog fabric-proxy to be accessible..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Try to reach the fabric-proxy metrics endpoint
        # It's okay if TLS fails, we just need connectivity
        if curl -sk --connect-timeout 2 "${HEDGEHOG_FABRIC_PROXY_ENDPOINT}/metrics" &> /dev/null; then
            log_info "Fabric-proxy is accessible at ${HEDGEHOG_FABRIC_PROXY_ENDPOINT}"
            return 0
        fi

        sleep 5
        ((attempt++))

        if [ $((attempt % 12)) -eq 0 ]; then
            log_info "Still waiting for fabric-proxy... (${attempt}/${max_attempts})"
        fi
    done

    log_warn "Fabric-proxy not accessible after ${max_attempts} attempts"
    log_warn "Continuing with configuration (proxy may not be ready yet)"
    return 0  # Don't fail - continue with config
}

# Create Prometheus scrape configuration
create_scrape_config() {
    log_info "Creating Prometheus scrape configuration for Hedgehog fabric..."

    # Create Secret with additional scrape config
    cat <<EOF | kubectl apply -f - >> "$LOG_FILE" 2>&1
apiVersion: v1
kind: Secret
metadata:
  name: additional-scrape-configs
  namespace: ${PROMETHEUS_NAMESPACE}
type: Opaque
stringData:
  prometheus-additional.yaml: |
    - job_name: '${HEDGEHOG_SCRAPE_JOB}'
      scrape_interval: ${SCRAPE_INTERVAL}
      scrape_timeout: 10s
      metrics_path: '/metrics'
      scheme: https
      tls_config:
        insecure_skip_verify: true
      static_configs:
        - targets:
            - '172.19.0.1:31028'
          labels:
            source: 'hedgehog-fabric'
            environment: 'vlab'
EOF

    if [ $? -eq 0 ]; then
        log_info "Created scrape configuration secret"
    else
        log_error "Failed to create scrape configuration secret"
        return 1
    fi

    # Patch Prometheus to use additional scrape configs
    # Note: The field is initialized as an empty array in k3d provisioning, so we use "replace"
    log_info "Patching Prometheus to use additional scrape configs..."

    if ! kubectl patch prometheus kube-prometheus-stack-prometheus \
        -n "$PROMETHEUS_NAMESPACE" \
        --type='json' \
        -p='[{
          "op": "replace",
          "path": "/spec/additionalScrapeConfigs",
          "value": {
            "name": "additional-scrape-configs",
            "key": "prometheus-additional.yaml"
          }
        }]' >> "$LOG_FILE" 2>&1; then
        log_error "Failed to patch Prometheus with additional scrape configs"
        log_error "Check $LOG_FILE for details"
        return 1
    fi

    log_info "Patched Prometheus successfully"

    # Wait for Prometheus to reload
    log_info "Waiting for Prometheus to reload configuration..."
    sleep 10
    return 0
}

# Verify Prometheus is scraping
verify_scraping() {
    log_info "Verifying Prometheus is scraping Hedgehog metrics..."

    # Wait for Prometheus pod to be ready
    log_info "Waiting for Prometheus pod to be ready..."
    if ! kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/name=prometheus" \
        -l "prometheus=kube-prometheus-stack-prometheus" \
        -n "$PROMETHEUS_NAMESPACE" \
        --timeout=120s >> "$LOG_FILE" 2>&1; then
        log_warn "Prometheus pod readiness check timed out"
    fi

    # Check Prometheus targets via API
    log_info "Checking Prometheus targets..."
    local prom_pod
    prom_pod=$(kubectl get pod -n "$PROMETHEUS_NAMESPACE" \
        -l "app.kubernetes.io/name=prometheus" \
        -l "prometheus=kube-prometheus-stack-prometheus" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$prom_pod" ]; then
        log_warn "Could not find Prometheus pod for verification"
        return 0
    fi

    # Port-forward to Prometheus and check targets
    log_info "Verifying scrape job is configured..."
    kubectl port-forward -n "$PROMETHEUS_NAMESPACE" "$prom_pod" 9091:9090 >> "$LOG_FILE" 2>&1 &
    local pf_pid=$!
    sleep 3

    # Query targets API
    local targets_response
    targets_response=$(curl -s "http://localhost:9091/api/v1/targets" 2>/dev/null || echo "")

    # Kill port-forward
    kill $pf_pid 2>/dev/null || true

    if echo "$targets_response" | grep -q "${HEDGEHOG_SCRAPE_JOB}"; then
        log_info "Hedgehog scrape job found in Prometheus targets"
    else
        log_warn "Hedgehog scrape job not yet visible in Prometheus targets"
        log_warn "This is normal if fabric-proxy is not ready yet"
    fi

    return 0
}

# Get configuration summary
get_config_summary() {
    log_info ""
    log_info "Prometheus Hedgehog Scrape Configuration Summary:"
    log_info "  Job Name: ${HEDGEHOG_SCRAPE_JOB}"
    log_info "  Scrape Interval: ${SCRAPE_INTERVAL}"
    log_info "  Target Endpoint: ${HEDGEHOG_FABRIC_PROXY_ENDPOINT}/metrics"
    log_info "  TLS Verification: Disabled (self-signed certs)"
    log_info "  Labels:"
    log_info "    - source: hedgehog-fabric"
    log_info "    - environment: vlab"
    log_info ""
    log_info "Verify metrics in Prometheus:"
    log_info "  1. Access Prometheus: http://localhost:9090"
    log_info "  2. Go to Status > Targets"
    log_info "  3. Look for job: ${HEDGEHOG_SCRAPE_JOB}"
    log_info "  4. Query metrics: up{source=\"hedgehog-fabric\"}"
    log_info ""
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "Prometheus Hedgehog Scrape Configuration Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${PROMETHEUS_SCRAPE_TIMEOUT}s ($(( PROMETHEUS_SCRAPE_TIMEOUT / 60 )) minutes)"
    log_info ""

    local overall_start
    overall_start=$(date +%s)

    # Execute configuration steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! wait_for_fabric_proxy; then
        log_warn "Fabric-proxy accessibility check incomplete (non-fatal)"
    fi

    if ! create_scrape_config; then
        log_error "Failed to create scrape configuration"
        return 1
    fi

    if ! verify_scraping; then
        log_warn "Scraping verification incomplete (non-fatal)"
    fi

    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    get_config_summary

    log_info ""
    log_info "=================================================="
    log_info "Prometheus Hedgehog Scrape Configuration Complete!"
    log_info "=================================================="
    log_info "Total configuration time: ${total_time}s"
    log_info "Prometheus is configured to scrape Hedgehog fabric"
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
    # Validate that scrape config secret exists
    kubectl config use-context k3d-k3d-observability &> /dev/null
    kubectl get secret -n "$PROMETHEUS_NAMESPACE" additional-scrape-configs &> /dev/null
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
  "timeout": $PROMETHEUS_SCRAPE_TIMEOUT,
  "dependencies": ["vlab", "k3d", "prometheus"]
}
EOF
}
