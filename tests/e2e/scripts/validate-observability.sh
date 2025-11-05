#!/bin/bash
# validate-observability.sh
# Validates observability stack (Prometheus, Grafana, Loki)
#
# Usage: ./validate-observability.sh
# Run inside the appliance VM after initialization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/observability-validation-${TIMESTAMP}.json"

HTTP_TIMEOUT=10

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Test result tracking
test_pass() {
    local test_name="$1"
    ((TESTS_RUN++))
    ((TESTS_PASSED++))
    log_info "✓ ${test_name}"
}

test_fail() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_RUN++))
    ((TESTS_FAILED++))
    FAILURES+=("${test_name}: ${reason}")
    log_error "✗ ${test_name}: ${reason}"
}

# Main validation logic
main() {
    echo "======================================"
    echo "Observability Validation Test"
    echo "======================================"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Test 1: Monitoring namespace exists
    if kubectl get namespace monitoring > /dev/null 2>&1; then
        test_pass "Monitoring namespace exists"
    else
        test_fail "Monitoring namespace exists" "Namespace not found"
        write_results "FAIL"
        exit 1
    fi

    # Test 2: Monitoring pods running
    local monitoring_pods
    monitoring_pods=$(kubectl get pods -n monitoring --no-headers 2>/dev/null | wc -l)
    if [ "${monitoring_pods}" -gt 0 ]; then
        local running_pods
        running_pods=$(kubectl get pods -n monitoring --no-headers 2>/dev/null | grep -c " Running " || echo "0")
        if [ "${running_pods}" -eq "${monitoring_pods}" ]; then
            test_pass "All monitoring pods running (${running_pods}/${monitoring_pods})"
        else
            test_fail "All monitoring pods running" "${running_pods}/${monitoring_pods} pods in Running state"
        fi
    else
        test_fail "Monitoring pods exist" "No pods found in monitoring namespace"
    fi

    # Test 3: Grafana accessible
    if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        test_pass "Grafana health endpoint accessible"
    else
        test_fail "Grafana health endpoint accessible" "Cannot reach http://localhost:3000/api/health"
    fi

    # Test 4: Grafana login page
    if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3000/login > /dev/null 2>&1; then
        test_pass "Grafana login page accessible"
    else
        test_fail "Grafana login page accessible" "Cannot reach http://localhost:3000/login"
    fi

    # Test 5: Grafana datasources API
    local grafana_ds
    grafana_ds=$(timeout "${HTTP_TIMEOUT}" curl -sf -u admin:admin http://localhost:3000/api/datasources 2>/dev/null || echo "[]")
    if echo "${grafana_ds}" | grep -q "Prometheus\|prometheus"; then
        test_pass "Grafana has Prometheus datasource"
    else
        test_warn "Grafana has Prometheus datasource" "Prometheus datasource not found or requires login"
    fi

    # Test 6: Prometheus accessible (may not be exposed)
    if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
        test_pass "Prometheus health endpoint accessible"
    else
        log_warn "Prometheus not accessible at localhost:9090 (may not be exposed externally)"
    fi

    # Test 7: Prometheus targets (via kubectl port-forward)
    local prom_pod
    prom_pod=$(kubectl get pods -n monitoring -l "app.kubernetes.io/name=prometheus" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "${prom_pod}" ]; then
        test_pass "Prometheus pod found (${prom_pod})"

        # Test Prometheus is responding (quick check via kubectl exec)
        if kubectl exec -n monitoring "${prom_pod}" -c prometheus -- wget -qO- http://localhost:9090/-/healthy > /dev/null 2>&1; then
            test_pass "Prometheus responding to health checks"
        else
            test_fail "Prometheus responding to health checks" "Health check failed"
        fi
    else
        test_fail "Prometheus pod found" "No Prometheus pod found"
    fi

    # Test 8: Loki pod exists
    local loki_pod
    loki_pod=$(kubectl get pods -n monitoring -l "app.kubernetes.io/name=loki" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "${loki_pod}" ]; then
        test_pass "Loki pod found (${loki_pod})"

        # Test Loki is responding
        if kubectl exec -n monitoring "${loki_pod}" -- wget -qO- http://localhost:3100/ready > /dev/null 2>&1; then
            test_pass "Loki responding to ready checks"
        else
            test_warn "Loki responding to ready checks" "Ready check failed or endpoint not available"
        fi
    else
        test_warn "Loki pod found" "No Loki pod found (may not be deployed)"
    fi

    # Test 9: Node exporter running
    local node_exporter_pods
    node_exporter_pods=$(kubectl get pods -n monitoring -l "app.kubernetes.io/name=node-exporter" --no-headers 2>/dev/null | wc -l)
    if [ "${node_exporter_pods}" -gt 0 ]; then
        test_pass "Node exporter pods running (${node_exporter_pods})"
    else
        test_warn "Node exporter pods running" "No node-exporter pods found"
    fi

    # Test 10: Kube-state-metrics running
    local ksm_pods
    ksm_pods=$(kubectl get pods -n monitoring -l "app.kubernetes.io/name=kube-state-metrics" --no-headers 2>/dev/null | wc -l)
    if [ "${ksm_pods}" -gt 0 ]; then
        test_pass "Kube-state-metrics pods running (${ksm_pods})"
    else
        test_warn "Kube-state-metrics pods running" "No kube-state-metrics pods found"
    fi

    # Test 11: Metrics server (if deployed)
    if kubectl top nodes > /dev/null 2>&1; then
        test_pass "Metrics server functional (kubectl top nodes works)"
    else
        test_warn "Metrics server functional" "kubectl top nodes failed (metrics server may not be deployed)"
    fi

    # Summary
    echo ""
    echo "======================================"
    echo "Observability Validation Summary"
    echo "======================================"
    echo "Tests run: ${TESTS_RUN}"
    echo "Tests passed: ${TESTS_PASSED}"
    echo "Tests failed: ${TESTS_FAILED}"
    echo ""

    if [ ${TESTS_FAILED} -eq 0 ]; then
        log_info "All tests passed! ✓"
        write_results "PASS"
        exit 0
    else
        log_error "Some tests failed:"
        for failure in "${FAILURES[@]}"; do
            echo "  - ${failure}"
        done
        write_results "FAIL"
        exit 1
    fi
}

# Write results to JSON file
write_results() {
    local status="$1"

    cat > "${RESULT_FILE}" <<EOF
{
  "test_suite": "observability-validation",
  "timestamp": "${TIMESTAMP}",
  "status": "${status}",
  "tests_run": ${TESTS_RUN},
  "tests_passed": ${TESTS_PASSED},
  "tests_failed": ${TESTS_FAILED},
  "failures": [
EOF

    # Add failures
    local first=true
    for failure in "${FAILURES[@]}"; do
        if [ "${first}" = true ]; then
            first=false
        else
            echo "," >> "${RESULT_FILE}"
        fi
        echo -n "    \"${failure}\"" >> "${RESULT_FILE}"
    done

    cat >> "${RESULT_FILE}" <<EOF

  ]
}
EOF

    log_info "Results written to: ${RESULT_FILE}"
}

# Entry point
main "$@"
