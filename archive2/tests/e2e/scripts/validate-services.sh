#!/bin/bash
# validate-services.sh
# Validates all services are running and accessible
#
# Usage: ./validate-services.sh
# Run inside the appliance VM after initialization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/service-validation-${TIMESTAMP}.json"

# Timeouts (in seconds)
KUBECTL_TIMEOUT=30
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

test_warn() {
    local test_name="$1"
    local reason="$2"
    log_warn "⚠ ${test_name}: ${reason}"
}

# Main validation logic
main() {
    echo "======================================"
    echo "Service Validation Test"
    echo "======================================"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Test 1: Lab initialized
    if [ -f "/var/lib/hedgehog-lab/initialized" ]; then
        test_pass "Lab initialization completed"
    else
        test_fail "Lab initialization completed" "Initialization stamp file not found"
    fi

    # Test 2: kubectl available
    if command -v kubectl > /dev/null 2>&1; then
        test_pass "kubectl command available"
    else
        test_fail "kubectl command available" "kubectl not found in PATH"
        write_results "FAIL"
        exit 1
    fi

    # Test 3: k3d cluster accessible
    if timeout "${KUBECTL_TIMEOUT}" kubectl cluster-info > /dev/null 2>&1; then
        test_pass "k3d cluster accessible"
    else
        test_fail "k3d cluster accessible" "Cannot connect to cluster"
    fi

    # Test 4: Cluster nodes ready
    local nodes_ready
    nodes_ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
    if [ "${nodes_ready}" -gt 0 ]; then
        test_pass "Cluster nodes ready (${nodes_ready} node(s))"
    else
        test_fail "Cluster nodes ready" "No nodes in Ready state"
    fi

    # Test 5: Monitoring namespace exists
    if kubectl get namespace monitoring > /dev/null 2>&1; then
        test_pass "Monitoring namespace exists"
    else
        test_fail "Monitoring namespace exists" "Namespace not found"
    fi

    # Test 6: Monitoring pods running
    if kubectl get namespace monitoring > /dev/null 2>&1; then
        local monitoring_pods
        monitoring_pods=$(kubectl get pods -n monitoring --no-headers 2>/dev/null | wc -l)
        if [ "${monitoring_pods}" -gt 0 ]; then
            local running_pods
            running_pods=$(kubectl get pods -n monitoring --no-headers 2>/dev/null | grep -c " Running " || echo "0")
            if [ "${running_pods}" -eq "${monitoring_pods}" ]; then
                test_pass "All monitoring pods running (${running_pods}/${monitoring_pods})"
            else
                test_fail "All monitoring pods running" "${running_pods}/${monitoring_pods} pods running"
            fi
        else
            test_warn "Monitoring pods running" "No pods found in monitoring namespace"
        fi
    fi

    # Test 7: Grafana endpoint accessible
    if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        test_pass "Grafana endpoint accessible"
    else
        test_fail "Grafana endpoint accessible" "Cannot reach http://localhost:3000"
    fi

    # Test 8: Prometheus endpoint accessible
    if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
        test_pass "Prometheus endpoint accessible"
    else
        test_warn "Prometheus endpoint accessible" "Cannot reach http://localhost:9090 (may not be exposed)"
    fi

    # Test 9: ArgoCD namespace exists (may be pending in v0.1.0)
    if kubectl get namespace argocd > /dev/null 2>&1; then
        test_pass "ArgoCD namespace exists"

        # Test 9a: ArgoCD pods running
        local argocd_pods
        argocd_pods=$(kubectl get pods -n argocd --no-headers 2>/dev/null | wc -l)
        if [ "${argocd_pods}" -gt 0 ]; then
            local running_argocd
            running_argocd=$(kubectl get pods -n argocd --no-headers 2>/dev/null | grep -c " Running " || echo "0")
            if [ "${running_argocd}" -eq "${argocd_pods}" ]; then
                test_pass "All ArgoCD pods running (${running_argocd}/${argocd_pods})"
            else
                test_fail "All ArgoCD pods running" "${running_argocd}/${argocd_pods} pods running"
            fi
        fi

        # Test 9b: ArgoCD endpoint accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:8080/healthz > /dev/null 2>&1; then
            test_pass "ArgoCD endpoint accessible"
        else
            test_fail "ArgoCD endpoint accessible" "Cannot reach http://localhost:8080"
        fi
    else
        log_warn "ArgoCD namespace not found (may be pending in v0.1.0)"
    fi

    # Test 10: Gitea namespace exists (may be pending in v0.1.0)
    if kubectl get namespace gitea > /dev/null 2>&1; then
        test_pass "Gitea namespace exists"

        # Test 10a: Gitea pods running
        local gitea_pods
        gitea_pods=$(kubectl get pods -n gitea --no-headers 2>/dev/null | wc -l)
        if [ "${gitea_pods}" -gt 0 ]; then
            local running_gitea
            running_gitea=$(kubectl get pods -n gitea --no-headers 2>/dev/null | grep -c " Running " || echo "0")
            if [ "${running_gitea}" -eq "${gitea_pods}" ]; then
                test_pass "All Gitea pods running (${running_gitea}/${gitea_pods})"
            else
                test_fail "All Gitea pods running" "${running_gitea}/${gitea_pods} pods running"
            fi
        fi

        # Test 10b: Gitea endpoint accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3001/ > /dev/null 2>&1; then
            test_pass "Gitea endpoint accessible"
        else
            test_fail "Gitea endpoint accessible" "Cannot reach http://localhost:3001"
        fi
    else
        log_warn "Gitea namespace not found (may be pending in v0.1.0)"
    fi

    # Test 11: Docker daemon accessible (for VLAB)
    if command -v docker > /dev/null 2>&1; then
        if docker info > /dev/null 2>&1; then
            test_pass "Docker daemon accessible"
        else
            test_fail "Docker daemon accessible" "Cannot connect to Docker daemon"
        fi
    else
        test_fail "Docker daemon accessible" "docker command not found"
    fi

    # Test 12: VLAB containers running
    if command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
        local vlab_containers
        vlab_containers=$(docker ps --filter "name=vlab-" --format "{{.Names}}" | wc -l)
        if [ "${vlab_containers}" -eq 7 ]; then
            test_pass "VLAB containers running (${vlab_containers}/7)"
        elif [ "${vlab_containers}" -gt 0 ]; then
            test_fail "VLAB containers running" "Only ${vlab_containers}/7 containers running"
        else
            test_fail "VLAB containers running" "No VLAB containers found"
        fi
    fi

    # Summary
    echo ""
    echo "======================================"
    echo "Service Validation Summary"
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
  "test_suite": "service-validation",
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
