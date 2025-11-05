#!/bin/bash
# validate-gitops.sh
# Validates GitOps stack (ArgoCD + Gitea) functionality
#
# Usage: ./validate-gitops.sh
# Run inside the appliance VM after initialization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/gitops-validation-${TIMESTAMP}.json"

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
    echo "GitOps Validation Test"
    echo "======================================"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Check if GitOps is deployed (may be pending in v0.1.0)
    local argocd_deployed=false
    local gitea_deployed=false

    # Test ArgoCD namespace
    if kubectl get namespace argocd > /dev/null 2>&1; then
        argocd_deployed=true
        test_pass "ArgoCD namespace exists"
    else
        log_warn "ArgoCD not deployed (pending in v0.1.0)"
    fi

    # Test Gitea namespace
    if kubectl get namespace gitea > /dev/null 2>&1; then
        gitea_deployed=true
        test_pass "Gitea namespace exists"
    else
        log_warn "Gitea not deployed (pending in v0.1.0)"
    fi

    # If neither deployed, skip remaining tests
    if [ "${argocd_deployed}" = false ] && [ "${gitea_deployed}" = false ]; then
        log_warn "GitOps stack not deployed - skipping tests"
        write_results "SKIP"
        exit 0
    fi

    # ArgoCD tests
    if [ "${argocd_deployed}" = true ]; then
        # Test 1: ArgoCD pods running
        local argocd_pods
        argocd_pods=$(kubectl get pods -n argocd --no-headers 2>/dev/null | wc -l)
        if [ "${argocd_pods}" -gt 0 ]; then
            local running_pods
            running_pods=$(kubectl get pods -n argocd --no-headers 2>/dev/null | grep -c " Running " || echo "0")
            if [ "${running_pods}" -eq "${argocd_pods}" ]; then
                test_pass "ArgoCD pods running (${running_pods}/${argocd_pods})"
            else
                test_fail "ArgoCD pods running" "${running_pods}/${argocd_pods} pods in Running state"
            fi
        else
            test_fail "ArgoCD pods exist" "No pods found in argocd namespace"
        fi

        # Test 2: ArgoCD server accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:8080/healthz > /dev/null 2>&1; then
            test_pass "ArgoCD server accessible"
        else
            test_fail "ArgoCD server accessible" "Cannot reach http://localhost:8080/healthz"
        fi

        # Test 3: ArgoCD API accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:8080/api/version > /dev/null 2>&1; then
            test_pass "ArgoCD API accessible"
        else
            test_fail "ArgoCD API accessible" "Cannot reach API endpoint"
        fi

        # Test 4: ArgoCD admin secret exists
        if kubectl get secret argocd-initial-admin-secret -n argocd > /dev/null 2>&1; then
            test_pass "ArgoCD admin secret exists"
        else
            test_fail "ArgoCD admin secret exists" "Secret not found"
        fi
    fi

    # Gitea tests
    if [ "${gitea_deployed}" = true ]; then
        # Test 5: Gitea pods running
        local gitea_pods
        gitea_pods=$(kubectl get pods -n gitea --no-headers 2>/dev/null | wc -l)
        if [ "${gitea_pods}" -gt 0 ]; then
            local running_gitea
            running_gitea=$(kubectl get pods -n gitea --no-headers 2>/dev/null | grep -c " Running " || echo "0")
            if [ "${running_gitea}" -eq "${gitea_pods}" ]; then
                test_pass "Gitea pods running (${running_gitea}/${gitea_pods})"
            else
                test_fail "Gitea pods running" "${running_gitea}/${gitea_pods} pods in Running state"
            fi
        else
            test_fail "Gitea pods exist" "No pods found in gitea namespace"
        fi

        # Test 6: Gitea server accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3001/ > /dev/null 2>&1; then
            test_pass "Gitea server accessible"
        else
            test_fail "Gitea server accessible" "Cannot reach http://localhost:3001"
        fi

        # Test 7: Gitea API accessible
        if timeout "${HTTP_TIMEOUT}" curl -sf http://localhost:3001/api/v1/version > /dev/null 2>&1; then
            test_pass "Gitea API accessible"
        else
            test_fail "Gitea API accessible" "Cannot reach API endpoint"
        fi
    fi

    # Summary
    echo ""
    echo "======================================"
    echo "GitOps Validation Summary"
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
  "test_suite": "gitops-validation",
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
