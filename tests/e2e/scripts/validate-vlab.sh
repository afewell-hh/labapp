#!/bin/bash
# validate-vlab.sh
# Validates VLAB environment functionality
#
# Usage: ./validate-vlab.sh
# Run inside the appliance VM after initialization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/vlab-validation-${TIMESTAMP}.json"

VLAB_DIR="/opt/hedgehog/vlab"
EXPECTED_SWITCHES=7

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
    echo "VLAB Validation Test"
    echo "======================================"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Test 1: VLAB directory exists
    if [ -d "${VLAB_DIR}" ]; then
        test_pass "VLAB directory exists"
    else
        test_fail "VLAB directory exists" "Directory not found: ${VLAB_DIR}"
    fi

    # Test 2: VLAB configuration files present
    if [ -d "${VLAB_DIR}" ]; then
        if [ -f "${VLAB_DIR}/wiring.yaml" ]; then
            test_pass "VLAB wiring configuration exists"
        else
            test_warn "VLAB wiring configuration exists" "wiring.yaml not found"
        fi
    fi

    # Test 3: Docker available
    if ! command -v docker > /dev/null 2>&1; then
        test_fail "Docker command available" "docker not found in PATH"
        write_results "FAIL"
        exit 1
    else
        test_pass "Docker command available"
    fi

    # Test 4: Docker daemon accessible
    if ! docker info > /dev/null 2>&1; then
        test_fail "Docker daemon accessible" "Cannot connect to Docker daemon"
        write_results "FAIL"
        exit 1
    else
        test_pass "Docker daemon accessible"
    fi

    # Test 5: VLAB containers exist
    local vlab_containers
    vlab_containers=$(docker ps -a --filter "name=vlab-" --format "{{.Names}}" | wc -l)
    if [ "${vlab_containers}" -eq "${EXPECTED_SWITCHES}" ]; then
        test_pass "VLAB containers exist (${vlab_containers}/${EXPECTED_SWITCHES})"
    else
        test_fail "VLAB containers exist" "Found ${vlab_containers}/${EXPECTED_SWITCHES} containers"
    fi

    # Test 6: VLAB containers running
    local running_containers
    running_containers=$(docker ps --filter "name=vlab-" --format "{{.Names}}" | wc -l)
    if [ "${running_containers}" -eq "${EXPECTED_SWITCHES}" ]; then
        test_pass "VLAB containers running (${running_containers}/${EXPECTED_SWITCHES})"
    else
        test_fail "VLAB containers running" "Only ${running_containers}/${EXPECTED_SWITCHES} running"
    fi

    # Test 7: Specific switch containers present
    local expected_switches=("vlab-spine-1" "vlab-spine-2" "vlab-leaf-1" "vlab-leaf-2" "vlab-leaf-3" "vlab-leaf-4" "vlab-control-1")
    for switch in "${expected_switches[@]}"; do
        if docker ps --filter "name=${switch}" --format "{{.Names}}" | grep -q "${switch}"; then
            test_pass "Switch container ${switch} running"
        else
            test_fail "Switch container ${switch} running" "Container not found or not running"
        fi
    done

    # Test 8: Switch console access (test one switch)
    if docker exec vlab-leaf-1 echo "test" > /dev/null 2>&1; then
        test_pass "Switch console access (vlab-leaf-1)"
    else
        test_fail "Switch console access (vlab-leaf-1)" "Cannot execute command in container"
    fi

    # Test 9: VLAB networks exist
    local vlab_networks
    vlab_networks=$(docker network ls --filter "name=vlab" --format "{{.Name}}" | wc -l)
    if [ "${vlab_networks}" -gt 0 ]; then
        test_pass "VLAB Docker networks exist (${vlab_networks} network(s))"
    else
        test_fail "VLAB Docker networks exist" "No VLAB networks found"
    fi

    # Test 10: VLAB log file exists
    if [ -f "/var/log/hedgehog-lab/modules/vlab.log" ]; then
        test_pass "VLAB initialization log exists"

        # Check for errors in log
        if grep -q "ERROR" "/var/log/hedgehog-lab/modules/vlab.log"; then
            test_warn "VLAB log has no errors" "ERROR messages found in log"
        else
            test_pass "VLAB log has no errors"
        fi
    else
        test_warn "VLAB initialization log exists" "Log file not found"
    fi

    # Summary
    echo ""
    echo "======================================"
    echo "VLAB Validation Summary"
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
  "test_suite": "vlab-validation",
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

  ],
  "details": {
    "vlab_containers_found": ${vlab_containers:-0},
    "vlab_containers_running": ${running_containers:-0},
    "expected_containers": ${EXPECTED_SWITCHES}
  }
}
EOF

    log_info "Results written to: ${RESULT_FILE}"
}

# Entry point
main "$@"
