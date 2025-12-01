#!/bin/bash
# test-orchestrator-ordering.sh
# Unit tests for orchestrator step ordering
# Validates that VLAB initialization happens before k3d/EMC/GitOps
#
# Usage: ./test-orchestrator-ordering.sh
# Requires: bash 4+, grep

set -euo pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCHESTRATOR_SCRIPT="${SCRIPT_DIR}/../../installer/modules/hedgehog-lab-orchestrator"
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

# Test 1: Orchestrator script exists
test_orchestrator_exists() {
    log_info "Test 1: Checking orchestrator script exists..."

    if [ -f "$ORCHESTRATOR_SCRIPT" ]; then
        log_pass "Orchestrator script found at $ORCHESTRATOR_SCRIPT"
        return 0
    else
        log_fail "Orchestrator script not found at $ORCHESTRATOR_SCRIPT"
        return 1
    fi
}

# Test 2: VLAB initialization comes before k3d
test_vlab_before_k3d() {
    log_info "Test 2: Checking VLAB initialization happens before k3d..."

    # Extract the line numbers for VLAB and k3d initialization
    local vlab_line
    vlab_line=$(grep -n "Initialize VLAB" "$ORCHESTRATOR_SCRIPT" | head -1 | cut -d: -f1)

    local k3d_line
    k3d_line=$(grep -n "Initialize k3d cluster" "$ORCHESTRATOR_SCRIPT" | head -1 | cut -d: -f1)

    if [ -z "$vlab_line" ]; then
        log_fail "Could not find VLAB initialization step"
        return 1
    fi

    if [ -z "$k3d_line" ]; then
        log_fail "Could not find k3d initialization step"
        return 1
    fi

    if [ "$vlab_line" -lt "$k3d_line" ]; then
        log_pass "VLAB initialization (line $vlab_line) comes before k3d (line $k3d_line)"
        return 0
    else
        log_fail "k3d initialization (line $k3d_line) comes before VLAB (line $vlab_line)"
        return 1
    fi
}

# Test 3: VLAB uses systemd service
test_vlab_uses_systemd() {
    log_info "Test 3: Checking VLAB initialization uses systemd service..."

    # Check that init_vlab function references systemd
    if grep -q "hhfab-vlab.service" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "VLAB initialization uses hhfab-vlab.service"
        return 0
    else
        log_fail "VLAB initialization does not reference hhfab-vlab.service"
        return 1
    fi
}

# Test 4: Orchestrator waits for service completion
test_orchestrator_waits_for_service() {
    log_info "Test 4: Checking orchestrator waits for VLAB service completion..."

    # Check that init_vlab function waits for systemd service
    if grep -A 120 "^init_vlab()" "$ORCHESTRATOR_SCRIPT" | grep -q "systemctl show"; then
        log_pass "Orchestrator waits for VLAB service state"
        return 0
    else
        log_fail "Orchestrator does not wait for VLAB service state"
        return 1
    fi
}

# Test 5: State marker verification
test_state_marker_check() {
    log_info "Test 5: Checking orchestrator verifies VLAB state marker..."

    # Check that init_vlab verifies the state marker
    if grep -A 70 "^init_vlab()" "$ORCHESTRATOR_SCRIPT" | grep -q "vlab-initialized"; then
        log_pass "Orchestrator checks for VLAB state marker"
        return 0
    else
        log_fail "Orchestrator does not check for VLAB state marker"
        return 1
    fi
}

# Test 6: Step numbering is correct
test_step_numbering() {
    log_info "Test 6: Checking step numbering is sequential..."

    # Extract step numbers from standard build section
    local step_numbers
    step_numbers=$(grep -A 20 'BUILD_TYPE.*=.*"standard"' "$ORCHESTRATOR_SCRIPT" | \
                   grep "execute_step" | \
                   grep -oP 'execute_step "[^"]*" \K\d+' | \
                   tr '\n' ' ')

    # Expected sequence: 1 2 3 4 5
    if echo "$step_numbers" | grep -q "1 2 3 4 5"; then
        log_pass "Step numbers are sequential: $step_numbers"
        return 0
    else
        log_fail "Step numbers are not sequential: $step_numbers"
        return 1
    fi
}

# Test 7: VLAB is step 3 (after network + hhfab install)
test_vlab_is_step_3() {
    log_info "Test 7: Checking VLAB is step 3 (after hhfab install)..."

    # Check that "Initialize VLAB" is step 3
    if grep -A 20 'BUILD_TYPE.*=.*\"standard\"' "$ORCHESTRATOR_SCRIPT" | \
       grep "execute_step.*Initialize VLAB" | \
       grep -q " 3 "; then
        log_pass "VLAB runs at step 3 after network + hhfab install"
        return 0
    else
        log_fail "VLAB is not step 3"
        return 1
    fi
}

# Test 8: Comments indicate VLAB-first requirement
test_vlab_first_comments() {
    log_info "Test 8: Checking code comments indicate VLAB-first requirement..."

    # Check for comments explaining VLAB-first ordering
    if grep -q "VLAB MUST initialize first" "$ORCHESTRATOR_SCRIPT" || \
       grep -q "Issue #73" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Code includes comments about VLAB-first requirement"
        return 0
    else
        log_fail "Code lacks comments explaining VLAB-first requirement"
        return 1
    fi
}

# Test 9: Log files pre-created with hhlab ownership
test_log_ownership_setup() {
    log_info "Test 9: Checking orchestrator sets up log file ownership..."

    # Each init function should touch and chown the log file before writing
    # This prevents permission errors when services run as hhlab
    local ownership_ok=true

    # Check wait_for_network sets up log ownership
    if ! grep -A 10 "wait_for_network()" "$ORCHESTRATOR_SCRIPT" | \
         grep -q 'chown hhlab:hhlab.*module_log'; then
        log_fail "wait_for_network does not set up log file ownership"
        ownership_ok=false
    fi

    # Check init_k3d_cluster sets up log ownership
    if ! grep -A 10 "init_k3d_cluster()" "$ORCHESTRATOR_SCRIPT" | \
         grep -q 'chown hhlab:hhlab.*module_log'; then
        log_fail "init_k3d_cluster does not set up log file ownership"
        ownership_ok=false
    fi

    # Check init_vlab sets up log ownership
    if ! grep -A 10 "init_vlab()" "$ORCHESTRATOR_SCRIPT" | \
         grep -q 'chown hhlab:hhlab.*module_log'; then
        log_fail "init_vlab does not set up log file ownership"
        ownership_ok=false
    fi

    if [ "$ownership_ok" = true ]; then
        log_pass "All module logs are pre-created with hhlab ownership"
        return 0
    else
        return 1
    fi
}

test_vlab_disk_check() {
    log_info "Test 10: Checking VLAB preflight enforces disk space guard..."

    if grep -A 40 "^init_vlab()" "$ORCHESTRATOR_SCRIPT" | grep -q "check_disk_space"; then
        log_pass "init_vlab() calls check_disk_space before launching hhfab"
        return 0
    else
        log_fail "init_vlab() is missing the disk space preflight check"
        return 1
    fi
}

# Main test execution
main() {
    echo ""
    echo "=========================================="
    echo "  Orchestrator Ordering Unit Tests"
    echo "=========================================="
    echo ""

    # Run all tests
    test_orchestrator_exists || true
    test_vlab_before_k3d || true
    test_vlab_uses_systemd || true
    test_orchestrator_waits_for_service || true
    test_state_marker_check || true
    test_step_numbering || true
    test_vlab_is_step_3 || true
    test_vlab_first_comments || true
    test_log_ownership_setup || true
    test_vlab_disk_check || true

    # Summary
    echo ""
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo ""

    # Exit with appropriate code
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run tests
main "$@"
