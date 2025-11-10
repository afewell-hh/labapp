#!/bin/bash
# test-first-boot-setup.sh
# Unit tests for first-boot GHCR setup flow (Issue #88)
#
# Tests the hh-lab setup command and systemd service gating

set -euo pipefail

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test result tracking
FAILED_TESTS=()

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_test() {
    echo ""
    echo "TEST: $*"
    TESTS_RUN=$((TESTS_RUN + 1))
}

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $*"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILED_TESTS+=("$*")
}

# File paths
HH_LAB_SCRIPT="packer/scripts/hh-lab"
INIT_SERVICE="packer/scripts/hedgehog-lab-init.service"

echo "========================================"
echo "First-Boot GHCR Setup Tests"
echo "========================================"
echo ""

# Test 1: hh-lab script exists and is executable
log_test "hh-lab script exists and is executable"
if [ -f "$HH_LAB_SCRIPT" ] && [ -x "$HH_LAB_SCRIPT" ]; then
    pass "hh-lab script exists and is executable"
else
    fail "hh-lab script not found or not executable"
fi

# Test 2: hh-lab script has valid bash syntax
log_test "hh-lab script has valid bash syntax"
if bash -n "$HH_LAB_SCRIPT"; then
    pass "hh-lab script has valid syntax"
else
    fail "hh-lab script has syntax errors"
fi

# Test 3: hh-lab script contains setup command
log_test "hh-lab script contains setup command"
if grep -q "cmd_setup()" "$HH_LAB_SCRIPT" && grep -q "setup)" "$HH_LAB_SCRIPT"; then
    pass "hh-lab script contains setup command"
else
    fail "hh-lab script missing setup command"
fi

# Test 4: hh-lab script contains GHCR_CREDS_MARKER variable
log_test "hh-lab script contains GHCR_CREDS_MARKER variable"
if grep -q "GHCR_CREDS_MARKER=" "$HH_LAB_SCRIPT"; then
    pass "hh-lab script defines GHCR_CREDS_MARKER variable"
else
    fail "hh-lab script missing GHCR_CREDS_MARKER variable"
fi

# Test 5: hh-lab script implements docker login
log_test "hh-lab script implements docker login"
if grep -q "docker login ghcr.io" "$HH_LAB_SCRIPT"; then
    pass "hh-lab script implements docker login to ghcr.io"
else
    fail "hh-lab script missing docker login implementation"
fi

# Test 6: hh-lab script wipes token from memory
log_test "hh-lab script wipes token from memory"
if grep -q "unset ghcr_token" "$HH_LAB_SCRIPT"; then
    pass "hh-lab script unsets token variable"
else
    fail "hh-lab script does not unset token variable"
fi

# Test 7: hh-lab status command shows credentials status
log_test "hh-lab status command shows credentials status"
if grep -q "GHCR Authentication" "$HH_LAB_SCRIPT"; then
    pass "hh-lab status shows GHCR authentication status"
else
    fail "hh-lab status missing GHCR authentication status"
fi

# Test 8: hedgehog-lab-init.service gates on credentials marker
log_test "hedgehog-lab-init.service gates on credentials marker"
if [ -f "$INIT_SERVICE" ]; then
    if grep -q "ConditionPathExists=/var/lib/hedgehog-lab/ghcr-authenticated" "$INIT_SERVICE"; then
        pass "hedgehog-lab-init.service gates on ghcr-authenticated marker"
    else
        fail "hedgehog-lab-init.service missing credentials gate condition"
    fi
else
    fail "hedgehog-lab-init.service not found"
fi

# Test 9: hh-lab help text documents setup command
log_test "hh-lab help text documents setup command"
if grep -q "setup}" "$HH_LAB_SCRIPT" && grep -q "Configure GHCR credentials" "$HH_LAB_SCRIPT"; then
    pass "hh-lab help text documents setup command"
else
    fail "hh-lab help text missing setup command documentation"
fi

# Test 10: hh-lab setup provides clear instructions for obtaining PAT
log_test "hh-lab setup provides PAT instructions"
if grep -q "github.com/settings/tokens" "$HH_LAB_SCRIPT" && grep -q "read:packages" "$HH_LAB_SCRIPT"; then
    pass "hh-lab setup provides clear PAT instructions"
else
    fail "hh-lab setup missing PAT instructions"
fi

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Tests run: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo ""
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}✗${NC} $test"
    done
else
    echo -e "${GREEN}Failed: $TESTS_FAILED${NC}"
fi
echo ""

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
