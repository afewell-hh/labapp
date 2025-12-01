#!/bin/bash
# test-first-boot-setup.sh
# Updated for Issue #97: BYO-VM installer replaces hh-lab setup

set -euo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

HH_LAB_SCRIPT="installer/modules/hh-lab"
INIT_SERVICE="installer/modules/hedgehog-lab-init.service"
INSTALLER="scripts/hh-lab-installer"
GHCR_AUTH="scripts/10-ghcr-auth.sh"

log_test() { echo -e "\nTEST: $*"; TESTS_RUN=$((TESTS_RUN+1)); }
pass() { echo -e "${GREEN}✓ PASS${NC}: $*"; TESTS_PASSED=$((TESTS_PASSED+1)); }
fail() { echo -e "${RED}✗ FAIL${NC}: $*"; TESTS_FAILED=$((TESTS_FAILED+1)); FAILED_TESTS+=("$*"); }

echo "========================================"
echo "BYO-VM Installer / First-Boot Tests"
echo "========================================"

log_test "hh-lab script exists and has valid syntax"
if [ -x "$HH_LAB_SCRIPT" ] && bash -n "$HH_LAB_SCRIPT"; then
    pass "hh-lab present and syntax valid"
else
    fail "hh-lab missing or invalid syntax"
fi

log_test "hh-lab setup command is deprecated with installer guidance"
if grep -q "BYO-VM installer" "$HH_LAB_SCRIPT"; then
    pass "Deprecated setup path points to installer"
else
    fail "Setup command did not indicate installer replacement"
fi

log_test "hh-lab still surfaces GHCR authentication status"
if grep -q "GHCR Authentication" "$HH_LAB_SCRIPT"; then
    pass "Status includes GHCR section"
else
    fail "GHCR status missing from hh-lab"
fi

log_test "credentials marker variable defined"
if grep -q "GHCR_CREDS_MARKER=" "$HH_LAB_SCRIPT"; then
    pass "GHCR marker variable present"
else
    fail "GHCR marker variable missing"
fi

log_test "installer assets exist"
if [ -x "$INSTALLER" ] && [ -f "$GHCR_AUTH" ]; then
    pass "Installer and GHCR auth scripts found"
else
    fail "Installer scripts missing"
fi

log_test "GHCR auth script performs docker login"
if grep -q "docker login ghcr.io" "$GHCR_AUTH"; then
    pass "GHCR auth script will login to GHCR"
else
    fail "GHCR auth script missing docker login"
fi

log_test "hedgehog-lab-init.service still gated on credentials marker"
if [ -f "$INIT_SERVICE" ] && grep -q "/var/lib/hedgehog-lab/ghcr-authenticated" "$INIT_SERVICE"; then
    pass "Service retains GHCR condition gate"
else
    fail "Service missing GHCR condition gate"
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
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}✗${NC} $t"
    done
else
    echo -e "${GREEN}Failed: $TESTS_FAILED${NC}"
fi

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
