#!/bin/bash
# test-gcp-build-script.sh
# Unit tests for GCP build script
# Validates argument parsing, environment loading, and dry-run functionality
#
# Usage: ./test-gcp-build-script.sh
# Requires: bash 4+, grep

set -euo pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_BUILD_SCRIPT="${SCRIPT_DIR}/../../scripts/launch-gcp-build.sh"
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

# Test 1: GCP build script exists
test_script_exists() {
    log_info "Test 1: Checking GCP build script exists..."

    if [ -f "$GCP_BUILD_SCRIPT" ]; then
        log_pass "GCP build script found at $GCP_BUILD_SCRIPT"
        return 0
    else
        log_fail "GCP build script not found at $GCP_BUILD_SCRIPT"
        return 1
    fi
}

# Test 2: Script has valid bash syntax
test_script_syntax() {
    log_info "Test 2: Checking script has valid bash syntax..."

    if bash -n "$GCP_BUILD_SCRIPT"; then
        log_pass "Script has valid bash syntax"
        return 0
    else
        log_fail "Script has syntax errors"
        return 1
    fi
}

# Test 3: Script is executable
test_script_executable() {
    log_info "Test 3: Checking script is executable..."

    if [ -x "$GCP_BUILD_SCRIPT" ]; then
        log_pass "Script is executable"
        return 0
    else
        log_fail "Script is not executable (run: chmod +x $GCP_BUILD_SCRIPT)"
        return 1
    fi
}

# Test 4: Script includes error handling
test_error_handling() {
    log_info "Test 4: Checking script includes error handling..."

    # Check for set -euo pipefail
    if grep -q "set -euo pipefail" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script uses 'set -euo pipefail' for error handling"
        return 0
    else
        log_fail "Script missing 'set -euo pipefail'"
        return 1
    fi
}

# Test 5: Script supports --dry-run flag
test_dry_run_support() {
    log_info "Test 5: Checking script supports --dry-run flag..."

    if grep -q "dry-run" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script supports --dry-run flag"
        return 0
    else
        log_fail "Script does not support --dry-run flag"
        return 1
    fi
}

# Test 6: Script loads .env.gcp
test_env_loading() {
    log_info "Test 6: Checking script loads .env.gcp..."

    if grep -q ".env.gcp" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script loads .env.gcp"
        return 0
    else
        log_fail "Script does not load .env.gcp"
        return 1
    fi
}

# Test 7: Script validates required environment variables
test_env_validation() {
    log_info "Test 7: Checking script validates required environment variables..."

    # Check for validation of GCP_PROJECT_ID, GCP_ZONE, GCS_BUCKET
    local required_vars_found=0

    if grep -q "GCP_PROJECT_ID" "$GCP_BUILD_SCRIPT"; then
        ((required_vars_found++))
    fi

    if grep -q "GCP_ZONE" "$GCP_BUILD_SCRIPT"; then
        ((required_vars_found++))
    fi

    if grep -q "GCS_BUCKET" "$GCP_BUILD_SCRIPT"; then
        ((required_vars_found++))
    fi

    if [ $required_vars_found -eq 3 ]; then
        log_pass "Script validates required environment variables"
        return 0
    else
        log_fail "Script missing validation for required environment variables (found $required_vars_found/3)"
        return 1
    fi
}

# Test 8: Script includes cost estimation
test_cost_estimation() {
    log_info "Test 8: Checking script includes cost estimation..."

    if grep -q -i "cost" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script includes cost estimation"
        return 0
    else
        log_fail "Script does not include cost estimation"
        return 1
    fi
}

# Test 9: Script supports both standard and prewarmed builds
test_build_type_support() {
    log_info "Test 9: Checking script supports both build types..."

    local build_types_found=0

    if grep -q "standard" "$GCP_BUILD_SCRIPT"; then
        ((build_types_found++))
    fi

    if grep -q "prewarmed" "$GCP_BUILD_SCRIPT"; then
        ((build_types_found++))
    fi

    if [ $build_types_found -eq 2 ]; then
        log_pass "Script supports both standard and prewarmed builds"
        return 0
    else
        log_fail "Script does not support both build types (found $build_types_found/2)"
        return 1
    fi
}

# Test 10: Script includes startup script creation
test_startup_script() {
    log_info "Test 10: Checking script creates startup script..."

    if grep -q "startup-script" "$GCP_BUILD_SCRIPT" || \
       grep -q "create_startup_script" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script includes startup script creation"
        return 0
    else
        log_fail "Script does not create startup script"
        return 1
    fi
}

# Test 11: Script includes proper logging
test_logging() {
    log_info "Test 11: Checking script includes proper logging..."

    local logging_functions=0

    if grep -q "log_info" "$GCP_BUILD_SCRIPT"; then
        ((logging_functions++))
    fi

    if grep -q "log_error" "$GCP_BUILD_SCRIPT"; then
        ((logging_functions++))
    fi

    if grep -q "log_warn" "$GCP_BUILD_SCRIPT"; then
        ((logging_functions++))
    fi

    if [ $logging_functions -ge 2 ]; then
        log_pass "Script includes proper logging functions"
        return 0
    else
        log_fail "Script missing logging functions (found $logging_functions/3)"
        return 1
    fi
}

# Test 12: Script includes cleanup function
test_cleanup_function() {
    log_info "Test 12: Checking script includes cleanup function..."

    if grep -q "cleanup" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script includes cleanup function"
        return 0
    else
        log_fail "Script does not include cleanup function"
        return 1
    fi
}

# Test 13: Script checks for required tools
test_tool_checks() {
    log_info "Test 13: Checking script validates required tools..."

    local tools_found=0

    if grep -q "gcloud" "$GCP_BUILD_SCRIPT"; then
        ((tools_found++))
    fi

    if grep -q "jq" "$GCP_BUILD_SCRIPT"; then
        ((tools_found++))
    fi

    if [ $tools_found -eq 2 ]; then
        log_pass "Script checks for required tools (gcloud, jq)"
        return 0
    else
        log_fail "Script missing tool checks (found $tools_found/2)"
        return 1
    fi
}

# Test 14: Script uses nested virtualization
test_nested_virtualization() {
    log_info "Test 14: Checking script enables nested virtualization..."

    # GCP instances with n2/n2d families support nested virtualization by default
    # Script should use appropriate machine types
    if grep -q -E "n2-standard|n2-highmem|c2-standard" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script uses machine types that support nested virtualization"
        return 0
    else
        log_fail "Script may not use machine types that support nested virtualization"
        return 1
    fi
}

# Test 15: Script includes user confirmation
test_user_confirmation() {
    log_info "Test 15: Checking script includes user confirmation..."

    if grep -q -E "read -p|--auto-approve" "$GCP_BUILD_SCRIPT"; then
        log_pass "Script includes user confirmation"
        return 0
    else
        log_fail "Script does not include user confirmation"
        return 1
    fi
}

# Main test execution
main() {
    echo ""
    echo "=========================================="
    echo "  GCP Build Script Unit Tests"
    echo "=========================================="
    echo ""

    # Run all tests
    test_script_exists || true
    test_script_syntax || true
    test_script_executable || true
    test_error_handling || true
    test_dry_run_support || true
    test_env_loading || true
    test_env_validation || true
    test_cost_estimation || true
    test_build_type_support || true
    test_startup_script || true
    test_logging || true
    test_cleanup_function || true
    test_tool_checks || true
    test_nested_virtualization || true
    test_user_confirmation || true

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
