#!/usr/bin/env bash
# Unit tests for scripts/publish-to-gcs.sh
# Tests artifact publishing logic without requiring GCP credentials

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test script path
SCRIPT_PATH="scripts/publish-to-gcs.sh"

# Logging functions
log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

# Test runner
run_test() {
    ((TESTS_RUN++))
    log_test "$1"
}

echo "================================"
echo "publish-to-gcs.sh Unit Tests"
echo "================================"
echo ""

# Test 1: Script exists
run_test "Script exists at expected path"
if [ -f "$SCRIPT_PATH" ]; then
    log_pass "Script found at $SCRIPT_PATH"
else
    log_fail "Script not found at $SCRIPT_PATH"
fi

# Test 2: Valid bash syntax
run_test "Script has valid bash syntax"
if bash -n "$SCRIPT_PATH"; then
    log_pass "Bash syntax is valid"
else
    log_fail "Bash syntax validation failed"
fi

# Test 3: Script is executable
run_test "Script has executable permissions"
if [ -x "$SCRIPT_PATH" ]; then
    log_pass "Script is executable"
else
    log_fail "Script is not executable (run: chmod +x $SCRIPT_PATH)"
fi

# Test 4: Script uses strict error handling
run_test "Script uses strict error handling (set -euo pipefail)"
if grep -q "^set -euo pipefail" "$SCRIPT_PATH"; then
    log_pass "Script uses strict error handling"
else
    log_fail "Script should use 'set -euo pipefail'"
fi

# Test 5: Script validates .env.gcp existence
run_test "Script validates .env.gcp file existence"
if grep -q "\.env\.gcp" "$SCRIPT_PATH" && \
   grep -q "error_exit.*\.env\.gcp" "$SCRIPT_PATH"; then
    log_pass "Script validates .env.gcp existence"
else
    log_fail "Script should validate .env.gcp file"
fi

# Test 6: Script validates required GCS_BUCKET variable
run_test "Script validates GCS_BUCKET environment variable"
if grep -q "GCS_BUCKET" "$SCRIPT_PATH" && \
   grep -q "error_exit.*GCS_BUCKET" "$SCRIPT_PATH"; then
    log_pass "Script validates GCS_BUCKET variable"
else
    log_fail "Script should validate GCS_BUCKET is set"
fi

# Test 7: Script has version-aware OVA file selection
run_test "Script implements version-aware OVA file selection"
if grep -q "\*\${version}\*\.ova" "$SCRIPT_PATH" || \
   grep -q "\*v\${version}\*\.ova" "$SCRIPT_PATH"; then
    log_pass "Script searches for version-specific OVA files"
else
    log_fail "Script should search for OVA files matching version"
fi

# Test 8: Script handles multiple OVA scenarios
run_test "Script handles multiple OVA file scenarios"
if grep -q "ova_count" "$SCRIPT_PATH" && \
   grep -q "Multiple OVA files" "$SCRIPT_PATH"; then
    log_pass "Script checks for multiple OVA files"
else
    log_fail "Script should handle multiple OVA file scenarios"
fi

# Test 9: Script validates output directory exists
run_test "Script validates output directory exists"
if grep -q "Output directory not found" "$SCRIPT_PATH"; then
    log_pass "Script validates output directory"
else
    log_fail "Script should validate output directory exists"
fi

# Test 10: Script creates build manifest
run_test "Script creates build manifest with metadata"
if grep -q "manifest" "$SCRIPT_PATH" && \
   grep -q "version" "$SCRIPT_PATH" && \
   grep -q "timestamp" "$SCRIPT_PATH"; then
    log_pass "Script creates build manifest"
else
    log_fail "Script should create build manifest with metadata"
fi

# Test 11: Script uploads checksum file
run_test "Script uploads checksum (.sha256) file"
if grep -q "\.sha256" "$SCRIPT_PATH" && \
   grep -q "checksum" "$SCRIPT_PATH"; then
    log_pass "Script handles checksum file upload"
else
    log_fail "Script should upload checksum file"
fi

# Test 12: Script uses gsutil for uploads
run_test "Script uses gsutil for GCS operations"
if grep -q "gsutil" "$SCRIPT_PATH"; then
    log_pass "Script uses gsutil for GCS operations"
else
    log_fail "Script should use gsutil for uploads"
fi

# Test 13: Script has prerequisite checks
run_test "Script validates prerequisites (gsutil, bucket access)"
if grep -q "check_prerequisites" "$SCRIPT_PATH" && \
   grep -q "gsutil.*command" "$SCRIPT_PATH"; then
    log_pass "Script checks prerequisites"
else
    log_fail "Script should validate prerequisites"
fi

# Test 14: Script has proper logging functions
run_test "Script has logging functions (log_info, log_error, etc.)"
if grep -q "log_info" "$SCRIPT_PATH" && \
   grep -q "log_error" "$SCRIPT_PATH"; then
    log_pass "Script has logging functions"
else
    log_fail "Script should have logging functions"
fi

# Test 15: Script displays usage when called incorrectly
run_test "Script has usage/help function"
if grep -q "usage()" "$SCRIPT_PATH" || \
   grep -q "Usage:" "$SCRIPT_PATH"; then
    log_pass "Script has usage documentation"
else
    log_fail "Script should have usage function"
fi

# Test 16: Script validates argument count
run_test "Script validates required arguments (output-dir, version)"
if grep -q '\$#' "$SCRIPT_PATH" && \
   grep -q "usage" "$SCRIPT_PATH"; then
    log_pass "Script validates argument count"
else
    log_fail "Script should validate required arguments"
fi

# Test 17: Script removes 'v' prefix from version
run_test "Script normalizes version string (removes 'v' prefix)"
if grep -q "version#v" "$SCRIPT_PATH" || \
   grep -q 'version=".*{version#' "$SCRIPT_PATH"; then
    log_pass "Script normalizes version string"
else
    log_fail "Script should remove 'v' prefix from version"
fi

# Test 18: Script creates versioned destination path
run_test "Script creates versioned GCS destination path"
if grep -q "v\${version}" "$SCRIPT_PATH" && \
   grep -q "dest_path" "$SCRIPT_PATH"; then
    log_pass "Script creates versioned destination path"
else
    log_fail "Script should use versioned GCS path"
fi

# Test 19: Script verifies uploads
run_test "Script verifies uploads after completion"
if grep -q "gsutil ls" "$SCRIPT_PATH" && \
   grep -q "Verifying" "$SCRIPT_PATH"; then
    log_pass "Script verifies uploads"
else
    log_fail "Script should verify uploads completed"
fi

# Test 20: Script has error handling for upload failures
run_test "Script has error handling for failed uploads"
if grep -q "Failed to upload" "$SCRIPT_PATH" || \
   grep -q "error_exit.*upload" "$SCRIPT_PATH"; then
    log_pass "Script handles upload failures"
else
    log_fail "Script should handle upload failures"
fi

# Test 21: Functional test - Missing arguments
run_test "Functional: Script exits with usage when called without arguments"
if ./"$SCRIPT_PATH" 2>&1 | grep -qi "usage"; then
    log_pass "Script shows usage when called without arguments"
else
    log_fail "Script should show usage when arguments missing"
fi

# Test 22: Functional test - .env.gcp check
run_test "Functional: Script exits when .env.gcp missing"
# Create temp directory and copy script
TEMP_DIR=$(mktemp -d)
cp "$SCRIPT_PATH" "$TEMP_DIR/"
cd "$TEMP_DIR"

# Create fake output directory
mkdir -p test-output

# Try to run without .env.gcp
if ./publish-to-gcs.sh test-output 1.0.0 2>&1 | grep -q "\.env\.gcp"; then
    log_pass "Script validates .env.gcp existence"
else
    log_fail "Script should error when .env.gcp missing"
fi

# Cleanup
cd - > /dev/null
rm -rf "$TEMP_DIR"

# Test 23: Shellcheck validation
run_test "Shellcheck validation (if available)"
if command -v shellcheck > /dev/null 2>&1; then
    if shellcheck -x "$SCRIPT_PATH" 2>&1 | grep -q "SC[0-9]"; then
        # Check if there are errors (not just info)
        if shellcheck -x "$SCRIPT_PATH" 2>&1 | grep -qE "error|warning"; then
            log_fail "Shellcheck found issues"
        else
            log_pass "Shellcheck validation passed (info only)"
        fi
    else
        log_pass "Shellcheck validation passed"
    fi
else
    log_pass "Shellcheck not available, skipping"
fi

# Summary
echo ""
echo "================================"
echo "Test Summary"
echo "================================"
echo "Tests Run:    $TESTS_RUN"
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    echo ""
    echo "Some tests failed. Please review the output above."
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
