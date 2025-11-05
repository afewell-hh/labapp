#!/bin/bash
# validate-build.sh
# Validates Packer build artifacts
#
# Usage: ./validate-build.sh <output-directory>
# Example: ./validate-build.sh ../../output-hedgehog-lab-standard

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/build-validation-${TIMESTAMP}.json"

# Expected file size ranges (in GB)
MIN_OVA_SIZE_GB=10
MAX_OVA_SIZE_GB=30

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Usage
usage() {
    cat <<EOF
Usage: $0 <output-directory>

Validates Packer build artifacts.

Arguments:
  output-directory    Path to Packer output directory (e.g., output-hedgehog-lab-standard)

Examples:
  $0 ../../output-hedgehog-lab-standard
  $0 /path/to/labapp/output-hedgehog-lab-standard

EOF
    exit 1
}

# Main validation logic
main() {
    local output_dir="$1"

    echo "======================================"
    echo "Build Validation Test"
    echo "======================================"
    echo "Output directory: ${output_dir}"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Test 1: Output directory exists
    if [ -d "${output_dir}" ]; then
        test_pass "Output directory exists"
    else
        test_fail "Output directory exists" "Directory not found: ${output_dir}"
        write_results "FAIL"
        exit 1
    fi

    # Test 2: Find OVA file
    local ova_file
    ova_file=$(find "${output_dir}" -maxdepth 1 -name "*.ova" -type f | head -1)
    if [ -n "${ova_file}" ]; then
        test_pass "OVA file exists"
    else
        test_fail "OVA file exists" "No .ova file found in ${output_dir}"
        write_results "FAIL"
        exit 1
    fi

    # Test 3: OVA file size
    local ova_size_bytes
    ova_size_bytes=$(stat -f%z "${ova_file}" 2>/dev/null || stat -c%s "${ova_file}" 2>/dev/null)
    local ova_size_gb=$((ova_size_bytes / 1024 / 1024 / 1024))

    if [ "${ova_size_gb}" -ge "${MIN_OVA_SIZE_GB}" ] && [ "${ova_size_gb}" -le "${MAX_OVA_SIZE_GB}" ]; then
        test_pass "OVA file size valid (${ova_size_gb} GB)"
    else
        test_fail "OVA file size valid" "Size ${ova_size_gb} GB outside range ${MIN_OVA_SIZE_GB}-${MAX_OVA_SIZE_GB} GB"
    fi

    # Test 4: SHA256 checksum file exists
    local checksum_file="${ova_file}.sha256"
    if [ -f "${checksum_file}" ]; then
        test_pass "SHA256 checksum file exists"
    else
        test_fail "SHA256 checksum file exists" "File not found: ${checksum_file}"
    fi

    # Test 5: Verify checksum
    if [ -f "${checksum_file}" ]; then
        cd "${output_dir}"
        if sha256sum -c "$(basename "${checksum_file}")" > /dev/null 2>&1; then
            test_pass "SHA256 checksum verification"
        else
            test_fail "SHA256 checksum verification" "Checksum mismatch"
        fi
        cd - > /dev/null
    fi

    # Test 6: VMDK file exists
    local vmdk_file
    vmdk_file=$(find "${output_dir}" -maxdepth 1 -name "*.vmdk" -type f | head -1)
    if [ -n "${vmdk_file}" ]; then
        test_pass "VMDK file exists"
    else
        test_warn "VMDK file exists" "No .vmdk file found (may be inside OVA)"
    fi

    # Test 7: OVF file exists or OVA is valid tar
    local ovf_file
    ovf_file=$(find "${output_dir}" -maxdepth 1 -name "*.ovf" -type f | head -1)
    if [ -n "${ovf_file}" ]; then
        test_pass "OVF file exists"
    else
        # Check if OVA is a valid tar archive
        if tar -tzf "${ova_file}" > /dev/null 2>&1; then
            test_pass "OVA is valid tar archive"
        else
            test_fail "OVA is valid tar archive" "OVA file is not a valid tar archive"
        fi
    fi

    # Test 8: OVA contains required files
    if tar -tzf "${ova_file}" | grep -q "\.ovf$"; then
        test_pass "OVA contains OVF descriptor"
    else
        test_fail "OVA contains OVF descriptor" "No .ovf file in OVA"
    fi

    if tar -tzf "${ova_file}" | grep -q "\.vmdk$"; then
        test_pass "OVA contains VMDK disk"
    else
        test_fail "OVA contains VMDK disk" "No .vmdk file in OVA"
    fi

    # Summary
    echo ""
    echo "======================================"
    echo "Build Validation Summary"
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
  "test_suite": "build-validation",
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
    "output_directory": "${1:-unknown}",
    "ova_file": "${ova_file:-none}",
    "ova_size_gb": ${ova_size_gb:-0}
  }
}
EOF

    log_info "Results written to: ${RESULT_FILE}"
}

# Entry point
if [ $# -ne 1 ]; then
    usage
fi

main "$1"
