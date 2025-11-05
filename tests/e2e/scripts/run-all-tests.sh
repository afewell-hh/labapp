#!/bin/bash
# run-all-tests.sh
# Runs all E2E validation tests
#
# Usage: ./run-all-tests.sh
# Run inside the appliance VM after initialization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUMMARY_FILE="${RESULTS_DIR}/test-summary-${TIMESTAMP}.txt"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test suites
declare -a TEST_SUITES=(
    "validate-services.sh:Service Validation"
    "validate-vlab.sh:VLAB Validation"
    "validate-gitops.sh:GitOps Validation"
    "validate-observability.sh:Observability Validation"
)

# Results tracking
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
SKIPPED_SUITES=0

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

log_header() {
    echo -e "${BLUE}[====]${NC} $*"
}

# Main execution
main() {
    echo ""
    echo "=========================================="
    echo "  Hedgehog Lab E2E Test Suite"
    echo "=========================================="
    echo "Timestamp: ${TIMESTAMP}"
    echo ""

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Initialize summary file
    cat > "${SUMMARY_FILE}" <<EOF
Hedgehog Lab E2E Test Suite - Summary
======================================
Timestamp: ${TIMESTAMP}
Hostname: $(hostname)

EOF

    # Run each test suite
    for suite_entry in "${TEST_SUITES[@]}"; do
        IFS=':' read -r script_name suite_name <<< "$suite_entry"
        ((TOTAL_SUITES++))

        log_header "Running: ${suite_name}"
        echo ""

        local script_path="${SCRIPT_DIR}/${script_name}"

        if [ ! -f "${script_path}" ]; then
            log_error "Test script not found: ${script_path}"
            ((FAILED_SUITES++))
            echo "${suite_name}: FAIL (script not found)" >> "${SUMMARY_FILE}"
            continue
        fi

        # Make script executable
        chmod +x "${script_path}"

        # Run test suite
        if "${script_path}"; then
            log_info "${suite_name}: PASSED ✓"
            ((PASSED_SUITES++))
            echo "${suite_name}: PASS" >> "${SUMMARY_FILE}"
        else
            local exit_code=$?
            if [ ${exit_code} -eq 0 ]; then
                log_warn "${suite_name}: SKIPPED"
                ((SKIPPED_SUITES++))
                echo "${suite_name}: SKIP" >> "${SUMMARY_FILE}"
            else
                log_error "${suite_name}: FAILED ✗"
                ((FAILED_SUITES++))
                echo "${suite_name}: FAIL" >> "${SUMMARY_FILE}"
            fi
        fi

        echo ""
    done

    # Overall summary
    echo "=========================================="
    echo "  Test Execution Summary"
    echo "=========================================="
    echo "Total test suites: ${TOTAL_SUITES}"
    echo "Passed: ${PASSED_SUITES}"
    echo "Failed: ${FAILED_SUITES}"
    echo "Skipped: ${SKIPPED_SUITES}"
    echo ""

    # Calculate pass rate
    local pass_rate=0
    if [ ${TOTAL_SUITES} -gt 0 ]; then
        pass_rate=$((PASSED_SUITES * 100 / TOTAL_SUITES))
    fi
    echo "Pass rate: ${pass_rate}%"
    echo ""

    # Write summary
    cat >> "${SUMMARY_FILE}" <<EOF

Summary
=======
Total test suites: ${TOTAL_SUITES}
Passed: ${PASSED_SUITES}
Failed: ${FAILED_SUITES}
Skipped: ${SKIPPED_SUITES}
Pass rate: ${pass_rate}%

Results Directory: ${RESULTS_DIR}
EOF

    log_info "Summary written to: ${SUMMARY_FILE}"
    echo ""

    # List all result files
    echo "Test result files:"
    find "${RESULTS_DIR}" -name "*-${TIMESTAMP}.json" -type f | while read -r result_file; do
        echo "  - $(basename "${result_file}")"
    done
    echo ""

    # Exit with appropriate code
    if [ ${FAILED_SUITES} -gt 0 ]; then
        log_error "Some test suites failed!"
        exit 1
    elif [ ${PASSED_SUITES} -eq 0 ]; then
        log_warn "No test suites passed (all skipped or failed)"
        exit 1
    else
        log_info "All test suites passed! ✓"
        exit 0
    fi
}

# Entry point
main "$@"
