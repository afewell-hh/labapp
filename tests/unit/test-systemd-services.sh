#!/bin/bash
# test-systemd-services.sh
# Unit tests for systemd service configuration
# Validates that hhfab-vlab.service is properly configured
#
# Usage: ./test-systemd-services.sh
# Requires: bash 4+, grep

set -euo pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VLAB_SERVICE_FILE="${SCRIPT_DIR}/../../packer/scripts/hhfab-vlab.service"
VLAB_RUNNER_SCRIPT="${SCRIPT_DIR}/../../packer/scripts/hhfab-vlab-runner"
ORCHESTRATOR_INSTALL="${SCRIPT_DIR}/../../packer/scripts/05-install-orchestrator.sh"
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

# Test 1: hhfab-vlab.service exists
test_service_file_exists() {
    log_info "Test 1: Checking hhfab-vlab.service file exists..."

    if [ -f "$VLAB_SERVICE_FILE" ]; then
        log_pass "Service file found at $VLAB_SERVICE_FILE"
        return 0
    else
        log_fail "Service file not found at $VLAB_SERVICE_FILE"
        return 1
    fi
}

# Test 2: Service has correct dependencies
test_service_dependencies() {
    log_info "Test 2: Checking service has correct dependencies..."

    local deps_ok=true

    # Check for network-online.target
    if ! grep -q "After=.*network-online.target" "$VLAB_SERVICE_FILE"; then
        log_fail "Service does not depend on network-online.target"
        deps_ok=false
    fi

    # Check for docker.service
    if ! grep -q "docker.service" "$VLAB_SERVICE_FILE"; then
        log_fail "Service does not reference docker.service"
        deps_ok=false
    fi

    if [ "$deps_ok" = true ]; then
        log_pass "Service has correct dependencies (network, docker)"
        return 0
    else
        return 1
    fi
}

# Test 3: Service runs as hhlab user
test_service_user() {
    log_info "Test 3: Checking service runs as hhlab user..."

    if grep -q "User=hhlab" "$VLAB_SERVICE_FILE"; then
        log_pass "Service configured to run as hhlab user"
        return 0
    else
        log_fail "Service not configured to run as hhlab user"
        return 1
    fi
}

# Test 4: Service has condition to prevent re-runs
test_service_condition() {
    log_info "Test 4: Checking service has condition to prevent re-initialization..."

    if grep -q "ConditionPathExists=!" "$VLAB_SERVICE_FILE" && \
       grep -q "vlab-initialized" "$VLAB_SERVICE_FILE"; then
        log_pass "Service has ConditionPathExists to prevent re-runs"
        return 0
    else
        log_fail "Service missing ConditionPathExists condition"
        return 1
    fi
}

# Test 5: Service points to hhfab-vlab-runner
test_service_execstart() {
    log_info "Test 5: Checking service ExecStart points to hhfab-vlab-runner..."

    if grep -q "ExecStart=/usr/local/bin/hhfab-vlab-runner" "$VLAB_SERVICE_FILE"; then
        log_pass "Service ExecStart correctly points to hhfab-vlab-runner"
        return 0
    else
        log_fail "Service ExecStart does not point to hhfab-vlab-runner"
        return 1
    fi
}

# Test 6: hhfab-vlab-runner script exists
test_runner_script_exists() {
    log_info "Test 6: Checking hhfab-vlab-runner script exists..."

    if [ -f "$VLAB_RUNNER_SCRIPT" ]; then
        log_pass "Runner script found at $VLAB_RUNNER_SCRIPT"
        return 0
    else
        log_fail "Runner script not found at $VLAB_RUNNER_SCRIPT"
        return 1
    fi
}

# Test 7: Runner script uses correct hhfab flags
test_runner_hhfab_flags() {
    log_info "Test 7: Checking runner uses correct hhfab flags..."

    local flags_ok=true

    # Check for --controls-restricted=false
    if ! grep -q "\-\-controls-restricted=false" "$VLAB_RUNNER_SCRIPT"; then
        log_fail "Runner does not use --controls-restricted=false flag"
        flags_ok=false
    fi

    # Check for --ready wait
    if ! grep -q "\-\-ready wait" "$VLAB_RUNNER_SCRIPT"; then
        log_fail "Runner does not use --ready wait flag"
        flags_ok=false
    fi

    if [ "$flags_ok" = true ]; then
        log_pass "Runner uses correct hhfab flags (--controls-restricted=false --ready wait)"
        return 0
    else
        return 1
    fi
}

# Test 8: Runner creates tmux session
test_runner_tmux_usage() {
    log_info "Test 8: Checking runner creates tmux session..."

    if grep -q "tmux.*new-session" "$VLAB_RUNNER_SCRIPT" && \
       grep -q "hhfab-vlab" "$VLAB_RUNNER_SCRIPT"; then
        log_pass "Runner creates tmux session named 'hhfab-vlab'"
        return 0
    else
        log_fail "Runner does not create proper tmux session"
        return 1
    fi
}

# Test 9: Runner creates state marker on success
test_runner_state_marker() {
    log_info "Test 9: Checking runner creates state marker on success..."

    if grep -q "vlab-initialized" "$VLAB_RUNNER_SCRIPT" && \
       grep -q "STATE_FILE" "$VLAB_RUNNER_SCRIPT"; then
        log_pass "Runner creates vlab-initialized state marker"
        return 0
    else
        log_fail "Runner does not create state marker"
        return 1
    fi
}

# Test 10: Runner logs to correct location
test_runner_logging() {
    log_info "Test 10: Checking runner logs to correct location..."

    if grep -q "/var/log/hedgehog-lab/modules/vlab.log" "$VLAB_RUNNER_SCRIPT"; then
        log_pass "Runner logs to /var/log/hedgehog-lab/modules/vlab.log"
        return 0
    else
        log_fail "Runner does not log to expected location"
        return 1
    fi
}

# Test 11: Installation script installs service/runner but does NOT enable service
test_install_script() {
    log_info "Test 11: Checking installation script installs service and runner..."

    local install_ok=true

    # Check for hhfab-vlab.service installation
    if ! grep -q "hhfab-vlab.service" "$ORCHESTRATOR_INSTALL"; then
        log_fail "Installation script does not install hhfab-vlab.service"
        install_ok=false
    fi

    # Check for hhfab-vlab-runner installation
    if ! grep -q "hhfab-vlab-runner" "$ORCHESTRATOR_INSTALL"; then
        log_fail "Installation script does not install hhfab-vlab-runner"
        install_ok=false
    fi

    # Verify service is NOT auto-enabled (orchestrator controls it)
    if grep -q "systemctl enable hhfab-vlab.service" "$ORCHESTRATOR_INSTALL"; then
        log_fail "Installation script enables hhfab-vlab.service (should be orchestrator-controlled)"
        install_ok=false
    fi

    if [ "$install_ok" = true ]; then
        log_pass "Installation script installs service/runner without auto-enabling"
        return 0
    else
        return 1
    fi
}

# Test 12: Runner has error handling
test_runner_error_handling() {
    log_info "Test 12: Checking runner has proper error handling..."

    if grep -q "set -euo pipefail" "$VLAB_RUNNER_SCRIPT" && \
       grep -q "log_error" "$VLAB_RUNNER_SCRIPT"; then
        log_pass "Runner has error handling (set -euo pipefail and logging)"
        return 0
    else
        log_fail "Runner missing proper error handling"
        return 1
    fi
}

# Test 13: Service does not use PrivateTmp (allows tmux socket access)
test_service_no_private_tmp() {
    log_info "Test 13: Checking service does NOT use PrivateTmp..."

    # PrivateTmp should NOT be set to true (prevents tmux socket access)
    if grep -q "^PrivateTmp=true" "$VLAB_SERVICE_FILE"; then
        log_fail "Service uses PrivateTmp=true (blocks tmux socket access)"
        return 1
    else
        log_pass "Service does not use PrivateTmp (tmux sockets accessible)"
        return 0
    fi
}

# Test 14: Runner uses proper exit code capture mechanism
test_runner_exit_code_capture() {
    log_info "Test 14: Checking runner captures exit code correctly..."

    # The runner must use a mechanism that prevents $? expansion in the parent shell
    # Valid approaches: printf with literal $?, sh -c with escaped \$?, or heredoc
    local capture_ok=false

    # Check for printf approach (preferred)
    if grep -q "printf.*echo.*\\\$?" "$VLAB_RUNNER_SCRIPT" || \
       grep -q "printf.*echo.*\$?" "$VLAB_RUNNER_SCRIPT"; then
        capture_ok=true
    fi

    # Check for sh -c with proper escaping
    if grep -q "sh -c.*echo.*\\\$?.*exit-code" "$VLAB_RUNNER_SCRIPT"; then
        capture_ok=true
    fi

    # Make sure it's NOT using simple variable assignment which expands $? immediately
    if grep -q 'local tmux_cmd=".*echo \$?.*exit-code"' "$VLAB_RUNNER_SCRIPT"; then
        log_fail "Runner uses direct assignment which expands \$? in parent shell"
        return 1
    fi

    if [ "$capture_ok" = true ]; then
        log_pass "Runner uses proper exit code capture mechanism"
        return 0
    else
        log_fail "Runner exit code capture mechanism unclear or missing"
        return 1
    fi
}

# Main test execution
main() {
    echo ""
    echo "=========================================="
    echo "  Systemd Service Unit Tests"
    echo "=========================================="
    echo ""

    # Run all tests
    test_service_file_exists || true
    test_service_dependencies || true
    test_service_user || true
    test_service_condition || true
    test_service_execstart || true
    test_runner_script_exists || true
    test_runner_hhfab_flags || true
    test_runner_tmux_usage || true
    test_runner_state_marker || true
    test_runner_logging || true
    test_install_script || true
    test_runner_error_handling || true
    test_service_no_private_tmp || true
    test_runner_exit_code_capture || true

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
