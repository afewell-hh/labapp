#!/bin/bash
# boot-and-test.sh
# Boots the built OVA appliance and runs automated validation tests
#
# Usage: ./boot-and-test.sh <ova-file>
# Example: ./boot-and-test.sh ../../output-hedgehog-lab-standard/hedgehog-lab-standard-0.1.0.ova

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/boot-test-${TIMESTAMP}.json"
VM_WORK_DIR="/tmp/hedgehog-lab-test-${TIMESTAMP}"

# VM Configuration
VM_NAME="hedgehog-lab-test-${TIMESTAMP}"
VM_MEMORY="8192"  # 8GB (reduced from 16GB for CI)
VM_CPUS="4"       # 4 CPUs (reduced from 8 for CI)
VM_DISK_SIZE="300G"

# SSH Configuration
VM_SSH_PORT="2222"
VM_USER="hhlab"
VM_PASS="hhlab"
VM_IP="127.0.0.1"

# Timeouts (in seconds)
BOOT_TIMEOUT=300          # 5 minutes for VM to boot
SSH_TIMEOUT=600           # 10 minutes for SSH to become available
INIT_TIMEOUT=2400         # 40 minutes for initialization (VLAB can take 30+ minutes)
SERVICE_CHECK_TIMEOUT=300 # 5 minutes for service checks

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()
WARNINGS=()

# Cleanup flag
CLEANUP_ON_EXIT=true
QEMU_PID=""

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

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $*"
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
    WARNINGS+=("${test_name}: ${reason}")
    log_warn "⚠ ${test_name}: ${reason}"
}

# Cleanup function
cleanup() {
    local exit_code=$?

    if [ "$CLEANUP_ON_EXIT" = true ]; then
        log_info "Cleaning up test environment..."

        # Stop QEMU if running
        if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
            log_debug "Stopping QEMU (PID: $QEMU_PID)"
            kill "$QEMU_PID" 2>/dev/null || true
            sleep 2
            kill -9 "$QEMU_PID" 2>/dev/null || true
        fi

        # Remove working directory
        if [ -d "$VM_WORK_DIR" ]; then
            log_debug "Removing working directory: $VM_WORK_DIR"
            rm -rf "$VM_WORK_DIR"
        fi
    else
        log_warn "Cleanup disabled. VM left running for debugging."
        log_warn "Working directory: $VM_WORK_DIR"
        if [ -n "$QEMU_PID" ]; then
            log_warn "QEMU PID: $QEMU_PID"
            log_warn "To stop VM: kill $QEMU_PID"
        fi
    fi

    exit "$exit_code"
}

trap cleanup EXIT INT TERM

# Usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <ova-file>

Boots the built OVA appliance and runs automated validation tests.

Arguments:
  ova-file            Path to OVA file to test

Options:
  --no-cleanup        Don't cleanup VM after tests (for debugging)
  --memory MB         VM memory in MB (default: $VM_MEMORY)
  --cpus N            VM CPUs (default: $VM_CPUS)
  --init-timeout SEC  Initialization timeout in seconds (default: $INIT_TIMEOUT)
  --help              Show this help message

Examples:
  $0 ../../output-hedgehog-lab-standard/hedgehog-lab-standard-0.1.0.ova
  $0 --no-cleanup --memory 4096 --cpus 2 /path/to/appliance.ova

EOF
    exit 1
}

# Extract OVA and prepare VM disk
extract_ova() {
    local ova_file="$1"

    log_info "Extracting OVA file..."
    mkdir -p "$VM_WORK_DIR"

    # Extract OVA (which is a tar file)
    tar -xf "$ova_file" -C "$VM_WORK_DIR"

    # Find VMDK file
    local vmdk_file
    vmdk_file=$(find "$VM_WORK_DIR" -name "*.vmdk" | head -n 1)

    if [ -z "$vmdk_file" ]; then
        log_error "No VMDK file found in OVA"
        return 1
    fi

    # Convert VMDK to qcow2 for QEMU
    log_info "Converting VMDK to qcow2 format..."
    qemu-img convert -f vmdk -O qcow2 "$vmdk_file" "$VM_WORK_DIR/disk.qcow2"

    if [ ! -f "$VM_WORK_DIR/disk.qcow2" ]; then
        log_error "Failed to convert VMDK to qcow2"
        return 1
    fi

    test_pass "OVA extraction and conversion"
    return 0
}

# Boot VM using QEMU
boot_vm() {
    log_info "Booting VM with QEMU..."
    log_debug "Memory: ${VM_MEMORY}MB, CPUs: ${VM_CPUS}"

    # Determine KVM availability
    local kvm_opts=""
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        kvm_opts="-enable-kvm"
        log_debug "KVM acceleration enabled"
    else
        log_warn "KVM not available, using TCG emulation (slower)"
    fi

    # Start QEMU in background
    # shellcheck disable=SC2086
    qemu-system-x86_64 \
        $kvm_opts \
        -name "$VM_NAME" \
        -m "$VM_MEMORY" \
        -smp "$VM_CPUS" \
        -drive file="$VM_WORK_DIR/disk.qcow2",if=virtio,cache=writeback \
        -net nic,model=virtio \
        -net user,hostfwd=tcp::${VM_SSH_PORT}-:22 \
        -nographic \
        -serial mon:stdio \
        > "$VM_WORK_DIR/qemu.log" 2>&1 &

    QEMU_PID=$!
    log_debug "QEMU started with PID: $QEMU_PID"

    # Wait for QEMU to start
    sleep 5

    # Check if QEMU is still running
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        log_error "QEMU failed to start"
        if [ -f "$VM_WORK_DIR/qemu.log" ]; then
            log_error "QEMU log:"
            tail -n 50 "$VM_WORK_DIR/qemu.log"
        fi
        return 1
    fi

    test_pass "VM boot started"
    return 0
}

# Wait for SSH to become available
wait_for_ssh() {
    log_info "Waiting for SSH to become available (timeout: ${SSH_TIMEOUT}s)..."

    local elapsed=0
    local interval=5

    while [ $elapsed -lt $SSH_TIMEOUT ]; do
        if sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -p "$VM_SSH_PORT" "${VM_USER}@${VM_IP}" "echo 'SSH ready'" &>/dev/null; then
            log_info "SSH connection established after ${elapsed}s"
            test_pass "SSH connectivity"
            return 0
        fi

        # Check if QEMU is still running
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            log_error "QEMU process died while waiting for SSH"
            test_fail "SSH connectivity" "QEMU process died"
            return 1
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
        log_debug "Waiting for SSH... (${elapsed}s/${SSH_TIMEOUT}s)"
    done

    log_error "SSH timeout after ${SSH_TIMEOUT}s"
    test_fail "SSH connectivity" "Timeout after ${SSH_TIMEOUT}s"
    return 1
}

# Execute command in VM via SSH
vm_exec() {
    local command="$1"
    sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$VM_SSH_PORT" "${VM_USER}@${VM_IP}" "$command"
}

# Wait for initialization to complete
wait_for_initialization() {
    log_info "Waiting for appliance initialization (timeout: ${INIT_TIMEOUT}s)..."
    log_warn "This may take 30-40 minutes for VLAB initialization..."

    local elapsed=0
    local interval=30  # Check every 30 seconds
    local last_status=""

    while [ $elapsed -lt $INIT_TIMEOUT ]; do
        # Check if initialization stamp file exists
        if vm_exec "test -f /var/lib/hedgehog-lab/initialized" 2>/dev/null; then
            log_info "Initialization completed after ${elapsed}s (~$((elapsed/60)) minutes)"
            test_pass "Appliance initialization"
            return 0
        fi

        # Get current initialization status
        local current_status
        current_status=$(vm_exec "sudo systemctl is-active hedgehog-lab-init.service 2>/dev/null || echo 'unknown'") || current_status="unknown"

        # Show status if changed
        if [ "$current_status" != "$last_status" ]; then
            log_debug "Initialization status: $current_status"
            last_status="$current_status"
        fi

        # If service failed, report it
        if [ "$current_status" = "failed" ]; then
            log_error "Initialization service failed"
            log_error "Fetching logs..."
            vm_exec "sudo journalctl -u hedgehog-lab-init.service -n 100 --no-pager" || true
            test_fail "Appliance initialization" "Service failed"
            return 1
        fi

        # Check if QEMU is still running
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            log_error "QEMU process died during initialization"
            test_fail "Appliance initialization" "QEMU process died"
            return 1
        fi

        sleep $interval
        elapsed=$((elapsed + interval))

        # Show progress every 5 minutes
        if [ $((elapsed % 300)) -eq 0 ]; then
            log_info "Still initializing... (${elapsed}s / ~$((elapsed/60)) minutes elapsed)"
        fi
    done

    log_error "Initialization timeout after ${INIT_TIMEOUT}s (~$((INIT_TIMEOUT/60)) minutes)"
    log_error "Fetching initialization logs..."
    vm_exec "sudo journalctl -u hedgehog-lab-init.service -n 200 --no-pager" || true
    test_fail "Appliance initialization" "Timeout after ${INIT_TIMEOUT}s"
    return 1
}

# Verify services are running
verify_services() {
    log_info "Verifying services are running..."

    # Check k3d cluster
    log_debug "Checking k3d cluster..."
    if vm_exec "k3d cluster list | grep -q k3d-observability" 2>/dev/null; then
        if vm_exec "kubectl get nodes --context k3d-k3d-observability | grep -q Ready" 2>/dev/null; then
            test_pass "k3d cluster operational"
        else
            test_fail "k3d cluster operational" "Nodes not ready"
            return 1
        fi
    else
        test_fail "k3d cluster operational" "Cluster not found"
        return 1
    fi

    # Check Docker daemon
    log_debug "Checking Docker daemon..."
    if vm_exec "docker ps >/dev/null 2>&1"; then
        test_pass "Docker daemon running"
    else
        test_fail "Docker daemon running" "Docker not accessible"
        return 1
    fi

    # Check VLAB containers
    log_debug "Checking VLAB containers..."
    local vlab_count
    vlab_count=$(vm_exec "docker ps --filter 'name=vlab-' --format '{{.Names}}' | wc -l" 2>/dev/null || echo "0")

    if [ "$vlab_count" -eq 7 ]; then
        test_pass "VLAB containers running (7/7)"
    elif [ "$vlab_count" -gt 0 ]; then
        test_warn "VLAB containers" "Only $vlab_count/7 containers running"
    else
        test_fail "VLAB containers running" "No VLAB containers found"
        return 1
    fi

    return 0
}

# Check service endpoints
check_endpoints() {
    log_info "Checking service endpoints..."

    # Note: These services may not be exposed to host via SSH tunnel
    # We'll check if they're listening inside the VM

    # Check Grafana (port 3000)
    log_debug "Checking Grafana endpoint..."
    if vm_exec "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 2>/dev/null | grep -q 200" 2>/dev/null; then
        test_pass "Grafana endpoint accessible"
    else
        test_warn "Grafana endpoint" "May not be fully initialized yet"
    fi

    # Check Prometheus (port 9090)
    log_debug "Checking Prometheus endpoint..."
    if vm_exec "curl -s -o /dev/null -w '%{http_code}' http://localhost:9090 2>/dev/null | grep -q 200" 2>/dev/null; then
        test_pass "Prometheus endpoint accessible"
    else
        test_warn "Prometheus endpoint" "May not be fully initialized yet"
    fi

    return 0
}

# Validate VLAB initialization
validate_vlab() {
    log_info "Validating VLAB initialization..."

    # Check if hhfab command is available
    log_debug "Checking hhfab command..."
    if ! vm_exec "command -v hhfab >/dev/null 2>&1"; then
        test_fail "VLAB validation" "hhfab command not found"
        return 1
    fi

    # Check if VLAB working directory exists
    log_debug "Checking VLAB working directory..."
    if ! vm_exec "test -d /opt/hedgehog/vlab"; then
        test_fail "VLAB validation" "VLAB working directory not found"
        return 1
    fi

    # Try to run vlab inspect
    log_debug "Running hhfab vlab inspect..."
    if vm_exec "cd /opt/hedgehog/vlab && hhfab vlab inspect >/dev/null 2>&1"; then
        test_pass "VLAB fabric operational"
    else
        test_warn "VLAB fabric" "Inspect command failed - may still be initializing"
    fi

    return 0
}

# Generate test report
generate_report() {
    log_info "Generating test report..."

    mkdir -p "$RESULTS_DIR"

    local status="PASS"
    if [ $TESTS_FAILED -gt 0 ]; then
        status="FAIL"
    fi

    # Create JSON report
    cat > "$RESULT_FILE" <<EOF
{
  "test_suite": "boot-and-test",
  "timestamp": "$TIMESTAMP",
  "status": "$status",
  "tests_run": $TESTS_RUN,
  "tests_passed": $TESTS_PASSED,
  "tests_failed": $TESTS_FAILED,
  "warnings": $(printf '%s\n' "${WARNINGS[@]}" | jq -R . | jq -s . || echo "[]"),
  "failures": $(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s . || echo "[]"),
  "configuration": {
    "vm_memory_mb": $VM_MEMORY,
    "vm_cpus": $VM_CPUS,
    "boot_timeout_s": $BOOT_TIMEOUT,
    "ssh_timeout_s": $SSH_TIMEOUT,
    "init_timeout_s": $INIT_TIMEOUT
  }
}
EOF

    log_info "Test report saved to: $RESULT_FILE"

    # Print summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Status: $status"
    echo "Tests run: $TESTS_RUN"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "Warnings: ${#WARNINGS[@]}"

    if [ ${#FAILURES[@]} -gt 0 ]; then
        echo ""
        echo "Failures:"
        for failure in "${FAILURES[@]}"; do
            echo "  - $failure"
        done
    fi

    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo ""
        echo "Warnings:"
        for warning in "${WARNINGS[@]}"; do
            echo "  - $warning"
        done
    fi

    echo "======================================"

    if [ "$status" = "FAIL" ]; then
        return 1
    fi
    return 0
}

# Main function
main() {
    local ova_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-cleanup)
                CLEANUP_ON_EXIT=false
                shift
                ;;
            --memory)
                VM_MEMORY="$2"
                shift 2
                ;;
            --cpus)
                VM_CPUS="$2"
                shift 2
                ;;
            --init-timeout)
                INIT_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                usage
                ;;
            -*)
                echo "Unknown option: $1"
                usage
                ;;
            *)
                ova_file="$1"
                shift
                ;;
        esac
    done

    # Validate OVA file argument
    if [ -z "$ova_file" ]; then
        echo "Error: OVA file not specified"
        usage
    fi

    if [ ! -f "$ova_file" ]; then
        echo "Error: OVA file not found: $ova_file"
        exit 1
    fi

    echo "======================================"
    echo "Hedgehog Lab Appliance Boot Test"
    echo "======================================"
    echo "OVA file: $ova_file"
    echo "Timestamp: $TIMESTAMP"
    echo "Working directory: $VM_WORK_DIR"
    echo ""

    # Check dependencies
    log_info "Checking dependencies..."
    local missing_deps=()

    for cmd in qemu-system-x86_64 qemu-img sshpass jq tar; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Install with: sudo apt-get install -y qemu-system-x86 qemu-utils sshpass jq"
        exit 1
    fi

    # Run tests - capture status but don't exit immediately
    local test_status=0

    extract_ova "$ova_file" || test_status=1

    if [ $test_status -eq 0 ]; then
        boot_vm || test_status=1
    fi

    if [ $test_status -eq 0 ]; then
        wait_for_ssh || test_status=1
    fi

    if [ $test_status -eq 0 ]; then
        wait_for_initialization || test_status=1
    fi

    if [ $test_status -eq 0 ]; then
        verify_services || test_status=1
    fi

    if [ $test_status -eq 0 ]; then
        check_endpoints || true  # Don't fail on endpoint checks
        validate_vlab || true     # Don't fail on VLAB validation
    fi

    # Always generate report, even on failure
    generate_report || test_status=1

    return $test_status
}

# Run main function
main "$@"
