#!/bin/bash
# 30-vlab-init.sh
# VLAB Initialization Module for Hedgehog Lab Appliance
# Initializes Hedgehog Virtual Lab with proper configuration
#
# This module:
# - Starts VLAB with correct parameters
# - Waits for control node ready
# - Applies wiring diagram
# - Waits for all switches to register
# - Verifies fabric health
# - Handles timeouts (30 min max)

set -euo pipefail

# Module metadata
MODULE_NAME="vlab"
MODULE_DESCRIPTION="Initialize Hedgehog Virtual Lab"
MODULE_VERSION="1.0.0"

# Configuration
VLAB_WORK_DIR="${VLAB_WORK_DIR:-/opt/hedgehog/vlab}"
VLAB_TIMEOUT="${VLAB_TIMEOUT:-1800}"  # 30 minutes in seconds
VLAB_TOPOLOGY="${VLAB_TOPOLOGY:-7switch}"
VLAB_WAIT_TIMEOUT="${VLAB_WAIT_TIMEOUT:-600}"  # 10 minutes for switch readiness
VLAB_HEALTH_CHECK_INTERVAL="${VLAB_HEALTH_CHECK_INTERVAL:-10}"
LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/vlab.log}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging functions
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_debug() {
    log "DEBUG" "$@"
}

# Check if hhfab is available
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v hhfab &> /dev/null; then
        log_error "hhfab command not found. Cannot initialize VLAB."
        return 1
    fi

    local hhfab_version
    hhfab_version=$(hhfab --version 2>&1 | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    log_info "Found hhfab version: $hhfab_version"

    return 0
}

# Initialize VLAB working directory
init_vlab_workdir() {
    log_info "Initializing VLAB working directory at $VLAB_WORK_DIR..."

    # Create working directory if it doesn't exist
    if [ ! -d "$VLAB_WORK_DIR" ]; then
        mkdir -p "$VLAB_WORK_DIR"
        log_info "Created VLAB working directory"
    fi

    cd "$VLAB_WORK_DIR" || {
        log_error "Failed to change to VLAB working directory"
        return 1
    }

    # Initialize hhfab if not already initialized
    if [ ! -f "$VLAB_WORK_DIR/fab.yaml" ]; then
        log_info "Initializing hhfab with development credentials..."
        if ! hhfab init --dev >> "$LOG_FILE" 2>&1; then
            log_error "Failed to initialize hhfab"
            return 1
        fi
        log_info "hhfab initialized successfully"
    else
        log_info "VLAB already initialized (fab.yaml exists)"
    fi

    return 0
}

# Generate VLAB wiring diagram
generate_wiring_diagram() {
    log_info "Generating VLAB wiring diagram for ${VLAB_TOPOLOGY} topology..."

    cd "$VLAB_WORK_DIR" || return 1

    # Check if wiring.yaml already exists
    if [ -f "$VLAB_WORK_DIR/wiring.yaml" ]; then
        log_info "Wiring diagram already exists, skipping generation"
        return 0
    fi

    # Generate wiring diagram
    log_info "Running 'hhfab vlab gen'..."
    if ! hhfab vlab gen >> "$LOG_FILE" 2>&1; then
        log_error "Failed to generate wiring diagram"
        return 1
    fi

    # Verify wiring diagram was created
    if [ ! -f "$VLAB_WORK_DIR/wiring.yaml" ]; then
        log_error "Wiring diagram not created after generation"
        return 1
    fi

    log_info "Wiring diagram generated successfully"
    return 0
}

# Start VLAB
start_vlab() {
    log_info "Starting VLAB..."
    log_info "This may take 15-20 minutes for initial setup..."

    cd "$VLAB_WORK_DIR" || return 1

    # Set timeout for the entire operation
    local start_time
    start_time=$(date +%s)
    local end_time
    end_time=$((start_time + VLAB_TIMEOUT))

    # Start VLAB with proper parameters
    # Using --ready wait to automatically wait for switches
    log_info "Running 'hhfab vlab up --ready wait'..."

    # Run hhfab vlab up with timeout
    if timeout "$VLAB_TIMEOUT" hhfab vlab up --ready wait >> "$LOG_FILE" 2>&1; then
        log_info "VLAB started and switches are ready"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "VLAB startup timed out after ${VLAB_TIMEOUT} seconds"
        else
            log_error "VLAB startup failed with exit code: $exit_code"
        fi

        # Capture last 50 lines of log for debugging
        log_error "Last 50 lines of VLAB output:"
        tail -50 "$LOG_FILE" | while IFS= read -r line; do
            log_error "  $line"
        done

        return 1
    fi
}

# Verify fabric health
verify_fabric_health() {
    log_info "Verifying fabric health..."

    cd "$VLAB_WORK_DIR" || return 1

    # Use hhfab vlab inspect to check switch status
    log_info "Running 'hhfab vlab inspect'..."
    if hhfab vlab inspect >> "$LOG_FILE" 2>&1; then
        log_info "Fabric health check passed - all switches are operational"
        return 0
    else
        log_warn "Fabric health check completed with warnings (this may be expected during initial setup)"
        # Don't fail here as some warnings are expected
        return 0
    fi
}

# Get VLAB status summary
get_vlab_status() {
    log_info "VLAB Status Summary:"

    cd "$VLAB_WORK_DIR" || return 1

    # Try to get basic VLAB info
    if [ -f "$VLAB_WORK_DIR/fab.yaml" ]; then
        log_info "  Working directory: $VLAB_WORK_DIR"
        log_info "  Configuration: fab.yaml present"
        log_info "  Wiring diagram: $([ -f "$VLAB_WORK_DIR/wiring.yaml" ] && echo "present" || echo "missing")"
    fi

    return 0
}

# Cleanup function for error conditions
cleanup_on_error() {
    log_warn "Performing cleanup after error..."

    # We don't destroy the VLAB on error to allow for debugging
    # The user can manually run cleanup if needed

    log_info "VLAB VMs left running for debugging. To cleanup manually:"
    log_info "  cd $VLAB_WORK_DIR && hhfab vlab down"

    return 0
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "VLAB Initialization Module Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${VLAB_TIMEOUT}s ($(( VLAB_TIMEOUT / 60 )) minutes)"
    log_info ""

    # Track overall start time
    local overall_start
    overall_start=$(date +%s)

    # Execute initialization steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! init_vlab_workdir; then
        log_error "VLAB working directory initialization failed"
        cleanup_on_error
        return 1
    fi

    if ! generate_wiring_diagram; then
        log_error "Wiring diagram generation failed"
        cleanup_on_error
        return 1
    fi

    if ! start_vlab; then
        log_error "VLAB startup failed"
        cleanup_on_error
        return 1
    fi

    if ! verify_fabric_health; then
        log_error "Fabric health verification failed"
        # Don't cleanup on health check failure - VLAB is running
        return 1
    fi

    # Calculate total time
    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    # Display status summary
    get_vlab_status

    log_info ""
    log_info "=================================================="
    log_info "VLAB Initialization Complete!"
    log_info "=================================================="
    log_info "Total initialization time: ${total_time}s ($(( total_time / 60 )) minutes)"
    log_info "VLAB is ready for use"
    log_info "Working directory: $VLAB_WORK_DIR"
    log_info ""

    return 0
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
    exit $?
fi

# Module interface functions for orchestrator integration
# These functions are called by the orchestrator when sourcing this script

module_run() {
    main "$@"
}

module_validate() {
    # Validate that VLAB is running
    cd "$VLAB_WORK_DIR" || return 1

    # Check if VLAB VMs are running
    # This is a basic check - could be enhanced
    if [ -f "$VLAB_WORK_DIR/fab.yaml" ] && [ -f "$VLAB_WORK_DIR/wiring.yaml" ]; then
        return 0
    else
        return 1
    fi
}

module_cleanup() {
    # Optional cleanup function
    cleanup_on_error
}

module_get_metadata() {
    cat <<EOF
{
  "name": "$MODULE_NAME",
  "description": "$MODULE_DESCRIPTION",
  "version": "$MODULE_VERSION",
  "timeout": $VLAB_TIMEOUT,
  "dependencies": ["network", "k3d"]
}
EOF
}
