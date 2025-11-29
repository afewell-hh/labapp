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

# Telemetry Configuration - Alloy pushes metrics to Prometheus
# The k3d docker bridge IP is 172.18.0.1 - this is where k3d exposes services
ALLOY_PROM_REMOTE_WRITE_URL="${ALLOY_PROM_REMOTE_WRITE_URL:-http://172.18.0.1:9090/api/v1/write}"
ALLOY_PROM_SEND_INTERVAL="${ALLOY_PROM_SEND_INTERVAL:-120}"
ALLOY_PROM_LABEL_ENV="${ALLOY_PROM_LABEL_ENV:-vlab}"
ALLOY_PROM_LABEL_CLUSTER="${ALLOY_PROM_LABEL_CLUSTER:-emc}"

# Extra TLS SANs for external access (space or comma separated, supports wildcards)
EXTRA_TLS_SANS="${EXTRA_TLS_SANS:-}"

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

# Apply fab.yaml overrides for TLS SANs and Alloy telemetry configuration
# This MUST be done before 'hhfab vlab up' is called
apply_fab_overrides() {
    log_info "Applying fab.yaml overrides for external access and telemetry..."

    cd "$VLAB_WORK_DIR" || return 1

    if [ ! -f "$VLAB_WORK_DIR/fab.yaml" ]; then
        log_error "fab.yaml not found - cannot apply overrides"
        return 1
    fi

    # Backup original
    cp "$VLAB_WORK_DIR/fab.yaml" "$VLAB_WORK_DIR/fab.yaml.orig.$(date +%Y%m%d%H%M%S)"

    # Collect TLS SANs - these are needed for external access to the Hedgehog controller
    # Include: loopback, docker bridges, host IPs, and any extra SANs
    local tls_sans=()

    # Standard entries
    tls_sans+=("127.0.0.1" "localhost")
    tls_sans+=("172.17.0.1")   # docker0 bridge
    tls_sans+=("172.18.0.1")   # k3d bridge (where k3d exposes services)
    tls_sans+=("0.0.0.0")      # Wildcard bind (lab-only!)
    tls_sans+=("0.0.0.0/0")    # CIDR wildcard (lab-only!)

    # Add host's primary IP
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$host_ip" ]; then
        tls_sans+=("$host_ip")
        log_info "Adding host IP to TLS SANs: $host_ip"
    fi

    # Add hostname and FQDN
    local hostname_short hostname_fqdn
    hostname_short=$(hostname -s 2>/dev/null)
    hostname_fqdn=$(hostname -f 2>/dev/null || echo "")
    [ -n "$hostname_short" ] && tls_sans+=("$hostname_short")
    [ -n "$hostname_fqdn" ] && [ "$hostname_fqdn" != "$hostname_short" ] && tls_sans+=("$hostname_fqdn")

    # Add common service DNS names
    tls_sans+=("argocd-server.argocd")
    tls_sans+=("gitea-http.gitea")
    tls_sans+=("kube-prometheus-stack-prometheus.monitoring")

    # Add any extra SANs from environment
    if [ -n "$EXTRA_TLS_SANS" ]; then
        # Support both space and comma separation
        local extra
        for extra in $(echo "$EXTRA_TLS_SANS" | tr ',' ' '); do
            [ -n "$extra" ] && tls_sans+=("$extra")
        done
    fi

    log_info "TLS SANs to be added: ${tls_sans[*]}"

    # Build the YAML for tlsSAN entries
    local tls_san_yaml=""
    for san in "${tls_sans[@]}"; do
        tls_san_yaml+="        - \"$san\"\n"
    done

    # Build the defaultAlloyConfig YAML for telemetry
    # This configures Alloy agents on switches to push metrics to Prometheus via remote write
    local alloy_config_yaml
    alloy_config_yaml=$(cat <<EOF
    defaultAlloyConfig:
      controlProxy:
        enabled: true
      collectors:
        integrations/self:
          enabled: true
        integrations/unix:
          enabled: true
        integrations/syslog:
          enabled: true
      destinations:
        prom:
          type: prometheus
          remoteWrite:
            url: "${ALLOY_PROM_REMOTE_WRITE_URL}"
          sendInterval: ${ALLOY_PROM_SEND_INTERVAL}
          extraLabels:
            env: "${ALLOY_PROM_LABEL_ENV}"
            cluster: "${ALLOY_PROM_LABEL_CLUSTER}"
EOF
)

    log_info "Alloy config to be added with remote write to: $ALLOY_PROM_REMOTE_WRITE_URL"

    # Now patch the fab.yaml file using yq if available, otherwise sed
    if command -v yq &> /dev/null; then
        log_info "Using yq to patch fab.yaml..."

        # Add TLS SANs
        for san in "${tls_sans[@]}"; do
            yq -i ".spec.config.control.tlsSAN += [\"$san\"]" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE" || true
        done

        # Add Alloy config
        yq -i ".spec.config.fabric.defaultAlloyConfig.controlProxy.enabled = true" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.collectors.\"integrations/self\".enabled = true" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.collectors.\"integrations/unix\".enabled = true" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.collectors.\"integrations/syslog\".enabled = true" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.destinations.prom.type = \"prometheus\"" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.destinations.prom.remoteWrite.url = \"${ALLOY_PROM_REMOTE_WRITE_URL}\"" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.destinations.prom.sendInterval = ${ALLOY_PROM_SEND_INTERVAL}" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.destinations.prom.extraLabels.env = \"${ALLOY_PROM_LABEL_ENV}\"" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"
        yq -i ".spec.config.fabric.defaultAlloyConfig.destinations.prom.extraLabels.cluster = \"${ALLOY_PROM_LABEL_CLUSTER}\"" "$VLAB_WORK_DIR/fab.yaml" 2>> "$LOG_FILE"

    else
        log_info "yq not found, using Python YAML patching..."

        # Use Python to patch YAML (more reliable than sed for YAML)
        python3 << PYEOF
import yaml
import sys

fab_yaml_path = "$VLAB_WORK_DIR/fab.yaml"

# Load all documents from fab.yaml
with open(fab_yaml_path, 'r') as f:
    docs = list(yaml.safe_load_all(f))

# TLS SANs to add
tls_sans = [$(printf '"%s",' "${tls_sans[@]}" | sed 's/,$//')
]

# Process each document
for doc in docs:
    if doc is None:
        continue

    kind = doc.get('kind', '')

    if kind == 'Fabricator':
        # Ensure nested structure exists
        if 'spec' not in doc:
            doc['spec'] = {}
        if 'config' not in doc['spec']:
            doc['spec']['config'] = {}
        if 'control' not in doc['spec']['config']:
            doc['spec']['config']['control'] = {}
        if 'fabric' not in doc['spec']['config']:
            doc['spec']['config']['fabric'] = {}

        # Add TLS SANs
        existing_sans = doc['spec']['config']['control'].get('tlsSAN', [])
        if existing_sans is None:
            existing_sans = []
        for san in tls_sans:
            if san not in existing_sans:
                existing_sans.append(san)
        doc['spec']['config']['control']['tlsSAN'] = existing_sans

        # Add Alloy config for telemetry
        doc['spec']['config']['fabric']['defaultAlloyConfig'] = {
            'controlProxy': {
                'enabled': True
            },
            'collectors': {
                'integrations/self': {'enabled': True},
                'integrations/unix': {'enabled': True},
                'integrations/syslog': {'enabled': True}
            },
            'destinations': {
                'prom': {
                    'type': 'prometheus',
                    'remoteWrite': {
                        'url': '${ALLOY_PROM_REMOTE_WRITE_URL}'
                    },
                    'sendInterval': ${ALLOY_PROM_SEND_INTERVAL},
                    'extraLabels': {
                        'env': '${ALLOY_PROM_LABEL_ENV}',
                        'cluster': '${ALLOY_PROM_LABEL_CLUSTER}'
                    }
                }
            }
        }

# Write back
with open(fab_yaml_path, 'w') as f:
    yaml.dump_all(docs, f, default_flow_style=False, sort_keys=False)

print("fab.yaml patched successfully")
PYEOF

        if [ $? -ne 0 ]; then
            log_error "Failed to patch fab.yaml with Python"
            return 1
        fi
    fi

    log_info "fab.yaml patched successfully"
    log_debug "Patched fab.yaml contents:"
    cat "$VLAB_WORK_DIR/fab.yaml" >> "$LOG_FILE" 2>&1

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
        log_error "Fabric health check failed"
        return 1
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

    # CRITICAL: Apply fab.yaml overrides for TLS SANs and Alloy config BEFORE vlab up
    # This enables external access and telemetry from day one
    if ! apply_fab_overrides; then
        log_error "Failed to apply fab.yaml overrides"
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
