#!/bin/bash
# Launch AWS metal instance for pre-warmed build
# This script orchestrates the complete build lifecycle:
# 1. Pre-flight checks (budget, existing builds)
# 2. Cost estimation and user confirmation
# 3. Terraform apply (launch instance)
# 4. Monitor build progress
# 5. Terraform destroy (cleanup)
#
# Usage:
#   ./launch-metal-build.sh [branch] [commit]
#
# Examples:
#   ./launch-metal-build.sh main
#   ./launch-metal-build.sh feature/45-test-prewarmed-build abc123

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${PROJECT_ROOT}/terraform/metal-build"
MAX_BUILD_TIME_HOURS=4  # Includes buffer for cleanup

# Parse arguments
BUILD_BRANCH="${1:-main}"
BUILD_COMMIT="${2:-}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}===${NC} $1 ${BLUE}===${NC}"
    echo ""
}

error_exit() {
    log_error "$1"
    exit "${2:-1}"
}

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    # Check for required tools
    local missing_tools=()

    for tool in terraform aws jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        error_exit "Missing required tools: ${missing_tools[*]}"
    fi

    log_info "✓ All required tools installed"

    # Check if .env file exists and load it BEFORE credential validation
    if [ -f "${PROJECT_ROOT}/.env" ]; then
        log_info "Loading .env file for AWS credentials"
        # shellcheck disable=SC1091
        set -a
        source "${PROJECT_ROOT}/.env"
        set +a
    fi

    # Check AWS credentials (after loading .env)
    if ! aws sts get-caller-identity &> /dev/null; then
        error_exit "AWS credentials not configured or invalid"
    fi

    log_info "✓ AWS credentials valid"
}

# Check for existing builds
check_existing_builds() {
    log_section "Checking for Existing Builds"

    # Query DynamoDB for active builds
    local active_builds=$(aws dynamodb scan \
        --table-name labapp-metal-builds \
        --filter-expression "#status IN (:launching, :building, :uploading)" \
        --expression-attribute-names '{"#status":"Status"}' \
        --expression-attribute-values '{":launching":{"S":"launching"},":building":{"S":"building"},":uploading":{"S":"uploading"}}' \
        --output json 2>/dev/null || echo '{"Count": 0}')

    local count=$(echo "$active_builds" | jq -r '.Count')

    if [ "$count" -gt 0 ]; then
        log_warn "Found ${count} active build(s):"
        echo "$active_builds" | jq -r '.Items[] | "\(.BuildID.S) - \(.Status.S) (launched: \(.LaunchTime.S))"'
        echo ""
        read -p "Continue anyway? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            error_exit "Aborted by user"
        fi
    else
        log_info "✓ No active builds found"
    fi
}

# Estimate costs
estimate_costs() {
    log_section "Cost Estimation"

    # c5n.metal pricing (us-east-1)
    local instance_hourly=4.32
    local ebs_hourly=0.08
    local transfer_gb=100
    local transfer_cost_per_gb=0.09

    local expected_hours=1.5
    local max_hours=3

    local expected_instance=$( echo "$instance_hourly * $expected_hours" | bc -l | xargs printf "%.2f" )
    local expected_ebs=$( echo "$ebs_hourly * $expected_hours" | bc -l | xargs printf "%.2f" )
    local transfer_cost=$( echo "$transfer_gb * $transfer_cost_per_gb" | bc -l | xargs printf "%.2f" )
    local expected_total=$( echo "$expected_instance + $expected_ebs + $transfer_cost" | bc -l | xargs printf "%.2f" )

    local max_instance=$( echo "$instance_hourly * $max_hours" | bc -l | xargs printf "%.2f" )
    local max_ebs=$( echo "$ebs_hourly * $max_hours" | bc -l | xargs printf "%.2f" )
    local max_total=$( echo "$max_instance + $max_ebs + $transfer_cost" | bc -l | xargs printf "%.2f" )

    cat <<EOF
Cost Breakdown (us-east-1, c5n.metal):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Expected Build (~90 minutes):
  Instance (c5n.metal):  \$${expected_instance}  ($instance_hourly/hr × ${expected_hours}h)
  EBS (500GB gp3):       \$${expected_ebs}   ($ebs_hourly/hr × ${expected_hours}h)
  Data Transfer (100GB): \$${transfer_cost}  ($transfer_cost_per_gb/GB × ${transfer_gb}GB)
  ────────────────────────────────────────
  Expected Total:        \$${expected_total}

Maximum (3-hour timeout):
  Instance:              \$${max_instance}  ($instance_hourly/hr × ${max_hours}h)
  EBS:                   \$${max_ebs}   ($ebs_hourly/hr × ${max_hours}h)
  Data Transfer:         \$${transfer_cost}
  ────────────────────────────────────────
  Maximum Total:         \$${max_total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Safety Controls:
  ✓ Watchdog Lambda (auto-terminate >3 hours)
  ✓ CloudWatch alarms
  ✓ Budget alerts
  ✓ Automatic cleanup on success/failure

EOF
}

# Confirm with user
confirm_launch() {
    log_section "Build Configuration"

    cat <<EOF
Build Details:
  Branch:        ${BUILD_BRANCH}
  Commit:        ${BUILD_COMMIT:-HEAD}
  Estimated Time: 90 minutes
  Instance Type: c5n.metal
  Disk Size:     500GB gp3

EOF

    estimate_costs

    read -p "Proceed with build? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        error_exit "Aborted by user"
    fi
}

# Initialize Terraform
init_terraform() {
    log_section "Initializing Terraform"

    cd "$TERRAFORM_DIR"

    terraform init

    log_info "✓ Terraform initialized"
}

# Detect caller's public IP for SSH access
get_caller_ip() {
    local ip

    # Try multiple services to get public IP
    ip=$(curl -s https://api.ipify.org 2>/dev/null) || \
    ip=$(curl -s https://ifconfig.me 2>/dev/null) || \
    ip=$(curl -s https://icanhazip.com 2>/dev/null)

    if [ -n "$ip" ]; then
        echo "$ip"
    else
        log_warn "Could not detect public IP address"
        echo ""
    fi
}

# Launch build instance
launch_build() {
    log_section "Launching Build Instance"

    cd "$TERRAFORM_DIR"

    # Generate unique build ID
    local build_id="build-$(date +%Y%m%d-%H%M%S)"

    log_info "Build ID: ${build_id}"

    # Detect caller's IP for SSH access restriction
    local caller_ip=$(get_caller_ip)
    local ssh_cidrs

    if [ -n "$caller_ip" ]; then
        ssh_cidrs="[\"${caller_ip}/32\"]"
        log_info "SSH access will be restricted to your IP: ${caller_ip}"
    else
        log_warn "Could not detect your IP - SSH will be open to 0.0.0.0/0"
        log_warn "Consider manually restricting SSH access in terraform.tfvars"
        ssh_cidrs="[\"0.0.0.0/0\"]"
    fi

    # Create terraform.tfvars
    cat > terraform.tfvars <<EOF
build_id         = "${build_id}"
build_branch     = "${BUILD_BRANCH}"
build_commit     = "${BUILD_COMMIT}"
github_token     = "${GITHUB_TOKEN:-}"
aws_region       = "us-east-1"
instance_type    = "c5n.metal"
volume_size      = 500
max_lifetime_hours = 3
ssh_allowed_cidrs = ${ssh_cidrs}
notification_email = ""
EOF

    # Apply Terraform
    log_info "Running Terraform apply..."

    if terraform apply -auto-approve; then
        log_info "✓ Instance launched successfully"

        # Save build ID for cleanup
        echo "$build_id" > "${PROJECT_ROOT}/.last-build-id"

        # Get outputs
        local instance_id=$(terraform output -raw instance_id)
        local public_ip=$(terraform output -raw instance_public_ip)
        local log_group=$(terraform output -raw cloudwatch_log_group)

        cat <<EOF

Build Instance Launched:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Build ID:       ${build_id}
  Instance ID:    ${instance_id}
  Public IP:      ${public_ip}
  Log Group:      ${log_group}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Monitor Progress:
  CloudWatch Logs: aws logs tail ${log_group} --follow
  SSH Access:      ssh ubuntu@${public_ip}
  DynamoDB State:  aws dynamodb get-item --table-name labapp-metal-builds --key '{"BuildID":{"S":"${build_id}"}}'

EOF

        return 0
    else
        error_exit "Terraform apply failed"
    fi
}

# Monitor build progress
monitor_build() {
    log_section "Monitoring Build Progress"

    local build_id=$(cat "${PROJECT_ROOT}/.last-build-id")
    local start_time=$(date +%s)

    log_info "Monitoring build ${build_id}"
    log_info "This will take approximately 90 minutes..."

    while true; do
        # Check DynamoDB for status
        local item=$(aws dynamodb get-item \
            --table-name labapp-metal-builds \
            --key "{\"BuildID\":{\"S\":\"${build_id}\"}}" \
            --output json 2>/dev/null || echo '{}')

        local status=$(echo "$item" | jq -r '.Item.Status.S // "unknown"')

        # Calculate elapsed time
        local now=$(date +%s)
        local elapsed=$((now - start_time))
        local elapsed_min=$((elapsed / 60))

        case "$status" in
            "completed")
                log_info "✓ Build completed successfully after ${elapsed_min} minutes"
                return 0
                ;;
            "failed"|"terminated")
                local error_msg=$(echo "$item" | jq -r '.Item.ErrorMessage.S // "Unknown error"')
                log_error "Build failed: ${error_msg}"
                return 1
                ;;
            "launching"|"building"|"uploading")
                log_info "[${elapsed_min} min] Status: ${status}"
                ;;
            *)
                log_warn "Unknown status: ${status}"
                ;;
        esac

        # Check timeout
        if [ $elapsed -gt $((MAX_BUILD_TIME_HOURS * 3600)) ]; then
            log_error "Build monitoring timeout after ${MAX_BUILD_TIME_HOURS} hours"
            return 1
        fi

        # Wait before next check
        sleep 60
    done
}

# Cleanup resources
cleanup_build() {
    log_section "Cleaning Up Resources"

    cd "$TERRAFORM_DIR"

    log_info "Running Terraform destroy..."

    if terraform destroy -auto-approve; then
        log_info "✓ Resources cleaned up successfully"
    else
        log_warn "Terraform destroy failed - some resources may remain"
        log_warn "Manual cleanup may be required"
    fi

    # Remove local state files
    rm -f terraform.tfvars
}

# Main execution
main() {
    log_section "Labapp Metal Build Launcher"

    echo "Starting AWS metal instance build for pre-warmed OVA"
    echo ""

    # Pre-flight checks
    check_prerequisites
    check_existing_builds
    confirm_launch

    # Setup
    init_terraform

    # Launch
    if ! launch_build; then
        error_exit "Failed to launch build instance"
    fi

    # Monitor (optional - can run in background)
    log_info ""
    read -p "Monitor build progress? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        if monitor_build; then
            log_info "Build completed successfully"
        else
            log_error "Build failed or timed out"
        fi
    else
        log_info "Build running in background. Monitor via CloudWatch Logs."
    fi

    # Cleanup
    log_info ""
    read -p "Clean up resources now? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        cleanup_build
    else
        log_warn "Resources left running. Remember to run 'terraform destroy' in ${TERRAFORM_DIR}"
        log_warn "Watchdog will terminate instance after 3 hours if still running"
    fi

    log_section "Complete"
}

# Execute main
main "$@"
