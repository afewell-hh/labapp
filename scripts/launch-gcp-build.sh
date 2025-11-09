#!/bin/bash
# Launch GCP compute instance for OVA builds with nested virtualization
# This script orchestrates the complete build lifecycle:
# 1. Pre-flight checks (credentials, quotas)
# 2. Cost estimation and user confirmation
# 3. Create GCP compute instance with nested virtualization
# 4. Monitor build progress (optional)
# 5. Cleanup resources (optional)
#
# Usage:
#   ./launch-gcp-build.sh [OPTIONS] [branch] [commit]
#
# Options:
#   --dry-run           Validate configuration without creating resources
#   --auto-approve      Skip confirmation prompts
#   --build-type TYPE   Build type: standard or prewarmed (default: standard)
#   --no-cleanup        Leave instance running after build
#
# Examples:
#   ./launch-gcp-build.sh main
#   ./launch-gcp-build.sh --dry-run main
#   ./launch-gcp-build.sh --build-type prewarmed feature/my-feature
#   ./launch-gcp-build.sh --auto-approve main abc123

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default values
DRY_RUN=false
AUTO_APPROVE=false
BUILD_TYPE="standard"
AUTO_CLEANUP=true
MONITOR_BUILD=true

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --auto-approve)
            AUTO_APPROVE=true
            shift
            ;;
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        --no-cleanup)
            AUTO_CLEANUP=false
            shift
            ;;
        --no-monitor)
            MONITOR_BUILD=false
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [OPTIONS] [branch] [commit]" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Parse positional arguments
BUILD_BRANCH="${1:-main}"
BUILD_COMMIT="${2:-}"

# Validate build type
if [[ "$BUILD_TYPE" != "standard" && "$BUILD_TYPE" != "prewarmed" ]]; then
    echo "Error: BUILD_TYPE must be 'standard' or 'prewarmed', got: $BUILD_TYPE" >&2
    exit 1
fi

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

# Load environment variables
load_environment() {
    log_section "Loading Environment"

    # Load .env if exists
    if [ -f "${PROJECT_ROOT}/.env" ]; then
        log_info "Loading .env file"
        # shellcheck disable=SC1091
        set -a
        source "${PROJECT_ROOT}/.env"
        set +a
    else
        log_warn ".env file not found, some variables may not be set"
    fi

    # Load .env.gcp if exists
    if [ -f "${PROJECT_ROOT}/.env.gcp" ]; then
        log_info "Loading .env.gcp file"
        # shellcheck disable=SC1091
        set -a
        source "${PROJECT_ROOT}/.env.gcp"
        set +a
    else
        error_exit ".env.gcp file not found. Copy .env.gcp.example to .env.gcp and configure it."
    fi

    # Validate required GCP variables
    local required_vars=(
        "GCP_PROJECT_ID"
        "GCP_ZONE"
        "GCS_BUCKET"
    )

    local missing_vars=()
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            missing_vars+=("$var")
        fi
    done

    if [ ${#missing_vars[@]} -gt 0 ]; then
        error_exit "Missing required environment variables: ${missing_vars[*]}"
    fi

    log_info "✓ Environment loaded successfully"
}

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    # Check for required tools
    local missing_tools=()

    for tool in gcloud jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        error_exit "Missing required tools: ${missing_tools[*]}"
    fi

    log_info "✓ All required tools installed"

    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        error_exit "No active gcloud authentication. Run: gcloud auth login"
    fi

    log_info "✓ gcloud authentication valid"

    # Set gcloud project
    gcloud config set project "${GCP_PROJECT_ID}" --quiet

    log_info "✓ gcloud project set to ${GCP_PROJECT_ID}"

    # Check GCS bucket exists
    if ! gsutil ls "gs://${GCS_BUCKET}/" &> /dev/null; then
        log_warn "GCS bucket gs://${GCS_BUCKET}/ does not exist or is not accessible"
        log_warn "Create it with: gsutil mb -p ${GCP_PROJECT_ID} -c STANDARD -l ${GCP_REGION:-us-central1} gs://${GCS_BUCKET}/"
    else
        log_info "✓ GCS bucket gs://${GCS_BUCKET}/ is accessible"
    fi
}

# Check for existing builds
check_existing_builds() {
    log_section "Checking for Existing Builds"

    # List running instances with builder label
    local running_builders
    running_builders=$(gcloud compute instances list \
        --filter="labels.purpose=labapp-builder AND status=RUNNING" \
        --format="table(name,zone,creationTimestamp)" \
        2>/dev/null || echo "")

    if [ -n "$running_builders" ]; then
        log_warn "Found running builder instance(s):"
        echo "$running_builders"
        echo ""

        if [ "$AUTO_APPROVE" = false ]; then
            read -p "Continue anyway? (yes/no): " -r
            if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                error_exit "Aborted by user"
            fi
        fi
    else
        log_info "✓ No active builds found"
    fi
}

# Estimate costs
estimate_costs() {
    log_section "Cost Estimation"

    # Machine type pricing (us-central1, approximate)
    local machine_type="${GCP_MACHINE_TYPE:-n2-standard-32}"
    local disk_size="${GCP_DISK_SIZE:-600}"
    local disk_type="${GCP_DISK_TYPE:-pd-ssd}"

    # Cost estimates (approximate, us-central1)
    local cost_per_hour
    case "$machine_type" in
        n2-standard-16) cost_per_hour=0.78 ;;
        n2-standard-32) cost_per_hour=1.55 ;;
        n2-highmem-32) cost_per_hour=2.08 ;;
        c2-standard-30) cost_per_hour=1.66 ;;
        *) cost_per_hour=1.55 ;; # default to n2-standard-32
    esac

    # Apply preemptible discount if enabled
    if [ "${GCP_ENABLE_PREEMPTIBLE:-false}" = "true" ]; then
        cost_per_hour=$(echo "$cost_per_hour * 0.2" | bc -l)
    fi

    local disk_cost_per_gb_month
    case "$disk_type" in
        pd-standard) disk_cost_per_gb_month=0.04 ;;
        pd-ssd) disk_cost_per_gb_month=0.17 ;;
        pd-balanced) disk_cost_per_gb_month=0.10 ;;
        *) disk_cost_per_gb_month=0.17 ;;
    esac

    # Calculate costs
    local expected_hours
    local max_hours="${GCP_MAX_BUILD_TIME_HOURS:-4}"

    if [ "$BUILD_TYPE" = "standard" ]; then
        expected_hours=1.0
    else
        expected_hours=1.5
    fi

    local expected_compute=$(echo "$cost_per_hour * $expected_hours" | bc -l | xargs printf "%.2f")
    local expected_disk=$(echo "$disk_cost_per_gb_month * $disk_size * ($expected_hours / 730)" | bc -l | xargs printf "%.2f")
    local expected_total=$(echo "$expected_compute + $expected_disk" | bc -l | xargs printf "%.2f")

    local max_compute=$(echo "$cost_per_hour * $max_hours" | bc -l | xargs printf "%.2f")
    local max_disk=$(echo "$disk_cost_per_gb_month * $disk_size * ($max_hours / 730)" | bc -l | xargs printf "%.2f")
    local max_total=$(echo "$max_compute + $max_disk" | bc -l | xargs printf "%.2f")

    # Estimate egress (approximate)
    local egress_cost
    if [ "$BUILD_TYPE" = "standard" ]; then
        egress_cost=2.40  # ~20GB
    else
        egress_cost=12.00  # ~100GB
    fi

    expected_total=$(echo "$expected_total + $egress_cost" | bc -l | xargs printf "%.2f")
    max_total=$(echo "$max_total + $egress_cost" | bc -l | xargs printf "%.2f")

    cat <<EOF
Cost Breakdown (${GCP_REGION:-us-central1}, $machine_type):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Expected Build (~${expected_hours}h):
  Compute ($machine_type):  \$${expected_compute}  (\$${cost_per_hour}/hr × ${expected_hours}h)
  Disk ($disk_type, ${disk_size}GB): \$${expected_disk}
  Network egress:           \$${egress_cost}
  ────────────────────────────────────────
  Expected Total:           \$${expected_total}

Maximum (${max_hours}-hour timeout):
  Compute:                  \$${max_compute}  (\$${cost_per_hour}/hr × ${max_hours}h)
  Disk:                     \$${max_disk}
  Network egress:           \$${egress_cost}
  ────────────────────────────────────────
  Maximum Total:            \$${max_total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Safety Controls:
  ✓ Auto-shutdown script (terminates after ${max_hours}h)
  ✓ Preemptible: ${GCP_ENABLE_PREEMPTIBLE:-false}
  ✓ Automatic cleanup on success

EOF
}

# Confirm with user
confirm_launch() {
    log_section "Build Configuration"

    cat <<EOF
Build Details:
  Branch:        ${BUILD_BRANCH}
  Commit:        ${BUILD_COMMIT:-HEAD}
  Build Type:    ${BUILD_TYPE}
  Machine Type:  ${GCP_MACHINE_TYPE:-n2-standard-32}
  Disk:          ${GCP_DISK_SIZE:-600}GB ${GCP_DISK_TYPE:-pd-ssd}
  Zone:          ${GCP_ZONE}
  Preemptible:   ${GCP_ENABLE_PREEMPTIBLE:-false}

EOF

    estimate_costs

    if [ "$AUTO_APPROVE" = false ]; then
        read -p "Proceed with build? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            error_exit "Aborted by user"
        fi
    fi
}

# Create startup script
create_startup_script() {
    local build_id="$1"
    local startup_script="/tmp/gcp-build-startup-${build_id}.sh"

    cat > "$startup_script" <<'EOF'
#!/bin/bash
# GCP Builder Instance Startup Script
# This script runs on instance startup to execute the Packer build

set -euo pipefail

# Logging setup
LOG_FILE="/var/log/gcp-build.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Build starting..."

# Metadata
BUILD_ID="__BUILD_ID__"
BUILD_BRANCH="__BUILD_BRANCH__"
BUILD_COMMIT="__BUILD_COMMIT__"
BUILD_TYPE="__BUILD_TYPE__"
GCS_BUCKET="__GCS_BUCKET__"
GCS_ARTIFACT_PATH="__GCS_ARTIFACT_PATH__"
GITHUB_TOKEN="__GITHUB_TOKEN__"
REPO_URL="https://github.com/afewell-hh/labapp.git"

echo "Build Configuration:"
echo "  Build ID: $BUILD_ID"
echo "  Branch: $BUILD_BRANCH"
echo "  Commit: ${BUILD_COMMIT:-HEAD}"
echo "  Build Type: $BUILD_TYPE"
echo "  GCS Bucket: gs://${GCS_BUCKET}/"

# Install dependencies
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    git \
    make \
    jq \
    bc \
    qemu-system-x86 \
    qemu-utils \
    cpu-checker

# Install Packer
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Installing Packer..."
curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update -qq
apt-get install -y -qq packer

# Verify KVM
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Verifying KVM support..."
if ! kvm-ok; then
    echo "ERROR: KVM not available. Ensure nested virtualization is enabled."
    exit 1
fi
echo "✓ KVM support confirmed"

# Clone repository
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Cloning repository..."
cd /root
if [ -n "$GITHUB_TOKEN" ]; then
    git clone --branch "$BUILD_BRANCH" "https://${GITHUB_TOKEN}@github.com/afewell-hh/labapp.git" labapp
else
    git clone --branch "$BUILD_BRANCH" "$REPO_URL" labapp
fi
cd labapp

# Checkout specific commit if provided
if [ -n "$BUILD_COMMIT" ]; then
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Checking out commit: $BUILD_COMMIT"
    git checkout "$BUILD_COMMIT"
fi

# Run build
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Starting Packer build..."
export VERSION="${BUILD_ID}"

if [ "$BUILD_TYPE" = "prewarmed" ]; then
    make build-prewarmed || {
        echo "ERROR: Packer build failed"
        exit 1
    }
else
    make build-standard || {
        echo "ERROR: Packer build failed"
        exit 1
    }
fi

echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Build completed successfully"

# Upload artifacts to GCS
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Uploading artifacts to GCS..."

OUTPUT_DIR="output-hedgehog-lab-${BUILD_TYPE}"
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "ERROR: Output directory not found: $OUTPUT_DIR"
    exit 1
fi

# Upload OVA and checksum
gsutil -m cp "${OUTPUT_DIR}"/*.ova "gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH}/" || {
    echo "ERROR: Failed to upload OVA to GCS"
    exit 1
}

gsutil -m cp "${OUTPUT_DIR}"/*.sha256 "gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH}/" || {
    echo "ERROR: Failed to upload checksum to GCS"
    exit 1
}

# Create and upload build manifest
cat > build-manifest.json <<MANIFEST
{
  "build_id": "$BUILD_ID",
  "build_type": "$BUILD_TYPE",
  "branch": "$BUILD_BRANCH",
  "commit": "${BUILD_COMMIT:-$(git rev-parse HEAD)}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    "gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH}/$(basename ${OUTPUT_DIR}/*.ova)"
  ]
}
MANIFEST

gsutil cp build-manifest.json "gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH}/${BUILD_ID}-manifest.json"

# Upload logs
gsutil cp "$LOG_FILE" "gs://${GCS_BUCKET}/builds/${BUILD_ID}/build.log"

echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] All artifacts uploaded successfully"
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Build process complete"

# Self-terminate instance
echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] Shutting down instance..."
shutdown -h now
EOF

    # Replace placeholders
    sed -i "s|__BUILD_ID__|${build_id}|g" "$startup_script"
    sed -i "s|__BUILD_BRANCH__|${BUILD_BRANCH}|g" "$startup_script"
    sed -i "s|__BUILD_COMMIT__|${BUILD_COMMIT}|g" "$startup_script"
    sed -i "s|__BUILD_TYPE__|${BUILD_TYPE}|g" "$startup_script"
    sed -i "s|__GCS_BUCKET__|${GCS_BUCKET}|g" "$startup_script"
    sed -i "s|__GCS_ARTIFACT_PATH__|${GCS_ARTIFACT_PATH:-releases}|g" "$startup_script"
    sed -i "s|__GITHUB_TOKEN__|${GITHUB_TOKEN:-}|g" "$startup_script"

    echo "$startup_script"
}

# Launch build instance
launch_build() {
    log_section "Launching Build Instance"

    # Generate unique build ID
    local build_id="build-$(date +%Y%m%d-%H%M%S)"
    local instance_name="labapp-builder-${build_id}"

    log_info "Build ID: ${build_id}"
    log_info "Instance name: ${instance_name}"

    if [ "$DRY_RUN" = true ]; then
        log_info "DRY RUN: Would create instance with configuration above"
        return 0
    fi

    # Create startup script
    local startup_script
    startup_script=$(create_startup_script "$build_id")

    # Create instance
    log_info "Creating GCP compute instance..."

    local preemptible_flag=""
    if [ "${GCP_ENABLE_PREEMPTIBLE:-false}" = "true" ]; then
        preemptible_flag="--preemptible"
    fi

    # Convert boolean GCP_ENABLE_PREEMPTIBLE to gcloud provisioning model
    local provisioning_model="STANDARD"
    if [[ "${GCP_ENABLE_PREEMPTIBLE:-false}" == "true" ]]; then
        provisioning_model="SPOT"
    fi

    gcloud compute instances create "$instance_name" \
        --project="${GCP_PROJECT_ID}" \
        --zone="${GCP_ZONE}" \
        --machine-type="${GCP_MACHINE_TYPE:-n2-standard-32}" \
        --network-interface="network-tier=PREMIUM,subnet=${GCP_NETWORK:-default}" \
        --maintenance-policy=TERMINATE \
        --provisioning-model="${provisioning_model}" \
        --service-account="${GCP_SERVICE_ACCOUNT:-default}" \
        --scopes=https://www.googleapis.com/auth/devstorage.full_control,https://www.googleapis.com/auth/cloud-platform \
        --create-disk="auto-delete=yes,boot=yes,device-name=${instance_name},image=projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts,mode=rw,size=${GCP_DISK_SIZE:-600},type=projects/${GCP_PROJECT_ID}/zones/${GCP_ZONE}/diskTypes/${GCP_DISK_TYPE:-pd-ssd},licenses=https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx" \
        --no-shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --labels="purpose=labapp-builder,build-id=${build_id},build-type=${BUILD_TYPE},managed-by=script" \
        --metadata-from-file=startup-script="$startup_script" \
        --min-cpu-platform="Intel Cascadelake" \
        ${preemptible_flag}

    log_info "✓ Instance created successfully"

    # Save build info
    echo "$build_id" > "${PROJECT_ROOT}/.last-gcp-build-id"
    echo "$instance_name" > "${PROJECT_ROOT}/.last-gcp-instance"

    # Clean up startup script
    rm -f "$startup_script"

    cat <<EOF

Build Instance Launched:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Build ID:       ${build_id}
  Instance:       ${instance_name}
  Zone:           ${GCP_ZONE}
  Machine Type:   ${GCP_MACHINE_TYPE:-n2-standard-32}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Monitor Progress:
  Serial Console:  gcloud compute instances get-serial-port-output ${instance_name} --zone=${GCP_ZONE}
  SSH:             gcloud compute ssh ${instance_name} --zone=${GCP_ZONE}
  Logs on VM:      tail -f /var/log/gcp-build.log

Artifacts will be uploaded to:
  gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH:-releases}/

EOF

    return 0
}

# Monitor build (simplified - just check if instance is still running)
monitor_build() {
    if [ "$MONITOR_BUILD" = false ]; then
        return 0
    fi

    log_section "Monitoring Build Progress"

    local instance_name
    instance_name=$(cat "${PROJECT_ROOT}/.last-gcp-instance" 2>/dev/null || echo "")

    if [ -z "$instance_name" ]; then
        log_warn "No instance name found, skipping monitoring"
        return 0
    fi

    log_info "Monitoring instance: $instance_name"
    log_info "Build will auto-shutdown when complete"
    log_info "Press Ctrl+C to stop monitoring (instance will continue)"

    while true; do
        local status
        status=$(gcloud compute instances describe "$instance_name" \
            --zone="${GCP_ZONE}" \
            --format="value(status)" 2>/dev/null || echo "NOTFOUND")

        case "$status" in
            RUNNING)
                echo -n "."
                ;;
            TERMINATED|STOPPING|STOPPED)
                echo ""
                log_info "Instance has stopped (status: $status)"
                log_info "Build likely complete. Check GCS for artifacts."
                return 0
                ;;
            NOTFOUND)
                echo ""
                log_warn "Instance not found (may have been deleted)"
                return 1
                ;;
            *)
                echo ""
                log_warn "Unexpected instance status: $status"
                ;;
        esac

        sleep 30
    done
}

# Cleanup resources
cleanup_build() {
    log_section "Cleaning Up Resources"

    local instance_name
    instance_name=$(cat "${PROJECT_ROOT}/.last-gcp-instance" 2>/dev/null || echo "")

    if [ -z "$instance_name" ]; then
        log_warn "No instance name found, nothing to clean up"
        return 0
    fi

    log_info "Deleting instance: $instance_name"

    if gcloud compute instances delete "$instance_name" \
        --zone="${GCP_ZONE}" \
        --quiet; then
        log_info "✓ Instance deleted successfully"
    else
        log_warn "Failed to delete instance (may already be deleted)"
    fi

    # Clean up local state files
    rm -f "${PROJECT_ROOT}/.last-gcp-build-id"
    rm -f "${PROJECT_ROOT}/.last-gcp-instance"
}

# Main execution
main() {
    log_section "Labapp GCP Build Launcher"

    echo "Starting GCP compute instance build for ${BUILD_TYPE} OVA"
    echo ""

    # Load environment
    load_environment

    # Pre-flight checks
    check_prerequisites
    check_existing_builds

    if [ "$DRY_RUN" = true ]; then
        log_section "Dry Run Mode"
        confirm_launch
        log_info "✓ Dry run validation passed"
        log_info "Remove --dry-run flag to actually launch build"
        exit 0
    fi

    # Confirm launch
    confirm_launch

    # Launch
    if ! launch_build; then
        error_exit "Failed to launch build instance"
    fi

    # Monitor (optional)
    if [ "$MONITOR_BUILD" = true ] && [ "$AUTO_APPROVE" = false ]; then
        echo ""
        read -p "Monitor build progress? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            monitor_build || true
        else
            log_info "Build running in background. Instance will auto-shutdown when complete."
        fi
    fi

    # Cleanup (optional)
    if [ "$AUTO_CLEANUP" = true ]; then
        echo ""
        if [ "$AUTO_APPROVE" = false ]; then
            read -p "Clean up instance now? (yes/no): " -r
            if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                cleanup_build
            else
                log_warn "Instance left running. Clean up manually with:"
                log_warn "  gcloud compute instances delete $(cat "${PROJECT_ROOT}/.last-gcp-instance") --zone=${GCP_ZONE}"
            fi
        fi
    fi

    log_section "Complete"
}

# Execute main
main "$@"
