#!/bin/bash
# User data script for AWS metal instance pre-warmed builds
# This script runs on instance launch and performs the complete build process
#
# Expected environment variables (injected by Terraform):
# - BUILD_ID: Unique build identifier
# - BUILD_BRANCH: Git branch to build from
# - BUILD_COMMIT: Git commit SHA (optional)
# - S3_BUCKET: S3 bucket for artifacts
# - DYNAMODB_TABLE: DynamoDB table for state tracking
# - SNS_TOPIC_ARN: SNS topic for notifications
# - CLOUDWATCH_LOG_GROUP: CloudWatch log group
# - GITHUB_TOKEN: GitHub token for private repos (optional)
# - AWS_REGION: AWS region

set -euo pipefail

# Template variables (replaced by Terraform)
export BUILD_ID="${build_id}"
export BUILD_BRANCH="${build_branch}"
export BUILD_COMMIT="${build_commit}"
export S3_BUCKET="${s3_bucket}"
export DYNAMODB_TABLE="${dynamodb_table}"
export SNS_TOPIC_ARN="${sns_topic_arn}"
export CLOUDWATCH_LOG_GROUP="${cloudwatch_log_group}"
export GITHUB_TOKEN="${github_token}"
export AWS_REGION="${aws_region}"

# Constants
REPO_URL="https://github.com/afewell-hh/labapp.git"
WORK_DIR="/home/ubuntu/labapp-build"
LOG_FILE="/var/log/metal-build.log"
STATE_FILE="/var/lib/metal-build-state.json"
MAX_BUILD_TIME_SECONDS=$((3 * 3600))  # 3 hours

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"

    # Also send to CloudWatch Logs (if awslogs is configured)
    logger -t "metal-build" "[${level}] ${message}"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Error handler
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"

    log_error "FATAL: ${message}"

    # Only attempt AWS operations if AWS CLI is available
    # This prevents failures during early stages (before install_dependencies completes)
    if command -v aws &> /dev/null; then
        update_build_state "failed" "{\":ErrorMessage\": {\"S\": \"${message}\"}}"
        send_notification "FAILED" "Build ${BUILD_ID} failed: ${message}"

        # Upload partial logs to S3
        upload_logs "failed"
    else
        log_warn "AWS CLI not available - skipping state update/notification"
        log_warn "Build will remain in 'launching' state - manual cleanup required"
    fi

    exit "$exit_code"
}

trap 'error_exit "Build script failed at line $LINENO"' ERR

# Update DynamoDB build state
update_build_state() {
    local status="$1"
    local extra_attributes="${2:-}"

    log_info "Updating build state: ${status}"

    # Build update expression and attribute values
    local update_expr="SET #status = :status, LastUpdate = :timestamp"
    local attr_values=$(cat <<EOF
{
    ":status": {"S": "${status}"},
    ":timestamp": {"S": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"}
}
EOF
    )

    # Add extra attributes if provided (e.g., ErrorMessage, BuildDurationSeconds)
    if [ -n "$extra_attributes" ]; then
        attr_values=$(echo "$attr_values" | jq ". + ${extra_attributes}")

        # Add to update expression (extract keys from extra_attributes)
        # Keys in extra_attributes already have ':' prefix, so strip it for attribute names
        local extra_keys=$(echo "$extra_attributes" | jq -r 'keys[]')
        for key in $extra_keys; do
            # Strip leading ':' from key for attribute name (e.g., ':ErrorMessage' -> 'ErrorMessage')
            local attr_name="${key#:}"
            update_expr="${update_expr}, ${attr_name} = ${key}"
        done
    fi

    # Use update-item instead of put-item to preserve existing attributes (LaunchTime, ExpirationTime TTL)
    aws dynamodb update-item \
        --table-name "$DYNAMODB_TABLE" \
        --key "{\"BuildID\":{\"S\":\"${BUILD_ID}\"}}" \
        --update-expression "$update_expr" \
        --expression-attribute-names '{"#status":"Status"}' \
        --expression-attribute-values "$attr_values" \
        --region "$AWS_REGION" || log_warn "Failed to update DynamoDB"
}

# Send SNS notification
send_notification() {
    local status="$1"
    local message="$2"

    log_info "Sending SNS notification: ${status}"

    local subject="[${status}] labapp metal build: ${BUILD_ID}"

    aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "$subject" \
        --message "$message" \
        --region "$AWS_REGION" || log_warn "Failed to send SNS notification"
}

# Upload logs to S3
upload_logs() {
    local status="$1"

    log_info "Uploading logs to S3"

    local log_key="builds/${BUILD_ID}/logs/build.log"

    aws s3 cp "$LOG_FILE" \
        "s3://${S3_BUCKET}/${log_key}" \
        --region "$AWS_REGION" || log_warn "Failed to upload logs to S3"
}

# Check disk space
check_disk_space() {
    local available_gb=$(df -BG /home/ubuntu | awk 'NR==2 {print $4}' | sed 's/G//')

    log_info "Available disk space: ${available_gb}GB"

    if [ "$available_gb" -lt 300 ]; then
        error_exit "Insufficient disk space: ${available_gb}GB (need 300GB+)"
    fi
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies (Packer, QEMU/KVM, AWS CLI)"

    # Update package lists
    sudo apt-get update -y

    # Install QEMU/KVM for nested virtualization
    log_info "Installing QEMU/KVM"
    sudo apt-get install -y \
        qemu-kvm \
        qemu-utils \
        libvirt-daemon-system \
        libvirt-clients \
        bridge-utils \
        cpu-checker \
        cloud-image-utils

    # Verify nested virtualization support
    if ! sudo kvm-ok; then
        error_exit "KVM nested virtualization not available"
    fi

    # Add ubuntu user to kvm and libvirt groups
    sudo usermod -aG kvm ubuntu
    sudo usermod -aG libvirt ubuntu

    # Install Packer
    log_info "Installing Packer"
    PACKER_VERSION="1.10.0"
    wget -q "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip"
    unzip -q packer_${PACKER_VERSION}_linux_amd64.zip
    sudo mv packer /usr/local/bin/
    rm packer_${PACKER_VERSION}_linux_amd64.zip

    packer --version || error_exit "Packer installation failed"

    # Install additional tools
    sudo apt-get install -y \
        git \
        jq \
        curl \
        wget

    # Install AWS CLI (if not already present)
    if ! command -v aws &> /dev/null; then
        log_info "Installing AWS CLI"
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip -q awscliv2.zip
        sudo ./aws/install
        rm -rf aws awscliv2.zip
    fi

    aws --version || error_exit "AWS CLI installation failed"

    log_info "All dependencies installed successfully"
}

# Clone repository
clone_repository() {
    log_info "Cloning repository: ${REPO_URL}"

    mkdir -p "$WORK_DIR"
    cd /home/ubuntu

    # Clone with token if provided
    if [ -n "$GITHUB_TOKEN" ]; then
        git clone "https://${GITHUB_TOKEN}@github.com/afewell-hh/labapp.git" labapp-build
    else
        git clone "$REPO_URL" labapp-build
    fi

    cd "$WORK_DIR"

    # Checkout specific branch
    git checkout "$BUILD_BRANCH"

    # Checkout specific commit if provided
    if [ -n "$BUILD_COMMIT" ]; then
        git checkout "$BUILD_COMMIT"
    fi

    local actual_commit=$(git rev-parse HEAD)
    log_info "Repository cloned at commit: ${actual_commit}"

    # Update DynamoDB with actual commit
    update_build_state "building" "{\":ActualCommit\": {\"S\": \"${actual_commit}\"}}"
}

# Run Packer build
run_packer_build() {
    log_info "Starting Packer build (this will take 60-90 minutes)"

    cd "$WORK_DIR"

    local start_time=$(date +%s)
    update_build_state "building" "{\":BuildStartTime\": {\"S\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}"}"

    # Run Packer with timeout
    timeout $MAX_BUILD_TIME_SECONDS \
        packer build \
        -force \
        -timestamp-ui \
        packer/prewarmed-build.pkr.hcl 2>&1 | tee -a "$LOG_FILE"

    local packer_exit_code=${PIPESTATUS[0]}

    if [ $packer_exit_code -eq 124 ]; then
        error_exit "Packer build timed out after ${MAX_BUILD_TIME_SECONDS} seconds"
    elif [ $packer_exit_code -ne 0 ]; then
        error_exit "Packer build failed with exit code ${packer_exit_code}"
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local duration_min=$((duration / 60))

    log_info "Packer build completed successfully in ${duration_min} minutes"

    update_build_state "uploading" "{\":BuildDurationSeconds\": {\"N\": \"${duration}\"}}"
}

# Upload artifacts to S3
upload_artifacts() {
    log_info "Uploading artifacts to S3"

    cd "$WORK_DIR"

    # Find the generated OVA file
    local ova_file=$(find output-hedgehog-lab-prewarmed -name "*.ova" | head -1)

    if [ -z "$ova_file" ] || [ ! -f "$ova_file" ]; then
        error_exit "OVA file not found in output directory"
    fi

    log_info "Found OVA file: ${ova_file}"

    # Get file size
    local file_size=$(stat -f%z "$ova_file" 2>/dev/null || stat -c%s "$ova_file")
    local file_size_gb=$((file_size / 1024 / 1024 / 1024))
    log_info "OVA file size: ${file_size_gb}GB"

    # Use existing upload script
    local version="${BUILD_BRANCH#v}"  # Remove 'v' prefix if present
    bash scripts/upload-to-s3.sh "$ova_file" "$version"

    log_info "Artifacts uploaded successfully"

    update_build_state "completed" "{\":CompletionTime\": {\"S\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}"}"
}

# Main execution
main() {
    log_info "=== Metal Build Started ==="
    log_info "Build ID: ${BUILD_ID}"
    log_info "Branch: ${BUILD_BRANCH}"
    log_info "Commit: ${BUILD_COMMIT:-HEAD}"

    # Use IMDSv2 to get instance metadata (ec2-metadata not installed by default in Ubuntu 22.04)
    local token=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
    local instance_type=$(curl -H "X-aws-ec2-metadata-token: $token" -s http://169.254.169.254/latest/meta-data/instance-type)
    local instance_id=$(curl -H "X-aws-ec2-metadata-token: $token" -s http://169.254.169.254/latest/meta-data/instance-id)

    log_info "Instance Type: ${instance_type}"
    log_info "Instance ID: ${instance_id}"

    send_notification "STARTED" "Build ${BUILD_ID} started on branch ${BUILD_BRANCH}"

    # Pre-flight checks
    check_disk_space

    # Installation phase
    install_dependencies

    # Repository setup
    clone_repository

    # Build phase
    run_packer_build

    # Upload phase
    upload_artifacts

    # Upload final logs
    upload_logs "completed"

    # Success notification
    send_notification "SUCCESS" "Build ${BUILD_ID} completed successfully. Artifacts uploaded to S3."

    log_info "=== Metal Build Completed Successfully ==="

    # Signal completion (Terraform will destroy resources)
    touch /tmp/build-complete
}

# Execute main function
main
