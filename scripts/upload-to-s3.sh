#!/bin/bash
# Upload pre-warmed build artifacts to AWS S3
# Part of Hedgehog Lab Appliance build pipeline
#
# This script handles:
# - Large file uploads (80-100GB) with multipart upload
# - SHA256 checksum generation and verification
# - Metadata JSON file creation
# - Retry logic for failed uploads
# - Progress logging
# - Integrity verification
#
# Usage:
#   ./upload-to-s3.sh <ova-file> <version> [event-name]
#
# Examples:
#   ./upload-to-s3.sh hedgehog-lab-prewarmed-0.2.0.ova 0.2.0
#   ./upload-to-s3.sh hedgehog-lab-prewarmed-0.2.0-kubecon.ova 0.2.0 kubecon2026

set -euo pipefail

# Configuration
S3_BUCKET="hedgehog-lab-artifacts"
S3_REGION="us-east-1"
MAX_RETRIES=3

# Multipart upload configuration for large files (80-100GB)
# S3 has a 10,000 part limit, so for 100GB files:
#   100GB / 10,000 parts = 10MB minimum chunk size
# We use 100MB chunks for better performance and safety margin
MULTIPART_THRESHOLD=$((100 * 1024 * 1024))    # 100MB in bytes
MULTIPART_CHUNKSIZE=$((100 * 1024 * 1024))    # 100MB in bytes
MAX_BANDWIDTH=""  # Empty = unlimited (set to limit if needed, e.g., "50MB/s")

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Usage function
usage() {
    echo "Usage: $0 <ova-file> <version> [event-name]"
    echo ""
    echo "Arguments:"
    echo "  ova-file    Path to the OVA file to upload"
    echo "  version     Version number (e.g., 0.2.0)"
    echo "  event-name  Optional event name (e.g., kubecon2026)"
    echo ""
    echo "Examples:"
    echo "  $0 output-hedgehog-lab-prewarmed/hedgehog-lab-prewarmed-0.2.0.ova 0.2.0"
    echo "  $0 hedgehog-lab-prewarmed-0.2.0.ova 0.2.0 kubecon2026"
    exit 1
}

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

# Validate arguments
if [ $# -lt 2 ]; then
    log_error "Missing required arguments"
    usage
fi

OVA_FILE="$1"
VERSION="$2"
EVENT_NAME="${3:-}"

# Validate OVA file exists
if [ ! -f "$OVA_FILE" ]; then
    log_error "OVA file not found: $OVA_FILE"
    exit 1
fi

# Extract build type from filename
FILENAME=$(basename "$OVA_FILE")
if [[ "$FILENAME" =~ hedgehog-lab-([a-z]+)- ]]; then
    BUILD_TYPE="${BASH_REMATCH[1]}"
else
    log_error "Could not determine build type from filename: $FILENAME"
    exit 1
fi

# Determine S3 path
if [ -n "$EVENT_NAME" ]; then
    S3_PREFIX="prewarmed/events/${EVENT_NAME}"
else
    S3_PREFIX="releases/v${VERSION}"
fi

# Create working directory for checksums and metadata
WORK_DIR=$(dirname "$OVA_FILE")
CHECKSUM_FILE="${OVA_FILE}.sha256"
METADATA_FILE="${WORK_DIR}/hedgehog-lab-${BUILD_TYPE}-${VERSION}"
if [ -n "$EVENT_NAME" ]; then
    METADATA_FILE="${METADATA_FILE}-${EVENT_NAME}"
fi
METADATA_FILE="${METADATA_FILE}.metadata.json"

echo "=================================================="
log_info "Hedgehog Lab Artifact Upload"
echo "=================================================="
log_info "OVA File:    $OVA_FILE"
log_info "Version:     $VERSION"
log_info "Build Type:  $BUILD_TYPE"
if [ -n "$EVENT_NAME" ]; then
    log_info "Event:       $EVENT_NAME"
fi
log_info "S3 Bucket:   s3://${S3_BUCKET}/${S3_PREFIX}/"
echo ""

# Step 1: Generate SHA256 checksum
echo "=================================================="
log_info "Step 1: Generating SHA256 checksum..."
echo "=================================================="

if [ -f "$CHECKSUM_FILE" ]; then
    log_warn "Checksum file already exists: $CHECKSUM_FILE"
    log_info "Verifying existing checksum..."
    if sha256sum -c "$CHECKSUM_FILE" > /dev/null 2>&1; then
        log_info "Existing checksum verified successfully"
    else
        log_warn "Existing checksum verification failed, regenerating..."
        rm -f "$CHECKSUM_FILE"
    fi
fi

if [ ! -f "$CHECKSUM_FILE" ]; then
    log_info "Computing SHA256 checksum (this may take several minutes for large files)..."
    # Generate checksum with only filename (not full path) for user verification
    # This ensures users can verify downloads with: sha256sum -c file.ova.sha256
    OVA_DIR=$(dirname "$OVA_FILE")
    OVA_BASENAME=$(basename "$OVA_FILE")
    if (cd "$OVA_DIR" && sha256sum "$OVA_BASENAME") > "$CHECKSUM_FILE"; then
        log_info "Checksum generated: $CHECKSUM_FILE"
        cat "$CHECKSUM_FILE"
    else
        log_error "Failed to generate checksum"
        exit 1
    fi
else
    log_info "Using existing checksum file"
    cat "$CHECKSUM_FILE"
fi

# Extract checksum value
SHA256_CHECKSUM=$(awk '{print $1}' "$CHECKSUM_FILE")
echo ""

# Step 2: Get file size and metadata
echo "=================================================="
log_info "Step 2: Gathering file metadata..."
echo "=================================================="

FILE_SIZE_BYTES=$(stat -c%s "$OVA_FILE")
FILE_SIZE_GB=$(echo "scale=2; $FILE_SIZE_BYTES / 1024 / 1024 / 1024" | bc)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log_info "File size: ${FILE_SIZE_GB} GB (${FILE_SIZE_BYTES} bytes)"
log_info "Build date: $BUILD_DATE"
echo ""

# Step 3: Create metadata JSON
echo "=================================================="
log_info "Step 3: Creating metadata JSON..."
echo "=================================================="

# Construct download URL
S3_URL="https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${S3_PREFIX}/${FILENAME}"

# Create metadata JSON
cat > "$METADATA_FILE" << EOF
{
  "version": "${VERSION}",
  "build_type": "${BUILD_TYPE}",
  "build_date": "${BUILD_DATE}",
  "file_size_bytes": ${FILE_SIZE_BYTES},
  "file_size_gb": ${FILE_SIZE_GB},
  "sha256": "${SHA256_CHECKSUM}",
  "download_url": "${S3_URL}",
  "first_boot_time_minutes": 5,
  "system_requirements": {
    "memory_gb": 16,
    "cpu_cores": 8,
    "disk_gb": 100
  }
EOF

# Add event name if provided
if [ -n "$EVENT_NAME" ]; then
    cat >> "$METADATA_FILE" << EOF
,
  "event": "${EVENT_NAME}"
EOF
fi

# Close JSON
cat >> "$METADATA_FILE" << EOF

}
EOF

log_info "Metadata file created: $METADATA_FILE"
log_info "Contents:"
cat "$METADATA_FILE"
echo ""

# Step 4: Upload files to S3 with retry logic
echo "=================================================="
log_info "Step 4: Uploading files to S3..."
echo "=================================================="

# Configure AWS CLI for large file uploads (80-100GB)
# Create temporary AWS config to set multipart upload parameters
AWS_CONFIG_DIR=$(mktemp -d)
export AWS_CONFIG_FILE="${AWS_CONFIG_DIR}/config"

cat > "$AWS_CONFIG_FILE" << EOF
[default]
s3 =
    multipart_threshold = ${MULTIPART_THRESHOLD}
    multipart_chunksize = ${MULTIPART_CHUNKSIZE}
    max_concurrent_requests = 10
    max_queue_size = 1000
EOF

log_info "Configured AWS CLI for large file uploads:"
log_info "  Multipart threshold: $((MULTIPART_THRESHOLD / 1024 / 1024))MB"
log_info "  Multipart chunk size: $((MULTIPART_CHUNKSIZE / 1024 / 1024))MB"
log_info "  Max parts for 100GB: $((100 * 1024 * 1024 * 1024 / MULTIPART_CHUNKSIZE)) parts"
echo ""

# Cleanup function for temporary config
cleanup_aws_config() {
    rm -rf "$AWS_CONFIG_DIR"
}
trap cleanup_aws_config EXIT

upload_file() {
    local file="$1"
    local s3_path="$2"
    local attempt=1

    while [ $attempt -le $MAX_RETRIES ]; do
        log_info "Uploading $(basename "$file") (attempt $attempt/$MAX_RETRIES)..."

        if aws s3 cp "$file" "s3://${S3_BUCKET}/${s3_path}" \
            --region "$S3_REGION" \
            --storage-class STANDARD \
            --metadata "version=${VERSION},build-type=${BUILD_TYPE},sha256=${SHA256_CHECKSUM}"; then
            log_info "Successfully uploaded: $(basename "$file")"
            return 0
        else
            log_warn "Upload failed (attempt $attempt/$MAX_RETRIES)"
            if [ $attempt -lt $MAX_RETRIES ]; then
                log_info "Retrying in 5 seconds..."
                sleep 5
            fi
            attempt=$((attempt + 1))
        fi
    done

    log_error "Failed to upload $(basename "$file") after $MAX_RETRIES attempts"
    return 1
}

# Upload OVA file
if ! upload_file "$OVA_FILE" "${S3_PREFIX}/${FILENAME}"; then
    log_error "OVA upload failed"
    exit 1
fi

# Upload checksum file
if ! upload_file "$CHECKSUM_FILE" "${S3_PREFIX}/$(basename "$CHECKSUM_FILE")"; then
    log_error "Checksum upload failed"
    exit 1
fi

# Upload metadata file
if ! upload_file "$METADATA_FILE" "${S3_PREFIX}/$(basename "$METADATA_FILE")"; then
    log_error "Metadata upload failed"
    exit 1
fi

echo ""

# Step 5: Verify uploaded files
echo "=================================================="
log_info "Step 5: Verifying uploaded files..."
echo "=================================================="

verify_upload() {
    local s3_path="$1"
    local filename=$(basename "$s3_path")

    log_info "Verifying ${filename}..."

    if aws s3api head-object \
        --bucket "$S3_BUCKET" \
        --key "$s3_path" \
        --region "$S3_REGION" > /dev/null 2>&1; then

        # Get uploaded file size
        UPLOADED_SIZE=$(aws s3api head-object \
            --bucket "$S3_BUCKET" \
            --key "$s3_path" \
            --region "$S3_REGION" \
            --query 'ContentLength' \
            --output text)

        log_info "✓ ${filename} verified (${UPLOADED_SIZE} bytes)"
        return 0
    else
        log_error "✗ ${filename} verification failed"
        return 1
    fi
}

# Verify all uploaded files
VERIFICATION_FAILED=0

if ! verify_upload "${S3_PREFIX}/${FILENAME}"; then
    VERIFICATION_FAILED=1
fi

if ! verify_upload "${S3_PREFIX}/$(basename "$CHECKSUM_FILE")"; then
    VERIFICATION_FAILED=1
fi

if ! verify_upload "${S3_PREFIX}/$(basename "$METADATA_FILE")"; then
    VERIFICATION_FAILED=1
fi

echo ""

# Step 6: Generate download instructions
if [ $VERIFICATION_FAILED -eq 0 ]; then
    echo "=================================================="
    log_info "Upload Complete! ✓"
    echo "=================================================="
    echo ""
    echo "Download URLs:"
    echo "  OVA:      ${S3_URL}"
    echo "  Checksum: https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${S3_PREFIX}/$(basename "$CHECKSUM_FILE")"
    echo "  Metadata: https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${S3_PREFIX}/$(basename "$METADATA_FILE")"
    echo ""
    echo "Verification command:"
    echo "  wget ${S3_URL}"
    echo "  wget https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${S3_PREFIX}/$(basename "$CHECKSUM_FILE")"
    echo "  sha256sum -c $(basename "$CHECKSUM_FILE")"
    echo ""
    echo "=================================================="

    exit 0
else
    log_error "Upload verification failed!"
    exit 1
fi
