#!/bin/bash
# Upload OVA artifacts to Google Cloud Storage
# This script uploads build artifacts (.ova and .sha256) to the configured GCS bucket
#
# Usage:
#   ./scripts/publish-to-gcs.sh [output-dir] [version]
#
# Examples:
#   ./scripts/publish-to-gcs.sh output-hedgehog-lab-standard 0.1.0
#   ./scripts/publish-to-gcs.sh output-hedgehog-lab-prewarmed 0.2.0
#
# Environment Variables (from .env.gcp):
#   GCS_BUCKET          - GCS bucket name (required)
#   GCS_ARTIFACT_PATH   - Path within bucket (default: releases)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

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
    if [ -z "${GCS_BUCKET:-}" ]; then
        error_exit "GCS_BUCKET not set in .env.gcp"
    fi

    # Set defaults
    GCS_ARTIFACT_PATH="${GCS_ARTIFACT_PATH:-releases}"

    log_info "✓ Environment loaded successfully"
    log_info "  Bucket: gs://${GCS_BUCKET}/"
    log_info "  Path: ${GCS_ARTIFACT_PATH}/"
}

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    # Check for gsutil
    if ! command -v gsutil &> /dev/null; then
        error_exit "gsutil not found. Install gcloud SDK: https://cloud.google.com/sdk/install"
    fi

    log_info "✓ gsutil installed"

    # Check GCS bucket exists
    if ! gsutil ls "gs://${GCS_BUCKET}/" &> /dev/null; then
        log_warn "GCS bucket gs://${GCS_BUCKET}/ does not exist or is not accessible"
        error_exit "Create it with: gsutil mb -p \${GCP_PROJECT_ID} -c STANDARD -l \${GCP_REGION:-us-central1} gs://${GCS_BUCKET}/"
    fi

    log_info "✓ GCS bucket gs://${GCS_BUCKET}/ is accessible"
}

# Upload artifacts
upload_artifacts() {
    local output_dir="$1"
    local version="$2"

    log_section "Uploading Artifacts"

    # Validate output directory exists
    if [ ! -d "${output_dir}" ]; then
        error_exit "Output directory not found: ${output_dir}"
    fi

    # Find OVA file matching the version
    local ova_file
    # Try to find OVA with version in filename first
    ova_file=$(find "${output_dir}" -maxdepth 1 -name "*${version}*.ova" -type f | head -n 1)

    # If not found, try with 'v' prefix
    if [ -z "$ova_file" ]; then
        ova_file=$(find "${output_dir}" -maxdepth 1 -name "*v${version}*.ova" -type f | head -n 1)
    fi

    # If still not found, check if there's only one OVA and warn
    if [ -z "$ova_file" ]; then
        local ova_count
        ova_count=$(find "${output_dir}" -maxdepth 1 -name "*.ova" -type f | wc -l)

        if [ "$ova_count" -eq 0 ]; then
            error_exit "No OVA file found in ${output_dir}"
        elif [ "$ova_count" -eq 1 ]; then
            ova_file=$(find "${output_dir}" -maxdepth 1 -name "*.ova" -type f)
            log_warn "OVA filename does not contain version '${version}'"
            log_warn "Found single OVA: $(basename "$ova_file")"
            log_warn "This will be published as version v${version}"
            echo ""
            read -r -p "Continue? [y/N] " response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                error_exit "Upload cancelled by user"
            fi
        else
            error_exit "Multiple OVA files found but none match version '${version}'. Please specify correct output directory or clean old builds."
        fi
    fi

    # Find checksum file
    local checksum_file="${ova_file}.sha256"

    if [ ! -f "$checksum_file" ]; then
        log_warn "Checksum file not found: ${checksum_file}"
        log_info "Generating checksum..."
        (cd "$(dirname "$ova_file")" && sha256sum "$(basename "$ova_file")" > "$(basename "$checksum_file")")
    fi

    log_info "Found artifacts:"
    log_info "  OVA: $(basename "$ova_file")"
    log_info "  Checksum: $(basename "$checksum_file")"
    log_info "  Size: $(du -h "$ova_file" | cut -f1)"

    # Determine destination path
    local dest_path="gs://${GCS_BUCKET}/${GCS_ARTIFACT_PATH}/v${version}/"

    log_info "Destination: ${dest_path}"

    # Upload OVA
    log_info "Uploading OVA file..."
    if gsutil -m cp "$ova_file" "${dest_path}"; then
        log_info "✓ OVA uploaded successfully"
    else
        error_exit "Failed to upload OVA to GCS"
    fi

    # Upload checksum
    log_info "Uploading checksum file..."
    if gsutil -m cp "$checksum_file" "${dest_path}"; then
        log_info "✓ Checksum uploaded successfully"
    else
        error_exit "Failed to upload checksum to GCS"
    fi

    # Create and upload build manifest
    log_info "Creating build manifest..."
    local manifest_file="/tmp/build-manifest-${version}.json"

    cat > "$manifest_file" <<MANIFEST
{
  "version": "${version}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    "${dest_path}$(basename "$ova_file")",
    "${dest_path}$(basename "$checksum_file")"
  ],
  "ova_size_bytes": $(stat -c%s "$ova_file" 2>/dev/null || stat -f%z "$ova_file"),
  "checksum": "$(awk '{print $1}' "$checksum_file")"
}
MANIFEST

    if gsutil cp "$manifest_file" "${dest_path}manifest.json"; then
        log_info "✓ Manifest uploaded successfully"
    else
        log_warn "Failed to upload manifest (non-critical)"
    fi

    rm -f "$manifest_file"

    # Verify uploads
    log_section "Verifying Upload"

    log_info "Listing uploaded artifacts:"
    gsutil ls -lh "${dest_path}"

    log_section "Upload Complete"

    cat <<EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Artifacts uploaded to GCS:

  Version: v${version}
  Location: ${dest_path}

  OVA: $(basename "$ova_file")
  Checksum: $(basename "$checksum_file")
  Manifest: manifest.json

To download:
  gsutil cp "${dest_path}$(basename "$ova_file")" ./

To generate signed URL (valid 7 days):
  gsutil signurl -d 7d \${GCP_SERVICE_ACCOUNT_KEY_PATH} \\
    "${dest_path}$(basename "$ova_file")"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

# Show usage
usage() {
    cat <<EOF
Usage: $0 [output-dir] [version]

Upload OVA artifacts to Google Cloud Storage.

Arguments:
  output-dir    Path to Packer output directory (e.g., output-hedgehog-lab-standard)
  version       Version number (e.g., 0.1.0)

Examples:
  $0 output-hedgehog-lab-standard 0.1.0
  $0 output-hedgehog-lab-prewarmed 0.2.0

Environment Variables (from .env.gcp):
  GCS_BUCKET          - GCS bucket name (required)
  GCS_ARTIFACT_PATH   - Path within bucket (default: releases)

EOF
    exit 1
}

# Main execution
main() {
    # Parse arguments
    if [ $# -ne 2 ]; then
        usage
    fi

    local output_dir="$1"
    local version="$2"

    # Remove 'v' prefix if present
    version="${version#v}"

    log_section "GCS Artifact Publisher"

    echo "Publishing version: v${version}"
    echo "Output directory: ${output_dir}"
    echo ""

    # Load environment
    load_environment

    # Pre-flight checks
    check_prerequisites

    # Upload
    upload_artifacts "$output_dir" "$version"
}

# Execute main
main "$@"
