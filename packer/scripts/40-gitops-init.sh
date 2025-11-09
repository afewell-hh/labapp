#!/bin/bash
# 40-gitops-init.sh
# GitOps Repository Initialization Module for Hedgehog Lab Appliance
# Seeds Gitea with the student/hedgehog-config repository for ArgoCD
#
# This module:
# - Creates the "student" organization in Gitea
# - Creates the "hedgehog-config" repository
# - Seeds the repository with example VPC manifests and documentation
# - Configures the repository for GitOps workflows
#
# Prerequisites:
# - Gitea must be running and accessible (installed by 20-k3d-observability-init.sh)
# - kubectl configured to access k3d-observability cluster

set -euo pipefail

# Module metadata
MODULE_NAME="gitops-init"
MODULE_DESCRIPTION="Initialize GitOps repository in Gitea"
MODULE_VERSION="1.0.0"

# Configuration
GITEA_HTTP_PORT="${GITEA_HTTP_PORT:-3001}"
GITEA_NAMESPACE="${GITEA_NAMESPACE:-gitea}"
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-gitea_admin}"
GITEA_ADMIN_PASSWORD="${GITEA_ADMIN_PASSWORD:-admin123}"
GITEA_URL="http://localhost:${GITEA_HTTP_PORT}"
GITEA_SERVICE_URL="http://gitea-http.${GITEA_NAMESPACE}:3000"

STUDENT_ORG="student"
REPO_NAME="hedgehog-config"
REPO_DESCRIPTION="Hedgehog Fabric GitOps Configuration"

# Source directory for seed content
SEED_DIR="/opt/hedgehog-lab/configs/gitops/student-hedgehog-config"
TMP_REPO_DIR="/tmp/hedgehog-config-seed"

LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/gitops.log}"
GITOPS_TIMEOUT="${GITOPS_TIMEOUT:-600}"  # 10 minutes

# Ensure log directory exists with correct ownership
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chown hhlab:hhlab "$LOG_FILE"

# Logging functions
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl command not found"
        return 1
    fi

    # Check for curl
    if ! command -v curl &> /dev/null; then
        log_error "curl command not found"
        return 1
    fi

    # Check for git
    if ! command -v git &> /dev/null; then
        log_error "git command not found"
        return 1
    fi

    # Check if Gitea is accessible
    log_info "Waiting for Gitea to be accessible..."
    local max_attempts=60
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "${GITEA_URL}/api/swagger" > /dev/null 2>&1; then
            log_info "Gitea is accessible at ${GITEA_URL}"
            return 0
        fi
        sleep 2
        ((attempt++))
    done

    log_error "Gitea is not accessible after ${max_attempts} attempts"
    return 1
}

# Create student organization
create_student_org() {
    log_info "Creating student organization in Gitea..."

    # Check if organization already exists
    local org_check
    org_check=$(curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/orgs/${STUDENT_ORG}" 2>/dev/null || echo "")

    if [ -n "$org_check" ]; then
        log_info "Organization '${STUDENT_ORG}' already exists"
        return 0
    fi

    # Create organization
    local response
    response=$(curl -sf -X POST \
        -H "Content-Type: application/json" \
        -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/orgs" \
        -d "{
            \"username\": \"${STUDENT_ORG}\",
            \"description\": \"Student organization for lab exercises\",
            \"visibility\": \"public\"
        }" 2>&1)

    if [ $? -eq 0 ]; then
        log_info "Created organization '${STUDENT_ORG}'"
        return 0
    else
        log_error "Failed to create organization: $response"
        return 1
    fi
}

# Create hedgehog-config repository
create_repo() {
    log_info "Creating hedgehog-config repository..."

    # Check if repository already exists
    local repo_check
    repo_check=$(curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/repos/${STUDENT_ORG}/${REPO_NAME}" 2>/dev/null || echo "")

    if [ -n "$repo_check" ]; then
        log_info "Repository '${STUDENT_ORG}/${REPO_NAME}' already exists"
        return 0
    fi

    # Create repository
    local response
    response=$(curl -sf -X POST \
        -H "Content-Type: application/json" \
        -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/orgs/${STUDENT_ORG}/repos" \
        -d "{
            \"name\": \"${REPO_NAME}\",
            \"description\": \"${REPO_DESCRIPTION}\",
            \"private\": false,
            \"auto_init\": true,
            \"default_branch\": \"main\",
            \"gitignores\": \"\",
            \"license\": \"\"
        }" 2>&1)

    if [ $? -eq 0 ]; then
        log_info "Created repository '${STUDENT_ORG}/${REPO_NAME}'"
        # Wait for repository to be fully initialized
        sleep 3
        return 0
    else
        log_error "Failed to create repository: $response"
        return 1
    fi
}

# Seed repository with initial content
seed_repo() {
    log_info "Seeding repository with initial content..."

    # Check if seed directory exists
    if [ ! -d "$SEED_DIR" ]; then
        log_error "Seed directory not found: $SEED_DIR"
        return 1
    fi

    # Clean up any existing temp directory
    rm -rf "$TMP_REPO_DIR"

    # Clone the repository
    log_info "Cloning repository..."
    local clone_url="${GITEA_URL}/${STUDENT_ORG}/${REPO_NAME}.git"

    # Configure git credential helper to avoid password in URL
    # This prevents credentials from appearing in process lists or git output
    git config --global credential.helper store

    # Create credential file temporarily
    local git_credentials_file="/tmp/.git-credentials-$$"
    echo "http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@localhost:${GITEA_HTTP_PORT}" > "$git_credentials_file"
    chmod 600 "$git_credentials_file"
    git config --global credential.helper "store --file=$git_credentials_file"

    # Clone without password in URL
    log_info "Cloning repository (credentials managed securely)..."
    if ! git clone "http://localhost:${GITEA_HTTP_PORT}/${STUDENT_ORG}/${REPO_NAME}.git" "$TMP_REPO_DIR" >> "$LOG_FILE" 2>&1; then
        log_error "Failed to clone repository"
        rm -f "$git_credentials_file"
        git config --global --unset credential.helper
        return 1
    fi

    cd "$TMP_REPO_DIR"

    # Configure git user for commits
    git config user.name "Hedgehog Lab"
    git config user.email "lab@hedgehog.local"

    # Copy seed files
    log_info "Copying seed files from $SEED_DIR..."

    # Copy examples directory
    if [ -d "${SEED_DIR}/examples" ]; then
        cp -r "${SEED_DIR}/examples" ./
        log_info "Copied examples directory"
    fi

    # Copy active directory
    if [ -d "${SEED_DIR}/active" ]; then
        cp -r "${SEED_DIR}/active" ./
        log_info "Copied active directory"
    fi

    # Copy README (rename REPOSITORY_README.md to README.md)
    if [ -f "${SEED_DIR}/REPOSITORY_README.md" ]; then
        cp "${SEED_DIR}/REPOSITORY_README.md" ./README.md
        log_info "Copied README.md"
    fi

    # Stage all files
    git add -A

    # Check if there are changes to commit
    if git diff --staged --quiet; then
        log_info "No changes to commit (repository may already be seeded)"
        cd - > /dev/null
        rm -rf "$TMP_REPO_DIR"
        rm -f "$git_credentials_file"
        git config --global --unset credential.helper
        return 0
    fi

    # Commit changes
    log_info "Committing seed content..."
    if ! git commit -m "Initial seed from Hedgehog Lab curriculum

This repository contains:
- Example VPC and VPCAttachment manifests
- Active directory for student work
- Documentation and best practices

Auto-seeded by 40-gitops-init.sh during lab initialization." >> "$LOG_FILE" 2>&1; then
        log_error "Failed to commit changes"
        cd - > /dev/null
        rm -rf "$TMP_REPO_DIR"
        rm -f "$git_credentials_file"
        git config --global --unset credential.helper
        return 1
    fi

    # Push changes (using credential helper configured earlier)
    log_info "Pushing seed content to Gitea..."
    if ! git push origin main >> "$LOG_FILE" 2>&1; then
        log_error "Failed to push changes"
        cd - > /dev/null
        rm -rf "$TMP_REPO_DIR"
        rm -f "$git_credentials_file"
        git config --global --unset credential.helper
        return 1
    fi

    log_info "Successfully seeded repository with initial content"

    # Cleanup
    cd - > /dev/null
    rm -rf "$TMP_REPO_DIR"
    rm -f "$git_credentials_file"
    git config --global --unset credential.helper

    return 0
}

# Verify repository is accessible
verify_repo() {
    log_info "Verifying repository accessibility..."

    # Check repository via API
    local repo_info
    repo_info=$(curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/repos/${STUDENT_ORG}/${REPO_NAME}")

    if [ $? -eq 0 ]; then
        # Extract repository details
        local default_branch
        default_branch=$(echo "$repo_info" | grep -o '"default_branch":"[^"]*"' | cut -d'"' -f4)
        log_info "Repository verified: default branch is '${default_branch}'"

        # Verify files exist
        local files_check
        files_check=$(curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
            "${GITEA_URL}/api/v1/repos/${STUDENT_ORG}/${REPO_NAME}/contents/README.md")

        if [ $? -eq 0 ]; then
            log_info "Repository content verified (README.md exists)"
            return 0
        else
            log_warn "Repository exists but content verification failed"
            return 0  # Don't fail, repo might be empty
        fi
    else
        log_error "Failed to verify repository"
        return 1
    fi
}

# Get repository summary
get_repo_summary() {
    log_info ""
    log_info "GitOps Repository Summary:"
    log_info "  Organization: ${STUDENT_ORG}"
    log_info "  Repository: ${REPO_NAME}"
    log_info "  Clone URL (HTTP): ${GITEA_URL}/${STUDENT_ORG}/${REPO_NAME}.git"
    log_info "  Clone URL (SSH): ssh://git@localhost:2222/${STUDENT_ORG}/${REPO_NAME}.git"
    log_info "  Web URL: ${GITEA_URL}/${STUDENT_ORG}/${REPO_NAME}"
    log_info "  Service URL (internal): ${GITEA_SERVICE_URL}/${STUDENT_ORG}/${REPO_NAME}.git"
    log_info "  Admin User: ${GITEA_ADMIN_USER}"
    log_info "  Password: (stored in Gitea - retrieve via: kubectl get secret gitea-admin-secret -n gitea)"
    log_info ""
    log_info "Repository Structure:"
    log_info "  - examples/          Example VPC and VPCAttachment manifests"
    log_info "  - active/            Student workspace for active configurations"
    log_info "  - README.md          Repository documentation"
    log_info ""
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "GitOps Repository Initialization Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${GITOPS_TIMEOUT}s ($(( GITOPS_TIMEOUT / 60 )) minutes)"
    log_info ""

    local overall_start
    overall_start=$(date +%s)

    # Execute initialization steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! create_student_org; then
        log_error "Failed to create student organization"
        return 1
    fi

    if ! create_repo; then
        log_error "Failed to create repository"
        return 1
    fi

    if ! seed_repo; then
        log_error "Failed to seed repository"
        return 1
    fi

    if ! verify_repo; then
        log_error "Failed to verify repository"
        return 1
    fi

    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    get_repo_summary

    log_info ""
    log_info "=================================================="
    log_info "GitOps Repository Initialization Complete!"
    log_info "=================================================="
    log_info "Total initialization time: ${total_time}s"
    log_info "Repository is ready for ArgoCD integration"
    log_info ""

    return 0
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
    exit $?
fi

# Module interface functions for orchestrator integration
module_run() {
    main "$@"
}

module_validate() {
    # Validate that repository exists and is accessible
    curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/repos/${STUDENT_ORG}/${REPO_NAME}" > /dev/null 2>&1
}

module_cleanup() {
    # Optional cleanup function
    log_info "Cleaning up temporary files..."
    rm -rf "$TMP_REPO_DIR"
}

module_get_metadata() {
    cat <<EOF
{
  "name": "$MODULE_NAME",
  "description": "$MODULE_DESCRIPTION",
  "version": "$MODULE_VERSION",
  "timeout": $GITOPS_TIMEOUT,
  "dependencies": ["k3d", "gitea"]
}
EOF
}
