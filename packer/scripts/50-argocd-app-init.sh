#!/bin/bash
# 50-argocd-app-init.sh
# ArgoCD Application Initialization Module for Hedgehog Lab Appliance
# Creates ArgoCD Application to sync student/hedgehog-config to Hedgehog controller
#
# This module:
# - Waits for Hedgehog VLAB controller to be ready
# - Retrieves the Hedgehog controller API endpoint
# - Creates ArgoCD cluster secret for Hedgehog controller
# - Creates ArgoCD Application for hedgehog-fabric GitOps workflow
# - Configures automated sync with self-heal enabled
#
# Prerequisites:
# - VLAB must be initialized (creates /var/lib/hedgehog-lab/vlab-initialized)
# - ArgoCD must be running in k3d-observability cluster
# - Gitea repository student/hedgehog-config must exist

set -euo pipefail

# Module metadata
MODULE_NAME="argocd-app-init"
MODULE_DESCRIPTION="Initialize ArgoCD Application for Hedgehog GitOps"
MODULE_VERSION="1.0.0"

# Configuration
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
GITEA_NAMESPACE="${GITEA_NAMESPACE:-gitea}"

# Hedgehog controller configuration
# The controller API is accessible from k3d containers via the bridge gateway IP
HEDGEHOG_API_SERVER="${HEDGEHOG_API_SERVER:-https://172.18.0.1:6443}"
HEDGEHOG_CLUSTER_NAME="hedgehog-vlab"

# GitOps repository
GITEA_SERVICE_URL="http://gitea-http.${GITEA_NAMESPACE}:3001"
REPO_URL="${GITEA_SERVICE_URL}/student/hedgehog-config.git"
REPO_PATH="active"  # ArgoCD watches the active/ directory
REPO_BRANCH="main"

# ArgoCD Application name
APP_NAME="hedgehog-fabric"

LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/argocd-app.log}"
ARGOCD_APP_TIMEOUT="${ARGOCD_APP_TIMEOUT:-600}"  # 10 minutes

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

    # Check if VLAB is initialized
    if [ ! -f "/var/lib/hedgehog-lab/vlab-initialized" ]; then
        log_error "VLAB not initialized. This module requires VLAB to complete first."
        return 1
    fi

    log_info "VLAB initialization confirmed"

    # Switch to k3d-observability context
    if ! kubectl config use-context k3d-k3d-observability >> "$LOG_FILE" 2>&1; then
        log_error "Failed to switch to k3d-observability context"
        return 1
    fi

    # Check if ArgoCD is running
    if ! kubectl get namespace "$ARGOCD_NAMESPACE" &> /dev/null; then
        log_error "ArgoCD namespace not found"
        return 1
    fi

    log_info "Prerequisites check passed"
    return 0
}

# Wait for ArgoCD CRDs and controllers to be ready
wait_for_argocd_ready() {
    log_info "Waiting for ArgoCD CRDs and controllers to be ready..."

    local max_wait=300  # 5 minutes
    local elapsed=0
    local check_interval=5

    # First, wait for the Application CRD to be established
    log_info "Waiting for Application CRD to be registered..."
    while [ $elapsed -lt $max_wait ]; do
        if kubectl get crd applications.argoproj.io &> /dev/null; then
            log_info "Application CRD is registered"
            break
        fi

        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))

        if [ $((elapsed % 30)) -eq 0 ]; then
            log_info "Still waiting for Application CRD... (${elapsed}s elapsed)"
        fi
    done

    if [ $elapsed -ge $max_wait ]; then
        log_error "Application CRD not available after ${max_wait}s"
        return 1
    fi

    # Wait for ArgoCD pods to be ready
    log_info "Waiting for ArgoCD pods to be ready..."
    elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        # Check if application-controller is ready
        local controller_ready
        controller_ready=$(kubectl get pods -n "$ARGOCD_NAMESPACE" \
            -l app.kubernetes.io/name=argocd-application-controller \
            -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")

        # Check if server is ready
        local server_ready
        server_ready=$(kubectl get pods -n "$ARGOCD_NAMESPACE" \
            -l app.kubernetes.io/name=argocd-server \
            -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")

        if [ "$controller_ready" = "True" ] && [ "$server_ready" = "True" ]; then
            log_info "ArgoCD controllers are ready"
            return 0
        fi

        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))

        if [ $((elapsed % 30)) -eq 0 ]; then
            log_info "Still waiting for ArgoCD pods... (${elapsed}s elapsed)"
        fi
    done

    log_error "ArgoCD pods not ready after ${max_wait}s"
    return 1
}

# Wait for Hedgehog controller API to be accessible
wait_for_hedgehog_api() {
    log_info "Waiting for Hedgehog controller API to be accessible..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Try to reach the API server (will fail TLS but that's okay, we just need connectivity)
        if curl -sk --connect-timeout 2 "${HEDGEHOG_API_SERVER}/healthz" &> /dev/null; then
            log_info "Hedgehog controller API is accessible at ${HEDGEHOG_API_SERVER}"
            return 0
        fi

        sleep 5
        ((attempt++))

        if [ $((attempt % 12)) -eq 0 ]; then
            log_info "Still waiting for Hedgehog API... (${attempt}/${max_attempts})"
        fi
    done

    log_error "Hedgehog controller API not accessible after ${max_attempts} attempts"
    return 1
}

# Get Hedgehog kubeconfig
get_hedgehog_kubeconfig() {
    log_info "Retrieving Hedgehog controller kubeconfig..."

    # The VLAB kubeconfig should be available at the standard location
    local vlab_kubeconfig="/home/hhlab/.hhfab/vlab/kubeconfig"

    if [ ! -f "$vlab_kubeconfig" ]; then
        log_error "VLAB kubeconfig not found at $vlab_kubeconfig"
        return 1
    fi

    # Read the kubeconfig
    HEDGEHOG_KUBECONFIG=$(cat "$vlab_kubeconfig")

    if [ -z "$HEDGEHOG_KUBECONFIG" ]; then
        log_error "Failed to read VLAB kubeconfig"
        return 1
    fi

    log_info "Retrieved Hedgehog kubeconfig"
    return 0
}

# Create ArgoCD cluster secret for Hedgehog controller
create_cluster_secret() {
    log_info "Creating ArgoCD cluster secret for Hedgehog controller..."

    # Check if secret already exists
    if kubectl get secret -n "$ARGOCD_NAMESPACE" "cluster-${HEDGEHOG_CLUSTER_NAME}" &> /dev/null; then
        log_info "Cluster secret already exists, updating..."
        kubectl delete secret -n "$ARGOCD_NAMESPACE" "cluster-${HEDGEHOG_CLUSTER_NAME}" >> "$LOG_FILE" 2>&1
    fi

    # Extract certificate and token from kubeconfig using yq/jq
    # For VLAB, we need to use the kubeconfig but allow insecure TLS
    # because the certificate doesn't include the Docker bridge IP (172.19.0.1)

    # Create / refresh serviceaccount token for Argo to talk to the controller cluster
    local bearer_token
    if ! bearer_token=$(KUBECONFIG="$vlab_kubeconfig" kubectl -n kube-system create token argocd-manager 2>/dev/null); then
        log_error "Failed to create service account token (argocd-manager)"
        return 1
    fi

    log_info "Generated service account token for ArgoCD cluster secret"

    # Create cluster secret with ArgoCD labels
    # ArgoCD expects the 'config' field to contain connection configuration (not the full kubeconfig)
    # and uses the 'name' and 'server' fields from stringData
    cat <<EOF | kubectl apply -f - >> "$LOG_FILE" 2>&1
apiVersion: v1
kind: Secret
metadata:
  name: cluster-${HEDGEHOG_CLUSTER_NAME}
  namespace: ${ARGOCD_NAMESPACE}
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: ${HEDGEHOG_CLUSTER_NAME}
  server: ${HEDGEHOG_API_SERVER}
  config: |
    {
      "bearerToken": "${bearer_token}",
      "tlsClientConfig": {
        "insecure": true
      }
    }
EOF

    if [ $? -eq 0 ]; then
        log_info "Created ArgoCD cluster secret for Hedgehog controller"
        return 0
    else
        log_error "Failed to create cluster secret"
        return 1
    fi
}

# Create ArgoCD Application
create_argocd_application() {
    log_info "Creating ArgoCD Application for hedgehog-fabric..."

    # Check if application already exists
    if kubectl get application -n "$ARGOCD_NAMESPACE" "$APP_NAME" &> /dev/null; then
        log_info "ArgoCD Application '${APP_NAME}' already exists"
        return 0
    fi

    # Create Application manifest
    cat <<EOF | kubectl apply -f - >> "$LOG_FILE" 2>&1
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${APP_NAME}
  namespace: ${ARGOCD_NAMESPACE}
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default

  # Source: Gitea repository
  source:
    repoURL: ${REPO_URL}
    targetRevision: ${REPO_BRANCH}
    path: ${REPO_PATH}

  # Destination: Hedgehog controller cluster
  destination:
    server: ${HEDGEHOG_API_SERVER}
    namespace: default

  # Sync policy: automated with self-heal
  syncPolicy:
    automated:
      prune: true       # Remove resources when deleted from Git
      selfHeal: true    # Force sync when cluster state drifts
      allowEmpty: false # Don't sync if path is empty
    syncOptions:
      - CreateNamespace=true
      - PruneLast=true  # Prune as last step
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m

  # Ignore differences in certain fields (common for managed resources)
  ignoreDifferences:
    - group: "*"
      kind: "*"
      jsonPointers:
        - /status
EOF

    if [ $? -eq 0 ]; then
        log_info "Created ArgoCD Application '${APP_NAME}'"
        return 0
    else
        log_error "Failed to create ArgoCD Application"
        return 1
    fi
}

# Wait for initial sync
wait_for_initial_sync() {
    log_info "Waiting for initial ArgoCD sync..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        local sync_status
        sync_status=$(kubectl get application -n "$ARGOCD_NAMESPACE" "$APP_NAME" \
            -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")

        local health_status
        health_status=$(kubectl get application -n "$ARGOCD_NAMESPACE" "$APP_NAME" \
            -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")

        log_debug "Sync status: ${sync_status}, Health status: ${health_status}"

        # Check if synced (even if active/ directory is empty, it should show Synced)
        if [ "$sync_status" = "Synced" ]; then
            log_info "ArgoCD Application synced successfully"
            log_info "Health status: ${health_status}"
            return 0
        fi

        sleep 5
        ((attempt++))

        if [ $((attempt % 12)) -eq 0 ]; then
            log_info "Still waiting for sync... (${attempt}/${max_attempts})"
        fi
    done

    log_warn "Initial sync did not complete within timeout"
    log_warn "This may be normal if the active/ directory is empty"
    log_warn "Check ArgoCD UI for details: http://localhost:8080"
    return 0  # Don't fail - empty repo is valid
}

# Verify application status
verify_application() {
    log_info "Verifying ArgoCD Application status..."

    # Get application details
    local app_info
    app_info=$(kubectl get application -n "$ARGOCD_NAMESPACE" "$APP_NAME" -o json 2>/dev/null)

    if [ -z "$app_info" ]; then
        log_error "Failed to retrieve Application information"
        return 1
    fi

    local sync_status
    sync_status=$(echo "$app_info" | grep -o '"sync":{"status":"[^"]*"' | cut -d'"' -f6)

    local health_status
    health_status=$(echo "$app_info" | grep -o '"health":{"status":"[^"]*"' | cut -d'"' -f6)

    local repo_url
    repo_url=$(echo "$app_info" | grep -o '"repoURL":"[^"]*"' | cut -d'"' -f4)

    log_info "Application verification:"
    log_info "  Sync Status: ${sync_status:-Unknown}"
    log_info "  Health Status: ${health_status:-Unknown}"
    log_info "  Repository: ${repo_url:-Unknown}"

    return 0
}

# Get application summary
get_application_summary() {
    log_info ""
    log_info "ArgoCD Application Summary:"
    log_info "  Application Name: ${APP_NAME}"
    log_info "  Namespace: ${ARGOCD_NAMESPACE}"
    log_info "  Source Repository: ${REPO_URL}"
    log_info "  Source Path: ${REPO_PATH}"
    log_info "  Source Branch: ${REPO_BRANCH}"
    log_info "  Destination Cluster: ${HEDGEHOG_CLUSTER_NAME}"
    log_info "  Destination Server: ${HEDGEHOG_API_SERVER}"
    log_info "  Destination Namespace: default"
    log_info ""
    log_info "Access ArgoCD UI:"
    log_info "  URL: http://localhost:8080"
    log_info "  Username: admin"
    log_info "  Password: (retrieve with: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)"
    log_info ""
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "ArgoCD Application Initialization Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${ARGOCD_APP_TIMEOUT}s ($(( ARGOCD_APP_TIMEOUT / 60 )) minutes)"
    log_info ""

    local overall_start
    overall_start=$(date +%s)

    # Execute initialization steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! wait_for_argocd_ready; then
        log_error "ArgoCD CRDs and controllers not ready"
        return 1
    fi

    if ! wait_for_hedgehog_api; then
        log_error "Hedgehog controller API not accessible"
        return 1
    fi

    if ! get_hedgehog_kubeconfig; then
        log_error "Failed to retrieve Hedgehog kubeconfig"
        return 1
    fi

    if ! create_cluster_secret; then
        log_error "Failed to create cluster secret"
        return 1
    fi

    if ! create_argocd_application; then
        log_error "Failed to create ArgoCD Application"
        return 1
    fi

    if ! wait_for_initial_sync; then
        log_warn "Initial sync check incomplete (non-fatal)"
    fi

    if ! verify_application; then
        log_error "Failed to verify Application"
        return 1
    fi

    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    get_application_summary

    log_info ""
    log_info "=================================================="
    log_info "ArgoCD Application Initialization Complete!"
    log_info "=================================================="
    log_info "Total initialization time: ${total_time}s"
    log_info "GitOps workflow is ready"
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
    # Validate that ArgoCD Application exists
    kubectl config use-context k3d-k3d-observability &> /dev/null
    kubectl get application -n "$ARGOCD_NAMESPACE" "$APP_NAME" &> /dev/null
}

module_cleanup() {
    log_info "No cleanup required"
}

module_get_metadata() {
    cat <<EOF
{
  "name": "$MODULE_NAME",
  "description": "$MODULE_DESCRIPTION",
  "version": "$MODULE_VERSION",
  "timeout": $ARGOCD_APP_TIMEOUT,
  "dependencies": ["vlab", "k3d", "argocd", "gitea", "gitops-repo"]
}
EOF
}
