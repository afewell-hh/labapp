#!/bin/bash
# 20-k3d-observability-init.sh
# K3d Observability Cluster Initialization Module for Hedgehog Lab Appliance
# Initializes k3d-observability cluster with monitoring and GitOps stack
#
# This module:
# - Creates k3d-observability cluster with correct ports
# - Installs kube-prometheus-stack via Helm
# - Installs ArgoCD
# - Installs Gitea
# - Configures Grafana dashboards
# - Verifies all pods running

set -euo pipefail

# Module metadata
MODULE_NAME="k3d-observability"
MODULE_DESCRIPTION="Initialize k3d observability cluster"
MODULE_VERSION="1.0.0"

# Configuration
K3D_CLUSTER_NAME="${K3D_CLUSTER_NAME:-k3d-observability}"
K3D_TIMEOUT="${K3D_TIMEOUT:-900}"  # 15 minutes in seconds
K3D_READY_TIMEOUT="${K3D_READY_TIMEOUT:-300}"  # 5 minutes for cluster ready
POD_READY_TIMEOUT="${POD_READY_TIMEOUT:-600}"  # 10 minutes for all pods ready
LOG_FILE="${LOG_FILE:-/var/log/hedgehog-lab/modules/k3d.log}"

# Port mappings for services
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
ARGOCD_HTTP_PORT="${ARGOCD_HTTP_PORT:-8080}"
ARGOCD_HTTPS_PORT="${ARGOCD_HTTPS_PORT:-8443}"
GITEA_HTTP_PORT="${GITEA_HTTP_PORT:-3001}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"

# Helm chart versions
PROMETHEUS_STACK_CHART_VERSION="${PROMETHEUS_STACK_CHART_VERSION:-65.2.0}"
ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-7.6.12}"
GITEA_CHART_VERSION="${GITEA_CHART_VERSION:-10.4.1}"

# Namespaces
PROMETHEUS_NAMESPACE="monitoring"
ARGOCD_NAMESPACE="argocd"
GITEA_NAMESPACE="gitea"

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for k3d
    if ! command -v k3d &> /dev/null; then
        log_error "k3d command not found. Cannot create cluster."
        return 1
    fi
    local k3d_version
    k3d_version=$(k3d version | grep k3d | awk '{print $3}')
    log_info "Found k3d version: $k3d_version"

    # Check for kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl command not found. Cannot manage cluster."
        return 1
    fi
    local kubectl_version
    kubectl_version=$(kubectl version --client --short 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    log_info "Found kubectl version: $kubectl_version"

    # Check for helm
    if ! command -v helm &> /dev/null; then
        log_error "helm command not found. Cannot deploy charts."
        return 1
    fi
    local helm_version
    helm_version=$(helm version --short 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    log_info "Found helm version: $helm_version"

    # Check for Docker
    if ! command -v docker &> /dev/null; then
        log_error "docker command not found. k3d requires Docker."
        return 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running."
        return 1
    fi
    log_info "Docker daemon is running"

    log_info "All prerequisites satisfied"
    return 0
}

# Create k3d cluster
create_k3d_cluster() {
    log_info "Creating k3d cluster: $K3D_CLUSTER_NAME..."

    # Check if cluster already exists
    if k3d cluster list | grep -q "$K3D_CLUSTER_NAME"; then
        log_info "Cluster $K3D_CLUSTER_NAME already exists"

        # Verify it's running
        if k3d cluster list | grep "$K3D_CLUSTER_NAME" | grep -q "running"; then
            log_info "Cluster is already running, skipping creation"
            return 0
        else
            log_warn "Cluster exists but not running, deleting and recreating..."
            k3d cluster delete "$K3D_CLUSTER_NAME" >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # Create cluster with port mappings
    log_info "Creating k3d cluster with port mappings..."
    log_info "  Grafana: localhost:${GRAFANA_PORT}"
    log_info "  Prometheus (remote_write + UI): localhost:${PROMETHEUS_PORT}"
    log_info "  ArgoCD HTTP: localhost:${ARGOCD_HTTP_PORT}"
    log_info "  ArgoCD HTTPS: localhost:${ARGOCD_HTTPS_PORT}"
    log_info "  Gitea HTTP: localhost:${GITEA_HTTP_PORT}"
    log_info "  Gitea SSH: localhost:${GITEA_SSH_PORT}"

    if ! k3d cluster create "$K3D_CLUSTER_NAME" \
        --api-port 6550 \
        --port "${GRAFANA_PORT}:${GRAFANA_PORT}@loadbalancer" \
        --port "${PROMETHEUS_PORT}:${PROMETHEUS_PORT}@loadbalancer" \
        --port "${ARGOCD_HTTP_PORT}:${ARGOCD_HTTP_PORT}@loadbalancer" \
        --port "${ARGOCD_HTTPS_PORT}:${ARGOCD_HTTPS_PORT}@loadbalancer" \
        --port "${GITEA_HTTP_PORT}:${GITEA_HTTP_PORT}@loadbalancer" \
        --port "${GITEA_SSH_PORT}:${GITEA_SSH_PORT}@loadbalancer" \
        --agents 2 \
        --wait >> "$LOG_FILE" 2>&1; then
        log_error "Failed to create k3d cluster"
        return 1
    fi

    log_info "k3d cluster created successfully"
    return 0
}

# Wait for cluster to be ready
wait_for_cluster_ready() {
    log_info "Waiting for cluster to be ready..."

    local start_time
    start_time=$(date +%s)
    local end_time
    end_time=$((start_time + K3D_READY_TIMEOUT))

    # Set kubeconfig context
    if ! k3d kubeconfig merge "$K3D_CLUSTER_NAME" --kubeconfig-switch-context >> "$LOG_FILE" 2>&1; then
        log_error "Failed to set kubeconfig context"
        return 1
    fi

    # Wait for cluster to be responsive
    while [ "$(date +%s)" -lt "$end_time" ]; do
        if kubectl cluster-info &> /dev/null; then
            log_info "Cluster API server is responsive"

            # Wait for system pods to be ready
            if kubectl wait --for=condition=ready pods --all -n kube-system --timeout=60s >> "$LOG_FILE" 2>&1; then
                log_info "All kube-system pods are ready"
                return 0
            fi
        fi

        log_debug "Waiting for cluster to be ready..."
        sleep 5
    done

    log_error "Cluster failed to become ready within ${K3D_READY_TIMEOUT} seconds"
    return 1
}

# Add Helm repositories
add_helm_repositories() {
    log_info "Adding Helm repositories..."

    # Add Prometheus Community repo (use --force-update for idempotency)
    if ! helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >> "$LOG_FILE" 2>&1; then
        log_error "Failed to add prometheus-community Helm repository"
        return 1
    fi
    log_info "Added/updated prometheus-community Helm repository"

    # Add ArgoCD repo (use --force-update for idempotency)
    if ! helm repo add argo https://argoproj.github.io/argo-helm --force-update >> "$LOG_FILE" 2>&1; then
        log_error "Failed to add argo Helm repository"
        return 1
    fi
    log_info "Added/updated argo Helm repository"

    # Add Gitea repo (use --force-update for idempotency)
    if ! helm repo add gitea-charts https://dl.gitea.com/charts/ --force-update >> "$LOG_FILE" 2>&1; then
        log_error "Failed to add gitea-charts Helm repository"
        return 1
    fi
    log_info "Added/updated gitea-charts Helm repository"

    # Update repositories
    if ! helm repo update >> "$LOG_FILE" 2>&1; then
        log_error "Failed to update Helm repositories"
        return 1
    fi
    log_info "Helm repositories updated"

    return 0
}

# Install kube-prometheus-stack
install_kube_prometheus_stack() {
    log_info "Installing kube-prometheus-stack..."

    # Create namespace
    if ! kubectl create namespace "$PROMETHEUS_NAMESPACE" >> "$LOG_FILE" 2>&1; then
        if kubectl get namespace "$PROMETHEUS_NAMESPACE" &> /dev/null; then
            log_info "Namespace $PROMETHEUS_NAMESPACE already exists"
        else
            log_error "Failed to create namespace $PROMETHEUS_NAMESPACE"
            return 1
        fi
    else
        log_info "Created namespace $PROMETHEUS_NAMESPACE"
    fi

    # Create values file for kube-prometheus-stack
    cat > /tmp/prometheus-values.yaml <<EOF
# Grafana configuration
grafana:
  enabled: true
  adminPassword: admin
  service:
    type: LoadBalancer
    port: ${GRAFANA_PORT}
  persistence:
    enabled: true
    size: 10Gi

# Prometheus configuration
prometheus:
  service:
    type: LoadBalancer
    port: ${PROMETHEUS_PORT}
    targetPort: ${PROMETHEUS_PORT}
  prometheusSpec:
    # Enable remote write receiver for Alloy telemetry
    enableRemoteWriteReceiver: true
    retention: 7d
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
      limits:
        cpu: 2000m
        memory: 4Gi

    # Additional scrape configs for Hedgehog fabric-proxy
    # This will be populated after VLAB initialization
    additionalScrapeConfigs: []

# Alert manager configuration
alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 10Gi

# Disable components we don't need for lab environment
kubeStateMetrics:
  enabled: true
nodeExporter:
  enabled: true
prometheusOperator:
  enabled: true
EOF

    # Install/upgrade chart (idempotent)
    log_info "Installing/upgrading kube-prometheus-stack chart (version: ${PROMETHEUS_STACK_CHART_VERSION})..."
    if ! helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace "$PROMETHEUS_NAMESPACE" \
        --create-namespace \
        --version "$PROMETHEUS_STACK_CHART_VERSION" \
        --values /tmp/prometheus-values.yaml \
        --wait \
        --timeout 10m >> "$LOG_FILE" 2>&1; then
        log_error "Failed to install/upgrade kube-prometheus-stack"
        rm -f /tmp/prometheus-values.yaml
        return 1
    fi

    rm -f /tmp/prometheus-values.yaml
    log_info "kube-prometheus-stack installed/upgraded successfully"
    return 0
}

# Install ArgoCD
install_argocd() {
    log_info "Installing ArgoCD..."

    # Create namespace
    if ! kubectl create namespace "$ARGOCD_NAMESPACE" >> "$LOG_FILE" 2>&1; then
        if kubectl get namespace "$ARGOCD_NAMESPACE" &> /dev/null; then
            log_info "Namespace $ARGOCD_NAMESPACE already exists"
        else
            log_error "Failed to create namespace $ARGOCD_NAMESPACE"
            return 1
        fi
    else
        log_info "Created namespace $ARGOCD_NAMESPACE"
    fi

    # Create values file for ArgoCD
    cat > /tmp/argocd-values.yaml <<EOF
# Server configuration
server:
  service:
    type: LoadBalancer
    servicePortHttp: ${ARGOCD_HTTP_PORT}
    servicePortHttps: ${ARGOCD_HTTPS_PORT}

  # Insecure mode for lab environment (no TLS required)
  extraArgs:
    - --insecure

# Redis for caching
redis:
  enabled: true

# Disable Dex (OAuth) for lab environment
dex:
  enabled: false

# Application controller
controller:
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 2000m
      memory: 2Gi

# Repo server
repoServer:
  resources:
    requests:
      cpu: 250m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
EOF

    # Install/upgrade chart (idempotent)
    log_info "Installing/upgrading ArgoCD chart (version: ${ARGOCD_CHART_VERSION})..."
    if ! helm upgrade --install argocd argo/argo-cd \
        --namespace "$ARGOCD_NAMESPACE" \
        --create-namespace \
        --version "$ARGOCD_CHART_VERSION" \
        --values /tmp/argocd-values.yaml \
        --wait \
        --timeout 10m >> "$LOG_FILE" 2>&1; then
        log_error "Failed to install/upgrade ArgoCD"
        rm -f /tmp/argocd-values.yaml
        return 1
    fi

    rm -f /tmp/argocd-values.yaml
    log_info "ArgoCD installed/upgraded successfully"

    # Get initial admin password
    log_info "Retrieving ArgoCD admin password..."
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if kubectl -n "$ARGOCD_NAMESPACE" get secret argocd-initial-admin-secret &> /dev/null; then
            local argocd_password
            argocd_password=$(kubectl -n "$ARGOCD_NAMESPACE" get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
            log_info "ArgoCD admin password: $argocd_password"
            log_info "ArgoCD admin username: admin"
            break
        fi
        sleep 2
        ((attempt++))
    done

    return 0
}

# Install Gitea
install_gitea() {
    log_info "Installing Gitea..."

    # Create namespace
    if ! kubectl create namespace "$GITEA_NAMESPACE" >> "$LOG_FILE" 2>&1; then
        if kubectl get namespace "$GITEA_NAMESPACE" &> /dev/null; then
            log_info "Namespace $GITEA_NAMESPACE already exists"
        else
            log_error "Failed to create namespace $GITEA_NAMESPACE"
            return 1
        fi
    else
        log_info "Created namespace $GITEA_NAMESPACE"
    fi

    # Create values file for Gitea
    cat > /tmp/gitea-values.yaml <<EOF
# Service configuration
service:
  http:
    type: LoadBalancer
    port: ${GITEA_HTTP_PORT}
  ssh:
    type: LoadBalancer
    port: ${GITEA_SSH_PORT}

# Gitea configuration
gitea:
  admin:
    username: gitea_admin
    password: admin123
    email: admin@gitea.local

  config:
    server:
      DOMAIN: localhost
      ROOT_URL: http://localhost:${GITEA_HTTP_PORT}
      SSH_DOMAIN: localhost
      SSH_PORT: ${GITEA_SSH_PORT}

    database:
      DB_TYPE: sqlite3

    security:
      INSTALL_LOCK: true

    service:
      DISABLE_REGISTRATION: false
      REQUIRE_SIGNIN_VIEW: false

# Persistence
persistence:
  enabled: true
  size: 10Gi

# PostgreSQL (disabled, using SQLite for simplicity)
postgresql:
  enabled: false

# Disable bundled HA postgres/redis components to reduce resource usage
postgresql-ha:
  enabled: false

valkey-cluster:
  enabled: false

redis-cluster:
  enabled: false
EOF

    # Install/upgrade chart (idempotent)
    log_info "Installing/upgrading Gitea chart (version: ${GITEA_CHART_VERSION})..."
    if ! helm upgrade --install gitea gitea-charts/gitea \
        --namespace "$GITEA_NAMESPACE" \
        --create-namespace \
        --version "$GITEA_CHART_VERSION" \
        --values /tmp/gitea-values.yaml \
        --wait \
        --timeout 20m >> "$LOG_FILE" 2>&1; then
        log_error "Failed to install/upgrade Gitea"
        rm -f /tmp/gitea-values.yaml
        return 1
    fi

    rm -f /tmp/gitea-values.yaml
    log_info "Waiting for Gitea deployment to become ready..."
    if ! kubectl rollout status deployment/gitea -n "$GITEA_NAMESPACE" --timeout=600s >> "$LOG_FILE" 2>&1; then
        log_error "Gitea deployment failed to become ready"
        return 1
    fi

    log_info "Gitea installed/upgraded successfully"
    log_info "Gitea admin username: gitea_admin"
    log_info "Gitea admin password: admin123"

    return 0
}

# Configure Grafana dashboards
configure_grafana_dashboards() {
    log_info "Configuring Grafana dashboards..."

    # Wait for Grafana to be ready
    log_info "Waiting for Grafana pod to be ready..."
    if ! kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/name=grafana" \
        -n "$PROMETHEUS_NAMESPACE" \
        --timeout=300s >> "$LOG_FILE" 2>&1; then
        log_warn "Grafana pod readiness check timed out, continuing anyway..."
    fi

    # The kube-prometheus-stack already includes many useful dashboards
    # They are automatically configured via the Grafana sidecar
    log_info "Grafana dashboards are automatically configured by kube-prometheus-stack"
    log_info "Default dashboards include:"
    log_info "  - Kubernetes cluster monitoring"
    log_info "  - Node exporter metrics"
    log_info "  - Prometheus stats"
    log_info "  - AlertManager overview"

    return 0
}

# Verify all pods are running
verify_pods_running() {
    log_info "Verifying all pods are running..."

    local namespaces=("$PROMETHEUS_NAMESPACE" "$ARGOCD_NAMESPACE" "$GITEA_NAMESPACE")
    local all_ready=true

    for ns in "${namespaces[@]}"; do
        log_info "Checking namespace: $ns"

        # Get pod status
        local not_ready
        not_ready=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -v "Running\|Completed" | wc -l)

        if [ "$not_ready" -gt 0 ]; then
            log_warn "Found $not_ready pods not in Running/Completed state in namespace $ns"
            kubectl get pods -n "$ns" | tee -a "$LOG_FILE"
            all_ready=false
        else
            local pod_count
            pod_count=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
            log_info "All $pod_count pods in namespace $ns are ready"
        fi
    done

    if [ "$all_ready" = false ]; then
        log_warn "Some pods are not ready, but continuing..."
        # Not failing here as pods may still be starting up
    fi

    return 0
}

# Get cluster status summary
get_cluster_status() {
    log_info "K3d Cluster Status Summary:"
    log_info "  Cluster name: $K3D_CLUSTER_NAME"
    log_info "  Kubeconfig context: k3d-$K3D_CLUSTER_NAME"
    log_info ""
    log_info "Installed Components:"
    log_info "  - kube-prometheus-stack (namespace: $PROMETHEUS_NAMESPACE)"
    log_info "    Grafana: http://localhost:${GRAFANA_PORT} (admin/admin)"
    log_info "  - ArgoCD (namespace: $ARGOCD_NAMESPACE)"
    log_info "    UI: http://localhost:${ARGOCD_HTTP_PORT}"
    log_info "  - Gitea (namespace: $GITEA_NAMESPACE)"
    log_info "    HTTP: http://localhost:${GITEA_HTTP_PORT}"
    log_info "    SSH: localhost:${GITEA_SSH_PORT}"
    log_info ""

    # Get node info
    log_info "Cluster Nodes:"
    kubectl get nodes 2>&1 | tee -a "$LOG_FILE"

    return 0
}

# Cleanup function for error conditions
cleanup_on_error() {
    log_warn "Performing cleanup after error..."

    # We don't destroy the cluster on error to allow for debugging
    log_info "k3d cluster left running for debugging. To cleanup manually:"
    log_info "  k3d cluster delete $K3D_CLUSTER_NAME"

    return 0
}

# Main execution function
main() {
    log_info "=================================================="
    log_info "k3d Observability Cluster Initialization Starting..."
    log_info "=================================================="
    log_info "Module: $MODULE_NAME v$MODULE_VERSION"
    log_info "Description: $MODULE_DESCRIPTION"
    log_info "Timeout: ${K3D_TIMEOUT}s ($(( K3D_TIMEOUT / 60 )) minutes)"
    log_info ""

    # Track overall start time
    local overall_start
    overall_start=$(date +%s)

    # Execute initialization steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        return 1
    fi

    if ! create_k3d_cluster; then
        log_error "k3d cluster creation failed"
        cleanup_on_error
        return 1
    fi

    if ! wait_for_cluster_ready; then
        log_error "Cluster readiness check failed"
        cleanup_on_error
        return 1
    fi

    if ! add_helm_repositories; then
        log_error "Helm repository setup failed"
        cleanup_on_error
        return 1
    fi

    if ! install_kube_prometheus_stack; then
        log_error "kube-prometheus-stack installation failed"
        cleanup_on_error
        return 1
    fi

    if ! install_argocd; then
        log_error "ArgoCD installation failed"
        cleanup_on_error
        return 1
    fi

    if ! install_gitea; then
        log_error "Gitea installation failed"
        cleanup_on_error
        return 1
    fi

    if ! configure_grafana_dashboards; then
        log_error "Grafana dashboard configuration failed"
        # Don't fail here - dashboards are already configured by stack
    fi

    if ! verify_pods_running; then
        log_error "Pod verification failed"
        # Don't fail here - pods may still be starting
    fi

    # Calculate total time
    local overall_end
    overall_end=$(date +%s)
    local total_time
    total_time=$((overall_end - overall_start))

    # Display status summary
    get_cluster_status

    log_info ""
    log_info "=================================================="
    log_info "k3d Observability Cluster Initialization Complete!"
    log_info "=================================================="
    log_info "Total initialization time: ${total_time}s ($(( total_time / 60 )) minutes)"
    log_info "Cluster is ready for use"
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
    # Validate that k3d cluster is running
    if k3d cluster list | grep "$K3D_CLUSTER_NAME" | grep -q "running"; then
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
  "timeout": $K3D_TIMEOUT,
  "dependencies": ["network", "docker"]
}
EOF
}
