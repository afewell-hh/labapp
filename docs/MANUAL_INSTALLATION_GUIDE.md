# Hedgehog Lab Manual Installation Guide

This document provides complete step-by-step instructions for manually setting up a Hedgehog Lab environment on Ubuntu 24.04 LTS. This guide consolidates all learnings from issues #96 and #97 and the existing automation scripts.

## Table of Contents

1. [Prerequisites and Requirements](#1-prerequisites-and-requirements)
2. [Phase 1: Base System Setup](#2-phase-1-base-system-setup)
3. [Phase 2: Install k3d](#3-phase-2-install-k3d)
4. [Phase 3: Install hhfab](#4-phase-3-install-hhfab)
5. [Phase 4: Install Kubernetes Tools](#5-phase-4-install-kubernetes-tools)
6. [Phase 5: GHCR Authentication](#6-phase-5-ghcr-authentication)
7. [Phase 6: Initialize k3d Observability Cluster (EMC)](#7-phase-6-initialize-k3d-observability-cluster-emc)
8. [Phase 7: Initialize VLAB](#8-phase-7-initialize-vlab)
9. [Phase 8: Initialize GitOps (Gitea Repository)](#9-phase-8-initialize-gitops-gitea-repository)
10. [Phase 9: Configure ArgoCD Application](#10-phase-9-configure-argocd-application)
11. [Phase 10: Verify Prometheus Metrics](#11-phase-10-verify-prometheus-metrics)
12. [Validation and Verification](#12-validation-and-verification)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Prerequisites and Requirements

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| vCPUs | 32 | 32+ |
| RAM | 100 GB | 128 GB |
| Disk | 350 GB | 400+ GB |
| Nested Virtualization | Required (VMX or SVM) | Required |

### Software Requirements

- **OS**: Ubuntu 24.04 LTS Server
- **GHCR Credentials**: GitHub Personal Access Token with `read:packages` scope

### Preflight Checks

Run these commands to validate your system:

```bash
# Check OS version
lsb_release -d
# Expected: Ubuntu 24.04 LTS

# Check nested virtualization
grep -Eq 'vmx|svm' /proc/cpuinfo && echo "Nested virt: OK" || echo "Nested virt: MISSING"

# Check resources
echo "CPUs: $(nproc)"
echo "RAM: $(free -g | awk '/^Mem:/ {print $2}') GB"
echo "Disk: $(df -BG / | awk 'NR==2 {gsub("G","",$4); print $4}') GB free"
```

---

## 2. Phase 1: Base System Setup

### 2.1 Create Lab User

```bash
# Create hhlab user with password (password: hhlab)
sudo useradd -m -s /bin/bash hhlab
echo "hhlab:hhlab" | sudo chpasswd
sudo usermod -aG sudo hhlab

# Configure passwordless sudo (required for hhfab setup-taps)
echo 'hhlab ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/hhlab
sudo chmod 440 /etc/sudoers.d/hhlab
```

### 2.2 Update System and Install Base Packages

```bash
# Update package lists
sudo apt-get update

# Upgrade existing packages
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential packages
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    curl \
    wget \
    git \
    vim \
    nano \
    jq \
    unzip \
    zip \
    tar \
    gzip \
    net-tools \
    dnsutils \
    iputils-ping \
    traceroute \
    tcpdump \
    htop \
    iotop \
    iftop \
    tmux \
    screen \
    tree \
    rsync \
    nfs-common \
    open-iscsi \
    sudo \
    systemd \
    systemd-sysv
```

### 2.3 Install Virtualization Support

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-guest-agent \
    linux-tools-virtual \
    linux-cloud-tools-virtual \
    qemu-utils \
    qemu-system-x86 \
    socat
```

### 2.4 Install Docker

```bash
# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Add hhlab to docker group
sudo usermod -aG docker hhlab

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker
```

### 2.5 Install Python

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Install Python packages (needed for fab.yaml patching)
pip3 install --break-system-packages pyyaml requests jinja2
```

### 2.6 Expand Root Filesystem (if using LVM)

```bash
if lsblk /dev/ubuntu-vg/ubuntu-lv &>/dev/null; then
    sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv || echo "LV already at max"
    sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
fi
```

### 2.7 Configure System Memory Optimizations

```bash
cat << 'EOF' | sudo tee /etc/sysctl.d/99-hedgehog-lab.conf
# Memory optimizations for lab environment
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF

sudo sysctl --system
```

---

## 3. Phase 2: Install k3d

```bash
# Install k3d v5.7.4
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | TAG=v5.7.4 bash

# Verify installation
k3d version

# Create configuration directory
sudo mkdir -p /etc/hedgehog-lab/k3d
sudo chown -R hhlab:hhlab /etc/hedgehog-lab
```

---

## 4. Phase 3: Install hhfab

### 4.1 Install Go

```bash
GO_VERSION="1.23.2"
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm go${GO_VERSION}.linux-amd64.tar.gz

# Add Go to PATH
cat << 'EOF' | sudo tee /etc/profile.d/golang.sh
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
EOF

source /etc/profile.d/golang.sh
```

### 4.2 Install oras CLI (required by hhfab)

```bash
curl -fsSL https://i.hhdev.io/oras | bash
```

### 4.3 Create hhfab Directories

```bash
sudo mkdir -p /opt/hedgehog
sudo mkdir -p /etc/hedgehog-lab/vlab
sudo chown -R hhlab:hhlab /opt/hedgehog
sudo chown -R hhlab:hhlab /etc/hedgehog-lab
```

---

## 5. Phase 4: Install Kubernetes Tools

```bash
# Create temp directory
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Define versions
KUBECTL_VERSION="v1.31.1"
KIND_VERSION="v0.24.0"
ARGOCD_VERSION="v2.12.4"
K9S_VERSION="v0.32.5"
STERN_VERSION="1.30.0"
YQ_VERSION="v4.44.3"

# Download tools in parallel
curl -sSL -o kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" &
curl -sSL -o kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64" &
curl -sSL -o argocd "https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-linux-amd64" &
curl -sSL -o k9s.tar.gz "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz" &
curl -sSL -o stern.tar.gz "https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_amd64.tar.gz" &
curl -sSL -o yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" &
wait

# Install kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install Helm
curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install kind
chmod +x kind
sudo mv kind /usr/local/bin/

# Install ArgoCD CLI
chmod +x argocd
sudo mv argocd /usr/local/bin/

# Install kustomize
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
sudo mv kustomize /usr/local/bin/

# Install kubectx and kubens
sudo rm -rf /opt/kubectx
sudo git clone --depth 1 https://github.com/ahmetb/kubectx /opt/kubectx
sudo ln -sf /opt/kubectx/kubectx /usr/local/bin/kubectx
sudo ln -sf /opt/kubectx/kubens /usr/local/bin/kubens

# Install k9s
tar -xzf k9s.tar.gz
chmod +x k9s
sudo mv k9s /usr/local/bin/

# Install stern
tar -xzf stern.tar.gz
chmod +x stern
sudo mv stern /usr/local/bin/

# Install yq
chmod +x yq
sudo mv yq /usr/local/bin/

# Install fzf
sudo rm -rf /opt/fzf
sudo git clone --depth 1 https://github.com/junegunn/fzf.git /opt/fzf
sudo /opt/fzf/install --all --no-update-rc
sudo ln -sf /opt/fzf/bin/fzf /usr/local/bin/fzf

# Cleanup
cd /
rm -rf "$TMPDIR"

# Setup bash completion
sudo mkdir -p /etc/bash_completion.d/
kubectl completion bash | sudo tee /etc/bash_completion.d/kubectl > /dev/null
helm completion bash | sudo tee /etc/bash_completion.d/helm > /dev/null
kind completion bash | sudo tee /etc/bash_completion.d/kind > /dev/null
argocd completion bash | sudo tee /etc/bash_completion.d/argocd > /dev/null
k3d completion bash | sudo tee /etc/bash_completion.d/k3d > /dev/null
```

---

## 6. Phase 5: GHCR Authentication

**IMPORTANT**: You need GitHub Container Registry credentials before proceeding.

```bash
# Set your credentials
export GHCR_USER="your-github-username"
export GHCR_TOKEN="your-github-pat-with-read-packages"

# Login to GHCR
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# Verify login
docker pull ghcr.io/hedgehogfabric/hhfab:latest 2>/dev/null && echo "GHCR auth: OK"
```

---

## 7. Phase 6: Initialize k3d Observability Cluster (EMC)

This creates the External Management Cluster with Prometheus, Grafana, ArgoCD, and Gitea.

### 7.1 Create k3d Cluster

```bash
# Port mappings:
# 3000 = Grafana
# 8080 = ArgoCD HTTP
# 8443 = ArgoCD HTTPS
# 3001 = Gitea HTTP
# 2222 = Gitea SSH
# 9090 = Prometheus (for Alloy remote write)

k3d cluster create k3d-observability \
    --api-port 6550 \
    --port "3000:3000@loadbalancer" \
    --port "8080:8080@loadbalancer" \
    --port "8443:8443@loadbalancer" \
    --port "3001:3001@loadbalancer" \
    --port "2222:2222@loadbalancer" \
    --port "9090:9090@loadbalancer" \
    --agents 2 \
    --wait

# Merge kubeconfig
k3d kubeconfig merge k3d-observability --kubeconfig-switch-context

# Wait for cluster to be ready
kubectl wait --for=condition=ready pods --all -n kube-system --timeout=120s
```

### 7.2 Add Helm Repositories

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update
helm repo add argo https://argoproj.github.io/argo-helm --force-update
helm repo add gitea-charts https://dl.gitea.com/charts/ --force-update
helm repo update
```

### 7.3 Install kube-prometheus-stack

**CRITICAL**: The `enableRemoteWriteReceiver: true` setting is required for VLAB Alloy agents to push metrics.

```bash
# Create namespace
kubectl create namespace monitoring

# Create values file
cat << 'EOF' > /tmp/prometheus-values.yaml
grafana:
  enabled: true
  adminPassword: admin
  service:
    type: LoadBalancer
    port: 3000
  persistence:
    enabled: true
    size: 10Gi

prometheus:
  service:
    type: LoadBalancer
    port: 9090
  prometheusSpec:
    retention: 7d
    # CRITICAL: Enable remote write receiver for Alloy
    enableRemoteWriteReceiver: true
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
    additionalScrapeConfigs: []

alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 10Gi

kubeStateMetrics:
  enabled: true
nodeExporter:
  enabled: true
prometheusOperator:
  enabled: true
EOF

# Install
helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --version 65.2.0 \
    --values /tmp/prometheus-values.yaml \
    --wait \
    --timeout 10m
```

### 7.4 Install ArgoCD

```bash
# Create namespace
kubectl create namespace argocd

# Create values file
cat << 'EOF' > /tmp/argocd-values.yaml
server:
  service:
    type: LoadBalancer
    servicePortHttp: 8080
    servicePortHttps: 8443
  extraArgs:
    - --insecure

redis:
  enabled: true

dex:
  enabled: false

controller:
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 2000m
      memory: 2Gi

repoServer:
  resources:
    requests:
      cpu: 250m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
EOF

# Install
helm upgrade --install argocd argo/argo-cd \
    --namespace argocd \
    --create-namespace \
    --version 7.6.12 \
    --values /tmp/argocd-values.yaml \
    --timeout 10m

# Wait for ArgoCD pods
kubectl wait --for=condition=ready pod \
    -l "app.kubernetes.io/name=argocd-server" \
    -n argocd \
    --timeout=300s

# Get ArgoCD admin password
echo "ArgoCD admin password:"
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
echo ""
```

### 7.5 Install Gitea

```bash
# Create namespace
kubectl create namespace gitea

# Create values file
cat << 'EOF' > /tmp/gitea-values.yaml
service:
  http:
    type: LoadBalancer
    port: 3001
  ssh:
    type: LoadBalancer
    port: 2222

gitea:
  admin:
    username: gitea_admin
    password: admin123
    email: admin@gitea.local

  config:
    server:
      DOMAIN: localhost
      ROOT_URL: http://localhost:3001
      SSH_DOMAIN: localhost
      SSH_PORT: 2222
    database:
      DB_TYPE: sqlite3
    security:
      INSTALL_LOCK: true
    service:
      DISABLE_REGISTRATION: false
      REQUIRE_SIGNIN_VIEW: false

persistence:
  enabled: true
  size: 10Gi

postgresql:
  enabled: false

postgresql-ha:
  enabled: false

valkey-cluster:
  enabled: false

redis-cluster:
  enabled: false
EOF

# Install
helm upgrade --install gitea gitea-charts/gitea \
    --namespace gitea \
    --create-namespace \
    --version 10.4.1 \
    --values /tmp/gitea-values.yaml \
    --wait \
    --timeout 20m

# Wait for Gitea
kubectl rollout status deployment/gitea -n gitea --timeout=600s
```

### 7.6 Verify EMC Services

```bash
echo "=== EMC Services Status ==="

# Check pods
echo "Monitoring namespace:"
kubectl get pods -n monitoring

echo ""
echo "ArgoCD namespace:"
kubectl get pods -n argocd

echo ""
echo "Gitea namespace:"
kubectl get pods -n gitea

echo ""
echo "=== Access URLs ==="
echo "Grafana: http://localhost:3000 (admin/admin)"
echo "ArgoCD: http://localhost:8080 (admin/<password above>)"
echo "Gitea: http://localhost:3001 (gitea_admin/admin123)"
echo "Prometheus: http://localhost:9090"
```

---

## 8. Phase 7: Initialize VLAB

This is the most critical phase. The VLAB initialization MUST have TLS SANs and Alloy configured BEFORE `hhfab vlab up`.

### 8.1 Switch to hhlab User

```bash
sudo -u hhlab -i
```

### 8.2 Initialize hhfab Working Directory

```bash
VLAB_WORK_DIR="/opt/hedgehog/vlab"
mkdir -p "$VLAB_WORK_DIR"
cd "$VLAB_WORK_DIR"

# Initialize hhfab with development credentials
hhfab init --dev
```

### 8.3 Patch fab.yaml for TLS SANs and Alloy Configuration

**CRITICAL**: This step MUST be done BEFORE running `hhfab vlab up`. The TLS SANs and Alloy configuration cannot be added after the VLAB is created.

```bash
cd "$VLAB_WORK_DIR"

# Backup original
cp fab.yaml fab.yaml.orig

# Get host IP for TLS SANs
HOST_IP=$(hostname -I | awk '{print $1}')

# Patch fab.yaml using Python (handles hhfab's tab characters correctly)
python3 << 'PYEOF'
import yaml

fab_yaml_path = "/opt/hedgehog/vlab/fab.yaml"

# Read and normalize tabs to spaces (hhfab may emit tabs)
with open(fab_yaml_path, 'r') as f:
    content = f.read().replace('\t', '    ')

docs = list(yaml.safe_load_all(content))

# TLS SANs - required for EMC to access VLAB controller
tls_sans = [
    "127.0.0.1",
    "localhost",
    "172.17.0.1",     # docker0 bridge
    "172.18.0.1",     # k3d bridge (where k3d exposes services)
    "0.0.0.0",        # Wildcard bind (lab-only!)
    "0.0.0.0/0",      # CIDR wildcard (lab-only!)
    "argocd-server.argocd",
    "gitea-http.gitea",
    "kube-prometheus-stack-prometheus.monitoring"
]

# Add host IP
import subprocess
host_ip = subprocess.check_output(['hostname', '-I']).decode().split()[0]
if host_ip:
    tls_sans.append(host_ip)

# Add hostname
import socket
hostname_short = socket.gethostname()
tls_sans.append(hostname_short)
try:
    hostname_fqdn = socket.getfqdn()
    if hostname_fqdn != hostname_short:
        tls_sans.append(hostname_fqdn)
except:
    pass

# Alloy configuration - PUSH-based telemetry to Prometheus
alloy_config = {
    'agentScrapeIntervalSeconds': 120,
    'unixScrapeIntervalSeconds': 120,
    'unixExporterEnabled': True,
    'collectSyslogEnabled': True,
    'prometheusTargets': {
        'emc': {
            'url': 'http://172.18.0.1:9090/api/v1/write',
            'sendIntervalSeconds': 120,
            'useControlProxy': True,
            'labels': {
                'env': 'vlab',
                'cluster': 'emc'
            }
        }
    },
    'unixExporterCollectors': [
        'cpu', 'filesystem', 'loadavg', 'meminfo', 'netdev', 'diskstats'
    ]
}

# Apply patches to Fabricator document
for doc in docs:
    if doc is None:
        continue
    if doc.get('kind') != 'Fabricator':
        continue

    # Ensure nested structure exists
    doc.setdefault('spec', {}).setdefault('config', {}).setdefault('control', {})
    doc['spec']['config'].setdefault('fabric', {})

    # Add TLS SANs
    existing_sans = doc['spec']['config']['control'].get('tlsSAN', []) or []
    for san in tls_sans:
        if san not in existing_sans:
            existing_sans.append(san)
    doc['spec']['config']['control']['tlsSAN'] = existing_sans

    # Add Alloy config
    doc['spec']['config']['fabric']['defaultAlloyConfig'] = alloy_config

# Write back
with open(fab_yaml_path, 'w') as f:
    yaml.dump_all(docs, f, default_flow_style=False, sort_keys=False)

print("fab.yaml patched successfully")
print(f"TLS SANs: {tls_sans}")
PYEOF

# Verify the patch
echo "=== Patched fab.yaml (relevant sections) ==="
grep -A 20 "tlsSAN:" fab.yaml || echo "tlsSAN section not found"
grep -A 20 "defaultAlloyConfig:" fab.yaml || echo "defaultAlloyConfig section not found"
```

### 8.4 Generate Wiring Diagram

```bash
cd "$VLAB_WORK_DIR"
hhfab vlab gen
ls -la *.yaml
```

### 8.5 Start VLAB

**NOTE**: This takes 15-25 minutes. The `--ready wait` flag ensures the command waits for all switches to be ready.

```bash
cd "$VLAB_WORK_DIR"

# Start VLAB (this takes 15-25 minutes)
echo "Starting VLAB... this will take 15-25 minutes"
hhfab vlab up --ready wait

# If the above times out, you can start without --ready wait and check manually:
# hhfab vlab up
# Then monitor with: hhfab vlab inspect
```

### 8.6 Verify VLAB Status

```bash
cd "$VLAB_WORK_DIR"

# Check VLAB status
hhfab vlab inspect

# Expected: 7 switches (2 spines, 5 leaves) all showing "Ready"

# Get kubeconfig for VLAB
export KUBECONFIG="$VLAB_WORK_DIR/vlab/kubeconfig"

# Check VLAB Kubernetes nodes
kubectl get nodes

# Check fabric pods
kubectl get pods -n fab
```

### 8.7 Exit hhlab User Session

```bash
exit
```

### 8.8 Create VLAB Initialized Marker (for subsequent scripts)

```bash
sudo mkdir -p /var/lib/hedgehog-lab
sudo touch /var/lib/hedgehog-lab/vlab-initialized
sudo chown -R hhlab:hhlab /var/lib/hedgehog-lab
```

---

## 9. Phase 8: Initialize GitOps (Gitea Repository)

This seeds Gitea with the student/hedgehog-config repository for ArgoCD.

### 9.1 Wait for Gitea API

```bash
# Wait for Gitea to be accessible
max_attempts=60
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf "http://localhost:3001/api/swagger" > /dev/null 2>&1; then
        echo "Gitea is accessible"
        break
    fi
    sleep 2
    ((attempt++))
done
```

### 9.2 Create Student Organization

```bash
GITEA_URL="http://localhost:3001"
GITEA_ADMIN_USER="gitea_admin"
GITEA_ADMIN_PASSWORD="admin123"

# Create organization
curl -X POST \
    -H "Content-Type: application/json" \
    -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/orgs" \
    -d '{
        "username": "student",
        "description": "Student organization for lab exercises",
        "visibility": "public"
    }'
```

### 9.3 Create hedgehog-config Repository

```bash
# Create repository
curl -X POST \
    -H "Content-Type: application/json" \
    -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/orgs/student/repos" \
    -d '{
        "name": "hedgehog-config",
        "description": "Hedgehog Fabric GitOps Configuration",
        "private": false,
        "auto_init": true,
        "default_branch": "main"
    }'
```

### 9.4 Seed Repository with Initial Content

```bash
# Clone the repository
TMP_REPO_DIR="/tmp/hedgehog-config-seed"
rm -rf "$TMP_REPO_DIR"

git config --global credential.helper store
echo "http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@localhost:3001" > /tmp/.git-credentials
git config --global credential.helper "store --file=/tmp/.git-credentials"

git clone "http://localhost:3001/student/hedgehog-config.git" "$TMP_REPO_DIR"
cd "$TMP_REPO_DIR"

git config user.name "Hedgehog Lab"
git config user.email "lab@hedgehog.local"

# Create directory structure
mkdir -p examples active

# Create README
cat << 'EOF' > README.md
# Hedgehog Config Repository

This repository contains GitOps configuration for the Hedgehog Fabric.

## Directory Structure

- `active/` - Active configurations that ArgoCD syncs to the fabric
- `examples/` - Example VPC and VPCAttachment manifests

## Usage

1. Copy example manifests to `active/`
2. Modify as needed
3. Commit and push
4. ArgoCD will automatically sync to the fabric
EOF

# Create example VPC manifest
cat << 'EOF' > examples/vpc-simple.yaml
apiVersion: vpc.githedgehog.com/v1alpha2
kind: VPC
metadata:
  name: vpc-simple
  namespace: default
spec:
  subnets:
    default:
      subnet: "10.100.0.0/24"
      gateway: "10.100.0.1"
      vlan: 1001
EOF

# Create .gitkeep for active directory
touch active/.gitkeep

# Commit and push
git add -A
git commit -m "Initial seed from Hedgehog Lab"
git push origin main

# Cleanup
cd /
rm -rf "$TMP_REPO_DIR"
rm /tmp/.git-credentials
git config --global --unset credential.helper
```

### 9.5 Verify Repository

```bash
curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/repos/student/hedgehog-config"
```

---

## 10. Phase 9: Configure ArgoCD Application

This creates the ArgoCD application that syncs from Gitea to the VLAB controller.

### 10.1 Set Kubeconfig for k3d Cluster

```bash
export KUBECONFIG="/root/.config/k3d/kubeconfig-k3d-observability.yaml"
kubectl config use-context k3d-k3d-observability
```

### 10.2 Detect k3d Gateway IP

```bash
# The VLAB API is accessible via the Docker bridge gateway
GATEWAY_IP=$(docker network inspect k3d-k3d-observability 2>/dev/null | grep -m1 '"Gateway"' | awk -F'"' '{print $4}')
if [ -z "$GATEWAY_IP" ]; then
    GATEWAY_IP="172.18.0.1"  # Fallback
fi
HEDGEHOG_API_SERVER="https://${GATEWAY_IP}:6443"
echo "Hedgehog API Server: $HEDGEHOG_API_SERVER"
```

### 10.3 Get Hedgehog Kubeconfig and Extract Credentials

```bash
VLAB_KUBECONFIG="/opt/hedgehog/vlab/vlab/kubeconfig"

# Symlink for hhlab user access
sudo mkdir -p /home/hhlab/.hhfab/vlab
sudo ln -sf "$VLAB_KUBECONFIG" /home/hhlab/.hhfab/vlab/kubeconfig

# Read kubeconfig and extract credentials
HEDGEHOG_KUBECONFIG=$(cat "$VLAB_KUBECONFIG")

# Try bearer token first
BEARER_TOKEN=$(echo "$HEDGEHOG_KUBECONFIG" | grep -m1 'token:' | sed 's/.*token:[[:space:]]*//' | tr -d '[:space:]')

# Or extract client cert/key
CERT_DATA=$(echo "$HEDGEHOG_KUBECONFIG" | grep -m1 'client-certificate-data:' | sed 's/.*client-certificate-data:[[:space:]]*//' | tr -d '[:space:]')
KEY_DATA=$(echo "$HEDGEHOG_KUBECONFIG" | grep -m1 'client-key-data:' | sed 's/.*client-key-data:[[:space:]]*//' | tr -d '[:space:]')
```

### 10.4 Create ArgoCD Cluster Secret

```bash
# Build auth block based on available credentials
if [ -n "$BEARER_TOKEN" ] && ! echo "$BEARER_TOKEN" | grep -q ':'; then
    AUTH_BLOCK="\"bearerToken\": \"${BEARER_TOKEN}\""
    echo "Using bearer token authentication"
elif [ -n "$CERT_DATA" ] && [ -n "$KEY_DATA" ]; then
    AUTH_BLOCK="\"tlsClientConfig\": { \"insecure\": true, \"certData\": \"${CERT_DATA}\", \"keyData\": \"${KEY_DATA}\" }"
    echo "Using client certificate authentication"
else
    echo "ERROR: No valid credentials found in kubeconfig"
    exit 1
fi

# Create cluster secret
kubectl apply -f - << EOF
apiVersion: v1
kind: Secret
metadata:
  name: cluster-hedgehog-vlab
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: hedgehog-vlab
  server: ${HEDGEHOG_API_SERVER}
  config: |
    {
      ${AUTH_BLOCK}
    }
EOF
```

### 10.5 Create ArgoCD Application

```bash
kubectl apply -f - << EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hedgehog-fabric
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: http://gitea-http.gitea:3000/student/hedgehog-config.git
    targetRevision: main
    path: active
  destination:
    server: ${HEDGEHOG_API_SERVER}
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
      - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
  ignoreDifferences:
    - group: "*"
      kind: "*"
      jsonPointers:
        - /status
EOF
```

### 10.6 Verify ArgoCD Application

```bash
# Check application status
kubectl get application -n argocd hedgehog-fabric

# Get sync status
kubectl get application -n argocd hedgehog-fabric -o jsonpath='{.status.sync.status}'
echo ""

# Get health status
kubectl get application -n argocd hedgehog-fabric -o jsonpath='{.status.health.status}'
echo ""
```

---

## 11. Phase 10: Verify Prometheus Metrics

The Hedgehog telemetry uses a PUSH model: Alloy agents on switches push metrics to Prometheus via remote write.

### 11.1 Verify Remote Write Receiver is Enabled

```bash
export KUBECONFIG="/root/.config/k3d/kubeconfig-k3d-observability.yaml"

# Check Prometheus configuration
kubectl get prometheus kube-prometheus-stack-prometheus \
    -n monitoring \
    -o jsonpath='{.spec.enableRemoteWriteReceiver}'
# Expected: true
```

### 11.2 Query for VLAB Metrics

```bash
# Start port-forward to Prometheus
PROM_POD=$(kubectl get pod -n monitoring \
    -l "app.kubernetes.io/name=prometheus" \
    -l "prometheus=kube-prometheus-stack-prometheus" \
    -o jsonpath='{.items[0].metadata.name}')

kubectl port-forward -n monitoring "$PROM_POD" 9091:9090 &
PF_PID=$!
sleep 5

# Query for VLAB metrics
curl -s "http://localhost:9091/api/v1/query?query=up{env=\"vlab\",cluster=\"emc\"}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('data', {}).get('result', [])
print(f'Found {len(results)} metric series from VLAB')
if results:
    print('SUCCESS: Hedgehog telemetry is working!')
else:
    print('Note: Metrics may take 2-3 minutes to appear after VLAB switches register')
"

# Kill port-forward
kill $PF_PID 2>/dev/null
```

### 11.3 Expected Metrics

When working correctly, you should see **21 metric series** (3 per switch x 7 switches):
- `integrations/self`
- `integrations/unix`
- `prometheus.scrape.agent`

---

## 12. Validation and Verification

### 12.1 Complete Status Check

```bash
echo "=== VLAB Status ==="
cd /opt/hedgehog/vlab && sudo -u hhlab hhfab vlab inspect

echo ""
echo "=== k3d Cluster ==="
export KUBECONFIG="/root/.config/k3d/kubeconfig-k3d-observability.yaml"
kubectl cluster-info --context k3d-k3d-observability

echo ""
echo "=== ArgoCD Application ==="
kubectl -n argocd get applications

echo ""
echo "=== ArgoCD Cluster Secret ==="
kubectl -n argocd get secrets -l argocd.argoproj.io/secret-type=cluster

echo ""
echo "=== Gitea Repository ==="
curl -s http://localhost:3001/api/v1/repos/student/hedgehog-config | head -5

echo ""
echo "=== Prometheus ==="
kubectl -n monitoring get pods -l app.kubernetes.io/name=kube-prometheus-stack-prometheus

echo ""
echo "=== Grafana ==="
kubectl -n monitoring get pods -l app.kubernetes.io/name=grafana
```

### 12.2 Service Access Summary

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | admin / admin |
| ArgoCD | http://localhost:8080 | admin / (see kubectl command) |
| Gitea | http://localhost:3001 | gitea_admin / admin123 |
| Prometheus | http://localhost:9090 | N/A |

```bash
# Get ArgoCD password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d && echo ""
```

---

## 13. Troubleshooting

### VLAB Won't Start

```bash
# Check hhfab logs
cd /opt/hedgehog/vlab
hhfab vlab inspect

# Check libvirt VMs
sudo virsh -c qemu:///system list --all

# Check for hhfab errors
journalctl -u hhfab-vlab.service --no-pager | tail -50
```

### ArgoCD Shows Unknown Sync Status

This is expected initially. The active/ directory may be empty or cluster authentication may still be establishing. Check:

```bash
# Check ArgoCD controller logs
kubectl logs -n argocd deployment/argocd-application-controller --tail=50

# Verify cluster secret
kubectl get secret -n argocd cluster-hedgehog-vlab -o yaml
```

### No Metrics in Prometheus

1. Verify remote write receiver is enabled:
```bash
kubectl get prometheus kube-prometheus-stack-prometheus -n monitoring -o jsonpath='{.spec.enableRemoteWriteReceiver}'
```

2. Check that fab.yaml was patched BEFORE hhfab vlab up:
```bash
grep -A 20 "defaultAlloyConfig:" /opt/hedgehog/vlab/fab.yaml
```

3. Verify VLAB switches are ready:
```bash
cd /opt/hedgehog/vlab && sudo -u hhlab hhfab vlab inspect
```

4. Check fabric-ctrl logs for Alloy status:
```bash
export KUBECONFIG="/opt/hedgehog/vlab/vlab/kubeconfig"
kubectl logs -n fab deployment/fabric-ctrl --tail=50
```

### TLS Certificate Errors

If you see TLS certificate errors when ArgoCD tries to connect to VLAB:

1. The fab.yaml TLS SANs were not configured before VLAB startup
2. You need to destroy and recreate the VLAB with proper fab.yaml configuration

```bash
cd /opt/hedgehog/vlab
sudo -u hhlab hhfab vlab down
rm -f fab.yaml wiring.yaml
# Re-run from Phase 7.2
```

---

## Key Learnings Summary

1. **Pre-Configuration is Mandatory**: TLS SANs and Alloy config MUST be in fab.yaml BEFORE `hhfab vlab up`
2. **k3d Bridge IP**: Use 172.18.0.1 for communication between EMC and VLAB
3. **Remote Write Receiver**: Prometheus must have `enableRemoteWriteReceiver: true`
4. **PUSH Telemetry**: Hedgehog uses Alloy agents that PUSH to Prometheus, not PULL
5. **Tab Normalization**: hhfab may emit tabs in fab.yaml; use Python for reliable parsing
6. **Expected Metrics**: 21 metric series (3 per switch x 7 switches)
