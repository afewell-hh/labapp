# Lab Environment Rebuild Guide
## Network Like a Hyperscaler Pathway

**Purpose**: Complete configuration guide for rebuilding the lab environment used in the "Network Like a Hyperscaler" learning pathway with identical student experience.

**Last Updated**: 2026-01-07
**Source**: Reverse-engineered from pathway content analysis (16 modules across 4 courses)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Component Requirements](#component-requirements)
4. [VLAB Setup (Base Environment)](#vlab-setup-base-environment)
5. [Gitea Configuration](#gitea-configuration)
6. [ArgoCD Configuration](#argocd-configuration)
7. [Prometheus/Grafana/LGTM Stack](#prometheusgrafanalgtm-stack)
8. [Integration & Validation](#integration--validation)
9. [Student Experience Checklist](#student-experience-checklist)
10. [Known Gaps & Research Needed](#known-gaps--research-needed)

---

## Executive Summary

### What We Know (Documented)

✅ **VLAB Base Environment**: Fully documented, uses `hhfab` default spine-leaf topology
✅ **Grafana Dashboards**: 6 complete dashboard JSON files found in repository
✅ **Service Access Details**: All URLs, ports, and credentials documented
✅ **Telemetry Architecture**: Complete configuration structure documented
✅ **GitOps Workflow**: Repository structure and integration patterns documented
✅ **Student Commands**: All kubectl, git, and diagnostic commands extracted

### What Needs Additional Research

⚠️ **Gitea Installation**: Setup scripts not in hh-learn repo (likely in main Hedgehog fabric repo or hhfab tool)
⚠️ **ArgoCD Installation**: Deployment manifests not in hh-learn repo
⚠️ **Monitoring Stack Deployment**: Prometheus/Loki/Grafana K8s manifests not in hh-learn repo
⚠️ **Initial Repository Setup**: Scripts to create `student/hedgehog-config` repo with initial structure

**Recommendation**: These components are likely deployed automatically by the Hedgehog fabric installation process or included in the External Management K3s Cluster (EMKC) setup. Check the main Hedgehog repositories:
- https://github.com/githedgehog/fabric
- https://github.com/githedgehog/fabricator (hhfab tool)

---

## Architecture Overview

### Infrastructure Layers

```
┌─────────────────────────────────────────────────────────────┐
│ VLAB Host (Cloud VM or Bare Metal)                         │
│  - Ubuntu 22.04 LTS                                         │
│  - Docker + QEMU/KVM                                        │
│  - hhfab CLI installed                                      │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────▼──────────┐                 ┌─────────▼────────┐
│ VLAB Environment │                 │ EMKC (External   │
│ (Default Topo)   │                 │ Management K3s)  │
│                  │                 │                  │
│ - 2x Spines      │◄────────────────┤ - Prometheus     │
│ - 4x Leaves      │   Telemetry     │ - Grafana        │
│ - 10x Servers    │                 │ - Loki           │
│ - Control Node   │                 │ - ArgoCD         │
│ - fabric-proxy   │                 │ - Gitea          │
└──────────────────┘                 └──────────────────┘
```

### Service Topology

| Service | Location | Port | Purpose |
|---------|----------|------|---------|
| **Prometheus** | EMKC | 9090 | Metrics database (15-day retention) |
| **Grafana** | EMKC | 3000 | Dashboard visualization (6 dashboards) |
| **Gitea** | EMKC | 3001 | Git repository hosting |
| **ArgoCD** | EMKC | 8080 | GitOps continuous delivery |
| **fabric-proxy** | Control Node | 31028 | Metrics aggregation from switches |
| **Alloy Agents** | Each Switch | N/A | Telemetry collection (120s interval) |

### Data Flow

```
Switches (SONiC) → Alloy Agents (120s scrape)
                        ↓
                  fabric-proxy (Control Node :31028)
                        ↓
                  Prometheus (EMKC :9090, 15-day retention)
                        ↓
                  Grafana (EMKC :3000, 6 dashboards)

Git Commits (Gitea :3001) → ArgoCD (EMKC :8080)
                        ↓
                  Fabric Controller (K8s)
                        ↓
                  Switch Agents (apply config)
```

---

## Component Requirements

### 1. VLAB (Base Environment)

**Topology**: Default Spine-Leaf

**Hardware Requirements**:
- **vCPUs**: 54
- **RAM**: 49,664 MB (~48.5 GB)
- **Disk**: 550 GB
- **Network**: Bridged networking for external access

**Components** (automatically deployed by `hhfab vlab up`):
- 2x Spine switches (SONiC)
- 4x Leaf switches (SONiC)
- 10x Servers (Ubuntu)
- 1x Control Node (K3s cluster)

**Default Credentials**: (Check `hhfab vlab` documentation for current defaults)

### 2. Gitea

**Required Configuration**:

| Setting | Value |
|---------|-------|
| URL | `http://localhost:3001` |
| Port | 3001 |
| Default User | `student` |
| Default Password | `hedgehog123` |
| Initial Repository | `student/hedgehog-config` |
| Repository Structure | See [Gitea Configuration](#gitea-configuration) |

**Key Features**:
- User account: `student` (password: `hedgehog123`)
- Repository: `student/hedgehog-config`
- Default branch: `main`
- Web UI accessible for students
- Git over HTTP(S) enabled

### 3. ArgoCD

**Required Configuration**:

| Setting | Value |
|---------|-------|
| URL | `http://localhost:8080` |
| Port | 8080 |
| Admin User | `admin` |
| Admin Password | `qV7hX0NMroAUhwoZ` |
| Default Application | `hedgehog-config` |
| Source Repository | Gitea: `http://localhost:3001/student/hedgehog-config.git` |
| Target Cluster | In-cluster (VLAB K3s) |
| Sync Policy | Manual (students trigger sync) |

**Application Configuration**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hedgehog-config
  namespace: argocd
spec:
  project: default
  source:
    repoURL: http://localhost:3001/student/hedgehog-config.git
    targetRevision: main
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
```

### 4. Prometheus

**Required Configuration**:

| Setting | Value |
|---------|-------|
| URL | `http://localhost:9090` |
| Port | 9090 |
| Retention Period | 15 days |
| Scrape Interval | 120 seconds (2 minutes) |
| Remote Write Endpoint | `http://<prometheus>:9100/api/v1/push` |

**Critical Scrape Jobs**:
```yaml
scrape_configs:
  - job_name: 'fabric-proxy'
    static_configs:
      - targets: ['<control-node>:31028']
    scrape_interval: 120s
```

**Key Metrics** (must be available):
- `cpu_usage_percent`
- `bgp_neighbor_state`
- `interface_bytes_out`
- `interface_bytes_in`
- `interface_operational_state`
- `psu_status`
- `fan_speed_rpm`
- `temperature_celsius`
- `optical_rx_power_dbm`
- `optical_tx_power_dbm`
- `route_table_usage_percent`
- `arp_table_usage_percent`
- `fdb_table_usage_percent`

### 5. Grafana

**Required Configuration**:

| Setting | Value |
|---------|-------|
| URL | `http://localhost:3000` |
| Port | 3000 |
| Admin Username | `admin` |
| Admin Password | `prom-operator` |
| Datasources | Prometheus (`prom`), Loki (`loki`) |
| Pre-loaded Dashboards | 6 (see below) |

**Datasources Configuration**:

**Prometheus** (UID: `prom`):
```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    uid: prom
    isDefault: true
    editable: true
```

**Loki** (UID: `loki`):
```yaml
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    uid: loki
    editable: true
```

**Required Dashboards** (6 total):

1. **Hedgehog Fabric Dashboard** (`grafana_fabric.json`)
   - UID: `ab831ceb-cf5c-474a-b7e9-83dcd075c218`
   - Focus: BGP underlay health
   - Key panels: BGP session state, VPC count, BGP flaps

2. **Hedgehog Interfaces Dashboard** (`grafana_interfaces.json`)
   - UID: `a5e5b12d-b340-4753-8f83-af8d54304822`
   - Focus: Interface state and traffic
   - Key panels: Operational state, utilization, errors, packet counters

3. **Hedgehog Platform Dashboard** (`grafana_platform.json`)
   - UID: `f8a648b9-5510-49ca-9273-952ba6169b7b`
   - Focus: Hardware health
   - Key panels: PSU status, fan speed, temperature, optics

4. **Hedgehog Logs Dashboard** (`grafana_logs.json`)
   - UID: `c42a51e5-86a8-42a0-b1c9-d1304ae655bc`
   - Focus: Syslog aggregation
   - Key panels: ERROR count, log patterns

5. **Switch Critical Resources Dashboard** (`grafana_crm.json`)
   - UID: `fb08315c-cabb-4da7-9db9-2e17278f1781`
   - Focus: ASIC resource capacity
   - Key panels: Route table, ARP table, FDB, ACL utilization

6. **Node Exporter Dashboard** (`grafana_node_exporter.json`)
   - UID: `rYdddlPWA`
   - Focus: Linux system metrics
   - Key panels: CPU, memory, disk, network I/O

**Dashboard Files Location**: `/home/ubuntu/afewell-hh/hh-learn/reference/docs/docs/user-guide/boards/`

### 6. Loki (Log Aggregation)

**Required Configuration**:

| Setting | Value |
|---------|-------|
| API Endpoint | `http://localhost:3100/loki/api/v1/push` |
| Port | 3100 |
| Retention | (Default or 15 days to match Prometheus) |

**Log Sources**:
- Switch syslogs (via Alloy agents)
- Fabric controller logs
- Switch kernel logs

---

## VLAB Setup (Base Environment)

### Prerequisites Installation

**Host System Requirements**:
- Ubuntu 22.04 LTS (or compatible)
- 54+ vCPUs
- 64+ GB RAM (49.7 GB minimum)
- 600+ GB disk
- Docker installed
- QEMU/KVM installed
- oras installed
- hhfab installed

**Installation Steps**:

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in

# 2. Install QEMU/KVM
sudo apt-get update
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

# 3. Install oras
curl -LO https://github.com/oras-project/oras/releases/download/v1.0.0/oras_1.0.0_linux_amd64.tar.gz
sudo tar -xzf oras_1.0.0_linux_amd64.tar.gz -C /usr/local/bin oras
rm oras_1.0.0_linux_amd64.tar.gz

# 4. Install hhfab
# (Follow official Hedgehog installation instructions)
# Typically: curl -fsSL https://install.hedgehog.dev | bash
```

### VLAB Initialization

```bash
# Initialize Hedgehog workspace
hhfab init --dev

# Generate default topology VLAB configuration
hhfab vlab gen

# Start VLAB (this will take 15-30 minutes)
hhfab vlab up

# Wait for all VMs to boot and fabric to be ready
# Monitor with:
watch kubectl get agents -n fab
# Wait until all agents show "Ready" status
```

### Verify VLAB Base

```bash
# Check all switches are reachable
hhfab vlab ssh leaf-01
hhfab vlab ssh leaf-02
hhfab vlab ssh spine-01

# Verify fabric controller is running
kubectl get pods -n fab

# Verify control node services
kubectl get svc -n fab
```

**Expected Output**:
- All switches accessible via SSH
- `fabric-controller-manager` pod running
- `fabric-proxy` service available on port 31028

---

## Gitea Configuration

### Installation

**Note**: Actual installation scripts not found in hh-learn repository. Gitea is likely installed automatically as part of the EMKC (External Management K3s Cluster) setup during fabric installation.

**Check if Gitea is already installed**:
```bash
kubectl get pods -n gitea 2>/dev/null || echo "Gitea namespace not found"
kubectl get svc -A | grep gitea
```

**If not installed**, check the main Hedgehog fabric repository for Gitea Helm charts or manifests.

### Manual Installation (if needed)

**Option 1: Helm Chart** (recommended):
```bash
helm repo add gitea-charts https://dl.gitea.io/charts/
helm install gitea gitea-charts/gitea \
  --namespace gitea \
  --create-namespace \
  --set service.http.type=NodePort \
  --set service.http.port=3001 \
  --set gitea.admin.username=admin \
  --set gitea.admin.password=adminpassword
```

**Option 2: Docker Compose** (simpler for single-node):
```yaml
# docker-compose.yml
version: "3"

services:
  gitea:
    image: gitea/gitea:latest
    container_name: gitea
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
    ports:
      - "3001:3000"
      - "2222:22"
    volumes:
      - ./gitea:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
```

```bash
docker-compose up -d
```

### Post-Installation Configuration

**1. Access Gitea**:
```bash
# Port-forward if running in K8s
kubectl port-forward -n gitea svc/gitea-http 3001:3000

# Or access directly if NodePort/LoadBalancer
open http://localhost:3001
```

**2. Create Student User**:
```bash
# Via Gitea CLI (if available)
gitea admin user create \
  --username student \
  --password hedgehog123 \
  --email student@hedgehog.local \
  --must-change-password=false

# Or via Web UI:
# - Navigate to http://localhost:3001
# - Click "Register"
# - Username: student
# - Password: hedgehog123
# - Email: student@hedgehog.local
```

**3. Create Initial Repository**:
```bash
# Clone this script or run manually in Gitea UI:
# Repository Name: hedgehog-config
# Owner: student
# Visibility: Public
# Initialize with README: Yes
```

**4. Setup Repository Structure**:
```bash
# Clone the repository
git clone http://localhost:3001/student/hedgehog-config.git
cd hedgehog-config

# Create directory structure
mkdir -p vpcs
mkdir -p vpcattachments
mkdir -p vpcpeerings

# Create README
cat > README.md <<'EOF'
# Hedgehog Fabric Configuration

GitOps repository for Hedgehog fabric network resources.

## Directory Structure

- `vpcs/` - VPC definitions
- `vpcattachments/` - VPC attachment configurations
- `vpcpeerings/` - VPC peering configurations

## Workflow

1. Create/edit YAML files in appropriate directories
2. Commit changes to Git
3. Trigger ArgoCD sync
4. Fabric controller applies changes to switches
EOF

# Create .gitignore
cat > .gitignore <<'EOF'
*.swp
*.swo
*~
.DS_Store
EOF

# Commit and push
git add .
git commit -m "Initial repository structure"
git push origin main
```

**5. Configure Git Credentials** (for student):
```bash
# Configure git to store credentials (for lab environment only!)
git config --global credential.helper store
git config --global user.name "Student"
git config --global user.email "student@hedgehog.local"

# First push will prompt for credentials
# Username: student
# Password: hedgehog123
```

### Expected Student Experience

Students should be able to:
```bash
# Clone repository
git clone http://localhost:3001/student/hedgehog-config.git

# Make changes
cd hedgehog-config
echo "..." > vpcs/test-vpc.yaml
git add vpcs/test-vpc.yaml
git commit -m "Add test VPC"
git push origin main

# View in Web UI
open http://localhost:3001/student/hedgehog-config
```

---

## ArgoCD Configuration

### Installation

**Note**: Actual installation manifests not found in hh-learn repository. ArgoCD is likely installed automatically as part of the EMKC setup.

**Check if ArgoCD is already installed**:
```bash
kubectl get pods -n argocd 2>/dev/null || echo "ArgoCD namespace not found"
kubectl get svc -n argocd
```

**If not installed**, install ArgoCD:

```bash
# Create namespace
kubectl create namespace argocd

# Install ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for ArgoCD pods to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server -n argocd --timeout=300s

# Expose ArgoCD server
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "NodePort", "ports": [{"port": 80, "nodePort": 8080, "name": "http"}]}}'

# Or use port-forward
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

### Post-Installation Configuration

**1. Set Admin Password**:
```bash
# Get initial admin password
ARGOCD_INITIAL_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
echo "Initial password: $ARGOCD_INITIAL_PASSWORD"

# Login with ArgoCD CLI (if installed)
argocd login localhost:8080 --username admin --password "$ARGOCD_INITIAL_PASSWORD" --insecure

# Change admin password to match lab environment
argocd account update-password --current-password "$ARGOCD_INITIAL_PASSWORD" --new-password "qV7hX0NMroAUhwoZ"

# Or manually set password via kubectl
kubectl -n argocd patch secret argocd-secret \
  -p '{"stringData": {"admin.password": "'$(htpasswd -bnBC 10 "" "qV7hX0NMroAUhwoZ" | tr -d ':\n')'"}}'
```

**2. Create ArgoCD Application**:
```bash
# Create Application manifest
cat > hedgehog-config-app.yaml <<'EOF'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hedgehog-config
  namespace: argocd
spec:
  project: default
  source:
    repoURL: http://gitea-http.gitea.svc.cluster.local:3000/student/hedgehog-config.git
    targetRevision: main
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
    automated:
      prune: false
      selfHeal: false
EOF

# Apply the application
kubectl apply -f hedgehog-config-app.yaml
```

**3. Configure Gitea Integration** (if using in-cluster Gitea):
```bash
# Add Gitea repository to ArgoCD
argocd repo add http://gitea-http.gitea.svc.cluster.local:3000/student/hedgehog-config.git \
  --username student \
  --password hedgehog123 \
  --insecure-skip-server-verification
```

**4. Access ArgoCD UI**:
```bash
# URL: http://localhost:8080
# Username: admin
# Password: qV7hX0NMroAUhwoZ
```

### Expected Student Experience

Students should be able to:
```bash
# Trigger sync via CLI
argocd app sync hedgehog-config

# Wait for sync to complete
argocd app wait hedgehog-config --health

# Check sync status
argocd app get hedgehog-config

# View sync history
argocd app history hedgehog-config
```

**Via Web UI**:
- Navigate to http://localhost:8080
- Login with admin / qV7hX0NMroAUhwoZ
- See `hedgehog-config` application
- Click "Sync" button to deploy changes
- View application topology and resource status

---

## Prometheus/Grafana/LGTM Stack

### Architecture

The monitoring stack consists of:
- **Prometheus**: Metrics database
- **Loki**: Log aggregation
- **Grafana**: Visualization (dashboards)
- **Tempo/Mimir**: (Optional, not explicitly required for pathway)

### Installation

**Note**: Installation manifests not found in hh-learn repository. The stack is likely deployed as part of EMKC or available as a Helm chart in the main Hedgehog repositories.

**Option 1: kube-prometheus-stack (Recommended)**:

```bash
# Add Prometheus community Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install kube-prometheus-stack (includes Prometheus, Grafana, Alertmanager)
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.retention=15d \
  --set prometheus.prometheusSpec.scrapeInterval=120s \
  --set prometheus.service.type=NodePort \
  --set prometheus.service.nodePort=9090 \
  --set grafana.service.type=NodePort \
  --set grafana.service.nodePort=3000 \
  --set grafana.adminPassword=prom-operator
```

**Option 2: Grafana LGTM Stack (if using Grafana Cloud or full LGTM)**:

This would require checking Hedgehog's official installation docs or main repository.

### Prometheus Configuration

**Configure fabric-proxy scrape job**:

```bash
# Create ConfigMap for additional scrape configs
cat > prometheus-additional-scrape-configs.yaml <<'EOF'
- job_name: 'fabric-proxy'
  static_configs:
    - targets: ['fabric-proxy.fab.svc.cluster.local:31028']
      labels:
        environment: 'vlab'
  scrape_interval: 120s
  scrape_timeout: 30s
EOF

# Create Kubernetes secret
kubectl create secret generic additional-scrape-configs \
  --from-file=prometheus-additional-scrape-configs.yaml \
  --namespace monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Update Prometheus to use additional configs
# (This depends on your Prometheus deployment method)
```

**Verify Prometheus targets**:
```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090

# Access http://localhost:9090/targets
# Verify fabric-proxy target is "UP"
```

### Loki Installation

```bash
# Add Grafana Helm repo
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Install Loki
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set loki.enabled=true \
  --set promtail.enabled=false \
  --set loki.persistence.enabled=true \
  --set loki.persistence.size=50Gi
```

**Configure Loki to receive logs from Alloy**:
```bash
# Loki should be accessible at http://loki.monitoring.svc.cluster.local:3100
# Verify service
kubectl get svc -n monitoring loki
```

### Grafana Configuration

**1. Access Grafana**:
```bash
# Port-forward
kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80

# Or if NodePort is configured
# Access directly at http://localhost:3000
```

**2. Login**:
- Username: `admin`
- Password: `prom-operator`

**3. Configure Datasources**:

**Prometheus Datasource**:
```bash
cat > prometheus-datasource.yaml <<'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090
    uid: prom
    isDefault: true
    editable: true
    jsonData:
      timeInterval: 120s
EOF

# If using kube-prometheus-stack, datasource is pre-configured
# Just update the UID to match "prom"
```

**Loki Datasource**:
```bash
cat > loki-datasource.yaml <<'EOF'
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki.monitoring.svc.cluster.local:3100
    uid: loki
    editable: true
EOF
```

Apply via Grafana UI or ConfigMap.

**4. Import Hedgehog Dashboards**:

**Dashboard JSON files location**: `/home/ubuntu/afewell-hh/hh-learn/reference/docs/docs/user-guide/boards/`

```bash
# Copy dashboard files to a working directory
cp /home/ubuntu/afewell-hh/hh-learn/reference/docs/docs/user-guide/boards/*.json ./dashboards/

# Import via Grafana UI:
# 1. Navigate to http://localhost:3000
# 2. Click "+" → "Import"
# 3. Upload each JSON file:
#    - grafana_fabric.json
#    - grafana_interfaces.json
#    - grafana_platform.json
#    - grafana_logs.json
#    - grafana_crm.json
#    - grafana_node_exporter.json
# 4. Select "Prometheus" datasource (UID: prom)
# 5. For logs dashboard, also select "Loki" datasource (UID: loki)
# 6. Click "Import"
```

**Or import via API**:
```bash
GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="prom-operator"

for dashboard in dashboards/*.json; do
  curl -X POST \
    -H "Content-Type: application/json" \
    -u "$GRAFANA_USER:$GRAFANA_PASS" \
    -d @"$dashboard" \
    "$GRAFANA_URL/api/dashboards/db"
done
```

**5. Verify Dashboards**:
```bash
# Navigate to http://localhost:3000
# Click "Dashboards" → "Browse"
# Verify all 6 dashboards are present:
# ✓ Hedgehog Fabric
# ✓ Hedgehog Interfaces
# ✓ Hedgehog Platform
# ✓ Hedgehog Logs
# ✓ Switch Critical Resources
# ✓ Node Exporter
```

### Alloy Configuration (Telemetry Agents)

Alloy agents are deployed on each switch and configured via the Fabricator CRD.

**Configure Fabricator for telemetry**:

```bash
# Create telemetry configuration patch
cat > telemetry-config.yaml <<'EOF'
spec:
  config:
    defaultAlloyConfig:
      agentScrapeIntervalSeconds: 120
      unixScrapeIntervalSeconds: 120
      unixExporterEnabled: true
      collectSyslogEnabled: true
      lokiTargets:
        lab:
          url: http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push
          labels:
            environment: vlab
      prometheusTargets:
        lab:
          url: http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9100/api/v1/push
          labels:
            environment: vlab
          sendIntervalSeconds: 120
EOF

# Apply to Fabricator
kubectl patch fabricator default -n fab --type merge --patch-file telemetry-config.yaml
```

**Verify Alloy agents on switches**:
```bash
# SSH to a switch
hhfab vlab ssh leaf-01

# Check Alloy service status
systemctl status alloy

# Check Alloy configuration
cat /etc/alloy/config.alloy

# Exit switch
exit
```

### Validation

**1. Verify Metrics Flow**:
```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090

# Query for Hedgehog metrics
curl 'http://localhost:9090/api/v1/query?query=cpu_usage_percent' | jq

# Expected: Should return metrics from switches
```

**2. Verify Dashboards Show Data**:
```bash
# Open Grafana
open http://localhost:3000

# Navigate to "Hedgehog Fabric" dashboard
# Verify:
# - BGP session metrics visible
# - All switches listed in dropdown
# - Last update timestamp recent (<5 minutes)
```

**3. Verify Logs in Loki**:
```bash
# Open Grafana → Explore
# Select "Loki" datasource
# Query: {job="alloy"}
# Should see syslog entries from switches
```

---

## Integration & Validation

### End-to-End GitOps Workflow Test

This validates the complete integration: Gitea → ArgoCD → Kubernetes → Fabric Controller → Switches

**1. Create a Test VPC**:
```bash
# Clone repository
git clone http://localhost:3001/student/hedgehog-config.git
cd hedgehog-config

# Create test VPC
cat > vpcs/test-vpc.yaml <<'EOF'
apiVersion: vpc.githedgehog.com/v1alpha2
kind: VPC
metadata:
  name: test-vpc
  namespace: default
spec:
  ipv4Namespace: default
  subnets:
    default:
      dhcp:
        enable: true
      subnet: 172.30.1.0/24
EOF

# Commit and push
git add vpcs/test-vpc.yaml
git commit -m "Add test VPC for validation"
git push origin main
```

**2. Trigger ArgoCD Sync**:
```bash
# Via CLI
argocd app sync hedgehog-config
argocd app wait hedgehog-config --health

# Via Web UI
# Navigate to http://localhost:8080
# Click hedgehog-config → Sync
```

**3. Verify VPC Created**:
```bash
# Check VPC resource
kubectl get vpc test-vpc

# Expected output:
# NAME       SUBNET            VLAN   IPv4 NAMESPACE   READY   AGE
# test-vpc   172.30.1.0/24     1030   default          True    30s

# Check events
kubectl get events --field-selector involvedObject.name=test-vpc

# Expected: No errors, successful allocation events
```

**4. Verify in Grafana**:
```bash
# Open Grafana → Hedgehog Fabric Dashboard
# Verify VPC count increased by 1
```

**5. Cleanup**:
```bash
# Remove test VPC
rm vpcs/test-vpc.yaml
git add vpcs/test-vpc.yaml
git commit -m "Remove test VPC"
git push origin main

# Sync ArgoCD
argocd app sync hedgehog-config

# Verify deletion
kubectl get vpc test-vpc
# Expected: Error from server (NotFound)
```

### Service Accessibility Checklist

Verify all services are accessible from the expected URLs:

```bash
# Prometheus
curl -f http://localhost:9090/-/healthy || echo "❌ Prometheus not accessible"

# Grafana
curl -f http://localhost:3000/api/health || echo "❌ Grafana not accessible"

# Gitea
curl -f http://localhost:3001/api/v1/version || echo "❌ Gitea not accessible"

# ArgoCD
curl -f -k http://localhost:8080/healthz || echo "❌ ArgoCD not accessible"

# fabric-proxy (from control node)
kubectl exec -n fab deployment/fabric-controller-manager -- curl -f http://fabric-proxy:31028/metrics || echo "❌ fabric-proxy not accessible"
```

### Telemetry Pipeline Validation

```bash
# 1. Verify Alloy agents running on switches
kubectl get agents -n fab -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.version}{"\n"}{end}'

# 2. Check fabric-proxy is receiving metrics
kubectl logs -n fab deployment/fabric-proxy --tail=50

# 3. Verify Prometheus is scraping fabric-proxy
# Open http://localhost:9090/targets
# fabric-proxy should be "UP"

# 4. Query metrics in Prometheus
# Open http://localhost:9090/graph
# Query: cpu_usage_percent{switch="leaf-01"}
# Should return data

# 5. Verify dashboards in Grafana
# Open http://localhost:3000
# All 6 dashboards should show live data
```

---

## Student Experience Checklist

Use this checklist to ensure the lab environment matches what students expect from the learning modules:

### Access & Authentication

- [ ] Prometheus accessible at `http://localhost:9090` (no auth)
- [ ] Grafana accessible at `http://localhost:3000` (admin / prom-operator)
- [ ] Gitea accessible at `http://localhost:3001` (student / hedgehog123)
- [ ] ArgoCD accessible at `http://localhost:8080` (admin / qV7hX0NMroAUhwoZ)

### Gitea Setup

- [ ] User `student` exists with password `hedgehog123`
- [ ] Repository `student/hedgehog-config` exists
- [ ] Repository has directories: `vpcs/`, `vpcattachments/`, `vpcpeerings/`
- [ ] Students can clone, commit, and push without errors
- [ ] Web UI is accessible and user-friendly

### ArgoCD Setup

- [ ] Application `hedgehog-config` exists
- [ ] Application is connected to Gitea repository
- [ ] Sync policy is manual (students trigger sync)
- [ ] Students can view application status in UI
- [ ] CLI commands work: `argocd app sync`, `argocd app get`, `argocd app wait`

### Grafana Dashboards

- [ ] All 6 dashboards imported and visible
- [ ] Dashboards show live data from switches
- [ ] Data updates every 2 minutes (120s scrape interval)
- [ ] No "No Data" errors on panels
- [ ] Time range selector works
- [ ] Variable dropdowns (switch, interface, etc.) populate correctly

**Specific Dashboard Checks**:
- [ ] **Hedgehog Fabric**: BGP session state shows "established" for all sessions
- [ ] **Hedgehog Interfaces**: Interface list shows all switch ports
- [ ] **Hedgehog Platform**: PSU, fan, temperature data visible
- [ ] **Hedgehog Logs**: Syslog entries appear (if syslog enabled)
- [ ] **Switch Critical Resources**: ASIC resource utilization shown
- [ ] **Node Exporter**: CPU, memory, disk metrics for switches

### Prometheus Queries

Students should be able to run these example queries:

- [ ] `cpu_usage_percent` returns data
- [ ] `cpu_usage_percent{switch="leaf-01"}` filters to specific switch
- [ ] `bgp_neighbor_state` shows BGP neighbor states
- [ ] `interface_bytes_out` shows interface traffic
- [ ] `rate(interface_bytes_out{switch="leaf-01",interface="Ethernet1"}[5m]) * 8` calculates bandwidth

### Kubectl Access

- [ ] `kubectl get vpc -A` works (may return empty initially)
- [ ] `kubectl get agents -n fab` shows all switches
- [ ] `kubectl get events --all-namespaces` shows events
- [ ] `kubectl logs -n fab deployment/fabric-controller-manager` shows controller logs
- [ ] Agent CRD queries work: `kubectl get agent leaf-01 -n fab -o jsonpath='{.status.state.interfaces}' | jq`

### SSH Access

- [ ] `hhfab vlab ssh leaf-01` connects to switch
- [ ] `systemctl status alloy` shows Alloy agent running on switch
- [ ] Students can exit switch and return to control node

### GitOps Workflow

Test the complete workflow students will use:

1. [ ] Clone repo: `git clone http://localhost:3001/student/hedgehog-config.git`
2. [ ] Create VPC YAML file in `vpcs/` directory
3. [ ] Commit and push to Git
4. [ ] Trigger ArgoCD sync (CLI or UI)
5. [ ] Verify VPC created: `kubectl get vpc <name>`
6. [ ] See VPC in Grafana dashboard (VPC count increments)
7. [ ] Delete VPC from Git
8. [ ] Sync ArgoCD
9. [ ] Verify VPC deleted: `kubectl get vpc <name>` returns NotFound

### Troubleshooting Tools

Students should be able to use these diagnostic commands:

- [ ] `kubectl get events --field-selector involvedObject.name=<vpc-name>`
- [ ] `kubectl describe vpc <name>`
- [ ] `kubectl get agent <switch> -n fab -o yaml`
- [ ] `kubectl logs -n fab deployment/fabric-controller-manager | grep <resource-name>`
- [ ] View Grafana dashboards for trends
- [ ] Query Prometheus for specific metrics

### Learning Module Commands

Verify all commands from the 16 modules work:

- [ ] VPC creation/deletion workflow (Course 2)
- [ ] VPCAttachment workflow (Course 2)
- [ ] PromQL queries (Course 3)
- [ ] Dashboard interpretation (Course 3)
- [ ] Event debugging (Course 3)
- [ ] Diagnostic collection script runs (Course 3)
- [ ] Git rollback workflow (Course 4)
- [ ] Finalizer removal (Course 4 - emergency only)

---

## Known Gaps & Research Needed

### Missing Components

The following components are referenced in the learning content but installation/configuration scripts were **not found** in the `hh-learn` repository:

#### 1. Gitea Installation

**What's Missing**:
- Helm chart or K8s manifests for Gitea deployment
- Gitea configuration file (`app.ini`)
- User creation scripts
- Repository initialization scripts
- SSH key setup

**Where to Find**:
- Check main Hedgehog repository: https://github.com/githedgehog/fabric
- Check Fabricator (hhfab) source: https://github.com/githedgehog/fabricator
- Check if included in EMKC setup during `hhfab init`

**Workaround**:
- Use community Gitea Helm chart (documented above)
- Manually configure via Web UI
- Create student user and repository manually

#### 2. ArgoCD Installation

**What's Missing**:
- ArgoCD Application manifests
- AppProject configuration
- RBAC policies
- Repository credentials setup
- Sync policies and hooks

**Where to Find**:
- Check main Hedgehog repository
- Check if ArgoCD is part of standard Hedgehog installation
- Check EMKC manifests

**Workaround**:
- Use official ArgoCD installation (documented above)
- Manually create Application CRD
- Configure repo credentials via CLI

#### 3. Prometheus/Grafana/Loki Deployment

**What's Missing**:
- Prometheus configuration for fabric-proxy scraping
- Grafana datasource provisioning
- Loki deployment manifests
- ServiceMonitor/PodMonitor CRDs for Prometheus Operator
- Default alerting rules

**Where to Find**:
- Check Hedgehog fabric repository for monitoring stack
- May be included in EMKC or deployed separately
- Check for Helm values files

**Workaround**:
- Use kube-prometheus-stack (documented above)
- Use Grafana LGTM stack Helm charts
- Manually configure scrape jobs and datasources

#### 4. Initial Repository Content

**What's Missing**:
- Template YAML files for `student/hedgehog-config` repository
- Example VPC, VPCAttachment, VPCPeering files
- Initial commit script

**Where to Find**:
- Check Hedgehog documentation for example YAMLs
- May be in a separate examples repository

**Workaround**:
- Create empty directory structure (documented above)
- Use examples from learning modules
- Extract YAML from module README files

#### 5. Telemetry Configuration

**What's Missing**:
- Complete Fabricator telemetry patch file
- Alloy agent configuration templates
- Remote write endpoints for Prometheus/Loki

**What Was Found**:
- Configuration structure in `/reference/docs/docs/install-upgrade/config.md`
- Example configuration snippets

**Workaround**:
- Use configuration structure from docs
- Adapt URLs to match actual service endpoints
- Apply via `kubectl patch fabricator`

### Recommended Next Steps

1. **Clone Main Hedgehog Repositories**:
   ```bash
   git clone https://github.com/githedgehog/fabric.git
   git clone https://github.com/githedgehog/fabricator.git
   ```

2. **Search for Monitoring Stack**:
   ```bash
   cd fabric
   find . -name "*prometheus*" -o -name "*grafana*" -o -name "*loki*"
   find . -name "*gitea*" -o -name "*argocd*"
   ```

3. **Check EMKC Setup**:
   - Review hhfab source code for EMKC initialization
   - Check if services are deployed during `hhfab init` or `hhfab vlab up`
   - Look for Helm charts in fabric repository

4. **Consult Hedgehog Documentation**:
   - https://docs.hedgehog.cloud/latest/install-upgrade/install/
   - https://docs.hedgehog.cloud/latest/vlab/overview/
   - Check for monitoring/observability sections

5. **Community/Support**:
   - Hedgehog Slack/Discord
   - GitHub Issues
   - Direct inquiry to Hedgehog team

### Alternative: Use Hedgehog's Built-in Stack

If the monitoring stack is already included in the Hedgehog installation:

```bash
# Check for existing services after VLAB is up
kubectl get svc -A | grep -E 'prometheus|grafana|loki|gitea|argocd'

# If found, just configure access and credentials
# Port-forward to access from host
kubectl port-forward -n <namespace> svc/<service> <local-port>:<service-port>
```

---

## Appendix A: Complete Credential Reference

| Service | URL | Username | Password | Notes |
|---------|-----|----------|----------|-------|
| Prometheus | http://localhost:9090 | N/A | N/A | No authentication |
| Grafana | http://localhost:3000 | admin | prom-operator | Web UI and API |
| Gitea | http://localhost:3001 | student | hedgehog123 | Student account |
| ArgoCD | http://localhost:8080 | admin | qV7hX0NMroAUhwoZ | Web UI and CLI |
| VLAB Switches | (via `hhfab vlab ssh`) | (default) | (default) | Check hhfab docs |

---

## Appendix B: Port Reference

| Port | Service | Protocol | Purpose |
|------|---------|----------|---------|
| 3000 | Grafana | HTTP | Dashboard UI |
| 3001 | Gitea | HTTP | Git repository hosting |
| 3100 | Loki | HTTP | Log ingestion API |
| 8080 | ArgoCD | HTTP | GitOps UI and API |
| 9090 | Prometheus | HTTP | Metrics query API and UI |
| 9100 | Prometheus | HTTP | Remote write endpoint |
| 31028 | fabric-proxy | HTTP | Metrics aggregation |

---

## Appendix C: Grafana Dashboard Files

**Location**: `/home/ubuntu/afewell-hh/hh-learn/reference/docs/docs/user-guide/boards/`

**Files**:
1. `grafana_fabric.json` - BGP fabric monitoring
2. `grafana_interfaces.json` - Interface state and traffic
3. `grafana_platform.json` - Hardware health (PSU, fans, temp)
4. `grafana_logs.json` - Syslog aggregation
5. `grafana_crm.json` - ASIC critical resources
6. `grafana_node_exporter.json` - Linux system metrics

**Import Instructions**:
```bash
# Via Grafana UI
# 1. Login to Grafana (http://localhost:3000)
# 2. Click "+" → "Import"
# 3. Upload JSON file
# 4. Select datasource: Prometheus (UID: prom)
# 5. Click "Import"

# Repeat for all 6 dashboards
```

---

## Appendix D: Key Configuration Values

### Telemetry
- **Scrape Interval**: 120 seconds (2 minutes)
- **Prometheus Retention**: 15 days
- **Kubernetes Events Retention**: 1 hour

### Reserved VLANs
- **Range**: 1020-1029
- **Purpose**: System reserved
- **Student Guidance**: Avoid when manually specifying VLANs

### Default Namespaces
- **Fabric Resources**: `fab`
- **VPCs**: `default` (or custom)
- **Monitoring**: `monitoring` (if using kube-prometheus-stack)
- **Gitea**: `gitea` (if using Helm chart)
- **ArgoCD**: `argocd`

---

## Appendix E: Troubleshooting

### Common Setup Issues

**1. Gitea Not Accessible**:
```bash
# Check Gitea pod status
kubectl get pods -n gitea

# Check service
kubectl get svc -n gitea

# Port-forward if needed
kubectl port-forward -n gitea svc/gitea-http 3001:3000
```

**2. ArgoCD Can't Reach Gitea**:
```bash
# Verify Gitea service is accessible from ArgoCD namespace
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl -v http://gitea-http.gitea.svc.cluster.local:3000/api/v1/version

# Add repository with in-cluster URL
argocd repo add http://gitea-http.gitea.svc.cluster.local:3000/student/hedgehog-config.git
```

**3. Grafana Dashboards Show "No Data"**:
```bash
# Verify Prometheus datasource
# Grafana → Configuration → Data Sources → Prometheus
# Click "Test" - should be successful

# Verify Prometheus is scraping fabric-proxy
# http://localhost:9090/targets
# fabric-proxy should be "UP"

# Check if metrics exist in Prometheus
# http://localhost:9090/graph
# Query: up{job="fabric-proxy"}
```

**4. No Metrics from Switches**:
```bash
# Check Alloy agent on switch
hhfab vlab ssh leaf-01
systemctl status alloy
journalctl -u alloy --since "5 minutes ago"

# Check Fabricator config
kubectl get fabricator default -n fab -o yaml | grep -A 30 defaultAlloyConfig

# Verify fabric-proxy is receiving metrics
kubectl logs -n fab deployment/fabric-proxy --tail=100
```

**5. ArgoCD Sync Fails**:
```bash
# Check ArgoCD application status
argocd app get hedgehog-config

# View sync errors
kubectl get application hedgehog-config -n argocd -o yaml | grep -A 20 status

# Check controller logs for errors
kubectl logs -n fab deployment/fabric-controller-manager --tail=200
```

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-07 | Initial document created from pathway content analysis |

---

**End of Document**
