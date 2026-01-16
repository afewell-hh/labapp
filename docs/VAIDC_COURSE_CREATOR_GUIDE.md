# Hedgehog Virtual AI Data Center (vAIDC) - Course Creator Guide

> **Document Version:** 1.0
> **Last Updated:** January 2026
> **Based on:** Live vAIDC Build (labapp-0-21)

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [VLAB Environment](#2-vlab-environment)
3. [EMC Cluster (k3d-k3d-observability)](#3-emc-cluster-k3d-k3d-observability)
4. [Observability Stack](#4-observability-stack)
5. [GitOps Stack](#5-gitops-stack)
6. [Student Access Methods](#6-student-access-methods)
7. [Lab Exercise Capabilities](#7-lab-exercise-capabilities)
8. [Technical Reference](#8-technical-reference)
9. [Course Creator Guidelines](#9-course-creator-guidelines)
10. [Appendices](#appendices)

---

## 1. Executive Overview

### What is the vAIDC?

The Hedgehog Virtual AI Data Center (vAIDC) is a pre-configured GCP VM image that provides a complete, production-like data center networking environment for hands-on training. It combines a virtual network fabric running Hedgehog Open Network Fabric with an observability and GitOps platform.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         GCP Virtual Machine (vAIDC)                              │
│                     Ubuntu 24.04 LTS | 32 vCPUs | 117GB RAM                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────┐  ┌──────────────────────────────────┐  │
│  │         VLAB Environment            │  │     EMC Cluster (k3d)            │  │
│  │  ┌─────────────────────────────┐    │  │  ┌────────────────────────────┐  │  │
│  │  │      Spine Switches (2)     │    │  │  │      Observability         │  │  │
│  │  │  ┌─────────┐  ┌─────────┐   │    │  │  │  ┌────────┐ ┌───────────┐  │  │  │
│  │  │  │spine-01 │  │spine-02 │   │    │  │  │  │Grafana │ │Prometheus │  │  │  │
│  │  │  └────┬────┘  └────┬────┘   │    │  │  │  │ :3000  │ │   :9090   │  │  │  │
│  │  │       │            │        │    │  │  │  └────────┘ └───────────┘  │  │  │
│  │  │       └─────┬──────┘        │    │  │  │  ┌────────────────────────┐│  │  │
│  │  │  ┌──────────┼───────────┐   │    │  │  │  │         Loki          ││  │  │
│  │  │  │          │           │   │    │  │  │  │   (Log Aggregation)   ││  │  │
│  │  │  │    Leaf Switches (5) │   │    │  │  │  └────────────────────────┘│  │  │
│  │  │  │ ┌───┐┌───┐┌───┐┌───┐┌───┐│   │  │  └────────────────────────────┘  │  │
│  │  │  │ │L01││L02││L03││L04││L05││   │  │                                   │  │
│  │  │  │ └─┬─┘└─┬─┘└─┬─┘└─┬─┘└─┬─┘│   │  │  ┌────────────────────────────┐  │  │
│  │  │  └───┼────┼────┼────┼────┼──┘   │  │  │        GitOps              │  │  │
│  │  │      │    │    │    │    │      │  │  │  ┌────────┐  ┌──────────┐  │  │  │
│  │  │  ┌───┴────┴────┴────┴────┴───┐  │  │  │  │ ArgoCD │  │  Gitea   │  │  │  │
│  │  │  │      Servers (10)         │  │  │  │  │ :8080  │  │  :3001   │  │  │  │
│  │  │  │  S01-S02: MCLAG           │  │  │  │  └────────┘  └──────────┘  │  │  │
│  │  │  │  S03-S04: Single-homed    │  │  │  └────────────────────────────┘  │  │
│  │  │  │  S05-S06: ESLAG           │  │  │                                   │  │
│  │  │  │  S07-S10: Single-homed    │  │  └──────────────────────────────────┘  │
│  │  │  └───────────────────────────┘  │                                        │
│  │  │                                  │                                        │
│  │  │  ┌───────────────────────────┐  │                                        │
│  │  │  │ Control Node (control-1)  │  │                                        │
│  │  │  │ Flatcar Linux | K3s       │  │                                        │
│  │  │  │ Hedgehog Fabric Manager   │  │                                        │
│  │  │  └───────────────────────────┘  │                                        │
│  │  └─────────────────────────────────┘                                        │
│  │                                                                              │
│  │  Management Network: 172.30.0.0/21 (hhbr bridge)                            │
│  │  Host IP on hhbr: 172.30.0.2                                                │
│  │                                                                              │
│  └──────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                     Access Points                                            ││
│  │  SSH: 22 | RDP: 3389 | Grafana: 3000 | Gitea: 3001 | ArgoCD: 8080 | Prom: 9090│
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description | Primary Use Case |
|-----------|-------------|------------------|
| **VLAB** | Virtual network fabric with 7 SONiC switches and 10 servers | Network configuration, VPC provisioning, traffic engineering |
| **Control Node** | Flatcar Linux VM running K3s + Hedgehog Fabric Manager | Fabric orchestration, Kubernetes API for network resources |
| **EMC Cluster** | k3d Kubernetes cluster hosting observability/GitOps tools | Monitoring, logging, GitOps workflows |
| **XFCE Desktop** | Lightweight Linux desktop accessible via RDP | GUI-based labs, browser access to dashboards |

---

## 2. VLAB Environment

### 2.1 Switch Inventory

The VLAB deploys a spine-leaf topology with 7 virtual SONiC switches:

| Switch | Role | Description | Groups |
|--------|------|-------------|--------|
| spine-01 | Spine | VS-06 | - |
| spine-02 | Spine | VS-07 | - |
| leaf-01 | Server-Leaf | VS-01 MCLAG 1 | mclag-1 |
| leaf-02 | Server-Leaf | VS-02 MCLAG 1 | mclag-1 |
| leaf-03 | Server-Leaf | VS-03 ESLAG 1 | eslag-1 |
| leaf-04 | Server-Leaf | VS-04 ESLAG 1 | eslag-1 |
| leaf-05 | Server-Leaf | VS-05 | - |

**Switch Resources (per switch):**
- CPU: 4 vCPUs
- RAM: 5120 MB
- Disk: 50 GB

### 2.2 Server Inventory

The VLAB includes 10 virtual servers with various connection types:

| Server | Connection Type | Leaf Switches |
|--------|-----------------|---------------|
| server-01 | MCLAG | leaf-01, leaf-02 |
| server-02 | MCLAG | leaf-01, leaf-02 |
| server-03 | Unbundled | leaf-01 |
| server-04 | Bundled | leaf-02 |
| server-05 | ESLAG | leaf-03, leaf-04 |
| server-06 | ESLAG | leaf-03, leaf-04 |
| server-07 | Unbundled | leaf-03 |
| server-08 | Bundled | leaf-04 |
| server-09 | Unbundled | leaf-05 |
| server-10 | Bundled | leaf-05 |

**Server Resources (per server):**
- CPU: 2 vCPUs
- RAM: 768 MB
- Disk: 10 GB

### 2.3 Network Topology

```
                    ┌─────────────┐     ┌─────────────┐
                    │  spine-01   │     │  spine-02   │
                    │ (10 ports)  │     │ (10 ports)  │
                    └──────┬──────┘     └──────┬──────┘
                           │                   │
         ┌─────────────────┼───────────────────┼─────────────────┐
         │                 │                   │                 │
    ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
    │ leaf-01 │  │ leaf-02 │  │ leaf-03 │  │ leaf-04 │  │ leaf-05 │
    │ (MCLAG) │──│ (MCLAG) │  │ (ESLAG) │──│ (ESLAG) │  │         │
    └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
         │            │            │            │            │
    ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
    │ S01,S02 │  │   S04   │  │ S05,S06 │  │   S08   │  │ S09,S10 │
    │   S03   │  │         │  │   S07   │  │         │  │         │
    └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘

Connection Types:
  ══════ MCLAG peer link (leaf-01 <-> leaf-02)
  ────── Fabric uplinks to spines
```

### 2.4 Management Network

- **Bridge Name:** hhbr
- **Network:** 172.30.0.0/21
- **Host IP:** 172.30.0.2
- **Control Node IP:** 172.30.0.5

### 2.5 hhfab CLI Reference

The Hedgehog Fabricator CLI (`hhfab`) is the primary tool for VLAB management:

```bash
# View switch/agent status
kubectl get agent                  # List all fabric agents
kubectl get switch                 # List all switches
kubectl get connection             # List all connections

# SSH to switches
hhfab vlab ssh -n leaf-01          # SSH to a switch
hhfab vlab serial -n leaf-01       # Serial console access
hhfab vlab seriallog -n leaf-01    # View serial console log

# VPC operations
kubectl get vpc                    # List VPCs
kubectl get vpcattachment          # List VPC attachments

# Wait for switches
hhfab vlab wait-switches           # Wait for all switches to be ready
hhfab vlab inspect-switches        # Inspect all switches

# VLAB management
tmux attach -t hhfab-vlab          # Attach to VLAB tmux session
```

---

## 3. EMC Cluster (k3d-k3d-observability)

### 3.1 Cluster Overview

The EMC (Edge Management Controller) cluster is a k3d-based Kubernetes cluster running on the vAIDC host. It provides the observability and GitOps platform.

**Cluster Details:**
- **Type:** k3d (k3s in Docker)
- **Nodes:** 1 server + 2 agents
- **kubectl context:** `k3d-k3d-observability`

### 3.2 Namespaces

| Namespace | Purpose | Key Workloads |
|-----------|---------|---------------|
| `monitoring` | Observability stack | Grafana, Prometheus, Loki, Alertmanager |
| `argocd` | GitOps platform | ArgoCD server, application controller |
| `gitea` | Git repository hosting | Gitea server |
| `kube-system` | Kubernetes infrastructure | CoreDNS, Traefik, metrics-server |

### 3.3 Accessing the Cluster

```bash
# Switch to EMC cluster context
kubectl config use-context k3d-k3d-observability

# List all pods
kubectl --context k3d-k3d-observability get pods -A

# Check services
kubectl --context k3d-k3d-observability get svc -A
```

---

## 4. Observability Stack

### 4.1 Grafana

**Access:**
- **URL:** http://localhost:3000
- **Username:** admin
- **Password:** admin

**Features:**
- Pre-configured Kubernetes dashboards
- Prometheus data source configured
- Loki data source for log exploration

**Use in Labs:**
- Monitor cluster resource utilization
- View Kubernetes workload metrics
- Explore logs from all namespaces

### 4.2 Prometheus

**Access:**
- **URL:** http://localhost:9090

**Features:**
- Automatic service discovery
- Kubernetes metrics collection
- Node exporter metrics

**Prometheus Queries for Labs:**
```promql
# CPU usage by pod
sum(rate(container_cpu_usage_seconds_total{namespace!=""}[5m])) by (pod)

# Memory usage by namespace
sum(container_memory_usage_bytes{namespace!=""}) by (namespace)

# Network traffic
sum(rate(container_network_receive_bytes_total[5m])) by (pod)
```

### 4.3 Loki

Loki provides log aggregation for the EMC cluster.

**Access via Grafana:**
1. Navigate to Grafana → Explore
2. Select "Loki" data source
3. Use LogQL queries

**Example LogQL Queries:**
```logql
# All logs from argocd namespace
{namespace="argocd"}

# Error logs from monitoring
{namespace="monitoring"} |= "error"

# Logs from specific pod
{pod="argocd-server-856946696f-x5545"}
```

### 4.4 Alertmanager

**Access:**
- Internal service: kube-prometheus-stack-alertmanager:9093

**Purpose:**
- Alert routing and grouping
- Notification management (not externally configured by default)

---

## 5. GitOps Stack

### 5.1 ArgoCD

**Access:**
- **URL:** http://localhost:8080
- **Username:** admin
- **Password:** paCHQ6AN2FhScB2O

**Features:**
- GitOps-based application deployment
- Sync status visualization
- Application health monitoring

**CLI Access:**
```bash
# Login to ArgoCD CLI (if installed)
argocd login localhost:8080 --username admin --password paCHQ6AN2FhScB2O --insecure

# List applications
argocd app list
```

### 5.2 Gitea

**Access:**
- **URL:** http://localhost:3001
- **Student Account:**
  - Username: student01
  - Password: hedgehog123
- **Admin Account:**
  - Username: gitea_admin
  - Password: admin123

**Pre-configured Repository:**
- **Clone URL:** http://localhost:3001/student/hedgehog-config.git

**Use in Labs:**
- Store Kubernetes manifests
- ArgoCD application source
- Version control for lab configurations

---

## 6. Student Access Methods

### 6.1 SSH Access

**Direct SSH to vAIDC Host:**
```bash
# From local machine (requires GCP access)
gcloud compute ssh --zone "ZONE" "INSTANCE_NAME" --project "PROJECT"

# Or direct SSH if IP is known
ssh ubuntu@<EXTERNAL_IP>
```

**SSH to VLAB Switches:**
```bash
# From vAIDC host
hhfab vlab ssh -n leaf-01    # SSH to leaf-01
hhfab vlab ssh -n spine-01   # SSH to spine-01
```

**SSH to Control Node:**
```bash
ssh -p 22000 core@localhost
# Password: Use key-based auth or password from fab.yaml
```

**SSH to VLAB Servers:**
```bash
# SSH ports 22001-22010 map to server-01 through server-10
ssh -p 22001 user@localhost   # server-01
ssh -p 22002 user@localhost   # server-02
# ... and so on
```

### 6.2 RDP Desktop Access

**Connection Details:**
- **Port:** 3389
- **Username:** ubuntu
- **Password:** HHLab.Admin!
- **Desktop Environment:** XFCE

**Features Available:**
- Firefox browser for web dashboards
- VS Code for editing
- Terminal for CLI access
- Full desktop experience

### 6.3 kubectl Access

Three Kubernetes contexts are configured:

| Context | Cluster | Use Case |
|---------|---------|----------|
| `vlab` (default) | VLAB Fabric | Managing VPCs, switches, connections |
| `k3d-k3d-observability` | EMC/Observability | Managing Grafana, ArgoCD, monitoring |
| `emc` | Same as k3d-k3d-observability | Alias for EMC cluster |

```bash
# List available contexts
kubectl config get-contexts

# Switch context
kubectl config use-context vlab
kubectl config use-context k3d-k3d-observability

# Use specific context without switching
kubectl --context vlab get vpc
kubectl --context k3d-k3d-observability get pods -n monitoring
```

---

## 7. Lab Exercise Capabilities

### 7.1 VPC Provisioning

**Create a VPC:**
```yaml
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPC
metadata:
  name: lab-vpc-1
  namespace: default
spec:
  subnets:
    default:
      subnet: 10.100.1.0/24
      gateway: 10.100.1.1
      vlan: 1001
```

```bash
kubectl apply -f vpc.yaml
kubectl get vpc
```

### 7.2 VPC Attachments

**Attach a server to a VPC:**
```yaml
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPCAttachment
metadata:
  name: server-01-vpc-1
  namespace: default
spec:
  vpc: lab-vpc-1
  subnet: default
  connection: server-01--mclag--leaf-01--leaf-02
```

### 7.3 VPC Peering

**Peer two VPCs:**
```yaml
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPCPeering
metadata:
  name: vpc1-to-vpc2
  namespace: default
spec:
  permit:
    - vpc: lab-vpc-1
    - vpc: lab-vpc-2
```

### 7.4 Observability Exercises

**Prometheus Exercises:**
- Write PromQL queries to analyze switch metrics
- Create custom Grafana dashboards
- Set up alert rules

**Logging Exercises:**
- Query Loki for switch logs
- Correlate log events with metrics
- Build log-based dashboards

### 7.5 GitOps Exercises

**ArgoCD Exercises:**
- Deploy applications from Gitea repository
- Configure auto-sync policies
- Implement progressive delivery patterns

### 7.6 Troubleshooting Scenarios

**Network Troubleshooting:**
```bash
# Check agent status
kubectl get agent -o wide

# Inspect switch configuration
hhfab vlab ssh -n leaf-01
# Then on switch: show running-config

# View connection status
kubectl get connection

# Check for applied configurations
kubectl get agent leaf-01 -o yaml
```

---

## 8. Technical Reference

### 8.1 Service Endpoints Summary

| Service | Port | Protocol | Access URL |
|---------|------|----------|------------|
| SSH (host) | 22 | SSH | Direct |
| RDP | 3389 | RDP | rdp://IP:3389 |
| Grafana | 3000 | HTTP | http://localhost:3000 |
| Gitea | 3001 | HTTP | http://localhost:3001 |
| ArgoCD | 8080 | HTTP | http://localhost:8080 |
| Prometheus | 9090 | HTTP | http://localhost:9090 |
| K3s API (vlab) | 6443 | HTTPS | Internal |
| K3d API (EMC) | 6550 | HTTPS | Internal |

### 8.2 VM Port Mapping

| Port Range | Purpose |
|------------|---------|
| 22000 | Control Node SSH |
| 22001-22010 | VLAB Servers SSH (server-01 to server-10) |
| 31000 | VLAB internal service |

### 8.3 Boot Sequence

1. **vlab-netfilter.service** - Disables bridge netfilter (critical for switch traffic)
2. **docker.service** - Starts Docker daemon
3. **hhfab-vlab-resume.service** - Starts VLAB in tmux session
4. **hhbr-ip.service** - Configures IP on hhbr bridge
5. **kubeconfig-merge.service** - Merges k3d kubeconfig
6. **argocd-port-fix.service** - Fixes ArgoCD port routing

### 8.4 Systemd Services

| Service | Purpose | Status |
|---------|---------|--------|
| hhfab-vlab-resume | Starts/resumes VLAB | Active |
| hhbr-ip | Configures hhbr bridge IP | Active |
| vlab-netfilter | Disables bridge netfilter | Active |
| kubeconfig-merge | Merges kubeconfigs | Oneshot |
| argocd-port-fix | Fixes ArgoCD ingress | Oneshot |
| xrdp | RDP server | Active |
| docker | Container runtime | Active |

### 8.5 File Locations

| Path | Description |
|------|-------------|
| `/home/ubuntu/hhfab/` | VLAB working directory |
| `/home/ubuntu/hhfab/fab.yaml` | Fabric configuration |
| `/home/ubuntu/hhfab/vlab/` | VLAB state directory |
| `/home/ubuntu/hhfab/vlab/vms/` | VM disk images and configs |
| `/home/ubuntu/.kube/config` | Merged kubeconfig |
| `/home/ubuntu/lab-info.yaml` | Lab credentials reference |
| `/var/log/hedgehog-lab/` | Service logs |
| `/usr/local/bin/hhfab` | hhfab CLI binary |

### 8.6 Credentials Summary

| Service | Username | Password |
|---------|----------|----------|
| RDP Desktop | ubuntu | HHLab.Admin! |
| Grafana | admin | admin |
| ArgoCD | admin | paCHQ6AN2FhScB2O |
| Gitea (student) | student01 | hedgehog123 |
| Gitea (admin) | gitea_admin | admin123 |
| Switch SSH | admin | (see fab.yaml) |
| Control Node | core | (SSH key auth) |

---

## 9. Course Creator Guidelines

### 9.1 Best Practices

**Lab Design:**
- Start labs with verification steps to ensure the environment is ready
- Provide clear expected outputs for each command
- Include troubleshooting sections for common issues

**Resource Considerations:**
- The vAIDC uses ~50GB RAM when all components are running
- Plan for 3-5 minute VLAB startup time after VM boot
- Switch agent synchronization takes ~30-60 seconds

**State Management:**
- VPCs and VPCAttachments persist across reboots
- Consider providing cleanup scripts for multi-session labs
- Use namespaces to isolate student work if needed

### 9.2 Recommended Lab Structure

```markdown
## Lab X: Title

### Objectives
- Objective 1
- Objective 2

### Prerequisites
- Verify VLAB is running: `kubectl get agent`
- All agents should show APPLIED status

### Tasks

#### Task 1: Description
1. Step 1
   ```bash
   command
   ```
   Expected output:
   ```
   output
   ```

2. Step 2...

### Verification
- Check 1
- Check 2

### Cleanup
```bash
kubectl delete vpc lab-vpc-1
```
```

### 9.3 Limitations

| Limitation | Description | Workaround |
|------------|-------------|------------|
| No external connectivity | VLAB servers cannot reach internet | Use usernet NICs for outbound |
| Single control node | No HA for fabric management | Acceptable for training |
| Virtual switches only | No hardware-specific features | Focus on concepts |
| Shared environment | No multi-tenancy | Use namespaces |

### 9.4 Recommended Tooling

Available on the vAIDC:
- `kubectl` (v1.35.0) - Kubernetes management
- `hhfab` (v0.43.1) - Hedgehog Fabricator CLI
- `helm` - Kubernetes package manager
- `k3d` - k3s in Docker management
- `docker` - Container runtime
- `jq` - JSON processor
- `curl`, `wget` - HTTP clients
- VS Code - IDE with terminal

---

## Appendices

### Appendix A: Service Inventory

**VLAB Kubernetes Resources (vlab context):**
```bash
kubectl api-resources | grep hedgehog
```

| Resource | Short Name | API Group | Description |
|----------|------------|-----------|-------------|
| agents | ag | agent.githedgehog.com | Switch agents |
| catalogs | - | agent.githedgehog.com | Agent catalogs |
| switches | sw | wiring.githedgehog.com | Switch definitions |
| switchgroups | sg | wiring.githedgehog.com | Switch groups (MCLAG, ESLAG) |
| connections | conn | wiring.githedgehog.com | Connection definitions |
| servers | srv | wiring.githedgehog.com | Server definitions |
| vpcs | - | vpc.githedgehog.com | VPC definitions |
| vpcattachments | vpcattach | vpc.githedgehog.com | VPC attachments |
| vpcpeerings | vpcpeer | vpc.githedgehog.com | VPC peerings |
| externals | ext | vpc.githedgehog.com | External networks |
| externalattachments | extattach | vpc.githedgehog.com | External attachments |
| dhcpsubnets | dhcp | dhcp.githedgehog.com | DHCP subnets |

### Appendix B: Infrastructure Details

**Host VM Specifications:**
- **OS:** Ubuntu 24.04.3 LTS (Noble Numbat)
- **Kernel:** 6.14.0-1020-gcp
- **Architecture:** x86_64
- **CPU:** Intel Xeon @ 2.20GHz (32 vCPUs, 16 cores)
- **RAM:** 117 GB
- **Disk:** 290 GB (SSD)
- **Virtualization:** KVM with nested virtualization

**Network Interfaces:**
| Interface | IP Address | Purpose |
|-----------|------------|---------|
| ens4 | 10.138.0.24/32 | GCP external |
| hhbr | 172.30.0.2/21 | VLAB management |
| docker0 | 172.17.0.1/16 | Docker default |
| br-* | 172.18.0.1/16 | k3d network |

### Appendix C: Systemd Service Details

**View service status:**
```bash
systemctl status hhfab-vlab-resume
systemctl status hhbr-ip
systemctl status vlab-netfilter
```

**View service logs:**
```bash
journalctl -u hhfab-vlab-resume -f
cat /var/log/hedgehog-lab/vlab-resume.log
```

**Service dependency order:**
```
sysinit.target
└── vlab-netfilter.service
    └── network-online.target
        └── docker.service
            └── hhfab-vlab-resume.service
                ├── hhbr-ip.service
                ├── kubeconfig-merge.service
                └── argocd-port-fix.service
```

### Appendix D: Troubleshooting Guide

**VLAB Not Starting:**
```bash
# Check service status
systemctl status hhfab-vlab-resume

# View tmux session
tmux attach -t hhfab-vlab

# Check logs
cat /var/log/hedgehog-lab/vlab-resume.log

# Manually start VLAB
cd /home/ubuntu/hhfab
hhfab vlab up --controls-restricted=false --kill-stale
```

**Switches Not Ready:**
```bash
# Wait for switches
hhfab vlab wait-switches

# Check agent status
kubectl get agent

# SSH to specific switch
hhfab vlab ssh -n leaf-01
```

**k3d Cluster Issues:**
```bash
# Check k3d clusters
k3d cluster list

# View container status
docker ps | grep k3d

# Check k3d logs
docker logs k3d-k3d-observability-serverlb
```

**ArgoCD Not Accessible:**
```bash
# Check ArgoCD pods
kubectl --context k3d-k3d-observability get pods -n argocd

# Verify port fix applied
systemctl status argocd-port-fix

# Restart port fix if needed
sudo systemctl restart argocd-port-fix
```

**Services Not Responding:**
```bash
# Check listening ports
ss -tlnp | grep -E '3000|3001|8080|9090'

# Verify Docker containers
docker ps

# Check k3d services
kubectl --context k3d-k3d-observability get svc -A
```

---

## Quick Reference Card

### Essential Commands

```bash
# VLAB Status
kubectl get agent                   # Check switch agents
kubectl get switch                  # List switches
kubectl get connection              # List connections
tmux attach -t hhfab-vlab           # View VLAB console

# VPC Operations
kubectl get vpc                     # List VPCs
kubectl get vpcattachment           # List attachments
kubectl apply -f vpc.yaml           # Create VPC

# Switch Access
hhfab vlab ssh -n leaf-01           # SSH to switch
hhfab vlab wait-switches            # Wait for ready

# Context Switching
kubectl config use-context vlab               # Fabric cluster
kubectl config use-context k3d-k3d-observability  # EMC cluster

# Service Access
http://localhost:3000    # Grafana (admin/admin)
http://localhost:3001    # Gitea (student01/hedgehog123)
http://localhost:8080    # ArgoCD (admin/paCHQ6AN2FhScB2O)
http://localhost:9090    # Prometheus
```

---

*This document was generated from the live vAIDC environment and reflects the actual running configuration.*
