# Hedgehog Lab Appliance - Frequently Asked Questions (FAQ)

Common questions and answers about the Hedgehog Lab Appliance.

## Table of Contents

- [General Questions](#general-questions)
- [Installation and Setup](#installation-and-setup)
- [Usage and Features](#usage-and-features)
- [Technical Questions](#technical-questions)
- [Troubleshooting](#troubleshooting)
- [Development and Contribution](#development-and-contribution)

## General Questions

### What is the Hedgehog Lab Appliance?

The Hedgehog Lab Appliance is a pre-configured virtual machine that provides a complete learning environment for Hedgehog Fabric. It includes:

- **Hedgehog Virtual Lab (VLAB):** A simulated 7-switch network topology
- **Kubernetes cluster:** k3d-based cluster for running services
- **GitOps stack:** ArgoCD and Gitea for configuration management (future sprint)
- **Observability stack:** Prometheus, Grafana, and Loki for monitoring
- **Command-line tools:** kubectl, helm, docker, and Hedgehog-specific utilities

### Who is this appliance for?

- **Students** learning Hedgehog Fabric and network automation
- **Engineers** exploring Hedgehog technology before deployment
- **Workshop participants** in instructor-led training
- **Developers** building integrations with Hedgehog
- **Anyone** interested in modern data center networking

### What are the system requirements?

**Minimum:**
- 4-core CPU with virtualization support
- 20 GB RAM (4 GB host + 16 GB VM)
- 120 GB free disk space

**Recommended:**
- 8-core CPU
- 32 GB RAM (16 GB host + 16 GB VM)
- 150 GB SSD storage

See [Installation Guide](INSTALL.md#system-requirements) for details.

### Is this free?

Yes, the Hedgehog Lab Appliance is free and open source under the Apache 2.0 license.

### What's the difference between Standard and Pre-warmed builds?

| Feature | Standard Build | Pre-warmed Build |
|---------|----------------|------------------|
| **Download size** | 15-20 GB | 80-100 GB |
| **First boot time** | 15-20 minutes | 2-3 minutes |
| **Initialization** | Full setup on first boot | Already configured |
| **Use case** | Self-paced learning | Workshops, events |
| **Distribution** | Direct download | USB drives, local network |

**Standard build** downloads smaller but takes longer to initialize. It fetches container images and configures everything on first boot.

**Pre-warmed build** is much larger but ready almost immediately. All container images are pre-pulled and services are pre-configured.

## Installation and Setup

### Which virtualization platform should I use?

Both **VMware** and **VirtualBox** are supported:

- **VMware Workstation/Fusion:** Better performance, commercial product
- **VirtualBox:** Free and open source, good performance
- **VMware ESXi/vSphere:** For enterprise/lab environments

Choose based on what you already have or prefer. Both work well.

### Can I run this on Apple Silicon (M1/M2/M3)?

Not currently. The appliance is built for x86_64 architecture. ARM64 support is planned for a future release.

**Workarounds:**
- Use a cloud-based VM (AWS, GCP, Azure)
- Use an x86_64 machine for the lab

### How much disk space do I really need?

**Host computer:**
- Downloaded OVA: 15-20 GB (standard) or 80-100 GB (pre-warmed)
- Extracted VM: Same size as OVA
- Total: ~30-40 GB for standard, ~160-200 GB for pre-warmed

**Inside the VM:**
- Base OS and tools: 10 GB
- Container images: 20-30 GB
- Working space: 30-40 GB
- Logs and data: 10-20 GB

SSD storage is highly recommended for good performance.

### Do I need internet access?

**During first boot:** Yes (standard build only)
- Downloads container images (5-10 GB)
- Pulls Helm charts
- Initializes services

**After initialization:** No
- All components run locally
- Internet only needed for updates or accessing external resources

**Pre-warmed build:** Internet helpful but not required for basic functionality.

### Can I run multiple instances?

Yes! You can import the OVA multiple times with different names. Each instance is independent.

**Considerations:**
- Each instance needs full resources (8 CPU, 16 GB RAM, 100 GB disk)
- Host computer must have sufficient capacity
- Each instance uses different ports or IP addresses

### How do I update the appliance?

Currently, updates are manual:

1. Download new OVA version
2. Import as new VM
3. Export data from old VM if needed
4. Delete old VM

**Future versions** will include an update mechanism.

## Usage and Features

### How do I access the services?

From your host computer's web browser:

- **Grafana:** http://localhost:3000 (admin/admin)
- **ArgoCD:** http://localhost:8080 (admin/[get password])
- **Gitea:** http://localhost:3001 (gitea_admin/admin123)

See [Quick Start Guide](QUICKSTART.md#accessing-services) for details.

### How do I get the ArgoCD password?

```bash
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d; echo
```

**Note:** ArgoCD deployment is planned for a future sprint and may not be available in the current MVP.

### What is VLAB?

VLAB (Virtual Lab) is a containerized network simulation that provides a complete Hedgehog Fabric topology:

- **7 switches:** 2 spines, 4 leaves, 1 control node
- **SONiC network OS:** Industry-standard network operating system
- **Docker containers:** Each switch runs in its own container
- **Realistic networking:** Full L2/L3 functionality

Access switches with:
```bash
docker exec -it vlab-leaf-1 bash
```

### Can I customize the VLAB topology?

Not in v0.1.0 MVP. Custom topologies and scenario management are planned for v0.3.0.

**Future features:**
- Custom switch counts
- Different network topologies
- Multiple simultaneous topologies
- Scenario-based configurations

### Does my data persist across reboots?

Yes! All data is persistent:

- ✓ Git repositories in Gitea
- ✓ Grafana dashboards and data sources
- ✓ ArgoCD applications and settings
- ✓ VLAB switch configurations
- ✓ Kubernetes resources and deployments

**Exception:** If you delete and recreate the k3d cluster, Kubernetes resources are lost.

### Can I take snapshots?

Yes! Use VM snapshots in VMware or VirtualBox:

- **Before experiments:** Take snapshot for easy rollback
- **After configuration:** Save working states
- **Before updates:** Safety net for changes

Snapshots are stored by the hypervisor, outside the VM.

### How do I reset the lab to default state?

**Soft reset** (keep data):
```bash
# Restart services
kubectl rollout restart deployment -A
```

**Hard reset** (destroy everything):
```bash
# Delete k3d cluster
k3d cluster delete k3d-observability

# Remove VLAB
docker stop $(docker ps -q --filter "name=vlab-")
docker rm $(docker ps -aq --filter "name=vlab-")

# Re-initialize
sudo rm /var/lib/hedgehog-lab/initialized
sudo systemctl restart hedgehog-lab-init
```

**Complete reset:** Revert to a VM snapshot or re-import the OVA.

## Technical Questions

### What Linux distribution is used?

**Ubuntu 22.04 LTS** (Jammy Jellyfish)

- Long-term support until 2027
- Wide compatibility
- Excellent documentation

### What Kubernetes distribution is used?

**k3s via k3d**

- k3d: k3s in Docker
- Lightweight Kubernetes (uses less resources than full Kubernetes)
- Production-ready
- Fast startup and teardown

### What versions of tools are included?

As of v0.1.0:

- Docker: Latest stable
- k3d: v5.7.4
- kubectl: v1.31.1
- Helm: v3.latest
- ArgoCD CLI: v2.12.4
- Prometheus: Latest (via kube-prometheus-stack)
- Grafana: Latest (via kube-prometheus-stack)

See `hh-lab info` for detailed version information.

### Can I install additional software?

Yes! You have full `sudo` access (password: `hhlab`).

```bash
# Update package lists
sudo apt update

# Install packages
sudo apt install <package-name>

# Install Python packages
pip install <package>

# Install Go packages
go install <package>
```

**Note:** Additional software may increase disk usage.

### How do I SSH into the VM?

**VirtualBox with NAT:**
Add SSH port forwarding:
- Host Port: 2222
- Guest Port: 22

```bash
ssh -p 2222 hhlab@localhost
```

**VMware or Bridged Mode:**
```bash
# Find VM IP
# (inside VM)
ip addr show | grep "inet "

# From host
ssh hhlab@<VM_IP>
```

**Password:** `hhlab`

### Can I use this in production?

**No.** This appliance is designed for **learning and development only**:

- Default passwords
- Minimal security hardening
- Single-node setup
- Not HA (High Availability)

For production Hedgehog Fabric deployments, follow official installation guides.

### What network ports are used?

**Exposed to host:**
- 3000: Grafana
- 8080: ArgoCD HTTP
- 8443: ArgoCD HTTPS (if configured)
- 3001: Gitea
- 2222: Gitea SSH

**Internal only:**
- 6443: Kubernetes API
- 9090: Prometheus
- Various: Service-specific ports

## Troubleshooting

### Why is initialization taking so long?

First boot initialization can take 15-20 minutes (standard build):

- Network detection: 1-2 minutes
- k3d cluster creation: 3-5 minutes
- VLAB initialization: 5-10 minutes
- Service deployment: 5-10 minutes

**Monitor progress:**
```bash
hh-lab logs --follow
```

See [Troubleshooting Guide](TROUBLESHOOTING.md#issue-initialization-takes-too-long) for details.

### Services are unreachable from my browser

**Common causes:**
1. Services still initializing - check `hh-lab status`
2. VirtualBox port forwarding not configured
3. Firewall blocking ports
4. Wrong URL (use `localhost` not `127.0.0.1` on some systems)

See [Troubleshooting Guide](TROUBLESHOOTING.md#issue-cannot-access-web-services) for solutions.

### kubectl commands don't work

**Solution:**
```bash
# Ensure kubeconfig is set
export KUBECONFIG=~/.kube/config

# Check cluster is running
k3d cluster list

# Use correct context
kubectl config use-context k3d-k3d-observability
```

See [Troubleshooting Guide](TROUBLESHOOTING.md#issue-kubectl-commands-fail) for more.

### The VM is very slow

**Common causes:**
- Insufficient host resources
- Running on HDD instead of SSD
- Hardware virtualization not enabled
- Other VMs or heavy apps running

**Solutions:**
- Close other applications
- Enable VT-x/AMD-V in BIOS
- Move VM to SSD
- Allocate more resources

See [Troubleshooting Guide](TROUBLESHOOTING.md#performance-issues) for details.

## Development and Contribution

### Can I contribute to this project?

Yes! Contributions are welcome:

- Bug reports and feature requests: [GitHub Issues](https://github.com/afewell-hh/labapp/issues)
- Code contributions: [Pull Requests](https://github.com/afewell-hh/labapp/pulls)
- Documentation improvements
- Testing and feedback

See [Contributing Guide](../CONTRIBUTING.md) for guidelines.

### How is the appliance built?

The appliance is built with **Packer** using infrastructure-as-code:

- Base: Ubuntu 22.04 Server ISO
- Provisioning: Bash scripts
- Automation: GitHub Actions CI/CD
- Output: OVA file for VMware/VirtualBox

See [Build Guide](build/BUILD_GUIDE.md) for details.

### Can I build my own custom version?

Yes! The entire build process is open source:

```bash
# Clone repository
git clone https://github.com/afewell-hh/labapp.git
cd labapp

# Build standard version
make build-standard

# Customize by editing:
# - packer/*.pkr.hcl (Packer templates)
# - packer/scripts/*.sh (Provisioning scripts)
```

See [Build Guide](build/BUILD_GUIDE.md) for comprehensive instructions.

### What's on the roadmap?

**v0.1.0 (Current - MVP):**
- ✓ Standard build pipeline
- ✓ Basic orchestrator
- ✓ Core services (k3d, VLAB, observability)

**v0.2.0 (Planned):**
- Pre-warmed build
- GitOps stack (ArgoCD, Gitea)
- Improved documentation

**v0.3.0 (Planned):**
- Scenario management
- Multiple topologies
- Scenario switching

**v0.4.0 (Planned):**
- Checkpoint system
- Save/restore lab state

**v1.0.0 (Planned):**
- Web UI
- Comprehensive testing
- Production-ready features

See [Roadmap](../ROADMAP.md) for full timeline.

### Where can I get help?

1. **Documentation:**
   - [Installation Guide](INSTALL.md)
   - [Quick Start Guide](QUICKSTART.md)
   - [Troubleshooting Guide](TROUBLESHOOTING.md)
   - This FAQ

2. **Community:**
   - [GitHub Issues](https://github.com/afewell-hh/labapp/issues) - Bug reports
   - [GitHub Discussions](https://github.com/afewell-hh/labapp/discussions) - Q&A, ideas
   - Project documentation - Additional guides

3. **Command-line:**
   ```bash
   hh-lab --help
   hh-lab status
   hh-lab logs
   ```

## Still Have Questions?

If your question isn't answered here:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Search [GitHub Issues](https://github.com/afewell-hh/labapp/issues)
3. Ask in [GitHub Discussions](https://github.com/afewell-hh/labapp/discussions)
4. Open a new issue with the `question` label

We're here to help you succeed with Hedgehog Fabric!
