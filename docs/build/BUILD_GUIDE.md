# Hedgehog Lab Appliance - Build Guide

This guide explains how to build the Hedgehog Lab Appliance from source using Packer.

## Table of Contents

- [Build Options](#build-options)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Process](#build-process)
- [Build Configuration](#build-configuration)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

## Build Options

The Hedgehog Lab Appliance supports two build types (see [ADR-001](../adr/001-dual-build-pipeline.md)):

### Standard Build
- **Use Case**: Self-paced learning, general distribution
- **Size**: ~15-20GB compressed
- **First Boot**: 15-20 minute initialization
- **Build Environment**: Local machine or GitHub Actions
- **Disk Required**: 150GB

### Pre-Warmed Build
- **Use Case**: Workshops, events requiring immediate access
- **Size**: ~80-100GB compressed
- **First Boot**: 2-3 minutes (just starts services)
- **Build Environment**: Requires nested virtualization (KVM)
- **Disk Required**: 300GB+
- **Build Time**: 60-90 minutes

**For Pre-Warmed Builds with Limited Resources:**

If your development machine lacks the disk space or nested virtualization support for pre-warmed builds, use the **AWS Metal Instance Build System**:

- **AWS Automated Builds**: See [AWS Metal Build Guide](AWS_METAL_BUILD.md)
- **Cost**: ~$15-20 per build (pay-per-use)
- **Requirements**: AWS account, Terraform installed
- **Advantages**: No local resource requirements, automatic cleanup, built-in safety controls

```bash
# Launch AWS metal instance build
./scripts/launch-metal-build.sh main
```

The remainder of this guide covers **local builds** for both standard and pre-warmed variants.

## Prerequisites

### System Requirements

**Hardware:**
- CPU: Modern x86_64 processor with KVM support
- RAM: 32GB (16GB for VM + overhead)
- Disk: 150GB free space
- Network: Stable internet connection

**Software:**
- Ubuntu 22.04 LTS (recommended) or similar Linux distribution
- Packer 1.11.2 or later
- QEMU/KVM with hardware acceleration
- Git

### Installing Dependencies

#### Ubuntu/Debian

```bash
# Install Packer
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update
sudo apt-get install -y packer

# Install QEMU/KVM
sudo apt-get install -y qemu-system-x86 qemu-utils

# Verify KVM support
egrep -c '(vmx|svm)' /proc/cpuinfo  # Should be > 0
```

#### Using Make

```bash
make install-deps
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/hedgehog-lab-appliance.git
cd hedgehog-lab-appliance

# Validate the Packer template
make validate

# Build the standard appliance
make build-standard

# Find the output
ls -lh output-hedgehog-lab-standard/
```

## Build Process

### Build Pipeline Types

The Hedgehog Lab Appliance supports two build pipelines optimized for different use cases:

1. **Standard Build**: ~15-20GB OVA that performs full initialization on first boot (15-20 minutes)
2. **Pre-Warmed Build**: ~80-100GB OVA that is fully initialized and ready to use immediately (2-3 minutes to start services)

See [ADR-001: Dual Build Pipeline Strategy](../adr/001-dual-build-pipeline.md) for the architectural decision and rationale.

#### When to Use Each Build Type

**Use Standard Build when:**
- Distributing to students for self-paced online learning
- Download size matters (limited bandwidth, cloud storage costs)
- First-boot initialization time is acceptable (15-20 minutes)
- Building for general public distribution

**Use Pre-Warmed Build when:**
- Running in-person workshops or training events
- Need immediate lab access (2-3 minute startup)
- Have local distribution method (USB drives, local network)
- Can afford larger file size and longer build time

### Standard Build Pipeline

The standard build creates a ~15-20GB OVA that performs full initialization on first boot.

#### Build Steps

1. **ISO Download**: Packer downloads Ubuntu 22.04 LTS Server ISO
2. **VM Creation**: Creates a QEMU VM with 8 CPUs, 16GB RAM, 100GB disk
3. **OS Installation**: Automated installation using Ubuntu autoinstall (cloud-init)
4. **Provisioning**: Runs installation scripts in order:
   - `01-install-base.sh` - Base system packages and Docker
   - `02-install-k3d.sh` - k3d for Kubernetes
   - `03-install-hhfab.sh` - Hedgehog Fabric tools
   - `04-install-tools.sh` - kubectl, helm, ArgoCD CLI, etc.
5. **Orchestrator Setup**: Installs the orchestrator script and marks as standard build
6. **Cleanup**: Removes logs, caches, and zeroes free space for compression
7. **Conversion**: Converts qcow2 to VMDK (streamOptimized)
8. **OVA Creation**: Packages VMDK with OVF descriptor into OVA
9. **Checksum**: Generates SHA256 checksum

#### Build Time

- **Total**: 45-60 minutes (depending on hardware and network)
- ISO download: 5 minutes
- OS installation: 10 minutes
- Provisioning: 20-30 minutes
- Cleanup and conversion: 10-15 minutes

### Manual Build

```bash
# Navigate to repository
cd hedgehog-lab-appliance

# Set version (optional)
export VERSION="0.1.0"

# Validate template
packer validate packer/standard-build.pkr.hcl

# Build with KVM (local development - fastest)
packer build -var "version=$VERSION" packer/standard-build.pkr.hcl

# Build without KVM (CI/CD or systems without virtualization)
packer build -var "version=$VERSION" -var "accelerator=tcg" packer/standard-build.pkr.hcl
```

**Note:** Builds without KVM (using TCG software emulation) will be significantly slower (2-4x build time).

### Pre-Warmed Build Pipeline

The pre-warmed build creates a ~80-100GB OVA that is fully initialized during the build process. This build is intended for workshops and events where immediate access is required.

#### Build Steps

The pre-warmed build includes all standard build steps PLUS:

1. **Full Initialization at Build Time**: Runs the orchestrator during Packer build
   - Initializes k3d observability cluster
   - Initializes Hedgehog VLAB (requires nested virtualization)
   - Deploys GitOps stack (ArgoCD, Gitea)
   - Deploys observability stack (Prometheus, Grafana)
2. **Build Type Marker**: Sets `/etc/hedgehog-lab/build-type` to `prewarmed`
3. **Service Disabled**: Disables init service since initialization is already complete
4. **Verification**: Confirms all initialization steps completed successfully

#### Build Time

- **Total**: 60-90 minutes (depending on hardware and network)
- Standard provisioning: 45-60 minutes
- Full initialization: 15-20 minutes
- Cleanup and conversion: 5-10 minutes

#### Nested Virtualization Requirements

**IMPORTANT**: Pre-warmed builds require nested virtualization support because the build process initializes k3d/Docker/VLAB inside the VM during the Packer build.

**Requirements:**
- **Hardware**: CPU with Intel VT-x/AMD-V support
- **Host OS**: Linux with KVM enabled
- **QEMU**: Configured with nested virtualization enabled
- **Self-hosted runner**: GitHub Actions cannot build pre-warmed images (no nested virt support)

**Verifying Nested Virtualization Support:**

```bash
# Check if your CPU supports nested virtualization
egrep -c '(vmx|svm)' /proc/cpuinfo  # Should be > 0

# For Intel CPUs - check if nested virt is enabled
cat /sys/module/kvm_intel/parameters/nested  # Should show 'Y' or '1'

# For AMD CPUs - check if nested virt is enabled
cat /sys/module/kvm_amd/parameters/nested  # Should show '1'

# Enable nested virtualization (Intel)
sudo modprobe -r kvm_intel
sudo modprobe kvm_intel nested=1

# Enable nested virtualization (AMD)
sudo modprobe -r kvm_amd
sudo modprobe kvm_amd nested=1

# Make it persistent across reboots (Intel)
echo "options kvm_intel nested=1" | sudo tee /etc/modprobe.d/kvm-nested.conf

# Make it persistent across reboots (AMD)
echo "options kvm_amd nested=1" | sudo tee /etc/modprobe.d/kvm-nested.conf
```

#### Manual Pre-Warmed Build

```bash
# Navigate to repository
cd hedgehog-lab-appliance

# Set version (optional)
export VERSION="0.1.0"

# Validate template
packer validate packer/prewarmed-build.pkr.hcl

# Build pre-warmed image (requires KVM with nested virtualization)
packer build -var "version=$VERSION" packer/prewarmed-build.pkr.hcl
```

**Note:** Pre-warmed builds REQUIRE KVM with nested virtualization. TCG software emulation is not supported.

### Using Make

```bash
# Validate only
make validate

# Build with default version (0.1.0)
make build-standard

# Build with custom version
make build-standard VERSION=0.2.0

# Clean build artifacts
make clean
```

## Build Configuration

### Variables

You can customize the build by setting variables:

```bash
packer build \
  -var "version=0.1.0" \
  -var "vm_name=my-custom-lab" \
  -var "memory=32768" \
  -var "cpus=16" \
  packer/standard-build.pkr.hcl
```

**Available Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `version` | 0.1.0 | Version number for the build |
| `ubuntu_version` | 22.04.5 | Ubuntu release version |
| `iso_url` | (Ubuntu URL) | ISO download URL |
| `iso_checksum` | (SHA256) | ISO checksum for verification |
| `vm_name` | hedgehog-lab-standard | Output VM name |
| `disk_size` | 100000M | Virtual disk size (in QEMU format with unit) |
| `memory` | 16384 | RAM in MB |
| `cpus` | 8 | Number of virtual CPUs |
| `ssh_username` | hhlab | SSH username |
| `ssh_password` | hhlab | SSH password (sensitive) |
| `accelerator` | kvm | QEMU accelerator (kvm, tcg, or none) |

**Important:** Use `accelerator=tcg` for environments without KVM support (GitHub Actions, some cloud VMs).

### Provisioning Scripts

Scripts are located in `packer/scripts/` and run in order:

#### 01-install-base.sh
- Updates Ubuntu packages
- Installs build tools, utilities
- Installs Docker and container tools
- Installs Python 3 and pip
- Adds hhlab user to docker group

#### 02-install-k3d.sh
- Installs k3d v5.7.4
- Creates k3d configuration directory

#### 03-install-hhfab.sh
- Installs Go 1.23.2
- Creates Hedgehog directory structure
- Placeholder for future hhfab CLI

#### 04-install-tools.sh
- kubectl v1.31.1
- Helm 3
- kind v0.24.0
- ArgoCD CLI v2.12.4
- kustomize
- kubectx/kubens
- k9s v0.32.5
- stern v1.30.0
- yq v4.44.3
- bat, fzf
- Bash completions for all tools

#### 99-cleanup.sh
- Removes apt cache
- Truncates log files
- Cleans cloud-init
- Removes SSH host keys
- Runs fstrim to discard unused blocks (efficient for qcow2)
- Optional: Zero-fills free space (disabled by default, controlled by `PACKER_ZERO_FILL` env var)

**Note:** Zero-fill is disabled by default to prevent disk space exhaustion on CI runners. Use `fstrim` instead for qcow2 images.

### Orchestrator

The orchestrator (`packer/scripts/hedgehog-lab-orchestrator`) is installed to `/usr/local/bin/` and runs automatically on first boot via systemd service.

**Systemd Services:**

1. **Main Orchestrator Service** (`hedgehog-lab-init.service`)
   - **Unit file:** `/etc/systemd/system/hedgehog-lab-init.service`
   - **Enabled:** Runs automatically on boot
   - **Condition:** Only runs if not already initialized
   - **Logs:** Available via `journalctl -u hedgehog-lab-init`
   - **Purpose:** Coordinates the overall initialization sequence

2. **VLAB Service** (`hhfab-vlab.service`)
   - **Unit file:** `/etc/systemd/system/hhfab-vlab.service`
   - **Enabled:** Started by the orchestrator (not on boot)
   - **Condition:** Only runs if VLAB not already initialized
   - **Logs:** Available via `journalctl -u hhfab-vlab` and `/var/log/hedgehog-lab/modules/vlab.log`
   - **Purpose:** Runs `hhfab vlab up --controls-restricted=false --ready wait` in a detached tmux session

**VLAB Tmux Session:**

The VLAB initialization runs inside a persistent tmux session named `hhfab-vlab`. This allows students to inspect the VLAB startup process and provides a detachable interface for troubleshooting.

```bash
# List all tmux sessions
tmux ls

# Attach to the hhfab-vlab session (if it's still running)
tmux attach -t hhfab-vlab

# Detach from tmux session (while inside)
# Press: Ctrl+b then d

# View VLAB logs
tail -f /var/log/hedgehog-lab/modules/vlab.log
```

**Note:** The tmux session will automatically exit once `hhfab vlab up` completes successfully. If initialization fails, the session may remain active for debugging.

**Initialization Order:**

The orchestrator enforces a strict initialization order to ensure proper operation:

1. **Network** - Wait for network connectivity (max 5 minutes)
2. **VLAB** - Initialize Hedgehog VLAB (15-20 minutes, MUST complete first)
   - Runs `hhfab vlab up` in persistent tmux session
   - Creates Hedgehog controller with fabric switches
   - Provides host-facing API at `https://172.19.0.1:6443`
3. **k3d Cluster** - Initialize k3d observability cluster (5-10 minutes)
   - Deploys Prometheus, Grafana, ArgoCD, Gitea
   - Exposes services on localhost ports (3000, 8080, 3001, etc.)
4. **GitOps Repository** - Seed `student/hedgehog-config` in Gitea (1-2 minutes)
   - Creates `student` organization in Gitea
   - Creates `hedgehog-config` repository
   - Seeds with example VPC manifests and documentation
5. **ArgoCD Application** - Configure GitOps sync (1-2 minutes)
   - Creates cluster secret for Hedgehog controller
   - Creates ArgoCD Application `hedgehog-fabric`
   - Enables automated sync with self-heal to VLAB controller
6. **Observability Config** - Configure Prometheus scraping (1 minute)
   - Adds scrape config for Hedgehog fabric-proxy metrics
   - Configures metrics collection from fabric switches
7. **Service Finalization** - Final health checks and status reporting

This order is critical because:
- VLAB must complete before k3d can connect to its API
- GitOps repository must exist before ArgoCD can sync it
- Prometheus must be running before adding Hedgehog scrape targets

**Manual control:**
```bash
# Check orchestrator status
systemctl status hedgehog-lab-init

# Check VLAB service status
systemctl status hhfab-vlab

# View orchestrator logs
journalctl -u hedgehog-lab-init -f

# View VLAB service logs
journalctl -u hhfab-vlab -f

# Manually run orchestrator (if needed)
sudo systemctl start hedgehog-lab-init

# Manually run VLAB service (if needed)
sudo systemctl start hhfab-vlab
```

## Troubleshooting

### Build Fails: KVM Not Available

```
Error: KVM not available
```

**Solution:**
1. Verify CPU supports virtualization: `egrep -c '(vmx|svm)' /proc/cpuinfo`
2. Enable virtualization in BIOS
3. Load KVM module: `sudo modprobe kvm_intel` or `sudo modprobe kvm_amd`

### Build Fails: Insufficient Disk Space

```
Error: No space left on device
```

**Solution:**
1. Free up disk space: `df -h`
2. Clean old builds: `make clean`
3. Remove unused Docker images: `docker system prune -a`

### Build Fails: ISO Download Timeout

```
Error: Failed to download ISO
```

**Solution:**
1. Check internet connection
2. Try different Ubuntu mirror by modifying `iso_url` variable
3. Download ISO manually and use file:// URL

### Build Hangs During Provisioning

**Solution:**
1. Check if VM is responding: `ps aux | grep qemu`
2. View Packer logs: `PACKER_LOG=1 packer build ...`
3. Increase SSH timeout in template

### OVA Creation Fails

```
Error: Failed to create OVA
```

**Solution:**
1. Check disk space: `df -h`
2. Verify VMDK was created: `ls output-*/`
3. Check permissions: `ls -l output-*/`

## Advanced Topics

### Custom ISO

To use a custom Ubuntu ISO:

```bash
packer build \
  -var "iso_url=file:///path/to/ubuntu.iso" \
  -var "iso_checksum=sha256:YOUR_CHECKSUM" \
  packer/standard-build.pkr.hcl
```

### Debugging

Enable verbose logging:

```bash
PACKER_LOG=1 packer build packer/standard-build.pkr.hcl
```

View QEMU console:

```bash
# In template, set headless = false
packer build -var "headless=false" packer/standard-build.pkr.hcl
```

### Parallel Builds

Build multiple versions concurrently:

```bash
packer build -parallel-builds=2 packer/standard-build.pkr.hcl
```

### CI/CD Integration

See `.github/workflows/build-standard.yml` for automated builds on:
- Tag pushes (e.g., `v0.1.0`)
- Manual workflow dispatch

**GitHub Actions Limitations:**

1. **No KVM Support**: GitHub-hosted runners don't support nested virtualization
   - Solution: Workflow uses `accelerator=tcg` (software emulation)
   - Impact: Build time increases to 2-4 hours vs. 45-60 minutes with KVM

2. **Limited Resources**: `ubuntu-latest` runners have constraints
   - Available: ~7GB RAM, 2 CPU cores
   - Required for full build: 16GB RAM, 8 CPU cores
   - Solution: Workflow uses reduced allocation (`memory=4096`, `cpus=2`)
   - Impact: CI builds are for validation only, not production use

3. **File Size Limits**:
   - GitHub Artifacts: 5GB per file (OVA is 15-20GB)
   - GitHub Releases: 2GB per file
   - Solution: Only checksums are uploaded; users build locally or use external storage

**⚠️ Important**: GitHub Actions builds use reduced resources and are **not recommended for production**. Always build locally with full resources for production deployments.

**Recommended Alternatives:**

1. **Self-Hosted Runners**:
   - Install on bare-metal with KVM support
   - Configure external storage (S3, GCS, Azure Blob)
   - Fast builds with artifact distribution

2. **Local Builds**:
   - Best for development and testing
   - Full KVM acceleration
   - Complete control over output

3. **External CI/CD**:
   - GitLab CI with KVM runners
   - Jenkins with KVM support
   - CircleCI with machine executor

## Build Output

After successful build, you'll find:

**Standard Build:**
```
output-hedgehog-lab-standard/
├── hedgehog-lab-standard-0.1.0.ova          # OVA file (~15-20GB)
├── hedgehog-lab-standard-0.1.0.ova.sha256   # Checksum
└── hedgehog-lab-standard-0.1.0.vmdk         # VMDK (kept for debugging)
```

**Pre-Warmed Build:**
```
output-hedgehog-lab-prewarmed/
├── hedgehog-lab-prewarmed-0.1.0.ova          # OVA file (~80-100GB)
├── hedgehog-lab-prewarmed-0.1.0.ova.sha256   # Checksum
└── hedgehog-lab-prewarmed-0.1.0.vmdk         # VMDK (kept for debugging)
```

**OVA Contents:**
- `*.ovf` - Virtual machine descriptor
- `*.mf` - Manifest with checksums
- `*.vmdk` - Virtual disk

## Next Steps

- See [USAGE.md](USAGE.md) for how to import and use the appliance
- See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines
- See [ROADMAP.md](../ROADMAP.md) for planned features

## Support

- **Issues:** https://github.com/YOUR_ORG/hedgehog-lab-appliance/issues
- **Discussions:** https://github.com/YOUR_ORG/hedgehog-lab-appliance/discussions
