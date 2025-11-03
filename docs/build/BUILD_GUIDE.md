# Hedgehog Lab Appliance - Build Guide

This guide explains how to build the Hedgehog Lab Appliance from source using Packer.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Process](#build-process)
- [Build Configuration](#build-configuration)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

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
| `disk_size` | 100G | Virtual disk size |
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
- Zeroes free space for compression

### Orchestrator

The orchestrator (`packer/scripts/hedgehog-lab-orchestrator`) is installed to `/usr/local/bin/` and will run on first boot to initialize the lab environment.

**Current implementation:** Placeholder that logs initialization steps
**Future implementation:** Will initialize k3d, VLAB, GitOps, and observability stacks

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

```
output-hedgehog-lab-standard/
├── hedgehog-lab-standard-0.1.0.ova          # OVA file
├── hedgehog-lab-standard-0.1.0.ova.sha256   # Checksum
└── hedgehog-lab-standard-0.1.0.vmdk         # VMDK (kept for debugging)
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
