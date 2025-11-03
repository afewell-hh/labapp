# Packer Build Configuration

This directory contains Packer templates and provisioning scripts for building the Hedgehog Lab Appliance.

## Directory Structure

```
packer/
├── README.md                    # This file
├── standard-build.pkr.hcl       # Packer template for standard build
├── http/                        # Files served via HTTP during installation
│   ├── user-data               # Ubuntu autoinstall configuration
│   └── meta-data               # Cloud-init metadata
└── scripts/                     # Provisioning scripts
    ├── 01-install-base.sh      # Base system packages
    ├── 02-install-k3d.sh       # k3d installation
    ├── 03-install-hhfab.sh     # Hedgehog Fabric tools
    ├── 04-install-tools.sh     # Kubernetes/cloud-native tools
    ├── 99-cleanup.sh           # Cleanup and optimization
    ├── create-ova.sh           # Convert VMDK to OVA
    └── hedgehog-lab-orchestrator # Main orchestrator script
```

## Templates

### standard-build.pkr.hcl

Builds the standard appliance (~15-20GB) that initializes on first boot.

**Usage:**
```bash
packer validate standard-build.pkr.hcl
packer build -var "version=0.1.0" standard-build.pkr.hcl
```

**Build Steps:**
1. Download Ubuntu 22.04 ISO
2. Create QEMU VM
3. Automated OS installation via autoinstall
4. Run provisioning scripts
5. Install orchestrator
6. Cleanup and optimize
7. Convert to OVA format

## HTTP Directory

Files in `http/` are served via Packer's built-in HTTP server during the build process. The Ubuntu installer fetches these files to perform automated installation.

### user-data

Cloud-init configuration for Ubuntu autoinstall:
- Sets locale, keyboard, network
- Configures storage (LVM)
- Creates user `hhlab` with sudo access
- Installs base packages
- Enables SSH

### meta-data

Cloud-init instance metadata for the installation.

## Provisioning Scripts

Scripts run in numerical order during the build process. All scripts are idempotent and include error handling.

### 01-install-base.sh

**Purpose:** Install base system packages and Docker

**Installs:**
- Build tools (gcc, make, etc.)
- System utilities (curl, wget, git, vim, etc.)
- Network tools (tcpdump, net-tools, etc.)
- Monitoring tools (htop, iotop, etc.)
- Docker and containerd
- Python 3 and pip

**Runtime:** ~10 minutes

### 02-install-k3d.sh

**Purpose:** Install k3d for local Kubernetes clusters

**Installs:**
- k3d v5.7.4

**Runtime:** ~1 minute

### 03-install-hhfab.sh

**Purpose:** Install Hedgehog Fabric tools

**Installs:**
- Go 1.23.2
- Hedgehog directory structure
- Placeholder for hhfab CLI (to be implemented)

**Runtime:** ~2 minutes

### 04-install-tools.sh

**Purpose:** Install Kubernetes and cloud-native tools

**Installs:**
- kubectl v1.31.1
- Helm 3
- kind v0.24.0
- ArgoCD CLI v2.12.4
- kustomize
- kubectx and kubens
- k9s v0.32.5
- stern v1.30.0
- yq v4.44.3
- bat (better cat)
- fzf (fuzzy finder)
- Bash completions

**Runtime:** ~5-8 minutes

### 99-cleanup.sh

**Purpose:** Reduce image size and prepare for distribution

**Actions:**
- Remove apt cache
- Clean logs
- Remove cloud-init seed
- Clear bash history
- Remove SSH host keys (regenerated on first boot)
- Zero free space for better compression

**Runtime:** ~5-10 minutes

### create-ova.sh

**Purpose:** Convert QEMU qcow2/VMDK to OVA format

**Process:**
1. Convert qcow2 to streamOptimized VMDK
2. Create OVF descriptor with VM specifications
3. Generate manifest with checksums
4. Package into OVA (tar archive)

**Runtime:** ~5 minutes

### hedgehog-lab-orchestrator

**Purpose:** Main orchestrator that runs on first boot

**Current Functionality:**
- Detects build type (standard vs pre-warmed)
- Creates lockfile to prevent concurrent runs
- Logs initialization steps
- Marks appliance as initialized

**Future Functionality (Sprint 2):**
- Initialize k3d cluster
- Initialize Hedgehog VLAB
- Deploy GitOps stack (ArgoCD, Gitea)
- Deploy observability stack (Prometheus, Grafana, Loki)

## Customization

### Changing Versions

Update version numbers in the respective scripts:

```bash
# In 02-install-k3d.sh
K3D_VERSION="v5.7.4"

# In 04-install-tools.sh
KUBECTL_VERSION="v1.31.1"
```

### Adding New Tools

1. Create a new script (e.g., `05-install-monitoring.sh`)
2. Make it executable: `chmod +x packer/scripts/05-install-monitoring.sh`
3. Add to build sequence in `standard-build.pkr.hcl`:

```hcl
provisioner "shell" {
  scripts = [
    "packer/scripts/01-install-base.sh",
    "packer/scripts/02-install-k3d.sh",
    "packer/scripts/03-install-hhfab.sh",
    "packer/scripts/04-install-tools.sh",
    "packer/scripts/05-install-monitoring.sh",  # New script
  ]
  execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Path }}'"
}
```

### Modifying Autoinstall

Edit `http/user-data` to customize the Ubuntu installation:
- Storage layout
- Installed packages
- Network configuration
- User settings

After changes, validate with:
```bash
cloud-init schema --config-file http/user-data
```

## Testing

### Validate Templates

```bash
packer validate standard-build.pkr.hcl
```

### Check Formatting

```bash
packer fmt -check standard-build.pkr.hcl
```

### Test Individual Scripts

Run scripts on a test VM:

```bash
# SSH into test VM
ssh hhlab@test-vm

# Run script
sudo bash /path/to/01-install-base.sh
```

## Debugging

### Enable Verbose Logging

```bash
PACKER_LOG=1 packer build standard-build.pkr.hcl
```

### Inspect Build VM

Set `headless = false` in template to see QEMU console:

```hcl
source "qemu" "ubuntu" {
  headless = false  # Show QEMU window
  # ...
}
```

### SSH Into Build VM

During build, Packer prints SSH connection details:

```
==> qemu.ubuntu: Using SSH communicator to connect: 127.0.0.1
==> qemu.ubuntu: Waiting for SSH to become available...
```

Connect manually:
```bash
ssh -p <port> hhlab@127.0.0.1
```

## See Also

- [Build Guide](../docs/build/BUILD_GUIDE.md) - Complete build documentation
- [Packer Documentation](https://www.packer.io/docs) - Official Packer docs
- [Ubuntu Autoinstall](https://ubuntu.com/server/docs/install/autoinstall) - Autoinstall reference
