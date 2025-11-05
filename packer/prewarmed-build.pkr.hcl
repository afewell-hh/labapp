# Hedgehog Lab Appliance - Pre-Warmed Build
# Built with Packer and QEMU
# Produces fully initialized OVA format suitable for VMware/VirtualBox
# Requires nested virtualization support (KVM)

packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

# Variables
variable "version" {
  type    = string
  default = "0.1.0"
}

variable "ubuntu_version" {
  type    = string
  default = "22.04.5"
}

variable "iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
}

variable "vm_name" {
  type    = string
  default = "hedgehog-lab-prewarmed"
}

variable "disk_size" {
  type        = string
  default     = "100000M"
  description = "Virtual disk size (e.g., '100000M' for 100GB, or '100G'). QEMU accepts size with unit suffix."
}

variable "memory" {
  type    = number
  default = 16384
}

variable "cpus" {
  type    = number
  default = 8
}

variable "ssh_username" {
  type    = string
  default = "hhlab"
}

variable "ssh_password" {
  type      = string
  default   = "hhlab"
  sensitive = true
}

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "QEMU accelerator (kvm required for pre-warmed builds). Pre-warmed builds require nested virtualization."
}

# Locals
locals {
  output_name = "${var.vm_name}-${var.version}"
  build_date  = formatdate("YYYY-MM-DD", timestamp())

  # CPU optimization: Pre-warmed builds require KVM with nested virt
  cpu_type = "host"
}

# Source: QEMU builder
source "qemu" "ubuntu" {
  # VM settings
  vm_name          = local.output_name
  output_directory = "output-${var.vm_name}"

  # ISO settings
  iso_url      = var.iso_url
  iso_checksum = var.iso_checksum

  # Hardware settings
  cpus        = var.cpus
  memory      = var.memory
  disk_size   = var.disk_size
  format      = "qcow2"
  accelerator = var.accelerator

  # QEMU settings
  qemu_binary        = "qemu-system-x86_64"
  headless           = true
  disk_interface     = "virtio-scsi"
  disk_cache         = "unsafe"
  disk_discard       = "unmap"
  disk_detect_zeroes = "unmap"
  net_device         = "virtio-net"

  # Performance optimizations with nested virtualization enabled
  # This allows k3d/Docker/VLAB to run inside the VM during build
  # Note: -cpu host automatically exposes nested virt (vmx/svm) if enabled on host
  qemuargs = [
    ["-cpu", "host"],
    ["-smp", "cpus=${var.cpus},sockets=1,cores=${var.cpus},threads=1"],
    ["-machine", "type=q35,accel=kvm"]
  ]

  # Boot configuration
  boot_wait = "5s"
  boot_command = [
    "<wait>c<wait>",
    "linux /casper/vmlinuz --- autoinstall ds='nocloud-net;s=http://{{.HTTPIP}}:{{.HTTPPort}}/' ",
    "<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  # HTTP server for autoinstall files
  http_directory = "packer/http"
  http_port_min  = 8100
  http_port_max  = 8200

  # SSH settings
  ssh_username           = var.ssh_username
  ssh_password           = var.ssh_password
  ssh_timeout            = "30m"
  ssh_handshake_attempts = 100

  # Shutdown
  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
}

# Build
build {
  name = "prewarmed-build"

  sources = ["source.qemu.ubuntu"]

  # Wait for cloud-init to finish
  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "cloud-init status --wait",
      "echo 'Cloud-init complete'"
    ]
  }

  # Run provisioning scripts (same as standard build)
  provisioner "shell" {
    scripts = [
      "packer/scripts/01-install-base.sh",
      "packer/scripts/02-install-k3d.sh",
      "packer/scripts/03-install-hhfab.sh",
      "packer/scripts/04-install-tools.sh"
    ]
    execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Path }}'"
  }

  # Prepare temporary directory for orchestrator files
  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/packer-provisioner-shell-scripts"
    ]
  }

  # Upload orchestrator files to temporary location
  provisioner "file" {
    source      = "packer/scripts/hedgehog-lab-orchestrator"
    destination = "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-orchestrator"
  }

  provisioner "file" {
    source      = "packer/scripts/hedgehog-lab-init.service"
    destination = "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-init.service"
  }

  provisioner "file" {
    source      = "packer/scripts/30-vlab-init.sh"
    destination = "/tmp/packer-provisioner-shell-scripts/30-vlab-init.sh"
  }

  provisioner "file" {
    source      = "packer/scripts/20-k3d-observability-init.sh"
    destination = "/tmp/packer-provisioner-shell-scripts/20-k3d-observability-init.sh"
  }

  provisioner "file" {
    source      = "packer/scripts/hedgehog-lab-readiness-ui"
    destination = "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-readiness-ui"
  }

  provisioner "file" {
    source      = "packer/scripts/hh-lab"
    destination = "/tmp/packer-provisioner-shell-scripts/hh-lab"
  }

  provisioner "file" {
    source      = "packer/scripts/hh-lab-completion.bash"
    destination = "/tmp/packer-provisioner-shell-scripts/hh-lab-completion.bash"
  }

  # Install orchestrator and modules
  provisioner "shell" {
    script          = "packer/scripts/05-install-orchestrator.sh"
    execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Path }}'"
  }

  # Set build type to 'prewarmed' (overrides the 'standard' set by install script)
  provisioner "shell" {
    inline = [
      "echo 'prewarmed' | sudo tee /etc/hedgehog-lab/build-type",
      "echo 'Build type set to: prewarmed'"
    ]
  }

  # Run full initialization at build time
  # This is the key difference from standard build
  provisioner "shell" {
    inline = [
      "echo '=================================================='",
      "echo 'Running full initialization at build time...'",
      "echo '=================================================='",
      "echo 'This will take 20-30 minutes to complete.'",
      "echo 'Initializing k3d cluster and VLAB...'",
      "echo ''",
      "# Create build-time log file separate from runtime logs",
      "sudo mkdir -p /var/log/hedgehog-lab",
      "export BUILD_TIME_LOG='/var/log/hedgehog-lab/build-time-init.log'",
      "echo \"[$(date '+%Y-%m-%d %H:%M:%S')] Starting build-time initialization\" | sudo tee -a \"$BUILD_TIME_LOG\"",
      "echo \"[$(date '+%Y-%m-%d %H:%M:%S')] Build type: prewarmed\" | sudo tee -a \"$BUILD_TIME_LOG\"",
      "echo \"[$(date '+%Y-%m-%d %H:%M:%S')] Expected duration: 20-30 minutes\" | sudo tee -a \"$BUILD_TIME_LOG\"",
      "echo ''",
      "# Run orchestrator with extended timeout (30 minutes)",
      "# Redirect output to both console and build-time log",
      "if sudo timeout 1800 /usr/local/bin/hedgehog-lab-orchestrator 2>&1 | sudo tee -a \"$BUILD_TIME_LOG\"; then",
      "  echo \"[$(date '+%Y-%m-%d %H:%M:%S')] Build-time initialization completed successfully\" | sudo tee -a \"$BUILD_TIME_LOG\"",
      "  echo ''",
      "  echo 'Build-time initialization complete!'",
      "  echo '=================================================='",
      "else",
      "  EXIT_CODE=$?",
      "  echo \"[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Build-time initialization failed with exit code: $EXIT_CODE\" | sudo tee -a \"$BUILD_TIME_LOG\"",
      "  echo ''",
      "  echo 'ERROR: Build-time initialization failed!'",
      "  echo 'Check log: /var/log/hedgehog-lab/build-time-init.log'",
      "  echo 'Last 50 lines of log:'",
      "  sudo tail -50 \"$BUILD_TIME_LOG\"",
      "  exit 1",
      "fi"
    ]
    expect_disconnect = false
    pause_after       = "10s"
    timeout           = "35m"
  }

  # Verify initialization succeeded
  provisioner "shell" {
    inline = [
      "echo 'Verifying initialization...'",
      "echo ''",
      "# Check for initialization stamp file",
      "if [ -f /var/lib/hedgehog-lab/initialized ]; then",
      "  echo 'SUCCESS: Initialization stamp file found'",
      "  cat /var/lib/hedgehog-lab/initialized",
      "else",
      "  echo 'ERROR: Initialization stamp file not found'",
      "  echo 'Build-time initialization logs:'",
      "  sudo cat /var/log/hedgehog-lab/build-time-init.log",
      "  exit 1",
      "fi",
      "echo ''",
      "# Verify k3d cluster is running",
      "echo 'Verifying k3d cluster...'",
      "if k3d cluster list | grep -q 'k3d-observability.*running'; then",
      "  echo 'SUCCESS: k3d-observability cluster is running'",
      "  k3d cluster list | grep k3d-observability",
      "else",
      "  echo 'ERROR: k3d-observability cluster is not running'",
      "  exit 1",
      "fi",
      "echo ''",
      "# Verify VLAB is initialized",
      "echo 'Verifying VLAB...'",
      "if [ -f /opt/hedgehog/vlab/fab.yaml ] && [ -f /opt/hedgehog/vlab/wiring.yaml ]; then",
      "  echo 'SUCCESS: VLAB configuration files found'",
      "  echo '  - fab.yaml: present'",
      "  echo '  - wiring.yaml: present'",
      "else",
      "  echo 'ERROR: VLAB configuration files missing'",
      "  exit 1",
      "fi",
      "echo ''",
      "echo 'All verification checks passed!'"
    ]
  }

  # Disable the systemd service since initialization is already done
  # Pre-warmed builds don't need to initialize on first boot
  provisioner "shell" {
    inline = [
      "echo 'Disabling hedgehog-lab-init service (already initialized)...'",
      "sudo systemctl disable hedgehog-lab-init.service",
      "echo 'Service disabled - pre-warmed build is ready to use on first boot'"
    ]
  }

  # Cleanup (modified for pre-warmed builds)
  # IMPORTANT: Do NOT run docker system prune as it would delete all initialized containers!
  provisioner "shell" {
    inline = [
      "echo '=================================================='",
      "echo 'Cleaning up image (preserving Docker state)...'",
      "echo '=================================================='",
      "echo 'NOTE: Skipping Docker cleanup to preserve initialized containers'",
      "",
      "# Stop unnecessary services",
      "echo 'Stopping unnecessary services...'",
      "sudo systemctl stop unattended-upgrades || true",
      "",
      "# Clean apt cache",
      "echo 'Cleaning apt cache...'",
      "sudo apt-get autoremove -y --purge",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -rf /var/cache/apt/archives/*.deb",
      "sudo rm -rf /var/cache/apt/archives/partial/*.deb",
      "",
      "# Clean pip cache",
      "echo 'Cleaning pip cache...'",
      "sudo rm -rf /root/.cache/pip",
      "sudo rm -rf /home/*/.cache/pip",
      "",
      "# Clean logs (but preserve initialization logs)",
      "echo 'Cleaning system logs...'",
      "sudo journalctl --vacuum-size=10M || true",
      "sudo rm -rf /var/log/*.gz",
      "sudo rm -rf /var/log/*.[0-9]",
      "sudo rm -rf /var/log/*-????????",
      "",
      "# Clean additional caches",
      "echo 'Cleaning additional caches...'",
      "sudo rm -rf /var/cache/man/*",
      "sudo rm -rf /var/cache/debconf/*-old",
      "sudo rm -rf /var/lib/dpkg/*-old",
      "",
      "# Clean cloud-init",
      "echo 'Cleaning cloud-init...'",
      "sudo cloud-init clean --logs --seed",
      "",
      "# Clean bash history",
      "echo 'Cleaning bash history...'",
      "sudo rm -f /root/.bash_history",
      "sudo rm -f /home/*/.bash_history",
      "history -c",
      "",
      "# Clean SSH keys (they will be regenerated on first boot)",
      "echo 'Removing SSH host keys (will be regenerated)...'",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "",
      "# Run fstrim to discard unused blocks",
      "echo 'Running fstrim to discard unused blocks...'",
      "if command -v fstrim &> /dev/null; then",
      "    sudo fstrim -v / || echo 'fstrim completed with warnings'",
      "else",
      "    echo 'fstrim not available, skipping trim operation'",
      "fi",
      "",
      "# Sync filesystem",
      "sudo sync",
      "",
      "echo '=================================================='",
      "echo 'Cleanup complete (Docker state preserved)!'",
      "echo '=================================================='"
    ]
  }

  # Convert to VMDK format
  # Note: streamOptimized subformat provides compression automatically
  post-processor "shell-local" {
    inline = [
      "echo 'Converting qcow2 to VMDK (streamOptimized format)...'",
      "qemu-img convert -f qcow2 -O vmdk -o subformat=streamOptimized,compat6 output-${var.vm_name}/${local.output_name} output-${var.vm_name}/${local.output_name}.vmdk",
      "echo 'Conversion complete'",
      "echo 'Image size:'",
      "du -h output-${var.vm_name}/${local.output_name}.vmdk"
    ]
  }

  # Create OVF/OVA (requires additional scripting)
  post-processor "shell-local" {
    script = "packer/scripts/create-ova.sh"
    environment_vars = [
      "VM_NAME=${local.output_name}",
      "OUTPUT_DIR=output-${var.vm_name}",
      "MEMORY=${var.memory}",
      "CPUS=${var.cpus}",
      "VERSION=${var.version}",
      "DISK_SIZE=${var.disk_size}"
    ]
  }

  # Generate checksums
  post-processor "shell-local" {
    inline = [
      "cd output-${var.vm_name}",
      "sha256sum ${local.output_name}.ova > ${local.output_name}.ova.sha256",
      "echo 'Checksums generated'"
    ]
  }
}
