# Hedgehog Lab Appliance - Standard Build
# Built with Packer and QEMU
# Produces OVA format suitable for VMware/VirtualBox

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
  default = "hedgehog-lab-standard"
}

variable "disk_size" {
  type    = string
  default = "100G"
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
  type    = string
  default = "hhlab"
  sensitive = true
}

# Locals
locals {
  output_name = "${var.vm_name}-${var.version}"
  build_date  = formatdate("YYYY-MM-DD", timestamp())
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
  accelerator = "kvm"

  # QEMU settings
  qemu_binary      = "qemu-system-x86_64"
  headless         = true
  disk_interface   = "virtio-scsi"
  disk_cache       = "unsafe"
  disk_discard     = "unmap"
  disk_detect_zeroes = "unmap"
  net_device       = "virtio-net"

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
  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = "30m"
  ssh_handshake_attempts = 100

  # Shutdown
  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
}

# Build
build {
  name = "standard-build"

  sources = ["source.qemu.ubuntu"]

  # Wait for cloud-init to finish
  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "cloud-init status --wait",
      "echo 'Cloud-init complete'"
    ]
  }

  # Run provisioning scripts
  provisioner "shell" {
    scripts = [
      "packer/scripts/01-install-base.sh",
      "packer/scripts/02-install-k3d.sh",
      "packer/scripts/03-install-hhfab.sh",
      "packer/scripts/04-install-tools.sh"
    ]
    execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Path }}'"
  }

  # Install orchestrator
  provisioner "file" {
    source      = "packer/scripts/hedgehog-lab-orchestrator"
    destination = "/tmp/hedgehog-lab-orchestrator"
  }

  provisioner "shell" {
    inline = [
      "sudo mkdir -p /usr/local/bin /etc/hedgehog-lab",
      "sudo mv /tmp/hedgehog-lab-orchestrator /usr/local/bin/",
      "sudo chmod +x /usr/local/bin/hedgehog-lab-orchestrator",
      "echo 'standard' | sudo tee /etc/hedgehog-lab/build-type"
    ]
    execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Vars }} {{ .Path }}'"
  }

  # Cleanup
  provisioner "shell" {
    script          = "packer/scripts/99-cleanup.sh"
    execute_command = "echo '${var.ssh_password}' | sudo -S bash -c '{{ .Path }}'"
  }

  # Convert to VMDK format
  post-processor "shell-local" {
    inline = [
      "echo 'Converting qcow2 to VMDK...'",
      "qemu-img convert -f qcow2 -O vmdk -o subformat=streamOptimized output-${var.vm_name}/${local.output_name} output-${var.vm_name}/${local.output_name}.vmdk",
      "echo 'Conversion complete'"
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
      "VERSION=${var.version}"
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
