# Stock Packer/QEMU portability experiment (README.md). NOT executed or even
# `packer validate`d in the preparation PR; every attribute below is taken from
# the pinned docs/source and remains UNRUN. Run only through supervise.py, which
# creates work_dir (0700), stages cd/, and supplies every variable via PKR_VAR_*.
packer {
  required_version = "= 1.16.2"
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "= 1.1.7"
    }
  }
}

variable "work_dir" { type = string }
variable "nonce" { type = string }
variable "inputs" { type = string }
variable "base_image" { type = string }
variable "base_sha256" { type = string }
variable "verifier" { type = string }
variable "verify_seconds" { type = number }

source "qemu" "labapp" {
  # Packer verifies the local base image against base_sha256; nothing downloads.
  iso_url      = var.base_image
  iso_checksum = "sha256:${var.base_sha256}"
  disk_image   = true
  format       = "qcow2"

  output_directory = "${var.work_dir}/out"
  vm_name          = "labapp.qcow2"

  accelerator = "kvm" # never fall back to TCG
  cpus        = 4
  memory      = 8192
  disk_size   = "40G"
  headless    = true
  boot_wait   = "1s"

  # NoCloud seed plus the staged module bytes: a CD labelled cidata.
  cd_files = ["${var.work_dir}/cd/*"]
  cd_label = "cidata"

  # No communicator: native SSH ignores server identity (SDK 0.6.11) and no
  # waiver is made. The guest self-provisions; completion is observed privately.
  communicator     = "none"
  shutdown_timeout = "5m"

  # Every builder channel that would touch QEMU is explicitly off, so the
  # verifier is the sole controller: no VNC (disable_vnc skips the pinned
  # stepTypeBootCommand VNC connection that would otherwise fail before
  # shell-local), no boot-command typing, no builder QMP (its monitor is a
  # separate single-client socket whose events go unread), no VNC password
  # (which forces qmp_enable) and no bridge networking. Any transient port
  # reservation stays on loopback. UNRUN: each attribute name/effect is taken
  # from the pinned docs/source and must be confirmed by `packer validate`.
  disable_vnc      = true
  vnc_bind_address = "127.0.0.1"
  vnc_use_password = false
  boot_command     = []
  qmp_enable       = false
  net_bridge       = ""

  # The two sockets belong to the verifier alone. -S starts QEMU paused so the
  # guest cannot run until the verifier has attached the receipt reader,
  # validated QMP and KVM, and sent `cont`. -monitor none removes the default
  # HMP monitor; -vnc none keeps the display listener off (UNRUN override check).
  qemuargs = [
    ["-S"],
    ["-cpu", "host"],
    ["-monitor", "none"],
    ["-qmp", "unix:${var.work_dir}/events.sock,server=on,wait=off"],
    ["-serial", "unix:${var.work_dir}/serial.sock,server=on,wait=off"],
    ["-vnc", "none"],
  ]
}

build {
  sources = ["source.qemu.labapp"]

  # Runs on the host while the guest builds itself (provision precedes the
  # builder's shutdown step). Exit 0 only after receipt AND guest shutdown.
  provisioner "shell-local" {
    environment_vars = [
      "LABAPP_VERIFIER=${var.verifier}",
      "LABAPP_DIR=${var.work_dir}",
      "LABAPP_NONCE=${var.nonce}",
      "LABAPP_INPUTS=${var.inputs}",
      "LABAPP_SECONDS=${var.verify_seconds}",
    ]
    inline = [
      "exec python3 -I \"$LABAPP_VERIFIER\" --qmp \"$LABAPP_DIR/events.sock\" --serial \"$LABAPP_DIR/serial.sock\" --result \"$LABAPP_DIR/verified.json\" --timeout \"$LABAPP_SECONDS\" --nonce \"$LABAPP_NONCE\" --inputs \"$LABAPP_INPUTS\"",
    ]
    timeout = "${var.verify_seconds}s" # secondary; supervise.py is the watchdog
  }
}
