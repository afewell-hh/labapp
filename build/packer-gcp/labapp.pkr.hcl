packer {
  required_version = "= 1.16.2"
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "= 1.2.9"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "= 1.1.6"
    }
  }
}

variable "release" {
  type    = string
  default = "r0"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,19}$", var.release))
    error_message = "Release must be a short release filename stem."
  }
}

variable "project_id" { type = string }
variable "zone" { type = string }
variable "subnetwork" { type = string }
variable "vm_service_account_email" { type = string }
variable "builder_service_account_email" {
  type        = string
  description = "Dedicated restricted build identity impersonated by Packer and its gcloud IAP tunnel."
}
variable "iap_network_tag" { type = string }

variable "source_image" {
  type        = string
  description = "Exact Ubuntu 24.04 amd64 image name in ubuntu-os-cloud; never an image family."
  validation {
    condition     = can(regex("^ubuntu-2404-noble-amd64-v[0-9]+$", var.source_image))
    error_message = "Select an exact Ubuntu 24.04 amd64 source image name."
  }
}

variable "build_id" {
  type        = string
  description = "Unique caller-owned build ID used for the candidate, VM and disk names."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,19}[a-z0-9]$", var.build_id))
    error_message = "Build ID must be 2–21 lowercase letters, digits or internal dashes."
  }
}

variable "ghcr_config_file" {
  type        = string
  sensitive   = true
  description = "Caller-prepared private Docker config.json outside the source tree; transferred directly to guest tmpfs."
}

variable "ansible_core_package_version" {
  type        = string
  default     = "2.16.3-0ubuntu2"
  description = "Exact Ubuntu package version of ansible-core, selected in the build environment."
  validation {
    condition     = can(regex("^[0-9][A-Za-z0-9.+:~-]+$", var.ansible_core_package_version))
    error_message = "Supply an exact apt package version, without shell characters."
  }
}

locals {
  build_dir    = abspath("${path.root}/..")
  release_file = "${local.build_dir}/releases/${var.release}.yaml"
  selected     = yamldecode(file(local.release_file)).release
  instance     = "labapp-build-${var.release}-${var.build_id}"
  image        = "labapp-candidate-${var.release}-${var.build_id}"
  guest_source = "/opt/labapp/build-source"
}

source "googlecompute" "labapp" {
  project_id                  = var.project_id
  zone                        = var.zone
  subnetwork                  = var.subnetwork
  service_account_email       = var.vm_service_account_email
  impersonate_service_account = var.builder_service_account_email
  # The plugin shares these scopes between its impersonated Compute client and
  # the VM. IAM still restricts the builder; the separate guest has no roles.
  scopes                  = ["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/compute"]
  source_image            = var.source_image
  source_image_project_id = ["ubuntu-os-cloud"]

  machine_type                 = local.selected.gcp.build.machine_type
  min_cpu_platform             = local.selected.gcp.build.min_cpu_platform
  enable_nested_virtualization = local.selected.gcp.build.nested_virtualization
  disk_size                    = local.selected.gcp.build.disk_gb
  disk_type                    = "pd-balanced"
  image_architecture           = "X86_64"
  on_host_maintenance          = "TERMINATE"

  instance_name = local.instance
  disk_name     = local.instance
  image_name    = local.image
  # Deliberately no image_family: capture cannot promote a production family.
  image_description = "Labapp ${var.release} candidate; course ${local.selected.course.revision}"
  labels = {
    labapp-role     = "builder"
    labapp-release  = var.release
    labapp-build-id = var.build_id
  }
  image_labels = {
    labapp-role     = "candidate"
    labapp-release  = var.release
    labapp-build-id = var.build_id
    course-revision = local.selected.course.revision
  }
  tags = [var.iap_network_tag]

  use_iap = true
  # Ephemeral outbound connectivity; firewall ingress stays IAP-only.
  omit_external_ip = false
  use_internal_ip  = true
  ssh_username     = "ubuntu"
  ssh_timeout      = "10m"
  # googlecompute also uses this limit while registering the captured image.
  state_timeout = "15m"
  # Set in the instance insertion request, not armed after guest access.
  max_run_duration_in_seconds = 7200
  instance_termination_action = "DELETE"
}

build {
  name    = "labapp"
  sources = ["source.googlecompute.labapp"]

  provisioner "shell" {
    script          = "${path.root}/bootstrap-ansible.sh"
    execute_command = "sudo -n /usr/bin/env {{ .Vars }} /bin/bash '{{ .Path }}'"
    environment_vars = [
      "ANSIBLE_CORE_PACKAGE_VERSION=${var.ansible_core_package_version}",
    ]
    timeout = "10m"
  }

  provisioner "file" {
    source      = var.ghcr_config_file
    destination = "/run/labapp-build-registry/config.json"
  }

  provisioner "shell" {
    inline = [
      "chmod 0600 /run/labapp-build-registry/config.json",
      "test -s /run/labapp-build-registry/config.json",
    ]
  }

  provisioner "ansible-local" {
    command                 = "/usr/local/sbin/labapp-build-ansible"
    playbook_dir            = local.build_dir
    playbook_files          = ["${local.build_dir}/ansible/image.yml"]
    staging_directory       = local.guest_source
    clean_staging_directory = false
    extra_arguments = [
      "--extra-vars=release_file=${local.guest_source}/releases/${var.release}.yaml",
    ]
    timeout = "100m"
  }

  provisioner "shell" {
    script          = "${path.root}/finish-build.sh"
    execute_command = "sudo -n /bin/bash '{{ .Path }}'"
    remote_path     = "/tmp/labapp-finish-build.sh"
    # The script removes itself; no helper-cleanup SSH command after key removal.
    skip_clean = true
    timeout    = "2m"
  }

  error-cleanup-provisioner "shell" {
    inline          = ["rm -rf -- /run/labapp-build-registry"]
    execute_command = "sudo -n /bin/bash '{{ .Path }}'"
    timeout         = "1m"
  }
}
