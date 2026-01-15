/**
 * Hedgehog Virtual AI Data Center (vAIDC) - Variables
 *
 * Copyright 2026 Hedgehog
 * SPDX-License-Identifier: Apache-2.0
 */

variable "project_id" {
  description = "The Google Cloud project ID where resources will be created"
  type        = string
}

variable "goog_cm_deployment_name" {
  description = "Deployment name for Cloud Marketplace (prevents naming conflicts)"
  type        = string
  default     = ""
}

variable "zone" {
  description = "GCP zone for deployment (must support nested virtualization)"
  type        = string
  default     = "us-west1-c"
}

variable "machine_type" {
  description = "Machine type (minimum 16 vCPUs, 32GB RAM for optimal performance)"
  type        = string
  default     = "n1-standard-32"

  validation {
    condition = can(regex("^(n1-standard-32|n1-standard-64|n1-highmem-32|n1-highmem-64|n2-standard-32|n2-standard-64|n2-highmem-32|n2-highmem-64|n2d-standard-32|n2d-standard-64|c2-standard-30|c2-standard-60)$", var.machine_type))
    error_message = "Machine type must support nested virtualization and have at least 16 vCPUs with 32GB RAM."
  }
}

variable "network" {
  description = "Network for the VM"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Subnetwork for the VM (leave empty for default)"
  type        = string
  default     = ""
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB (minimum 200GB, recommended 300GB)"
  type        = number
  default     = 300

  validation {
    condition     = var.boot_disk_size_gb >= 200 && var.boot_disk_size_gb <= 1000
    error_message = "Boot disk size must be between 200 and 1000 GB."
  }
}

variable "boot_disk_type" {
  description = "Boot disk type (pd-balanced recommended)"
  type        = string
  default     = "pd-balanced"

  validation {
    condition     = contains(["pd-standard", "pd-balanced", "pd-ssd"], var.boot_disk_type)
    error_message = "Boot disk type must be pd-standard, pd-balanced, or pd-ssd."
  }
}

variable "source_image" {
  description = "Source VM image for the vAIDC instance"
  type        = string
  default     = "projects/teched-473722/global/images/hedgehog-vaidc-v20260114"
}

variable "firewall_source_ranges" {
  description = "Source IP ranges for firewall rules"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
