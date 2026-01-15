/**
 * Hedgehog Virtual AI Data Center (vAIDC) - Terraform Deployment Module
 *
 * This module deploys a pre-configured Hedgehog vAIDC lab environment
 * on Google Cloud Platform.
 *
 * Copyright 2026 Hedgehog
 * SPDX-License-Identifier: Apache-2.0
 */

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0.0, < 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  deployment_name = var.goog_cm_deployment_name != "" ? var.goog_cm_deployment_name : "vaidc-${random_id.suffix.hex}"
  vm_name         = "${local.deployment_name}-vm"
  firewall_name   = "${local.deployment_name}-firewall"
}

# Hedgehog vAIDC VM Instance
resource "google_compute_instance" "vaidc" {
  project      = var.project_id
  name         = local.vm_name
  zone         = var.zone
  machine_type = var.machine_type

  boot_disk {
    initialize_params {
      image = var.source_image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
    auto_delete = true
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork != "" ? var.subnetwork : null

    access_config {
      network_tier = "PREMIUM"
    }
  }

  tags = ["vaidc-instance", "http-server", "https-server"]

  metadata = {
    enable-oslogin = "TRUE"
    startup-script = <<-EOF
      #!/bin/bash
      echo "Hedgehog vAIDC instance started at $(date)" >> /var/log/vaidc-startup.log
    EOF
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = "default"
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write"
    ]
  }

  min_cpu_platform = "Intel Cascade Lake"

  advanced_machine_features {
    enable_nested_virtualization = true
  }

  labels = {
    product    = "hedgehog-vaidc"
    deployment = local.deployment_name
  }

  allow_stopping_for_update = true
}

# Firewall rule for vAIDC services
resource "google_compute_firewall" "vaidc" {
  project     = var.project_id
  name        = local.firewall_name
  network     = var.network
  description = "Allow access to Hedgehog vAIDC services"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "3000", "3001", "8080", "9090"]
  }

  target_tags   = ["vaidc-instance"]
  source_ranges = var.firewall_source_ranges
}
