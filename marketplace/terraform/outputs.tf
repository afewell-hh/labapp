/**
 * Hedgehog Virtual AI Data Center (vAIDC) - Outputs
 *
 * Copyright 2026 Hedgehog
 * SPDX-License-Identifier: Apache-2.0
 */

output "vm_name" {
  description = "Name of the vAIDC VM instance"
  value       = google_compute_instance.vaidc.name
}

output "vm_self_link" {
  description = "Self link to the VM instance"
  value       = google_compute_instance.vaidc.self_link
}

output "external_ip" {
  description = "External IP address of the vAIDC VM"
  value       = google_compute_instance.vaidc.network_interface[0].access_config[0].nat_ip
}

output "internal_ip" {
  description = "Internal IP address of the vAIDC VM"
  value       = google_compute_instance.vaidc.network_interface[0].network_ip
}

output "zone" {
  description = "Zone where the VM is deployed"
  value       = google_compute_instance.vaidc.zone
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "gcloud compute ssh ${google_compute_instance.vaidc.name} --zone=${google_compute_instance.vaidc.zone} --project=${var.project_id}"
}

output "grafana_url" {
  description = "URL to access Grafana dashboards"
  value       = "http://${google_compute_instance.vaidc.network_interface[0].access_config[0].nat_ip}:3000"
}

output "gitea_url" {
  description = "URL to access Gitea repository"
  value       = "http://${google_compute_instance.vaidc.network_interface[0].access_config[0].nat_ip}:3001"
}

output "argocd_url" {
  description = "URL to access ArgoCD"
  value       = "http://${google_compute_instance.vaidc.network_interface[0].access_config[0].nat_ip}:8080"
}

output "prometheus_url" {
  description = "URL to access Prometheus"
  value       = "http://${google_compute_instance.vaidc.network_interface[0].access_config[0].nat_ip}:9090"
}

output "argocd_password_command" {
  description = "Command to retrieve ArgoCD admin password"
  value       = "gcloud compute ssh ${google_compute_instance.vaidc.name} --zone=${google_compute_instance.vaidc.zone} --project=${var.project_id} --command=\"kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d && echo\""
}

output "vlab_status_command" {
  description = "Command to check VLAB status"
  value       = "gcloud compute ssh ${google_compute_instance.vaidc.name} --zone=${google_compute_instance.vaidc.zone} --project=${var.project_id} --command=\"cd ~/hhfab && hhfab vlab inspect\""
}
