# Hedgehog vAIDC - Terraform Deployment Module

This Terraform module deploys the Hedgehog Virtual AI Data Center (vAIDC) on Google Cloud Platform.

## Overview

The vAIDC is a pre-configured lab environment for learning Hedgehog Fabric network operations, including:

- **VLAB**: 7 virtual SONiC switches (2 spines, 5 leaves), 10 virtual servers, 1 control node
- **Grafana**: Monitoring dashboards with Hedgehog-specific views
- **Prometheus**: Metrics collection and alerting
- **ArgoCD**: GitOps-based configuration management
- **Gitea**: Git repository for infrastructure as code
- **Loki**: Log aggregation

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0.0 |
| google | >= 4.0.0, < 6.0.0 |
| random | >= 3.0.0 |

## Machine Requirements

- **Nested virtualization support required**
- Minimum: 16 vCPUs, 32GB RAM
- Recommended: n1-standard-32
- Boot disk: 300GB (minimum 200GB)

## Usage

### Basic Deployment

```hcl
module "vaidc" {
  source     = "./terraform"
  project_id = "your-project-id"
  zone       = "us-west1-c"
}
```

### Custom Configuration

```hcl
module "vaidc" {
  source            = "./terraform"
  project_id        = "your-project-id"
  zone              = "us-central1-a"
  machine_type      = "n1-highmem-32"
  boot_disk_size_gb = 400
  network           = "projects/your-project/global/networks/custom-network"
  subnetwork        = "projects/your-project/regions/us-central1/subnetworks/custom-subnet"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| project_id | GCP project ID | `string` | n/a | yes |
| zone | GCP zone (must support nested virtualization) | `string` | `"us-west1-c"` | no |
| machine_type | Machine type (min 16 vCPUs, 32GB RAM) | `string` | `"n1-standard-32"` | no |
| network | Network for the VM | `string` | `"default"` | no |
| subnetwork | Subnetwork for the VM | `string` | `""` | no |
| boot_disk_size_gb | Boot disk size in GB (200-1000) | `number` | `300` | no |
| boot_disk_type | Boot disk type | `string` | `"pd-balanced"` | no |
| source_image | Source VM image | `string` | `"projects/teched-473722/global/images/hedgehog-vaidc-v20260114"` | no |
| firewall_source_ranges | Source IP ranges for firewall | `list(string)` | `["0.0.0.0/0"]` | no |

## Outputs

| Name | Description |
|------|-------------|
| vm_name | Name of the vAIDC VM instance |
| external_ip | External IP address of the VM |
| grafana_url | URL to access Grafana (port 3000) |
| gitea_url | URL to access Gitea (port 3001) |
| argocd_url | URL to access ArgoCD (port 8080) |
| prometheus_url | URL to access Prometheus (port 9090) |
| ssh_command | SSH command to connect to the VM |
| argocd_password_command | Command to retrieve ArgoCD admin password |
| vlab_status_command | Command to check VLAB status |

## Post-Deployment Access

After deployment (allow 5-10 minutes for services to initialize):

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Grafana | http://[EXTERNAL_IP]:3000 | admin / admin |
| Gitea | http://[EXTERNAL_IP]:3001 | student01 / hedgehog123 |
| ArgoCD | http://[EXTERNAL_IP]:8080 | admin / (retrieve via SSH) |
| Prometheus | http://[EXTERNAL_IP]:9090 | No auth required |

## Testing

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Preview deployment
terraform plan -var project_id=YOUR_PROJECT_ID

# Deploy
terraform apply -var project_id=YOUR_PROJECT_ID

# Test with marketplace variables
terraform plan -var-file=marketplace_test.tfvars
```

## Firewall Ports

The module creates a firewall rule allowing:

| Port | Service |
|------|---------|
| 80 | HTTP |
| 443 | HTTPS |
| 3000 | Grafana |
| 3001 | Gitea |
| 8080 | ArgoCD |
| 9090 | Prometheus |

## License

Apache 2.0 - See [LICENSE](../../LICENSE) for details.
