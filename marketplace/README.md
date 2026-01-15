# Hedgehog vAIDC - GCP Marketplace Templates

This directory contains the Google Cloud Platform Marketplace deployment templates for the Hedgehog Virtual AI Data Center (vAIDC).

## Quick Links

- [**GCP Marketplace Publishing Guide**](./GCP_MARKETPLACE_PUBLISHING_GUIDE.md) - Complete step-by-step instructions
- [**Terraform Module**](./terraform/) - Recommended deployment method
- [**EULA**](./legal/EULA.md) - End User License Agreement

## Directory Structure

```
marketplace/
├── hedgehog-vaidc.jinja           # Deployment Manager main template
├── hedgehog-vaidc.jinja.schema    # DM schema definition
├── hedgehog-vaidc.jinja.display   # Marketplace UI configuration
├── c2d_deployment_configuration.json  # Click-to-deploy config
├── test_config.yaml               # Local DM testing
├── GCP_MARKETPLACE_PUBLISHING_GUIDE.md  # Publication instructions
├── terraform/                     # Terraform module (recommended)
│   ├── main.tf                    # Main configuration
│   ├── variables.tf               # Variable definitions
│   ├── outputs.tf                 # Output definitions
│   ├── metadata.display.yaml      # UI metadata
│   ├── marketplace_test.tfvars    # Test variables
│   └── README.md                  # Module documentation
└── legal/
    └── EULA.md                    # End User License Agreement
```

## Files

| File | Purpose |
|------|---------|
| `hedgehog-vaidc.jinja` | Main Deployment Manager template |
| `hedgehog-vaidc.jinja.schema` | Schema defining template properties |
| `hedgehog-vaidc.jinja.display` | Display metadata for Marketplace UI |
| `c2d_deployment_configuration.json` | Click-to-deploy configuration |
| `test_config.yaml` | Test configuration for local validation |
| `GCP_MARKETPLACE_PUBLISHING_GUIDE.md` | Complete publication guide |
| `terraform/*` | Terraform deployment module |
| `legal/EULA.md` | End User License Agreement |

## Deployment Methods

### Terraform (Recommended)

Terraform is the recommended deployment method as Cloud Deployment Manager will reach end of support on March 31, 2026.

```bash
cd terraform
terraform init
terraform plan -var project_id=YOUR_PROJECT_ID
terraform apply -var project_id=YOUR_PROJECT_ID
```

See [terraform/README.md](./terraform/README.md) for detailed instructions.

### Deployment Manager (Legacy)

```bash
gcloud deployment-manager deployments create vaidc \
    --config test_config.yaml \
    --project YOUR_PROJECT_ID
```

## Updating the Image

When a new vAIDC image is created, update the image name in these locations:

1. **`hedgehog-vaidc.jinja`** - Line with `vaidcImage` variable:
   ```jinja
   {% set vaidcImage = "projects/teched-473722/global/images/YOUR_NEW_IMAGE_NAME" %}
   ```

2. **`c2d_deployment_configuration.json`** - The `imageName` field:
   ```json
   "imageName": "YOUR_NEW_IMAGE_NAME"
   ```

## Testing Locally

Before submitting to Marketplace, test the template:

```bash
# Create a test deployment
gcloud deployment-manager deployments create test-vaidc \
    --config test_config.yaml \
    --project YOUR_PROJECT_ID

# Check deployment status
gcloud deployment-manager deployments describe test-vaidc \
    --project YOUR_PROJECT_ID

# Delete test deployment
gcloud deployment-manager deployments delete test-vaidc \
    --project YOUR_PROJECT_ID
```

## Marketplace Submission

See Issue #136 for complete Marketplace publication instructions.

## Firewall Ports

The template creates a firewall rule allowing:
- TCP 80 (HTTP/landing page)
- TCP 443 (HTTPS)
- TCP 3000 (Grafana)
- TCP 3001 (Gitea)
- TCP 8080 (ArgoCD)
- TCP 9090 (Prometheus)

## Machine Requirements

- Nested virtualization support required
- Minimum: 16 vCPUs, 32GB RAM
- Recommended: n1-standard-32
- Boot disk: 300GB (minimum 200GB)
