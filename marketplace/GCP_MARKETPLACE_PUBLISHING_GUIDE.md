# Hedgehog vAIDC - GCP Marketplace Publishing Guide

This document provides step-by-step instructions for publishing the Hedgehog Virtual AI Data Center (vAIDC) to Google Cloud Marketplace.

## Table of Contents

1. [Prerequisites Checklist](#prerequisites-checklist)
2. [Step 1: Partner Account Registration](#step-1-partner-account-registration)
3. [Step 2: GCP Environment Setup](#step-2-gcp-environment-setup)
4. [Step 3: VM Image Preparation](#step-3-vm-image-preparation)
5. [Step 4: Deployment Package Configuration](#step-4-deployment-package-configuration)
6. [Step 5: EULA Setup](#step-5-eula-setup)
7. [Step 6: Producer Portal Submission](#step-6-producer-portal-submission)
8. [Step 7: Post-Publication Maintenance](#step-7-post-publication-maintenance)
9. [Timeline Estimates](#timeline-estimates)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites Checklist

Before starting the publication process, ensure you have:

- [ ] Google Cloud account with billing enabled
- [ ] Company authorized to represent Hedgehog
- [ ] Access to hedgehog.cloud domain for EULA hosting
- [ ] VM image `hedgehog-vaidc-v20260114` ready in project `teched-473722`
- [ ] Deployment Manager templates validated
- [ ] Terraform module validated
- [ ] EULA document finalized

### Current Asset Status

| Asset | Location | Status |
|-------|----------|--------|
| VM Image | `projects/teched-473722/global/images/hedgehog-vaidc-v20260114` | READY |
| DM Templates | `/marketplace/*.jinja*` | Validated |
| Terraform Module | `/marketplace/terraform/` | Validated |
| EULA | `/marketplace/legal/EULA.md` | Draft Complete |
| C2D Config | `/marketplace/c2d_deployment_configuration.json` | Ready |

---

## Step 1: Partner Account Registration

### 1.1 Join Google Cloud Partner Advantage

1. Go to [Google Cloud Partner Advantage Registration](https://www.partneradvantage.goog/GCPPRM/s/memberregistration)
2. Select **"Build"** engagement model (for ISV/software vendors)
3. Complete company profile:
   - Company name: Hedgehog
   - Company website: https://hedgehog.cloud
   - Industry: Technology / Network Infrastructure
4. Sign the Partner Program Agreement
5. Wait for approval (typically 2-3 business days)

### 1.2 Access Partner Hub

After approval:
1. Sign in to [Partner Hub](https://partners.cloud.google.com/)
2. Navigate to **Cloud Marketplace** section
3. Click **"Become a Marketplace Vendor"**

### 1.3 Complete Cloud Marketplace Project Info Form

Google will provide a form to collect:
- GCP project IDs (dev and public projects)
- Product overview
- Contact information
- Technical requirements

---

## Step 2: GCP Environment Setup

### 2.1 Project Structure

Create two dedicated GCP projects:

```bash
# Development/testing project
gcloud projects create hedgehog-dev \
  --name="Hedgehog Development" \
  --organization=YOUR_ORG_ID

# Public image hosting project
gcloud projects create hedgehog-public \
  --name="Hedgehog Public" \
  --organization=YOUR_ORG_ID
```

**Note:** If using existing project `teched-473722`, ensure it follows the naming convention or create separate projects for production.

### 2.2 Enable Required APIs

```bash
# Enable APIs in both projects
for PROJECT in hedgehog-dev hedgehog-public; do
  gcloud services enable compute.googleapis.com --project=$PROJECT
  gcloud services enable deploymentmanager.googleapis.com --project=$PROJECT
  gcloud services enable servicemanagement.googleapis.com --project=$PROJECT
done
```

### 2.3 Configure IAM for Marketplace Onboarding

After Google provides access to Producer Portal, grant these roles:

```bash
PROJECT_ID="teched-473722"  # or your public project

# Grant Editor and Service Management Admin to onboarding service account
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloud-commerce-marketplace-onboarding@twosync-src.google.com.iam.gserviceaccount.com" \
  --role="roles/editor"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloud-commerce-marketplace-onboarding@twosync-src.google.com.iam.gserviceaccount.com" \
  --role="roles/servicemanagement.admin"

# Grant Config Editor to producer service account
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloud-commerce-producer@system.gserviceaccount.com" \
  --role="roles/servicemanagement.configEditor"
```

### 2.4 Configure Security Contact

Set a security contact for the project:

```bash
gcloud resource-manager contacts create \
  --contact-id="security-contact" \
  --email="security@hedgehog.cloud" \
  --notification-category-subscriptions="security" \
  --project=$PROJECT_ID
```

---

## Step 3: VM Image Preparation

### 3.1 Verify Image Readiness

```bash
# Check image exists and is ready
gcloud compute images describe hedgehog-vaidc-v20260114 \
  --project=teched-473722 \
  --format="yaml(name,status,family,diskSizeGb,licenses)"
```

Expected output:
```yaml
name: hedgehog-vaidc-v20260114
status: READY
family: hedgehog-labapp
diskSizeGb: '300'
licenses:
- https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2404-lts
```

### 3.2 Image Requirements Checklist

Verify the image meets GCP Marketplace requirements:

- [x] No hardcoded credentials or secrets
- [x] SSH authentication functional (OS Login enabled)
- [x] All services auto-start on boot
- [x] Ubuntu 24.04 LTS base
- [x] Nested virtualization enabled
- [x] 300GB boot disk with lab environment

### 3.3 Make Image Public (Optional)

For testing purposes, you can make the image accessible:

```bash
# Share image with all authenticated users (for testing)
gcloud compute images add-iam-policy-binding hedgehog-vaidc-v20260114 \
  --project=teched-473722 \
  --member="allAuthenticatedUsers" \
  --role="roles/compute.imageUser"
```

**Note:** For production, use "Marketplace owned images" option in Producer Portal.

---

## Step 4: Deployment Package Configuration

### 4.1 Deployment Options

The vAIDC supports two deployment methods:

| Method | Status | Recommendation |
|--------|--------|----------------|
| Terraform | Validated | **Recommended** (DM deprecated March 2026) |
| Deployment Manager | Validated | Supported until March 2026 |

### 4.2 Test Deployment Manager Templates

```bash
cd /home/ubuntu/afewell-hh/labapp/marketplace

# Preview deployment
gcloud deployment-manager deployments create test-vaidc \
  --config test_config.yaml \
  --project=teched-473722 \
  --preview

# Verify resources
gcloud deployment-manager deployments describe test-vaidc \
  --project=teched-473722

# Clean up
gcloud deployment-manager deployments delete test-vaidc \
  --project=teched-473722 --quiet
```

### 4.3 Test Terraform Module

```bash
cd /home/ubuntu/afewell-hh/labapp/marketplace/terraform

# Initialize
terraform init

# Validate
terraform validate

# Plan (requires authentication)
terraform plan -var-file=marketplace_test.tfvars

# Apply (optional - creates real resources)
# terraform apply -var-file=marketplace_test.tfvars
```

### 4.4 Configure Producer Portal

In Producer Portal, configure the deployment package:

1. **Deployment method:** Select both Terraform and Deployment Manager
2. **Use Marketplace owned images:** Enable (required for Terraform)
3. **VM image:** Select `hedgehog-vaidc-v20260114`
4. **Default zone:** `us-west1-c`
5. **Default machine type:** `n1-standard-32`
6. **Minimum requirements:** 16 vCPUs, 32GB RAM
7. **Boot disk:** 300GB pd-balanced

---

## Step 5: EULA Setup

### 5.1 Host EULA Document

The EULA must be publicly accessible. Options:

**Option A: Host on hedgehog.cloud**
1. Convert `marketplace/legal/EULA.md` to HTML or PDF
2. Upload to `https://hedgehog.cloud/vaidc-terms`
3. Verify accessibility

**Option B: Use GitHub Raw URL**
1. Commit EULA to repository
2. Use raw GitHub URL: `https://raw.githubusercontent.com/afewell-hh/labapp/main/marketplace/legal/EULA.md`

### 5.2 EULA Requirements

- **Format:** PDF (max 4MB) or URL to hosted document
- **Content:** Must include permitted use, prohibited use, warranty disclaimer, liability limitations
- **Display name:** "Hedgehog vAIDC Terms of Service"

### 5.3 Update Display Configuration

The display configuration references the EULA URL:

```yaml
# In hedgehog-vaidc.jinja.display
eulaUrl: https://hedgehog.cloud/vaidc-terms
```

Update this URL once the EULA is hosted.

---

## Step 6: Producer Portal Submission

### 6.1 Create Product in Producer Portal

1. Go to [Producer Portal](https://console.cloud.google.com/partner/products)
2. Click **"Add product"**
3. Select **"Virtual machine"**
4. Enter product details:
   - **Product name:** Hedgehog Virtual AI Data Center (vAIDC)
   - **Product ID:** `hedgehog-vaidc` (cannot be changed)
   - **Version:** 1.0.0

### 6.2 Configure Product Details

**Overview Tab:**
- Title: Hedgehog Virtual AI Data Center (vAIDC)
- Tagline: Pre-configured lab environment for Hedgehog Fabric training
- Description: (from display file)
- Categories: Developer Tools, Networking
- Support: https://docs.hedgehog.cloud/vaidc

**Technical Tab:**
- Deployment package configuration (from Step 4)
- Machine requirements
- Firewall rules

**Pricing Tab:**
- Pricing model: Free
- Users pay only for GCP compute resources

**Legal Tab:**
- EULA URL: https://hedgehog.cloud/vaidc-terms
- Privacy policy URL: https://hedgehog.cloud/privacy

### 6.3 Submit for Review

1. Complete all required fields
2. Click **"Submit for review"**
3. Wait for Google review (1-2 weeks typical)

### 6.4 Address Review Feedback

Google may request changes. Common feedback includes:
- Documentation improvements
- Security enhancements
- Metadata corrections

---

## Step 7: Post-Publication Maintenance

### 7.1 Monitor Usage

Track product performance in Producer Portal:
- Deployments per day/week/month
- Geographic distribution
- Error rates

### 7.2 Update Process

To release a new version:

1. Create new VM image with updates
2. Update image reference in templates:
   ```bash
   # In hedgehog-vaidc.jinja
   {% set vaidcImage = "projects/teched-473722/global/images/hedgehog-vaidc-vYYYYMMDD" %}

   # In c2d_deployment_configuration.json
   "imageName": "hedgehog-vaidc-vYYYYMMDD"

   # In terraform/variables.tf
   default = "projects/teched-473722/global/images/hedgehog-vaidc-vYYYYMMDD"
   ```
3. Test updated templates
4. Submit update in Producer Portal

### 7.3 Support Requests

Handle customer support through:
- Documentation at https://docs.hedgehog.cloud/vaidc
- Community forums at https://hedgehog.cloud/community
- Email support (as needed)

---

## Timeline Estimates

| Phase | Duration | Notes |
|-------|----------|-------|
| Partner registration | 3-5 business days | Initial approval |
| Environment setup | 1-2 days | Projects, IAM, APIs |
| Template testing | 1 day | Both DM and Terraform |
| EULA hosting | 1 day | Depends on web team |
| Producer Portal submission | 1 day | Complete all fields |
| Google review | 1-2 weeks | May require revisions |
| **Total** | **2-4 weeks** | End-to-end |

---

## Troubleshooting

### Common Issues

**IAM Permission Errors**
```
Error: Service account does not exist
```
Solution: IAM bindings for marketplace service accounts are only valid after Partner registration is complete and Producer Portal access is granted.

**Deployment Manager API Not Enabled**
```bash
gcloud services enable deploymentmanager.googleapis.com --project=PROJECT_ID
```

**Terraform Provider Authentication**
```bash
gcloud auth application-default login
```

**Image Not Found**
```bash
# Verify image exists
gcloud compute images list --project=teched-473722 --filter="name~hedgehog-vaidc"
```

### Support Resources

- [GCP Marketplace Partner Documentation](https://cloud.google.com/marketplace/docs/partners)
- [Producer Portal Help](https://cloud.google.com/marketplace/docs/partners/vm)
- [Deployment Manager Documentation](https://cloud.google.com/deployment-manager/docs)
- [Terraform GCP Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)

---

## File Inventory

| File | Purpose |
|------|---------|
| `hedgehog-vaidc.jinja` | Deployment Manager main template |
| `hedgehog-vaidc.jinja.schema` | DM schema definition |
| `hedgehog-vaidc.jinja.display` | Marketplace UI configuration |
| `c2d_deployment_configuration.json` | Click-to-deploy config |
| `test_config.yaml` | Local DM testing |
| `terraform/main.tf` | Terraform main configuration |
| `terraform/variables.tf` | Terraform variables |
| `terraform/outputs.tf` | Terraform outputs |
| `terraform/metadata.display.yaml` | Terraform UI metadata |
| `terraform/marketplace_test.tfvars` | Terraform test variables |
| `legal/EULA.md` | End User License Agreement |

---

## Next Steps

1. [ ] Complete Partner Advantage registration
2. [ ] Host EULA at https://hedgehog.cloud/vaidc-terms
3. [ ] Configure Producer Portal with deployment package
4. [ ] Submit product for Google review
5. [ ] Address any review feedback
6. [ ] Test published product from Marketplace
7. [ ] Announce availability to users

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Author:** Hedgehog Team
