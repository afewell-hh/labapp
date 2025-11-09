## GCP Nested Virtualization Builder - User Guide

This guide explains how to use the GCP nested virtualization builder system to create OVA builds for the Hedgehog Lab appliance.

**Status:** This is the **primary recommended builder** for the Hedgehog Lab project. All artifacts are automatically uploaded to Google Cloud Storage (GCS).

### Overview

Building OVAs requires significant resources and nested virtualization support:
- **Disk Space**: 200-300GB during build (standard) or 600GB+ (pre-warmed)
- **Nested Virtualization**: KVM support required for QEMU builds
- **Build Time**: 45-60 minutes (standard) or 60-90 minutes (pre-warmed)
- **Cost**: ~$4-15 per build (pay-per-use)
- **Artifact Storage**: Automatic upload to GCS (Google Cloud Storage)

The GCP builder system provides automated VM provisioning with built-in cost controls, automatic cleanup, and seamless GCS integration.

**Why GCP Builder?**
- **Primary Method:** Official builder for all release artifacts
- **Integrated Storage:** Automatic upload to GCS bucket during build
- **Cost Effective:** ~$4 for standard builds, ~$15 for pre-warmed
- **Native KVM:** Full nested virtualization support
- **Audit Trail:** Build logs uploaded to GCS for tracking

**Alternate:** AWS Metal Builder is available as an alternate option for future marketplace integration. See [AWS Metal Build Guide](AWS_METAL_BUILD.md).

### Architecture

```
┌─────────────────────────────────────────────┐
│  Developer                                  │
│  └─> scripts/launch-gcp-build.sh           │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│  Terraform Infrastructure (Optional)        │
│  ├─ GCE n2-standard-32 instance            │
│  ├─ 600GB+ SSD persistent disk             │
│  └─ Auto-shutdown script (cost control)    │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│  Build Execution (on instance)              │
│  └─> Packer → Build → Upload to GCS        │
└─────────────────────────────────────────────┘
```

### Prerequisites

#### 1. GCP Account Setup

**Create GCP Project:**
```bash
# Set project ID (use your own unique ID)
export GCP_PROJECT_ID="hedgehog-lab-builder"

# Create project
gcloud projects create $GCP_PROJECT_ID

# Set as default
gcloud config set project $GCP_PROJECT_ID

# Link billing account (required for Compute Engine)
gcloud beta billing projects link $GCP_PROJECT_ID \
  --billing-account=YOUR_BILLING_ACCOUNT_ID
```

**Enable Required APIs:**
```bash
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
```

#### 2. Install Required Tools

```bash
# Google Cloud SDK
# See: https://cloud.google.com/sdk/docs/install

# macOS
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Ubuntu/Debian
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
  https://packages.cloud.google.com/apt cloud-sdk main" | \
  sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
  sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-sdk

# Terraform (optional, for infrastructure-as-code approach)
brew install terraform  # macOS
# or
sudo apt-get install terraform  # Ubuntu

# jq (JSON processor)
brew install jq  # macOS
# or
sudo apt-get install jq  # Ubuntu
```

#### 3. Configure Authentication

**Create Service Account:**
```bash
# Create service account for builder
gcloud iam service-accounts create hedgehog-builder \
  --display-name="Hedgehog Lab Builder"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:hedgehog-builder@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.instanceAdmin.v1"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:hedgehog-builder@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:hedgehog-builder@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

# Create and download key
gcloud iam service-accounts keys create ~/hedgehog-builder-key.json \
  --iam-account=hedgehog-builder@${GCP_PROJECT_ID}.iam.gserviceaccount.com
```

**Set up Application Default Credentials:**
```bash
# Option 1: Use service account key
export GOOGLE_APPLICATION_CREDENTIALS=~/hedgehog-builder-key.json

# Option 2: Use gcloud auth (for interactive use)
gcloud auth application-default login
```

#### 4. Create GCS Bucket for Artifacts

```bash
# Create bucket (use unique name)
export GCS_BUCKET="hedgehog-lab-artifacts-${GCP_PROJECT_ID}"

gsutil mb -p $GCP_PROJECT_ID \
  -c STANDARD \
  -l us-central1 \
  gs://$GCS_BUCKET/

# Set lifecycle policy (optional: auto-delete old builds after 90 days)
cat > lifecycle.json <<EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {
          "age": 90,
          "matchesPrefix": ["builds/"]
        }
      }
    ]
  }
}
EOF

gsutil lifecycle set lifecycle.json gs://$GCS_BUCKET/
rm lifecycle.json
```

#### 5. Configure Environment Variables

Create `.env.gcp` file in project root (this file is gitignored):

```bash
# Copy template
cp .env.gcp.example .env.gcp

# Edit with your values
vim .env.gcp
```

Required variables in `.env.gcp`:
```bash
# GCP Configuration
GCP_PROJECT_ID="hedgehog-lab-builder"
GCP_REGION="us-central1"
GCP_ZONE="us-central1-a"

# Service Account
GCP_SERVICE_ACCOUNT="hedgehog-builder@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
GCP_SERVICE_ACCOUNT_KEY_PATH="${HOME}/hedgehog-builder-key.json"

# Storage
GCS_BUCKET="hedgehog-lab-artifacts-${GCP_PROJECT_ID}"
GCS_ARTIFACT_PATH="releases"

# Build Instance Configuration
GCP_MACHINE_TYPE="n2-standard-32"          # 32 vCPUs, 128GB RAM
GCP_DISK_SIZE="600"                        # GB
GCP_DISK_TYPE="pd-ssd"                     # SSD for performance

# Cost Controls
GCP_MAX_BUILD_TIME_HOURS="4"               # Auto-shutdown after 4 hours
GCP_ENABLE_PREEMPTIBLE="false"             # Set to "true" for 80% cost savings (may be interrupted)

# Network
GCP_NETWORK="default"
GCP_SUBNETWORK=""                          # Leave empty to use default
```

### Quick Start

#### Launch a Build

```bash
cd /home/ubuntu/afewell-hh/labapp

# Ensure .env.gcp is configured
source .env.gcp

# Build from main branch
./scripts/launch-gcp-build.sh main

# Build from specific branch
./scripts/launch-gcp-build.sh feature/my-feature

# Build from specific commit
./scripts/launch-gcp-build.sh main abc1234

# Dry-run (validate without creating resources)
./scripts/launch-gcp-build.sh --dry-run main
```

The script will:
1. Load environment variables from `.env` and `.env.gcp`
2. Verify GCP credentials and quotas
3. Display cost estimate
4. Ask for confirmation
5. Create GCP compute instance with nested virtualization
6. Sync repository and run Packer build
7. Upload artifacts to GCS
8. Optionally cleanup resources

#### Monitor Build Progress

**Option 1: SSH to Instance**
```bash
# Get instance name from script output
gcloud compute ssh builder-$(date +%Y%m%d-%H%M%S) \
  --zone=$GCP_ZONE \
  --project=$GCP_PROJECT_ID

# View logs on instance
tail -f /var/log/gcp-build.log
```

**Option 2: Serial Port Output**
```bash
# View serial console output
gcloud compute instances get-serial-port-output INSTANCE_NAME \
  --zone=$GCP_ZONE \
  --project=$GCP_PROJECT_ID
```

**Option 3: Cloud Logging**
```bash
# View logs in Cloud Logging
gcloud logging read "resource.type=gce_instance AND \
  resource.labels.instance_id=INSTANCE_ID" \
  --limit 50 \
  --format json
```

#### Cleanup Resources

**Automatic Cleanup:**
- Build completes successfully → Instance self-terminates
- Build fails → Instance remains for debugging (manual cleanup required)
- Timeout (4 hours) → Instance auto-shutdowns via shutdown script

**Manual Cleanup:**
```bash
# List all builder instances
gcloud compute instances list \
  --filter="labels.purpose=labapp-builder" \
  --project=$GCP_PROJECT_ID

# Delete specific instance
gcloud compute instances delete INSTANCE_NAME \
  --zone=$GCP_ZONE \
  --project=$GCP_PROJECT_ID \
  --quiet
```

### Recommended Machine Types

| Machine Type | vCPUs | RAM | Disk | Use Case | Cost/Hour* |
|--------------|-------|-----|------|----------|-----------|
| n2-standard-16 | 16 | 64GB | 300GB | Standard builds only | ~$0.78 |
| n2-standard-32 | 32 | 128GB | 600GB | Pre-warmed builds (recommended) | ~$1.55 |
| n2-highmem-32 | 32 | 256GB | 600GB | Memory-intensive builds | ~$2.08 |
| c2-standard-30 | 30 | 120GB | 600GB | Compute-optimized | ~$1.66 |

*Approximate us-central1 pricing, subject to change

**Cost Savings Options:**
- **Preemptible VMs**: 80% discount, may be interrupted (set `GCP_ENABLE_PREEMPTIBLE="true"`)
- **Spot VMs**: Similar to preemptible, newer offering
- **Committed Use Discounts**: 1 or 3-year commitment for ~37-55% savings

### Verifying Nested Virtualization

The builder script automatically enables nested virtualization, but you can verify:

```bash
# SSH into instance
gcloud compute ssh INSTANCE_NAME --zone=$GCP_ZONE

# Check if KVM is available
sudo apt-get install -y cpu-checker
kvm-ok

# Expected output:
# INFO: /dev/kvm exists
# KVM acceleration can be used
```

### Cost Management

#### Estimated Costs

**Standard Build (~60 minutes):**
- Compute (n2-standard-32): $1.55/hr × 1hr = $1.55
- SSD Disk (300GB): $0.17/GB/month × 300GB × (1hr/730hr) = $0.07
- Network egress (20GB): $0.12/GB × 20GB = $2.40
- **Total: ~$4.00**

**Pre-Warmed Build (~90 minutes):**
- Compute (n2-standard-32): $1.55/hr × 1.5hr = $2.33
- SSD Disk (600GB): $0.17/GB/month × 600GB × (1.5hr/730hr) = $0.21
- Network egress (100GB): $0.12/GB × 100GB = $12.00
- **Total: ~$14.50**

**Maximum (4-hour timeout):**
- Compute: $1.55/hr × 4hr = $6.20
- SSD Disk: $0.40
- Network egress: ~$12.00
- **Total: ~$18.60**

#### Cost Controls

1. **Auto-Shutdown Script**: Terminates instance after max build time
2. **Budget Alerts**: Configure in GCP Console for spending notifications
3. **Preemptible VMs**: Enable for 80% cost savings (with interruption risk)
4. **Resource Quotas**: Prevent accidental over-provisioning
5. **Manual Confirmation**: Required before each launch

#### Set Up Budget Alerts

```bash
# Create budget alert for $100/month
gcloud billing budgets create \
  --billing-account=YOUR_BILLING_ACCOUNT_ID \
  --display-name="Hedgehog Lab Builder Budget" \
  --budget-amount=100 \
  --threshold-rule=percent=50 \
  --threshold-rule=percent=90 \
  --threshold-rule=percent=100
```

### Local Validation Harness

Before running expensive cloud builds, validate changes locally:

#### Validation Targets

```bash
# Run all pre-flight validation
make test-modules

# Individual validation targets
make validate-provisioning    # Test provisioning scripts
make validate-orchestrator    # Test orchestrator logic
make dry-run-build           # Validate Packer without building

# Syntax and linting
make lint                    # shellcheck, yamllint, terraform fmt
```

#### Test Provisioning Scripts

```bash
# Run provisioning scripts in test container
make test-provisioning

# Test specific script
make test-script SCRIPT=packer/scripts/01-install-base.sh
```

#### Dry-Run Packer Build

```bash
# Validate Packer template without building
packer validate packer/standard-build.pkr.hcl

# Check what Packer would do (no actual build)
packer inspect packer/standard-build.pkr.hcl
```

### Integration with CI/CD

#### GitHub Actions Workflow

The repository includes a workflow that runs validation on every PR:

`.github/workflows/ci.yml`:
- Runs `make test-modules` to validate provisioning scripts
- Runs `make validate` to check Packer templates
- Runs `shellcheck` on all shell scripts
- Validates Terraform configurations

#### Manual GCP Build via Workflow Dispatch

Create `.github/workflows/gcp-build.yml`:

```yaml
name: GCP Build

on:
  workflow_dispatch:
    inputs:
      branch:
        description: 'Branch to build'
        required: true
        default: 'main'
      build_type:
        description: 'Build type (standard or prewarmed)'
        required: true
        default: 'standard'
        type: choice
        options:
          - standard
          - prewarmed

jobs:
  launch-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup gcloud CLI
        uses: google-github-actions/setup-gcloud@v1
        with:
          service_account_key: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
          project_id: ${{ secrets.GCP_PROJECT_ID }}

      - name: Launch GCP Build
        run: |
          # Configure .env.gcp from secrets
          cat > .env.gcp <<EOF
          GCP_PROJECT_ID="${{ secrets.GCP_PROJECT_ID }}"
          GCP_ZONE="${{ secrets.GCP_ZONE }}"
          GCS_BUCKET="${{ secrets.GCS_BUCKET }}"
          EOF

          # Launch build
          ./scripts/launch-gcp-build.sh \
            --auto-approve \
            --build-type=${{ github.event.inputs.build_type }} \
            ${{ github.event.inputs.branch }}
```

### Troubleshooting

#### Build Fails to Launch

**Error: "Project not found"**
- Verify `GCP_PROJECT_ID` is correct
- Ensure project is created: `gcloud projects list`

**Error: "Permission denied"**
- Verify service account has required roles
- Check `GOOGLE_APPLICATION_CREDENTIALS` is set correctly
- Ensure service account key is not expired

**Error: "Quota exceeded"**
- Check compute quotas: `gcloud compute project-info describe --project=$GCP_PROJECT_ID`
- Request quota increase in GCP Console

#### Build Fails During Execution

**Packer build fails:**
- SSH to instance and check `/var/log/gcp-build.log`
- Verify nested virtualization: Run `kvm-ok` on instance
- Check disk space: `df -h`

**Upload to GCS fails:**
- Verify bucket exists: `gsutil ls gs://$GCS_BUCKET/`
- Check service account permissions
- Verify network connectivity

#### Instance Won't Terminate

**Auto-shutdown failed:**
- Check shutdown script logs: `sudo journalctl -u google-shutdown-scripts`
- Manually delete: `gcloud compute instances delete INSTANCE_NAME --zone=$GCP_ZONE`

**Orphaned resources:**
```bash
# List all instances with builder label
gcloud compute instances list --filter="labels.purpose=labapp-builder"

# Delete all builder instances
gcloud compute instances list --filter="labels.purpose=labapp-builder" \
  --format="value(name,zone)" | \
  while read name zone; do
    gcloud compute instances delete $name --zone=$zone --quiet
  done
```

### Advanced Usage

#### Custom Machine Type

```bash
# Edit .env.gcp
GCP_MACHINE_TYPE="custom-32-131072"  # 32 vCPUs, 128GB RAM
```

#### Using Preemptible VMs (80% Cost Savings)

```bash
# Edit .env.gcp
GCP_ENABLE_PREEMPTIBLE="true"

# Note: Build may be interrupted, suitable for development builds
```

#### Multi-Region Builds

```bash
# Build in different region
GCP_ZONE="europe-west1-b" ./scripts/launch-gcp-build.sh main
```

#### Persistent Build Cache

Create a persistent disk for Packer cache to speed up repeated builds:

```bash
# Create persistent cache disk
gcloud compute disks create packer-cache \
  --size=100GB \
  --type=pd-ssd \
  --zone=$GCP_ZONE

# Attach to builder instance (modify startup script)
```

### Build Artifacts

Successful builds upload to GCS:

**Bucket**: `gs://${GCS_BUCKET}/`

**Path Structure**:
```
releases/v<version>/
  ├─ hedgehog-lab-standard-<version>.ova
  ├─ hedgehog-lab-standard-<version>.ova.sha256
  ├─ hedgehog-lab-prewarmed-<version>.ova
  ├─ hedgehog-lab-prewarmed-<version>.ova.sha256
  └─ build-manifest.json  (metadata)

builds/<build-id>/
  └─ logs/
     └─ build.log
```

**Download Artifact**:
```bash
gsutil cp \
  gs://${GCS_BUCKET}/releases/v0.2.0/hedgehog-lab-standard-0.2.0.ova \
  ./
```

**Generate Signed URL (for sharing)**:
```bash
gsutil signurl -d 7d \
  ${GCP_SERVICE_ACCOUNT_KEY_PATH} \
  gs://${GCS_BUCKET}/releases/v0.2.0/hedgehog-lab-standard-0.2.0.ova
```

### Security Considerations

#### Service Account Permissions

The service account has minimal required permissions:
- Compute: Create/delete instances, manage disks
- Storage: Read/write to specific GCS bucket only
- IAM: Use service account credentials

#### Network Security

- Instance uses default VPC with firewall rules
- SSH access restricted to IAM-authenticated users
- No external services exposed during build

#### Secrets Management

- Service account key stored locally (never committed to git)
- `.env.gcp` is gitignored
- GitHub tokens passed via environment variables (not logged)

### Comparison: GCP vs AWS Metal

| Feature | GCP Builder | AWS Metal |
|---------|-------------|-----------|
| **Cost per build** | $4-15 | $15-20 |
| **Nested Virt** | Native KVM support | Native KVM support |
| **Setup** | Simple (gcloud + service account) | More complex (Terraform + Lambda) |
| **Auto-shutdown** | Shutdown script | Watchdog Lambda |
| **Build monitoring** | Serial console, Cloud Logging | CloudWatch Logs, DynamoDB |
| **Artifact storage** | GCS | S3 |
| **Best for** | Development, cost-sensitive | Production, integrated AWS workflow |

### References

- [GCP Nested Virtualization Docs](https://cloud.google.com/compute/docs/instances/nested-virtualization/overview)
- [GCP Machine Types](https://cloud.google.com/compute/docs/machine-types)
- [GCP Pricing Calculator](https://cloud.google.com/products/calculator)
- [Issue #75: Implementation Details](https://github.com/afewell-hh/labapp/issues/75)

### Support

For issues or questions:
1. Check this troubleshooting guide
2. Review GCP build logs
3. Verify `.env.gcp` configuration
4. Create GitHub issue with logs attached
