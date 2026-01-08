# Hedgehog Lab Appliance – Agent Playbook (Updated 2025-01-08)

Read this before touching the repo. It supersedes any prior agent guidance and applies to **all** dev/CI agents.

---

## 1. Mission Snapshot

- **Product:** A pre-configured GCP VM image with a fully functional Hedgehog VLAB environment, plus tooling to automate the setup process on fresh Ubuntu VMs.
- **Distribution Model:** Two delivery paths:
  1. **Pre-built Image (Primary Focus):** A ready-to-use GCP Marketplace image with VLAB pre-installed
  2. **Automated Installer (Future):** Scripts that transform a fresh Ubuntu 24.04 VM into the same configured state

### Current Priority

**Manually building and publishing a pre-configured VM image** to GCP Marketplace. This provides users with an immediately usable solution while the fully automated installer is developed.

### Near-Term Objectives

1. **Refine cloud-config.yaml** - Automate as much of the base system setup as cloud-init can handle (packages, Docker, XRDP, dev tools)
2. **Manual VLAB installation** - Complete remaining setup steps manually on cloud-init-provisioned VMs
3. **Image creation & publishing** - Save configured VMs as GCP images and publish to Marketplace
4. **Incremental automation** - Progressively move manual steps into cloud-config or installer scripts

### Longer-Term Goals

- Complete fully automated installer that handles everything cloud-config cannot
- EMC GitOps + observability stack (ArgoCD, Gitea, Prometheus, Grafana with Hedgehog dashboards)

### Source of Truth

- Cloud-config: `cloud-config.yaml` (base system setup via cloud-init)
- Hedgehog docs: `https://docs.hedgehog.cloud/latest/vlab/overview/`

---

## 2. Project Structure

**Active Components:**
- `cloud-config.yaml` - Cloud-init configuration for base system setup (packages, Docker, XRDP, tools)
- `gcp_vm_launch_command.sh` - GCP VM launch command with cloud-config

**Work in Progress:**
- Installer scripts to automate post-cloud-init setup steps
- Documentation of manual installation steps

**Archived (NOT part of current project):**
- `_archive/` - OVA Packer templates, GCP OVA builder scripts, AWS metal build infrastructure
- `archive2/` - Reference materials and previous iteration artifacts

---

## 3. Current Workflow: Building a Lab VM Image

### Step 1: Launch VM with cloud-config
```bash
# See gcp_vm_launch_command.sh for the full command
gcloud compute instances create hedgehog-lab-YYYYMMDD \
  --project=YOUR_PROJECT \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=400GB \
  --boot-disk-type=pd-ssd \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Cascade Lake" \
  --metadata-from-file=user-data=cloud-config.yaml
```

### Step 2: Verify cloud-init completion
```bash
# SSH in and check cloud-init status
gcloud compute ssh hedgehog-lab-YYYYMMDD --zone=us-central1-a

# On the VM:
cloud-init status --wait
cat /var/log/cloud-init-output.log
```

### Step 3: Manual VLAB installation
Complete any steps that cloud-config cannot handle:
- Verify all dependencies installed correctly (Docker, KVM/QEMU, hhfab, etc.)
- Run `hhfab init` and configure fab.yaml
- Run `hhfab vlab up` and wait for VLAB to be ready

### Step 4: Save VM as image
```bash
# Stop the VM first
gcloud compute instances stop hedgehog-lab-YYYYMMDD --zone=us-central1-a

# Create image from the VM's boot disk
gcloud compute images create hedgehog-lab-vYYYYMMDD \
  --source-disk=hedgehog-lab-YYYYMMDD \
  --source-disk-zone=us-central1-a \
  --family=hedgehog-labapp \
  --description="Hedgehog VLAB pre-configured lab environment"
```

### Step 5: Test the image
```bash
gcloud compute instances create test-from-image \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image=hedgehog-lab-vYYYYMMDD \
  --boot-disk-size=400GB \
  --enable-nested-virtualization
```

---

## 4. Known Issues & Troubleshooting

### QEMU/KVM not installed after cloud-init
The `qemu-kvm` package in cloud-config may fail silently. Verify with:
```bash
which qemu-system-x86_64
kvm --version
```
If missing, install manually:
```bash
sudo apt-get update
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
```

### Checking cloud-init logs
```bash
# Full output log
cat /var/log/cloud-init-output.log

# Cloud-init status
cloud-init status
cloud-init status --long

# Per-module logs
cat /var/log/cloud-init.log
```

---

## 5. Development Guidelines

### Updating cloud-config.yaml
- Test changes by launching a fresh VM and monitoring cloud-init logs
- Keep installations idempotent where possible
- Document any packages that consistently fail in cloud-init

### Committing changes
```bash
git checkout -b feature/description
# Make changes
git add .
git commit -m "feat(cloud-config): add package X

Closes #N"
git push origin feature/description
```

### Important reminders
- Delete test VMs when done (500GB persistent disk quota)
- Never commit secrets or credentials
- Update this file when workflow changes

---

## 6. GCP Marketplace Publishing (Future)

Once the image is stable:
1. Create image in GCP project
2. Set up Cloud Marketplace Partner account
3. Create product listing with VM image
4. Submit for review

---

## 7. Quick Reference

```bash
# Launch new VM with cloud-config
./gcp_vm_launch_command.sh

# SSH into VM
gcloud compute ssh INSTANCE_NAME --zone=us-central1-a

# Check cloud-init status
cloud-init status --wait

# Stop VM for imaging
gcloud compute instances stop INSTANCE_NAME --zone=us-central1-a

# Create image
gcloud compute images create IMAGE_NAME \
  --source-disk=INSTANCE_NAME \
  --source-disk-zone=us-central1-a \
  --family=hedgehog-labapp

# List images
gcloud compute images list --filter="family:hedgehog-labapp"

# Delete old test VMs
gcloud compute instances delete INSTANCE_NAME --zone=us-central1-a
```
