# Hedgehog Lab Appliance – Agent Playbook (Updated 2025-01-08)

Read this before touching the repo. It supersedes any prior agent guidance and applies to **all** dev/CI agents.

---

## 1. Mission Snapshot

- **Product:** A pre-configured GCP VM image with a fully functional Hedgehog VLAB environment, plus tooling to automate the setup process on fresh Ubuntu VMs.
- **Production Use:** Labapp is already a production GCP VM image. It is used for Hedgehog LMS lab exercises at hedgehog.cloud/learn and for demos. Students run the VM alongside course content in a separate terminal/window; it is not directly embedded in the LMS.
- **Current Production Image:** Built through a combination of automated setup (cloud-init) and manual configuration.
- **Delivery Paths:**
  1. **Pre-built Image (Primary Focus):** A ready-to-use GCP VM image with VLAB pre-installed
  2. **Automated Installer (Future):** Scripts that transform a fresh Ubuntu 24.04 VM into the same configured state

### Current Priority

**An efficient, reproducible, automated Packer image build** that replaces the partially manual production build process, developed with a lead / Claude worker / Codex reviewer workflow. GCP Marketplace publication is not the current primary objective (see recorded decisions in #136 and #137). Until the Packer build exists, the manual workflow below remains the documented way to build an image.

### Near-Term Objectives

1. **Refine cloud-config.yaml** - Automate as much of the base system setup as cloud-init can handle (packages, Docker, XRDP, dev tools)
2. **Manual VLAB installation** - Complete remaining setup steps manually on cloud-init-provisioned VMs
3. **Image creation** - Save configured VMs as GCP images (Marketplace publication is not currently a primary objective)
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

### Packer-ready provisioning modules (`build/provision/`)
Pilot: `build/provision/install-k3d.sh` installs a pinned k3d release binary (v5.7.4, linux/amd64, SHA256 verified, noninteractive). It is the one file used both for development and, later, Packer shell provisioning. `cloud-config.yaml` is unchanged during the pilot.
```bash
# Install (override K3D_INSTALL_DIR to isolate; default /usr/local/bin)
K3D_INSTALL_DIR=/tmp/k3d-test bash build/provision/install-k3d.sh
# Disposable Ubuntu 24.04 container test of the real module (needs docker + network)
bash build/provision/test-install-k3d.sh
# Static checks
bash -n build/provision/*.sh && shellcheck -x build/provision/*.sh
```
The test covers clean install, idempotent rerun, bad-digest and unavailable-download failures that preserve an existing binary, and unsupported-architecture failure. It does not verify Docker, a k3d cluster, systemd, cloud-init, nested KVM or VLAB.

### Committing changes
```bash
git checkout -b feature/description
# Make changes
git add .
git commit -m "feat(cloud-config): add package X

Closes #N"
git push origin feature/description
```

### Claude and Codex GitHub automation
- `.github/workflows/claude.yml` runs Claude when an issue or PR comment contains `@claude`; Codex separately reviews PRs when they are opened or when `@codex review` is commented.
- `claude_args --allowedTools` enables `WebSearch` and `WebFetch` for source research, plus only `gh issue view/comment` and `gh pr create/view/diff/checks/comment` as additional shell commands. GitHub token permissions and all other shell permissions are unchanged, and merge/approval commands are not allowed.
- Research workers must consult current primary sources and cite evidence in their issue/PR. If source access is denied, report the blocker and mark conclusions provisional rather than presenting unverified research as complete.
- Known limitation: in tag mode the action may restrict Claude to a single comment and may default to a branch plus prefilled PR link. The extra tool permissions do not override its injected instructions.
- Unverified until a fresh Claude run after merge: PR creation via `gh pr create` and bot-authored review handoff comments. Record run evidence rather than assuming they work.

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
