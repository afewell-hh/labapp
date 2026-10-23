# Manual Lab VM Image Build (current documented process)

This is the documented way to build a Lab VM image until an automated Packer
build exists. It was moved here from the former root `AGENTS.md`/`CLAUDE.md`
without changing the commands. An automated Packer build does **not** exist
yet; progress is tracked in issue #145.

These steps create cloud resources and images. Run them only as the
lead/owner or when a task explicitly authorizes cloud commands. Workers must
not run them otherwise. Delete test VMs when done (500GB persistent disk
quota). Never commit secrets or credentials.

## Step 1: Launch VM with cloud-config

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

## Step 2: Verify cloud-init completion

```bash
# SSH in and check cloud-init status
gcloud compute ssh hedgehog-lab-YYYYMMDD --zone=us-central1-a

# On the VM:
cloud-init status --wait
cat /var/log/cloud-init-output.log
```

## Step 3: Manual VLAB installation

Complete any steps that cloud-config cannot handle:

- Verify all dependencies installed correctly (Docker, KVM/QEMU, hhfab, etc.)
- Run `hhfab init` and configure fab.yaml
- Run `hhfab vlab up` and wait for VLAB to be ready

## Step 4: Save VM as image

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

## Step 5: Test the image

```bash
gcloud compute instances create test-from-image \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image=hedgehog-lab-vYYYYMMDD \
  --boot-disk-size=400GB \
  --enable-nested-virtualization
```

## Known issues and troubleshooting

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

### Updating cloud-config.yaml

- Test changes by launching a fresh VM and monitoring cloud-init logs.
- Keep installations idempotent where possible.
- Document any packages that consistently fail in cloud-init (in the
  relevant GitHub issue until a stable limit is confirmed, then here).

## Quick reference

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

## GCP Marketplace publishing (future, not a current objective)

Marketplace publication is not the current primary objective (decisions
recorded in #136 and #137). If it is revisited once the image is stable:

1. Create image in GCP project
2. Set up Cloud Marketplace Partner account
3. Create product listing with VM image
4. Submit for review
