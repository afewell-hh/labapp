# Hedgehog Lab Appliance - Installation Guide

This guide walks you through downloading and installing the Hedgehog Lab Appliance on VMware or VirtualBox.

## Table of Contents

- [System Requirements](#system-requirements)
- [Download](#download)
- [Installation on VMware](#installation-on-vmware)
- [Installation on VirtualBox](#installation-on-virtualbox)
- [First Boot](#first-boot)
- [Network Configuration](#network-configuration)
- [Next Steps](#next-steps)

## System Requirements

### Host System Requirements

**Minimum:**
- CPU: 4 cores (Intel VT-x or AMD-V virtualization support required)
- RAM: 20 GB (4 GB for host + 16 GB for VM)
- Disk: 320 GB free space
- OS: Windows 10+, macOS 10.15+, or Linux

**Recommended:**
- CPU: 8+ cores with hardware virtualization
- RAM: 32 GB (16 GB for host + 16 GB for VM)
- Disk: 400 GB free space (SSD preferred)
- Network: High-speed internet connection for initial download

### VM Resource Allocation

The appliance is configured with:
- **vCPUs:** 8
- **Memory:** 16 GB
- **Disk:** 300 GB (thin provisioned, dynamically allocated)
- **Network:** 1 adapter (NAT or Bridged)

## Download

### Standard Build (Recommended for Self-Paced Learning)

**Size:** ~3-4 GB compressed
**First boot time:** 15-20 minutes (one-time initialization after GHCR setup)

```bash
# Download from Google Cloud Storage
gsutil cp gs://hedgehog-lab-artifacts-teched-473722/releases/hedgehog-lab-standard-build-20251110-235348.ova .
gsutil cp gs://hedgehog-lab-artifacts-teched-473722/releases/hedgehog-lab-standard-build-20251110-235348.ova.sha256 .

# Verify checksum (recommended)
sha256sum -c hedgehog-lab-standard-build-20251110-235348.ova.sha256

# Expected SHA256: c26295bb29ac017a8c4d9e096a19ff551a6c8956f9964f8bd37d7760627d61f8
```

> **Note:** You'll need `gsutil` installed and configured. See [Google Cloud SDK installation](https://cloud.google.com/sdk/docs/install).

### Pre-warmed Build (For Workshops/Training Events)

**Status:** Coming in future release

> **Note:** Pre-warmed builds will be available for workshops once Issue #74 (GitOps seed configs) and related optimizations are complete.

## Installation on VMware

The Hedgehog Lab Appliance is distributed as an OVA (Open Virtualization Archive) file, which is compatible with VMware products.

### VMware Workstation (Windows/Linux)

1. **Open VMware Workstation**
   - Launch VMware Workstation Pro or Player

2. **Import the OVA**
   - Go to **File** → **Open**
   - Navigate to the downloaded OVA file
   - Click **Open**

3. **Review Import Settings**
   - **Name:** Hedgehog Lab (or customize)
   - **Storage path:** Choose where to store VM files
   - Review resource allocation (CPU, RAM, disk)

4. **Accept License Agreement**
   - Read and accept the EULA
   - Click **Import**

5. **Wait for Import**
   - Import takes 5-10 minutes depending on disk speed
   - Progress bar shows status

6. **Adjust Network Settings (Optional)**
   - Right-click the VM → **Settings**
   - Go to **Network Adapter**
   - Choose network mode:
     - **NAT:** Simple, works out of the box (recommended)
     - **Bridged:** VM gets IP on local network (for multi-user access)

7. **Power On**
   - Click **Power On** or **Play Virtual Machine**

### VMware Fusion (macOS)

1. **Open VMware Fusion**
   - Launch VMware Fusion

2. **Import the OVA**
   - Go to **File** → **Import**
   - Select the downloaded OVA file
   - Click **Continue**

3. **Configure Import**
   - **Name:** Hedgehog Lab
   - **Save As:** Choose location
   - Click **Save**

4. **Customize Settings (Optional)**
   - Before starting, click **Customize Settings**
   - Adjust CPU, RAM, or network as needed

5. **Start the VM**
   - Click the **Play** button

### VMware ESXi / vSphere

1. **Log into vSphere Client**
   - Open web browser
   - Navigate to vCenter or ESXi host
   - Log in with credentials

2. **Deploy OVF Template**
   - Right-click on datacenter or cluster
   - Select **Deploy OVF Template**

3. **Select OVA File**
   - Choose **Local file**
   - Click **Browse** and select the OVA
   - Click **Next**

4. **Configure Deployment**
   - **Name:** HedgehogLab
   - **Location:** Select folder/datacenter
   - Click **Next**

5. **Select Compute Resource**
   - Choose ESXi host or cluster
   - Click **Next**

6. **Review Details**
   - Verify OVA details
   - Click **Next**

7. **Accept License**
   - Read and accept EULA
   - Click **Next**

8. **Select Storage**
   - Choose datastore (min 120 GB free)
   - Select **Thin Provision** to save space
   - Click **Next**

9. **Select Network**
   - Map network to appropriate port group
   - Click **Next**

10. **Review and Finish**
    - Review all settings
    - Click **Finish**
    - Wait for import to complete

11. **Power On**
    - Right-click VM → **Power** → **Power On**

## Installation on VirtualBox

VirtualBox can import OVA files directly.

### VirtualBox (All Platforms)

1. **Open VirtualBox**
   - Launch Oracle VM VirtualBox

2. **Import Appliance**
   - Go to **File** → **Import Appliance**
   - Or click **Import** button in toolbar

3. **Select OVA File**
   - Click the folder icon
   - Browse to the downloaded OVA file
   - Click **Open**, then **Next**

4. **Appliance Settings**
   - Review the configuration:
     - Name: Hedgehog Lab
     - CPUs: 8
     - RAM: 16384 MB
     - Network: NAT
   - **Optional:** Adjust settings if needed
     - For lower-end systems, you can reduce to 4 CPUs / 8 GB RAM (may impact performance)
   - Check **Import hard drives as VDI** for better compatibility
   - Click **Import**

5. **Accept License**
   - Read and accept the EULA
   - Click **Agree**

6. **Wait for Import**
   - Import takes 5-15 minutes
   - Progress bar shows status

7. **Configure Network (Recommended)**
   - Select the imported VM
   - Click **Settings** → **Network**
   - **Adapter 1:**
     - Enable Network Adapter: ✓
     - Attached to: **NAT**
     - Advanced → Port Forwarding
     - Add these rules (click the + icon):

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|------|----------|---------|-----------|----------|------------|
| SSH | TCP | 127.0.0.1 | 2222 | | 22 |
| Grafana | TCP | 127.0.0.1 | 3000 | | 3000 |
| ArgoCD | TCP | 127.0.0.1 | 8080 | | 8080 |
| Gitea | TCP | 127.0.0.1 | 3001 | | 3001 |
| RDP | TCP | 127.0.0.1 | 3389 | | 3389 |
| VNC | TCP | 127.0.0.1 | 5901 | | 5901 |

   - Click **OK**

8. **Start the VM**
   - Select the VM
   - Click **Start**

### VirtualBox Guest Additions (Optional)

For better performance and integration:

1. After first boot and login
2. **Devices** → **Insert Guest Additions CD Image**
3. Inside the VM:
   ```bash
   sudo mount /dev/cdrom /mnt
   sudo /mnt/VBoxLinuxAdditions.run
   sudo reboot
   ```

## Installation on Google Cloud Platform (GCP)

For cloud-based deployments, you can import the OVA as a GCP custom image and run it on Compute Engine.

### Prerequisites

- GCP project with Compute Engine API enabled
- `gcloud` CLI installed and authenticated
- `qemu-img` utility for image conversion

### Step 1: Download and Convert OVA

```bash
# Download the OVA
gsutil cp gs://hedgehog-lab-artifacts-teched-473722/releases/hedgehog-lab-standard-build-20251110-235348.ova .

# Extract the OVA (it's a tar archive)
tar -xvf hedgehog-lab-standard-build-20251110-235348.ova

# Convert VMDK to RAW format (GCP requirement)
VMDK_FILE=$(ls *.vmdk | head -1)
qemu-img convert -f vmdk -O raw "${VMDK_FILE}" disk.raw

# Compress for faster upload
tar -Szcf hedgehog-lab.tar.gz disk.raw
```

### Step 2: Upload to Google Cloud Storage

```bash
# Set your project and bucket
PROJECT_ID="your-project-id"
BUCKET_NAME="your-bucket-name"

# Upload the image
gsutil cp hedgehog-lab.tar.gz gs://${BUCKET_NAME}/images/

# Clean up local files
rm disk.raw hedgehog-lab.tar.gz *.vmdk *.ovf *.mf
```

### Step 3: Create Custom Image

```bash
# Create the custom image (takes 10-20 minutes)
gcloud compute images create hedgehog-lab-20251110 \
    --source-uri=gs://${BUCKET_NAME}/images/hedgehog-lab.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE \
    --licenses="https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx" \
    --project=${PROJECT_ID}

> **Why this matters:** The `enable-vmx` license flag is required for nested virtualization. Without it the imported image cannot expose `/dev/kvm`, causing hhfab VLAB to crash immediately (Bug #24).

# Monitor progress
gcloud compute images describe hedgehog-lab-20251110 --project=${PROJECT_ID}
```

### Step 4: Create VM Instance

```bash
# Create instance with nested virtualization enabled
gcloud compute instances create hedgehog-lab-instance \
    --project=${PROJECT_ID} \
    --zone=us-central1-a \
    --machine-type=n2-standard-16 \
    --image=hedgehog-lab-20251110 \
    --boot-disk-size=300GB \
    --boot-disk-type=pd-ssd \
    --enable-nested-virtualization \
    --min-cpu-platform="Intel Cascade Lake" \
    --tags=hedgehog-lab \
    --scopes=https://www.googleapis.com/auth/cloud-platform

# Create firewall rules
gcloud compute firewall-rules create allow-hedgehog-services \
    --project=${PROJECT_ID} \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:22,tcp:3000,tcp:3001,tcp:3389,tcp:5901,tcp:8080 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=hedgehog-lab
```

### Step 5: Connect to Instance

```bash
# SSH into the instance
gcloud compute ssh hhlab@hedgehog-lab-instance --zone=us-central1-a

# Get external IP for RDP/VNC access
gcloud compute instances describe hedgehog-lab-instance \
    --zone=us-central1-a \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

**Cost Considerations:**
- **n2-standard-16** (16 vCPUs, 64GB RAM): ~$0.78/hour
- **300GB SSD**: ~$50/month (pd-ssd)
- **Stop when not in use** to save costs:
  ```bash
  gcloud compute instances stop hedgehog-lab-instance --zone=us-central1-a
  ```

## First Boot

### IMPORTANT: GHCR Authentication Required

**The lab will NOT initialize automatically on first boot.** You must provide GitHub Container Registry (GHCR) credentials before initialization can start.

#### Why GHCR Authentication is Required

The Hedgehog VLAB pulls container images from GitHub Container Registry (ghcr.io), which requires authentication. Even though the lab uses development configuration (`hhfab init --dev`), it still needs production container images from GHCR.

### First-Time Setup Process

> **Tip:** `hh-lab setup` now copies Docker credentials to both `/root/.docker` and `/home/hhlab/.docker`, so the hhfab VLAB service can pull private images without manual fixes (Issue #92 / Bug #17).

> **Heads-up:** The orchestrator refuses to start VLAB unless the root filesystem has at least 120 GB free (override with `VLAB_MIN_FREE_GB`). If you see an "insufficient disk space" error, expand the boot disk or rerun the `lvextend`/`resize2fs` commands described earlier (Issue #92 / Bug #22).

1. **VM Boots and Login**
   - GRUB bootloader appears
   - Ubuntu 24.04 boots automatically
   - Login at the console, SSH, RDP, or VNC
   - **Username:** `hhlab`
   - **Password:** `hhlab`

2. **Create GitHub Personal Access Token**
   - Go to https://github.com/settings/tokens
   - Click "Generate new token" (classic)
   - Give it a descriptive name (e.g., "Hedgehog Lab")
   - Select the `read:packages` scope
   - Click "Generate token" and **copy it immediately**

3. **Run the Setup Wizard**
   ```bash
   hh-lab setup
   ```

4. **Follow Interactive Prompts**
   - Enter your GitHub username
   - Paste your Personal Access Token (input is hidden)
   - The wizard authenticates with ghcr.io
   - Choose whether to start initialization immediately (recommended: Yes)

5. **Monitor Initialization** (if you chose to start it)
   ```bash
   # Check overall status
   hh-lab status

   # Follow logs in real-time
   hh-lab logs -f

   # Or use systemd directly
   sudo journalctl -u hedgehog-lab-init.service -f
   ```

### What the Setup Wizard Does

- Performs `docker login ghcr.io` with your credentials
- Creates marker file at `/var/lib/hedgehog-lab/ghcr-authenticated`
- **Securely wipes token from memory** (NEVER stored to disk)
- Optionally starts lab initialization via systemd

### Security Notes

- Your PAT token is **NEVER stored permanently** to disk
- Token is wiped from environment variables immediately after `docker login`
- Only a marker file (with username and timestamp) is persisted
- You can refresh credentials anytime by running `hh-lab setup` again

### Initialization Process (After GHCR Setup)

Once credentials are configured and initialization starts:

**Standard Build:**
1. Detects network connectivity (~10s)
2. Initializes Hedgehog VLAB via systemd+tmux (~10 min)
   - Runs `hhfab init --dev` to create config
   - Runs `hhfab vlab up --controls-restricted=false --ready wait`
   - Creates 7-switch Hedgehog topology
3. Creates k3d observability cluster (~3-5 min)
4. Deploys GitOps stack (ArgoCD, Gitea) (~2-3 min)
5. Configures observability (Prometheus, Grafana) (~1-2 min)
- **Total time:** 15-20 minutes

### Access Methods

The appliance provides multiple ways to access the environment:

**SSH Access:**
```bash
ssh hhlab@<vm-ip>
# Password: hhlab
```

**RDP Access (Recommended for Desktop):**
- Use any RDP client
- Connect to: `<vm-ip>:3389`
- Username: `hhlab`
- Password: `hhlab`

**VNC Access:**
- Use any VNC client
- Connect to: `<vm-ip>:5901`
- Password: `hhlab`

**Desktop Environment:**
- XFCE desktop with VS Code, Firefox, and Terminal
- Desktop shortcuts for common tools

### Troubleshooting First Boot

**GHCR Authentication Issues:**

```bash
# Check if credentials are configured
hh-lab status

# Re-run setup to update credentials
hh-lab setup

# Verify docker login succeeded
sudo docker login ghcr.io
# Should show: "Login Succeeded"

# Check marker file exists
ls -la /var/lib/hedgehog-lab/ghcr-authenticated
```

**Initialization Failures:**

1. **Check logs:**
   ```bash
   hh-lab logs

   # Or view specific modules
   tail -f /var/log/hedgehog-lab/modules/vlab.log
   tail -f /var/log/hedgehog-lab/modules/k3d.log
   ```

2. **View detailed orchestrator logs:**
   ```bash
   sudo cat /var/log/hedgehog-lab-init.log
   ```

3. **Check network connectivity:**
   ```bash
   ping -c 3 8.8.8.8
   curl -I https://ghcr.io
   ```

4. **Inspect VLAB tmux session:**
   ```bash
   # Attach to the hhfab VLAB session
   tmux attach -t hhfab-vlab
   # Press Ctrl+B then D to detach without stopping it
   ```

5. **Retry initialization:**
   ```bash
   # Stop services
   sudo systemctl stop hhfab-vlab.service
   sudo systemctl stop hedgehog-lab-init.service

   # Clean state (keeps GHCR credentials)
   sudo rm -f /var/lib/hedgehog-lab/initialized
   sudo rm -f /var/lib/hedgehog-lab/vlab-initialized

   # Restart
   sudo systemctl start hedgehog-lab-init.service
   ```

See [Troubleshooting Guide](TROUBLESHOOTING.md) for more help.

## Network Configuration

### NAT Mode (Default)

**Best for:** Single-user, local development

- VM gets IP from VMware/VirtualBox DHCP
- VM can access internet
- Host can access VM services via port forwarding
- Other machines cannot access VM

**No configuration needed** - works out of the box

### Bridged Mode

**Best for:** Multi-user workshops, team access

- VM gets IP from local network DHCP
- VM accessible from other machines on the network
- Requires network supports DHCP

**To configure:**

1. **VMware:**
   - VM Settings → Network Adapter → Bridged
   - Select physical adapter

2. **VirtualBox:**
   - VM Settings → Network → Adapter 1
   - Attached to: Bridged Adapter
   - Select physical adapter

3. **Find VM IP:**
   ```bash
   # Inside VM
   ip addr show | grep inet
   ```

4. **Access from other machines:**
   ```
   http://<VM_IP>:3000    # Grafana
   http://<VM_IP>:8080    # ArgoCD
   http://<VM_IP>:3001    # Gitea
   ```

## Next Steps

After installation completes successfully:

1. **Verify Services:** [Quick Start Guide](QUICKSTART.md#verify-services)
2. **Access Web UIs:** [Service URLs and Credentials](QUICKSTART.md#accessing-services)
3. **Explore VLAB:** [Quick Start Guide](QUICKSTART.md#exploring-the-vlab)
4. **Learn More:** [FAQ](FAQ.md)

## Support

- **Issues:** https://github.com/afewell-hh/labapp/issues
- **Discussions:** https://github.com/afewell-hh/labapp/discussions
- **Documentation:** https://github.com/afewell-hh/labapp/docs
