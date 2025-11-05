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
- Disk: 120 GB free space
- OS: Windows 10+, macOS 10.15+, or Linux

**Recommended:**
- CPU: 8+ cores with hardware virtualization
- RAM: 32 GB (16 GB for host + 16 GB for VM)
- Disk: 150 GB free space (SSD preferred)
- Network: High-speed internet connection for initial download

### VM Resource Allocation

The appliance is configured with:
- **vCPUs:** 8
- **Memory:** 16 GB
- **Disk:** 100 GB (dynamically allocated)
- **Network:** 1 adapter (NAT or Bridged)

## Download

### Standard Build (Recommended for Self-Paced Learning)

**Size:** ~15-20 GB compressed
**First boot time:** 15-20 minutes (one-time initialization)

```bash
# Download the latest standard build OVA
wget https://releases.hedgehogfabric.io/lab/hedgehog-lab-standard-latest.ova

# Or download a specific version
wget https://releases.hedgehogfabric.io/lab/hedgehog-lab-standard-0.1.0.ova

# Verify checksum (recommended)
wget https://releases.hedgehogfabric.io/lab/hedgehog-lab-standard-0.1.0.ova.sha256
sha256sum -c hedgehog-lab-standard-0.1.0.ova.sha256
```

### Pre-warmed Build (For Workshops/Training Events)

**Size:** ~80-100 GB compressed
**First boot time:** 2-3 minutes

> **Note:** Pre-warmed builds are typically provided by workshop instructors on USB drives or local network storage due to their large size.

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
| Grafana | TCP | 127.0.0.1 | 3000 | | 3000 |
| ArgoCD | TCP | 127.0.0.1 | 8080 | | 8080 |
| Gitea | TCP | 127.0.0.1 | 3001 | | 3001 |

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

## First Boot

### What Happens on First Boot

The first time you start the appliance, it performs a one-time initialization:

**Standard Build:**
- Detects network connectivity
- Creates k3d observability cluster
- Initializes Hedgehog VLAB (7-switch topology)
- Deploys GitOps stack (ArgoCD, Gitea)
- Deploys observability stack (Prometheus, Grafana, Loki)
- **Total time:** 15-20 minutes

**Pre-warmed Build:**
- Detects network connectivity
- Starts pre-configured services
- **Total time:** 2-3 minutes

### Boot Process

1. **VM Starts**
   - GRUB bootloader appears
   - Ubuntu boots automatically

2. **Login Screen**
   - You'll see a login prompt
   - **Username:** `hhlab`
   - **Password:** `hhlab`

3. **Initialization Status**
   - After login, check initialization status:
     ```bash
     hh-lab status
     ```

4. **Monitor Progress**
   - View real-time logs:
     ```bash
     hh-lab logs --follow
     ```
   - Or use systemd:
     ```bash
     sudo journalctl -u hedgehog-lab-init -f
     ```

5. **Completion**
   - When initialization completes, you'll see:
     ```
     Hedgehog Lab Appliance Initialization Complete!
     Lab is ready for use.
     ```

### Troubleshooting First Boot

If initialization fails:

1. **Check logs:**
   ```bash
   hh-lab logs
   ```

2. **View detailed logs:**
   ```bash
   sudo cat /var/log/hedgehog-lab-init.log
   ```

3. **Check network:**
   ```bash
   ping -c 3 8.8.8.8
   ```

4. **Retry initialization:**
   ```bash
   sudo rm /var/lib/hedgehog-lab/initialized
   sudo systemctl restart hedgehog-lab-init
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
