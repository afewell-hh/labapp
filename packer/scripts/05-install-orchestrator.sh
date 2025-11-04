#!/bin/bash
# 05-install-orchestrator.sh
# Install orchestrator and initialization modules
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing Hedgehog Lab Orchestrator..."
echo "=================================================="

# Create necessary directories
echo "Creating orchestrator directories..."
mkdir -p /usr/local/bin
mkdir -p /usr/local/lib/hedgehog-lab/modules
mkdir -p /etc/hedgehog-lab
mkdir -p /var/lib/hedgehog-lab
mkdir -p /var/log/hedgehog-lab/modules
mkdir -p /opt/hedgehog/vlab

# Install main orchestrator script
echo "Installing main orchestrator..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-orchestrator" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hedgehog-lab-orchestrator /usr/local/bin/hedgehog-lab-orchestrator
    chmod +x /usr/local/bin/hedgehog-lab-orchestrator
    echo "Main orchestrator installed at /usr/local/bin/hedgehog-lab-orchestrator"
else
    echo "ERROR: Orchestrator script not found"
    exit 1
fi

# Install k3d initialization module
echo "Installing k3d initialization module..."
if [ -f "/tmp/packer-provisioner-shell-scripts/20-k3d-observability-init.sh" ]; then
    cp /tmp/packer-provisioner-shell-scripts/20-k3d-observability-init.sh /usr/local/bin/hedgehog-k3d-init
    chmod +x /usr/local/bin/hedgehog-k3d-init
    echo "k3d module installed at /usr/local/bin/hedgehog-k3d-init"
else
    echo "ERROR: k3d init script not found"
    exit 1
fi

# Install VLAB initialization module
echo "Installing VLAB initialization module..."
if [ -f "/tmp/packer-provisioner-shell-scripts/30-vlab-init.sh" ]; then
    cp /tmp/packer-provisioner-shell-scripts/30-vlab-init.sh /usr/local/bin/hedgehog-vlab-init
    chmod +x /usr/local/bin/hedgehog-vlab-init
    echo "VLAB module installed at /usr/local/bin/hedgehog-vlab-init"
else
    echo "ERROR: VLAB init script not found"
    exit 1
fi

# Install systemd service
echo "Installing systemd service..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-init.service" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hedgehog-lab-init.service /etc/systemd/system/hedgehog-lab-init.service
    systemctl daemon-reload
    systemctl enable hedgehog-lab-init.service
    echo "Systemd service installed and enabled"
else
    echo "ERROR: Systemd service file not found"
    exit 1
fi

# Set build type (default to standard)
echo "standard" > /etc/hedgehog-lab/build-type
echo "Build type set to: standard"

# Set proper permissions
echo "Setting permissions..."
chown -R hhlab:hhlab /opt/hedgehog
chown -R hhlab:hhlab /var/lib/hedgehog-lab
chown -R hhlab:hhlab /var/log/hedgehog-lab
chmod 755 /usr/local/bin/hedgehog-lab-orchestrator
chmod 755 /usr/local/bin/hedgehog-k3d-init
chmod 755 /usr/local/bin/hedgehog-vlab-init

echo "=================================================="
echo "Orchestrator installation complete!"
echo "=================================================="
echo "Installed components:"
echo "  - Main orchestrator: /usr/local/bin/hedgehog-lab-orchestrator"
echo "  - k3d module: /usr/local/bin/hedgehog-k3d-init"
echo "  - VLAB module: /usr/local/bin/hedgehog-vlab-init"
echo "  - Systemd service: /etc/systemd/system/hedgehog-lab-init.service"
echo "  - Config directory: /etc/hedgehog-lab"
echo "  - State directory: /var/lib/hedgehog-lab"
echo "  - Log directory: /var/log/hedgehog-lab"
echo "  - VLAB working directory: /opt/hedgehog/vlab"
echo ""
