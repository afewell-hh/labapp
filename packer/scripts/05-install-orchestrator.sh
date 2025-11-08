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

# Install VLAB initialization module (legacy, kept for compatibility)
echo "Installing VLAB initialization module (legacy)..."
if [ -f "/tmp/packer-provisioner-shell-scripts/30-vlab-init.sh" ]; then
    cp /tmp/packer-provisioner-shell-scripts/30-vlab-init.sh /usr/local/bin/hedgehog-vlab-init
    chmod +x /usr/local/bin/hedgehog-vlab-init
    echo "VLAB module installed at /usr/local/bin/hedgehog-vlab-init"
else
    echo "ERROR: VLAB init script not found"
    exit 1
fi

# Install hhfab-vlab-runner (new tmux-based runner)
echo "Installing hhfab-vlab-runner..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hhfab-vlab-runner" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hhfab-vlab-runner /usr/local/bin/hhfab-vlab-runner
    chmod +x /usr/local/bin/hhfab-vlab-runner
    echo "hhfab-vlab-runner installed at /usr/local/bin/hhfab-vlab-runner"
else
    echo "ERROR: hhfab-vlab-runner script not found"
    exit 1
fi

# Install readiness UI tool
echo "Installing readiness UI tool..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-readiness-ui" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hedgehog-lab-readiness-ui /usr/local/bin/hedgehog-lab-readiness-ui
    chmod +x /usr/local/bin/hedgehog-lab-readiness-ui
    echo "Readiness UI installed at /usr/local/bin/hedgehog-lab-readiness-ui"
else
    echo "ERROR: Readiness UI script not found"
    exit 1
fi

# Install hh-lab CLI tool
echo "Installing hh-lab CLI tool..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hh-lab" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hh-lab /usr/local/bin/hh-lab
    chmod +x /usr/local/bin/hh-lab
    echo "hh-lab CLI installed at /usr/local/bin/hh-lab"
else
    echo "ERROR: hh-lab CLI script not found"
    exit 1
fi

# Install bash completion for hh-lab
echo "Installing bash completion for hh-lab..."
if [ -f "/tmp/packer-provisioner-shell-scripts/hh-lab-completion.bash" ]; then
    mkdir -p /etc/bash_completion.d
    cp /tmp/packer-provisioner-shell-scripts/hh-lab-completion.bash /etc/bash_completion.d/hh-lab
    echo "Bash completion installed at /etc/bash_completion.d/hh-lab"
else
    echo "WARNING: Bash completion script not found (optional)"
fi

# Install systemd services
echo "Installing systemd services..."

# Install main orchestrator service
if [ -f "/tmp/packer-provisioner-shell-scripts/hedgehog-lab-init.service" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hedgehog-lab-init.service /etc/systemd/system/hedgehog-lab-init.service
    echo "Main orchestrator service installed"
else
    echo "ERROR: hedgehog-lab-init.service file not found"
    exit 1
fi

# Install hhfab-vlab service
if [ -f "/tmp/packer-provisioner-shell-scripts/hhfab-vlab.service" ]; then
    cp /tmp/packer-provisioner-shell-scripts/hhfab-vlab.service /etc/systemd/system/hhfab-vlab.service
    echo "hhfab-vlab service installed"
else
    echo "ERROR: hhfab-vlab.service file not found"
    exit 1
fi

# Reload systemd and enable services
systemctl daemon-reload
systemctl enable hedgehog-lab-init.service
systemctl enable hhfab-vlab.service
echo "Systemd services installed and enabled"

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
chmod 755 /usr/local/bin/hhfab-vlab-runner
chmod 755 /usr/local/bin/hedgehog-lab-readiness-ui
chmod 755 /usr/local/bin/hh-lab

echo "=================================================="
echo "Orchestrator installation complete!"
echo "=================================================="
echo "Installed components:"
echo "  - Main orchestrator: /usr/local/bin/hedgehog-lab-orchestrator"
echo "  - k3d module: /usr/local/bin/hedgehog-k3d-init"
echo "  - VLAB module: /usr/local/bin/hedgehog-vlab-init"
echo "  - VLAB runner: /usr/local/bin/hhfab-vlab-runner"
echo "  - Readiness UI: /usr/local/bin/hedgehog-lab-readiness-ui"
echo "  - hh-lab CLI: /usr/local/bin/hh-lab"
echo "  - Bash completion: /etc/bash_completion.d/hh-lab"
echo ""
echo "Systemd services:"
echo "  - Main orchestrator: /etc/systemd/system/hedgehog-lab-init.service"
echo "  - VLAB service: /etc/systemd/system/hhfab-vlab.service"
echo ""
echo "Directories:"
echo "  - Config directory: /etc/hedgehog-lab"
echo "  - State directory: /var/lib/hedgehog-lab"
echo "  - Log directory: /var/log/hedgehog-lab"
echo "  - VLAB working directory: /opt/hedgehog/vlab"
echo ""
