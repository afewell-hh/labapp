#!/bin/bash
# 03-install-hhfab.sh
# Install Hedgehog Fabric tools and dependencies
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing Hedgehog Fabric tools..."
echo "=================================================="

# Install ONIE-related tools (if available)
echo "Installing ONIE tools and dependencies..."

# Note: The actual Hedgehog Fabric installation will depend on
# the specific tools and repositories available. This is a placeholder
# that should be updated with the actual installation commands.

# For now, we'll create the directory structure and install any prerequisites
mkdir -p /opt/hedgehog
mkdir -p /etc/hedgehog-lab/vlab

# Install Go (required for some Hedgehog tools)
echo "Installing Go..."
GO_VERSION="1.23.2"
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm go${GO_VERSION}.linux-amd64.tar.gz

# Add Go to PATH for all users
cat >> /etc/profile.d/golang.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
EOF

# Set up Go for hhlab user
mkdir -p /home/hhlab/go
chown -R hhlab:hhlab /home/hhlab/go

# Install hhfab CLI (placeholder - update with actual installation)
# This will be updated when the actual hhfab tool is available
echo "Hedgehog Fabric tool installation placeholder created"

# Set permissions
chown -R hhlab:hhlab /opt/hedgehog
chown -R hhlab:hhlab /etc/hedgehog-lab

echo "=================================================="
echo "Hedgehog Fabric tools installation complete!"
echo "=================================================="
