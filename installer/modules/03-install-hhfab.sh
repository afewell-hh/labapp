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

# Install oras CLI (required by hhfab installer - Bug #16)
echo "Installing oras CLI dependency..."
if curl -fsSL https://i.hhdev.io/oras | bash; then
    if command -v oras &> /dev/null; then
        oras --version 2>/dev/null || true
        echo "oras CLI installed successfully"
    else
        echo "WARNING: oras installer completed but oras not found in PATH" >&2
    fi
else
    echo "ERROR: Failed to install oras CLI" >&2
    exit 1
fi

# Placeholder for future hhfab installation improvements
echo "Hedgehog Fabric tool bootstrap complete"

# Set permissions
chown -R hhlab:hhlab /opt/hedgehog
chown -R hhlab:hhlab /etc/hedgehog-lab

echo "=================================================="
echo "Hedgehog Fabric tools installation complete!"
echo "=================================================="
