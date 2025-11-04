#!/bin/bash
# 02-install-k3d.sh
# Install k3d for local Kubernetes development
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing k3d..."
echo "=================================================="

# Define version
K3D_VERSION="v5.7.4"

# Download and install k3d
echo "Downloading k3d ${K3D_VERSION}..."
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | TAG=${K3D_VERSION} bash

# Verify installation
if command -v k3d &> /dev/null; then
    echo "k3d installed successfully:"
    k3d version
else
    echo "ERROR: k3d installation failed!"
    exit 1
fi

# Create k3d directory for configurations
mkdir -p /etc/hedgehog-lab/k3d
chown -R hhlab:hhlab /etc/hedgehog-lab

echo "=================================================="
echo "k3d installation complete!"
echo "=================================================="
