#!/bin/bash
# 01-install-base.sh
# Install base system packages and perform system updates
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing base system packages..."
echo "=================================================="

# Configure APT for faster downloads and better caching
echo "Configuring APT for optimal performance..."
cat > /etc/apt/apt.conf.d/99-packer-optimizations <<'EOF'
# Packer build optimizations
Acquire::Languages "none";
Acquire::GzipIndexes "true";
Acquire::CompressionTypes::Order:: "gz";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
EOF

# Update package lists
echo "Updating package lists..."
apt-get update

# Upgrade existing packages
echo "Upgrading existing packages..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential build tools and utilities
echo "Installing essential packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    curl \
    wget \
    git \
    vim \
    nano \
    jq \
    unzip \
    zip \
    tar \
    gzip \
    net-tools \
    dnsutils \
    iputils-ping \
    traceroute \
    tcpdump \
    htop \
    iotop \
    iftop \
    tmux \
    screen \
    tree \
    rsync \
    nfs-common \
    open-iscsi \
    sudo \
    systemd \
    systemd-sysv

# Install virtualization and container tools
echo "Installing virtualization support packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-guest-agent \
    linux-tools-virtual \
    linux-cloud-tools-virtual

# Install Docker
echo "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add hhlab user to docker group
usermod -aG docker hhlab

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Install Python 3 and pip
echo "Installing Python 3 and related packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Install common Python packages
pip3 install --no-cache-dir --upgrade pip setuptools wheel
pip3 install --no-cache-dir pyyaml requests jinja2

# Optimize memory usage
echo "Configuring memory optimizations..."
cat >> /etc/sysctl.d/99-hedgehog-lab.conf <<'EOF'
# Memory optimizations for lab environment
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF

# Clean up
echo "Cleaning up package cache..."
apt-get autoremove -y
apt-get clean
rm -rf /var/lib/apt/lists/*

# Remove unnecessary documentation to save space
echo "Removing unnecessary documentation..."
rm -rf /usr/share/doc/*
rm -rf /usr/share/man/*
rm -rf /usr/share/info/*
find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en*' -exec rm -rf {} +

echo "=================================================="
echo "Base system installation complete!"
echo "=================================================="
