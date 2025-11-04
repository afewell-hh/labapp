#!/bin/bash
# 01-install-base.sh
# Install base system packages and perform system updates
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing base system packages..."
echo "=================================================="

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
pip3 install --upgrade pip
pip3 install --upgrade setuptools wheel
pip3 install pyyaml requests jinja2

# Clean up
echo "Cleaning up package cache..."
apt-get autoremove -y
apt-get clean

echo "=================================================="
echo "Base system installation complete!"
echo "=================================================="
