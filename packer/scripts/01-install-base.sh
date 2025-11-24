#!/bin/bash
# 01-install-base.sh
# Install base system packages and perform system updates
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing base system packages..."
echo "=================================================="

# Ensure the hhlab user exists for downstream scripts and services
if ! id hhlab >/dev/null 2>&1; then
    echo "Creating lab user 'hhlab' (password: hhlab)..."
    useradd -m -s /bin/bash hhlab
    echo "hhlab:hhlab" | chpasswd
    usermod -aG sudo hhlab
else
    echo "User 'hhlab' already exists; skipping creation."
fi

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

# Expand root filesystem to consume full disk (Bug #23)
if lsblk /dev/ubuntu-vg/ubuntu-lv &>/dev/null; then
    echo "Expanding root logical volume to use all free space..."
    # Use || true to prevent build failure when LV already consumes 100% of VG
    lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv || echo "LV already at maximum size (expected on some configurations)"
    echo "Resizing filesystem to match expanded LV..."
    resize2fs /dev/ubuntu-vg/ubuntu-lv
else
    echo "WARNING: /dev/ubuntu-vg/ubuntu-lv not found; skipping LV expansion"
fi

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
    linux-cloud-tools-virtual \
    qemu-utils \
    qemu-system-x86 \
    socat

# Install Docker
echo "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add hhlab user to required desktop/system groups (Bug #17 dependency)
for grp in sudo adm dialout cdrom floppy audio dip video plugdev netdev docker; do
    if getent group "$grp" >/dev/null; then
        usermod -aG "$grp" hhlab
    else
        echo "WARNING: Group $grp not found; skipping"
    fi
done

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Ensure SSH directory exists with correct permissions for hhlab (Bug #15/#92)
install -d -m 700 -o hhlab -g hhlab /home/hhlab/.ssh
touch /home/hhlab/.ssh/authorized_keys
chown hhlab:hhlab /home/hhlab/.ssh/authorized_keys
chmod 600 /home/hhlab/.ssh/authorized_keys

# Install Python 3 and pip
echo "Installing Python 3 and related packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Install common Python packages
# Ubuntu 24.04 uses PEP 668 externally-managed environment, use --break-system-packages for system-wide install
# Use --ignore-installed to avoid trying to uninstall Debian-packaged versions
# Check if pip supports --break-system-packages (pip >= 23.0)
PIP_BREAK_SYSTEM_FLAG=""
if pip3 install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_BREAK_SYSTEM_FLAG="--break-system-packages"
fi
pip3 install $PIP_BREAK_SYSTEM_FLAG --ignore-installed --no-cache-dir --upgrade pip setuptools wheel
pip3 install $PIP_BREAK_SYSTEM_FLAG --no-cache-dir pyyaml requests jinja2

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
