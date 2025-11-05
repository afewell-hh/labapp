#!/bin/bash
# 99-cleanup.sh
# Cleanup script to reduce image size
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Cleaning up image..."
echo "=================================================="

# Stop services
echo "Stopping unnecessary services..."
systemctl stop unattended-upgrades || true

# Clean apt cache
echo "Cleaning apt cache..."
apt-get autoremove -y --purge
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -rf /var/cache/apt/archives/*.deb
rm -rf /var/cache/apt/archives/partial/*.deb

# Clean Docker build cache and unused images
echo "Cleaning Docker cache..."
docker system prune -af --volumes || true

# Clean pip cache
echo "Cleaning pip cache..."
rm -rf /root/.cache/pip
rm -rf /home/*/.cache/pip

# Clean logs
echo "Cleaning logs..."
find /var/log -type f -exec truncate -s 0 {} \;
rm -rf /var/log/*.gz
rm -rf /var/log/*.[0-9]
rm -rf /var/log/*-????????
rm -rf /tmp/*
rm -rf /var/tmp/*
journalctl --vacuum-size=1M || true

# Clean additional caches
echo "Cleaning additional caches..."
rm -rf /var/cache/man/*
rm -rf /var/cache/debconf/*-old
rm -rf /var/lib/dpkg/*-old
rm -rf /usr/share/doc-base/*
rm -rf /usr/share/groff/*
rm -rf /usr/share/linda/*
rm -rf /usr/share/lintian/*

# Clean cloud-init
echo "Cleaning cloud-init..."
cloud-init clean --logs --seed

# Clean bash history
echo "Cleaning bash history..."
rm -f /root/.bash_history
rm -f /home/*/.bash_history
history -c

# Clean SSH keys (they will be regenerated on first boot)
echo "Removing SSH host keys (will be regenerated)..."
rm -f /etc/ssh/ssh_host_*

# Zero out free space to improve compression
# NOTE: This step is SKIPPED by default for qcow2 images as it causes the
# image to expand to full disk size (~100GB), which exhausts disk space on
# CI/CD runners (GitHub Actions has limited disk space).
#
# For production builds with ample disk space, you can enable this by setting:
# export PACKER_ZERO_FILL=true
#
# Alternative: Use fstrim (already installed) which works better with qcow2
echo "Running fstrim to discard unused blocks..."
if command -v fstrim &> /dev/null; then
    fstrim -v / || echo "fstrim completed with warnings (may not be supported on all filesystems)"
else
    echo "fstrim not available, skipping trim operation"
fi

# Optional zero-fill (disabled by default for CI/CD compatibility)
if [ "${PACKER_ZERO_FILL:-false}" = "true" ]; then
    echo "PACKER_ZERO_FILL is set - zeroing out free space..."
    echo "WARNING: This will expand qcow2 to full size and may exhaust disk space"
    dd if=/dev/zero of=/EMPTY bs=1M || true
    rm -f /EMPTY
else
    echo "Skipping zero-fill (use PACKER_ZERO_FILL=true to enable)"
    echo "Using fstrim instead, which is more efficient for qcow2 images"
fi

# Sync filesystem
sync

echo "=================================================="
echo "Cleanup complete!"
echo "=================================================="
