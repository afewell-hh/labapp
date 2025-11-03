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
apt-get autoremove -y
apt-get clean
rm -rf /var/lib/apt/lists/*

# Clean logs
echo "Cleaning logs..."
find /var/log -type f -exec truncate -s 0 {} \;
rm -rf /var/log/*.gz
rm -rf /var/log/*.[0-9]
rm -rf /var/log/*-????????
rm -rf /tmp/*
rm -rf /var/tmp/*

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

# Zero out free space to improve compression (optional, can take time)
echo "Zeroing out free space for better compression..."
dd if=/dev/zero of=/EMPTY bs=1M || true
rm -f /EMPTY

# Sync filesystem
sync

echo "=================================================="
echo "Cleanup complete!"
echo "=================================================="
