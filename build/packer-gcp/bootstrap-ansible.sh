#!/usr/bin/env bash
# Ubuntu 24.04 guest bootstrap, run as root by Packer. No registry content is read.
# Input: ANSIBLE_CORE_PACKAGE_VERSION, an exact Ubuntu apt package version.
set -euo pipefail

[[ $(id -u) == 0 ]]
[[ ${ANSIBLE_CORE_PACKAGE_VERSION:?exact ansible-core package version required} =~ ^[0-9][A-Za-z0-9.+:~-]+$ ]]
[[ $(findmnt -n -o FSTYPE --target /run) == tmpfs ]]

export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait
apt-get update
apt-get install -y --no-install-recommends \
  "ansible-core=${ANSIBLE_CORE_PACKAGE_VERSION}" python3-apt ca-certificates

install -d -o ubuntu -g ubuntu -m 0700 /run/labapp-build-registry
install -o ubuntu -g ubuntu -m 0600 /dev/null /run/labapp-build-registry/config.json
install -d -o ubuntu -g ubuntu -m 0700 /opt/labapp/build-source

# Ansible-local needs an executable path rather than an embedded sudo command.
cat > /usr/local/sbin/labapp-build-ansible <<'WRAPPER'
#!/bin/sh
exec sudo -n /usr/bin/ansible-playbook "$@"
WRAPPER
chmod 0755 /usr/local/sbin/labapp-build-ansible
