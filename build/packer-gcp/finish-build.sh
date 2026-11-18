#!/usr/bin/env bash
# Root-only final Packer step after the image playbook succeeds. No secret reads.
# The image playbook owns VLAB/management readiness and service quiescence.
# This final SSH step removes builder access and host identity before capture.
set -euo pipefail

[[ $(id -u) == 0 ]]
rm -rf -- /run/labapp-build-registry /opt/labapp/build-source
rm -f -- /usr/local/sbin/labapp-build-ansible
[[ ! -e /run/labapp-build-registry/config.json ]]

# Prevent the metadata agent from restoring the builder key during capture.
# Leave services enabled so they can establish the new student's access on boot.
for unit in google-guest-agent-manager.service google-guest-agent.service; do
  if [[ $(systemctl show --property=LoadState --value "$unit") != not-found ]]; then
    systemctl stop "$unit"
  fi
done
cloud-init clean --logs --machine-id
rm -f -- /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
rm -f -- /etc/ssh/ssh_host_*
rm -f -- /tmp/labapp-finish-build.sh
# Do not remove the nested VLAB's SSH keys or the student's merged kubeconfig.
# No further SSH provisioning follows: Packer stops/captures through the API.
sync
