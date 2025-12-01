#!/usr/bin/env bats
# test-desktop-services.sh
# Unit tests for desktop and remote access installation script
# Part of Hedgehog Lab Appliance test suite (Issue #86)

@test "Desktop installation script exists" {
  [ -f "packer/scripts/04.5-install-desktop.sh" ]
}

@test "Desktop installation script is executable" {
  [ -x "packer/scripts/04.5-install-desktop.sh" ]
}

@test "Desktop installation script has valid bash syntax" {
  bash -n packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script has proper error handling" {
  grep -q "set -euo pipefail" packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script installs XFCE" {
  grep -q "xfce4" packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script installs xRDP" {
  grep -q "xrdp" packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script installs TigerVNC" {
  grep -q "tigervnc" packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script installs VS Code" {
  grep -q "code" packer/scripts/04.5-install-desktop.sh
}

@test "Desktop installation script is referenced in standard-build.pkr.hcl" {
  grep -q "04.5-install-desktop.sh" packer/standard-build.pkr.hcl
}

@test "Desktop installation script is referenced in prewarmed-build.pkr.hcl" {
  grep -q "04.5-install-desktop.sh" packer/prewarmed-build.pkr.hcl
}

@test "Packer standard template uses Ubuntu 24.04" {
  grep -q "24.04" packer/standard-build.pkr.hcl
}

@test "Packer prewarmed template uses Ubuntu 24.04" {
  grep -q "24.04" packer/prewarmed-build.pkr.hcl
}
