#!/bin/bash
# 00-preflight-checks.sh
# Validate host readiness before running the Hedgehog Lab installer

set -euo pipefail

log() {
    local level="${1:-INFO}"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        log ERROR "Run the installer as root (sudo ./hh-lab-installer ...)."
        exit 1
    fi
}

check_os_version() {
    local desc
    desc=$(lsb_release -d 2>/dev/null | awk -F'\t' '{print $2}')
    if ! echo "$desc" | grep -q "Ubuntu 24.04"; then
        log ERROR "Unsupported OS: '${desc:-unknown}'. Ubuntu 24.04 LTS required."
        exit 1
    fi
    log INFO "OS check passed: $desc"
}

check_nested_virt() {
    if ! grep -Eq 'vmx|svm' /proc/cpuinfo; then
        log ERROR "Nested virtualization not detected. Enable Intel VT-x/AMD-V (with nesting) and retry."
        exit 1
    fi
    log INFO "Nested virtualization detected."
}

check_resources() {
    local cpu mem disk
    cpu=$(nproc)
    mem=$(free -g | awk '/^Mem:/ {print $2}')
    disk=$(df -BG / | awk 'NR==2 {gsub("G","",$4); print $4}')

    if [ "$cpu" -lt 32 ]; then
        log WARN "Detected ${cpu} vCPUs (<32). Installer will continue but VLAB performance may degrade."
    else
        log INFO "CPU check passed (${cpu} vCPUs)."
    fi

    if [ "$mem" -lt 128 ]; then
        log WARN "Detected ${mem}GB RAM (<128GB). Lab stability is not guaranteed."
    else
        log INFO "Memory check passed (${mem}GB)."
    fi

    if [ "$disk" -lt 400 ]; then
        log WARN "Detected ${disk}GB free disk on /. At least 400GB is recommended."
    else
        log INFO "Disk check passed (${disk}GB free on /)."
    fi
}

ensure_hhlab_user() {
    if id hhlab >/dev/null 2>&1; then
        log INFO "User 'hhlab' already present."
        return
    fi

    log INFO "Creating user 'hhlab' with password login (lab use only)."
    useradd -m -s /bin/bash hhlab
    echo "hhlab:hhlab" | chpasswd
    usermod -aG sudo hhlab
}

require_root
check_os_version
check_nested_virt
check_resources
ensure_hhlab_user
