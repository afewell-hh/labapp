#!/usr/bin/env bash
# Exercise build/provision/install-k3d.sh in a disposable Ubuntu 24.04 container.
# Usage: bash build/provision/test-install-k3d.sh   (host needs docker + network)
# The module under test is the real file, bind-mounted read-only.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" != "--inside" ]]; then
  exec docker run --rm -v "${here}:/provision:ro" ubuntu:24.04 \
    bash -c 'apt-get update -qq && apt-get install -y -qq curl ca-certificates > /dev/null && bash /provision/test-install-k3d.sh --inside'
fi

mod=/provision/install-k3d.sh
pinned="$(sed -n 's/^K3D_PINNED_SHA256="\(.*\)"/\1/p' "${mod}")"
zeros="0000000000000000000000000000000000000000000000000000000000000000"
ones="1111111111111111111111111111111111111111111111111111111111111111"
dir="$(mktemp -d)"
fail=0
check() { if "$@"; then echo "PASS: $*"; else echo "FAIL: $*"; fail=1; fi; }
sha() { sha256sum "$1" | awk '{print $1}'; }

# 1. clean destination
K3D_INSTALL_DIR="${dir}/a" bash "${mod}"
check test "$(sha "${dir}/a/k3d")" = "${pinned}"
check bash -c "'${dir}/a/k3d' version | grep -q 'k3d version v5.7.4'"

# 2. second run does not replace
inode1="$(stat -c %i "${dir}/a/k3d")"
K3D_INSTALL_DIR="${dir}/a" bash "${mod}" | tee "${dir}/rerun.log"
check grep -q 'nothing to do' "${dir}/rerun.log"
check test "$(stat -c %i "${dir}/a/k3d")" = "${inode1}"

# 3. bad digest leaves a known-good binary untouched
before="$(sha "${dir}/a/k3d")"
check bash -c "! K3D_INSTALL_DIR='${dir}/a' K3D_SHA256='${zeros}' bash '${mod}' 2> '${dir}/bad.err'"
check grep -q 'checksum mismatch' "${dir}/bad.err"
check test "$(sha "${dir}/a/k3d")" = "${before}"
check test -z "$(find "${dir}/a" -name '.k3d.*')"

# 4. unavailable release leaves a known-good binary untouched
check bash -c "! K3D_INSTALL_DIR='${dir}/a' K3D_SHA256='${ones}' K3D_BASE_URL=https://github.com/k3d-io/k3d/releases/download/v0.0.0-does-not-exist bash '${mod}' 2> '${dir}/dl.err'"
check grep -q 'download failed' "${dir}/dl.err"
check test "$(sha "${dir}/a/k3d")" = "${before}"

# 5. unsupported architecture fails clearly
mkdir "${dir}/shim"
printf '#!/bin/sh\n[ "$1" = -m ] && echo aarch64 || /usr/bin/uname "$@"\n' > "${dir}/shim/uname"
chmod +x "${dir}/shim/uname"
check bash -c "! PATH='${dir}/shim':\$PATH K3D_INSTALL_DIR='${dir}/b' bash '${mod}' 2> '${dir}/arch.err'"
check grep -q 'unsupported architecture' "${dir}/arch.err"
check test ! -e "${dir}/b/k3d"

exit "${fail}"
