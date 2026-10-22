#!/usr/bin/env bash
# Install a pinned k3d release binary (Linux amd64 only). Noninteractive.
#
# Source: https://github.com/k3d-io/k3d/releases/tag/v5.7.4
# The SHA256 below is the k3d-linux-amd64 entry of that release's
# checksums.txt (the same file upstream's install.sh verifies against).
# Bumping the version means updating K3D_VERSION and K3D_PINNED_SHA256 together.
#
# Overrides (for tests/isolation; the defaults are what provisioning uses):
#   K3D_INSTALL_DIR  destination directory (default /usr/local/bin)
#   K3D_BASE_URL     release download base (default upstream GitHub releases)
#   K3D_SHA256       expected digest (default: pinned below)
set -euo pipefail

K3D_VERSION="v5.7.4"
K3D_PINNED_SHA256="1ac1da365236736a8df8c32107b54aca208384ab1d9a06771443c85ad698a5eb"

install_dir="${K3D_INSTALL_DIR:-/usr/local/bin}"
base_url="${K3D_BASE_URL:-https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}}"
expected_sha="${K3D_SHA256:-${K3D_PINNED_SHA256}}"
dest="${install_dir}/k3d"

log() { echo "install-k3d: $*"; }
die() { echo "install-k3d: ERROR: $*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "unsupported OS '$(uname -s)'; only Linux is supported"
case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) die "unsupported architecture '$(uname -m)'; only amd64 is supported" ;;
esac
command -v curl > /dev/null || die "curl is required"
command -v sha256sum > /dev/null || die "sha256sum is required"

# Idempotent: leave a binary that already matches the expected digest alone.
if [[ -f "${dest}" ]] && echo "${expected_sha}  ${dest}" | sha256sum -c --status 2> /dev/null; then
  log "${dest} already matches ${expected_sha}; nothing to do"
  exit 0
fi

mkdir -p "${install_dir}"
tmp="$(mktemp "${install_dir}/.k3d.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

log "downloading ${base_url}/k3d-linux-amd64"
curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 \
  --output "${tmp}" "${base_url}/k3d-linux-amd64" \
  || die "download failed; existing ${dest} (if any) left untouched"

actual_sha="$(sha256sum "${tmp}" | awk '{print $1}')"
if [[ "${actual_sha}" != "${expected_sha}" ]]; then
  die "checksum mismatch (expected ${expected_sha}, got ${actual_sha}); existing ${dest} (if any) left untouched"
fi

chmod 0755 "${tmp}"
mv -f "${tmp}" "${dest}"
trap - EXIT
log "installed ${dest} (sha256 ${actual_sha})"
