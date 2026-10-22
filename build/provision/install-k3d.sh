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
#   K3D_DOWNLOAD_MAX_TIME       seconds allowed per download attempt (default 120)
#   K3D_DOWNLOAD_TOTAL_TIMEOUT  hard cap in seconds on the whole download
#                               including retries (default 600)
# Download bounds: each attempt is capped by --max-time and aborted if it moves
# under 1 KiB/s for 30s; curl retries up to 3 times; `timeout` caps the total.
# Worst case with defaults is therefore 600s, after which the install fails and
# any existing binary is left untouched.
set -euo pipefail

K3D_VERSION="v5.7.4"
K3D_PINNED_SHA256="1ac1da365236736a8df8c32107b54aca208384ab1d9a06771443c85ad698a5eb"

install_dir="${K3D_INSTALL_DIR:-/usr/local/bin}"
base_url="${K3D_BASE_URL:-https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}}"
expected_sha="${K3D_SHA256:-${K3D_PINNED_SHA256}}"
max_time="${K3D_DOWNLOAD_MAX_TIME:-120}"
total_timeout="${K3D_DOWNLOAD_TOTAL_TIMEOUT:-600}"
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
command -v timeout > /dev/null || die "timeout (coreutils) is required"

# Idempotent: leave a binary that already matches the expected digest alone,
# but repair the mode if a preseeded copy is not executable.
if [[ -f "${dest}" ]] && echo "${expected_sha}  ${dest}" | sha256sum -c --status 2> /dev/null; then
  if [[ ! -x "${dest}" ]]; then
    chmod 0755 "${dest}"
    log "${dest} matched ${expected_sha} but was not executable; mode repaired to 0755"
  else
    log "${dest} already matches ${expected_sha}; nothing to do"
  fi
  exit 0
fi

mkdir -p "${install_dir}"
tmp="$(mktemp "${install_dir}/.k3d.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

log "downloading ${base_url}/k3d-linux-amd64"
rc=0
timeout --kill-after=5 "${total_timeout}" \
  curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 \
  --max-time "${max_time}" --speed-limit 1024 --speed-time 30 \
  --output "${tmp}" "${base_url}/k3d-linux-amd64" || rc=$?
if [[ "${rc}" -ne 0 ]]; then
  die "download failed (exit ${rc}; 124 = ${total_timeout}s total cap hit, 28 = curl timeout); existing ${dest} (if any) left untouched"
fi

actual_sha="$(sha256sum "${tmp}" | awk '{print $1}')"
if [[ "${actual_sha}" != "${expected_sha}" ]]; then
  die "checksum mismatch (expected ${expected_sha}, got ${actual_sha}); existing ${dest} (if any) left untouched"
fi

chmod 0755 "${tmp}"
mv -f "${tmp}" "${dest}"
trap - EXIT
log "installed ${dest} (sha256 ${actual_sha})"
