#!/usr/bin/env bash
# Exercise build/provision/install-k3d.sh in a disposable Ubuntu 24.04 container.
# Usage: bash build/provision/test-install-k3d.sh [RUNS]   (host needs docker + network)
# Runs the whole suite in RUNS (default 2) separate fresh ubuntu:24.04 containers.
# Each container is isolated: only this directory is mounted, read-only; no Docker
# socket, no host credentials, no host env passed through. Prints the base image
# id/digest, os-release, each check's result and per-run timing.
# The module under test is the real file.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" != "--inside" ]]; then
  runs="${1:-2}"
  docker pull ubuntu:24.04 > /dev/null
  echo "base image: $(docker image inspect ubuntu:24.04 --format '{{.Id}} {{join .RepoDigests ","}}')"
  overall=0
  for i in $(seq 1 "${runs}"); do
    echo "=== fresh container run ${i}/${runs} ($(date -u +%FT%TZ)) ==="
    start=${SECONDS}
    rc=0
    docker run --rm -v "${here}:/provision:ro" ubuntu:24.04 \
      bash -c 'grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release; apt-get update -qq && apt-get install -y -qq curl ca-certificates python3 > /dev/null && bash /provision/test-install-k3d.sh --inside' || rc=$?
    echo "=== run ${i} exit ${rc} in $((SECONDS - start))s ==="
    [[ "${rc}" -eq 0 ]] || overall=1
  done
  exit "${overall}"
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

# 4b. a stalled (connected, then silent) download is bounded and preserves the binary
cat > "${dir}/stall.py" <<'PYEOF'
import socketserver, time
class H(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nx")
        time.sleep(300)
class S(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("127.0.0.1", 8099), H).serve_forever()
PYEOF
python3 "${dir}/stall.py" &
stall_pid=$!
sleep 1
t0=${SECONDS}
check bash -c "! K3D_INSTALL_DIR='${dir}/a' K3D_SHA256='${ones}' K3D_BASE_URL=http://127.0.0.1:8099 K3D_DOWNLOAD_MAX_TIME=2 K3D_DOWNLOAD_TOTAL_TIMEOUT=30 bash '${mod}' 2> '${dir}/stall.err'"
check test "$((SECONDS - t0))" -le 35
check grep -q 'download failed' "${dir}/stall.err"
check test "$(sha "${dir}/a/k3d")" = "${before}"
check test -z "$(find "${dir}/a" -name '.k3d.*')"
kill "${stall_pid}" 2> /dev/null || true

# 4c. preseeded matching but non-executable binary is repaired and runs
mkdir "${dir}/c"
cp "${dir}/a/k3d" "${dir}/c/k3d"
chmod 0644 "${dir}/c/k3d"
check test ! -x "${dir}/c/k3d"
K3D_INSTALL_DIR="${dir}/c" bash "${mod}" | tee "${dir}/mode.log"
check grep -q 'mode repaired' "${dir}/mode.log"
check test -x "${dir}/c/k3d"
check bash -c "'${dir}/c/k3d' version | grep -q 'k3d version v5.7.4'"

# 5. unsupported architecture fails clearly
mkdir "${dir}/shim"
cat > "${dir}/shim/uname" <<'SHIMEOF'
#!/bin/sh
[ "$1" = -m ] && echo aarch64 || /usr/bin/uname "$@"
SHIMEOF
chmod +x "${dir}/shim/uname"
check bash -c "! PATH='${dir}/shim':\$PATH K3D_INSTALL_DIR='${dir}/b' bash '${mod}' 2> '${dir}/arch.err'"
check grep -q 'unsupported architecture' "${dir}/arch.err"
check test ! -e "${dir}/b/k3d"

exit "${fail}"
