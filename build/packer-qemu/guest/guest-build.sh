#!/usr/bin/env bash
# Guest build runner for the Packer/QEMU experiment (see ../README.md).
#
# Interpreter: bash (invoked as `bash path`). Runs as root from
# labapp-build.service, started after cloud-final.service; cwd is `/`.
# Environment: none read. Each plan line runs under `env -i` with a fixed
# PATH/HOME/LC_ALL/DEBIAN_FRONTEND, stdin /dev/null, cwd `/`, as `root`
# directly or as `ubuntu` via runuser, so modules keep their documented
# user/privilege/noninteractive contract.
# Inputs: /var/lib/labapp-build/in/{MANIFEST,nonce,plan.txt,<staged files>}.
# plan.txt lines: `<root|ubuntu> <argv...>` (whitespace-split, no quoting;
# `@IN@` expands to the staging directory); blank and `#` lines ignored.
#
# Order: cloud-init success check -> staged bytes match MANIFEST exactly ->
# plan (modules, then verification) -> seal -> sync -> receipt on the private
# serial port -> poweroff. A failure emits a status=fail receipt and exits;
# the host watchdog, not this script, terminates the VM.
set -Eeuo pipefail

IN=/var/lib/labapp-build/in
SAFE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ZERO=$(printf '0%.0s' {1..64})
inputs=$ZERO
nonce=$ZERO

emit() { # status
  printf '\nLABAPP-RECEIPT v1 nonce=%s inputs=%s status=%s\n' "$nonce" "$inputs" "$1" \
    >/dev/ttyS0
}

check_cloud_init() {
  cloud-init status --format json | python3 -c '
import json, sys
s = json.load(sys.stdin)
sys.exit(0 if s.get("status") == "done" and not s.get("errors") else 1)'
}

check_inputs() {
  (cd "$IN" && sha256sum --check --strict --quiet MANIFEST)
  diff <(cd "$IN" && ls -A | grep -vx -e nonce -e MANIFEST | sort) \
       <(awk '{print $2}' "$IN/MANIFEST" | sort) >/dev/null
}

run_plan() {
  local user rest home
  local -a words prefix
  while read -r user rest || [[ -n ${user:-} ]]; do
    [[ -z ${user:-} || $user == \#* ]] && continue
    read -r -a words <<<"${rest//@IN@/$IN}"
    case $user in
      root) prefix=(); home=/root ;;
      ubuntu) prefix=(runuser -u ubuntu --); home=/home/ubuntu ;;
      *) echo "unsupported plan user" >&2; return 1 ;;
    esac
    (cd / && "${prefix[@]}" env -i PATH="$SAFE_PATH" HOME="$home" LC_ALL=C.UTF-8 \
      DEBIAN_FRONTEND=noninteractive "${words[@]}" </dev/null)
  done <"$IN/plan.txt"
}

# Placeholder minimum; real Noble identity/sealing behavior is an UNRUN gate.
seal() {
  cloud-init clean --logs
  : >/etc/machine-id
  rm -rf "$IN" /etc/systemd/system/labapp-build.service
}

main() {
  nonce=$(<"$IN/nonce")
  inputs=$(sha256sum "$IN/MANIFEST" | cut -d' ' -f1)
  trap 'emit fail' ERR
  check_cloud_init
  check_inputs
  run_plan
  seal
  sync
  trap - ERR
  emit ok
  systemctl --no-block poweroff
}

main "$@"
exit
