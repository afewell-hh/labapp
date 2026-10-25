#!/usr/bin/env bash
# Trusted lead only: actual captured STATE -> new OUTPUT directory, no overrides.
# Never host APT; one pinned disposable downloader. Print expected receipt SHA.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: prepare-qemu-offline.sh STATE OUTPUT' >&2; exit 1; }
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state="$(realpath -- "$1")"
output="$2"
[[ -f "$state" && ! -L "$1" && ! -e "$output" ]]
IFS= read -r suffix < /proc/sys/kernel/random/uuid
name="labapp-qemu-acquire-${suffix}"
label="labapp.qemu-offline.run=${suffix}"
id=
output_owned=0
owned() {
  timeout --kill-after=1s 5s docker container ls -aq --no-trunc \
    --filter "name=^/${name}$" --filter "label=$label"
}
cleanup() {
  local object remaining
  object="$(owned)" || return 1
  if [[ -z "$object" ]]; then
    if [[ -n "$id" ]]; then
      remaining="$(timeout --kill-after=1s 5s docker container ls -aq --no-trunc --filter "id=$id")" || return 1
      [[ -z "$remaining" ]] || return 1
    fi
    return 0
  fi
  [[ "$object" =~ ^[a-f0-9]{64}$ ]] || return 1
  timeout --kill-after=1s 5s docker rm -f "$object" >/dev/null || return 1
  remaining="$(owned)" || return 1
  [[ -z "$remaining" ]] || return 1
  remaining="$(timeout --kill-after=1s 5s docker container ls -aq --no-trunc --filter "id=$object")" || return 1
  [[ -z "$remaining" ]]
}
finish() {
  local result=$?
  trap - EXIT
  cleanup || result=1
  if ((result && output_owned)); then rm -rf -- "$output" || result=1; fi
  if ((result)); then echo 'QEMU acquisition failed; output is not trusted' >&2; fi
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Only bounded local data is copied; no raw config executes in the guest.
python3 - "$state" <<'PY'
import os,stat,sys
p=sys.argv[1]; s=os.lstat(p)
assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= 16*1024**2
PY
id="$(timeout --kill-after=3s 15s docker create --name "$name" --label "$label" \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETUID --cap-add=SETGID \
  --memory=1g --cpus=2 --pids-limit=128 --security-opt=no-new-privileges \
  --tmpfs /work:rw,nosuid,nodev,noexec,size=320m \
  ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac \
  timeout --kill-after=3s 420s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17 ca-certificates=20240203
    exec python3 /suite/qemu_acquire.py
  ')"
[[ "$id" =~ ^[a-f0-9]{64}$ && "$(owned)" == "$id" ]]
timeout --kill-after=3s 30s docker cp "$here/." "$id:/suite/"
timeout --kill-after=3s 30s docker cp "$state" "$id:/target-state.json"
# Suppress bootstrap and APT logs (including target package state); only the
# bounded public receipt summary is printed after successful guest completion.
python3 - "$id" "$here" <<'PY2'
import sys
sys.path.insert(0,sys.argv[2])
from hhfab_release import bounded,Refusal
code,output = bounded(['docker','start','-a',sys.argv[1]],450,limit=1024*1024)
if code:
    for line in output.decode(errors='replace').splitlines():
        if line.startswith(('QEMU acquisition stage: ', 'QEMU acquisition refused: ')):
            print(line, file=sys.stderr)
    raise Refusal('downloader failed; raw logs withheld')
PY2
[[ "$(timeout --kill-after=1s 5s docker inspect --format '{{.State.ExitCode}}' "$id")" == 0 ]]
mkdir -- "$output"
output_owned=1
timeout --kill-after=3s 30s docker cp "$id:/export-bundle/." "$output"
python3 - "$output/receipt.json" "$here" <<'PY'
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[2])
import qemu_offline as protocol
p=Path(sys.argv[1]); r=protocol.load(p)
assert {v.name for v in p.parent.iterdir()} == {'receipt.json','lists','archives'}
assert protocol.inventory(p.parent) == r['files']
print(json.dumps({'receipt_sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                  'files': len(r['files']), 'bytes':sum(v['bytes'] for v in r['files'].values())}))
PY
