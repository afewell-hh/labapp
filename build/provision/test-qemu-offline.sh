#!/usr/bin/env bash
# Host-only Docker preparation + network-none nonroot execution; no overrides.
set -euo pipefail
selection=test-20261024
if [[ $# != 0 ]]; then
  [[ $# == 2 && $1 == --selection && $2 == baseline-20260114 ]] || {
    echo 'usage: test-qemu-offline.sh [--selection baseline-20260114]' >&2; exit 1;
  }
  selection=baseline-20260114
fi
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.qemu-offline-test.run=${suffix}"
image_tag="labapp-qemu-offline-test:${suffix}"
prep="labapp-qemu-offline-prep-${suffix}"
runtime="labapp-qemu-offline-target-${suffix}"
prep_id=
runtime_id=
image_id=
workdir="$(mktemp -d)"
owned_container() {
  timeout --kill-after=1s 5s docker container ls -aq --no-trunc \
    --filter "name=^/${1}$" --filter "label=$run_label"
}
owned_image() {
  timeout --kill-after=1s 5s docker image ls --no-trunc --quiet \
    --filter "reference=$image_tag" --filter "label=$run_label"
}
cleanup() {
  local failed=0 object remaining known
  # Recover by exact nonce-bearing name/tag AND ownership label even if create
  # or commit succeeded at the daemon but its response was lost. Never infer
  # absence from a failed query; never remove by a name prefix or label alone.
  for container in "$runtime" "$prep"; do
    if ! object="$(owned_container "$container")"; then
      failed=1
      continue
    fi
    if [[ -z "$object" ]]; then
      known="$prep_id"
      [[ "$container" != "$runtime" ]] || known="$runtime_id"
      if [[ -n "$known" ]]; then
        remaining="$(timeout --kill-after=1s 5s docker container ls -aq --no-trunc --filter "id=$known")" || failed=1
        [[ -z "$remaining" ]] || failed=1
      fi
      continue
    fi
    if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then failed=1; continue; fi
    timeout --kill-after=1s 5s docker rm -f "$object" >/dev/null || failed=1
    remaining="$(owned_container "$container")" || failed=1
    [[ -z "$remaining" ]] || failed=1
    remaining="$(timeout --kill-after=1s 5s docker container ls -aq --no-trunc --filter "id=$object")" || failed=1
    [[ -z "$remaining" ]] || failed=1
  done
  if ! object="$(owned_image)"; then
    failed=1
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      timeout --kill-after=1s 5s docker image rm "$object" >/dev/null || failed=1
      remaining="$(owned_image)" || failed=1
      [[ -z "$remaining" ]] || failed=1
    else
      failed=1
    fi
  fi
  if ((failed)); then echo 'qemu test: owned cleanup failed' >&2; fi
  rm -rf -- "$workdir" || failed=1
  # A successful rm is not absence evidence: check the exact owned path again.
  if [[ -e "$workdir" || -L "$workdir" ]]; then
    echo "qemu test: host scratch still present: $workdir" >&2
    failed=1
  else
    echo "qemu test: host scratch absent: $workdir"
  fi
  return "$failed"
}
finish() {
  local result=$?
  trap - EXIT
  cleanup || { if ((result == 0)); then result=1; fi; }
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for dependency in docker timeout python3; do command -v "$dependency" >/dev/null; done
timeout --kill-after=1s 5s docker version --format 'Docker server {{.Server.Version}}'
echo 'Preparing one Python-only target image; target APT state captured after this step'
prep_id="$(timeout --kill-after=3s 15s docker create --name "$prep" --label "$run_label" \
  --memory=1g --cpus=2 --pids-limit=128 --security-opt=no-new-privileges \
  "$base" timeout --kill-after=3s 180s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17
  ')"
[[ "$prep_id" =~ ^[a-f0-9]{64}$ && "$(owned_container "$prep")" == "$prep_id" ]]
timeout --kill-after=5s 210s docker start -a "$prep_id" >/dev/null
[[ "$(timeout --kill-after=1s 5s docker inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
image_id="$(timeout --kill-after=3s 30s docker commit --change "LABEL $run_label" "$prep_id" "$image_tag")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
runtime_id="$(timeout --kill-after=3s 15s docker create --name "$runtime" --label "$run_label" \
  --network=none --cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETUID --cap-add=SETGID \
  --security-opt=no-new-privileges --memory=1g --cpus=2 --pids-limit=128 \
  "$image_id" sleep 720)"
[[ "$runtime_id" =~ ^[a-f0-9]{64}$ && "$(owned_container "$runtime")" == "$runtime_id" ]]
timeout --kill-after=3s 30s docker cp "$here/." "$runtime_id:/suite/"
timeout --kill-after=1s 10s docker start "$runtime_id" >/dev/null
# Prove conflicting ambient policy is active before unchanged state capture.
timeout --kill-after=3s 30s docker exec "$runtime_id" python3 /suite/qemu_offline_container.py --prepare-policy
# Exact actual target state is captured using the same unchanged module CLI.
timeout --kill-after=3s 30s docker exec "$runtime_id" python3 /suite/install-qemu.py \
  --capture-state /target-state.json --base-id "$base" --selection "$selection"
timeout --kill-after=3s 30s docker cp "$runtime_id:/target-state.json" "$workdir/state.json"
# This digest comes from the trusted acquisition result, independently of the
# bundle subsequently copied to the disconnected target. Never hash receipt there
# to invent the expected value.
acquisition_start=$SECONDS
acquisition="$(timeout --kill-after=10s 9m bash "$here/prepare-qemu-offline.sh" "$workdir/state.json" "$workdir/bundle")"
printf '%s\n' "$acquisition"
printf 'qemu test: acquisition seconds %s\n' "$((SECONDS - acquisition_start))"
expected="$(python3 -c 'import json,re,sys; r=json.loads(sys.argv[1]); s=r["receipt_sha256"]; assert isinstance(s,str) and re.fullmatch("[a-f0-9]{64}",s); print(s)' "$acquisition")"
timeout --kill-after=3s 30s docker cp "$workdir/bundle" "$runtime_id:/bundle"
timeout --kill-after=5s 510s docker exec "$runtime_id" python3 /suite/qemu_offline_container.py \
  --selection "$selection" --receipt-sha256 "$expected"
