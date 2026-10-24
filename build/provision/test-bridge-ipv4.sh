#!/usr/bin/env bash
# Host-side test runner; Docker + network for isolated apt-only preparation.
# Helper execution uses only NET_ADMIN, network=none and a read-only narrow mount.
# No cloud identity, host socket/credentials, privileged mode or host networking.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.bridge-test.run=${suffix}"
image_tag="labapp-bridge-test:${suffix}"
prep="labapp-bridge-prep-${suffix}"
runtime="labapp-bridge-runtime-${suffix}"
prep_id=
runtime_id=
image_id=
owned_container() {
  timeout --kill-after=1s 5s docker container ls -aq --no-trunc \
    --filter "name=^/${1}$" --filter "label=$run_label"
}
owned_image() {
  timeout --kill-after=1s 5s docker image ls --no-trunc --quiet \
    --filter "reference=$image_tag" --filter "label=$run_label"
}
cleanup() {
  local failed=0 object remaining
  # Recover by exact nonce-bearing name/tag AND ownership label even if create
  # or commit succeeded at the daemon but its response was lost. Never infer
  # absence from a failed query; never remove by a name prefix or label alone.
  for container in "$runtime" "$prep"; do
    if ! object="$(owned_container "$container")"; then
      failed=1
      continue
    fi
    [[ -n "$object" ]] || continue
    if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then failed=1; continue; fi
    timeout --kill-after=1s 5s docker rm -f "$object" >/dev/null || failed=1
    remaining="$(owned_container "$container")" || failed=1
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
  if ((failed)); then echo 'bridge test: owned cleanup failed' >&2; fi
  return "$failed"
}
finish() {
  local result=$?
  trap - EXIT
  cleanup || result=1
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
command -v docker >/dev/null
command -v timeout >/dev/null
docker version --format 'Docker server {{.Server.Version}}'
# Preparation never sees repository code or NET_ADMIN. Dependencies are distro
# packages, not helper install/download fallback. No source mounts or secrets.
prep_id="$(timeout --kill-after=3s 15s docker create --name "$prep" --label "$run_label" \
  --memory=512m --cpus=1 --pids-limit=128 --security-opt=no-new-privileges \
  "$base" timeout --kill-after=3s 210s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3 iproute2
    rm -rf /var/lib/apt/lists/*
  ')"
timeout --kill-after=5s 240s docker start -a "$prep_id"
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
image_id="$(timeout --kill-after=3s 30s docker commit --change "LABEL $run_label" "$prep_id" "$image_tag")"
docker image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
docker image inspect "$image_id" --format 'Prepared {{.Id}}'
# Internal timeout and host timeout both bound execution; EXIT verifies cleanup.
runtime_id="$(timeout --kill-after=3s 15s docker create --name "$runtime" --label "$run_label" \
  --network=none --cap-drop=ALL --cap-add=NET_ADMIN \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --memory=256m --cpus=1 --pids-limit=64 --security-opt=no-new-privileges \
  --mount "type=bind,src=${here},dst=/provision,readonly" \
  "$image_id" timeout --kill-after=3s 30s bash -ceu '
    cat /etc/os-release
    uname -r
    python3 --version
    ip -Version
    capsh --print
    export PYTHONDONTWRITEBYTECODE=1 LABAPP_DISPOSABLE_NETNS_TEST=1
    python3 /provision/test_bridge_ipv4_container.py
  ')"
timeout --kill-after=5s 45s docker start -a "$runtime_id"
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$runtime_id")" == 0 ]]
