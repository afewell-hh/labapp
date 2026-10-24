#!/usr/bin/env bash
# Host-side test runner; Docker + network for isolated apt-only preparation.
# Helper execution uses only NET_ADMIN, network=none and a read-only narrow mount.
# No cloud identity, host socket/credentials, privileged mode or host networking.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
suffix="${RANDOM}-${RANDOM}-$$"
prep="labapp-bridge-prep-${suffix}"
runtime="labapp-bridge-runtime-${suffix}"
prep_id=
runtime_id=
image_id=
cleanup() {
  local failed=0 remaining
  # Remove only exact IDs returned by this run, then query the daemon to verify
  # absence. An unreachable daemon is a cleanup failure, not apparent absence.
  for container in "$runtime_id" "$prep_id"; do
    [[ -n "$container" ]] || continue
    timeout --kill-after=3s 15s docker rm -f "$container" >/dev/null || failed=1
    remaining="$(timeout --kill-after=3s 15s docker container ls -aq --no-trunc \
      --filter "id=$container")" || failed=1
    [[ -z "$remaining" ]] || failed=1
  done
  if [[ -n "$image_id" ]]; then
    timeout --kill-after=3s 15s docker image rm "$image_id" >/dev/null || failed=1
    remaining="$(timeout --kill-after=3s 15s docker image ls --no-trunc --quiet)" || failed=1
    if [[ $'\n'"$remaining"$'\n' == *$'\n'"$image_id"$'\n'* ]]; then failed=1; fi
  fi
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
prep_id="$(timeout --kill-after=3s 15s docker create --name "$prep" \
  --memory=512m --cpus=1 --pids-limit=128 --security-opt=no-new-privileges \
  "$base" timeout --kill-after=3s 210s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3 iproute2
    rm -rf /var/lib/apt/lists/*
  ')"
timeout --kill-after=5s 240s docker start -a "$prep_id"
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
image_id="$(timeout --kill-after=3s 30s docker commit "$prep_id")"
docker image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
docker image inspect "$image_id" --format 'Prepared {{.Id}}'
# Internal timeout and host timeout both bound execution; EXIT verifies cleanup.
runtime_id="$(timeout --kill-after=3s 15s docker create --name "$runtime" \
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
