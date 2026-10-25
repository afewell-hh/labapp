#!/usr/bin/env bash
# Test-only Bash host launcher; rootless guests, network only for preparation.
# Requires Docker, curl, Python3 stdlib, timeout; no environment overrides/cwd dependency.
# No cloud identity, host socket/credentials, privileged mode or host networking.
set -euo pipefail
mode=${1:-offline}
[[ "$#" -le 1 && ( "$mode" == offline || "$mode" == install ) ]]
prepare_command=prepare
lane_program=hhfab_test.py
work_tmpfs=/work:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=700
if [[ "$mode" == install ]]; then
  prepare_command=prepare-install
  lane_program=test_install_hhfab.py
  work_tmpfs=/work:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=700
fi
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.hhfab-test.run=${suffix}"
image_tag="labapp-hhfab-test:${suffix}"
prep="labapp-hhfab-prep-${suffix}"
runtime="labapp-hhfab-runtime-${suffix}"
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
  if ((failed)); then echo 'hhfab test: owned cleanup failed' >&2; fi
  rm -rf -- "$workdir" || failed=1
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
for dependency in docker timeout python3 curl; do command -v "$dependency" >/dev/null; done
timeout --kill-after=1s 5s docker version --format 'Docker server {{.Server.Version}}'
# Official archives verified/extracted on host, never executed on host.
timeout --kill-after=3s 270s python3 "$here/hhfab_test.py" "$prepare_command" "$workdir" "$here/../.."
prep_id="$(timeout --kill-after=3s 15s docker create --name "$prep" --label "$run_label" \
  --memory=512m --cpus=1 --pids-limit=128 --security-opt=no-new-privileges \
  "$base" timeout --kill-after=3s 210s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17 python3-yaml=6.0.1-2build2 libyaml-0-2=0.2.5-1build1
    rm -rf /var/lib/apt/lists/*
    mkdir /suite
    dpkg-query -W
  ')"
[[ "$prep_id" =~ ^[a-f0-9]{64}$ ]]
timeout --kill-after=5s 240s docker start -a "$prep_id"
[[ "$(timeout --kill-after=1s 5s docker inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
timeout --kill-after=3s 30s docker cp "$workdir/." "$prep_id:/suite/"
# Only public binary and fixture files; guest can read them without host mount.
# mktemp source directory permissions do not propagate through copy's /. contents.
image_id="$(timeout --kill-after=3s 30s docker commit --change "LABEL $run_label" "$prep_id" "$image_tag")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
timeout --kill-after=1s 5s docker image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
timeout --kill-after=1s 5s docker image inspect "$image_id" --format 'Prepared {{.Id}}'
lane_failed=0
for version in 0.43.1 0.50.4; do
  runtime_id="$(timeout --kill-after=3s 15s docker create --name "$runtime" --label "$run_label" \
    --network=none --cap-drop=ALL --security-opt=no-new-privileges --read-only --user=1000:1000 \
    --tmpfs "$work_tmpfs" \
    --tmpfs /var/log:rw,nosuid,nodev,noexec,size=8m,uid=1000,gid=1000,mode=700 \
    --memory=1g --cpus=2 --pids-limit=128 --env LABAPP_HHFAB_TEST=1 \
    --env PYTHONDONTWRITEBYTECODE=1 "$image_id" \
    timeout --kill-after=3s 120s python3 "/suite/$lane_program" lane "$version")"
  [[ "$runtime_id" =~ ^[a-f0-9]{64}$ ]]
  if ! python3 "$here/hhfab_test.py" attach "$runtime_id" "$workdir/report"; then
    echo "hhfab test: lane $version failed" >&2
    lane_failed=1
  fi
  if [[ "$(timeout --kill-after=1s 5s docker inspect --format '{{.State.ExitCode}}' "$runtime_id")" != 0 ]]; then
    lane_failed=1
  fi
  object="$(owned_container "$runtime")"
  [[ "$object" =~ ^[a-f0-9]{64}$ ]]
  timeout --kill-after=1s 5s docker rm "$object" >/dev/null
  remaining="$(owned_container "$runtime")"
  [[ -z "$remaining" ]]
done
[[ "$lane_failed" == 0 ]]
