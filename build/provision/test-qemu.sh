#!/usr/bin/env bash
# Host-only Docker preparation + network-none nonroot execution; no overrides.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
auth_only=0
case "$*" in
  '') ;;
  --auth-only) auth_only=1 ;;
  *) echo 'usage: test-qemu.sh [--auth-only]' >&2; exit 2 ;;
esac
[[ $# == 0 || ( $# == 1 && "$1" == --auth-only ) ]]
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.qemu-test.run=${suffix}"
image_tag="labapp-qemu-test:${suffix}"
prep="labapp-qemu-prep-${suffix}"
runtime="labapp-qemu-runtime-${suffix}"
auth="labapp-qemu-auth-${suffix}"
prep_id=
runtime_id=
auth_id=
auth_runs=0
image_id=
workdir="$(mktemp -d /tmp/labapp-qemu-test.XXXXXXXX)"
docker_timeout() {
  local kill_after=$1 seconds=$2
  shift 2
  # Never read the caller's Docker config, context, proxy or credential helpers.
  # Fixed local daemon and trusted executable; no environment/endpoint overrides.
  timeout --kill-after="$kill_after" "$seconds" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$workdir/home" \
    DOCKER_CONFIG="$workdir/docker" /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
owned_container() {
  docker_timeout 1s 5s container ls -aq --no-trunc \
    --filter "name=^/${1}$" --filter "label=$run_label"
}
owned_image() {
  docker_timeout 1s 5s image ls --no-trunc --quiet \
    --filter "reference=$image_tag" --filter "label=$run_label"
}
cleanup() {
  local failed=0 object remaining
  # Recover by exact nonce-bearing name/tag AND ownership label even if create
  # or commit succeeded at the daemon but its response was lost. Never infer
  # absence from a failed query; never remove by a name prefix or label alone.
  for container in "$runtime" "$auth" "$prep"; do
    if ! object="$(owned_container "$container")"; then
      failed=1
      continue
    fi
    [[ -n "$object" ]] || continue
    if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then failed=1; continue; fi
    docker_timeout 1s 5s rm -f "$object" >/dev/null || failed=1
    remaining="$(owned_container "$container")" || failed=1
    [[ -z "$remaining" ]] || failed=1
  done
  if ! object="$(owned_image)"; then
    failed=1
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      docker_timeout 1s 5s image rm "$object" >/dev/null || failed=1
      remaining="$(owned_image)" || failed=1
      [[ -z "$remaining" ]] || failed=1
    else
      failed=1
    fi
  fi
  if ((failed)); then echo 'qemu test: owned cleanup failed' >&2; fi
  return "$failed"
}
finish() {
  local result=$?
  trap - EXIT
  cleanup || result=1
  rm -rf -- "$workdir" || result=1
  [[ ! -e "$workdir" && ! -L "$workdir" ]] || result=1
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$workdir/home" "$workdir/docker"
printf '{}\n' > "$workdir/docker/config.json"
[[ -x /usr/bin/docker ]]
docker_timeout 1s 5s version --format 'Docker server {{.Server.Version}}'
lane_failed=0
lanes=(1 2)
((auth_only == 0)) || lanes=(1)
for lane in "${lanes[@]}"; do
  if ((auth_only == 0)); then echo "QEMU clean installation/runtime lane $lane"; fi
  preparation='
      apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
      DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
        install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17 ca-certificates=20240203
      test -s /usr/share/keyrings/ubuntu-archive-keyring.gpg
      dpkg-query -W ubuntu-keyring
  '
  if ((auth_only == 0)); then
    preparation+='python3 /suite/qemu_container.py install'
  else
    echo 'AUTH-ONLY: Python/CA/distribution-keyring preparation; NOT the full QEMU suite'
  fi
  prep_id="$(docker_timeout 3s 15s create --init --name "$prep" --label "$run_label" \
    --memory=1g --cpus=2 --pids-limit=128 --security-opt=no-new-privileges \
    "$base" timeout --kill-after=3s 510s bash -ceu "$preparation")"
  [[ "$prep_id" =~ ^[a-f0-9]{64}$ ]]
  docker_timeout 3s 30s cp "$here/." "$prep_id:/suite/"
  docker_timeout 5s 540s start -a "$prep_id"
  [[ "$(docker_timeout 1s 5s inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
  image_id="$(docker_timeout 3s 30s commit --change "LABEL $run_label" "$prep_id" "$image_tag")"
  [[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
  docker_timeout 1s 5s image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
  docker_timeout 1s 5s image inspect "$image_id" --format 'Prepared {{.Id}}'
  if ((lane == 1)); then
    # Native-APT metadata-authentication controls (#447 Tier 1): a separate
    # disconnected root container from the committed image, with local signed
    # fixtures only. Its success is the only way auth_runs becomes 1; the final
    # guard below refuses a suite pass without it. KILL permits the bounded
    # supervisor to kill different-UID _apt children; init reaps owned orphans.
    auth_id="$(docker_timeout 3s 15s create --init --name "$auth" --label "$run_label" \
      --network=none --cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER \
      --cap-add=SETUID --cap-add=SETGID --cap-add=KILL --security-opt=no-new-privileges --user=0:0 \
      --memory=768m --cpus=1 --pids-limit=128 --env PYTHONDONTWRITEBYTECODE=1 \
      "$image_id" timeout --kill-after=3s 150s python3 /suite/qemu_auth_control.py run)"
    [[ "$auth_id" =~ ^[a-f0-9]{64}$ ]]
    if ! docker_timeout 5s 170s start -a "$auth_id"; then lane_failed=1; fi
    if [[ "$(docker_timeout 1s 5s inspect --format '{{.State.ExitCode}}' "$auth_id")" == 0 ]]; then
      ((auth_runs += 1))
    else
      lane_failed=1
    fi
  fi
  if ((auth_only)); then
    [[ "$auth_runs" == 1 && "$lane_failed" == 0 ]]
    echo 'AUTH-ONLY controls qualified; NOT a full-suite result'
    exit 0
  fi
  runtime_id="$(docker_timeout 3s 15s create --name "$runtime" --label "$run_label" \
    --network=none --cap-drop=ALL --security-opt=no-new-privileges --read-only --user=1000:1000 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=700 \
    --memory=768m --cpus=1 --pids-limit=128 --env PYTHONDONTWRITEBYTECODE=1 \
    "$image_id" timeout --kill-after=3s 45s python3 /suite/qemu_container.py runtime)"
  [[ "$runtime_id" =~ ^[a-f0-9]{64}$ ]]
  if ! docker_timeout 5s 60s start -a "$runtime_id"; then lane_failed=1; fi
  [[ "$(docker_timeout 1s 5s inspect --format '{{.State.ExitCode}}' "$runtime_id")" == 0 ]] || lane_failed=1
  cleanup
  prep_id='' runtime_id='' auth_id='' image_id=''
done
# A full-suite pass requires the native authentication controls to have run and passed.
[[ "$auth_runs" == 1 && "$lane_failed" == 0 ]]
