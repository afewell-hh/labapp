#!/usr/bin/env bash
# Hosted test-only launcher: Docker + ordinary public Internet for preparation.
# Invoke with bash from any cwd, no arguments/overrides; no cloud/private input.
# Preparation runs fixed apt/git/curl only; project code executes network-none.
set -euo pipefail
[[ $# == 0 ]]
umask 077
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/../../../.." && pwd)"
for dependency in docker timeout mktemp stat; do command -v "$dependency" >/dev/null; done
scratch=$(mktemp -d /tmp/labapp-pinned-api.XXXXXXXXXX)
identity=$(stat -c %d:%i:%u:%a -- "$scratch")
suffix=${scratch##*.}
label="labapp.pinned-api=$suffix"
prep="labapp-pinned-api-prep-$suffix"
runtime="labapp-pinned-api-runtime-$suffix"
tag="labapp-pinned-api:$suffix"
prep_pending=0
runtime_pending=0
commit_pending=0
docker() {
  env -i HOME="$scratch/home" DOCKER_CONFIG="$scratch/home/docker" PATH=/usr/bin:/bin \
    timeout --kill-after=1s 5s docker "$@"
}
containers() {
  docker container ls -aq --no-trunc --filter "name=^/${1}$" --filter "label=$label"
}
images() {
  docker image ls --no-trunc -q --filter "reference=$tag" --filter "label=$label"
}
finish() {
  local primary=$? failed=0 name object remaining
  trap - EXIT
  trap '' INT TERM
  # Lost create/commit responses may still complete at the daemon. Best-effort
  # exact cleanup below does not turn that uncertainty into an absence claim.
  if ((prep_pending || runtime_pending || commit_pending)); then failed=1; fi
  for name in "$runtime" "$prep"; do
    if ! object=$(containers "$name"); then failed=1; continue; fi
    if [[ -n "$object" ]]; then
      if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then failed=1; continue; fi
      docker rm -f "$object" >/dev/null || failed=1
    fi
    if ! remaining=$(containers "$name"); then failed=1; continue; fi
    [[ -z "$remaining" ]] || failed=1
  done
  if ! object=$(images); then failed=1
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      docker image rm "$object" >/dev/null || failed=1
    else failed=1; fi
  fi
  if ! remaining=$(images); then failed=1
  elif [[ -n "$remaining" ]]; then failed=1; fi
  if [[ -d "$scratch" && ! -L "$scratch" && $(stat -c %d:%i:%u:%a -- "$scratch") == "$identity" ]]; then
    rm -rf --one-file-system -- "$scratch" || failed=1
    [[ ! -e "$scratch" && ! -L "$scratch" ]] || failed=1
  else failed=1; fi
  if ((failed)); then
    echo 'Pinned API owned cleanup unverified' >&2
    if ((primary)); then exit "$primary"; fi
    exit 1
  fi
  echo 'Pinned API exact containers/image/host scratch absent'
  exit "$primary"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$scratch/home" "$scratch/home/docker"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
echo 'Public network preparation (not offline proof)'
env -i HOME="$scratch/home" DOCKER_CONFIG="$scratch/home/docker" PATH=/usr/bin:/bin \
  timeout --kill-after=5s 120s docker pull "$base" >/dev/null
docker image inspect "$base" --format '{{.Id}} {{join .RepoDigests ","}}'
prep_pending=1
prep_id=$(docker create --name "$prep" --label "$label" \
  --memory=2g --memory-swap=2g --cpus=2 --pids-limit=256 \
  --security-opt=no-new-privileges --log-driver=local --log-opt max-size=1m --log-opt max-file=1 \
  --ulimit fsize=268435456:268435456 \
  --mount "type=bind,src=$here,dst=/fixture,readonly" \
  "$base" env -i HOME=/root PATH=/usr/bin:/bin \
  timeout --kill-after=5s 420s bash /fixture/prepare.sh)
[[ "$prep_id" =~ ^[a-f0-9]{64}$ ]]
prep_pending=0
status=0
(ulimit -f 1024; env -i HOME="$scratch/home" DOCKER_CONFIG="$scratch/home/docker" PATH=/usr/bin:/bin \
  timeout --kill-after=5s 440s docker start --attach "$prep_id" > "$scratch/prep.log" 2>&1) || status=$?
cat "$scratch/prep.log"
if ((status)); then exit "$status"; fi
test "$(docker inspect --format '{{.State.ExitCode}}' "$prep_id")" = 0
commit_pending=1
image_id=$(env -i HOME="$scratch/home" DOCKER_CONFIG="$scratch/home/docker" PATH=/usr/bin:/bin \
  timeout --kill-after=5s 60s docker commit --change "LABEL $label" "$prep_id" "$tag")
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
commit_pending=0
runtime_pending=1
runtime_id=$(docker create --name "$runtime" --label "$label" \
  --network=none --read-only --user=1000:1000 --cap-drop=ALL \
  --security-opt=no-new-privileges --memory=6g --memory-swap=6g --cpus=2 --pids-limit=512 \
  --log-driver=local --log-opt max-size=1m --log-opt max-file=1 \
  --ulimit fsize=134217728:134217728 --ulimit nofile=1024:1024 \
  --tmpfs /work:rw,exec,nosuid,nodev,size=8g,uid=1000,gid=1000,mode=700 \
  --mount "type=bind,src=$here,dst=/fixture,readonly" \
  --mount "type=bind,src=$repo/build/provision,dst=/repo/build/provision,readonly" \
  --mount "type=bind,src=$repo/wiringd.yaml,dst=/repo/wiringd.yaml,readonly" \
  "$image_id" env -i PATH=/opt/go/bin:/usr/bin:/bin \
  timeout --kill-after=5s 740s bash /fixture/inside.sh)
[[ "$runtime_id" =~ ^[a-f0-9]{64}$ ]]
runtime_pending=0
echo 'Offline compilation, producer and required Python suite (network none)'
status=0
(ulimit -f 1024; env -i HOME="$scratch/home" DOCKER_CONFIG="$scratch/home/docker" PATH=/usr/bin:/bin \
  timeout --kill-after=5s 760s docker start --attach "$runtime_id" > "$scratch/runtime.log" 2>&1) || status=$?
cat "$scratch/runtime.log"
if ((status)); then exit "$status"; fi
test "$(docker inspect --format '{{.State.ExitCode}}' "$runtime_id")" = 0
