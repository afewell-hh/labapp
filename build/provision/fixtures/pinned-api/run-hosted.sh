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
# Diagnostics only: fixed stage/outcome words and a numeric status. Arguments are
# literals or exit codes; Docker output, names, IDs and environment are never printed.
diag() { printf 'Pinned API cleanup stage=%s status=%s outcome=%s\n' "$1" "$2" "$3" >&2 || :; }
# Observed status only: Docker can itself return 124/137; 137 is also an
# ambiguous kill. These statuses do not establish timeout provenance.
failure_outcome() { case $1 in 124|137) echo timeout-status ;; *) echo command-failed ;; esac; }
# $1 value, $2 anchored ID regex: value is non-empty; a second line means multiple IDs.
id_outcome() {
  if [[ "$1" =~ $2 ]]; then echo valid
  elif [[ "$1" == *$'\n'* ]]; then echo multiple-ids
  else echo malformed-id; fi
}
finish() {
  local primary=$? failed=0 name object remaining rc stage now
  trap - EXIT
  trap '' INT TERM
  diag primary "$primary" recorded
  # Lost create/commit responses may still complete at the daemon. Best-effort
  # exact cleanup below does not turn that uncertainty into an absence claim.
  if ((prep_pending || runtime_pending || commit_pending)); then
    failed=1; diag create-commit-uncertain 0 outstanding
  fi
  for name in "$runtime" "$prep"; do
    case $name in "$runtime") stage=runtime-container ;; *) stage=prep-container ;; esac
    rc=0; object=$(containers "$name") || rc=$?
    if ((rc)); then failed=1; diag "$stage-select" "$rc" "$(failure_outcome "$rc")"; continue; fi
    if [[ -n "$object" ]]; then
      if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then
        failed=1; diag "$stage-select" 0 "$(id_outcome "$object" '^[a-f0-9]{64}$')"; continue
      fi
      rc=0; docker rm -f "$object" >/dev/null || rc=$?
      if ((rc)); then failed=1; diag "$stage-remove" "$rc" "$(failure_outcome "$rc")"
      else diag "$stage-remove" 0 command-ok; fi
    else diag "$stage-select" 0 none-found; fi
    rc=0; remaining=$(containers "$name") || rc=$?
    if ((rc)); then failed=1; diag "$stage-verify" "$rc" "$(failure_outcome "$rc")"; continue; fi
    if [[ -z "$remaining" ]]; then diag "$stage-verify" 0 absent
    else failed=1; diag "$stage-verify" 0 still-present; fi
  done
  rc=0; object=$(images) || rc=$?
  if ((rc)); then failed=1; diag image-select "$rc" "$(failure_outcome "$rc")"
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      rc=0; docker image rm "$object" >/dev/null || rc=$?
      if ((rc)); then failed=1; diag image-remove "$rc" "$(failure_outcome "$rc")"
      else diag image-remove 0 command-ok; fi
    else failed=1; diag image-select 0 "$(id_outcome "$object" '^sha256:[a-f0-9]{64}$')"; fi
  else diag image-select 0 none-found; fi
  rc=0; remaining=$(images) || rc=$?
  if ((rc)); then failed=1; diag image-verify "$rc" "$(failure_outcome "$rc")"
  elif [[ -n "$remaining" ]]; then failed=1; diag image-verify 0 still-present
  else diag image-verify 0 absent; fi
  if [[ -d "$scratch" && ! -L "$scratch" ]]; then
    rc=0; now=$(stat -c %d:%i:%u:%a -- "$scratch") || rc=$?
    if ((rc)); then failed=1; diag scratch-identity "$rc" stat-failed
    elif [[ "$now" != "$identity" ]]; then failed=1; diag scratch-identity 0 identity-mismatch
    else
      diag scratch-identity 0 match
      rc=0; rm -rf --one-file-system -- "$scratch" || rc=$?
      if ((rc)); then failed=1; diag scratch-remove "$rc" command-failed
      else diag scratch-remove 0 command-ok; fi
      if [[ ! -e "$scratch" && ! -L "$scratch" ]]; then diag scratch-verify 0 absent
      else failed=1; diag scratch-verify 0 still-present; fi
    fi
  else failed=1; diag scratch-identity 0 not-owned-directory; fi
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
docker image inspect "$base" --format '{{.Id}} {{json .RepoDigests}}'
prep_pending=1
prep_id=$(docker create --name "$prep" --label "$label" \
  --memory=2g --memory-swap=2g --cpus=2 --pids-limit=256 \
  --security-opt=no-new-privileges --log-driver=local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false \
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
  --log-driver=local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false \
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
