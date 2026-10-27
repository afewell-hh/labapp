#!/usr/bin/env bash
# Test-only Bash host launcher: ONE fresh Ubuntu 24.04 amd64 container runs the
# unchanged install-docker.py twice (install, then rerun) in the SAME target.
# Needs docker, timeout, cp-style coreutils; no arguments, overrides or cwd
# dependency. Separately scoped lead execution only: it acquires the pinned base
# image, Ubuntu fixture packages, the Docker key/indexes and packages.
# No privileged mode, host socket/network/devices or forwarded credentials; the
# docker client uses an empty private config. No retry, widening or repair.
set -euo pipefail
[[ "$#" -eq 0 ]]
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
total=600
SECONDS=0
work_timeout() {
  local cap=$1 remaining=$((total - SECONDS - 1))
  shift
  ((remaining > 0)) || return 124
  ((cap <= remaining)) || cap=$remaining
  timeout --kill-after=1s "${cap}s" "$@"
}
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.docker-test.run=${suffix}"
target="labapp-docker-target-${suffix}"
target_id=
echo "docker test: ownership name=${target} label=${run_label}"
start_pid=
workdir="$(mktemp -d)"
# Printable, bounded Bash quoting for the fixed public diagnostic fields only.
# Truncation is for display; comparisons below always use the complete strings.
display() {
  local LC_ALL=C value=$1 truncated=false
  ((${#value} <= 128)) || truncated=true
  printf '%q truncated=%s' "${value:0:128}" "$truncated"
}
diagnose() {
  local group=$1 status=$2 actual=$3 requested=$4 i match
  local -a fields observed expected
  if [[ "$group" == applied ]]; then
    fields=(privileged memory nano_cpus pids binds)
  else
    fields=(swap network security cap_drop devices)
  fi
  mapfile -t expected <<<"$requested"
  observed=()
  [[ -z "$actual" ]] || mapfile -t observed <<<"$actual"
  echo "docker test: ${group} inspect_status=${status} fields=${#observed[@]} expected_fields=5"
  for i in "${!fields[@]}"; do
    printf 'docker test: %s field=%s requested=' "$group" "${fields[i]}"
    display "${expected[i]}"
    if ((status != 0)); then
      printf ' observed=<inspect-unavailable> match=false\n'
    elif ((i >= ${#observed[@]})); then
      printf ' observed=<missing> match=false\n'
    else
      [[ "${observed[i]}" == "${expected[i]}" ]] && match=true || match=false
      printf ' observed='
      display "${observed[i]}"
      printf ' match=%s\n' "$match"
    fi
  done
  if ((${#observed[@]} > 5)); then
    echo "docker test: ${group} extra_fields=$((${#observed[@]} - 5)) values=omitted"
  fi
}
owned_container() {
  timeout --kill-after=1s 5s docker container ls -aq --no-trunc \
    --filter "name=^/${target}$" --filter "label=$run_label"
}
cleanup() {
  local failed=0 object remaining
  # The supervising client is only a local process; stop it after the target.
  # Recover by exact nonce-bearing name AND ownership label even if create
  # succeeded at the daemon but its response was lost. Never infer absence from
  # a failed query; never remove by a name prefix or label alone. Removing the
  # container also ends every process, anonymous volume and temp file inside it.
  if ! object="$(owned_container)"; then
    failed=1
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^[a-f0-9]{64}$ ]]; then
      if [[ -n "$target_id" && "$object" != "$target_id" ]]; then
        echo 'docker test: owned identity differs from created immutable ID' >&2
        failed=1
      else
        echo "docker test: cleanup owned name=${target} id=${object} recovered=$([[ -z "$target_id" ]] && echo true || echo false)"
        target_id=$object
        timeout --kill-after=1s 20s docker rm -fv "$object" >/dev/null || failed=1
        remaining="$(owned_container)" || failed=1
        [[ -z "$remaining" ]] || failed=1
      fi
    else
      failed=1
    fi
  fi
  if [[ -n "$target_id" ]]; then
    remaining="$(timeout --kill-after=1s 5s docker container ls -aq --no-trunc --filter "id=$target_id")" || failed=1
    [[ -z "$remaining" ]] || failed=1
  fi
  if ((failed == 0)); then
    echo "docker test: cleanup checked exact owned absence name=${target} id=${target_id:-not-observed} label=${run_label}"
  fi
  if [[ -n "$start_pid" ]]; then
    kill "$start_pid" 2>/dev/null || true
    for _ in {1..20}; do
      kill -0 "$start_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$start_pid" 2>/dev/null || true
    wait "$start_pid" 2>/dev/null || true
  fi
  if ((failed)); then echo 'docker test: owned cleanup failed' >&2; fi
  local host_failed=0 file path
  # Never follow replaced directories or unlink unknown children/types. rmdir
  # preserves unexpected entries, including dangling links, for inspection.
  if [[ -d "$workdir" && ! -L "$workdir" ]]; then
    if [[ -d "$workdir/suite" && ! -L "$workdir/suite" ]]; then
      for file in install-docker.py hhfab_release.py docker_container.py; do
        path="$workdir/suite/$file"
        if [[ -f "$path" && ! -L "$path" ]]; then rm -f -- "$path" || host_failed=1
        elif [[ -e "$path" || -L "$path" ]]; then host_failed=1; fi
      done
      rmdir -- "$workdir/suite" 2>/dev/null || host_failed=1
    elif [[ -e "$workdir/suite" || -L "$workdir/suite" ]]; then host_failed=1; fi
    if [[ -f "$workdir/out" && ! -L "$workdir/out" ]]; then rm -f -- "$workdir/out" || host_failed=1
    elif [[ -e "$workdir/out" || -L "$workdir/out" ]]; then host_failed=1; fi
    for path in "$workdir/docker-config" "$workdir"; do
      if [[ -d "$path" && ! -L "$path" ]]; then rmdir -- "$path" 2>/dev/null || host_failed=1
      elif [[ -e "$path" || -L "$path" ]]; then host_failed=1; fi
    done
  fi
  if [[ -e "$workdir" || -L "$workdir" ]]; then host_failed=1; fi
  printf 'docker test: host temp cleanup '
  if ((host_failed)); then
    printf 'failed preserved workdir='; display "$workdir"; printf '\n'
    failed=1
  else
    printf 'checked exact owned absence workdir='; display "$workdir"; printf '\n'
  fi
  return "$failed"
}
finish() {
  local result=$?
  trap - EXIT
  # Bounded sanitized diagnostics from the guest; guest output is public data.
  if [[ -d "$workdir" && ! -L "$workdir" && -f "$workdir/out" && ! -L "$workdir/out" ]]; then tail -c 65536 "$workdir/out" || true; fi
  # A cleanup failure is reported but never replaces a primary failure code.
  cleanup || { [[ "$result" -ne 0 ]] || result=1; }
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for dependency in docker timeout tail; do command -v "$dependency" >/dev/null; done
chmod 755 "$workdir"
mkdir -m 700 "$workdir/docker-config"
export DOCKER_CONFIG="$workdir/docker-config"
work_timeout 5 docker version --format 'Docker server {{.Server.Version}}'
# Only the public installer, its sibling and the driver are exposed, read-only.
mkdir -m 755 "$workdir/suite"
for file in install-docker.py hhfab_release.py docker_container.py; do
  install -m 644 -- "$here/$file" "$workdir/suite/$file"
done
# Guest: record then apply fixture preparation (pins as in test-qemu.sh; curl and its
# libraries are resolved by APT and recorded), then the Python driver. Remaining budget
# is handed to the driver, which refuses a run it cannot bound.
read -r -d '' guest <<'GUEST' || true
SECONDS=0
prepare() {
  # errexit is inactive inside an if-tested function, so every step reports explicitly.
  apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update || return 1
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
    install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17 \
    ca-certificates=20240203 curl || return 1
  rm -rf /var/lib/apt/lists/* || return 1
}
if ! prepare >/tmp/prepare.log 2>&1; then
  echo 'docker test: fixture preparation failed (not installer evidence)' >&2
  tail -c 4096 /tmp/prepare.log >&2
  exit 3
fi
exec python3 /suite/docker_container.py run --base "$LABAPP_BASE_REF" --budget "$((565 - SECONDS))"
GUEST
target_id="$(work_timeout 90 docker create --platform=linux/amd64 --init --name "$target" --label "$run_label" \
  --memory=1g --memory-swap=1g --cpus=2 --pids-limit=128 --security-opt=no-new-privileges \
  --network=bridge --cap-drop=CAP_NET_RAW -v "$workdir/suite:/suite:ro" \
  --env PYTHONDONTWRITEBYTECODE=1 --env "LABAPP_BASE_REF=$base" \
  "$base" timeout --kill-after=5s 570s bash -ceu "$guest")"
[[ "$target_id" =~ ^[a-f0-9]{64}$ ]]
echo "docker test: created name=${target} id=${target_id} label=${run_label}"
work_timeout 5 docker image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
applied_status=0 isolation_status=0
applied="$(work_timeout 5 docker inspect --format \
  '{{.HostConfig.Privileged}}
{{.HostConfig.Memory}}
{{.HostConfig.NanoCpus}}
{{.HostConfig.PidsLimit}}
{{json .HostConfig.Binds}}' "$target_id")" || applied_status=$?
printf -v expected 'false\n1073741824\n2000000000\n128\n["%s/suite:/suite:ro"]' "$workdir"
isolation="$(work_timeout 5 docker inspect --format \
  '{{.HostConfig.MemorySwap}}
{{.HostConfig.NetworkMode}}
{{json .HostConfig.SecurityOpt}}
{{json .HostConfig.CapDrop}}
{{json .HostConfig.Devices}}' "$target_id")" || isolation_status=$?
expected_isolation=$'1073741824\nbridge\n["no-new-privileges"]\n["CAP_NET_RAW"]\n[]'
diagnose applied "$applied_status" "$applied" "$expected"
diagnose isolation "$isolation_status" "$isolation" "$expected_isolation"
((applied_status == 0)) || exit "$applied_status"
((isolation_status == 0)) || exit "$isolation_status"
[[ "$isolation" == "$expected_isolation" ]] || {
  echo 'docker test: applied containment differs from request' >&2; exit 1;
}
[[ "$applied" == "$expected" ]] || { echo 'docker test: applied containment differs from request' >&2; exit 1; }
echo "docker test: applied id=${target_id}"
remaining=$((total - SECONDS - 5))
if ((remaining < 60)); then echo 'docker test: insufficient total budget remains' >&2; exit 1; fi
timeout --kill-after=1s "${remaining}s" docker start -a "$target_id" >"$workdir/out" 2>&1 &
start_pid=$!
status=0
wait "$start_pid" || status=$?
start_pid=
if ((status == 124 || status == 137)); then
  echo 'docker test: supervisor timeout; not native APT evidence' >&2
fi
# Preserve attach failure even if later daemon observation would also fail.
((status == 0)) || exit "$status"
exit_code="$(work_timeout 5 docker inspect --format '{{.State.ExitCode}}' "$target_id")"
oom="$(work_timeout 5 docker inspect --format '{{.State.OOMKilled}}' "$target_id")"
failed=0
[[ "$exit_code" == 0 && "$oom" == false ]] || { echo "docker test: guest exit=${exit_code} oom=${oom}" >&2; failed=1; }
((status == 0)) || failed=1
echo "docker test: elapsed ${SECONDS}s of ${total}s"
((failed == 0)) || exit "$((status ? status : 1))"
