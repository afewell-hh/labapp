#!/usr/bin/env bash
# Test-only Bash host launcher (#452): real pinned kubectl readiness timing proof in a disposable
# Ubuntu 24.04 amd64 container. Usage: bash test-kubectl-readiness.sh /absolute/path/to/kubectl
# The only input is the lead-attested pinned kubectl file (58597560 bytes, SHA256 below); it is
# copied, re-hashed and mounted read-only, never executed on the host. Network only for the
# separate preparation container; the runtime container has network none. No Docker socket, host
# credentials, KVM, privileged or host-network mode. Requires trusted host tools and local daemon.
set -euo pipefail
export PATH=/usr/bin:/bin
umask 077
[[ "$#" -eq 1 && "$1" == /* ]]
source_kubectl=$1
pin_size=58597560
pin_sha=a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IFS= read -r suffix < /proc/sys/kernel/random/uuid
run_label="labapp.kubectl-readiness.run=${suffix}"
image_tag="labapp-kubectl-readiness:${suffix}"
prep="labapp-kubectl-readiness-prep-${suffix}"
runtime="labapp-kubectl-readiness-run-${suffix}"
prep_id=
runtime_id=
image_id=
workdir="$(mktemp -d)"
mkdir "$workdir/home" "$workdir/docker"
printf '{}\n' > "$workdir/docker/config.json"
# Never consult the user's Docker config, context, credential helpers or proxy settings.
# Fixed local daemon; no inherited Docker/HTTP proxy/auth/TLS environment reaches the CLI.
docker() {
  local grace=$1 seconds=$2
  shift 2
  env -i PATH=/usr/bin:/bin HOME="$workdir/home" DOCKER_CONFIG="$workdir/docker" \
    /usr/bin/timeout --kill-after="$grace" "$seconds" /usr/bin/docker \
    --config "$workdir/docker" --host unix:///var/run/docker.sock "$@"
}
owned_container() {
  docker 1s 5s container ls -aq --no-trunc \
    --filter "name=^/${1}$" --filter "label=$run_label"
}
owned_image() {
  docker 1s 5s image ls --no-trunc --quiet \
    --filter "reference=$image_tag" --filter "label=$run_label"
}
cleanup() {
  local failed=0 object remaining container
  # Recover by exact nonce-bearing name/tag AND ownership label even if a create or commit
  # succeeded at the daemon but its response was lost. A failed query never implies absence.
  for container in "$runtime" "$prep"; do
    if ! object="$(owned_container "$container")"; then
      failed=1
      continue
    fi
    [[ -n "$object" ]] || continue
    if [[ ! "$object" =~ ^[a-f0-9]{64}$ ]]; then failed=1; continue; fi
    docker 1s 5s rm -f "$object" >/dev/null || failed=1
    remaining="$(owned_container "$container")" || failed=1
    [[ -z "$remaining" ]] || failed=1
  done
  if ! object="$(owned_image)"; then
    failed=1
  elif [[ -n "$object" ]]; then
    if [[ "$object" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      docker 1s 5s image rm "$object" >/dev/null || failed=1
      remaining="$(owned_image)" || failed=1
      [[ -z "$remaining" ]] || failed=1
    else
      failed=1
    fi
  fi
  if ((failed)); then echo 'kubectl readiness: owned cleanup failed' >&2; fi
  rm -rf -- "$workdir" || failed=1
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
for dependency in timeout python3 sha256sum stat install cut; do command -v "$dependency" >/dev/null; done
[[ -x /usr/bin/docker ]]
[[ -f "$source_kubectl" && ! -L "$source_kubectl" ]]
docker 1s 5s version --format 'Docker server {{.Server.Version}}'

# Stage a private copy first, then verify the COPY (not the original) so there is no check/use gap.
stage="$workdir/stage"
mkdir -p "$stage/suite" "$workdir/client"
install -m 0755 -- "$source_kubectl" "$workdir/client/kubectl"
[[ "$(stat -c %s -- "$workdir/client/kubectl")" == "$pin_size" ]]
[[ "$(sha256sum -- "$workdir/client/kubectl" | cut -d' ' -f1)" == "$pin_sha" ]]
for module in kubectl_readiness_proof.py vlab_core.py owned_process.py; do
  install -m 0644 -- "$here/$module" "$stage/suite/$module"
done

# Preparation (network allowed, bounded, separate from the proof): pinned distro packages plus an
# unpinned-but-recorded openssl; generates SYNTHETIC test certificates and the accepted kubeconfig.
prep_id="$(docker 3s 15s create --name "$prep" --label "$run_label" \
  --memory=512m --cpus=1 --pids-limit=128 --security-opt=no-new-privileges \
  "$base" timeout --kill-after=3s 150s bash -ceu '
    apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 \
      install -y --no-install-recommends python3=3.12.3-0ubuntu2.1 python3.12=3.12.3-1ubuntu0.17 \
      python3-yaml=6.0.1-2build2 libyaml-0-2=0.2.5-1build1 openssl
    rm -rf /var/lib/apt/lists/*
    getent passwd ubuntu
    python3 -B /suite/kubectl_readiness_proof.py prepare
  ')"
[[ "$prep_id" =~ ^[a-f0-9]{64}$ ]]
docker 3s 30s cp "$stage/." "$prep_id:/"
docker 5s 170s start -a "$prep_id"
[[ "$(docker 1s 5s inspect --format '{{.State.ExitCode}}' "$prep_id")" == 0 ]]
image_id="$(docker 3s 30s commit --change "LABEL $run_label" "$prep_id" "$image_tag")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
docker 1s 5s image inspect "$base" --format 'Base {{.Id}} {{json .RepoDigests}}'
docker 1s 5s image inspect "$image_id" --format 'Prepared {{.Id}}'

# Runtime: network none (loopback only), read-only root, kubectl mounted read-only. Root with the
# four capabilities production uid/group drop and process-group kill need (SETUID/SETGID for the
# account switch, KILL for the group signal, DAC_OVERRIDE to read the ubuntu-owned 0600 kubeconfig).
runtime_id="$(docker 3s 15s create --name "$runtime" --label "$run_label" \
  --network=none --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=KILL \
  --cap-add=DAC_OVERRIDE --security-opt=no-new-privileges --read-only --user=0:0 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
  --mount "type=bind,source=$workdir/client/kubectl,target=/usr/local/bin/kubectl,readonly" \
  --memory=1g --cpus=2 --pids-limit=256 --env PYTHONDONTWRITEBYTECODE=1 "$image_id" \
  timeout --kill-after=3s 200s python3 -B /suite/kubectl_readiness_proof.py run)"
[[ "$runtime_id" =~ ^[a-f0-9]{64}$ ]]
run_status=0
docker 5s 215s start -a "$runtime_id" > "$workdir/report.json" || run_status=$?
exit_code="$(docker 1s 5s inspect --format '{{.State.ExitCode}}' "$runtime_id")"
[[ "$(stat -c %s -- "$workdir/report.json")" -le 262144 ]]
# One JSON object line; print only the validated, re-serialized report.
python3 -I -c '
import json, sys
lines = open(sys.argv[1], "rb").read().splitlines()
report = json.loads(lines[-1])
assert isinstance(report, dict) and report.get("harness") == "labapp-kubectl-readiness-v1"
print(json.dumps(report, sort_keys=True))
' "$workdir/report.json"
echo "runtime container exit code: $exit_code (docker start status: $run_status)"
[[ "$exit_code" == 0 && "$run_status" == 0 ]]
