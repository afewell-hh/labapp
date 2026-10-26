#!/usr/bin/env bash
# Fixed trusted-main hosted preparation. Python 3.10+, Docker + pinned Buildx.
# No root privilege in this client; docker-container BuildKit itself is privileged.
# Caller: env -i with only fixed workflow identity/paths; no inputs or TTY.
# GitHub step/job timeouts bound work; always() cleanup is a separate bounded step.
# No VM, no Docker run/load, no arbitrary command/image option. See README.
set -euo pipefail
umask 077
component=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root="$RUNNER_TEMP/labapp-runtime"
builder="labapp-rt-$RUNTIME_RUN"
python3 -I -B "$component/runtime_prepare.py" admit
mkdir -m 0700 "$root/context"
cp -- "$component/runtime/Dockerfile" "$root/context/Dockerfile"
# Admission excludes existing names; create records config before bootstrap.
# No default mutable BuildKit tag, automatic restart or GHA provenance context.
buildkit=$(python3 -I -B - "$component/runtime_prepare.py" <<'PY'
import runpy,sys
print(runpy.run_path(sys.argv[1])['BUILDKIT_IMAGE'])
PY
)
docker --host unix:///var/run/docker.sock --config "$DOCKER_CONFIG" buildx create \
  --name "$builder" --node "${builder}0" --driver docker-container \
  --driver-opt "image=$buildkit" --driver-opt restart-policy=no \
  --driver-opt provenance-add-gha=false unix:///var/run/docker.sock
python3 -I -B "$component/runtime_prepare.py" bind
docker --host unix:///var/run/docker.sock --config "$DOCKER_CONFIG" buildx inspect "$builder" --bootstrap
python3 -I -B "$component/runtime_prepare.py" bind
# Missing FROM/BuildKit images CAN be fetched; digest pins authenticate content.
# Default platform is explicit; this runtime candidate proves no ARM/VM support.
# Force normalization of inherited AND new layers: the data-only reader hashes
# uncompressed tar bytes as DiffIDs. BuildKit otherwise defaults to gzip.
docker --host unix:///var/run/docker.sock --config "$DOCKER_CONFIG" buildx build \
  --builder "$builder" --platform linux/amd64 --no-cache --provenance=false \
  --output "type=docker,dest=$root/out/image.tar,compression=uncompressed,force-compression=true" \
  --iidfile "$root/out/iid.txt" --metadata-file "$root/out/metadata.json" "$root/context"
python3 -I -B "$component/runtime_prepare.py" evidence
