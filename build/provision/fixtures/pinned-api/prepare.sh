#!/usr/bin/env bash
# Fixed public preparation only, invoked inside the disposable root container.
# No project code/toolchain is executed here; compiler execution is offline.
set -euo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive
timeout --kill-after=5s 180s bash -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl git python3 python3-yaml'
mkdir /opt/fabricator
timeout --kill-after=5s 180s git -C /opt/fabricator \
  -c credential.helper= -c core.hooksPath=/dev/null init -q
timeout --kill-after=5s 180s git -C /opt/fabricator \
  -c credential.helper= -c core.hooksPath=/dev/null fetch --depth=1 \
  https://github.com/githedgehog/fabricator.git 65254ebab3cb7173598985dfb9f3f358e08769ca
git -C /opt/fabricator -c core.hooksPath=/dev/null checkout --detach FETCH_HEAD
test "$(git -C /opt/fabricator rev-parse HEAD)" = 65254ebab3cb7173598985dfb9f3f358e08769ca
test "$(du -sk /opt/fabricator | cut -f1)" -le 1048576
grep -Eq '^[[:space:]]+go.githedgehog.com/fabric v0.96.2$' /opt/fabricator/go.mod
grep -Fx '# go.githedgehog.com/fabric v0.96.2' /opt/fabricator/vendor/modules.txt
# Vendor metadata records the version, not fabric's peeled commit. The known
# v0.96.2 commit is 8b0aefa0937a95e51cc04ec3ea33fadb06782a99; do not claim
# modules.txt independently records that commit. Vendored bytes are pinned by
# the immutable fabricator git tree above.
timeout --kill-after=5s 180s curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 170 \
  --max-filesize 100000000 -o /tmp/go.tar.gz \
  https://go.dev/dl/go1.25.9.linux-amd64.tar.gz
printf '%s  %s\n' 00859d7bd6defe8bf84d9db9e57b9a4467b2887c18cd93ae7460e713db774bc1 /tmp/go.tar.gz | sha256sum -c -
tar -xzf /tmp/go.tar.gz -C /opt
rm -- /tmp/go.tar.gz
printf '%s\n' 65254ebab3cb7173598985dfb9f3f358e08769ca > /opt/fabricator-commit
chmod -R a-w /opt/fabricator /opt/go
dpkg-query -W python3 python3-yaml ca-certificates git curl
