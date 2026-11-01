#!/usr/bin/env bash
# Offline, unprivileged fixture build/producer/tests. Only /work is writable.
# Fixed paths; no caller overrides, no cwd dependence, no installed appliance.
set -euo pipefail
umask 077
test "$(id -u)" = 1000
test "$(cat /opt/fabricator-commit)" = 65254ebab3cb7173598985dfb9f3f358e08769ca
test "$(/opt/go/bin/go version)" = 'go version go1.25.9 linux/amd64'
mkdir -m 700 /work/home /work/tmp /work/cache /work/gopath /work/output
export HOME=/work/home TMPDIR=/work/tmp GOCACHE=/work/cache GOPATH=/work/gopath
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
export GOMAXPROCS=2 GOENV=off GOTELEMETRY=off
ulimit -f 131072
cp -R --no-preserve=ownership /opt/fabricator /work/upstream
chmod u+w /work/upstream /work/upstream/cmd
test ! -e /work/upstream/cmd/labapp-pinned-api
mkdir -m 700 /work/upstream/cmd/labapp-pinned-api
cp /fixture/main.go /work/upstream/cmd/labapp-pinned-api/main.go
cd /work/upstream
echo 'Offline compiler: Go1.25.9, immutable upstream vendor, network disabled'
# Compiler logs are public-only and bounded; a cap/timeout failure fails the job.
status=0
(ulimit -f 1024; timeout --kill-after=5s 600s /opt/go/bin/go build \
  -p 2 -mod=vendor -trimpath -buildvcs=false -o /work/producer ./cmd/labapp-pinned-api \
  > /work/build.log 2>&1) || status=$?
cat /work/build.log
if ((status)); then exit "$status"; fi
timeout --kill-after=5s 30s /work/producer -out /work/output
export LABAPP_PINNED_API_FIXTURE_DIR=/work/output
cd /repo
timeout --kill-after=5s 90s python3 -I -B - <<'PY'
import os
from pathlib import Path
import stat
import sys
import unittest

def audit(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('offline fixture socket operation denied')

sys.addaudithook(audit)
output = Path('/work/output')
if {p.name for p in output.iterdir()} != {'expected.yaml', 'observed.json', 'meta.json'}:
    raise SystemExit('Required fixture output set differs')
total = 0
for path in output.iterdir():
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise SystemExit('Unsafe fixture output')
    total += info.st_size
if not 0 < total <= 1 << 20:
    raise SystemExit('Fixture output size outside bound')
root = '/repo/build/provision'
sys.path.insert(0, root)
suite = unittest.TestLoader().discover(root, pattern='test_pinned_api_fixture.py')
if suite.countTestCases() == 0:
    raise SystemExit('Required pinned API suite discovered no tests')
print(f'Required pinned API tests: {suite.countTestCases()}', flush=True)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful() or result.skipped:
    raise SystemExit(1)
PY
