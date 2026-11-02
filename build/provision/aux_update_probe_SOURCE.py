raise SystemExit('SOURCE ONLY')
"""#472 extraction artifact, NOT an entrypoint or VM/containment evidence.

Root must independently review before extracting all lines AFTER the first line.
Run that exact reviewed derivative as /driver.py using trusted CPython3.12.16
(-I -S, binary SHA23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5)
and trusted stdlib RO mounts; verify loader/library compatibility BEFORE imports.
Mount trusted system CA RO at /etc/ssl/certs/ca-certificates.crt (base lacks CA).
Bind public accepted source RO /repo and public Root-authored /bindings.json RO:
source_sha = BASE below, driver_sha256 = extracted derivative SHA256, files =
{relative build/**/*.py path: SHA256}, complete for BASE production source only.
The inert artifact is absent from /repo; /driver.py is separately derivative-hash-bound.
Root externally binds actual Git head/tree, original blob, derivative, manifest,
TCB and mount paths; these checks do NOT approve their own supplied hashes.

SAME driver in two fresh containers: Root-selected online metadata-only envelope,
then --network none. No mode flag changes code/argv. Ubuntu amd64 digest
68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
(inspected image6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36).
Root0, --cap-drop ALL plus CHOWN,DAC_OVERRIDE,FOWNER,SETUID,SETGID;
no-new-privileges; root/source RO, 1GiB/2CPU/128PID; total writable
application scratch tmpfs budget320MiB across /out,/state,/tmp,/var/tmp, fresh empty each.
Default namespaced /dev/shm is separately bounded and charged to the 1GiB cgroup.
/var/tmp MUST be traversable0755 for _apt42:65534; private dirs below0700.
No host private inputs/config, credentials, socket, host networking, proxy,
package bootstrap, guardian/full CLI, workflows or VM. Launch env cleared.
Root verifies original signed-source/CA/redirect controls; no policy overrides.
No hard request-count/wire-byte claim. Container outer cap300s, finite stop/remove
and independent exact owned-ID/nonce absence confirmation remain Root duties.
Only after stopped: Docker cp /out/summary.json
and /out/retained/installer-failure-00000000-0000-0000-0000-000000000472.bin
(if any) to fresh owner-private0600 storage. Never publish raw files/errors.
UID0 inside outputs is legitimate; do not require host-user ownership inside.
Synthetic contract/result/boot below exercise real validators, NOT VM provenance.
No apt check/simulation/download/install. A native baseline failure stays failure.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

BASE = 'd81b0104d4d27d8da6d7837e6e4c7a9c57224ffe'
REPO, OUT, STATE = Path('/repo'), Path('/out'), Path('/state')


def need(condition):
    if not condition:
        raise RuntimeError('probe refused')


def main():
    os.umask(0o077)
    sys.dont_write_bytecode = True
    need(sys.version_info[:3] == (3, 12, 16) and os.geteuid() == 0)
    need(len(sys.argv) == 1)
    raw = Path('/bindings.json').read_bytes()
    need(len(raw) <= 262144)
    binding = json.loads(raw)
    files = {str(p.relative_to(REPO)): p for p in (REPO / 'build').rglob('*.py')}
    need(set(binding) == {'source_sha', 'driver_sha256', 'files'})
    need(binding['source_sha'] == BASE and set(binding['files']) == set(files))
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == binding['driver_sha256'])
    for name, path in files.items():
        need(not path.is_symlink() and path.is_file())
        need(hashlib.sha256(path.read_bytes()).hexdigest() == binding['files'][name])
    for directory in (OUT, STATE):
        need(not directory.is_symlink() and directory.is_dir() and not any(directory.iterdir()))
        directory.chmod(0o700)
    sys.path[:0] = [str(REPO), str(REPO / 'build/provision')]
    from build.provision import vlab_trial as g
    from build.gcp import vlab_trial as h
    need(h.guest is g)
    # Local-only schema placeholders; never supplied to admission/cloud/guardian.
    boot = '00000000-0000-0000-0000-000000000472'
    lease = boot
    now = time.time()
    stamp = lambda t: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))
    value = g.contract(dict(schema=1, nonce=os.urandom(16).hex(), lease=lease,
                           epoch=1, run_id=1, attempt=1, body_sha256='0' * 64,
                           vm_id='1', boot_id='1', image_id='4575951068918267275',
                           admitted_at=stamp(now), deadline=stamp(int(now) + 7200),
                           boot_uuid=boot, source_sha=BASE))
    work_end, cleanup_end = time.monotonic() + 240, time.monotonic() + 270

    class LocalClock(g.Clock):
        def remaining(self, phase):
            left = min(super().remaining(phase), work_end - time.monotonic())
            g.require(left > 0, category='phase-cutoff')
            return left

        def cleanup_remaining(self):
            left = min(super().cleanup_remaining(), cleanup_end - time.monotonic())
            g.require(left > 0, category='phase-cutoff')
            return left

    clock = LocalClock(value)
    g.ROOT = STATE / 'synthetic-guest'
    g.ROOT.mkdir(mode=0o700)
    g.kernel_boot = lambda: boot  # explicit synthetic local binding, never host boot
    g.exclusive(g.ROOT / 'contract.json', g.encoded(value))
    retained = OUT / 'retained'
    retained.mkdir(mode=0o700)
    apt_tree = g.APT_TMP / ('labapp-vlab-aux-' + str(os.getpid()))
    need(not apt_tree.exists() and not apt_tree.is_symlink())
    real_mark, real_call, real_failure = g.mark, g.call_bounded, g.child_failure
    seen, update, built, failed = [], [], [], []

    class StopBeforeCheck(BaseException):
        pass

    stop = StopBeforeCheck()

    def mark(phase, operation):
        if operation == 'aux-check':
            need(update and update[0][0] == 0)
            raise stop  # BEFORE real checkpoint, check or any later work
        need(operation in ('aux-inventory', 'aux-audit', 'aux-holds', 'aux-setup', 'aux-update'))
        seen.append(operation)
        real_mark(phase, operation)

    def call(args, seconds, env=g.ENV):
        result = real_call(args, seconds, env)
        if result[0]:
            failed.append(result)
        if seen[-1] == 'aux-update':
            need(args[0] == '/usr/bin/apt-get' and args[-1] == 'update' and not update)
            update.append(result)  # actual tuple ONLY, never a manufactured exit100
        return result

    def failure(code, message):
        error = real_failure(code, message)
        built.append(error)
        return error

    def no_core(name):
        raise RuntimeError('no core in local fixture')

    g.mark, g.call_bounded, g.child_failure, g.load_sibling = mark, call, failure, no_core
    primary = None
    try:
        g.provision_aux(clock, value)
    except BaseException as error:
        primary = error  # retain SAME object through all diagnostic work
    clean = not apt_tree.exists() and not apt_tree.is_symlink()
    uncertain = bool(getattr(primary, 'cleanup_uncertain', False)) or not clean
    stopped = (primary is stop and not uncertain and len(update) == 1 and update[0][0] == 0
               and seen == ['aux-inventory', 'aux-audit', 'aux-holds', 'aux-setup', 'aux-update'])
    code, category, status = (0, 'none', None) if stopped else g.failure_fields(primary, 'worker')
    diagnostic_state = 'not-attempted'
    try:
        if isinstance(primary, g.Failure) and update and update[0][0] != 0:
            need(built and primary is built[-1])
            detail = g.diagnostic(dict(origin='worker', phase='stage', operation='aux-update',
                                       category=category, child_status=status))
            # Synthetic terminal explicitly makes NO containment claim.
            terminal = g.result_record(dict(schema=2, code=code, contained=False,
                                            nonce=value['nonce'], diagnostic=detail), value['nonce'])
            g.exclusive(g.ROOT / 'result.json', g.encoded(terminal))
            expected = dict(lease=lease, admitted_at=value['admitted_at'], detail=detail)
            calls = []

            class LocalTransport:
                # Fake transport ONLY; writer/export/accept/extract/retention are real.
                def remote(self, argv, phase, cap, cleanup, until, limit):
                    need(not calls and argv == h.export_command(value['nonce']))
                    need(phase == 'persistence' and cleanup and cap == h.EXPORT_CAP_SECONDS)
                    need(time.monotonic() < until and limit == h.EXPORT_READ_LIMIT)
                    calls.append(True)
                    return g.export_failure(value['nonce'])

            event = threading.Event()
            diagnostic_state = h.extract_failure(
                LocalTransport(), clock, value['nonce'], {'source_sha': BASE}, boot,
                retained, lease, event, 'installer', expected)
            uncertain = uncertain or event.is_set()
    except BaseException:
        diagnostic_state = 'unavailable'  # never replace native primary/status
    summary = dict(schema=1, fixture='synthetic-local-not-vm', code=code,
                   category=category, child_status=status, stopped_before_check=stopped,
                   update_status=update[0][0] if update else None,
                   apt_workspace_absent=clean, cleanup_uncertain=uncertain,
                   private_diagnostic=diagnostic_state)
    try:
        g.exclusive(OUT / 'summary.json', g.encoded(summary))
    except BaseException:
        if code == 0:
            return 1
    return code  # exit100 remains100 in BOTH Root network envelopes


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        result = 1  # no traceback, exception message, paths or raw bytes on stdout
    raise SystemExit(result)
