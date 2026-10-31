"""SOURCE-ONLY disposable local fixture for ``owned_process.OwnedGroup`` (issue #365).

NOT executed by CI, unittest discovery (name has no ``test_`` prefix) or this
change. Running it needs separate lead scope after an independent assessor
inspects this source. It is credential-free: no cloud, GitHub, SSH, gcloud,
network, or private input. It only starts fixed trusted Python children from
this file, in fresh sessions, with an empty private HOME/TMPDIR and bounded
time/FD/file-size limits, and writes exactly one ``result.json`` artifact.

Proposed native command (lead executes only after review; D is a new empty
mode-0700 directory owned by the caller)::

    env -i PATH=/usr/bin:/bin HOME="$D" TMPDIR="$D" \\
        timeout --kill-after=5 120 python3 -I -B build/gcp/process_group_fixture.py --output "$D/out"

Production code under test is ``OwnedGroup.close`` itself (the primitive shared
by ``Master.close`` and ``command()``): signal-before-reap order, bounded TERM
grace then KILL while the leader is an unreaped zombie, positive group ESRCH
after the single reap. Mocks cannot show kernel group lifetime; this does.
It does NOT exercise ``command()`` I/O, OpenSSH, gcloud/IAP or escaped sessions.

FIXTURE-ONLY ADAPTER (needs its own source/authority review): the harness sets
``PR_SET_CHILD_SUBREAPER`` through ctypes so orphaned fixture children
reparent to it, not to this host's PID 1. A harness thread reaps ONLY those
positively registered child PIDs with ``waitpid(pid, WNOHANG)``. It never calls
``wait(-1)`` and never waits on a production leader, which remains the
exclusive, unreaped child of ``OwnedGroup`` until its single ``Popen.wait``.
Any native timeout, unexpected state or assertion is FAIL, never a skip.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from build.gcp import owned_process  # noqa: E402  (the unchanged production module)

PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER = 36, 37
WALL_SECONDS = 90
LEADER = r'''
import os, signal, sys, time
mode = sys.argv[1]
if mode == "leader-only":
    os.write(1, b"READY 0\n")
    while True:
        signal.pause()
if os.fork() == 0:
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    else:
        def slow_term(*_):
            time.sleep(1.0)
            os._exit(0)
        signal.signal(signal.SIGTERM, slow_term)
    os.write(1, b"READY %d\n" % os.getpid())
    while True:
        signal.pause()
os._exit(0)  # leader exits FIRST; the child stays alive in the original group
'''
SENTINEL = "import signal\nwhile True:\n    signal.pause()\n"
# (name, child mode, TERM grace, final budget): the first three use Master.close policy,
# the last uses command()'s immediate-KILL policy.
CASES = (
    ('leader-first-exit-delayed-term-child', 'delayed-term', owned_process.TERM_GRACE_SECONDS, owned_process.CLEANUP_SECONDS),
    ('term-ignoring-child-needs-kill', 'ignore-term', owned_process.TERM_GRACE_SECONDS, owned_process.CLEANUP_SECONDS),
    ('ordinary-leader-only', 'leader-only', owned_process.TERM_GRACE_SECONDS, owned_process.CLEANUP_SECONDS),
    ('command-policy-immediate-kill', 'ignore-term', 0, owned_process.CLEANUP_SECONDS),
)


def become_subreaper():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'subreaper unavailable')
    value = ctypes.c_int(0)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(value), 0, 0, 0) != 0 or value.value != 1:
        raise OSError('subreaper not confirmed')


class Reaper(threading.Thread):
    """Reaps only registered orphan PIDs; never wait(-1), never a production leader."""
    def __init__(self):
        super().__init__(daemon=True)
        self.pids, self.reaped, self.stop = set(), [], threading.Event()
        self.lock = threading.Lock()

    def register(self, pid):
        with self.lock:
            self.pids.add(pid)

    def run(self):
        while not self.stop.is_set():
            with self.lock:
                pending = sorted(self.pids - set(self.reaped))
            for pid in pending:
                try:
                    done, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    done = pid
                if done == pid:
                    with self.lock:
                        self.reaped.append(pid)
            self.stop.wait(.02)


def ready(pipe, limit=5.0):
    end, raw = time.monotonic() + limit, b''
    while b'\n' not in raw:
        left = end - time.monotonic()
        if left <= 0 or not select.select([pipe], [], [], left)[0]:
            raise AssertionError('fixture readiness timeout')
        chunk = os.read(pipe.fileno(), 64)
        if not chunk:
            raise AssertionError('fixture readiness closed early')
        raw += chunk
    fields = raw.split()
    if len(fields) != 2 or fields[0] != b'READY' or not fields[1].isdigit():
        raise AssertionError('fixture readiness malformed')
    return int(fields[1])


def alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def run_case(name, mode, term, final, env, home, reaper, sentinel):
    started = time.monotonic()
    leader = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', LEADER, mode], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                              env=env, cwd=home, close_fds=True)
    group = owned_process.OwnedGroup(leader)
    try:
        child = ready(leader.stdout)
        if child:
            reaper.register(child)
            end = time.monotonic() + 5
            while group.status() is None:  # non-reaping leader-first-exit observation
                assert time.monotonic() < end, 'leader did not exit'
                time.sleep(.01)
        assert alive(group.pgid), 'group must be live before closure'
        closed = group.close(term, final)
        assert closed is True, 'production closure must report positive absence'
        assert leader.returncode is not None, 'leader must be reaped by the primitive'
        assert not alive(group.pgid), 'original group must be positively ESRCH'
        if child:
            end = time.monotonic() + 3
            while child not in reaper.reaped and time.monotonic() < end:
                time.sleep(.01)
            assert child in reaper.reaped, 'registered orphan child not reaped'
        assert sentinel.poll() is None and alive(sentinel.pid), 'unrelated sentinel changed'
        return {'case': name, 'ok': True, 'seconds': round(time.monotonic() - started, 3), 'child_reaped': bool(child)}
    finally:
        leader.stdout.close()
        if group.outcome is None:
            group.close(0, owned_process.CLEANUP_SECONDS)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux'):
        raise SystemExit('Linux fixture only')
    home = args.output
    home.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError('fixture wall limit')))
    signal.alarm(WALL_SECONDS)
    become_subreaper()
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'HOME': str(home), 'TMPDIR': str(home)}
    reaper = Reaper()
    reaper.start()
    sentinel = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', SENTINEL], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                                env=env, cwd=home, close_fds=True)
    results, failure = [], None
    try:
        for name, mode, term, final in CASES:
            results.append(run_case(name, mode, term, final, env, home, reaper, sentinel))
    except BaseException as error:  # any failure/timeout is FAIL, never a skip
        failure = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            owned_process.OwnedGroup(sentinel).close(1.0, owned_process.CLEANUP_SECONDS)
        except BaseException as error:
            failure = failure or 'sentinel cleanup: ' + type(error).__name__
        reaper.stop.set()
        reaper.join(2)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (Path(__file__).resolve(), Path(owned_process.__file__).resolve())}
    document = {'schema': 1, 'python': sys.version.split()[0], 'sources': hashes, 'cases': results,
                'failure': failure, 'passed': failure is None and len(results) == len(CASES)}
    fd = os.open(home / 'result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(document, handle, sort_keys=True)
    print(json.dumps(document, sort_keys=True))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
