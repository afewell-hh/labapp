"""SOURCE-ONLY kernel fixture; never discovered by CI or authorized by this file.

Requires separately reviewed root-owned OS containment of ALL descendants,
including new sessions, with immutable deadline and independent empty-cgroup
evidence afterwards. A shell timeout cannot provide that boundary. The required
--outer-boundary records the caller's identity claim, NOT qualification. External
disposal cannot convert incomplete own cleanup into PASS.

Trusted launcher pins absolute CPython 3.12.16/runtime dependencies, uses -I -S -B,
env-i, unusable PATH, umask077, empty private HOME/TMP/output, and installs its
reviewed authority guard BEFORE source import. Read authority: frozen source,
pinned runtime and /dev/null only. No network/credentials/cloud/site packages,
host process search or arbitrary numeric-PID fallback. Fresh exec children rely
on the hashed fixed code below, not inherited audit hooks. killpg instrumentation
here is NOT a syscall audit or sandbox. Fixture-only ctypes authority is exactly
libc prctl SET/GET_CHILD_SUBREAPER; adapter/wrapper need separate authority review.

Exercises actual OwnedGroup closure policy, not command I/O, SSH/IAP, native PID
reuse or escaped-session qualification. Normal SIGCHLD and sole leader-reaper
semantics are trusted-launch preconditions. Missing/false/late cleanup is FAIL,
including partial setup. Failed close is never retried against an unanchored PID.
Root freezes and reviews the exact wrapper before any separately scoped run.
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

SOURCE = Path(__file__).resolve()
HELPER = SOURCE.with_name('owned_process.py')


def identities(runtime):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (SOURCE, HELPER, runtime)}


# Capture before production import; launcher must already enforce its read guard.
IMPORT_IDENTITIES = identities(Path(sys.executable).resolve())
sys.path.insert(0, str(SOURCE.parents[2]))
from build.gcp import owned_process  # noqa: E402

WALL_SECONDS, CLEANUP_RESERVE = 90, 15
LEADER = r'''
import os, signal, sys, time
mode = sys.argv[1]
if mode == "leader-only":
    os.write(1, b"REGISTER 0\n")
    if os.read(0, 1) != b"A": os._exit(2)
    os.write(1, b"READY 0\n")
    while True: signal.pause()
gate_r, gate_w = os.pipe()
ready_r, ready_w = os.pipe()
child = os.fork()
if child == 0:
    os.close(gate_w); os.close(ready_r)
    if os.read(gate_r, 1) != b"A": os._exit(2)
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    else:
        def slow_term(*_):
            time.sleep(1.0)
            os._exit(0)
        signal.signal(signal.SIGTERM, slow_term)
    os.write(ready_w, b"R")
    while True: signal.pause()
os.close(gate_r); os.close(ready_w)
os.write(1, b"REGISTER %d\n" % child)
# Both processes wait for exact provenance registration BEFORE normal leader exit.
if os.read(0, 1) != b"A": os._exit(2)
os.write(gate_w, b"A")
if os.read(ready_r, 1) != b"R": os._exit(2)
os.write(1, b"READY %d\n" % child)
os._exit(0)
'''
SENTINEL = 'import os,signal\nos.write(1,b"READY 0\\n")\nwhile True: signal.pause()\n'
CASES = (
    ('leader-first-exit-delayed-term-child', 'delayed-term', 5),
    ('term-ignoring-child-needs-kill', 'ignore-term', 5),
    ('ordinary-leader-only', 'leader-only', 5),
    ('command-policy-immediate-kill', 'ignore-term', 0),
)


def become_subreaper():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError('subreaper unavailable')
    value = ctypes.c_int(0)
    if libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0 or value.value != 1:
        raise OSError('subreaper not confirmed')


class Reaper(threading.Thread):
    """Exact registered fork children only; ECHILD before adoption stays pending."""
    def __init__(self):
        super().__init__(daemon=True)
        self.registry, self.reaped, self.errors = {}, {}, []
        self.stop, self.lock = threading.Event(), threading.Lock()

    def register(self, pid, leader):
        assert type(pid) is int and pid > 1 and pid != leader.pid
        with self.lock:
            assert pid not in self.registry and pid not in self.registry.values()
            assert leader.pid not in self.registry
            self.registry[pid] = leader.pid

    def complete(self):
        with self.lock:
            return not self.errors and set(self.registry) == set(self.reaped)

    def run(self):
        try:
            while not self.stop.is_set():
                with self.lock:
                    pending = sorted(set(self.registry) - set(self.reaped))
                for pid in pending:
                    try:
                        done, status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        continue  # adoption pending or ownership lost: NEVER a successful reap
                    assert done in (0, pid)
                    if done == pid:
                        with self.lock:
                            self.reaped[pid] = status
                self.stop.wait(.02)
        except BaseException as error:
            with self.lock:
                self.errors.append(type(error).__name__)


def message(pipe, tag, end):
    raw = b''
    while b'\n' not in raw:
        left = end - time.monotonic()
        assert left > 0 and select.select([pipe], [], [], left)[0], 'readiness timeout'
        part = os.read(pipe.fileno(), 1)
        assert part and len(raw) < 64, 'readiness closed/malformed'
        raw += part
    fields = raw.split()
    assert len(fields) == 2 and fields[0] == tag and fields[1].isdigit()
    assert time.monotonic() < end
    return int(fields[1])


class Fixture:
    def __init__(self, home, runtime, finish):
        self.home, self.runtime, self.finish = home, runtime, finish
        self.entries, self.events, self.failures = [], [], []
        self.killpg = os.killpg
        self.reaper = Reaper()

    def signal(self, pgid, number):
        matches = [e for e in self.entries if e['proc'] is not None and e['proc'].pid == pgid]
        assert len(matches) == 1, 'unregistered group signal'
        entry = matches[0]
        if number:
            assert entry['group'] is not None and not entry['group'].reaping
            assert entry['proc'].returncode is None, 'post-reap destructive signal'
        self.events.append([entry['name'], pgid, int(number)])
        return self.killpg(pgid, number)

    def spawn(self, name, code, mode=None):
        env = {'PATH': '/unusable', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'HOME': str(self.home), 'TMPDIR': str(self.home)}
        entry = {'name': name, 'proc': None, 'group': None, 'clean': False}
        self.entries.append(entry)  # even failed Popen/handoff must appear in FAIL evidence
        entry['proc'] = subprocess.Popen([str(self.runtime), '-I', '-S', '-B', '-c', code,
                                          *([] if mode is None else [mode])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, env=env, cwd=self.home, bufsize=0)
        entry['group'] = owned_process.OwnedGroup(entry['proc'])
        return entry

    def close(self, entry, term=0):
        if entry['clean']:
            return True
        proc, group = entry['proc'], entry['group']
        clean = False
        try:
            if group is not None:
                clean = group.close(term, 3, until=self.finish)
                clean = clean and proc.returncode is not None
                if clean:
                    try:
                        self.signal(proc.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        clean = False
        except BaseException as error:
            self.failures.append('closure:' + type(error).__name__)
        finally:
            for pipe in (getattr(proc, 'stdin', None), getattr(proc, 'stdout', None)):
                try:
                    if pipe is not None:
                        pipe.close()
                except BaseException as error:
                    clean = False
                    self.failures.append('pipe:' + type(error).__name__)
        entry['clean'] = clean and time.monotonic() < self.finish
        return entry['clean']

    def run_case(self, name, mode, term, sentinel):
        started = time.monotonic()
        assert started < self.finish - CLEANUP_RESERVE
        entry = self.spawn(name, LEADER, mode)
        proc, group = entry['proc'], entry['group']
        end = min(started + 5, self.finish - CLEANUP_RESERVE)
        child = message(proc.stdout, b'REGISTER', end)
        if child:
            self.reaper.register(child, proc)
        assert os.write(proc.stdin.fileno(), b'A') == 1
        assert message(proc.stdout, b'READY', end) == child
        if child:
            while group.status() is None:
                assert time.monotonic() < end, 'leader did not exit first'
                time.sleep(.01)
        self.signal(proc.pid, 0)
        assert self.close(entry, term), 'production closure uncertain'
        assert sentinel['group'].status() is None, 'sentinel leader changed'
        self.signal(sentinel['proc'].pid, 0)
        assert not any(e[0] == 'sentinel' and e[2] for e in self.events), 'sentinel signalled'
        return {'case': name, 'seconds': time.monotonic() - started, 'child': child, 'leader': proc.pid}


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--outer-boundary', required=True)
    parser.add_argument('--nproc', type=int, required=True)
    args = parser.parse_args(argv)
    assert sys.platform.startswith('linux') and sys.version.split()[0] == '3.12.16'
    if sys.flags.optimize:
        raise RuntimeError('fixture assertions require optimization disabled')
    assert args.runtime.is_absolute() and args.runtime.resolve() == Path(sys.executable).resolve()
    assert args.nproc >= 8 and args.outer_boundary
    assert args.output.is_dir() and not any(args.output.iterdir())
    assert args.output.stat().st_uid == os.geteuid() and args.output.stat().st_mode & 0o777 == 0o700
    before = identities(args.runtime.resolve())
    assert before == IMPORT_IDENTITIES
    child_hashes = {name: hashlib.sha256(code.encode()).hexdigest()
                    for name, code in (('leader', LEADER), ('sentinel', SENTINEL))}
    for which, value in ((resource.RLIMIT_FSIZE, 1 << 20), (resource.RLIMIT_NOFILE, 64),
                         (resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 30),
                         (resource.RLIMIT_AS, 1 << 30), (resource.RLIMIT_NPROC, args.nproc)):
        resource.setrlimit(which, (value, value))
    fixture = Fixture(args.output, args.runtime.resolve(), time.monotonic() + WALL_SECONDS)
    results, reaper_started = [], False
    original_killpg = os.killpg
    def interrupted(*_):
        raise KeyboardInterrupt('fixture interrupted')
    try:
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            signal.signal(number, interrupted)
        signal.alarm(WALL_SECONDS)
        become_subreaper()
        os.killpg = fixture.signal
        fixture.reaper.start()
        reaper_started = True
        sentinel = fixture.spawn('sentinel', SENTINEL)
        assert message(sentinel['proc'].stdout, b'READY', time.monotonic() + 5) == 0
        for case in CASES:
            results.append(fixture.run_case(*case, sentinel))
    except BaseException as error:
        fixture.failures.append('work:' + type(error).__name__)
    finally:
        signal.alarm(0)  # original finish remains; external containment is independent
        for entry in reversed(fixture.entries):
            if not fixture.close(entry):
                fixture.failures.append('incomplete:' + entry['name'])
        if reaper_started:
            while not fixture.reaper.complete() and time.monotonic() < fixture.finish - 1:
                time.sleep(.02)
            fixture.reaper.stop.set()
            fixture.reaper.join(max(0, min(1, fixture.finish - time.monotonic())))
            if fixture.reaper.is_alive() or not fixture.reaper.complete():
                fixture.failures.append('incomplete-reaper')
        os.killpg = original_killpg
    after = identities(args.runtime.resolve())
    if before != after or any(args.output.iterdir()) or time.monotonic() >= fixture.finish:
        fixture.failures.append('identity/files/deadline')
    document = {'schema': 2, 'python': sys.version.split()[0], 'before': before, 'after': after,
                'child_code': child_hashes, 'outer_boundary_claim': args.outer_boundary,
                'cases': results, 'signals': fixture.events, 'failures': fixture.failures,
                'registered': fixture.reaper.registry, 'reaped': fixture.reaper.reaped,
                'reaper_errors': fixture.reaper.errors,
                'cleanup': {e['name']: e['clean'] for e in fixture.entries},
                'passed': not fixture.failures and reaper_started and fixture.reaper.complete()
                          and not fixture.reaper.is_alive() and len(results) == len(CASES)
                          and len(fixture.entries) == len(CASES) + 1
                          and all(e['clean'] for e in fixture.entries)}
    fd = os.open(args.output / 'result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(document, handle, sort_keys=True)
    print(json.dumps(document, sort_keys=True))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
