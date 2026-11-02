"""Test-only runner inside owned Docker containers; never a cloud entrypoint."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
import threading
import time

from hhfab_release import Refusal, bounded, digest
import qemu_offline
import qemu_witness

APT_HELPER = '/usr/lib/apt/apt-helper'
TRANSPORT = re.compile(rb'(?i)\b50[0-9]\b|bad gateway|service unavailable|gateway time-?out|'
                       rb'connection (timed out|failed|reset)|could not (connect|resolve)|'
                       rb'temporary failure|timed out')
BODY = b'labapp transport fixture\n'


def apt_stage(args):
    """Stage label for a fixed-installer APT command; None for non-APT commands."""
    if args[0] != '/usr/bin/apt-get':
        return None
    if '--simulate' in args:
        return 'simulate'
    for stage in ('update', 'check'):
        if args[-1] == stage:
            return stage
    return 'install' if 'install' in args else 'other'


def recording_call(module, log):
    """Replacement for the installer's call() that keeps stage, exit code and output."""
    def call(args, seconds=10):
        code, output = bounded(args, seconds, env=module['ENV'])
        log.append((apt_stage(args), code, output))
        if code:
            raise Refusal(f'command failed: stage={apt_stage(args)} code={code!r}')
        return output
    return call


def signature_proof(code, output):
    """Only a real NO_PUBKEY authentication failure proves the signature refusal."""
    if code != 0 and b'NO_PUBKEY' in output:
        return
    kind = ('succeeded' if code == 0 else 'transport-only failure' if TRANSPORT.search(output)
            else 'unclassified failure')
    raise AssertionError(f'stage=update empty-keyring {kind}, not signature proof: '
                         f'code={code!r} output_tail={output[-4096:]!r}')


SENSITIVE = re.compile(rb'(?i)authorization|bearer|password|passwd|secret|token|credential|api[-_]?key|'
                       rb'cookie|://[^/\s@]*@')


def diagnostic_tail(output, limit=4096, lines=40):
    """Finite text-only tail of APT output: last lines, credential-looking lines dropped."""
    if not isinstance(output, (bytes, bytearray)):
        return f'<non-bytes output: {type(output).__name__}>'
    kept = [line for line in bytes(output).splitlines()[-lines:] if not SENSITIVE.search(line)]
    text = b'\n'.join(kept).decode('utf-8', 'replace')
    text = ''.join(ch if ch == '\n' or ch.isprintable() else '?' for ch in text)[-limit:]
    return text if text.strip() else '<empty>'


def missing_pin_proof(log, name, version):
    """Missing-version proof must reach simulation and fail with APT's exact pin error."""
    trail = [(stage, code) for stage, code, _ in log if stage]
    if ([stage for stage, _ in trail] != ['update', 'check', 'simulate']
            or trail[0][1] != 0 or trail[1][1] != 0 or trail[2][1] == 0):
        # Keep the failed stage/exit primary; the bounded tail only explains it.
        failed = next(((s, c, o) for s, c, o in log if s and c != 0), None)
        detail = ('' if failed is None else
                  f' failed_stage={failed[0]} exit={failed[1]!r} output_tail={diagnostic_tail(failed[2])!r}')
        raise AssertionError(f'invalid pin did not fail at simulation after update/check: {trail!r}{detail}')
    output = log[-1][2]
    if f"Version '{version}' for '{name}' was not found".encode() not in output:
        raise AssertionError(f'simulation failure was not the invalid-pin outcome: output_tail={diagnostic_tail(output)!r}')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        server.hits[self.path] = count = server.hits.get(self.path, 0) + 1
        if self.path == '/permanent':
            self.send_error(404)
        elif self.path in ('/always502', '/always503'):
            self.send_error(int(self.path[-3:]))
        elif self.path == '/transient' and count == 1:
            self.send_error(503)
        elif self.path == '/hang':
            server.release.wait(30)
        else:
            self.send_response(200)
            self.send_header('Content-Length', str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)


@contextlib.contextmanager
def serve():
    """Loopback-only bounded stdlib server; returns base URL and per-path request counts."""
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    server.hits, server.release = {}, threading.Event()
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}', server.hits
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(5)


def process_identity(path):
    """Linux stat identity: PID, PGID, session and start tick; no argv matching."""
    value = path.read_text()
    pid, rest = value.split(' (', 1)
    fields = rest.rsplit(')', 1)[1].split()
    return int(pid), int(fields[2]), int(fields[3]), int(fields[19])


class OwnedGroup:
    """Observe the new session leader, then prove no owned group/session survives."""
    def __init__(self, proc=Path('/proc')):
        self.proc, self.identity = proc, None

    def started(self, pid):
        identity = process_identity(self.proc / str(pid) / 'stat')
        if identity[:3] != (pid, pid, pid):
            raise Refusal('native transport process ownership unknown')
        self.identity = identity

    def remaining(self):
        if self.identity is None:
            raise Refusal('native transport process ownership unobserved')
        leader, group, session, start = self.identity
        found = []
        entries = list(self.proc.iterdir())
        if len(entries) > 4096:
            raise Refusal('native transport process census overflow')
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                identity = process_identity(entry / 'stat')
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError):
                raise Refusal('native transport process census unknown') from None
            pid, pgid, sid, tick = identity
            if pid == leader and tick != start:
                raise Refusal('native transport leader identity changed')
            if pgid == group or sid == session:
                found.append(identity)
        return found

    def verify(self):
        # SIGKILL is already issued by bounded(); this only observes exact owned
        # identities while the container init reaps orphan method descendants.
        deadline = time.monotonic() + 2
        while self.remaining():
            if time.monotonic() >= deadline:
                raise Refusal('native transport owned process remains')
            time.sleep(0.02)


def production_retries():
    """The Acquire::Retries value emitted by the shared production setup()."""
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-retries-') as temporary:
        apt, _ = qemu_offline.setup(Path(temporary), 'unused')
    return next(item.split('=', 1)[1] for item in apt if item.startswith('Acquire::Retries='))


def transport(run=bounded, server=serve, ownership=OwnedGroup, limit=15):
    """Native apt-helper over loopback HTTP; no package install, signature or TLS proof."""
    retries = production_retries()
    version = run(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'apt'], 10)[1].decode()
    options = ['-o', 'Acquire::Retries=' + retries, '-o', f'Acquire::http::Timeout={limit}',
               '-o', 'Acquire::http::Proxy=DIRECT']
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
    seconds = {}
    with server() as (base, hits), tempfile.TemporaryDirectory(prefix='labapp-transport-') as temporary:
        Path(temporary).chmod(0o755)
        def fetch(name, deadline, expected=None):
            target = Path(temporary) / name.strip('/')
            args = [APT_HELPER, *options, 'download-file', base + name, str(target)]
            if expected:
                args.append('SHA256:' + expected)
            started = time.monotonic()
            owned = ownership()
            try:
                code, output = run(args, deadline, env=env, on_start=owned.started)
            except Refusal as exc:
                if name != '/hang' or str(exc) != 'command timeout':
                    raise
                code, output = str(exc), b''
            finally:
                owned.verify()
            seconds[name.strip('/')] = round(time.monotonic() - started, 3)
            return code, output, target
        attempts = 1 + int(retries)
        code, output, target = fetch('/transient', 60, hashlib.sha256(BODY).hexdigest())
        assert code == 0 and hits['/transient'] == 2 and target.read_bytes() == BODY, (
            f'transient-then-success: code={code!r} hits={hits!r} output_tail={output[-2048:]!r}')
        for name in ('/always502', '/always503'):
            code, output, target = fetch(name, 60)
            assert type(code) is int and code != 0 and re.search(name[-3:].encode() + rb'[ \t]+(?:Bad Gateway|Service Unavailable)\b', output) and hits[name] == attempts and not target.exists(), (
                f'persistent {name}: code={code!r} hits={hits!r} output_tail={output[-2048:]!r}')
        code, output, target = fetch('/permanent', 60)
        assert type(code) is int and code != 0 and re.search(rb'\b404[ \t]+Not Found\b', output) and hits['/permanent'] == 1 and not target.exists(), (
            f'permanent 404: code={code!r} hits={hits!r} output_tail={output[-2048:]!r}')
        code, output, target = fetch('/baddigest', 60, '0' * 64)
        assert type(code) is int and code != 0 and b'mismatch' in output.lower() and hits['/baddigest'] <= attempts, (
            f'bad digest: code={code!r} hits={hits!r} output_tail={output[-2048:]!r}')
        code, output, target = fetch('/hang', 3)
        assert code == 'command timeout', f'external deadline: code={code!r}'
        requests = dict(hits)
    return {'transport_fixture': True, 'apt_version': version, 'retries': retries, 'http_timeout': limit,
            'requests': requests, 'seconds': seconds, 'http_only_not_tls_or_signature_proof': True}


def install():
    # Native transport semantics first, so no public snapshot request is made
    # if the retry/deadline behavior is not as the production policy assumes.
    print(json.dumps(transport()), flush=True)
    module = runpy.run_path('/suite/install-qemu.py')
    apt_before ={str(p): digest(p) for p in Path('/etc/apt').rglob('*') if p.is_file()}
    packages_before = module['installed']()
    # Exercise actual APT authentication failure against the official signed
    # snapshot with an owned empty trust keyring, before installing anything.
    globals_ = module['install'].__globals__
    original_call = globals_['call']
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-rejection-') as temporary:
        Path(temporary).chmod(0o755)
        key = Path(temporary) / 'empty.gpg'
        key.write_bytes(b'')
        def rejected_trust(args, seconds=10):
            if args[0] == '/usr/bin/apt-get' and args[-1] == 'update':
                source = Path(next(a.split('=', 1)[1] for a in args if a.startswith('Dir::Etc::sourcelist=')))
                source.write_text(source.read_text().replace('/usr/share/keyrings/ubuntu-archive-keyring.gpg', str(key)))
                code, output = bounded(args, seconds, env=module['ENV'])
                signature_proof(code, output)
                raise Refusal('actual signature refusal')
            return original_call(args, seconds)
        globals_['call'] = rejected_trust
        try:
            module['install']()
        except Refusal as exc:
            assert str(exc) == 'stage=update: actual signature refusal'
        else:
            raise AssertionError('untrusted signature accepted')
        finally:
            globals_['call'] = original_call
    assert module['installed']() == packages_before
    # Unavailable explicit pin must fail at resolution, without package changes.
    original_pin = module['PINS']['qemu-system-x86']
    module['PINS']['qemu-system-x86'] = '999:0.invalid'
    log = []
    globals_['call'] = recording_call(module, log)
    try:
        module['install']()
    except Refusal:
        missing_pin_proof(log, 'qemu-system-x86', '999:0.invalid')
    else:
        raise AssertionError('unavailable pin accepted')
    finally:
        globals_['call'] = original_call
        module['PINS']['qemu-system-x86'] = original_pin
    assert module['installed']() == packages_before
    print(json.dumps({'actual_signature_refusal': True, 'actual_unavailable_pin_refusal': True,
                      'preinstall_failure_packages_unchanged': True}))
    for _ in range(2):
        code, output = bounded(['/usr/bin/python3', '/suite/install-qemu.py'], 240,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        if code:
            raise Refusal(f'unchanged installer CLI failed: code={code!r} output_tail={output[-4096:]!r}')
        print(json.dumps(json.loads(output)), flush=True)
    assert {str(p): digest(p) for p in Path('/etc/apt').rglob('*') if p.is_file()} == apt_before
    # Real held-state preflight refuses before an APT transaction.
    assert bounded(['/usr/bin/apt-mark', 'hold', 'socat'], 10)[0] == 0
    try:
        module['preflight']()
    except Refusal as exc:
        assert 'held packages' in str(exc)
    else:
        raise AssertionError('held state accepted')
    finally:
        assert bounded(['/usr/bin/apt-mark', 'unhold', 'socat'], 10)[0] == 0
    print(json.dumps({'apt_configuration_unchanged': True, 'actual_hold_refusal': True}))
    # Real drift refusal occurs before APT mutation. A target version change is
    # simulated in this test process only, never by altering installed packages.
    module['PINS']['socat'] = '0.invalid'
    try:
        module['preflight']()
    except Refusal as exc:
        assert 'drift' in str(exc)
    else:
        raise AssertionError('drift accepted')


def runtime():
    assert os.getuid() == 1000
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    assert not Path('/dev/kvm').exists()
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1'
    print(json.dumps(qemu_witness.probe(test_tcg=True)), flush=True)
    # Invoke unchanged production CLI: no KVM device means refusal, never TCG.
    code, output = bounded(['/usr/bin/python3', '/suite/qemu_witness.py'], 20, limit=4096)
    assert code == 1 and b'KVM character device absent; no fallback' in output
    # Also prove actual QEMU's KVM-only path refuses, rather than just our guard.
    code, output = bounded(['/usr/bin/qemu-system-x86_64', '-nodefaults', '-display', 'none',
                            '-accel', 'kvm', '-cpu', 'host', '-machine', 'pc-i440fx-8.2'], 5, limit=4096)
    assert code != 0 and b'failed to initialize kvm' in output and b'LABAPP-L2:' not in output
    print(json.dumps({'production_no_kvm_refusal': True, 'actual_qemu_kvm_refusal': True}))


if __name__ == '__main__':
    {'install': install, 'runtime': runtime}[sys.argv[1]]()
