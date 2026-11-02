"""Test-only driver: real pinned kubectl readiness timing through the unchanged vlab_core.kubectl (#452).

Runs only inside the disposable container made by test-kubectl-readiness.sh (Ubuntu 24.04
amd64, Python 3.12 stdlib + distribution PyYAML). Two commands, no other inputs:

  prepare  (preparation container, once): generate SYNTHETIC test certificates with OpenSSL and
           the accepted kubeconfig for the existing ``ubuntu`` account. Never used at runtime.
  run      (runtime container, network none): serve a deterministic loopback TLS fixture on
           127.0.0.1:6443 and call the production ``vlab_core.kubectl`` (real pinned kubectl,
           real routed/execute, real uid/group drop, real accepted kubeconfig) per case.

Test seams, disclosed in the report: this calls ``kubectl()`` for the ``get --raw=/readyz`` step
only, NOT ``api_ready``/``ready_body``/systemd/cloud-init; the retry loop here sleeps 1s (the
production loop sleeps 5s); the fixture speaks HTTP/1.1 (no ALPN h2); there is no real
kube-apiserver. Same-code client time bounds may race (request timeout 10s vs execute cap 10s):
timings and outcomes are RECORDED and a case only asserts what is deterministic. Nothing here
changes a timeout, classifier, retry or budget, and a 124 is never treated as Pending.
Report: sanitized JSON only (fixed strings, counts, booleans, timings), never child output.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

HOST, PORT = '127.0.0.1', 6443
FIXTURES = Path('/opt/labapp-readiness')
SUITE = Path(__file__).resolve().parent
CLIENT_CN = 'labapp-readiness-client'
KUBECTL_PIN = {'size': 58597560,
               'sha256': 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989'}
KUBECTL_PATH = '/usr/local/bin/kubectl'
KUBECONFIG_PATH = Path('/home/ubuntu/hhfab/vlab/kubeconfig')
WORK_BUDGET = 170          # whole runtime proof (seconds); the launcher adds an outer bound
SETTLE = 2.0               # post-case wait for owned-uid processes to disappear
CLEANUP = 1.0              # listener, sockets and threads, inside each case reservation
REAP = 2.0                 # unchanged production executor's cleanup wait
REPORT_RESERVE = 5.0       # held inside the original proof deadline
MAX_CONNECTIONS = 64
MAX_REPORTED_REQUESTS = 12
MAX_REPORTED_ATTEMPTS = 20
PACKAGES = ('python3', 'python3.12', 'python3-yaml', 'libyaml-0-2', 'openssl')
HARNESS = 'labapp-kubectl-readiness-v1'

SEAMS = (
    'kubectl() only for get --raw=/readyz; api_ready, ready_body, systemd and cloud-init not run',
    'retry loop in the refusal case sleeps 1s (production ready_body sleeps min(5s, remaining))',
    'Python stdlib HTTP/1.1 fixture without ALPN h2, not a kube-apiserver',
    'runtime container root with only SETUID, SETGID, KILL and DAC_OVERRIDE capabilities',
    'synthetic OpenSSL certificates generated in the separate preparation container',
    'request timeout 10s and execute cap 10s may race; outcomes recorded, no winner guaranteed',
    'quick-case operation deadlines are 2s, delayed startup 6s, explicit exhaustion 3s; stalls 10s',
    'production diagnostic storage is unprepared; exception byte counts are not emitted-byte counts',
    'Pending context is inspected only for discarded cleanup uncertainty, never to restore child output',
)
REMAINING = (
    'SIGTERM/SIGINT delivery during a live kubectl child (existing production executor tests only)',
    'all eight former Retry-After observations deferred: 429 absent/malformed/date/1s/30s; 503 absent/1s/30s',
    '503 malformed/date Retry-After were never implemented',
    'unknown error; repeated refusal through expiry',
    'body trickle slower than the output limit; HTTP/2; ten-retry (eleven-attempt) exhaustion',
    'plain-text (non-Status) 503/500 bodies; Retry-After values between 1s and the cap',
    'full api_ready/ready_body, native forwarding, systemd/cgroup, 18 nodes, switches, trial-16 cause',
)

FLAG_PATTERNS = {
    'refused': rb'was refused',
    'x509': rb'x509:',
    'unknown_authority': rb'x509: certificate signed by unknown authority',
    'wrong_san': rb'x509: certificate is valid for 127\.0\.0\.2, not 127\.0\.0\.1',
    'client_timeout': rb'Client\.Timeout|context deadline exceeded|i/o timeout|timed out',
    'unauthorized': rb'Unauthorized',
    'forbidden': rb'Forbidden',
    'too_many_requests': rb'TooManyRequests',
    'service_unavailable': rb'ServiceUnavailable',
    'internal_error': rb'InternalError|Internal error',
}


# ---------------------------------------------------------------- fixture steps

def status_body(code, reason, message='synthetic fixture response'):
    return json.dumps({'kind': 'Status', 'apiVersion': 'v1', 'metadata': {}, 'status': 'Failure',
                       'message': message, 'reason': reason, 'code': code}).encode()


def respond(name, code, phrase, body, ctype='application/json', headers=()):
    return {'do': 'respond', 'name': name, 'code': code, 'phrase': phrase, 'body': body,
            'type': ctype, 'headers': tuple(headers)}


def OK():
    return respond('ok', 200, 'OK', b'ok', 'text/plain')


def STATUS(code, phrase, reason, retry_after=None, name=None):
    headers = () if retry_after is None else (('Retry-After', retry_after),)
    return respond(name or '%d' % code, code, phrase, status_body(code, reason), headers=headers)


STALL_HEADER = {'do': 'stall', 'name': 'stall-before-response-header'}
STALL_BODY = {'do': 'stall-body', 'name': 'stall-after-partial-body'}


def HUGE(size):
    return respond('oversize-200', 200, 'OK', b'a' * size, 'text/plain')


# ---------------------------------------------------------------- loopback fixture

def clean(value, limit=128):
    return re.sub(r'[^A-Za-z0-9=&._%/-]', '?', value)[:limit]


class Fixture:
    """One deterministic loopback server. mode: serve | tcp-stall | tls-stall
    (accept, read the ClientHello, never answer). All sockets/threads are owned and closed by close()."""

    def __init__(self, port=PORT, host=HOST, context=None, clock=time.monotonic):
        self.port, self.host, self.context, self.clock = port, host, context, clock
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests, self.errors, self.threads = [], {}, []
        self.accepted = 0
        self.sockets = set()
        self.acceptor = None
        self.handshakes_started = self.handshakes_completed = self.clienthello_bytes = 0
        self.sock = None
        self.steps = []
        self.mode = 'serve'
        self.t0 = None

    def start(self, steps, mode='serve'):
        self.steps, self.mode, self.t0 = list(steps), mode, self.clock()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(8)
        self.sock = sock
        if self.port == 0:
            self.port = sock.getsockname()[1]
        if mode != 'backlog':
            sock.settimeout(0.2)
            thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.acceptor = thread
            thread.start()

    def _accept_loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.accepted += 1
                refuse = self.stop.is_set() or self.accepted > MAX_CONNECTIONS
                if not refuse:
                    self.sockets.add(conn)
            if refuse:
                conn.close()
                continue
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            with self.lock:
                self.threads.append(thread)
            thread.start()

    def _error(self, error):
        name = type(error).__name__
        with self.lock:
            self.errors[name] = self.errors.get(name, 0) + 1

    def _wait_stop(self, limit=20.0):
        self.stop.wait(limit)

    def _recv(self, conn, deadline):
        while not self.stop.is_set() and self.clock() < deadline:
            try:
                return conn.recv(4096)
            except socket.timeout:
                continue
        return b''

    def _serve(self, conn):
        try:
            if self.mode == 'tcp-stall':
                self._wait_stop()
                return
            conn.settimeout(5.0)
            if self.mode == 'tls-stall':
                conn.settimeout(0.5)
                hello = self._recv(conn, self.clock() + 5.0)
                with self.lock:
                    self.clienthello_bytes += len(hello)
                self._wait_stop()
                return
            client_cn = None
            if self.context is not None:
                # Track the SSLSocket BEFORE its blocking handshake, not the detached raw socket.
                with self.lock:
                    self.handshakes_started += 1
                    wrapped = self.context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
                    self.sockets.discard(conn)
                    self.sockets.add(wrapped)
                    conn = wrapped
                conn.do_handshake()
                with self.lock:
                    self.handshakes_completed += 1
                cert = conn.getpeercert() or {}
                for rdn in cert.get('subject', ()):
                    for key, value in rdn:
                        if key == 'commonName':
                            client_cn = value
            conn.settimeout(0.5)
            data, deadline = b'', self.clock() + 5.0
            while b'\r\n\r\n' not in data and len(data) <= 16384:
                chunk = self._recv(conn, deadline)
                if not chunk:
                    return
                data += chunk
            line = data.split(b'\r\n', 1)[0].decode('latin-1').split(' ')
            target = line[1] if len(line) > 1 else ''
            path, _, query = target.partition('?')
            with self.lock:
                index = len(self.requests)
                step = self.steps[min(index, len(self.steps) - 1)]
                request = {'n': index + 1, 'at': round(self.clock() - self.t0, 3),
                           'method': clean(line[0], 8), 'path': clean(path),
                           'query': clean(query), 'client_cn': client_cn, 'step': step['name'],
                           'headers_sent': False, 'body_bytes_sent': 0}
                self.requests.append(request)
            if step['do'] == 'stall':
                self._wait_stop()
            elif step['do'] == 'stall-body':
                head = ('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n'
                        'Connection: close\r\n\r\n')
                conn.sendall(head.encode())
                with self.lock:
                    request['headers_sent'] = True
                conn.sendall(b'ok')
                with self.lock:
                    request['body_bytes_sent'] = 2
                self._wait_stop()
            else:
                extra = ''.join('%s: %s\r\n' % pair for pair in step['headers'])
                head = ('HTTP/1.1 %d %s\r\nContent-Type: %s\r\n%sContent-Length: %d\r\n'
                        'Connection: close\r\n\r\n' % (step['code'], step['phrase'], step['type'],
                                                       extra, len(step['body'])))
                conn.sendall(head.encode())
                with self.lock:
                    request['headers_sent'] = True
                view = memoryview(step['body'])
                while view and not self.stop.is_set():
                    sent = conn.send(view[:65536])
                    if not sent:
                        break
                    with self.lock:
                        request['body_bytes_sent'] += sent
                    view = view[sent:]
        except (OSError, ssl.SSLError, ValueError) as error:
            self._error(error)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self.lock:
                self.sockets.discard(conn)

    def close(self, deadline=None):
        """Stop, close the listener, join owned threads; returns closed-state evidence."""
        self.stop.set()
        listener_closed = True
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                listener_closed = False
        end = min(self.clock() + CLEANUP, deadline) if deadline is not None else self.clock() + CLEANUP
        # No final handler inventory until the only producer has settled.
        if self.acceptor is not None:
            self.acceptor.join(max(0.0, end - self.clock()))
        acceptor_alive = self.acceptor is not None and self.acceptor.is_alive()
        with self.lock:
            threads = list(self.threads)
            sockets = list(self.sockets)
        sockets_closed = True
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                sockets_closed = False
        for thread in threads:
            thread.join(max(0.0, end - self.clock()))
        return {'listener_closed': listener_closed,
                'threads_alive': int(acceptor_alive) + sum(1 for thread in threads if thread.is_alive()),
                'sockets_closed': sockets_closed and all(conn.fileno() == -1 for conn in sockets),
                'connections_accepted': self.accepted, 'server_errors': dict(self.errors),
                'handshakes_started': self.handshakes_started,
                'handshakes_completed': self.handshakes_completed,
                'clienthello_bytes': self.clienthello_bytes}


# ---------------------------------------------------------------- classification

def private_flags(raw):
    return {name: bool(re.search(pattern, raw)) for name, pattern in FLAG_PATTERNS.items()}


def attempt(core, kubectl, deadline, clock=time.monotonic):
    """One production call -> fixed-schema record. Never includes child output, only derived flags."""
    begun = clock()
    record = {'at_remaining': round(deadline - begun, 3)}
    try:
        out = kubectl(['get', '--raw=/readyz'], deadline, 'api-initial-readyz')
        record['kind'] = 'ok' if out.strip() == b'ok' else 'success-non-ok'
        record['code'], record['message'], record['output_bytes'] = None, '', len(out)
    except core.Pending as error:
        record.update(kind='pending', code=error.code, message=str(error),
                      route=error.route, private_output_bytes=len(error.private_output),
                      flags=private_flags(error.private_output),
                      cleanup_uncertain=bool(getattr(error, 'cleanup_uncertain', False)
                                            or getattr(error.__context__, 'cleanup_uncertain', False)))
    except core.Failure as error:
        record.update(kind='failure', code=error.code, message=str(error), route=error.route,
                      cleanup_uncertain=bool(getattr(error, 'cleanup_uncertain', False)),
                      private_output_bytes=len(error.private_output),
                      flags=private_flags(error.private_output))
    except Exception as error:  # noqa: BLE001 - a harness/environment fault, reported by class
        record.update(kind='harness-error', code=None, message=type(error).__name__)
    record['elapsed'] = round(clock() - begun, 3)
    return record


def owned_uid_processes(uid):
    """Live (non-zombie) processes of the container's own ubuntu uid; container-scoped only."""
    found = 0
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            if os.stat('/proc/' + entry).st_uid != uid:
                continue
            state = Path('/proc/%s/stat' % entry).read_text().rsplit(')', 1)[-1].split()[0]
        except (OSError, IndexError):
            continue
        if state != 'Z':
            found += 1
    return found


def case(name, steps, *, mode='serve', tls='good', allowed=None, message=None, requests=None,
         elapsed=(0.0, 7.0), deadline=2.0, budget=7.0, loop=False, start_after=None,
         pre_final=None, min_pending=0, flag=None):
    return {'name': name, 'steps': steps, 'mode': mode, 'tls': tls, 'allowed': allowed,
            'message': message, 'requests': requests, 'elapsed': elapsed, 'deadline': deadline,
            'budget': budget, 'loop': loop, 'start_after': start_after, 'pre_final': pre_final,
            'min_pending': min_pending, 'flag': flag}


HANG = {('failure', 124), ('failure', 1)}   # request timeout and execute cap may race
CAPPED = (5.0, 15.0)


def build_cases():
    return (
        case('ok-ready', [OK()], allowed={('ok', None)}, requests=(1, 1)),
        case('refused-then-delayed-start', [OK()], loop=True, start_after=3.0, deadline=6.0,
             allowed={('ok', None)}, pre_final={('pending', 1)}, min_pending=1, budget=11.0,
             elapsed=(2.0, 11.0), requests=(1, 1)),
        case('success-but-not-ok-body', [respond('not-ok', 200, 'OK', b'not-ok', 'text/plain')],
             allowed={('success-non-ok', None)}, requests=(1, 1)),
        case('401-unauthorized', [STATUS(401, 'Unauthorized', 'Unauthorized')],
             allowed={('failure', 1)}, requests=(1, 1), flag='unauthorized', message='child command failed'),
        case('403-forbidden', [STATUS(403, 'Forbidden', 'Forbidden')], allowed={('failure', 1)},
             requests=(1, 1), flag='forbidden', message='child command failed'),
        case('x509-unknown-authority', [OK()], tls='foreign', allowed={('failure', 1)},
             requests=(0, 0), flag='unknown_authority', message='child command failed'),
        case('x509-wrong-ip-san', [OK()], tls='wrong-san', allowed={('failure', 1)},
             requests=(0, 0), flag='wrong_san', message='child command failed'),
        case('500-no-retry-after', [STATUS(500, 'Internal Server Error', 'InternalError')],
             allowed={('failure', 1)}, requests=(1, 1), flag='internal_error', message='child command failed'),
        case('output-overflow', [HUGE(1024 * 1024 + 4096)], allowed={('failure', 1)},
             message='private child output overflow', requests=(1, 1)),
        case('absolute-deadline-before-cap', [STALL_HEADER], deadline=3.0, allowed={('failure', 124)},
             elapsed=(2.0, 8.0), budget=8.0, requests=(1, 1)),
        case('tcp-accepted-never-served', [OK()], mode='tcp-stall', allowed=HANG, elapsed=CAPPED,
             requests=(0, 0), budget=15.0, deadline=10.0),
        case('tls-clienthello-never-answered', [OK()], mode='tls-stall', allowed=HANG,
             elapsed=CAPPED, requests=(0, 0), budget=15.0, deadline=10.0),
        case('header-stall-after-request', [STALL_HEADER], allowed=HANG, elapsed=CAPPED,
             budget=15.0, deadline=10.0, requests=(1, 1)),
        case('body-stall-after-partial-body', [STALL_BODY], allowed=HANG, elapsed=CAPPED,
             budget=15.0, deadline=10.0, requests=(1, 1)),
    )


def verdict(spec, attempts, fixture, evidence):
    """Return (verdict, reasons). Deterministic claims only; others are 'recorded'."""
    reasons = []
    final = attempts[-1] if attempts else {'kind': 'not-run', 'code': None, 'message': ''}
    if not attempts or any(a['kind'] == 'harness-error' for a in attempts):
        reasons.append('harness error')
    if any(a.get('cleanup_uncertain', False) for a in attempts):
        reasons.append('child cleanup uncertain')
    for row in attempts:
        if row['kind'] == 'failure' and row.get('route') != 'api-initial-readyz':
            reasons.append('failure lacks original child route')
        if row['kind'] == 'pending' and (row['code'] != 1 or row.get('route') is not None
                or row.get('private_output_bytes') != 0 or row['message'] != 'API discovery pending'):
            reasons.append('pending differs from the production contract')
    if spec['flag'] and not final.get('flags', {}).get(spec['flag'], False):
        reasons.append('missing cause-specific child evidence')
    if spec['allowed'] == HANG or spec['name'] == 'absolute-deadline-before-cap':
        if final['code'] == 124:
            if final['message'] not in ('child deadline exceeded', 'deadline exceeded'):
                reasons.append('missing deadline evidence')
        elif final['message'] != 'child command failed' or not final.get('flags', {}).get('client_timeout'):
            reasons.append('missing client timeout evidence')
    if spec['allowed'] is not None and (final['kind'], final['code']) not in spec['allowed']:
        reasons.append('final outcome not in the allowed set')
    if spec['message'] is not None and final.get('message') != spec['message']:
        reasons.append('final message differs')
    if spec['loop']:
        early = attempts[:-1]
        if len(early) < spec['min_pending']:
            reasons.append('too few pending attempts before readiness')
        if any((a['kind'], a['code']) not in spec['pre_final'] for a in early):
            reasons.append('a pre-final attempt was not exact pending')
        if any(a.get('server_started', True) for a in early):
            reasons.append('pending was not observed before listener startup')
    low, high = spec['elapsed']
    if not low <= evidence['elapsed'] <= high:
        reasons.append('elapsed outside the case window')
    if spec['requests'] is not None and not spec['requests'][0] <= evidence['request_count'] <= spec['requests'][1]:
        reasons.append('server request count outside bounds')
    cleanup = evidence['cleanup']
    if spec['requests'] and spec['requests'][0]:
        if (cleanup.get('connections_accepted') != evidence['request_count']
                or cleanup.get('handshakes_completed') != evidence['request_count']
                or any(r.get('path') != '/readyz' or r.get('method') != 'GET'
                       or r.get('query') != 'timeout=10s' or r.get('client_cn') != CLIENT_CN
                       for r in fixture['requests'])):
            reasons.append('request lacks matching connection and verified mTLS evidence')
        for request in fixture['requests']:
            step = spec['steps'][0]
            expected_body = len(step['body']) if step['do'] == 'respond' else 2 if step['do'] == 'stall-body' else 0
            body_matches = (request.get('body_bytes_sent', 0) > 1024 * 1024
                            if spec['name'] == 'output-overflow'
                            else request.get('body_bytes_sent') == expected_body)
            if (request.get('step') != step['name']
                    or request.get('headers_sent') != (step['do'] != 'stall')
                    or not body_matches):
                reasons.append('fixture response evidence differs')
    if spec['tls'] != 'good' and (cleanup.get('connections_accepted') != 1
            or cleanup.get('handshakes_started') != 1 or cleanup.get('handshakes_completed') != 0
            or not cleanup.get('server_errors')):
        reasons.append('missing rejected TLS handshake evidence')
    if spec['mode'] in ('tcp-stall', 'tls-stall'):
        if cleanup.get('connections_accepted') != 1 or cleanup.get('handshakes_completed') != 0:
            reasons.append('missing accepted connection stall evidence')
        if spec['mode'] == 'tls-stall' and not cleanup.get('clienthello_bytes', 0):
            reasons.append('missing ClientHello evidence')
    if (not cleanup['listener_closed'] or cleanup['threads_alive']
            or not cleanup.get('sockets_closed', False)):
        reasons.append('fixture cleanup incomplete')
    if evidence['owned_uid_processes_after']:
        reasons.append('ubuntu-uid process remained in the container')
    if reasons:
        return 'failed', reasons
    return ('passed' if spec['allowed'] is not None else 'recorded'), reasons


def run_case(spec, core, contexts, kubectl, uid, clock=time.monotonic, sleep=time.sleep,
             factory=Fixture, count=owned_uid_processes, proof_deadline=None):
    fixture = factory(context=contexts.get(spec['tls']), clock=clock)
    begun = clock()
    end = begun + spec['budget']
    if proof_deadline is not None:
        end = min(end, proof_deadline - REPORT_RESERVE)
    deadline = min(begun + spec['deadline'], end - REAP - CLEANUP - SETTLE)
    attempts, started = [], False
    try:
        while True:
            if not started and (spec['start_after'] is None or clock() - begun >= spec['start_after']):
                fixture.start(spec['steps'], spec['mode'])
                started = True
            record = attempt(core, kubectl, deadline, clock)
            record['server_started'] = started
            if len(attempts) < MAX_REPORTED_ATTEMPTS:
                attempts.append(record)
            else:
                attempts[-1] = record
            if (not spec['loop'] or record['kind'] != 'pending'
                    or record.get('cleanup_uncertain') or clock() >= deadline):
                break
            sleep(max(0.0, min(1.0, deadline - clock())))
    finally:
        cleanup = fixture.close(min(end - SETTLE, clock() + CLEANUP))
    settle = min(end, clock() + SETTLE)
    remaining = count(uid)
    while remaining and clock() < settle:
        sleep(min(0.1, max(0.0, settle - clock())))
        remaining = count(uid)
    served = fixture.requests
    elapsed = round(clock() - begun, 3)
    evidence = {'elapsed': elapsed, 'request_count': len(served), 'cleanup': cleanup,
                'owned_uid_processes_after': remaining}
    outcome, reasons = verdict(spec, attempts, {'requests': served}, evidence)
    if clock() >= end:
        outcome = 'failed'
        reasons.append('case reservation exhausted including cleanup and settling')
    return {'name': spec['name'], 'verdict': outcome, 'reasons': reasons,
            'asserted': spec['allowed'] is not None, 'mode': spec['mode'], 'tls': spec['tls'],
            'operation_deadline_seconds': spec['deadline'], 'elapsed': elapsed,
            'server_requests': served[:MAX_REPORTED_REQUESTS], 'server_request_count': len(served),
            'route_counts': {'api-initial-readyz': sum(a.get('route') == 'api-initial-readyz' for a in attempts),
                             'unlabeled_pending': sum(a['kind'] == 'pending' and a.get('route') is None
                                                      for a in attempts)},
            'attempts': attempts, 'cleanup': cleanup, 'owned_uid_processes_after': remaining}


# ---------------------------------------------------------------- identity / report

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def package_versions(run=subprocess.run):
    out = run(['/usr/bin/dpkg-query', '-W', '-f=${Package} ${Version} ${db:Status-Status}\\n', *PACKAGES],
              capture_output=True, timeout=15, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    rows = {}
    for line in out.stdout.decode('ascii', 'replace').splitlines():
        parts = line.split(' ')
        if len(parts) == 3 and parts[2] == 'installed':
            rows[parts[0]] = parts[1]
    return rows


def os_release():
    values = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        key, _, value = line.partition('=')
        values[key] = value.strip('"')
    return {key: values.get(key) for key in ('ID', 'VERSION_ID', 'VERSION_CODENAME')}


def source_binding(core_path):
    """Drift detector: the reviewed time bindings this proof labels as 10s/10s must still be in source."""
    text = Path(core_path).read_text()
    return {'request_timeout_10s': "'--request-timeout=10s'" in text,
            'execute_cap_10_user_drop': bool(re.search(r"\*args\],\s*deadline,\s*10,\s*user=True\)", text)),
            'kubectl_path': "KUBECTL = '/usr/local/bin/kubectl'" in text}


def identity(core_path):
    files = {name: sha256(SUITE / name) for name in
             ('kubectl_readiness_proof.py', 'vlab_core.py', 'owned_process.py')}
    info = os.stat(KUBECTL_PATH)
    return {'source_sha256': files,
            'kubectl': {'size': info.st_size, 'sha256': sha256(KUBECTL_PATH), 'mode': oct(info.st_mode & 0o777),
                        'pinned_size': KUBECTL_PIN['size'], 'pinned_sha256': KUBECTL_PIN['sha256'],
                        'version_pin': '1.35.0 linux/amd64 (binary compiler identity not inspected)'},
            'base': os_release(), 'python': sys.version.split()[0], 'packages': package_versions(),
            'binding': source_binding(core_path)}


def make_contexts():
    contexts = {}
    for key, stem in (('good', 'server'), ('foreign', 'foreign'), ('wrong-san', 'wrongsan')):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(FIXTURES / (stem + '.crt')), str(FIXTURES / (stem + '.key')))
        context.load_verify_locations(str(FIXTURES / 'ca.crt'))
        context.verify_mode = ssl.CERT_REQUIRED
        contexts[key] = context
    return contexts


def run(core, kubectl=None, contexts=None, clock=time.monotonic, cases=None, ident=None,
        fixtures=FIXTURES, config_path=KUBECONFIG_PATH, proof_deadline=None,
        case_runner=run_case):
    begun = clock()
    end = begun + WORK_BUDGET if proof_deadline is None else proof_deadline
    report = {'harness': HARNESS, 'status': 'failed', 'work_budget_seconds': WORK_BUDGET,
              'cap_seconds': 10, 'request_timeout_seconds': 10, 'seams': list(SEAMS),
              'remaining_coverage': list(REMAINING), 'cases': []}
    try:
        report['identity'] = ident = ident if ident is not None else identity(core.__file__)
        problems = []
        if ident['kubectl']['size'] != KUBECTL_PIN['size'] or ident['kubectl']['sha256'] != KUBECTL_PIN['sha256']:
            problems.append('kubectl bytes differ from the pin')
        if not all(ident['binding'].values()):
            problems.append('production kubectl binding differs from the reviewed 10s/10s shape')
        if problems:
            report['error'] = '; '.join(problems)
            return report
        account = core.ubuntu()
        ca = core.kubeconfig()          # the accepted kubeconfig reader, unchanged
        report['kubeconfig'] = {'accepted': True, 'ca_sha256': ca,
                                'owner_is_ubuntu': os.stat(config_path).st_uid == account.pw_uid}
        if ca != sha256(Path(fixtures) / 'ca.crt') or not report['kubeconfig']['owner_is_ubuntu']:
            report['error'] = 'kubeconfig CA or owner differs from the fixture'
            return report
        kubectl = kubectl or core.kubectl
        contexts = contexts if contexts is not None else make_contexts()
        for spec in (cases if cases is not None else build_cases()):
            if clock() + spec['budget'] + REPORT_RESERVE > end:
                report['cases'].append({'name': spec['name'], 'verdict': 'not-run',
                                        'reasons': ['insufficient remaining proof budget']})
                continue
            report['cases'].append(case_runner(spec, core, contexts, kubectl, account.pw_uid, clock,
                                                proof_deadline=end))
        verdicts = [c['verdict'] for c in report['cases']]
        report['summary'] = {name: verdicts.count(name) for name in ('passed', 'recorded', 'failed', 'not-run')}
        if verdicts and not report['summary']['failed'] and not report['summary']['not-run']:
            report['status'] = 'passed'
    except ProofExpired:
        report['error'] = 'original proof deadline exhausted'
    except KeyboardInterrupt:
        report['error'] = 'interrupted'
    except Exception as error:  # noqa: BLE001 - fixed class only, never message text
        report['error'] = 'operational failure (%s)' % type(error).__name__
    finally:
        report['elapsed_seconds'] = round(clock() - begun, 3)
        json.dumps(report, sort_keys=True)  # charge report construction to the original clock
        if clock() >= end:
            report['status'] = 'failed'
            report['error'] = 'original proof deadline exhausted'
    return report


# ---------------------------------------------------------------- preparation (separate container)

def openssl(*args):
    subprocess.run(['/usr/bin/openssl', *args], check=True, timeout=30, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})


def kubeconfig_text(ca_pem, cert_pem, key_pem):
    def b64(raw):
        return base64.b64encode(raw).decode('ascii')
    return ('apiVersion: v1\nkind: Config\nclusters:\n- name: labapp\n  cluster:\n'
            '    server: https://127.0.0.1:6443\n    certificate-authority-data: %s\n'
            'contexts:\n- name: labapp\n  context:\n    cluster: labapp\n    user: labapp\n'
            'current-context: labapp\nusers:\n- name: labapp\n  user:\n'
            '    client-certificate-data: %s\n    client-key-data: %s\n'
            % (b64(ca_pem), b64(cert_pem), b64(key_pem)))


def prepare():
    """Synthetic test data only. Fails closed if the target already exists."""
    account = pwd.getpwnam('ubuntu')
    if account.pw_dir != '/home/ubuntu' or account.pw_uid <= 0:
        raise SystemExit('ubuntu identity refused')
    if FIXTURES.exists() or Path('/home/ubuntu/hhfab').exists():
        raise SystemExit('fixture target is not fresh')
    FIXTURES.mkdir(mode=0o700, parents=True)
    ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes']

    def ca(stem, cn):
        openssl('req', '-x509', *ec, '-keyout', str(FIXTURES / (stem + '.key')), '-out', str(FIXTURES / (stem + '.crt')),
                '-subj', '/CN=' + cn, '-days', '7', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign')

    def leaf(stem, signer, cn, extension):
        ext = FIXTURES / (stem + '.ext')
        ext.write_text(extension)
        openssl('req', '-new', *ec, '-keyout', str(FIXTURES / (stem + '.key')), '-out', str(FIXTURES / (stem + '.csr')),
                '-subj', '/CN=' + cn)
        openssl('x509', '-req', '-in', str(FIXTURES / (stem + '.csr')), '-CA', str(FIXTURES / (signer + '.crt')),
                '-CAkey', str(FIXTURES / (signer + '.key')), '-CAcreateserial', '-out', str(FIXTURES / (stem + '.crt')),
                '-days', '7', '-extfile', str(ext))

    server = 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n'
    ca('ca', 'labapp-readiness-ca')
    ca('foreign-ca', 'labapp-readiness-foreign-ca')
    leaf('server', 'ca', 'readiness-server', server % '127.0.0.1')
    leaf('wrongsan', 'ca', 'readiness-wrong-san', server % '127.0.0.2')
    leaf('foreign', 'foreign-ca', 'readiness-foreign', server % '127.0.0.1')
    leaf('client', 'ca', CLIENT_CN, 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n')
    config = kubeconfig_text((FIXTURES / 'ca.crt').read_bytes(), (FIXTURES / 'client.crt').read_bytes(),
                             (FIXTURES / 'client.key').read_bytes())
    for pattern in ('*.csr', '*.ext', '*.srl', 'foreign-ca.*', 'ca.key', 'client.*'):
        for path in FIXTURES.glob(pattern):
            path.unlink()
    for path in (Path('/home/ubuntu/hhfab'), Path('/home/ubuntu/hhfab/vlab')):
        path.mkdir(mode=0o700)
        os.chown(path, account.pw_uid, account.pw_gid)
    target = Path('/home/ubuntu/hhfab/vlab/kubeconfig')
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(config)
    os.chown(target, account.pw_uid, account.pw_gid)
    for path in FIXTURES.iterdir():
        os.chmod(path, 0o600)
    print(json.dumps({'prepared': sorted(path.name for path in FIXTURES.iterdir()),
                      'packages': package_versions(), 'base': os_release()}, sort_keys=True), flush=True)


def _terminate(_signum, _frame):
    raise KeyboardInterrupt


class ProofExpired(BaseException):
    """Whole-driver deadline, not a child error and never Pending."""


def _expire(_signum, _frame):
    raise ProofExpired


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=('prepare', 'run'))
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        prepare()
        return 0
    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGALRM, _expire)
    end = time.monotonic() + WORK_BUDGET
    signal.setitimer(signal.ITIMER_REAL, max(0.001, end - time.monotonic()))
    try:
        sys.path.insert(0, str(SUITE))
        import vlab_core as core
        report = run(core, proof_deadline=end)
        if time.monotonic() >= end:
            raise ProofExpired
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0 if report['status'] == 'passed' and time.monotonic() < end else 1
    except ProofExpired:
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    sys.exit(main())
