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
SLACK = 2.0                # scheduling slack on top of the 10s cap plus 2s kill/reap grace
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
)
REMAINING = (
    'SIGTERM/SIGINT delivery during a live kubectl child (existing production executor tests only)',
    'matching exit-1 transient rewrite with cleanup_uncertain (separate source/synthetic control)',
    'body trickle slower than the output limit; HTTP/2; ten-retry (eleven-attempt) exhaustion',
    'plain-text (non-Status) 503/500 bodies; Retry-After values between 1s and the cap',
    'full api_ready/ready_body, native forwarding, systemd/cgroup, 18 nodes, switches, trial-16 cause',
)

FLAG_PATTERNS = {
    'refused': rb'was refused',
    'x509': rb'x509:',
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
    """One deterministic loopback server. mode: serve | backlog (listen, never accept) | tls-stall
    (accept, read the ClientHello, never answer). All sockets/threads are owned and closed by close()."""

    def __init__(self, port=PORT, host=HOST, context=None, clock=time.monotonic):
        self.port, self.host, self.context, self.clock = port, host, context, clock
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests, self.errors, self.threads = [], {}, []
        self.accepted = 0
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
            self.threads.append(thread)
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
                refuse = self.accepted > MAX_CONNECTIONS
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
            conn.settimeout(5.0)
            if self.mode == 'tls-stall':
                conn.settimeout(0.5)
                self._recv(conn, self.clock() + 5.0)  # the ClientHello, never answered
                self._wait_stop()
                return
            client_cn = None
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
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
                self.requests.append({'n': index + 1, 'at': round(self.clock() - self.t0, 3),
                                      'method': clean(line[0], 8), 'path': clean(path),
                                      'query': clean(query), 'client_cn': client_cn,
                                      'step': step['name']})
            if step['do'] == 'stall':
                self._wait_stop()
            elif step['do'] == 'stall-body':
                head = ('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n'
                        'Connection: close\r\n\r\nok')
                conn.sendall(head.encode())
                self._wait_stop()
            else:
                extra = ''.join('%s: %s\r\n' % pair for pair in step['headers'])
                head = ('HTTP/1.1 %d %s\r\nContent-Type: %s\r\n%sContent-Length: %d\r\n'
                        'Connection: close\r\n\r\n' % (step['code'], step['phrase'], step['type'],
                                                       extra, len(step['body'])))
                conn.sendall(head.encode() + step['body'])
        except (OSError, ssl.SSLError, ValueError) as error:
            self._error(error)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        """Stop, close the listener, join owned threads; returns closed-state evidence."""
        self.stop.set()
        listener_closed = True
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                listener_closed = False
        end = self.clock() + 8.0
        with self.lock:
            threads = list(self.threads)
        for thread in threads:
            thread.join(max(0.0, end - self.clock()))
        return {'listener_closed': listener_closed,
                'threads_alive': sum(1 for thread in threads if thread.is_alive()),
                'connections_accepted': self.accepted, 'server_errors': dict(self.errors)}


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
                      route=error.route, flags=private_flags(error.private_output))
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
         elapsed=(0.0, 8.0), deadline=30.0, budget=6.0, loop=False, start_after=None,
         pre_final=None, min_pending=0):
    return {'name': name, 'steps': steps, 'mode': mode, 'tls': tls, 'allowed': allowed,
            'message': message, 'requests': requests, 'elapsed': elapsed, 'deadline': deadline,
            'budget': budget, 'loop': loop, 'start_after': start_after, 'pre_final': pre_final,
            'min_pending': min_pending}


HANG = {('failure', 124), ('failure', 1)}   # request timeout and execute cap may race
CAPPED = (5.0, 10.0 + 2.0 + SLACK)


def build_cases():
    return (
        case('ok-ready', [OK()], allowed={('ok', None)}, requests=(1, 1)),
        case('refused-then-delayed-start', [OK()], loop=True, start_after=3.0, deadline=25.0,
             allowed={('ok', None)}, pre_final={('pending', 1)}, min_pending=1, budget=28.0,
             elapsed=(2.0, 25.0), requests=(1, 1)),
        case('success-but-not-ok-body', [respond('not-ok', 200, 'OK', b'not-ok', 'text/plain')],
             allowed={('success-non-ok', None)}, requests=(1, 1)),
        case('401-unauthorized', [STATUS(401, 'Unauthorized', 'Unauthorized')],
             allowed={('failure', 1)}),
        case('403-forbidden', [STATUS(403, 'Forbidden', 'Forbidden')], allowed={('failure', 1)}),
        case('x509-unknown-authority', [OK()], tls='foreign', allowed={('failure', 1)}),
        case('x509-wrong-ip-san', [OK()], tls='wrong-san', allowed={('failure', 1)}),
        case('500-no-retry-after', [STATUS(500, 'Internal Server Error', 'InternalError')],
             allowed={('failure', 1), ('failure', 124)}),
        case('output-overflow', [HUGE(1024 * 1024 + 4096)], allowed={('failure', 1)},
             message='private child output overflow'),
        case('429-no-retry-after', [STATUS(429, 'Too Many Requests', 'TooManyRequests')],
             elapsed=(0.0, 16.0)),
        case('429-retry-after-malformed',
             [STATUS(429, 'Too Many Requests', 'TooManyRequests', 'soon'), OK()],
             elapsed=(0.0, 16.0)),
        case('429-retry-after-http-date',
             [STATUS(429, 'Too Many Requests', 'TooManyRequests', 'Wed, 21 Oct 2026 07:28:00 GMT'),
              OK()], elapsed=(0.0, 16.0)),
        case('503-no-retry-after', [STATUS(503, 'Service Unavailable', 'ServiceUnavailable')],
             elapsed=(0.0, 16.0)),
        case('429-retry-after-1s-then-ok',
             [STATUS(429, 'Too Many Requests', 'TooManyRequests', '1'), OK()], elapsed=(0.0, 16.0)),
        case('503-retry-after-1s-then-ok',
             [STATUS(503, 'Service Unavailable', 'ServiceUnavailable', '1'), OK()],
             elapsed=(0.0, 16.0)),
        case('absolute-deadline-before-cap', [STALL_HEADER], deadline=3.0, allowed={('failure', 124)},
             message='child deadline exceeded', elapsed=(2.0, 3.0 + 2.0 + SLACK), budget=8.0),
        case('tcp-accepted-never-served', [OK()], mode='backlog', allowed=HANG, elapsed=CAPPED,
             requests=(0, 0), budget=14.0),
        case('tls-clienthello-never-answered', [OK()], mode='tls-stall', allowed=HANG,
             elapsed=CAPPED, requests=(0, 0), budget=14.0),
        case('header-stall-after-request', [STALL_HEADER], allowed=HANG, elapsed=CAPPED, budget=14.0),
        case('body-stall-after-partial-body', [STALL_BODY], allowed=HANG, elapsed=CAPPED, budget=14.0),
        case('429-retry-after-30s-over-cap',
             [STATUS(429, 'Too Many Requests', 'TooManyRequests', '30'), OK()],
             elapsed=(0.0, 16.0), budget=14.0),
        case('503-retry-after-30s-over-cap',
             [STATUS(503, 'Service Unavailable', 'ServiceUnavailable', '30'), OK()],
             elapsed=(0.0, 16.0), budget=14.0),
    )


def verdict(spec, attempts, fixture, evidence):
    """Return (verdict, reasons). Deterministic claims only; others are 'recorded'."""
    reasons = []
    final = attempts[-1] if attempts else {'kind': 'not-run', 'code': None, 'message': ''}
    if final['kind'] == 'harness-error':
        reasons.append('harness error')
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
        if any(a['kind'] == 'pending' and not a['flags']['refused'] for a in early):
            reasons.append('pending without the exact refusal text')
    low, high = spec['elapsed']
    if not low <= evidence['elapsed'] <= high:
        reasons.append('elapsed outside the case window')
    if spec['requests'] is not None and not spec['requests'][0] <= evidence['request_count'] <= spec['requests'][1]:
        reasons.append('server request count outside bounds')
    if spec['name'] == 'ok-ready':
        first = fixture['requests'][:1]
        if not first or first[0]['path'] != '/readyz' or first[0]['client_cn'] != CLIENT_CN:
            reasons.append('ok case did not show a verified mTLS /readyz request')
    if not evidence['cleanup']['listener_closed'] or evidence['cleanup']['threads_alive']:
        reasons.append('fixture cleanup incomplete')
    if evidence['owned_uid_processes_after']:
        reasons.append('ubuntu-uid process remained in the container')
    if reasons:
        return 'failed', reasons
    return ('passed' if spec['allowed'] is not None else 'recorded'), reasons


def run_case(spec, core, contexts, kubectl, uid, clock=time.monotonic, sleep=time.sleep,
             factory=Fixture, count=owned_uid_processes):
    fixture = factory(context=contexts.get(spec['tls']), clock=clock)
    begun = clock()
    deadline = begun + spec['deadline']          # ONE original absolute operation deadline
    attempts, started = [], False
    try:
        while True:
            if not started and (spec['start_after'] is None or clock() - begun >= spec['start_after']):
                fixture.start(spec['steps'], spec['mode'])
                started = True
            record = attempt(core, kubectl, deadline, clock)
            if len(attempts) < MAX_REPORTED_ATTEMPTS:
                attempts.append(record)
            else:
                attempts[-1] = record
            if not spec['loop'] or record['kind'] != 'pending' or clock() >= deadline:
                break
            sleep(max(0.0, min(1.0, deadline - clock())))
    finally:
        cleanup = fixture.close() if started else {'listener_closed': True, 'threads_alive': 0,
                                                    'connections_accepted': 0, 'server_errors': {}}
    elapsed = round(clock() - begun, 3)
    settle = clock() + SETTLE
    remaining = count(uid)
    while remaining and clock() < settle:
        sleep(0.1)
        remaining = count(uid)
    served = fixture.requests
    evidence = {'elapsed': elapsed, 'request_count': len(served), 'cleanup': cleanup,
                'owned_uid_processes_after': remaining}
    outcome, reasons = verdict(spec, attempts, {'requests': served}, evidence)
    return {'name': spec['name'], 'verdict': outcome, 'reasons': reasons,
            'asserted': spec['allowed'] is not None, 'mode': spec['mode'], 'tls': spec['tls'],
            'operation_deadline_seconds': spec['deadline'], 'elapsed': elapsed,
            'server_requests': served[:MAX_REPORTED_REQUESTS], 'server_request_count': len(served),
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
        fixtures=FIXTURES, config_path=KUBECONFIG_PATH):
    begun = clock()
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
            if clock() - begun + spec['budget'] > WORK_BUDGET:
                report['cases'].append({'name': spec['name'], 'verdict': 'not-run',
                                        'reasons': ['insufficient remaining proof budget']})
                continue
            report['cases'].append(run_case(spec, core, contexts, kubectl, account.pw_uid, clock))
        verdicts = [c['verdict'] for c in report['cases']]
        report['summary'] = {name: verdicts.count(name) for name in ('passed', 'recorded', 'failed', 'not-run')}
        if verdicts and not report['summary']['failed'] and not report['summary']['not-run']:
            report['status'] = 'passed'
    except KeyboardInterrupt:
        report['error'] = 'interrupted'
    except Exception as error:  # noqa: BLE001 - fixed class only, never message text
        report['error'] = 'operational failure (%s)' % type(error).__name__
    finally:
        report['elapsed_seconds'] = round(clock() - begun, 3)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=('prepare', 'run'))
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        prepare()
        return 0
    signal.signal(signal.SIGTERM, _terminate)
    sys.path.insert(0, str(SUITE))
    import vlab_core as core
    report = run(core)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
