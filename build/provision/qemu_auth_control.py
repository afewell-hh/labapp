"""Test-only disconnected native-APT metadata-authentication controls (#447 Tier 1).

Runs real ``apt-get update`` with the unchanged production options against a
loopback HTTP server that serves three unchanged public Ubuntu snapshot
``InRelease`` fixtures. Only the source URI (and, for the empty-key controls, the
``signed-by`` path) is rewritten, after asserting the exact production text. It
never installs packages, never changes ``install-qemu.py`` policy and never
falls back to an external host. HTTP proves neither TLS nor transport security.

Order is deliberate: the native POSITIVE probe (valid key, intact releases)
runs first and fails closed if it cannot show per-suite signature acceptance
followed by authenticated index scheduling. Only then are the empty-key,
tamper-with-valid-key and persistent 502/503 controls run.

STATUS: exact APT 2.8.3 diagnostic semantics remain unverified. The positive
probe captures evidence but ALWAYS refuses UNQUALIFIED until a separately
reviewed per-suite native correlation is implemented. No native pass is claimed.
"""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import runpy
import socket
import sys
import tempfile
import threading
import time

from hhfab_release import Refusal, bounded, digest
import qemu_container
import qemu_offline

SNAPSHOT = '20261024T000000Z'
SUITES = ('noble', 'noble-updates', 'noble-security')
FIXTURE_DIR = Path(__file__).parent / 'fixtures' / f'ubuntu-snapshot-{SNAPSHOT}'
# Unchanged public bytes: (file name, size, sha256). Total 508102 bytes.
FIXTURES = {
    'noble': ('noble.InRelease', 255850,
              'cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0'),
    'noble-updates': ('noble-updates.InRelease', 126125,
                      '4fcba3fb02086679f7e86677e320b92e0d076a8c02e30dc0abbbe06b67640db7'),
    'noble-security': ('noble-security.InRelease', 126127,
                       'e56daa3c9903f06da8161b4f0e61a747aab215647f4bfabbecd5655631200f09'),
}
FIXTURE_TOTAL = 508102
KEY = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
EXPECTED_APT = '2.8.3'
SOURCE_LINE = ('deb [signed-by=' + KEY + '] https://snapshot.ubuntu.com/ubuntu/' + SNAPSHOT +
               '/ {suite} main universe\n')
PRODUCTION_SOURCES = ''.join(SOURCE_LINE.format(suite=suite) for suite in SUITES)
PRODUCTION_UPDATE = ['-o', 'APT::Update::Error-Mode=any', 'update']  # as install-qemu.py
# Diagnostic-only options, used by the separate positive probe only. Their output
# format is NOT verified against APT 2.8.3; an unmet expectation fails closed.
DIAGNOSTIC = ['-o', 'Debug::Acquire::gpgv=true', '-o', 'Debug::pkgAcquire::Auth=true']
CASE_SECONDS = 25
MAX_REQUESTS = 64
SOCKET_SECONDS = 2
SHUTDOWN_SECONDS = 3
OUTPUT_LIMIT = 4 * 1024 * 1024
BASE_PATH = f'/ubuntu/{SNAPSHOT}/dists/'
PATH_RE = re.compile(re.escape(BASE_PATH) + r'(noble|noble-updates|noble-security)/([A-Za-z0-9_.+~/-]{1,240})')
INDEX_RE = re.compile(r'(main|universe)/[A-Za-z0-9_.+~/-]{1,200}')
# Failure vocabulary that must be absent from a positive acceptance.
REJECTION = re.compile(rb'NO_PUBKEY|BADSIG|EXPKEYSIG|REVKEYSIG|ERRSIG|NODATA|signatures were invalid|'
                       rb'is not signed|could not be verified|couldn.t be verified|has expired|'
                       rb'not valid yet|changed its')
BADSIG = re.compile(rb'BADSIG|signatures were invalid')
MIXED_TRANSPORT = re.compile(rb'(?i)\b(?:40[0-9]|41[0-9]|429)\b[ \t]+(?:not found|forbidden|'
                             rb'unauthorized|too many requests)|could not handshake|'
                             rb'connection refused|network is unreachable|unexpected eof|'
                             rb'undetermined error|hash sum mismatch|file has unexpected size')


# ---------------------------------------------------------------- fixtures

def load_fixtures(directory=FIXTURE_DIR):
    """Exact public bytes or a refusal; never synthesizes or fetches replacements."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise Refusal('signed InRelease fixtures not staged')
    names = {name for name, _, _ in FIXTURES.values()}
    if {p.name for p in directory.iterdir()} != names:
        raise Refusal('signed InRelease fixture set mismatch (missing or extra files)')
    result = {}
    for suite, (name, size, expected) in FIXTURES.items():
        data = qemu_offline.regular(directory / name, 512 * 1024)
        if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
            raise Refusal('signed InRelease fixture identity mismatch: ' + suite)
        result[suite] = data
    if sum(len(v) for v in result.values()) != FIXTURE_TOTAL:
        raise Refusal('signed InRelease fixture total mismatch')
    return result


def tamper(data):
    """Flip one hex digit of the first signed SHA256 entry; same length and envelope.

    The cleartext changes while the PGP armor, signature block and framing stay
    byte-identical, so the valid key must refuse it as a bad signature."""
    begin = data.find(b'-----BEGIN PGP SIGNATURE-----')
    match = re.search(rb'\n ([0-9a-f]{64}) +[0-9]+ +\S+\n', data[:begin])
    if begin < 0 or match is None:
        raise Refusal('cannot tamper unexpected InRelease envelope')
    at = match.start(1)
    flipped = b'1' if data[at:at + 1] == b'0' else b'0'
    result = data[:at] + flipped + data[at + 1:]
    changed = [i for i, (a, b) in enumerate(zip(data, result)) if a != b]
    if len(result) != len(data) or changed != [at] or result[begin:] != data[begin:]:
        raise Refusal('tamper altered more than one signed cleartext byte')
    return result


# ------------------------------------------------------------ source rewrite

def rewrite_sources(original, base, key=None):
    """Assert exact production text, then change only each URI (and signed-by if key)."""
    if original != PRODUCTION_SOURCES:
        raise Refusal('production sources text changed; refusing rewrite')
    uri = f'{base}/ubuntu/{SNAPSHOT}/'
    lines = []
    for suite in SUITES:
        line = SOURCE_LINE.format(suite=suite).replace('https://snapshot.ubuntu.com/ubuntu/' + SNAPSHOT + '/', uri)
        if key is not None:
            line = line.replace('signed-by=' + KEY, 'signed-by=' + str(key))
        lines.append(line)
    result = ''.join(lines)
    restored = result.replace(uri, 'https://snapshot.ubuntu.com/ubuntu/' + SNAPSHOT + '/')
    if key is not None:
        restored = restored.replace('signed-by=' + str(key), 'signed-by=' + KEY)
    if restored != original or len(result.splitlines()) != 3:
        raise Refusal('source rewrite changed more than URI/empty key')
    for before, after in zip(original.split(), result.split()):
        if before != after and not (after.startswith(base) or after.startswith('[signed-by=')):
            raise Refusal('unexpected source token rewritten')
    return result


# -------------------------------------------------------- loopback fixture

class Ledger:
    """Atomic socket admission and ordered write observations, not client receipts."""
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = []
        self.order = 0

    def admit(self):
        with self.lock:
            if len(self.rows) > MAX_REQUESTS:
                raise Refusal('fixture admission already closed')
            over = len(self.rows) == MAX_REQUESTS
            row = dict(n=len(self.rows), method='<unparsed>', path='<unparsed>',
                       headers=[], status=None, bytes=0, sha256=None,
                       kind='over-budget' if over else 'incomplete',
                       attempted=False, completed=False, failure=None,
                       completed_bytes=None, completed_sha256=None,
                       admitted_order=self.order)
            self.order += 1
            self.rows.append(row)
            return row['n'], over

    def update(self, n, event, **values):
        with self.lock:
            self.rows[n].update(values)
            self.rows[n][event + '_order'] = self.order
            self.order += 1

    def snapshot(self):
        with self.lock:
            return [dict(row, headers=[list(pair) for pair in row['headers']]) for row in self.rows]


class Case:
    """Closed behavior for one control: key, delivered bytes, status, allowances."""
    def __init__(self, key, bodies, status=200, index_absence=False, fallback=False, debug=False):
        self.key, self.bodies, self.status = key, bodies, status
        self.index_absence, self.fallback, self.debug = index_absence, fallback, debug


def decide(case, method, path, headers):
    """Closed route table -> (status, body, kind). Anything else is 'unexpected'."""
    if method != 'GET':
        return 405, b'', 'unexpected'
    if any(name in headers for name in ('If-Modified-Since', 'If-None-Match', 'Range', 'If-Range')):
        return 404, b'', 'unexpected'  # stale lists / partial / conditional: forbidden
    match = PATH_RE.fullmatch(path)
    if match is None or '..' in path or '//' in path[1:]:
        return 404, b'', 'unexpected'
    suite, rest = match.groups()
    if rest == 'InRelease':
        if case.status == 200:
            return 200, case.bodies[suite], 'release'
        return case.status, b'', 'release-transport'
    if case.fallback and rest in ('Release', 'Release.gpg'):
        return case.status, b'', 'fallback-transport'
    if case.index_absence and INDEX_RE.fullmatch(rest):
        return 404, b'', 'index-absence'
    return 404, b'', 'unexpected'


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'labapp-fixture'
    protocol_version = 'HTTP/1.0'

    def log_message(self, *args):
        pass

    def handle(self):
        self.row = self.server.sockets[self.request]
        try:
            super().handle()
        finally:
            row = self.server.ledger.snapshot()[self.row]
            if not row['completed'] and row['failure'] is None:
                self.server.ledger.update(self.row, 'failure', failure='incomplete-request')

    def send_error(self, code, message=None, explain=None):
        # Base parser errors and unknown verbs must not escape the same ledger.
        self._request_fields()
        self.server.ledger.update(self.row, 'parsed', kind='unexpected', status=code)
        self._write(code, b'')

    def _write(self, status, body):
        ledger = self.server.ledger
        ledger.update(self.row, 'attempt', attempted=True, status=status,
                      bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        try:
            self.send_response_only(status)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            sent = self.wfile.write(body)
            if sent != len(body):
                raise OSError('short write')
            self.wfile.flush()
        except OSError:
            ledger.update(self.row, 'failure', failure='write-failed')
        else:
            ledger.update(self.row, 'complete', completed=True, completed_bytes=len(body),
                          completed_sha256=hashlib.sha256(body).hexdigest())
        self.close_connection = True

    def _request_fields(self):
        server = self.server
        # Never publish arbitrary request text or header values. Recognized
        # public loopback/APT fields only, with bounded redaction for everything else.
        headers = []
        seen = set()
        safe = True
        for name, value in getattr(self, 'headers', {}).items():
            lower = name.lower()
            allowed = lower not in seen and len(value) <= 128 and (
                lower == 'host' and value == f'127.0.0.1:{server.server_port}'
                or lower == 'user-agent' and re.fullmatch(r'Debian APT-HTTP/[0-9.]+ \(2\.8\.3\)', value)
                or lower == 'connection' and value.lower() in ('close', 'keep-alive')
                or lower == 'accept' and value == '*/*'
                or lower == 'accept-encoding' and value == 'identity'
                or lower == 'cache-control' and value == 'max-age=0')
            seen.add(lower)
            headers.append([lower if lower in ('host', 'user-agent', 'connection', 'accept',
                                               'accept-encoding', 'cache-control') else '<other>',
                            value if allowed else '<redacted>'])
            safe = safe and bool(allowed)
        if len(headers) > 16:
            headers, safe = [['<overflow>', '<redacted>']], False
        path = getattr(self, 'path', '')
        path = path if PATH_RE.fullmatch(path) else '<unexpected>'
        method = getattr(self, 'command', '')
        method = method if method in ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS',
                                      'PATCH', 'CONNECT', 'TRACE') else '<other>'
        server.ledger.update(self.row, 'request', method=method, path=path, headers=headers)
        return safe

    def _serve(self):
        server = self.server
        status, body, kind = decide(server.case, self.command, self.path, self.headers)
        if not self._request_fields():
            status, body, kind = 404, b'', 'unexpected'
        server.ledger.update(self.row, 'parsed', kind=kind)
        self._write(status, body)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = _serve


class Server(http.server.HTTPServer):
    """Track sockets before spawning; stop admission before draining all handlers."""
    def __init__(self, case):
        self.case, self.ledger = case, Ledger()
        self.stopping = threading.Event()
        self.guard = threading.Lock()
        self.sockets, self.handlers = {}, []
        super().__init__(('127.0.0.1', 0), Handler)
        self.timeout = 0.1

    def get_request(self):
        request, address = super().get_request()
        try:
            request.settimeout(SOCKET_SECONDS)
            n, over = self.ledger.admit()
        except BaseException:
            request.close()
            raise
        if over:
            self.ledger.update(n, 'failure', failure='request-budget')
            self.stopping.set()
            request.close()
            raise OSError('request budget')
        with self.guard:
            self.sockets[request] = n
        return request, address

    def process_request(self, request, address):
        thread = threading.Thread(target=self.worker, args=(request, address))
        with self.guard:
            self.handlers.append(thread)
        try:
            thread.start()
        except BaseException:
            self.ledger.update(self.sockets[request], 'failure', failure='handler-start')
            self.shutdown_request(request)
            with self.guard:
                del self.sockets[request]
                self.handlers.remove(thread)
            raise

    def worker(self, request, address):
        try:
            self.finish_request(request, address)
        except Exception:
            self.ledger.update(self.sockets[request], 'failure', failure='handler-failed')
        finally:
            self.shutdown_request(request)
            with self.guard:
                del self.sockets[request]

    def loop(self):
        while not self.stopping.is_set():
            self.handle_request()

    def close_owned(self, thread):
        self.stopping.set()
        thread.join(SHUTDOWN_SECONDS)
        self.server_close()
        # Admission/spawn has settled before taking the handler snapshot.
        with self.guard:
            sockets, handlers = list(self.sockets), list(self.handlers)
        for request in sockets:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + SHUTDOWN_SECONDS
        for handler in handlers:
            handler.join(max(0, deadline - time.monotonic()))
        if thread.is_alive() or any(handler.is_alive() for handler in handlers) or self.sockets:
            raise Refusal('fixture owned socket/handler remains')


@contextlib.contextmanager
def serve(case):
    """Loopback-only server; bounded reads/writes, admission and exact owned shutdown."""
    server = Server(case)
    port = server.server_port
    thread = threading.Thread(target=server.loop)
    thread.start()
    try:
        yield f'http://127.0.0.1:{port}', server.ledger
    finally:
        server.close_owned(thread)
        probe = socket.socket()
        probe.settimeout(1)
        try:
            probe.connect(('127.0.0.1', port))
        except OSError:
            pass
        else:
            raise Refusal('fixture server port remains open')
        finally:
            probe.close()


# ------------------------------------------------------------ classification

def _rows(rows, kind):
    return [row for row in rows if row['kind'] == kind]


def _release_rows(rows, bodies, expect_status=200):
    """Exactly the three expected InRelease deliveries with exact delivered bytes."""
    kind = 'release' if expect_status == 200 else 'release-transport'
    found = _rows(rows, kind)
    expected = {f'{BASE_PATH}{suite}/InRelease' for suite in SUITES}
    if sorted(row['path'] for row in found) != sorted(expected) and expect_status == 200:
        raise AssertionError(f'InRelease requests are not exactly one per suite: {[r["path"] for r in found]!r}')
    if expect_status == 200:
        for row in found:
            suite = PATH_RE.fullmatch(row['path']).group(1)
            if not row['completed'] or row['failure'] is not None or (
                    row['status'], row['completed_bytes'], row['completed_sha256']) != (
                    200, len(bodies[suite]), hashlib.sha256(bodies[suite]).hexdigest()) or (
                    row['bytes'], row['sha256']) != (row['completed_bytes'], row['completed_sha256']):
                raise AssertionError('delivered InRelease bytes differ from the expected body: ' + suite)
    return found


def _no_unexpected(rows):
    bad = [row for row in rows if row['kind'] in ('unexpected', 'over-budget', 'incomplete')
           or not row['completed'] or row['failure'] is not None]
    if bad:
        raise AssertionError(f'unexplained request(s): {[(r["method"], r["path"], r["status"]) for r in bad]!r}')


def classify_positive(code, output, rows, intact):
    """Native positive boundary: per-suite signature + policy acceptance -> index scheduling.

    The deliberately absent indexes make update NONZERO; that is expected and is
    never reported as a successful update. Unmet evidence means UNQUALIFIED."""
    if type(code) is not int or code == 0:
        raise AssertionError(f'positive probe update must fail on the deliberately absent indexes: code={code!r}')
    _no_unexpected(rows)
    _release_rows(rows, intact)
    rejection = REJECTION.search(output)
    if rejection:
        raise AssertionError(f'positive probe shows an authentication/policy rejection: {rejection.group(0)!r}')
    # Neither globally counted gpgv tokens nor release-request order associates
    # verification with a suite, metadata-policy acceptance and subsequent index
    # scheduling. Exact 2.8.3 diagnostics have not been verified. Do not invent a
    # grammar from synthetic tests; retain the bounded native capture for ROOT.
    raise AssertionError('UNQUALIFIED: exact APT 2.8.3 per-suite verification -> '
                         'metadata-policy acceptance -> authenticated index scheduling '
                         'diagnostic correlation is not verified')


def _only_releases(code, output, rows, bodies):
    _no_unexpected(rows)
    if len(rows) != 3 or any(row['kind'] != 'release' for row in rows):
        raise AssertionError(f'requests are not exactly the three InRelease deliveries: {len(rows)} rows')
    _release_rows(rows, bodies)


def classify_empty_key(code, output, rows, intact):
    """Genuine NO_PUBKEY with intact releases delivered 200, using the unchanged predicate."""
    qemu_container.signature_proof(code, output)
    if type(code) is not int:
        raise AssertionError('empty-key control has no native integer exit')
    if qemu_container.TRANSPORT.search(output) or MIXED_TRANSPORT.search(output):
        raise AssertionError('empty-key control mixed with transport failure')
    if BADSIG.search(output):
        raise AssertionError('empty-key control mixed with a bad-signature failure')
    _only_releases(code, output, rows, intact)
    return {'no_pubkey': True}


def classify_tamper(code, output, rows, tampered):
    """Valid key + tampered cleartext: explicit integrity refusal, not an empty-key failure."""
    if type(code) is not int or code == 0:
        raise AssertionError(f'tampered releases were accepted: code={code!r}')
    if b'NO_PUBKEY' in output or not BADSIG.search(output):
        raise AssertionError('tamper refusal is not an explicit signature-integrity failure')
    if (qemu_container.TRANSPORT.search(output) or MIXED_TRANSPORT.search(output)
            or re.search(rb'GOODSIG|VALIDSIG', output)):
        raise AssertionError('tamper control has mixed or ambiguous authentication/transport evidence')
    try:
        qemu_container.signature_proof(code, output)
    except AssertionError:
        pass
    else:
        raise AssertionError('tamper failure was masked as an empty-key proof')
    _only_releases(code, output, rows, tampered)
    return {'bad_signature': True}


def classify_transport(status, code, output, rows, attempts):
    """Persistent 502/503 stays a transport failure rejected by the unchanged predicate."""
    try:
        qemu_container.signature_proof(code, output)
    except AssertionError as exc:
        if 'transport-only failure' not in str(exc):
            raise AssertionError(f'{status} was not classified as transport-only: {exc}') from None
    else:
        raise AssertionError(f'{status} control was accepted as signature proof')
    if type(code) is not int or code == 0:
        raise AssertionError(f'{status} control has no native nonzero integer exit')
    _no_unexpected(rows)
    if b'NO_PUBKEY' in output or BADSIG.search(output):
        raise AssertionError(f'{status} control produced an authentication result')
    releases = _rows(rows, 'release-transport')
    if (len(releases) != attempts * len(SUITES) or any(row['status'] != status for row in rows)
            or {row['path'] for row in releases} != {f'{BASE_PATH}{s}/InRelease' for s in SUITES}
            or any(sum(1 for row in releases if row['path'].endswith(f'/{s}/InRelease')) != attempts
                   for s in SUITES)):
        raise AssertionError(f'{status} request count/status differs from retry policy: {len(releases)}')
    return {'attempts_per_suite': attempts, 'fallback_requests': len(_rows(rows, 'fallback-transport'))}


# --------------------------------------------------------------------- runner

def identity(module):
    """Actual prepared APT/keyring identity; APT must be exactly the known 2.8.3."""
    def query(package):
        code, output = bounded(['/usr/bin/dpkg-query', '-W', '-f=${Version}', package], 10, env=module['ENV'])
        if code != 0:
            raise Refusal('prepared package identity query failed')
        return output.decode()
    release = Path('/etc/os-release').read_text().splitlines()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        raise Refusal('prepared Ubuntu 24.04 required')
    version = query('apt')
    if version != EXPECTED_APT:
        raise Refusal(f'prepared APT is not the attested {EXPECTED_APT}: {version!r}')
    keyring = query('ubuntu-keyring')
    return {'apt': version, 'ubuntu_keyring': keyring, 'keyring_sha256': digest(Path(KEY))}


def run_case(name, case, module, run=bounded, ownership=qemu_container.OwnedGroup):
    """One fresh owned workspace and server; real production-option ``apt-get update``."""
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-auth-', dir='/var/tmp') as temporary:
        root = Path(temporary)
        apt, config = qemu_offline.setup(root, SNAPSHOT)
        original = (root / 'sources.list').read_text()
        empty = root / 'empty.gpg'
        if case.key == 'empty':
            empty.write_bytes(b'')
        ledger = None
        code, output = None, b''
        try:
            with serve(case) as (base, ledger):
                (root / 'sources.list').write_text(
                    rewrite_sources(original, base, empty if case.key == 'empty' else None))
                env = dict(module['ENV'], APT_CONFIG=config)
                args = [*apt, *(DIAGNOSTIC if case.debug else []), *PRODUCTION_UPDATE]
                owned = ownership()
                started = time.monotonic()
                try:
                    code, output = run(args, CASE_SECONDS, limit=OUTPUT_LIMIT, env=env, on_start=owned.started)
                finally:
                    owned.verify()
                elapsed = round(time.monotonic() - started, 3)
        finally:
            rows = ledger.snapshot() if ledger is not None else []
            print(json.dumps({'auth_case': name, 'exit': code, 'ledger': summary(rows),
                              'diagnostics': public_diagnostics(output),
                              'server_write_is_not_client_receipt': True}), flush=True)
    return code, output, rows, elapsed


def summary(rows):
    return [dict(row) for row in rows]


def public_diagnostics(output):
    """Complete bounded controlled-public-fixture output, with unsafe lines withheld."""
    if not isinstance(output, bytes) or len(output) > OUTPUT_LIMIT:
        return '<unavailable>'
    return '\n'.join(line.decode('ascii') for line in output.split(b'\n')
                     if all(32 <= ch < 127 or ch == 9 for ch in line)
                     and not qemu_container.SENSITIVE.search(line))


def main(installer=None, fixtures=None, run=bounded):
    if os.geteuid() != 0:
        raise Refusal('root required')
    if {p.name for p in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise Refusal('disconnected loopback-only container required')
    intact = load_fixtures(FIXTURE_DIR) if fixtures is None else fixtures
    module = runpy.run_path(str(installer or Path(__file__).with_name('install-qemu.py')))
    retries = int(qemu_container.production_retries())
    packages = module['installed']()
    apt_before = qemu_offline.policy_files()
    report = {'native_auth_control': True, 'snapshot': SNAPSHOT, 'fixture_bytes': FIXTURE_TOTAL,
              'identity': identity(module), 'retries': retries, 'http_only_not_tls_proof': True,
              'qualification': 'UNQUALIFIED', 'not_full_qemu_suite': True}
    print(json.dumps(report, sort_keys=True), flush=True)
    try:
        report.update(controls(module, intact, 1 + retries, run))
    finally:
        if module['installed']() != packages:
            raise Refusal('installed packages changed')
        if qemu_offline.policy_files() != apt_before:
            raise Refusal('/etc/apt changed')
        print(json.dumps({'packages_unchanged': True, 'apt_configuration_unchanged': True,
                          'no_install_invoked': True, 'not_full_qemu_suite': True}), flush=True)


def controls(module, intact, attempts, run=bounded, ownership=qemu_container.OwnedGroup):
    """Ordered controls. The native positive boundary runs first and gates all others."""
    report = {}
    tampered = {suite: tamper(data) for suite, data in intact.items()}
    code, output, rows, elapsed = run_case('positive', Case('production', intact, index_absence=True, debug=True),
                                          module, run, ownership)
    try:
        report['positive'] = classify_positive(code, output, rows, intact)
    except AssertionError as exc:
        raise Refusal('native positive boundary UNQUALIFIED; empty-key control not relied upon: '
                      f'{exc} ledger={summary(rows)!r} output_tail={qemu_container.diagnostic_tail(output)!r}') from None
    report['positive']['seconds'] = elapsed
    cases = [
        ('empty_key', Case('empty', intact), lambda c, o, r: classify_empty_key(c, o, r, intact)),
        ('tampered_valid_key', Case('production', tampered), lambda c, o, r: classify_tamper(c, o, r, tampered)),
    ] + [(f'persistent_{status}', Case('empty', {}, status=status, fallback=True),
          (lambda s: lambda c, o, r: classify_transport(s, c, o, r, attempts))(status))
         for status in (502, 503)]
    for name, case, classify in cases:
        code, output, rows, elapsed = run_case(name, case, module, run, ownership)
        try:
            report[name] = classify(code, output, rows)
        except AssertionError as exc:
            raise Refusal(f'{name} control failed: {exc} ledger={summary(rows)!r} '
                          f'output_tail={qemu_container.diagnostic_tail(output)!r}') from None
        report[name]['seconds'] = elapsed
    return report


if __name__ == '__main__':
    if sys.argv[1:] != ['run']:
        raise SystemExit('usage: qemu_auth_control.py run')
    try:
        main()
    except (Refusal, OSError) as exc:
        print('qemu auth control: ' + str(exc), file=sys.stderr)
        sys.exit(1)
