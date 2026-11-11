"""Tests for the local signed-metadata authentication controls (#447 Tier 1).

AUTHORED WITHOUT EXECUTION. They use synthetic stand-in bytes only to exercise the
runner mechanics; real signed-bytes identity is checked only when the lead stages
the public fixtures (see test_staged_fixtures_match_public_identity). No test here
is, or claims to be, native APT proof: the actual native proof is the disconnected
container run of ``qemu_auth_control.py run`` and remains unrun.
"""
import hashlib
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

from hhfab_release import Refusal
import qemu_auth_control as auth
import qemu_container
import qemu_offline
import test_bridge_ipv4_harness as ownership

HERE = Path(__file__).parent
INSTALL = HERE / 'install-qemu.py'
SIGNED = (b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nSuite: noble\nSHA256:\n'
          b' ' + b'a' * 64 + b'      123 main/binary-amd64/Packages\n'
          b' ' + b'b' * 64 + b'       45 main/binary-amd64/Release\n'
          b'-----BEGIN PGP SIGNATURE-----\n\nSYNTHETICSIGNATUREBLOCK\n-----END PGP SIGNATURE-----\n')
NO_PUBKEY = b'W: GPG error: x InRelease: NO_PUBKEY 871920D1991BC93C\nE: The repository is not signed.\n'
BAD = b'W: GPG error: x InRelease: The following signatures were invalid: BADSIG 871920D1991BC93C\n'


def bodies(data=SIGNED):
    return {suite: data + suite.encode() for suite in auth.SUITES}


def release(n, suite, body, status=200, kind='release'):
    return {'n': n, 'method': 'GET', 'path': f'{auth.BASE_PATH}{suite}/InRelease', 'status': status,
            'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'kind': kind,
            'headers': [], 'attempted': True, 'completed': True, 'failure': None,
            'completed_bytes': len(body), 'completed_sha256': hashlib.sha256(body).hexdigest()}


def index(n, suite, name='main/binary-amd64/Packages.xz'):
    return {'n': n, 'method': 'GET', 'path': f'{auth.BASE_PATH}{suite}/{name}', 'status': 404,
            'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest(), 'kind': 'index-absence',
            'headers': [], 'attempted': True, 'completed': True, 'failure': None,
            'completed_bytes': 0, 'completed_sha256': hashlib.sha256(b'').hexdigest()}


def get(base, path, method='GET', headers=None):
    host, port = base.removeprefix('http://').split(':')
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        # Send only explicit headers; request() injects Content-Length: 0 for POST.
        conn.putrequest(method, path)
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


class IdentityAndFixtureTests(unittest.TestCase):
    def test_public_constants(self):
        self.assertEqual(sum(size for _, size, _ in auth.FIXTURES.values()), auth.FIXTURE_TOTAL)
        self.assertEqual(auth.FIXTURE_TOTAL, 508102)
        self.assertEqual({s: (n, z) for s, (n, z, _) in auth.FIXTURES.items()},
                         {'noble': ('noble.InRelease', 255850), 'noble-updates': ('noble-updates.InRelease', 126125),
                          'noble-security': ('noble-security.InRelease', 126127)})
        for _, _, sha in auth.FIXTURES.values():
            self.assertRegex(sha, '^[0-9a-f]{64}$')
        self.assertEqual(auth.SNAPSHOT, '20261024T000000Z')

    def test_sources_and_update_options_match_production_source(self):
        with tempfile.TemporaryDirectory() as directory:
            apt, _ = qemu_offline.setup(Path(directory), auth.SNAPSHOT)
            self.assertEqual((Path(directory) / 'sources.list').read_text(), auth.PRODUCTION_SOURCES)
        text = INSTALL.read_text()
        self.assertIn('SNAPSHOT = "' + auth.SNAPSHOT + '"', text)
        self.assertIn('"-o", "APT::Update::Error-Mode=any", "update"', text)
        self.assertEqual(auth.PRODUCTION_UPDATE, ['-o', 'APT::Update::Error-Mode=any', 'update'])
        self.assertIn('Acquire::Check-Valid-Until=true', ' '.join(apt))

    def test_missing_fixtures_fail_closed_without_fetch_or_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(Refusal, 'not staged'):
                auth.load_fixtures(Path(directory) / 'absent')
            with self.assertRaisesRegex(Refusal, 'mismatch'):
                auth.load_fixtures(Path(directory))

    def staged(self, directory, data):
        table = {}
        for suite, body in data.items():
            name = f'{suite}.InRelease'
            (Path(directory) / name).write_bytes(body)
            table[suite] = (name, len(body), hashlib.sha256(body).hexdigest())
        return table

    def test_loader_accepts_only_exact_bytes_and_set(self):
        data = bodies()
        with tempfile.TemporaryDirectory() as directory:
            table = self.staged(directory, data)
            total = sum(len(v) for v in data.values())
            with patch.object(auth, 'FIXTURES', table), patch.object(auth, 'FIXTURE_TOTAL', total):
                self.assertEqual(auth.load_fixtures(directory), data)
                (Path(directory) / 'extra').write_bytes(b'')
                with self.assertRaisesRegex(Refusal, 'set mismatch'):
                    auth.load_fixtures(directory)
                (Path(directory) / 'extra').unlink()
                (Path(directory) / 'noble.InRelease').write_bytes(data['noble'][:-1] + b'X')
                with self.assertRaisesRegex(Refusal, 'identity mismatch: noble'):
                    auth.load_fixtures(directory)

    def test_staged_fixtures_match_public_identity(self):
        loaded = auth.load_fixtures()
        self.assertEqual(sum(len(v) for v in loaded.values()), 508102)

    def test_prepared_identity_requires_exact_apt_and_successful_queries(self):
        module = {'ENV': {'PATH': '/usr/bin', 'LANG': 'C'}}
        with patch.object(Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"\n'), \
             patch.object(auth, 'digest', return_value='0' * 64):
            with patch.object(auth, 'bounded', side_effect=[(0, b'2.8.3'), (0, b'public-keyring-version')]):
                self.assertEqual(auth.identity(module)['apt'], '2.8.3')
            for result in ((0, b'2.8.30'), (0, b'2.8.3ubuntu1'), (1, b'2.8.3')):
                with patch.object(auth, 'bounded', return_value=result), self.assertRaises(Refusal):
                    auth.identity(module)
        with patch.object(Path, 'read_text', return_value='ID=debian\n'), \
             patch.object(auth, 'bounded', side_effect=AssertionError('query on wrong OS')):
            with self.assertRaisesRegex(Refusal, 'Ubuntu'):
                auth.identity(module)


class RewriteAndTamperTests(unittest.TestCase):
    BASE = 'http://127.0.0.1:41234'

    def test_rewrite_changes_only_uri_and_optionally_key(self):
        rewritten = auth.rewrite_sources(auth.PRODUCTION_SOURCES, self.BASE)
        self.assertEqual(rewritten.count(f'{self.BASE}/ubuntu/{auth.SNAPSHOT}/'), 3)
        self.assertNotIn('https://', rewritten)
        self.assertIn('signed-by=' + auth.KEY, rewritten)
        self.assertEqual([line.split()[2:] for line in rewritten.splitlines()],
                         [[f'{self.BASE}/ubuntu/{auth.SNAPSHOT}/', s, 'main', 'universe'] for s in auth.SUITES])
        empty = auth.rewrite_sources(auth.PRODUCTION_SOURCES, self.BASE, '/x/empty.gpg')
        self.assertEqual(empty.count('signed-by=/x/empty.gpg'), 3)
        self.assertNotIn(auth.KEY, empty)

    def test_changed_production_text_refuses(self):
        for text in (auth.PRODUCTION_SOURCES.replace('universe', 'multiverse'),
                     auth.PRODUCTION_SOURCES.replace('[signed-by=', '[trusted=yes signed-by='),
                     auth.PRODUCTION_SOURCES + 'deb http://x y z\n', ''):
            with self.subTest(text=text[:40]), self.assertRaisesRegex(Refusal, 'changed'):
                auth.rewrite_sources(text, self.BASE)

    def test_tamper_flips_exactly_one_cleartext_byte_and_keeps_envelope(self):
        result = auth.tamper(SIGNED)
        self.assertEqual(len(result), len(SIGNED))
        self.assertEqual(sum(1 for a, b in zip(SIGNED, result) if a != b), 1)
        begin = SIGNED.index(b'-----BEGIN PGP SIGNATURE-----')
        self.assertEqual(result[begin:], SIGNED[begin:])
        self.assertTrue(result.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n'))
        for bad in (b'no envelope', SIGNED.replace(b'a' * 64, b'zz').replace(b'b' * 64, b'zz')):
            with self.assertRaises(Refusal):
                auth.tamper(bad)


class ServerAndLedgerTests(unittest.TestCase):
    def test_exact_bytes_ledger_and_closed_route_table(self):
        data = bodies()
        case = auth.Case('production', data, index_absence=True)
        with auth.serve(case) as (base, ledger):
            path = f'{auth.BASE_PATH}noble/InRelease'
            self.assertEqual(get(base, path), (200, data['noble']))
            self.assertEqual(get(base, f'{auth.BASE_PATH}noble/main/binary-amd64/Packages.xz')[0], 404)
            self.assertEqual(get(base, '/elsewhere')[0], 404)
            self.assertEqual(get(base, path, 'POST'), (405, b''))
            self.assertEqual(get(base, path, headers={'If-Modified-Since': 'x'})[0], 404)
            self.assertEqual(get(base, f'{auth.BASE_PATH}noble/../x')[0], 404)
        rows = ledger.snapshot()
        kinds = [row['kind'] for row in rows]
        self.assertEqual(kinds[:3], ['release', 'index-absence', 'unexpected'])
        self.assertEqual(kinds[3:], ['unexpected'] * 3)
        self.assertEqual(rows[3]['status'], 405)
        self.assertNotIn('<other>', [name for name, _ in rows[3]['headers']])
        self.assertEqual(rows[0]['sha256'], hashlib.sha256(data['noble']).hexdigest())
        self.assertEqual(rows[0]['bytes'], len(data['noble']))
        self.assertEqual(rows[0]['completed_sha256'], rows[0]['sha256'])
        self.assertEqual(rows[0]['completed_bytes'], rows[0]['bytes'])
        self.assertLess(rows[0]['admitted_order'], rows[0]['attempt_order'])
        self.assertLess(rows[0]['attempt_order'], rows[0]['complete_order'])

    def test_forbidden_headers_override_method_refusal_and_remain_accounted(self):
        forbidden = {'Content-Length': '0', 'If-Modified-Since': 'x',
                     'If-None-Match': '"x"', 'Range': 'bytes=0-1', 'If-Range': 'x'}
        with auth.serve(auth.Case('production', bodies())) as (base, ledger):
            path = f'{auth.BASE_PATH}noble/InRelease'
            for method in ('GET', 'POST'):
                for name, value in forbidden.items():
                    with self.subTest(method=method, header=name):
                        self.assertEqual(get(base, path, method, {name: value}), (404, b''))
        rows = ledger.snapshot()
        self.assertEqual(len(rows), 2 * len(forbidden))
        self.assertEqual([row['method'] for row in rows],
                         ['GET'] * len(forbidden) + ['POST'] * len(forbidden))
        for row in rows:
            self.assertEqual((row['kind'], row['status']), ('unexpected', 404))
            self.assertIn(['<other>', '<redacted>'], row['headers'])
            self.assertTrue(row['attempted'])
            self.assertTrue(row['completed'])
            self.assertIsNone(row['failure'])
            self.assertEqual((row['bytes'], row['completed_bytes']), (0, 0))
            self.assertEqual(row['sha256'], hashlib.sha256(b'').hexdigest())
            self.assertEqual(row['completed_sha256'], row['sha256'])
            self.assertLess(row['attempt_order'], row['complete_order'])
        with self.assertRaisesRegex(AssertionError, 'unexplained request'):
            auth._no_unexpected(rows)

    def test_index_absence_only_when_allowed(self):
        with auth.serve(auth.Case('production', bodies())) as (base, ledger):
            get(base, f'{auth.BASE_PATH}noble/main/binary-amd64/Packages.xz')
        self.assertEqual(ledger.snapshot()[0]['kind'], 'unexpected')

    def test_transport_status_and_fallback_routes(self):
        for status in (502, 503):
            with auth.serve(auth.Case('empty', {}, status=status, fallback=True)) as (base, ledger):
                self.assertEqual(get(base, f'{auth.BASE_PATH}noble/InRelease')[0], status)
                self.assertEqual(get(base, f'{auth.BASE_PATH}noble/Release.gpg')[0], status)
                self.assertEqual(get(base, f'{auth.BASE_PATH}noble/main/x')[0], 404)
            self.assertEqual([r['kind'] for r in ledger.snapshot()],
                             ['release-transport', 'fallback-transport', 'unexpected'])

    def test_request_budget_and_owned_shutdown(self):
        with patch.object(auth, 'MAX_REQUESTS', 2):
            with auth.serve(auth.Case('production', bodies())) as (base, ledger):
                for _ in range(2):
                    get(base, f'{auth.BASE_PATH}noble/InRelease')
                with self.assertRaises((OSError, http.client.HTTPException)):
                    get(base, f'{auth.BASE_PATH}noble/InRelease')
                kinds = [r['kind'] for r in ledger.snapshot()]
        self.assertEqual(kinds, ['release', 'release', 'over-budget'])
        with self.assertRaises(OSError):
            get(base, '/')  # closed on exit; no persistent service

    def test_atomic_concurrent_admission_stops_at_terminal_overflow(self):
        ledger = auth.Ledger()
        barrier = threading.Barrier(3)
        admitted = []
        def admit():
            barrier.wait(timeout=2)
            admitted.append(ledger.admit())
        with patch.object(auth, 'MAX_REQUESTS', 2):
            threads = [threading.Thread(target=admit) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(admitted), [(0, False), (1, False), (2, True)])
            with self.assertRaisesRegex(Refusal, 'closed'):
                ledger.admit()
        self.assertEqual(len(ledger.snapshot()), 3)

    def test_write_attempt_is_not_completion_or_client_receipt(self):
        for outcome in (OSError('synthetic partial write'), 1):
            server = Mock(ledger=auth.Ledger())
            n, _ = server.ledger.admit()
            handler = object.__new__(auth.Handler)
            handler.server, handler.row = server, n
            handler.send_response_only = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.wfile = Mock()
            if isinstance(outcome, Exception):
                handler.wfile.write.side_effect = outcome
            else:
                handler.wfile.write.return_value = outcome
            handler._write(200, b'body')
            row = server.ledger.snapshot()[0]
            self.assertTrue(row['attempted'])
            self.assertFalse(row['completed'])
            self.assertIsNone(row['completed_bytes'])
            self.assertIsNone(row['completed_sha256'])
            self.assertEqual(row['failure'], 'write-failed')
            self.assertEqual(row['sha256'], hashlib.sha256(b'body').hexdigest())
            self.assertEqual(auth.summary([row]), [row])
            self.assertLess(row['attempt_order'], row['failure_order'])

    def test_malformed_and_unsupported_methods_are_accounted_without_request_secrets(self):
        with auth.serve(auth.Case('production', bodies())) as (base, ledger):
            port = int(base.rsplit(':', 1)[1])
            for request in (b'NOTHTTP\r\n\r\n', b'PATCH /private-SENTINEL HTTP/1.0\r\n\r\n'):
                with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                    client.sendall(request)
                    while client.recv(4096):
                        pass
        rows = ledger.snapshot()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['kind'] == 'unexpected' for row in rows))
        self.assertNotIn('SENTINEL', json.dumps(auth.summary(rows)))
        with self.assertRaises(AssertionError):
            auth._no_unexpected(rows)

    def test_shutdown_waits_for_accepted_handler_and_closes_partial_request(self):
        entered, release_handler, closed = threading.Event(), threading.Event(), threading.Event()
        original = auth.Handler.handle
        def gated(handler):
            entered.set()
            if not release_handler.wait(3):
                raise AssertionError('test handler gate')
            original(handler)
        server = auth.Server(auth.Case('production', bodies()))
        serving = threading.Thread(target=server.loop)
        failures = []
        def close():
            try:
                server.close_owned(serving)
            except BaseException as exc:
                failures.append(exc)
            finally:
                closed.set()
        with patch.object(auth.Handler, 'handle', gated):
            serving.start()
            closer = None
            try:
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b'GET /')
                    self.assertTrue(entered.wait(2))
                    closer = threading.Thread(target=close)
                    closer.start()
                    self.assertEqual(client.recv(1), b'')
                    self.assertFalse(closed.is_set())  # handler is still gated
            finally:
                release_handler.set()
                if closer is None:
                    close()
                else:
                    closer.join(4)
        self.assertTrue(closed.is_set())
        self.assertEqual(failures, [])
        self.assertFalse(serving.is_alive())
        self.assertTrue(all(not t.is_alive() for t in server.handlers))
        self.assertEqual(server.sockets, {})
        row = server.ledger.snapshot()[0]
        self.assertTrue(row['kind'] in ('unexpected', 'incomplete') or row['failure'] is not None)

    def test_headers_are_bounded_and_unknown_values_withheld(self):
        with auth.serve(auth.Case('production', bodies())) as (base, ledger):
            get(base, f'{auth.BASE_PATH}noble/InRelease', headers={'X-Test': 'synthetic-SENTINEL'})
            get(base, f'{auth.BASE_PATH}noble/InRelease',
                headers={'User-Agent': 'Debian APT-HTTP/' + '1' * 200 + ' (2.8.3)'})
        rows = ledger.snapshot()
        row = rows[0]
        self.assertEqual(row['kind'], 'unexpected')
        self.assertIn(['<other>', '<redacted>'], row['headers'])
        self.assertNotIn('SENTINEL', json.dumps(row))
        self.assertTrue(row['completed'])
        self.assertEqual(rows[1]['kind'], 'unexpected')
        self.assertTrue(all(len(value) <= 128 for row in rows for _, value in row['headers']))


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.intact = bodies()
        self.tampered = {s: auth.tamper(b) for s, b in self.intact.items()}

    def releases(self, data, status=200):
        return [release(i, s, data[s]) for i, s in enumerate(auth.SUITES)]

    def positive_rows(self):
        rows = self.releases(self.intact)
        for suite in auth.SUITES:
            rows.append(index(len(rows), suite))
        return rows

    GOOD = b'GOODSIG\nVALIDSIG\n' * 3

    def test_positive_requires_all_evidence(self):
        rows = self.positive_rows()
        # Global tokens and request order are specifically NOT native correlation.
        with self.assertRaisesRegex(AssertionError, 'UNQUALIFIED'):
            auth.classify_positive(100, self.GOOD, rows, self.intact)
        bad = {
            'update succeeded': (0, self.GOOD, rows),
            'no pubkey': (100, self.GOOD + NO_PUBKEY, rows),
            'bad signature': (100, self.GOOD + BAD, rows),
            'expired': (100, self.GOOD + b'Release file has expired', rows),
            'no per-suite goodsig': (100, b'GOODSIG\nVALIDSIG\n', rows),
            'missing index scheduling': (100, self.GOOD, rows[:5]),
            'index before release': (100, self.GOOD, [index(-1, 'noble')] + rows[:3] + rows[4:]),
            'wrong bytes': (100, self.GOOD, [release(0, 'noble', b'other')] + rows[1:]),
            'unexpected request': (100, self.GOOD, rows + [dict(index(9, 'noble'), kind='unexpected')]),
            'duplicate release': (100, self.GOOD, rows + [release(9, 'noble', self.intact['noble'])]),
        }
        for name, (code, output, data) in bad.items():
            with self.subTest(name), self.assertRaises(AssertionError):
                auth.classify_positive(code, output, data, self.intact)

    def test_empty_key_requires_genuine_no_pubkey_and_only_three_200s(self):
        rows = self.releases(self.intact)
        auth.classify_empty_key(100, NO_PUBKEY, rows, self.intact)
        bad = {
            'success': (0, NO_PUBKEY, rows),
            'non-native exit': ('failure', NO_PUBKEY, rows),
            'transport': (100, b'Err 502  Bad Gateway\n', rows),
            'mixed bad signature': (100, NO_PUBKEY + BAD, rows),
            'extra request': (100, NO_PUBKEY, rows + [index(9, 'noble')]),
            'two releases': (100, NO_PUBKEY, rows[:2]),
            'mixed transport': (100, NO_PUBKEY, [dict(rows[0], status=503, kind='release-transport')] + rows[1:]),
            'tampered bytes': (100, NO_PUBKEY, self.releases(self.tampered)),
            'all 200 but transport bytes': (100, NO_PUBKEY + b'503 Service Unavailable', rows),
            'all 200 but timeout bytes': (100, NO_PUBKEY + b'Connection timed out', rows),
            'incomplete write': (100, NO_PUBKEY, [dict(rows[0], completed=False)] + rows[1:]),
            'failed write': (100, NO_PUBKEY, [dict(rows[0], failure='write-failed')] + rows[1:]),
            'wrong completed hash': (100, NO_PUBKEY, [dict(rows[0], completed_sha256='0' * 64)] + rows[1:]),
            'short completed body': (100, NO_PUBKEY, [dict(rows[0], completed_bytes=1)] + rows[1:]),
        }
        for name, (code, output, data) in bad.items():
            with self.subTest(name), self.assertRaises(AssertionError):
                auth.classify_empty_key(code, output, data, self.intact)

    def test_tamper_requires_explicit_integrity_refusal_not_empty_key_failure(self):
        rows = self.releases(self.tampered)
        auth.classify_tamper(100, BAD, rows, self.tampered)
        bad = {
            'accepted': (0, BAD, rows),
            'masked as empty key': (100, NO_PUBKEY, rows),
            'both': (100, NO_PUBKEY + BAD, rows),
            'unrelated': (100, b'something\n', rows),
            'intact delivered': (100, BAD, self.releases(self.intact)),
            'extra request': (100, BAD, rows + [index(9, 'noble')]),
            'transport mixed': (100, BAD + b'502 Bad Gateway', rows),
            'ambiguous good signature': (100, BAD + b'GOODSIG\nVALIDSIG', rows),
        }
        for name, (code, output, data) in bad.items():
            with self.subTest(name), self.assertRaises(AssertionError):
                auth.classify_tamper(code, output, data, self.tampered)

    def test_persistent_502_503_remain_rejected_by_unchanged_predicate(self):
        for status, text in ((502, b'502  Bad Gateway'), (503, b'503  Service Unavailable')):
            output = b'Err:1 http://x InRelease\n  ' + text + b'\n'
            with self.assertRaisesRegex(AssertionError, 'transport-only'):
                qemu_container.signature_proof(100, output)
            rows = []
            for attempt in range(2):
                for suite in auth.SUITES:
                    rows.append(release(len(rows), suite, b'', status, 'release-transport'))
            self.assertEqual(auth.classify_transport(status, 100, output, rows, 2)['attempts_per_suite'], 2)
            for name, (code, out, data) in {
                    'signature proof': (100, NO_PUBKEY, rows),
                    'non-native exit': ('failure', output, rows),
                    'success': (0, output, rows),
                    'fewer attempts': (100, output, rows[:-1]),
                    'wrong status': (100, output, [dict(r, status=500) for r in rows]),
                    'bad signature': (100, output + BAD, rows)}.items():
                with self.subTest(status=status, name=name), self.assertRaises(AssertionError):
                    auth.classify_transport(status, code, out, data, 2)


class RunCaseTests(unittest.TestCase):
    """The fake runner performs real loopback HTTP requests against the real rewritten
    sources; it is not an APT model and proves only harness mechanics."""
    def module(self):
        return {'ENV': {'PATH': '/usr/bin', 'LANG': 'C'}}

    class Owner:
        started_with = None
        def started(self, pid):
            pass
        def verify(self):
            pass

    def test_sources_options_env_and_cleanup(self):
        seen = {}
        data = bodies()
        def fake(args, seconds, limit=0, env=None, on_start=None):
            options = dict(a.split('=', 1) for a in args if '=' in a and not a.startswith('-'))
            source = Path(options['Dir::Etc::sourcelist'])
            seen.update(args=args, env=env, seconds=seconds, text=source.read_text(), root=source.parent)
            base = re.search(r'(http://127\.0\.0\.1:\d+)/ubuntu', seen['text']).group(1)
            for suite in auth.SUITES:
                get(base, f'{auth.BASE_PATH}{suite}/InRelease')
            return 100, NO_PUBKEY
        code, output, rows, _ = auth.run_case('empty', auth.Case('empty', data), self.module(), fake, self.Owner)
        self.assertEqual((code, output), (100, NO_PUBKEY))
        self.assertEqual(seen['args'][-3:], auth.PRODUCTION_UPDATE)
        self.assertNotIn('install', seen['args'])
        self.assertFalse(any(a.startswith('Debug::') for a in seen['args']))
        self.assertEqual(seen['env']['APT_CONFIG'], str(seen['root'] / 'fixed.conf'))
        self.assertLessEqual(seen['seconds'], 25)
        self.assertIn('empty.gpg', seen['text'])
        self.assertNotIn('https://', seen['text'])
        self.assertFalse(seen['root'].exists())
        self.assertEqual([r['kind'] for r in rows], ['release'] * 3)

    def test_positive_probe_alone_adds_diagnostics(self):
        captured = []
        def fake(args, seconds, limit=0, env=None, on_start=None):
            captured.append(args)
            return 100, b''
        auth.run_case('p', auth.Case('production', bodies(), debug=True, index_absence=True),
                      self.module(), fake, self.Owner)
        auth.run_case('n', auth.Case('production', bodies()), self.module(), fake, self.Owner)
        self.assertEqual(captured[0][-3:], auth.PRODUCTION_UPDATE)
        self.assertEqual(len([a for a in captured[0] if a.startswith('Debug::')]), 2)
        self.assertEqual([a for a in captured[1] if a.startswith('Debug::')], [])

    def test_runner_failure_still_cleans_owned_resources(self):
        captured = io.StringIO()
        def fake(args, seconds, limit=0, env=None, on_start=None):
            source = Path(next(a.split('=', 1)[1] for a in args if a.startswith('Dir::Etc::sourcelist=')))
            base = re.search(r'(http://127\.0\.0\.1:\d+)/ubuntu', source.read_text()).group(1)
            get(base, f'{auth.BASE_PATH}noble/InRelease')
            raise Refusal('command timeout')
        with contextlib.redirect_stdout(captured), self.assertRaisesRegex(Refusal, 'timeout'):
            auth.run_case('x', auth.Case('production', bodies()), self.module(), fake, self.Owner)
        report = json.loads(captured.getvalue())
        self.assertEqual(len(report['ledger']), 1)
        row = report['ledger'][0]
        self.assertTrue(row['completed'])
        self.assertEqual(row['completed_sha256'], hashlib.sha256(bodies()['noble']).hexdigest())
        self.assertEqual(len(row['sha256']), 64)
        self.assertTrue(report['server_write_is_not_client_receipt'])

    def test_public_diagnostics_retains_bounded_safe_capture_not_only_tail(self):
        output = b'first\n' + b'native evidence\n' * 100 + b'last\n'
        self.assertEqual(auth.public_diagnostics(output), output.decode())
        self.assertEqual(auth.public_diagnostics(b'Authorization: synthetic-SENTINEL\nsafe\x00bad\nsafe\n'),
                         'safe\n')
        self.assertEqual(auth.public_diagnostics(b'x' * (auth.OUTPUT_LIMIT + 1)), '<unavailable>')


class ControlsOrderingTests(unittest.TestCase):
    def test_positive_unqualified_stops_before_any_other_control(self):
        calls = []
        def fake_run_case(name, case, module, run, ownership):
            calls.append(name)
            return 0, b'', [], 0.0
        with patch.object(auth, 'run_case', fake_run_case), self.assertRaisesRegex(Refusal, 'UNQUALIFIED'):
            auth.controls({}, bodies(), 2)
        self.assertEqual(calls, ['positive'])

    def test_all_controls_run_in_order_when_each_classifies(self):
        data = bodies()
        tampered = {s: auth.tamper(b) for s, b in data.items()}
        order = []
        def rows_for(name):
            if name == 'positive':
                rows = [release(i, s, data[s]) for i, s in enumerate(auth.SUITES)]
                return 100, b'GOODSIG\nVALIDSIG\n' * 3, rows + [index(3 + i, s) for i, s in enumerate(auth.SUITES)]
            if name == 'empty_key':
                return 100, NO_PUBKEY, [release(i, s, data[s]) for i, s in enumerate(auth.SUITES)]
            if name == 'tampered_valid_key':
                return 100, BAD, [release(i, s, tampered[s]) for i, s in enumerate(auth.SUITES)]
            status = int(name[-3:])
            text = b'%d  Bad Gateway' % status if status == 502 else b'%d  Service Unavailable' % status
            return 100, text, [release(i, s, b'', status, 'release-transport')
                               for i, s in enumerate(auth.SUITES * 2)]
        def fake_run_case(name, case, module, run, ownership):
            order.append(name)
            code, output, rows = rows_for(name)
            return code, output, rows, 0.1
        # This mock tests orchestration only, never a fabricated native parser pass.
        with patch.object(auth, 'run_case', fake_run_case), \
             patch.object(auth, 'classify_positive', return_value={'orchestration_only': True}):
            report = auth.controls({}, data, 2)
        self.assertEqual(order, ['positive', 'empty_key', 'tampered_valid_key', 'persistent_502', 'persistent_503'])
        self.assertEqual(list(report), order)

    def test_main_refuses_when_fixtures_are_not_staged(self):
        with patch('os.geteuid', return_value=0), \
             patch.object(Path, 'iterdir', return_value=iter([Path('/sys/class/net/lo')])), \
             patch.object(auth, 'FIXTURE_DIR', Path('/nonexistent-labapp-fixtures')), \
             patch.object(auth, 'controls', side_effect=AssertionError('controls ran')):
            with self.assertRaisesRegex(Refusal, 'not staged'):
                auth.main()


class LauncherTests(unittest.TestCase):
    SCRIPT = HERE / 'test-qemu.sh'

    def run_harness(self, mode, fail_auth=False, auth_only=False):
        fake_source = ownership.FAKE_DOCKER.replace("elif a[0] == 'start':", "elif a[0] == 'cp':\n    pass\nelif a[0] == 'start':")
        if fail_auth:
            fake_source = fake_source.replace(
                "elif a[0] == 'inspect':\n    print('0')",
                "elif a[0] == 'inspect':\n    print('1' if 'auth' in s['containers'].get(a[-1], {}).get('name', '') else '0')")
            self.assertIn("'auth' in", fake_source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'docker'
            fake.write_text(fake_source)
            fake.chmod(0o755)
            state_path = root / 'state.json'
            state_path.write_text(json.dumps({'containers': {}, 'images': {}, 'calls': []}))
            host_config = root / 'synthetic-host-config'
            host_config.mkdir()
            sentinel_config = '{"proxies":{"default":{"httpProxy":"http://synthetic-SENTINEL.invalid"}}}'
            (host_config / 'config.json').write_text(sentinel_config)
            # Test-copy only: fixed absolute fake binary and synthetic environment.
            # The production launcher has no executable, config or daemon override.
            script = root / 'test-qemu.sh'
            source = self.SCRIPT.read_text().replace('[[ -x /usr/bin/docker ]]', 'true')
            fake_source = fake.read_text().replace(
                "s['calls'].append(a)",
                "s['calls'].append(a)\n"
                "assert os.environ.get('HTTP_PROXY') is None\n"
                "assert os.environ.get('DOCKER_CONTEXT') is None\n"
                "assert Path(os.environ['DOCKER_CONFIG'], 'config.json').read_text() == '{}\\n'\n"
                "assert os.environ['DOCKER_CONFIG'] != os.environ.get('SYNTHETIC_HOST_CONFIG')\n")
            fake.write_text(fake_source)
            source = source.replace('/usr/bin/docker --host unix:///var/run/docker.sock',
                                    f'FAKE_DOCKER_STATE={state_path} FAKE_DOCKER_MODE={mode} {fake}')
            script.write_text(source)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       FAKE_DOCKER_STATE=str(state_path), FAKE_DOCKER_MODE=mode,
                       DOCKER_CONFIG=str(root / 'synthetic-host-config'), DOCKER_CONTEXT='SENTINEL',
                       HTTP_PROXY='http://synthetic-SENTINEL.invalid')
            result = subprocess.run(['bash', str(script)] + (['--auth-only'] if auth_only else []),
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual((host_config / 'config.json').read_text(), sentinel_config)
            self.assertNotIn('SENTINEL', result.stdout + result.stderr)
            return result, json.loads(state_path.read_text())

    def test_one_disconnected_root_auth_container_between_prep_and_runtime(self):
        result, state = self.run_harness('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        creates = [a for a in state['calls'] if a[0] == 'create']
        names = [a[a.index('--name') + 1] for a in creates]
        kinds = ['prep' if 'prep' in n else 'auth' if 'auth' in n else 'runtime' for n in names]
        self.assertEqual(kinds, ['prep', 'auth', 'runtime', 'prep', 'runtime'])
        args = creates[1]
        for flag in ('--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=0:0',
                     '--memory=768m', '--cpus=1', '--pids-limit=128', '--init', '--cap-add=KILL'):
            self.assertIn(flag, args)
        for forbidden in ('--privileged', '--read-only'):
            self.assertNotIn(forbidden, args)
        self.assertFalse(any(a.startswith(('--volume', '--mount', '--device', '--network=host', '-v'))
                             for a in args))
        self.assertEqual(args[args.index('timeout'):args.index('timeout') + 3], ['timeout', '--kill-after=3s', '150s'])
        self.assertEqual(args[-2:], ['/suite/qemu_auth_control.py', 'run'])

    def test_auth_only_never_invokes_qemu_install_or_runtime(self):
        result, state = self.run_harness('success', auth_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        creates = [a for a in state['calls'] if a[0] == 'create']
        self.assertEqual(len(creates), 2)
        self.assertNotIn('qemu_container.py', ' '.join(' '.join(a) for a in creates))
        self.assertIn('ubuntu-keyring', creates[0][-1])
        self.assertIn('NOT a full-suite result', result.stdout)
        result, _ = self.run_harness('success', fail_auth=True, auth_only=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('controls qualified', result.stdout)

    def test_fixed_docker_client_prerequisites_have_no_host_config_or_endpoint_override(self):
        text = self.SCRIPT.read_text()
        self.assertIn('/usr/bin/env -i', text)
        self.assertIn('/usr/bin/docker --host unix:///var/run/docker.sock', text)
        self.assertIn('PATH=/usr/sbin:/usr/bin:/sbin:/bin', text)
        self.assertNotIn('${DOCKER_CONFIG', text)
        self.assertNotIn('${DOCKER_HOST', text)

    def test_auth_failure_fails_suite_and_removes_owned_resources(self):
        result, state = self.run_harness('success', fail_auth=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(o['name'].endswith('-foreign') for o in state['containers'].values()))

    def test_suite_pass_requires_auth_stage_in_source(self):
        text = self.SCRIPT.read_text()
        self.assertIn('[[ "$auth_runs" == 1 && "$lane_failed" == 0 ]]', text)
        self.assertEqual(text.count('qemu_auth_control.py run'), 1)
        self.assertLess(text.index('qemu_auth_control.py run'), text.index('qemu_container.py runtime'))

    def test_online_empty_key_control_is_replaced_not_duplicated(self):
        source = (HERE / 'qemu_container.py').read_text()
        self.assertNotIn('rejected_trust', source)
        self.assertNotIn('empty.gpg', source)
        self.assertIn('def signature_proof', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
