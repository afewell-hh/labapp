"""Offline tests for kubectl_readiness_proof.py: no kubectl, Docker, TLS, OpenSSL or external network.

They exercise the harness logic only (loopback plain-socket fixture on an ephemeral port, fake
production callables, fake clocks). They prove nothing about the real pinned kubectl; the actual
timing evidence comes only from separately authorized execution of test-kubectl-readiness.sh.
"""
import copy
import http.client
import json
from pathlib import Path
import re
import socket
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

import kubectl_readiness_proof as proof
import vlab_core as core

SECRET = b'PRIVATE-CHILD-OUTPUT-MARKER'


def get(fixture, path='/readyz?timeout=10s'):
    connection = http.client.HTTPConnection(proof.HOST, fixture.port, timeout=3)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


class FixtureTests(unittest.TestCase):
    def fixture(self, steps, mode='serve'):
        fixture = proof.Fixture(port=0)
        self.addCleanup(fixture.close)
        fixture.start(steps, mode)
        return fixture

    def test_ok_step_records_request_and_closes_cleanly(self):
        fixture = self.fixture([proof.OK()])
        status, _, body = get(fixture)
        cleanup = fixture.close()
        self.assertEqual((status, body), (200, b'ok'))
        request = fixture.requests[0]
        self.assertEqual((request['n'], request['method'], request['path'], request['query'], request['step']),
                         (1, 'GET', '/readyz', 'timeout=10s', 'ok'))
        self.assertTrue(cleanup['listener_closed'])
        self.assertEqual(cleanup['threads_alive'], 0)

    def test_scripted_sequence_is_by_request_index_and_last_step_repeats(self):
        fixture = self.fixture([proof.STATUS(429, 'Too Many Requests', 'TooManyRequests', '30'), proof.OK()])
        first, second, third = get(fixture), get(fixture), get(fixture)
        fixture.close()
        self.assertEqual((first[0], first[1].get('Retry-After')), (429, '30'))
        self.assertEqual(json.loads(first[2])['reason'], 'TooManyRequests')
        self.assertEqual((second[0], third[0]), (200, 200))
        self.assertEqual([r['n'] for r in fixture.requests], [1, 2, 3])

    def test_plaintext_readyz_failure_has_exact_public_multiline_body(self):
        fixture = self.fixture([proof.HEALTH_500])
        code, headers, body = get(fixture)
        cleanup = fixture.close()
        self.assertEqual(code, 500)
        self.assertEqual(headers['Content-Type'], 'text/plain; charset=utf-8')
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertNotIn('Retry-After', headers)
        self.assertEqual(body, b'[+]ping ok\n[-]informer-sync failed: reason withheld\nreadyz check failed\n')
        request = fixture.requests[0]
        self.assertEqual((request['response_code'], request['body_bytes_sent']), (500, len(body)))
        self.assertEqual(request['response_body_sha256'], proof.hashlib.sha256(body).hexdigest())
        self.assertEqual(cleanup['threads_alive'], 0)

    def test_k3s_prehandler_is_negotiated_status_not_plaintext_then_ready(self):
        fixture = self.fixture([proof.K3S_503, proof.OK()])
        code, headers, body = get(fixture)
        ready = get(fixture)
        cleanup = fixture.close()
        self.assertEqual((code, headers['Content-Type']), (503, 'application/json'))
        self.assertNotIn('Retry-After', headers)
        self.assertEqual(json.loads(body), {'kind': 'Status', 'apiVersion': 'v1', 'metadata': {},
                                          'status': 'Failure', 'message': 'apiserver not ready',
                                          'reason': 'ServiceUnavailable', 'code': 503})
        self.assertEqual((ready[0], ready[2]), (200, b'ok'))
        self.assertEqual([r['response_code'] for r in fixture.requests], [503, 200])
        self.assertEqual(cleanup['threads_alive'], 0)

    def test_request_text_is_sanitized_and_bounded(self):
        fixture = self.fixture([proof.OK()])
        get(fixture, '/a%20b?x=' + 'y' * 400)
        fixture.close()
        self.assertEqual(fixture.requests[0]['path'], '/a%20b')
        self.assertLessEqual(len(fixture.requests[0]['query']), 128)

    def test_header_stall_sends_nothing_and_close_releases_the_handler(self):
        fixture = self.fixture([proof.STALL_HEADER])
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        self.addCleanup(sock.close)
        sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual(cleanup['threads_alive'], 0)
        self.assertEqual(fixture.requests[0]['step'], 'stall-before-response-header')

    def test_body_stall_sends_headers_and_partial_body_only(self):
        fixture = self.fixture([proof.STALL_BODY])
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        self.addCleanup(sock.close)
        sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n')
        data = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        cleanup = fixture.close()
        sock.close()
        self.assertTrue(data.startswith(b'HTTP/1.1 200 OK'))
        self.assertTrue(data.endswith(b'\r\n\r\nok'))
        self.assertIn(b'Content-Length: 100000', data)
        self.assertEqual(cleanup['threads_alive'], 0)

    def test_backlog_mode_listens_but_never_serves(self):
        fixture = self.fixture([proof.OK()], 'backlog')
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        self.addCleanup(sock.close)
        sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual((fixture.requests, cleanup['connections_accepted']), ([], 0))

    def test_tls_stall_mode_reads_the_first_bytes_and_never_answers(self):
        fixture = self.fixture([proof.OK()], 'tls-stall')
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        self.addCleanup(sock.close)
        sock.sendall(b'\x16\x03\x01\x00\x05hello')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual((fixture.requests, cleanup['threads_alive']), ([], 0))

    def test_closed_listener_is_really_closed(self):
        fixture = self.fixture([proof.OK()])
        port = fixture.port
        fixture.close()
        with self.assertRaises(OSError):
            socket.create_connection((proof.HOST, port), timeout=1)

    def test_oversize_step_exceeds_the_production_output_limit(self):
        step = proof.HUGE(1024 * 1024 + 4096)
        self.assertGreater(len(step['body']), core.LIMIT)
        self.assertEqual(core.LIMIT, 1024 * 1024)

    def test_close_settles_acceptor_before_final_handler_and_socket_inventory(self):
        fixture = proof.Fixture(port=0)
        self.addCleanup(fixture.close)
        conn, peer = socket.socketpair()
        self.addCleanup(conn.close)
        self.addCleanup(peer.close)
        handler = Mock()
        handler.is_alive.return_value = False

        def finish_accept(_timeout):
            # Deterministic late registration during acceptor.join(), after close began.
            fixture.threads.append(handler)
            fixture.sockets.add(conn)
        fixture.acceptor = Mock()
        fixture.acceptor.join.side_effect = finish_accept
        fixture.acceptor.is_alive.return_value = False
        cleanup = fixture.close()
        handler.join.assert_called_once()
        self.assertEqual(conn.fileno(), -1)
        self.assertTrue(cleanup['sockets_closed'])
        self.assertEqual(cleanup['threads_alive'], 0)
        fixture.acceptor = None

    def test_unsettled_acceptor_can_never_report_clean(self):
        fixture = proof.Fixture(port=0)
        self.addCleanup(fixture.close)
        fixture.acceptor = Mock()
        fixture.acceptor.is_alive.return_value = True
        self.assertGreater(fixture.close()['threads_alive'], 0)

    def test_handler_cannot_replace_tracked_socket_after_stop(self):
        context = Mock()
        fixture = proof.Fixture(port=0, context=context)
        self.addCleanup(fixture.close)
        conn, peer = socket.socketpair()
        self.addCleanup(conn.close)
        self.addCleanup(peer.close)
        fixture.sockets.add(conn)
        fixture.stop.set()
        fixture._serve(conn)
        context.wrap_socket.assert_not_called()
        self.assertEqual(conn.fileno(), -1)
        self.assertFalse(fixture.sockets)


class AttemptTests(unittest.TestCase):
    def call(self, outcome):
        def kubectl(args, deadline, route):
            self.assertEqual((args, route), (['get', '--raw=/readyz'], 'api-initial-readyz'))
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return proof.attempt(core, kubectl, 1000.0, clock=lambda: 990.0)

    def failure(self, message, code, output=b'', cls=core.Failure, route='api-initial-readyz'):
        error = cls(message, code, output)
        error.route = route
        return error

    def test_ok_and_non_ok_success_are_distinct(self):
        self.assertEqual(self.call(b'ok\n')['kind'], 'ok')
        self.assertEqual(self.call(b'nope')['kind'], 'success-non-ok')

    def test_pending_failure_and_124_are_never_conflated(self):
        refused = (b'The connection to the server 127.0.0.1:6443 was refused - '
                   b'did you specify the right host or port?\n')
        with patch.object(core, 'execute', side_effect=core.Failure('child command failed', 1, refused)):
            pending = proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0)
        deadline = self.call(self.failure('child deadline exceeded', 124))
        self.assertEqual((pending['kind'], pending['code'], pending['route'],
                          pending['private_output_bytes']), ('pending', 1, None, 0))
        self.assertFalse(any(pending['flags'].values()))
        self.assertEqual((deadline['kind'], deadline['code']), ('failure', 124))

    def test_matching_transient_uncertainty_is_fatal_even_if_classifier_discards_it(self):
        error = core.Failure('child command failed', 1, b'Error from server (ServiceUnavailable): fixture\n')
        error.cleanup_uncertain = True
        with patch.object(core, 'execute', side_effect=error):
            record = proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0)
        self.assertTrue(record['cleanup_uncertain'])
        self.assertEqual(proof.verdict(spec(allowed=None), [record], {'requests': []},
                                       VerdictAndCaseTests.EVIDENCE)[0], 'failed')

    def test_unknown_error_and_124_stay_fatal_through_unchanged_classifier(self):
        for error in (core.Failure('child command failed', 1, b'unknown fixture error'),
                      core.Failure('child deadline exceeded', 124)):
            error._executed_child = True
            with patch.object(core, 'execute', side_effect=error):
                record = proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0)
            self.assertEqual((record['kind'], record['code'], record['route']),
                             ('failure', error.code, 'api-initial-readyz'))

    def test_cleanup_uncertainty_and_route_are_preserved(self):
        error = self.failure('child command failed', 1, b'x509: certificate signed by unknown authority')
        error.cleanup_uncertain = True
        record = self.call(error)
        self.assertTrue(record['cleanup_uncertain'])
        self.assertTrue(record['flags']['x509'])
        self.assertEqual(record['route'], 'api-initial-readyz')

    def test_report_never_contains_child_output(self):
        record = self.call(self.failure('child command failed', 1, SECRET + b' Unauthorized'))
        self.assertTrue(record['flags']['unauthorized'])
        self.assertNotIn('PRIVATE-CHILD', json.dumps(record))
        self.assertEqual(record['private_output_bytes'], len(SECRET) + len(b' Unauthorized'))

    def test_harness_error_is_reported_by_class_only(self):
        record = self.call(KeyError('secret detail'))
        self.assertEqual((record['kind'], record['message']), ('harness-error', 'KeyError'))
        self.assertNotIn('secret', json.dumps(record))


def fake_fixture_factory(requests=(), cleanup=None):
    class Fake:
        def __init__(self, context=None, clock=None):
            self.requests = list(requests)
            self.started = None

        def start(self, steps, mode):
            self.started = (len(steps), mode)

        def close(self, deadline=None):
            return cleanup or {'listener_closed': True, 'threads_alive': 0,
                               'sockets_closed': True, 'connections_accepted': len(requests),
                               'handshakes_started': len(requests), 'handshakes_completed': len(requests),
                               'clienthello_bytes': 0, 'server_errors': {}}
    return Fake


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def spec(**overrides):
    base = proof.case('t', [proof.OK()], allowed={('ok', None)})
    base.update(overrides)
    return base


def attempts_of(*rows):
    return [dict(kind=k, code=c, message=m, flags={}, private_output_bytes=0,
                 route='api-initial-readyz' if k == 'failure' else None,
                 server_started=False) for k, c, m in rows]


class VerdictAndCaseTests(unittest.TestCase):
    EVIDENCE = {'elapsed': 1.0, 'request_count': 1,
                'cleanup': {'listener_closed': True, 'threads_alive': 0, 'sockets_closed': True},
                'owned_uid_processes_after': 0}

    def test_allowed_outcome_passes_and_unlisted_outcome_fails(self):
        self.assertEqual(proof.verdict(spec(), attempts_of(('ok', None, '')), {'requests': [
            {'path': '/readyz', 'client_cn': proof.CLIENT_CN}]}, self.EVIDENCE)[0], 'passed')
        for bad in (('pending', 1, 'API discovery pending'), ('failure', 124, 'child deadline exceeded')):
            result, reasons = proof.verdict(spec(name='x'), attempts_of(bad), {'requests': []}, self.EVIDENCE)
            self.assertEqual(result, 'failed')
            self.assertIn('final outcome not in the allowed set', reasons)

    def test_ok_case_requires_a_verified_mtls_request(self):
        result, reasons = proof.verdict(spec(name='ok-ready', requests=(1, 1)), attempts_of(('ok', None, '')),
                                        {'requests': [{'path': '/readyz', 'client_cn': None}]}, self.EVIDENCE)
        self.assertEqual(result, 'failed')
        self.assertIn('request lacks matching connection and verified mTLS evidence', reasons)

    def test_observation_only_case_is_recorded_not_passed(self):
        result, _ = proof.verdict(spec(name='x', allowed=None), attempts_of(('failure', 1, 'child command failed')),
                                  {'requests': []}, self.EVIDENCE)
        self.assertEqual(result, 'recorded')

    def test_window_cleanup_and_leftover_process_each_fail_a_case(self):
        for change, text in (({'elapsed': 99.0}, 'elapsed outside the case window'),
                             ({'cleanup': {'listener_closed': True, 'threads_alive': 1}}, 'fixture cleanup incomplete'),
                             ({'owned_uid_processes_after': 2}, 'ubuntu-uid process remained in the container')):
            evidence = {**self.EVIDENCE, **change}
            result, reasons = proof.verdict(spec(name='x', allowed=None), attempts_of(('failure', 1, 'm')),
                                            {'requests': []}, evidence)
            self.assertEqual(result, 'failed')
            self.assertIn(text, reasons)

    def test_retry_loop_requires_exact_pending_then_ready(self):
        loop = spec(loop=True, pre_final={('pending', 1)}, min_pending=1)
        good = attempts_of(('pending', 1, 'API discovery pending'), ('pending', 1, 'API discovery pending'),
                           ('ok', None, ''))
        self.assertEqual(proof.verdict(loop, good, {'requests': [{'path': '/readyz', 'client_cn': proof.CLIENT_CN}]},
                                       self.EVIDENCE)[0], 'passed')
        for rows in ((('ok', None, ''),), (('failure', 124, 'm'), ('ok', None, ''))):
            self.assertEqual(proof.verdict(loop, attempts_of(*rows), {'requests': []}, self.EVIDENCE)[0], 'failed')

    def test_run_case_keeps_one_absolute_deadline_and_loops_only_on_pending(self):
        clock, seen = Clock(), []

        def kubectl(args, deadline, route):
            seen.append(deadline)
            clock.now += 0.5
            if len(seen) < 3:
                raise core.Failure('child command failed', 1,
                                   b'The connection to the server 127.0.0.1:6443 was refused - '
                                   b'did you specify the right host or port?\n')
            return b'ok'
        loop = spec(loop=True, deadline=25.0, budget=30.0, pre_final={('pending', 1)}, min_pending=1,
                    start_after=3.0, elapsed=(0.0, 30.0))
        # Adapt only the synthetic child boundary; classifier and routed remain unchanged.
        with patch.object(core, 'execute', side_effect=lambda *a, **k: kubectl([], a[1], None)):
            record = proof.run_case(loop, core, {}, core.kubectl, 1000, clock, clock.sleep,
                                    fake_fixture_factory(), lambda uid: 0)
        self.assertEqual(len(set(seen)), 1)                       # the original deadline never renews
        self.assertEqual(seen[0], 125.0)
        self.assertEqual([a['kind'] for a in record['attempts']], ['pending', 'pending', 'ok'])
        self.assertEqual(record['verdict'], 'passed')

    def test_non_loop_case_makes_one_call_even_when_pending(self):
        clock, calls = Clock(), []

        def kubectl(args, deadline, route):
            calls.append(1)
            raise core.Pending('API discovery pending')
        record = proof.run_case(spec(allowed=None), core, {}, kubectl, 1000, clock, clock.sleep,
                                fake_fixture_factory(), lambda uid: 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(record['attempts'][0]['kind'], 'pending')

    def test_leftover_processes_are_polled_then_reported(self):
        clock = Clock()
        record = proof.run_case(spec(allowed=None), core, {}, lambda *a: b'ok', 1000, clock, clock.sleep,
                                fake_fixture_factory(), lambda uid: 3)
        self.assertEqual((record['owned_uid_processes_after'], record['verdict']), (3, 'failed'))
        self.assertGreaterEqual(record['elapsed'], proof.SETTLE)

    def test_cleanup_uncertainty_fails_even_an_observation_or_earlier_attempt(self):
        rows = attempts_of(('pending', 1, 'API discovery pending'), ('ok', None, ''))
        rows[0]['cleanup_uncertain'] = True
        outcome, reasons = proof.verdict(spec(allowed=None), rows, {'requests': []}, self.EVIDENCE)
        self.assertEqual(outcome, 'failed')
        self.assertIn('child cleanup uncertain', reasons)

    def test_generic_exit_one_cannot_prove_auth_tls_stall_or_500(self):
        names = ('401-', '403-', 'x509-', '500-', 'tcp-', 'tls-', 'header-', 'body-')
        for item in proof.build_cases():
            if item['name'].startswith(names):
                with self.subTest(case=item['name']):
                    outcome, _ = proof.verdict(item, attempts_of(('failure', 1, 'child command failed')),
                                               {'requests': []}, self.EVIDENCE)
                    self.assertEqual(outcome, 'failed')

    def test_500_requires_actual_response_single_request_and_cause(self):
        item = next(c for c in proof.build_cases() if c['name'] == '500-no-retry-after')
        rows = attempts_of(('failure', 1, 'child command failed'))
        rows[0]['flags']['internal_error'] = True
        request = {'method': 'GET', 'path': '/readyz', 'query': 'timeout=10s', 'client_cn': proof.CLIENT_CN,
                   'step': item['steps'][0]['name'], 'headers_sent': True,
                   'body_bytes_sent': len(item['steps'][0]['body'])}
        evidence = {**self.EVIDENCE, 'cleanup': {**self.EVIDENCE['cleanup'],
                    'connections_accepted': 1, 'handshakes_completed': 1}}
        self.assertEqual(proof.verdict(item, rows, {'requests': [request]}, evidence)[0], 'passed')
        for change in ({'headers_sent': False}, {'body_bytes_sent': 0}, {'query': ''}):
            self.assertEqual(proof.verdict(item, rows, {'requests': [{**request, **change}]},
                                           evidence)[0], 'failed')
        self.assertEqual(proof.verdict(item, rows, {'requests': [request, request]},
                                       {**evidence, 'request_count': 2})[0], 'failed')

    def test_case_deadline_includes_cleanup_and_settling(self):
        clock, deadlines = Clock(), []
        factory = fake_fixture_factory()
        original_close = factory.close

        def close(instance, deadline=None):
            deadlines.append(deadline)
            clock.now += proof.CLEANUP
            return original_close(instance, deadline)
        factory.close = close

        def kubectl(_args, deadline, _route):
            deadlines.append(deadline)
            clock.now += 1
            return b'ok'
        record = proof.run_case(spec(), core, {}, kubectl, 1000, clock, clock.sleep,
                                factory, lambda uid: 0, proof_deadline=111.0)
        self.assertEqual(deadlines[0], 101.0)  # 111 - 5 report - 2 reap - 1 cleanup - 2 settle
        self.assertLessEqual(deadlines[1], 102.0)
        self.assertEqual(record['elapsed'], 2.0)


class UnauthorizedFormatterTests(unittest.TestCase):
    CANONICAL = b'error: You must be logged in to the server (synthetic fixture response)\n'

    def classify(self, raw, code=1, message='child command failed'):
        error = core.Failure(message, code, raw)
        error._executed_child = True
        with patch.object(core, 'execute', side_effect=error):
            return proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0)

    def verdict(self, record, request_changes=None, cleanup_changes=None, **changes):
        item = next(c for c in proof.build_cases() if c['name'] == '401-unauthorized')
        request = {'method': 'GET', 'path': '/readyz', 'query': 'timeout=10s', 'client_cn': proof.CLIENT_CN,
                   'step': item['steps'][0]['name'], 'headers_sent': True,
                   'body_bytes_sent': len(item['steps'][0]['body']), **(request_changes or {})}
        evidence = {'elapsed': 1.0, 'request_count': 1, 'owned_uid_processes_after': 0,
                    'cleanup': {'listener_closed': True, 'threads_alive': 0, 'sockets_closed': True,
                                'connections_accepted': 1, 'handshakes_completed': 1,
                                **(cleanup_changes or {})}, **changes}
        return proof.verdict(item, [record], {'requests': [request]}, evidence)

    def test_source_backed_canonical_and_existing_unauthorized_forms_remain_fatal(self):
        self.assertEqual(len(self.CANONICAL), 72)
        for raw in (self.CANONICAL, b'error: You must be logged in to the server (Unauthorized)\n'):
            with self.subTest(raw=raw):
                record = self.classify(raw)
                self.assertEqual((record['kind'], record['code'], record['route']),
                                 ('failure', 1, 'api-initial-readyz'))
                self.assertTrue(record['flags']['unauthorized'])
                self.assertEqual(self.verdict(record), ('passed', []))
                self.assertNotIn(raw.decode().strip(), json.dumps(record))

    def test_near_miss_and_unrelated_401_diagnostics_do_not_supply_cause(self):
        for raw in (self.CANONICAL.rstrip(b'\n'), self.CANONICAL + b'\n',
                    b'prefix ' + self.CANONICAL, self.CANONICAL + b'extra',
                    self.CANONICAL.lower(), self.CANONICAL.replace(b'response', b'responses'),
                    b'error: You must be logged in to the server (expired token)\n',
                    b'error: server returned status 401\n', b'unknown fixture error'):
            with self.subTest(raw=raw):
                record = self.classify(raw)
                self.assertEqual(record['kind'], 'failure')
                self.assertFalse(record['flags']['unauthorized'])
                outcome, reasons = self.verdict(record)
                self.assertEqual(outcome, 'failed')
                self.assertIn('missing cause-specific child evidence', reasons)

    def test_canonical_requires_matching_server_request_response_and_clean_peers(self):
        record = self.classify(self.CANONICAL)
        for change in ({'method': 'POST'}, {'path': '/other'}, {'query': ''}, {'client_cn': None},
                       {'step': '403'}, {'headers_sent': False}, {'body_bytes_sent': 0}):
            with self.subTest(request=change):
                self.assertEqual(self.verdict(record, request_changes=change)[0], 'failed')
        for change in ({'connections_accepted': 0}, {'handshakes_completed': 0},
                       {'listener_closed': False}, {'sockets_closed': False}, {'threads_alive': 1}):
            with self.subTest(cleanup=change):
                self.assertEqual(self.verdict(record, cleanup_changes=change)[0], 'failed')
        for change in ({'request_count': 0}, {'request_count': 2}, {'owned_uid_processes_after': 1}):
            with self.subTest(evidence=change):
                self.assertEqual(self.verdict(record, **change)[0], 'failed')

    def test_canonical_cannot_override_timeout_route_message_or_cleanup_failure(self):
        for record in (self.classify(self.CANONICAL, code=124, message='child deadline exceeded'),
                       self.classify(self.CANONICAL, message='child containment unverified'),
                       {**self.classify(self.CANONICAL), 'route': None},
                       {**self.classify(self.CANONICAL), 'cleanup_uncertain': True}):
            with self.subTest(record=record):
                self.assertEqual(record['kind'], 'failure')
                self.assertEqual(self.verdict(record)[0], 'failed')


class PublicHealthFormatterTests(unittest.TestCase):
    NAMES = ('plaintext-readyz-500', 'k3s-prehandler-503-then-ready')

    def classify(self, name, raw=None, code=1, message='child command failed', route=None,
                 executed=True, uncertain=False):
        error = core.Failure(message, code, proof.PUBLIC_FORMATTERS[name] if raw is None else raw)
        error.route = route
        error._executed_child = executed
        error.cleanup_uncertain = uncertain
        with patch.object(core, 'execute', side_effect=error):
            return proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0, public_case=name)

    def data(self, name):
        item = next(c for c in proof.build_cases() if c['name'] == name)
        rows = [self.classify(name)]
        if item['loop']:
            rows += attempts_of(('ok', None, ''))
        requests = []
        for index, (row, step) in enumerate(zip(rows, item['steps'])):
            row.update(server_started=True, request_start=index, request_end=index + 1)
            requests.append({'n': index + 1, 'method': 'GET', 'path': '/readyz', 'query': 'timeout=10s',
                             'client_cn': proof.CLIENT_CN, 'step': step['name'], 'headers_sent': True,
                             'body_bytes_sent': len(step['body']), 'response_code': step['code'],
                             'response_type': step['type'],
                             'response_body_sha256': proof.hashlib.sha256(step['body']).hexdigest()})
        evidence = {'elapsed': 1.5, 'request_count': len(requests), 'owned_uid_processes_after': 0,
                    'cleanup': {'listener_closed': True, 'sockets_closed': True, 'threads_alive': 0,
                                'connections_accepted': len(requests), 'handshakes_completed': len(requests)}}
        return item, rows, {'requests': requests}, evidence

    def test_exact_candidates_bind_empty_unlabeled_pending_then_ready(self):
        pins = ((178, '0e3c3fc0399c911b89b8b73e970cb32bd64be9e0131de8b1d0e8119f0e001dac'),
                (60, '3f7e946c59f2ab5dcac5f1442315b4cc6c2ddb69b6bd6829f24aa5bb63ac0b95'))
        for name, pin in zip(self.NAMES, pins):
            with self.subTest(case=name):
                record = self.classify(name)
                expected = proof.PUBLIC_FORMATTERS[name]
                self.assertEqual((record['kind'], record['code']), ('pending', 1))
                receipt = record['public_synthetic_formatter']
                self.assertTrue(receipt['matches'])
                self.assertEqual(receipt['text'].encode('ascii'), expected)
                self.assertEqual((receipt['bytes'], receipt['sha256']),
                                 (len(expected), proof.hashlib.sha256(expected).hexdigest()))
                self.assertEqual((receipt['bytes'], receipt['sha256']), pin)
                self.assertEqual(receipt['child_route'], 'api-initial-readyz')
                self.assertEqual((record['route'], record['private_output_bytes']), (None, 0))
                self.assertFalse(any(record['flags'].values()))
                self.assertEqual(proof.verdict(*self.data(name)), ('passed', []))

    def test_whole_formatter_near_misses_never_release_text_or_hash(self):
        for name in self.NAMES:
            raw = proof.PUBLIC_FORMATTERS[name]
            for other in (raw.rstrip(b'\n'), raw + b'\n', raw + SECRET, SECRET + raw, raw.lower(),
                          raw.replace(b'not ready', b'not ready yet').replace(b'withheld', b'unknown'),
                          b'Error from server (InternalError): unrelated\n'):
                with self.subTest(case=name, raw=other):
                    receipt = self.classify(name, other)['public_synthetic_formatter']
                    self.assertEqual(receipt, {'matches': False})
                    self.assertNotIn('PRIVATE-CHILD', json.dumps(receipt))
                    item, rows, fixture, evidence = self.data(name)
                    rows[0] = {**rows[0], **self.classify(name, other)}
                    self.assertEqual(proof.verdict(item, rows, fixture, evidence)[0], 'failed')

    def test_exact_bytes_cannot_override_child_status_provenance_or_cleanup(self):
        for name in self.NAMES:
            for change in ({'code': 124, 'message': 'child deadline exceeded'},
                           {'message': 'child containment unverified'}, {'route': 'api-final-readyz'},
                           {'executed': False}, {'uncertain': True}):
                with self.subTest(case=name, change=change):
                    row = self.classify(name, **change)
                    self.assertEqual(row['public_synthetic_formatter'], {'matches': False})
                    item, rows, fixture, evidence = self.data(name)
                    rows[0] = {**rows[0], **row}
                    self.assertEqual(proof.verdict(item, rows, fixture, evidence)[0], 'failed')

    def test_other_cases_do_not_export_even_exact_public_candidate_bytes(self):
        for raw in (*proof.PUBLIC_FORMATTERS.values(), SECRET):
            error = core.Failure('child command failed', 1, raw)
            error._executed_child = True
            with patch.object(core, 'execute', side_effect=error):
                row = proof.attempt(core, core.kubectl, 1000.0, clock=lambda: 990.0)
            self.assertNotIn('public_synthetic_formatter', row)
            self.assertNotIn('PRIVATE-CHILD', json.dumps(row))
            self.assertNotIn(proof.hashlib.sha256(raw).hexdigest(), json.dumps(row))

    def test_status_delivery_mtls_and_order_are_required_for_both_new_cases(self):
        for name in self.NAMES:
            item, rows, fixture, evidence = self.data(name)
            for index in range(len(fixture['requests'])):
                for change in ({'method': 'POST'}, {'path': '/other'}, {'query': ''}, {'client_cn': None},
                               {'n': 9}, {'step': 'other'}, {'headers_sent': False}, {'body_bytes_sent': 0},
                               {'response_code': 401}, {'response_code': 500 if index else 200},
                               {'response_type': 'application/octet-stream'}, {'response_body_sha256': '0' * 64}):
                    with self.subTest(case=name, index=index, change=change):
                        changed = copy.deepcopy(fixture)
                        changed['requests'][index].update(change)
                        self.assertEqual(proof.verdict(item, rows, changed, evidence)[0], 'failed')
            for requests in ([], fixture['requests'] * 2, list(reversed(fixture['requests']))):
                if requests == fixture['requests']:
                    continue
                self.assertEqual(proof.verdict(item, rows, {'requests': requests}, evidence)[0], 'failed')

    def test_cleanup_route_and_formatter_evidence_are_required(self):
        for name in self.NAMES:
            item, rows, fixture, evidence = self.data(name)
            for change in ({'listener_closed': False}, {'sockets_closed': False}, {'threads_alive': 1},
                           {'connections_accepted': 0}, {'handshakes_completed': 0}):
                altered = {**evidence, 'cleanup': {**evidence['cleanup'], **change}}
                self.assertEqual(proof.verdict(item, rows, fixture, altered)[0], 'failed')
            for change in ({'owned_uid_processes_after': 1}, {'request_count': 0}, {'elapsed': 99}):
                self.assertEqual(proof.verdict(item, rows, fixture, {**evidence, **change})[0], 'failed')
            for change in ({'public_synthetic_formatter': {'matches': False}}, {'cleanup_uncertain': True},
                           {'route': 'api-final-readyz'}, {'request_start': 9}, {'request_end': 9},
                           {'server_started': False}):
                changed = [{**rows[0], **change}, *rows[1:]]
                self.assertEqual(proof.verdict(item, changed, fixture, evidence)[0], 'failed')
            for key, value in (('text', 'other'), ('sha256', '0' * 64), ('bytes', 0), ('child_route', None)):
                changed = copy.deepcopy(rows)
                changed[0]['public_synthetic_formatter'][key] = value
                self.assertEqual(proof.verdict(item, changed, fixture, evidence)[0], 'failed')

    def test_listener_started_pending_exception_is_only_the_two_exact_health_cases(self):
        for name in self.NAMES:
            item, rows, fixture, evidence = self.data(name)
            for change in ({'name': 'other'}, {'steps': [proof.STATUS(503, 'Service Unavailable',
                                                                   'ServiceUnavailable'), proof.OK()]},
                           {'deadline': 4.0}):
                outcome, reasons = proof.verdict({**item, **change}, rows, fixture, evidence)
                self.assertEqual(outcome, 'failed')
                self.assertIn('pending was not observed before listener startup', reasons)
            original = next(c for c in proof.build_cases() if c['name'] == 'refused-then-delayed-start')
            self.assertEqual(proof.verdict(original, rows, fixture, evidence)[0], 'failed')
            for changed in ([rows[-1]], [rows[0], rows[0], rows[-1]], list(reversed(rows))):
                self.assertEqual(proof.verdict(item, changed, fixture, evidence)[0], 'failed')

    def check_health_run(self, name):
        item, _, scripted, _ = self.data(name)
        factory = fake_fixture_factory(cleanup={'listener_closed': True, 'threads_alive': 0,
                                               'sockets_closed': True, 'connections_accepted': 2,
                                               'handshakes_completed': 2})
        instance = factory()
        clock, deadlines = Clock(), []
        original_start = instance.start

        def start(steps, mode):
            clock.now += 0.4                 # real fixture startup consumes the same caller deadline
            original_start(steps, mode)
        instance.start = start

        def execute(*args, **kwargs):
            index = len(deadlines)
            deadlines.append(args[1])
            instance.requests.append(scripted['requests'][index])
            clock.now += 0.1
            if index == 0:
                error = core.Failure('child command failed', 1, proof.PUBLIC_FORMATTERS[item['name']])
                error._executed_child = True
                raise error
            return b'ok'
        with patch.object(core, 'execute', side_effect=execute):
            record = proof.run_case(item, core, {}, core.kubectl, 1000, clock, clock.sleep,
                                    lambda **kwargs: instance, lambda uid: 0)
        self.assertEqual(deadlines, [103.0, 103.0])
        self.assertEqual([a['kind'] for a in record['attempts']], ['pending', 'ok'])
        self.assertTrue(all(a['server_started'] for a in record['attempts']))
        self.assertEqual(record['verdict'], 'passed')
        self.assertAlmostEqual(record['elapsed'], 1.6)

    def test_health_runs_use_one_deadline_and_one_delivered_response_per_attempt(self):
        for name in self.NAMES:
            with self.subTest(case=name):
                self.check_health_run(name)


class RunTests(unittest.TestCase):
    def ident(self, **kubectl):
        pinned = {'size': proof.KUBECTL_PIN['size'], 'sha256': proof.KUBECTL_PIN['sha256'], **kubectl}
        return {'kubectl': pinned, 'binding': {'a': True}}

    def test_wrong_kubectl_or_drifted_binding_stops_before_any_case(self):
        for ident in (self.ident(sha256='0' * 64), {**self.ident(), 'binding': {'a': False}}):
            report = proof.run(core, ident=ident, cases=[spec()])
            self.assertEqual((report['status'], report['cases']), ('failed', []))
            self.assertIn('error', report)

    def test_report_always_states_seams_and_remaining_coverage(self):
        report = proof.run(core, ident=self.ident(size=1), cases=[])
        self.assertGreaterEqual(len(report['seams']), 5)
        self.assertGreaterEqual(len(report['remaining_coverage']), 4)
        self.assertEqual((report['cap_seconds'], report['request_timeout_seconds']), (10, 10))

    def test_budget_exhaustion_is_not_run_and_never_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp)
            (fixtures / 'ca.crt').write_bytes(b'ca')
            config = fixtures / 'kubeconfig'
            config.write_bytes(b'x')
            fake = types.SimpleNamespace(
                ubuntu=lambda: types.SimpleNamespace(pw_uid=config.stat().st_uid),
                kubeconfig=lambda: proof.hashlib.sha256(b'ca').hexdigest(),
                __file__='x')
            fake.Pending, fake.Failure = core.Pending, core.Failure
            clock = Clock()
            big = spec(budget=proof.WORK_BUDGET + 1)
            report = proof.run(fake, kubectl=lambda *a: b'ok', contexts={}, clock=clock, cases=[big],
                               ident=self.ident(), fixtures=fixtures, config_path=config)
        self.assertEqual(report['cases'][0]['verdict'], 'not-run')
        self.assertEqual(report['status'], 'failed')

    def test_ca_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp)
            (fixtures / 'ca.crt').write_bytes(b'ca')
            config = fixtures / 'kubeconfig'
            config.write_bytes(b'x')
            fake = types.SimpleNamespace(ubuntu=lambda: types.SimpleNamespace(pw_uid=config.stat().st_uid),
                                         kubeconfig=lambda: '0' * 64, __file__='x')
            report = proof.run(fake, ident=self.ident(), cases=[spec()], fixtures=fixtures, config_path=config)
        self.assertEqual((report['status'], report['cases']), ('failed', []))

    def test_complete_successful_run_with_fake_callables_is_not_native_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp)
            (fixtures / 'ca.crt').write_bytes(b'ca')
            config = fixtures / 'kubeconfig'
            config.write_bytes(b'x')
            fake = types.SimpleNamespace(
                ubuntu=lambda: types.SimpleNamespace(pw_uid=config.stat().st_uid),
                kubeconfig=lambda: proof.sha256(fixtures / 'ca.crt'),
                Pending=core.Pending, Failure=core.Failure)
            clock, calls = Clock(), []

            def kubectl(args, deadline, route):
                calls.append((args, deadline, route))
                clock.now += 0.1
                return b'ok'

            def case_runner(*args, **kwargs):
                return proof.run_case(*args, **kwargs, sleep=clock.sleep,
                                      factory=fake_fixture_factory(), count=lambda uid: 0)
            report = proof.run(fake, kubectl=kubectl, contexts={}, clock=clock, cases=[spec()],
                               ident=self.ident(), fixtures=fixtures, config_path=config,
                               case_runner=case_runner)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['summary'], {'passed': 1, 'recorded': 0, 'failed': 0, 'not-run': 0})
        self.assertEqual(calls, [(['get', '--raw=/readyz'], 102.0, 'api-initial-readyz')])
        self.assertNotIn('PRIVATE-CHILD', json.dumps(report))

    def test_late_final_case_cannot_pass_the_original_driver_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp)
            (fixtures / 'ca.crt').write_bytes(b'ca')
            config = fixtures / 'kubeconfig'
            config.write_bytes(b'x')
            fake = types.SimpleNamespace(
                ubuntu=lambda: types.SimpleNamespace(pw_uid=config.stat().st_uid),
                kubeconfig=lambda: proof.sha256(fixtures / 'ca.crt'))
            clock = Clock()

            def late(*args, **kwargs):
                self.assertEqual(kwargs['proof_deadline'], 270.0)
                clock.now = 271.0
                return {'verdict': 'passed'}
            report = proof.run(fake, kubectl=lambda *a: b'ok', contexts={}, clock=clock,
                               cases=[spec()], ident=self.ident(), fixtures=fixtures,
                               config_path=config, case_runner=late)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['error'], 'original proof deadline exhausted')


class StaticContractTests(unittest.TestCase):
    def test_original_fourteen_case_deadlines_reservations_and_order_are_unchanged(self):
        self.assertEqual([(c['name'], c['deadline'], c['budget']) for c in proof.build_cases()[:14]], [
            ('ok-ready', 2.0, 7.0), ('refused-then-delayed-start', 6.0, 11.0),
            ('success-but-not-ok-body', 2.0, 7.0), ('401-unauthorized', 2.0, 7.0),
            ('403-forbidden', 2.0, 7.0), ('x509-unknown-authority', 2.0, 7.0),
            ('x509-wrong-ip-san', 2.0, 7.0), ('500-no-retry-after', 2.0, 7.0),
            ('output-overflow', 2.0, 7.0), ('absolute-deadline-before-cap', 3.0, 8.0),
            ('tcp-accepted-never-served', 10.0, 15.0), ('tls-clienthello-never-answered', 10.0, 15.0),
            ('header-stall-after-request', 10.0, 15.0), ('body-stall-after-partial-body', 10.0, 15.0),
        ])
        self.assertEqual((proof.WORK_BUDGET, proof.REPORT_RESERVE, proof.REAP, proof.CLEANUP, proof.SETTLE),
                         (170, 5.0, 2.0, 1.0, 2.0))

    def test_case_matrix_is_coherent(self):
        cases = proof.build_cases()
        names = [c['name'] for c in cases]
        self.assertEqual(len(names), len(set(names)))
        for c in cases:
            self.assertTrue(c['steps'])
            self.assertLessEqual(c['elapsed'][0], c['elapsed'][1])
            self.assertIn(c['mode'], ('serve', 'tcp-stall', 'tls-stall'))
            self.assertIn(c['tls'], ('good', 'foreign', 'wrong-san'))
        # no case may allow the production 124 to be presented as Pending
        for c in cases:
            self.assertFalse({('pending', 124)} & (c['allowed'] or set()))
        required = {'ok-ready', 'refused-then-delayed-start', 'tcp-accepted-never-served',
                    'tls-clienthello-never-answered', 'header-stall-after-request',
                    'body-stall-after-partial-body', 'absolute-deadline-before-cap', 'output-overflow',
                    '500-no-retry-after', '401-unauthorized',
                    'x509-unknown-authority', 'success-but-not-ok-body'}
        self.assertLessEqual(required, set(names))

    def test_hang_cases_never_allow_ok_or_pending(self):
        for c in proof.build_cases():
            if c['mode'] in ('tcp-stall', 'tls-stall') or c['name'].endswith('stall-after-request'):
                self.assertTrue(all(k == 'failure' for k, _ in c['allowed']))

    def test_reservations_cover_full_case_windows_inside_unchanged_budget(self):
        cases = proof.build_cases()
        self.assertEqual((len(cases), sum(c['budget'] for c in cases)), (16, 151.0))
        self.assertEqual((len(cases[:14]), sum(c['budget'] for c in cases[:14])), (14, 135.0))
        self.assertLess(sum(c['budget'] for c in cases) + proof.REPORT_RESERVE, proof.WORK_BUDGET)
        for item in cases:
            self.assertGreaterEqual(item['budget'], item['elapsed'][1])
            self.assertGreaterEqual(item['budget'], item['deadline'] + proof.REAP + proof.CLEANUP + proof.SETTLE)

    def test_production_binding_detector_matches_the_actual_source(self):
        text = Path(core.__file__)
        binding = proof.source_binding(text)
        self.assertTrue(all(binding.values()), binding)

    def test_binding_detector_rejects_changed_bounds(self):
        source = Path(core.__file__).read_text()
        with tempfile.TemporaryDirectory() as tmp:
            for old, new in (("'--request-timeout=10s'", "'--request-timeout=30s'"),
                             ('deadline, 10, user=True)', 'deadline, 30, user=True)')):
                changed = Path(tmp) / 'vlab_core.py'
                changed.write_text(source.replace(old, new))
                self.assertFalse(all(proof.source_binding(changed).values()))

    def test_kubeconfig_is_accepted_shape_with_fixed_loopback_server(self):
        text = proof.kubeconfig_text(b'-----BEGIN CERTIFICATE-----\nca\n', b'cert', b'key')
        docs = core.yaml_documents(text.encode())
        cfg = docs[0]
        core.keys(cfg, ('apiVersion', 'kind', 'clusters', 'contexts', 'current-context', 'users'), ('preferences',))
        self.assertEqual(cfg['clusters'][0]['cluster']['server'], 'https://127.0.0.1:6443')
        core.keys(cfg['clusters'][0]['cluster'], ('server', 'certificate-authority-data'))
        core.keys(cfg['users'][0]['user'], ('client-certificate-data', 'client-key-data'))
        self.assertNotIn('insecure-skip-tls-verify', text)
        self.assertNotIn('exec', text)
        self.assertNotIn('token', text)

    def test_sources_have_no_arbitrary_command_or_network_binding(self):
        source = Path(proof.__file__).read_text()
        self.assertEqual(sorted(set(re.findall(r"choices=\(([^)]*)\)", source))), ["'prepare', 'run'"])
        self.assertNotIn('shell=True', source)
        self.assertNotIn('0.0.0.0', source)
        self.assertEqual(proof.HOST, '127.0.0.1')
        self.assertEqual(proof.PORT, 6443)

    def test_launcher_has_the_reviewed_isolation_flags(self):
        launcher = Path(proof.__file__).with_name('test-kubectl-readiness.sh').read_text()
        for flag in ('--network=none', '--cap-drop=ALL', '--read-only', '--security-opt=no-new-privileges',
                     'readonly', '--pids-limit', '--memory=1g', 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989',
                     '58597560', 'ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac'):
            self.assertIn(flag, launcher)
        for forbidden in ('target=/var/run/docker.sock', '--privileged', '--network=host', '--net=host',
                          '/dev/kvm', '--pid=host'):
            self.assertNotIn(forbidden, launcher)
        self.assertEqual(launcher.count('--cap-add='), 4)
        self.assertEqual(proof.KUBECTL_PIN, {'size': 58597560, 'sha256': 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989'})

    def test_docker_cli_uses_only_private_empty_config_and_fixed_local_daemon(self):
        launcher = Path(proof.__file__).with_name('test-kubectl-readiness.sh').read_text()
        for text in ('env -i PATH=/usr/bin:/bin', 'DOCKER_CONFIG="$workdir/docker"',
                     "printf '{}\\n'", '--config "$workdir/docker"',
                     '--host unix:///var/run/docker.sock', '/usr/bin/docker'):
            self.assertIn(text, launcher)
        self.assertNotIn('~/.docker', launcher)
        self.assertNotIn('timeout --kill-after=1s 5s docker', launcher)


if __name__ == '__main__':
    unittest.main()
