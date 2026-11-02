"""Offline tests for kubectl_readiness_proof.py: no kubectl, Docker, TLS, OpenSSL or external network.

They exercise the harness logic only (loopback plain-socket fixture on an ephemeral port, fake
production callables, fake clocks). They prove nothing about the real pinned kubectl; the actual
timing evidence comes only from separately authorized execution of test-kubectl-readiness.sh.
"""
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
        self.assertEqual((len(cases), sum(c['budget'] for c in cases)), (14, 135.0))
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
