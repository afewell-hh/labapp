"""Offline tests for kubectl_readiness_proof.py: no kubectl, Docker, TLS, OpenSSL or network.

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

import kubectl_readiness_proof as proof
import vlab_core as core

SECRET = b'PRIVATE-CHILD-OUTPUT-MARKER'


def served(steps, mode='serve'):
    fixture = proof.Fixture(port=0)
    fixture.start(steps, mode)
    return fixture


def get(fixture, path='/readyz?timeout=10s'):
    connection = http.client.HTTPConnection(proof.HOST, fixture.port, timeout=3)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


class FixtureTests(unittest.TestCase):
    def test_ok_step_records_request_and_closes_cleanly(self):
        fixture = served([proof.OK()])
        status, _, body = get(fixture)
        cleanup = fixture.close()
        self.assertEqual((status, body), (200, b'ok'))
        request = fixture.requests[0]
        self.assertEqual((request['n'], request['method'], request['path'], request['query'], request['step']),
                         (1, 'GET', '/readyz', 'timeout=10s', 'ok'))
        self.assertTrue(cleanup['listener_closed'])
        self.assertEqual(cleanup['threads_alive'], 0)

    def test_scripted_sequence_is_by_request_index_and_last_step_repeats(self):
        fixture = served([proof.STATUS(429, 'Too Many Requests', 'TooManyRequests', '30'), proof.OK()])
        first, second, third = get(fixture), get(fixture), get(fixture)
        fixture.close()
        self.assertEqual((first[0], first[1].get('Retry-After')), (429, '30'))
        self.assertEqual(json.loads(first[2])['reason'], 'TooManyRequests')
        self.assertEqual((second[0], third[0]), (200, 200))
        self.assertEqual([r['n'] for r in fixture.requests], [1, 2, 3])

    def test_request_text_is_sanitized_and_bounded(self):
        fixture = served([proof.OK()])
        get(fixture, '/a%20b?x=' + 'y' * 400)
        fixture.close()
        self.assertEqual(fixture.requests[0]['path'], '/a%20b')
        self.assertLessEqual(len(fixture.requests[0]['query']), 128)

    def test_header_stall_sends_nothing_and_close_releases_the_handler(self):
        fixture = served([proof.STALL_HEADER])
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual(cleanup['threads_alive'], 0)
        self.assertEqual(fixture.requests[0]['step'], 'stall-before-response-header')

    def test_body_stall_sends_headers_and_partial_body_only(self):
        fixture = served([proof.STALL_BODY])
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
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
        fixture = served([proof.OK()], 'backlog')
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        sock.sendall(b'GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual((fixture.requests, cleanup['connections_accepted']), ([], 0))

    def test_tls_stall_mode_reads_the_first_bytes_and_never_answers(self):
        fixture = served([proof.OK()], 'tls-stall')
        sock = socket.create_connection((proof.HOST, fixture.port), timeout=0.4)
        sock.sendall(b'\x16\x03\x01\x00\x05hello')
        with self.assertRaises(socket.timeout):
            sock.recv(1)
        cleanup = fixture.close()
        sock.close()
        self.assertEqual((fixture.requests, cleanup['threads_alive']), ([], 0))

    def test_closed_listener_is_really_closed(self):
        fixture = served([proof.OK()])
        port = fixture.port
        fixture.close()
        with self.assertRaises(OSError):
            socket.create_connection((proof.HOST, port), timeout=1)

    def test_oversize_step_exceeds_the_production_output_limit(self):
        step = proof.HUGE(1024 * 1024 + 4096)
        self.assertGreater(len(step['body']), core.LIMIT)
        self.assertEqual(core.LIMIT, 1024 * 1024)


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
        pending = self.call(self.failure('API discovery pending', 1, b'The connection ... was refused', core.Pending))
        deadline = self.call(self.failure('child deadline exceeded', 124))
        self.assertEqual((pending['kind'], pending['code'], pending['flags']['refused']), ('pending', 1, True))
        self.assertEqual((deadline['kind'], deadline['code']), ('failure', 124))

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

        def close(self):
            return cleanup or {'listener_closed': True, 'threads_alive': 0,
                               'connections_accepted': 0, 'server_errors': {}}
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
    return [dict(kind=k, code=c, message=m, flags={'refused': True}) for k, c, m in rows]


class VerdictAndCaseTests(unittest.TestCase):
    EVIDENCE = {'elapsed': 1.0, 'request_count': 1,
                'cleanup': {'listener_closed': True, 'threads_alive': 0}, 'owned_uid_processes_after': 0}

    def test_allowed_outcome_passes_and_unlisted_outcome_fails(self):
        self.assertEqual(proof.verdict(spec(), attempts_of(('ok', None, '')), {'requests': [
            {'path': '/readyz', 'client_cn': proof.CLIENT_CN}]}, self.EVIDENCE)[0], 'passed')
        for bad in (('pending', 1, 'API discovery pending'), ('failure', 124, 'child deadline exceeded')):
            result, reasons = proof.verdict(spec(name='x'), attempts_of(bad), {'requests': []}, self.EVIDENCE)
            self.assertEqual(result, 'failed')
            self.assertIn('final outcome not in the allowed set', reasons)

    def test_ok_case_requires_a_verified_mtls_request(self):
        result, reasons = proof.verdict(spec(name='ok-ready'), attempts_of(('ok', None, '')),
                                        {'requests': [{'path': '/readyz', 'client_cn': None}]}, self.EVIDENCE)
        self.assertEqual(result, 'failed')
        self.assertIn('ok case did not show a verified mTLS /readyz request', reasons)

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
        good = attempts_of(('pending', 1, 'p'), ('pending', 1, 'p'), ('ok', None, ''))
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
                raise core.Pending('API discovery pending', 1, b'was refused')
            return b'ok'
        loop = spec(loop=True, deadline=25.0, pre_final={('pending', 1)}, min_pending=1, start_after=1.0,
                    elapsed=(0.0, 25.0))
        record = proof.run_case(loop, core, {}, kubectl, 1000, clock, clock.sleep,
                                fake_fixture_factory([{'path': '/readyz', 'client_cn': proof.CLIENT_CN}]),
                                lambda uid: 0)
        self.assertEqual(len(set(seen)), 1)                       # the original deadline never renews
        self.assertEqual(seen[0], 125.0)
        self.assertEqual([a['kind'] for a in record['attempts']], ['pending', 'pending', 'ok'])
        self.assertEqual(record['verdict'], 'passed')

    def test_non_loop_case_makes_one_call_even_when_pending(self):
        clock, calls = Clock(), []

        def kubectl(args, deadline, route):
            calls.append(1)
            raise core.Pending('API discovery pending', 1, b'was refused')
        record = proof.run_case(spec(allowed=None), core, {}, kubectl, 1000, clock, clock.sleep,
                                fake_fixture_factory(), lambda uid: 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(record['attempts'][0]['kind'], 'pending')

    def test_leftover_processes_are_polled_then_reported(self):
        clock = Clock()
        record = proof.run_case(spec(allowed=None), core, {}, lambda *a: b'ok', 1000, clock, clock.sleep,
                                fake_fixture_factory(), lambda uid: 3)
        self.assertEqual((record['owned_uid_processes_after'], record['verdict']), (3, 'failed'))


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


class StaticContractTests(unittest.TestCase):
    def test_case_matrix_is_coherent(self):
        cases = proof.build_cases()
        names = [c['name'] for c in cases]
        self.assertEqual(len(names), len(set(names)))
        for c in cases:
            self.assertTrue(c['steps'])
            self.assertLessEqual(c['elapsed'][0], c['elapsed'][1])
            self.assertIn(c['mode'], ('serve', 'backlog', 'tls-stall'))
            self.assertIn(c['tls'], ('good', 'foreign', 'wrong-san'))
        # no case may allow the production 124 to be presented as Pending
        for c in cases:
            self.assertFalse({('pending', 124)} & (c['allowed'] or set()))
        required = {'ok-ready', 'refused-then-delayed-start', 'tcp-accepted-never-served',
                    'tls-clienthello-never-answered', 'header-stall-after-request',
                    'body-stall-after-partial-body', 'absolute-deadline-before-cap', 'output-overflow',
                    '429-retry-after-30s-over-cap', '500-no-retry-after', '401-unauthorized',
                    'x509-unknown-authority', 'success-but-not-ok-body'}
        self.assertLessEqual(required, set(names))

    def test_hang_cases_never_allow_ok_or_pending(self):
        for c in proof.build_cases():
            if c['mode'] in ('backlog', 'tls-stall') or c['name'].endswith('stall-after-request'):
                self.assertTrue(all(k == 'failure' for k, _ in c['allowed']))

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
        for forbidden in ('docker.sock', '--privileged', '--network=host', '--net=host', '/dev/kvm', '--pid=host'):
            self.assertNotIn(forbidden, launcher)
        self.assertEqual(launcher.count('--cap-add='), 4)
        self.assertEqual(proof.KUBECTL_PIN, {'size': 58597560, 'sha256': 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989'})


if __name__ == '__main__':
    unittest.main()
