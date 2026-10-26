"""Consequential offline failures; no host QEMU/APT invocation or cloud access."""
import contextlib
import os
from pathlib import Path
import runpy
import sys
import tempfile
import subprocess
import json
import test_bridge_ipv4_harness as ownership
import unittest
from unittest.mock import patch

from hhfab_release import Refusal, bounded
import qemu_container as container
import qemu_offline as offline_protocol
import qemu_witness as witness

INSTALL = Path(__file__).with_name('install-qemu.py')


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))
        self.globals = self.module['install'].__globals__

    def test_nonroot_no_command(self):
        with patch('os.geteuid', return_value=1000), patch.dict(self.globals, {'call': lambda *a: self.fail('command')}):
            with self.assertRaisesRegex(Refusal, 'root'):
                self.module['preflight']()

    def preflight_call(self, audit=b'', holds=b'', architecture=b'amd64\n', foreign=b'', packages=None):
        def call(args, seconds=10):
            if args[0].endswith('dpkg'):
                if '--print-foreign-architectures' in args:
                    return foreign
                return architecture if '--print-architecture' in args else audit
            if args[0].endswith('apt-mark'):
                return holds
            self.fail('unexpected command')
        return {'call': call, 'installed': lambda: packages or {}}

    def test_wrong_os_arch_audit_hold_drift(self):
        # OS read and key presence are fixture inputs; no fake executable/APT.
        for override, reason in [({'architecture': b'arm64'}, 'amd64'),
                                 ({'foreign': b'arm64'}, 'foreign'),
                                 ({'audit': b'partial'}, 'broken'), ({'holds': b'socat'}, 'held'),
                                 ({'packages': {'socat': '0'}}, 'drift')]:
            with self.subTest(reason=reason), patch('os.geteuid', return_value=0), \
                 patch.object(Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
                 patch.object(Path, 'is_file', return_value=True), patch.dict(self.globals, self.preflight_call(**override)):
                with self.assertRaisesRegex(Refusal, reason):
                    self.module['preflight']()
        with patch('os.geteuid', return_value=0), patch.object(Path, 'read_text', return_value='ID=debian'):
            with self.assertRaisesRegex(Refusal, 'Ubuntu'):
                self.module['preflight']()

    def test_cli_sigterm_kills_reaps_real_child_and_unwinds_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / 'pid'
            workspace = root / 'owned'
            child = ("import os,signal,time; from pathlib import Path; "
                     "Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); "
                     "os.kill(os.getppid(),signal.SIGTERM); time.sleep(10)")
            program = """
import runpy,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hhfab_release import bounded
n=runpy.run_path(sys.argv[2]); main=n['main']; child=sys.argv[3]; parent=Path(sys.argv[4])
def harmless_workload():
    parent.mkdir()
    try:
        bounded([sys.executable,'-c',child],5)
    finally:
        parent.rmdir()
main.__globals__['install']=harmless_workload
sys.argv=['install-qemu.py']
try:
    main()
except KeyboardInterrupt:
    sys.exit(130)
"""
            result = subprocess.run([sys.executable, '-c', program, str(INSTALL.parent), str(INSTALL), child, str(workspace)],
                                    capture_output=True, timeout=7)
            self.assertEqual(result.returncode, 130, result.stderr)
            self.assertFalse(workspace.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_dependency_check_failure_blocks_simulation_and_install(self):
        calls = []
        def call(args, seconds=10):
            calls.append(args)
            if args[-1] == 'update':
                return b''
            if args[-1] == 'check':
                raise Refusal('unsatisfied dependency base')
            self.fail('mutation/simulation attempted on broken base')
        before = set(Path('/var/tmp').glob('labapp-qemu-*'))
        with patch.dict(self.globals, {'preflight': lambda: {}, 'call': call}):
            with self.assertRaisesRegex(Refusal, 'unsatisfied'):
                self.module['install']()
        self.assertEqual([args[-1] for args in calls], ['update', 'check'])
        self.assertEqual(set(Path('/var/tmp').glob('labapp-qemu-*')), before)

    def test_authenticated_update_failure_stops_before_install_and_removes_workspace(self):
        calls = []
        def call(args, seconds=10):
            calls.append(args)
            raise Refusal('authentication failure')
        before = set(Path('/var/tmp').glob('labapp-qemu-*'))
        with patch.dict(self.globals, {'preflight': lambda: {}, 'call': call}):
            with self.assertRaisesRegex(Refusal, 'authentication'):
                self.module['install']()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], 'update')
        self.assertEqual(set(Path('/var/tmp').glob('labapp-qemu-*')), before)


class WitnessTests(unittest.TestCase):
    def test_fixture_and_invalid_nonce(self):
        data, expected = witness.fixture('a' * 32)
        self.assertEqual(len(data), 1024 * 1024)
        self.assertEqual(data[510:512], b'\x55\xaa')
        self.assertEqual(expected, b'LABAPP-L2:' + b'a' * 32 + b'\n')
        for bad in ('../x', 'A' * 32, 'a' * 31, 'a' * 33, '\n' * 32):
            with self.assertRaises(Refusal):
                witness.fixture(bad)

    def test_exact_nonce_exit(self):
        expected = b'LABAPP-L2:abc\n'
        witness.verdict(33, expected, expected)
        for code, output in [(0, expected), (124, expected), (33, b''), (33, expected + b'extra'), (33, expected[:-1])]:
            with self.subTest(code=code, output=output), self.assertRaises(Refusal):
                witness.verdict(code, output, expected)

    def test_failures_remove_only_owned_workspace(self):
        installed = {'PINS': {}, 'installed': lambda: {}}
        for failure in (Refusal('command timeout'), Refusal('command output overflow'), KeyboardInterrupt()):
            before = set(Path('/tmp').glob('labapp-qemu-witness-*'))
            with patch.object(witness, 'ARTIFACTS', {}), patch('runpy.run_path', return_value=installed), \
                 patch.object(witness, 'bounded', side_effect=failure):
                with self.assertRaises(type(failure)):
                    witness.probe(test_tcg=True)
            self.assertEqual(set(Path('/tmp').glob('labapp-qemu-witness-*')), before)

    def test_owned_child_timeout_overflow_and_interrupt_reap(self):
        # Exercises the shared real process-group supervisor, not a mocked return.
        for program, seconds, limit, reason in [
            ('import time; time.sleep(10)', .1, 100, 'timeout'),
            ('import os; os.write(1,b"x"*10000)', 2, 10, 'overflow')]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Refusal, reason):
                bounded([sys.executable, '-c', program], seconds, limit=limit)
        with patch('selectors.EpollSelector.select', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                bounded([sys.executable, '-c', 'import time; time.sleep(10)'], 2)


class OwnershipTests(ownership.CleanupTests):
    def run_harness(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'docker'
            fake.write_text(ownership.FAKE_DOCKER.replace("elif a[0] == 'start':", "elif a[0] == 'cp':\n    pass\nelif a[0] == 'start':"))
            fake.chmod(0o755)
            state_path = root / 'state.json'
            state_path.write_text(json.dumps({'containers': {}, 'images': {}, 'calls': []}))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       FAKE_DOCKER_STATE=str(state_path), FAKE_DOCKER_MODE=mode)
            result = subprocess.run(['bash', str(Path(__file__).with_name('test-qemu.sh'))],
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, json.loads(state_path.read_text())

    def assert_owned_removed(self, state):
        adjusted = json.loads(json.dumps(state).replace('labapp.qemu-test.run=', 'labapp.bridge-test.run=')
                              .replace('labapp-qemu-test:', 'labapp-bridge-test:'))
        super().assert_owned_removed(adjusted)


class RetryPolicyAndEvidenceTests(unittest.TestCase):
    """Pure/mocked: no APT, HTTP server, loopback socket or container is used."""
    NO_PUBKEY = b'W: GPG error: InRelease: NO_PUBKEY 871920D1991BC93C\n'

    def test_setup_emits_one_retry_and_leaves_every_other_option_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt, _ = offline_protocol.setup(root, '20261024T000000Z')
        options = dict(item.split('=', 1) for item in apt[1:] if item != '-o')
        self.assertEqual(apt[0], '/usr/bin/apt-get')
        self.assertEqual(options['Acquire::Retries'], '1')
        self.assertEqual({k: v for k, v in options.items() if not k.startswith('Dir::')}, {
            'Acquire::Retries': '1', 'Acquire::https::Timeout': '15', 'Acquire::GzipIndexes': 'true',
            'APT::Architecture': 'amd64', 'APT::Architectures::': 'amd64', 'DPkg::Lock::Timeout': '10',
            'APT::Get::AllowUnauthenticated': 'false', 'Acquire::AllowInsecureRepositories': 'false',
            'Acquire::AllowWeakRepositories': 'false', 'Acquire::AllowDowngradeToInsecureRepositories': 'false',
            'Acquire::Check-Valid-Until': 'true', 'APT::Get::allow-Downgrades': 'false',
            'APT::Get::allow-Change-Held-Packages': 'false'})
        self.assertEqual(container.production_retries(), '1')

    def test_protocol_identity_covers_setup_source_and_invalidates_old_state(self):
        identity = offline_protocol.identity()
        self.assertIn('qemu_offline.py', identity)
        keys = {'format', 'base', 'module', 'status', 'architecture', 'foreign', 'holds', 'audit',
                'selections_sha256', 'policy', 'keyring', 'apt_config_sha256', 'os_release_sha256'}
        state = {key: '' for key in keys}
        state.update(format='labapp-qemu-state-v1', base=offline_protocol.BASE, architecture='amd64',
                     module={**identity, 'qemu_offline.py': '0' * 64})
        with self.assertRaisesRegex(Refusal, 'module'):
            offline_protocol.check_state(state, offline_protocol.BASE)

    def test_stage_labels(self):
        apt = '/usr/bin/apt-get'
        self.assertEqual(container.apt_stage([apt, '-o', 'a=b', 'update']), 'update')
        self.assertEqual(container.apt_stage([apt, 'check']), 'check')
        self.assertEqual(container.apt_stage([apt, '--simulate', 'install', 'x=1']), 'simulate')
        self.assertEqual(container.apt_stage([apt, '--yes', 'install', 'x=1']), 'install')
        self.assertIsNone(container.apt_stage(['/usr/bin/dpkg', '--audit']))

    def test_signature_proof_requires_real_authentication_failure(self):
        container.signature_proof(100, self.NO_PUBKEY)
        for code, output, kind in ((100, b'Err:1 https://x InRelease\n  502  Bad Gateway\n', 'transport-only'),
                                   (100, b'Err:1 https://x InRelease\n  503  Service Unavailable\n', 'transport-only'),
                                   (100, b'unrelated\n', 'unclassified'), (0, self.NO_PUBKEY, 'succeeded')):
            with self.subTest(output=output), self.assertRaisesRegex(AssertionError, kind):
                container.signature_proof(code, output)

    def test_missing_pin_proof_requires_simulation_and_exact_pin_error(self):
        pin = b"E: Version '999:0.invalid' for 'qemu-system-x86' was not found\n"
        good = [('update', 0, b''), (None, 0, b''), ('check', 0, b''), ('simulate', 100, pin)]
        container.missing_pin_proof(good, 'qemu-system-x86', '999:0.invalid')
        bad = {
            'transport at update': [('update', 100, b'503  Service Unavailable')],
            'authentication at update': [('update', 100, self.NO_PUBKEY)],
            'check failure': [('update', 0, b''), ('check', 100, pin)],
            'unrelated simulate failure': good[:3] + [('simulate', 100, b'E: Unable to locate package')],
            'other pin': good[:3] + [('simulate', 100, pin.replace(b'qemu-system-x86', b'socat'))],
            'simulate accepted': good[:3] + [('simulate', 0, pin)],
        }
        for name, log in bad.items():
            with self.subTest(name), self.assertRaises(AssertionError):
                container.missing_pin_proof(log, 'qemu-system-x86', '999:0.invalid')

    def test_recording_call_keeps_stage_code_and_output(self):
        log = []
        module = {'ENV': {'APT_CONFIG': '/x'}}
        with patch.object(container, 'bounded', return_value=(100, b'out')) as run:
            with self.assertRaises(Refusal):
                container.recording_call(module, log)(['/usr/bin/apt-get', 'check'], 7)
        run.assert_called_once_with(['/usr/bin/apt-get', 'check'], 7, env=module['ENV'])
        self.assertEqual(log, [('check', 100, b'out')])

    @staticmethod
    def mocked_native(persistent_requests, leftovers, calls):
        """Mocked server/process boundary, scripted like the expected native apt-helper results."""
        hits = {}
        prefix = 'http://127.0.0.1:1'
        @contextlib.contextmanager
        def server():
            yield prefix, hits
        def run(args, seconds, env=None):
            if args[0] == '/usr/bin/dpkg-query':
                return 0, b'2.8.test'
            calls.append((args, seconds, env))
            path = args[args.index('download-file') + 1][len(prefix):]
            hits[path] = (1 if path in ('/permanent', '/baddigest', '/hang')
                          else min(persistent_requests, 2) if path == '/transient' else persistent_requests)
            if path == '/transient':
                Path(args[args.index('download-file') + 2]).write_bytes(container.BODY)
                return 0, b''
            if path == '/hang':
                raise Refusal('command timeout')
            if path == '/permanent':
                return 100, b'404  Not Found'
            if path == '/baddigest':
                return 100, b'Hash Sum mismatch'
            return 100, b'503  Service Unavailable'
        return dict(run=run, server=server, scan=lambda marker: leftovers)

    def test_transport_fixture_exact_options_limits_and_deadline(self):
        calls = []
        report = container.transport(**self.mocked_native(2, [], calls))
        self.assertEqual(report['requests'], {'/transient': 2, '/always502': 2, '/always503': 2,
                                              '/permanent': 1, '/baddigest': 1, '/hang': 1})
        self.assertEqual((report['apt_version'], report['retries'], report['http_timeout']), ('2.8.test', '1', 15))
        self.assertTrue(report['http_only_not_tls_or_signature_proof'])
        for args, _, env in calls:
            self.assertEqual(args[:8], [container.APT_HELPER, '-o', 'Acquire::Retries=1', '-o',
                                        'Acquire::http::Timeout=15', '-o', 'Acquire::http::Proxy=DIRECT',
                                        'download-file'])
            self.assertTrue(args[8].startswith('http://127.0.0.1:'))
            self.assertNotIn('APT_CONFIG', env)
        self.assertEqual([seconds for _, seconds, _ in calls], [60, 60, 60, 60, 60, 3])

    def test_transport_fixture_rejects_wrong_native_behavior_and_leftovers(self):
        # A zero-retry client makes the transient case fail first.
        with self.assertRaisesRegex(AssertionError, 'transient-then-success'):
            container.transport(**self.mocked_native(1, [], []))
        with self.assertRaisesRegex(AssertionError, 'external deadline'):
            container.transport(**self.mocked_native(2, [123], []))
        # More requests than one retry allows is unbounded retry.
        with self.assertRaisesRegex(AssertionError, 'persistent'):
            container.transport(**self.mocked_native(3, [], []))


if __name__ == '__main__':
    unittest.main(verbosity=2)
