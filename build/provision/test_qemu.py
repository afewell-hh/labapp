"""Consequential offline failures; no host QEMU/APT invocation or cloud access."""
import os
from pathlib import Path
import runpy
import sys
import tempfile
import subprocess
import json
import re
import test_bridge_ipv4_harness as ownership
import unittest
from unittest.mock import patch

from hhfab_release import Refusal, bounded
import qemu_container
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


class PhaseDiagnosticTests(unittest.TestCase):
    SEQUENCE = ['apt-update', 'apt-check-before', 'apt-simulate', 'apt-install', 'apt-check-after']
    NONZERO = "command failed: apt-get code=100 output_tail=b'E: boom\\n'"

    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))
        self.globals = self.module['install'].__globals__

    def step(self, args):
        if args[-1] == 'update':
            return 'apt-update'
        if '--simulate' in args:
            return 'apt-simulate'
        if '--yes' in args:
            return 'apt-install'
        return 'apt-check'

    def failing_call(self, target, message, calls):
        def call(args, seconds=10):
            name = self.step(args)
            calls.append((name, seconds))
            if name == 'apt-check':
                name = 'apt-check-before' if sum(c[0] == 'apt-check' for c in calls) == 1 else 'apt-check-after'
            if name == target:
                raise Refusal(message)
            return b''
        return call

    def test_each_transaction_phase_is_labelled_and_stops_later_work(self):
        for target in self.SEQUENCE:
            for message, kind in [('command timeout', 'timeout'), (self.NONZERO, 'nonzero'),
                                  ('command output overflow', 'overflow')]:
                calls = []
                before = set(Path('/var/tmp').glob('labapp-qemu-*'))
                patched = {'preflight': lambda: {}, 'call': self.failing_call(target, message, calls),
                           'installed': lambda: self.fail('verification after failed phase')}
                with self.subTest(target=target, kind=kind), patch.dict(self.globals, patched):
                    with self.assertRaises(self.module['PhaseRefusal']) as caught:
                        self.module['install']()
                    exc = caught.exception
                    self.assertEqual((exc.phase, exc.kind, exc.cause), (target, kind, message))
                    self.assertRegex(str(exc), r'^' + re.escape(message) +
                                     r' \[phase=' + target + ' class=' + kind +
                                     r' elapsed=\d+\.\ds allocated=\d+\.\ds\]$')
                    self.assertIsInstance(exc.__cause__, Refusal)
                    # Nothing after the failed phase ran; workspace removed.
                    self.assertEqual(len(calls), self.SEQUENCE.index(target) + 1)
                    self.assertTrue(0 < exc.allocated <= 180)
                    self.assertEqual(set(Path('/var/tmp').glob('labapp-qemu-*')), before)

    def test_exhausted_shared_budget_is_labelled_without_running_command(self):
        calls = []
        ticks = iter([0.0])  # installer start; every later reading is past the 210 s budget
        fake_time = type('T', (), {'monotonic': staticmethod(lambda: next(ticks, 211.0))})
        with patch.dict(self.globals, {'preflight': lambda: {}, 'time': fake_time,
                                       'call': lambda args, seconds=10: calls.append(args) or b''}):
            with self.assertRaises(self.module['PhaseRefusal']) as caught:
                self.module['install']()
        self.assertEqual((caught.exception.kind, caught.exception.allocated), ('budget', 0.0))
        self.assertEqual(calls, [])
        self.assertEqual(caught.exception.phase, 'apt-update')

    def test_preflight_and_package_verification_phases(self):
        def refuse(args, seconds=10):
            raise Refusal('command timeout')
        with patch('os.geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
             patch.object(Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
             patch.dict(self.globals, {'call': refuse}):
            with self.assertRaises(self.module['PhaseRefusal']) as caught:
                self.module['install']()
        self.assertEqual((caught.exception.phase, caught.exception.kind, caught.exception.allocated),
                         ('preflight', 'timeout', 10))
        pins = dict(self.module['PINS'])
        with patch('os.geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
             patch.object(Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
             patch.dict(self.globals, {'call': lambda args, seconds=10: b'amd64\n' if '--print-architecture' in args else b'',
                                       'installed': lambda: pins,
                                       'verify_tools': lambda: (_ for _ in ()).throw(Refusal('command timeout'))}):
            with self.assertRaises(self.module['PhaseRefusal']) as caught:
                self.module['install']()
        # The inner label wins; preflight does not relabel it.
        self.assertEqual((caught.exception.phase, caught.exception.kind), ('package-verification', 'timeout'))

    def test_post_install_verification_phase(self):
        with patch.dict(self.globals, {'preflight': lambda: {}, 'call': lambda args, seconds=10: b'',
                                       'installed': lambda: {}}):
            with self.assertRaises(self.module['PhaseRefusal']) as caught:
                self.module['install']()
        self.assertEqual((caught.exception.phase, caught.exception.kind, caught.exception.cause),
                         ('package-verification', 'refusal', 'installed version mismatch'))

    def test_classification_and_diagnostic_text_are_fixed(self):
        classify = self.module['classify']
        for cause, kind in [('command timeout', 'timeout'), ('command output overflow', 'overflow'),
                            ('installation deadline exceeded', 'budget'), (self.NONZERO, 'nonzero'),
                            ('authentication failure', 'refusal'), ('actual signature refusal', 'refusal')]:
            self.assertEqual(classify(cause), kind)
        exc = self.module['PhaseRefusal']('command timeout', 'apt-update', 1.5, 180)
        self.assertEqual(str(exc), 'command timeout [phase=apt-update class=timeout elapsed=1.5s allocated=180.0s]')


class StrictNegativeTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))
        self.make = self.module['PhaseRefusal']

    def refusal(self, cause, phase):
        return self.make(cause, phase, 1, 180)

    def test_unavailable_version_only_from_nonzero_simulation(self):
        good = "command failed: apt-get code=100 output_tail=b\"E: Version '999:0.invalid' for 'qemu-system-x86' was not found\\n\""
        escaped = ("command failed: apt-get code=100 output_tail=b'E: Version \\'999:0.invalid\\' "
                   "for \\'qemu-system-x86\\' was not found\\n'")
        for accepted in (good, escaped):
            qemu_container.require_unavailable_version(self.refusal(accepted, 'apt-simulate'))
        for cause, phase in [
                ('command timeout', 'apt-simulate'), ('command timeout', 'apt-update'),
                (good, 'apt-update'), (good, 'apt-check-before'),
                ("command failed: apt-get code=100 output_tail=b'W: GPG error NO_PUBKEY'", 'apt-simulate'),
                ("command failed: apt-get code=100 output_tail=b'E: Unable to locate package'", 'apt-simulate'),
                (good.replace('999:0.invalid', '1:1.0'), 'apt-simulate'),
                (good.replace('qemu-system-x86', 'socat'), 'apt-simulate'),
                ('authentication failure', 'apt-simulate'), ('actual signature refusal', 'apt-update')]:
            with self.subTest(cause=cause, phase=phase), self.assertRaises(AssertionError):
                qemu_container.require_unavailable_version(self.refusal(cause, phase))
        with self.assertRaises(AssertionError):
            qemu_container.require_unavailable_version(Refusal(good))

    def test_signature_negative_requires_authenticated_update_phase(self):
        qemu_container.require_signature_refusal(self.refusal('actual signature refusal', 'apt-update'))
        for exc in (self.refusal('actual signature refusal', 'apt-simulate'),
                    self.refusal('command timeout', 'apt-update'), Refusal('actual signature refusal')):
            with self.assertRaises(AssertionError):
                qemu_container.require_signature_refusal(exc)


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
