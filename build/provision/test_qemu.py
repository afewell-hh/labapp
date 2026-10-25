"""Consequential offline failures; no host QEMU/APT invocation or cloud access."""
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
