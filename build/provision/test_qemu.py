"""Consequential offline failures; no host QEMU/APT invocation or cloud access."""
import contextlib
import os
from pathlib import Path
import re
import runpy
import signal
import sys
import tempfile
import subprocess
import json
import test_bridge_ipv4_harness as ownership
import unittest
from unittest.mock import patch, Mock

import hhfab_release
from hhfab_release import Refusal, bounded
import qemu_container as container
import qemu_offline as offline_protocol
import qemu_witness as witness

INSTALL = Path(__file__).with_name('install-qemu.py')
UNAVAILABLE = ' observation=unavailable'
# The complete public diagnostic grammar: fixed keys, integers and 0/1 flags only.
OBSERVED = (' observation=through-cutoff-not-total cap=\\d+ block=\\d+ deadline_seconds=\\d+ elapsed_ms=\\d+'
            ' blocks=\\d+ observed_bytes=\\d+ retained_bytes=\\d+ long_records=\\d+'
            ' lines\\[get=\\d+ hit=\\d+ ign=\\d+ err=\\d+ w=\\d+ e=\\d+ dpkg=\\d+ other=\\d+\\]'
            ' unterminated_tail=[01] non_ascii=[01]')


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


class CommandDiagnosticTests(unittest.TestCase):
    """Actual call/transaction boundaries; only synthetic failures or tiny Python children."""
    STAGES = ('update', 'pre-check', 'simulate', 'install', 'post-check')

    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))
        self.globals = self.module['call'].__globals__

    def test_bounded_refusal_labels_are_fixed_and_preserve_reason(self):
        for executable, label in (
                ('/usr/bin/apt-get', 'apt-get'), ('/usr/bin/dpkg', 'dpkg'),
                ('/usr/bin/dpkg-query', 'dpkg-query'), ('/usr/bin/apt-mark', 'apt-mark'),
                ('/usr/bin/apt-config', 'apt-config'), ('/usr/bin/gpgv', 'gpgv'),
                ('/private/secret-command', 'other')):
            for reason in ('command output overflow', 'command timeout', 'overall deadline exceeded'):
                args = [executable, '/private/secret-argument', 'token=secret']
                with self.subTest(executable=executable, reason=reason), \
                     patch.dict(self.globals, {'bounded': Mock(side_effect=Refusal(reason))}):
                    with self.assertRaises(Refusal) as caught:
                        self.module['call'](args, 7)
                    # A refusal without a valid closed observation says so; no text is invented.
                    self.assertEqual(str(caught.exception), f'command={label}: {reason}'
                                     + (UNAVAILABLE if 'overflow' in reason else ''))
                    self.globals['bounded'].assert_called_once_with(args, 7, env=self.module['ENV'], observe=True)

    def test_unknown_bounded_refusal_does_not_export_exception_text(self):
        with patch.dict(self.globals, {'bounded': Mock(side_effect=Refusal('secret-token sentinel\n/private/path'))}):
            with self.assertRaises(Refusal) as caught:
                self.module['call'](['/private/secret-command', 'token=secret'])
        self.assertEqual(str(caught.exception), 'command=other: command refused')

    def test_returned_nonzero_keeps_existing_bounded_tail_and_code(self):
        output = b'x' * 5000 + b'fixed failure'
        with patch.dict(self.globals, {'bounded': Mock(return_value=(100, output))}):
            with self.assertRaises(Refusal) as caught:
                self.module['call'](['/usr/bin/apt-get', 'check'])
        self.assertEqual(str(caught.exception),
                         f"command failed: apt-get code=100 output_tail={output[-4096:]!r}")

    def test_every_transaction_stage_keeps_refusal_and_stops_later_work(self):
        for failing, stage in enumerate(self.STAGES):
            for reason in ('command output overflow', 'command timeout'):
                calls = []
                def bounded_call(args, seconds, env=None, observe=False):
                    self.assertIs(observe, True)
                    calls.append(args)
                    self.assertEqual(seconds, 180)
                    self.assertIs(env, self.module['ENV'])
                    if len(calls) == failing + 1:
                        raise Refusal(reason)
                    return 0, b''
                with self.subTest(stage=stage, reason=reason), \
                     tempfile.TemporaryDirectory() as directory, \
                     patch.dict(self.globals, {'bounded': bounded_call,
                                              'installed': Mock(side_effect=AssertionError('later inventory')),
                                              'verify_tools': Mock(side_effect=AssertionError('later verification'))}), \
                     patch('time.monotonic', return_value=10):
                    with self.assertRaises(Refusal) as caught:
                        self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], 10,
                                                    {}, None, None, None)
                    self.assertEqual(str(caught.exception), f'stage={stage}: command=apt-get: {reason}'
                                     + (UNAVAILABLE if 'overflow' in reason else ''))
                    expected = [
                        ['/usr/bin/apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'],
                        ['/usr/bin/apt-get', 'check'],
                        ['/usr/bin/apt-get', '--simulate', '--no-remove', '--no-install-recommends',
                         'install', *[name + '=' + version for name, version in self.module['PINS'].items()]],
                        ['/usr/bin/apt-get', '--yes', '--no-remove', '--no-install-recommends',
                         'install', *[name + '=' + version for name, version in self.module['PINS'].items()]],
                        ['/usr/bin/apt-get', 'check'],
                    ]
                    self.assertEqual(calls, expected[:failing + 1])

    def test_transaction_nonzero_retains_stage_and_native_failure(self):
        calls = []
        def native(args, seconds, env=None, observe=False):
            calls.append(args)
            return (100, b'fixed native failure') if args[-1] == 'check' else (0, b'')
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(self.globals, {'bounded': native}), patch('time.monotonic', return_value=10):
            with self.assertRaises(Refusal) as caught:
                self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], 10, {}, None, None, None)
        self.assertEqual(str(caught.exception),
                         "stage=pre-check: command failed: apt-get code=100 output_tail=b'fixed native failure'")
        self.assertEqual([args[-1] for args in calls], ['update', 'check'])

    def test_deadline_has_stage_without_starting_child(self):
        forbidden = Mock(side_effect=AssertionError('child after deadline'))
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(self.globals, {'bounded': forbidden}), patch('time.monotonic', return_value=211):
            with self.assertRaisesRegex(Refusal, '^stage=update: installation deadline exceeded$'):
                self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], 0, {}, None, None, None)
        forbidden.assert_not_called()

    def test_interrupt_is_same_exception_and_stops_transaction(self):
        interrupted = KeyboardInterrupt()
        child = Mock(side_effect=interrupted)
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(self.globals, {'bounded': child}), patch('time.monotonic', return_value=10):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], 10, {}, None, None, None)
        self.assertIs(caught.exception, interrupted)
        child.assert_called_once()

    def test_bounded_failure_unwinds_install_workspace_and_environment(self):
        before = set(Path('/var/tmp').glob('labapp-qemu-*'))
        environment = dict(self.module['ENV'])
        with patch.dict(self.globals, {'preflight': lambda: {},
                                      'bounded': Mock(side_effect=Refusal('command output overflow'))}):
            with self.assertRaisesRegex(Refusal, '^stage=update: command=apt-get: command output overflow observation=unavailable$'):
                self.module['install']()
        self.assertEqual(self.module['ENV'], environment)
        self.assertEqual(set(Path('/var/tmp').glob('labapp-qemu-*')), before)

    def test_actual_bounded_timeout_and_default_output_cap_reap_children(self):
        for action, seconds, reason in (
                ('time.sleep(10)', .3, 'command timeout'),
                ('os.write(1, b"x" * (2 * 1024 * 1024)); time.sleep(10)', 2, 'command output overflow')):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                pidfile = Path(directory) / 'pid'
                program = ('import os,time; from pathlib import Path; '
                           f'Path({str(pidfile)!r}).write_text(str(os.getpid())); {action}')
                with self.assertRaises(Refusal) as caught:
                    self.module['call']([sys.executable, '-c', program], seconds)
                if 'overflow' in reason:
                    self.assertRegex(str(caught.exception), '^' + re.escape(f'command=other: {reason}') + OBSERVED + '$')
                else:
                    self.assertEqual(str(caught.exception), f'command=other: {reason}')
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)

    def test_actual_container_signature_callback_accepts_only_authentication_refusal(self):
        # Run the maintained harness and installer transaction together. Stop at
        # the inventory immediately after the signature assertion; never execute
        # the later missing-pin, installation or held-package native fixtures.
        class SignatureBoundaryReached(Exception):
            pass
        cases = (
            ('signature', (100, RetryPolicyAndEvidenceTests.NO_PUBKEY), SignatureBoundaryReached, ''),
            ('transport', (100, b'503 Service Unavailable'), AssertionError, 'transport-only'),
            ('unclassified', (100, b'unrelated error'), AssertionError, 'unclassified'),
            ('succeeded', (0, RetryPolicyAndEvidenceTests.NO_PUBKEY), AssertionError, 'succeeded'),
            ('timeout', Refusal('command timeout'), AssertionError, ''),
        )
        for name, outcome, exception, reason in cases:
            with self.subTest(name=name):
                owned = []
                original_call = self.globals['call']
                inventory = Mock(side_effect=[{}, SignatureBoundaryReached()])
                def native_update(args, seconds, env=None):
                    self.assertEqual(args[0], '/usr/bin/apt-get')
                    self.assertEqual(args[-1], 'update')
                    self.assertIn('APT::Update::Error-Mode=any', args)
                    self.assertIs(env, self.module['ENV'])
                    source = Path(next(arg.split('=', 1)[1] for arg in args
                                       if arg.startswith('Dir::Etc::sourcelist=')))
                    text = source.read_text()
                    self.assertNotIn('/usr/share/keyrings/ubuntu-archive-keyring.gpg', text)
                    key = Path(text.split('[signed-by=', 1)[1].split(']', 1)[0])
                    self.assertEqual(key.read_bytes(), b'')
                    owned.extend((source.parent, key.parent))
                    if isinstance(outcome, Refusal):
                        raise outcome
                    return outcome
                with patch.dict(self.globals, {'preflight': lambda: {}, 'installed': inventory}), \
                     patch.dict(self.module, {'installed': inventory}), \
                     patch.object(container, 'transport', return_value={}), \
                     patch.object(container.runpy, 'run_path', return_value=self.module), \
                     patch.object(container, 'bounded', side_effect=native_update) as native, \
                     patch.object(Path, 'rglob', return_value=[]):
                    with self.assertRaisesRegex(exception, reason):
                        container.install()
                    self.assertIs(self.globals['call'], original_call)
                    self.assertEqual(inventory.call_count, 2 if name == 'signature' else 1)
                    native.assert_called_once()
                self.assertEqual(len(owned), 2)
                for path in owned:
                    self.assertFalse(path.exists())
                    self.assertFalse(path.is_symlink())


class WitnessTests(unittest.TestCase):
    def test_historical_packages_refuse_unchanged_test_witness_before_qemu(self):
        module = runpy.run_path(str(INSTALL))
        historical = offline_protocol.selection(offline_protocol.BASELINE)['pins']
        with patch.object(witness, 'ARTIFACTS', {}), \
             patch.object(witness.runpy if hasattr(witness, 'runpy') else runpy, 'run_path',
                          return_value={'PINS': module['PINS'], 'installed': lambda: historical}), \
             patch.object(witness, 'bounded', side_effect=AssertionError('QEMU executed')):
            with self.assertRaisesRegex(Refusal, 'package identity mismatch'):
                witness.probe(test_tcg=True)

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


class OverflowObservationTests(unittest.TestCase):
    """Closed overflow observations from the shared supervisor and the QEMU caller.

    Children are small safe Python programs run by the supervisor; assertions use
    invariants that hold for any pipe read-block boundaries."""
    SECRET = b'SECRET-TOKEN-7f3a /private/path'

    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))

    def child(self, program, seconds=5, limit=1024 * 1024, **kwargs):
        return bounded([sys.executable, '-c', program], seconds, limit=limit, observe=True, **kwargs)

    def overflow(self, program, limit, seconds=5):
        with self.assertRaises(Refusal) as caught:
            self.child(program, seconds, limit)
        self.assertEqual(str(caught.exception), 'command output overflow')
        self.assertIsNotNone(caught.exception.observation)
        return caught.exception.observation

    def test_exact_limit_succeeds_and_limit_plus_one_fails_with_hard_cap(self):
        code, output = self.child('import os; os.write(1, b"x" * 1000)', limit=1000)
        self.assertEqual((code, len(output)), (0, 1000))
        data = self.overflow('import os; os.write(1, b"x" * 1001)', 1000)
        self.assertEqual(data['cap'], 1000)
        self.assertLessEqual(data['retained_bytes'], 1000)
        self.assertGreaterEqual(data['observed_bytes'], 1001)
        self.assertEqual(data['outcome'], 'overflow')

    def test_crossing_block_is_observed_but_never_retained(self):
        # Pipe writes need not arrive as one read; assert only cutoff invariants.
        data = self.overflow('import os; os.write(1, b"x" * 1000)', 100)
        self.assertLessEqual(data['retained_bytes'], 100)
        self.assertGreater(data['observed_bytes'], 100)
        self.assertLessEqual(data['observed_bytes'], 1000)
        self.assertGreaterEqual(data['blocks'], 1)
        self.assertLessEqual(data['observed_bytes'] - data['retained_bytes'], hhfab_release.READ_BLOCK)
        data = self.overflow('import os,time\nfor _ in range(30):\n os.write(1, b"y" * 500); time.sleep(.01)', 1200)
        self.assertLessEqual(data['retained_bytes'], 1200)
        self.assertGreater(data['observed_bytes'], 1200)
        self.assertLessEqual(data['observed_bytes'] - data['retained_bytes'], hhfab_release.READ_BLOCK)

    def test_controlled_crossing_read_counts_the_whole_rejected_block(self):
        # Exact read blocks are controlled here, independently of pipe scheduling.
        proc = Mock(pid=42)
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {3: object()}
        selector.select.return_value = [(Mock(fileobj=proc.stdout), 1)]
        with patch.object(hhfab_release.subprocess, 'Popen', return_value=proc), \
             patch.object(hhfab_release.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(hhfab_release.os, 'read', side_effect=[b'a' * 60, b'b' * 30, b'c' * 20]) as read, \
             patch.object(hhfab_release.os, 'killpg'):
            data = self.overflow('unused controlled child', 100)
        self.assertEqual((data['retained_bytes'], data['observed_bytes'], data['blocks']), (90, 110, 3))
        self.assertEqual(read.call_count, 3)
        proc.wait.assert_called_once_with(timeout=2)
        proc.stdout.close.assert_called_once_with()

    def test_fragmented_combined_stdout_stderr_counts_records_not_fragments(self):
        program = ('import os\nfor _ in range(40):\n os.write(1, b"Ge"); os.write(2, b"t:1 par"); '
                   'os.write(1, b"t\\n"); os.write(2, b"Hit:2 x\\nW: w\\r")')
        data = self.overflow(program, 200)
        lines = data['lines']
        self.assertGreater(lines['get'], 0)
        self.assertLessEqual(lines['get'], 40)
        self.assertEqual(lines['other'], 0)
        self.assertLessEqual(abs(lines['get'] - lines['hit']), 1)

    def test_classification_is_independent_of_chunking_and_handles_cr_long_and_binary(self):
        text = (b'Get:1 a\rHit:2 b\r\r\rIgn:3 c\nErr:4 d\nW: e\nE: f\nSetting up p (1) ...\n'
                b'(Reading database ... 5%\r(Reading database ... 10%\r\xff\xfe\x00junk\n' + b'z' * 20000 + b'\ntail')
        whole = hhfab_release._Observer()
        whole.feed(text)
        for size in (1, 3, 7, 4096):
            part = hhfab_release._Observer()
            for index in range(0, len(text), size):
                part.feed(text[index:index + size])
            with self.subTest(size=size):
                self.assertEqual((part.lines, part.long_records, part.non_ascii, part._length),
                                 (whole.lines, whole.long_records, whole.non_ascii, whole._length))
                self.assertLessEqual(len(part._prefix), hhfab_release._PREFIX)
        self.assertEqual(whole.lines, dict(get=1, hit=1, ign=1, err=1, w=1, e=1, dpkg=3, other=2))
        self.assertEqual((whole.long_records, whole.non_ascii), (1, True))
        self.assertEqual(whole.snapshot(10, 0, 5, 0)['unterminated_tail'], True)

    def test_real_cr_heavy_binary_and_overlong_records_are_bounded(self):
        program = ('import os\nfor _ in range(200):\n os.write(1, b"\\r" * 500 + b"Get:1 \\xff\\x00" + b"q" * 9000 + b"\\n")')
        data = self.overflow(program, 50000)
        self.assertTrue(data['non_ascii'])
        self.assertGreater(data['long_records'], 0)
        self.assertGreater(data['lines']['get'], 0)
        self.assertEqual(data['lines']['other'], 0)

    def test_native_nonzero_timeout_and_default_mode_carry_no_observation(self):
        self.assertEqual(self.child('import sys; print("Err:1 x"); sys.exit(3)'), (3, b'Err:1 x\n'))
        with self.assertRaises(Refusal) as caught:
            self.child('import time; time.sleep(10)', .2)
        self.assertEqual((str(caught.exception), caught.exception.observation), ('command timeout', None))
        with self.assertRaises(Refusal) as caught:
            bounded([sys.executable, '-c', 'import os; os.write(1, b"x" * 2000)'], 5, limit=100)
        self.assertEqual((str(caught.exception), caught.exception.observation), ('command output overflow', None))

    def test_retained_descendant_pipe_times_out_without_success(self):
        program = ('import subprocess,sys; subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]); '
                   'print("Get:1 leader exits")')
        started = hhfab_release.time.monotonic()
        with self.assertRaises(Refusal) as caught:
            self.child(program, .5)
        self.assertEqual(str(caught.exception), 'command timeout')
        self.assertLess(hhfab_release.time.monotonic() - started, 5)

    def test_interrupt_and_observer_failure_preserve_primary_behaviour(self):
        with patch('selectors.EpollSelector.select', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.child('import time; time.sleep(10)', 2)
        broken = RuntimeError('observer secret')
        with patch.object(hhfab_release._Observer, 'feed', side_effect=broken):
            with self.assertRaises(Refusal) as caught:
                self.child('import os; os.write(1, b"x" * 2000)', limit=100)
        self.assertEqual((str(caught.exception), caught.exception.observation), ('command output overflow', None))
        with patch.object(hhfab_release._Observer, 'snapshot', side_effect=broken):
            with self.assertRaises(Refusal) as caught:
                self.child('import os; os.write(1, b"x" * 2000)', limit=100)
        self.assertEqual((str(caught.exception), caught.exception.observation), ('command output overflow', None))
        self.assertEqual(self.child('print("ok")'), (0, b'ok\n'))

    def test_primary_survives_every_cleanup_failure_and_all_cleanup_still_runs(self):
        proc = Mock(pid=42)
        proc.wait.side_effect = subprocess.TimeoutExpired('x', 2)
        proc.stdout.close.side_effect = OSError('close')
        with patch('hhfab_release.subprocess.Popen', return_value=proc), \
             patch('hhfab_release.os.killpg', side_effect=PermissionError('kill')) as kill:
            with self.assertRaisesRegex(Refusal, '^primary$'):
                bounded(['/native'], 3, on_start=Mock(side_effect=Refusal('primary')), observe=True)
        kill.assert_called_once_with(42, signal.SIGKILL)
        proc.wait.assert_called_once_with(timeout=2)
        proc.stdout.close.assert_called_once_with()

    def test_observer_constructor_failure_or_interrupt_cannot_strand_spawned_child(self):
        original_spawn = subprocess.Popen
        for failure in (RuntimeError('observer constructor secret'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                owned = []
                def spawn(*args, **kwargs):
                    proc = original_spawn(*args, **kwargs)
                    owned.append(proc)
                    return proc
                with patch.object(hhfab_release.subprocess, 'Popen', side_effect=spawn), \
                     patch.object(hhfab_release, '_Observer', side_effect=failure):
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            self.child('import time; time.sleep(10)')
                        self.assertIs(caught.exception, failure)
                    else:
                        with self.assertRaises(Refusal) as caught:
                            self.child('import os; os.write(1, b"x" * 2000)', limit=100)
                        self.assertEqual((str(caught.exception), caught.exception.observation),
                                         ('command output overflow', None))
                        self.assertEqual(self.module['_overflow_observation'](caught.exception.observation), UNAVAILABLE)
                self.assertEqual(len(owned), 1)
                self.assertIsNotNone(owned[0].returncode)
                self.assertTrue(owned[0].stdout.closed)
                with self.assertRaises(ProcessLookupError):
                    os.kill(owned[0].pid, 0)

    def test_cleanup_interrupt_at_each_step_preserves_primary_and_attempts_all_steps(self):
        for step in ('kill', 'wait', 'close'):
            for primary in (None, Refusal('primary')):
                with self.subTest(step=step, primary=primary is not None):
                    interrupted = KeyboardInterrupt()
                    proc = Mock(pid=42)
                    # The first wait is the successful command result when there
                    # is no primary; cleanup gets its own subsequent wait.
                    proc.wait.return_value = 0
                    if step == 'wait':
                        proc.wait.side_effect = [interrupted] if primary is not None else [0, interrupted]
                    proc.stdout.close.side_effect = interrupted if step == 'close' else None
                    selector = Mock()
                    selector.__enter__ = Mock(return_value=selector)
                    selector.__exit__ = Mock(return_value=False)
                    selector.get_map.return_value = {}
                    start = Mock(side_effect=primary) if primary is not None else None
                    with patch.object(hhfab_release.subprocess, 'Popen', return_value=proc), \
                         patch.object(hhfab_release.selectors, 'DefaultSelector', return_value=selector), \
                         patch.object(hhfab_release.os, 'killpg',
                                      side_effect=interrupted if step == 'kill' else None) as kill:
                        with self.assertRaises(type(primary) if primary is not None else KeyboardInterrupt) as caught:
                            bounded(['/controlled'], 3, on_start=start, observe=True)
                    self.assertIs(caught.exception, primary if primary is not None else interrupted)
                    kill.assert_called_once_with(42, signal.SIGKILL)
                    self.assertEqual(proc.wait.call_count, 1 if primary is not None else 2)
                    proc.wait.assert_called_with(timeout=2)
                    proc.stdout.close.assert_called_once_with()

    def test_cleanup_failure_after_apparent_success_still_fails(self):
        with patch('hhfab_release.os.killpg', side_effect=PermissionError('uncertain')):
            with self.assertRaises(PermissionError):
                self.child('print("done")')

    def test_qemu_caller_exposes_only_fixed_numeric_format_without_child_text(self):
        program = ('import os,sys; sys.stdout.flush()\nfor _ in range(30000):\n'
                   f' os.write(1, b"Get:1 " + {self.SECRET!r} + b"\\n")')
        with self.assertRaises(Refusal) as caught:
            self.module['call']([sys.executable, '-c', program, 'token=SECRET-TOKEN-7f3a'], 5)
        text = str(caught.exception)
        self.assertRegex(text, '^' + re.escape('command=other: command output overflow') + OBSERVED + '$')
        self.assertNotIn('SECRET', text)
        self.assertNotIn('/private', text)
        self.assertIn('cap=1048576 block=65536', text)

    def test_formatter_drops_unknown_keys_and_rejects_invalid_data(self):
        good = dict(cap=1, block=2, deadline_seconds=3, elapsed_ms=4, blocks=5, observed_bytes=6,
                    retained_bytes=0, long_records=0, outcome='overflow', unterminated_tail=False,
                    non_ascii=True, lines=dict.fromkeys(('get', 'hit', 'ign', 'err', 'w', 'e', 'dpkg', 'other'), 1))
        fmt = self.module['_overflow_observation']
        self.assertRegex(fmt(dict(good, secret='SECRET', dynamic_key='x')), '^' + OBSERVED + '$')
        self.assertNotIn('SECRET', fmt(dict(good, secret='SECRET')))
        for bad in (None, 'text', dict(good, cap='1'), dict(good, cap=True), dict(good, cap=-1),
                    dict(good, non_ascii=1), dict(good, lines={'get': 1}), dict(good, outcome='timeout')):
            with self.subTest(bad=bad):
                self.assertEqual(fmt(bad), UNAVAILABLE)


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

    def test_preparation_uses_init_without_changing_containment(self):
        result, state = self.run_harness('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        creates = [args for args in state['calls'] if args[0] == 'create']
        prep = [args for args in creates if 'prep' in args[args.index('--name') + 1]]
        runtime = [args for args in creates if 'runtime' in args[args.index('--name') + 1]]
        self.assertEqual(len(prep), 2)
        self.assertEqual(len(runtime), 2)
        for args in prep:
            self.assertEqual(args[:2], ['create', '--init'])
            self.assertEqual(args.count('--init'), 1)
            self.assertIn('--memory=1g', args)
            self.assertIn('--cpus=2', args)
            self.assertIn('--pids-limit=128', args)
            self.assertIn('--security-opt=no-new-privileges', args)
            self.assertNotIn('--privileged', args)
            self.assertFalse(any(arg.startswith(('--volume', '--mount', '--device', '--network=host')) for arg in args))
            self.assertEqual(args[args.index('timeout'):args.index('timeout') + 3],
                             ['timeout', '--kill-after=3s', '510s'])
        for args in runtime:
            self.assertNotIn('--init', args)
            for flag in ('--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                         '--read-only', '--user=1000:1000', '--pids-limit=128'):
                self.assertIn(flag, args)

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
    def mocked_native(persistent_requests, leftovers, calls, failure=None):
        """Mocked server/process boundary, scripted like the expected native apt-helper results."""
        hits = {}
        prefix = 'http://127.0.0.1:1'
        @contextlib.contextmanager
        def server():
            yield prefix, hits
        def run(args, seconds, env=None, on_start=None):
            if args[0] == '/usr/bin/dpkg-query':
                return 0, b'2.8.test'
            on_start(42)
            calls.append((args, seconds, env))
            path = args[args.index('download-file') + 1][len(prefix):]
            hits[path] = (1 if path in ('/permanent', '/baddigest', '/hang')
                          else min(persistent_requests, 2) if path == '/transient' else persistent_requests)
            if failure and path == failure[0]:
                raise Refusal(failure[1])
            if path == '/transient':
                Path(args[args.index('download-file') + 2]).write_bytes(container.BODY)
                return 0, b''
            if path == '/hang':
                raise Refusal('command timeout')
            if path == '/permanent':
                return 100, b'404  Not Found'
            if path == '/baddigest':
                return 100, b'Hash Sum mismatch'
            return 100, b'502  Bad Gateway' if path == '/always502' else b'503  Service Unavailable'
        class Ownership:
            def started(self, pid):
                assert pid == 42
            def verify(self):
                if leftovers:
                    raise Refusal('native transport owned process remains')
        return dict(run=run, server=server, ownership=Ownership)

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
        with self.assertRaisesRegex(Refusal, 'owned process remains'):
            container.transport(**self.mocked_native(2, [123], []))
        # More requests than one retry allows is unbounded retry.
        with self.assertRaisesRegex(AssertionError, 'persistent'):
            container.transport(**self.mocked_native(3, [], []))

    def test_transport_supervisor_timeout_or_overflow_never_proves_native_refusal(self):
        for path in ('/always502', '/always503', '/permanent', '/baddigest'):
            for failure in ('command timeout', 'command output overflow'):
                with self.subTest(path=path, failure=failure), self.assertRaisesRegex(Refusal, failure):
                    container.transport(**self.mocked_native(2, [], [], (path, failure)))

    def test_transport_requires_native_integer_exit_and_status_evidence(self):
        for result in (('failure', b'502'), (True, b'502'), (100, b'unrelated'),
                       (100, b'Failed to fetch http://127.0.0.1/always502: unrelated failure')):
            native = self.mocked_native(2, [], [])
            original = native['run']
            def run(args, seconds, **kwargs):
                answer = original(args, seconds, **kwargs)
                return result if '/always502' in args[-2] else answer
            native['run'] = run
            with self.subTest(result=result), self.assertRaisesRegex(AssertionError, 'persistent'):
                container.transport(**native)

    @staticmethod
    def stat(pid, group, session, tick, name='http'):
        return f'{pid} ({name}) ' + ' '.join(['S', '1', str(group), str(session)] + ['0'] * 15 + [str(tick)])

    def test_owned_group_detects_orphan_http_method_without_target_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '42').mkdir()
            (root / '42' / 'stat').write_text(self.stat(42, 42, 42, 100, 'apt-helper'))
            owned = container.OwnedGroup(root)
            owned.started(42)
            (root / '42' / 'stat').unlink()
            (root / '42').rmdir()
            (root / '43').mkdir()
            (root / '43' / 'stat').write_text(self.stat(43, 42, 42, 101))
            (root / '43' / 'cmdline').write_bytes(b'/usr/lib/apt/methods/http\x00')
            self.assertEqual(owned.remaining(), [(43, 42, 42, 101)])
            with patch.object(container.time, 'monotonic', side_effect=[0, 3]), self.assertRaisesRegex(Refusal, 'owned process remains'):
                owned.verify()
            (root / '43' / 'stat').unlink()
            (root / '43' / 'cmdline').unlink()
            (root / '43').rmdir()
            owned.verify()

    def test_owned_group_unknown_or_reused_identity_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = container.OwnedGroup(root)
            with self.assertRaisesRegex(Refusal, 'unobserved'):
                owned.verify()
            (root / '42').mkdir()
            path = root / '42' / 'stat'
            path.write_text(self.stat(42, 42, 42, 100))
            owned.started(42)
            path.write_text(self.stat(42, 42, 42, 999))
            with self.assertRaisesRegex(Refusal, 'identity changed'):
                owned.verify()
            path.write_text('malformed')
            with self.assertRaisesRegex(Refusal, 'census unknown'):
                owned.verify()

    def test_bounded_observer_exception_still_kills_owned_group_and_reaps(self):
        proc = Mock(pid=42)
        with patch('hhfab_release.subprocess.Popen', return_value=proc), patch('hhfab_release.os.killpg') as kill:
            def reject(pid):
                self.assertEqual(pid, 42)
                raise Refusal('observer failure')
            with self.assertRaisesRegex(Refusal, 'observer failure'):
                bounded(['/native'], 3, on_start=reject)
        kill.assert_called_once_with(42, signal.SIGKILL)
        proc.wait.assert_called_once_with(timeout=2)
        proc.stdout.close.assert_called_once_with()


class HistoricalInstallTests(unittest.TestCase):
    setUp = InstallTests.setUp
    preflight_call = InstallTests.preflight_call
    def test_default_and_explicit_test_bind_actual_pins_mutations(self):
        self.assertEqual(self.module['selected_policy'](), offline_protocol.selection())
        self.module['PINS']['qemu-system-x86'] = '999:0.invalid'
        for selected in (None, offline_protocol.TEST):
            self.assertIs(self.module['selected_policy'](selected)['pins'], self.module['PINS'])
        self.assertEqual(self.module['selected_policy'](offline_protocol.BASELINE)['pins']['qemu-system-x86'],
                         '1:8.2.2+ds-0ubuntu1.11')
        calls = []
        def call(args, seconds=10):
            calls.append(args)
            if '--simulate' in args:
                self.assertIn('qemu-system-x86=999:0.invalid', args)
                raise Refusal('actual invalid pin reached simulation')
            return b''
        with tempfile.TemporaryDirectory() as directory, patch.dict(self.globals, {'call': call}):
            with self.assertRaisesRegex(Refusal, 'stage=simulate: actual invalid pin'):
                self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], __import__('time').monotonic(),
                                            {}, None, None, None)
        self.assertEqual(len(calls), 3)

    def test_actual_test_transaction_output_passes_unchanged_guest_parser(self):
        adapter = runpy.run_path(str(INSTALL.parents[1]/'packer-qemu/guest/assert-qemu.py'))
        for selected in (None, offline_protocol.TEST):
            output = __import__('io').StringIO()
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'archives').mkdir()
                with patch.dict(self.globals, {'call': lambda *a: b'', 'installed': lambda: self.module['PINS'],
                                              'verify_tools': Mock()}), \
                     patch.object(Path, 'is_file', return_value=True), contextlib.redirect_stdout(output):
                    self.module['_transaction'](root, ['/usr/bin/apt-get'], __import__('time').monotonic(),
                                                {}, None, None, None, selected)
            report = adapter['install_report'](output.getvalue().encode(), 1)
            self.assertEqual(set(report), adapter['INSTALL_KEYS'])
            self.assertTrue(report['changed'])
            report['selection'] = offline_protocol.TEST
            with self.assertRaises(adapter['Check']):
                adapter['install_report'](json.dumps(report).encode(), 1)

    def test_unknown_refuses_before_preflight_or_workspace(self):
        with patch.dict(self.globals, {'preflight': Mock(side_effect=AssertionError('preflight'))}), \
             patch.object(tempfile, 'TemporaryDirectory', side_effect=AssertionError('workspace')):
            with self.assertRaisesRegex(Refusal, 'unknown'):
                self.module['install'](selected='latest')

    def test_historical_preflight_refuses_test_version(self):
        for selected, version in ((offline_protocol.BASELINE, '1:8.2.2+ds-0ubuntu1.18'),
                                  (None, '1:8.2.2+ds-0ubuntu1.11')):
            with patch('os.geteuid', return_value=0), \
                 patch.object(Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
                 patch.object(Path, 'is_file', return_value=True), \
                 patch.dict(self.globals, self.preflight_call(packages={'qemu-system-x86': version})):
                with self.assertRaisesRegex(Refusal, 'drift'):
                    self.module['preflight'](selected=selected)

    def test_actual_historical_online_install_uses_selected_source_and_preflight(self):
        calls = []
        selected = offline_protocol.BASELINE
        policy = offline_protocol.selection(selected)
        def call(args, seconds=10):
            calls.append(args)
            source = next((item.split('=',1)[1] for item in args if item.startswith('Dir::Etc::sourcelist=')), None)
            if source:
                text = Path(source).read_text()
                self.assertIn('/20260114T000000Z/', text)
                self.assertNotIn('20261024', text)
            return b''
        preflight = Mock(return_value={})
        with patch.dict(self.globals, {'preflight': preflight, 'call': call, 'installed': lambda: policy['pins'],
                                      'verify_tools': Mock()}), \
             patch.object(Path, 'is_file', return_value=True), contextlib.redirect_stdout(__import__('io').StringIO()):
            self.module['install'](selected=selected)
        preflight.assert_called_once_with(network=True, selected=selected)
        self.assertTrue(any(args[-1] == 'update' for args in calls))
        self.assertEqual(len([args for args in calls if 'install' in args]), 2)

    def test_selected_payload_verifier_actual_boundaries(self):
        data = b'synthetic package payload'
        import hashlib
        for selected in (offline_protocol.TEST, offline_protocol.BASELINE):
            calls = []
            paths = offline_protocol.artifacts(selected)
            def call(args, seconds=10):
                calls.append(args)
                relative = dict(paths)[args[2]]
                return (hashlib.md5(data).hexdigest()+'  '+relative+'\n').encode()
            with patch.dict(self.globals, {'call': call}), \
                 patch.object(Path, 'is_symlink', autospec=True,
                              side_effect=lambda p: selected == offline_protocol.TEST and str(p) == '/usr/bin/socat'), \
                 patch.object(Path, 'is_file', return_value=True), \
                 patch.object(Path, 'read_bytes', return_value=data), \
                 patch.object(os, 'readlink', return_value='socat1'):
                self.module['verify_tools'](selected)
            self.assertEqual([args[2] for args in calls], [p for p,_ in paths])
            for missing in (True, False):
                with patch.dict(self.globals, {'call': call}), patch.object(Path, 'is_symlink', return_value=False), \
                     patch.object(Path, 'is_file', return_value=not missing), \
                     patch.object(Path, 'read_bytes', return_value=b'drift'):
                    with self.assertRaisesRegex(Refusal, 'missing' if missing else 'drift'):
                        self.module['verify_tools'](selected)

    def test_actual_historical_transaction_requests_two_and_preserves_rerun_rule(self):
        selected = offline_protocol.BASELINE
        policy = offline_protocol.selection(selected)
        for rerun in (False, True):
            calls, captures = [], []
            def call(args, seconds=10):
                calls.append(args); return b''
            def capture(*args):
                captures.append(args)
                self.assertEqual(args[-1], selected)
                return {'expected': True}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'archives').mkdir()
                with patch.dict(self.globals, {'call': call, 'installed': lambda: policy['pins'], 'verify_tools': Mock()}), \
                     patch.object(offline_protocol, 'receive', return_value={'expected': True}) as receive, \
                     patch.object(offline_protocol, 'capture', side_effect=capture), \
                     patch.dict(self.module['ENV'], {'APT_CONFIG': '/fixed'}), \
                     patch.object(Path, 'is_file', return_value=True), contextlib.redirect_stdout(__import__('io').StringIO()):
                    self.module['_transaction'](root, ['/usr/bin/apt-get'], __import__('time').monotonic(),
                                                policy['pins'] if rerun else {}, root, '1'*64, offline_protocol.BASE, selected)
                self.assertEqual(receive.call_args.args[-1], selected)
                self.assertEqual(len(captures), 0 if rerun else 2)
                installs = [args for args in calls if 'install' in args]
                self.assertEqual(len(installs), 1 if rerun else 2)
                for args in installs:
                    self.assertEqual(args[args.index('install')+1:], [k+'='+v for k,v in policy['pins'].items()])
                self.assertTrue(all('--no-download' in args for args in calls if args[0] == '/usr/bin/apt-get'))

    def test_historical_post_simulation_drift_refuses_before_mutation(self):
        calls = []
        def call(args, seconds=10):
            calls.append(args)
            if 'install' in args and '--simulate' not in args:
                self.fail('drifted target mutation')
            return b''
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(self.globals, {'call': call}), \
             patch.dict(self.module['ENV'], {'APT_CONFIG': '/fixed'}), \
             patch.object(offline_protocol, 'receive', return_value={'expected': 1}), \
             patch.object(offline_protocol, 'capture', side_effect=[{'expected': 1}, {'drifted': 1}]):
            with self.assertRaisesRegex(Refusal, 'immediately before'):
                self.module['_transaction'](Path(directory), ['/usr/bin/apt-get'], __import__('time').monotonic(),
                                            {}, Path(directory), '1'*64, offline_protocol.BASE, offline_protocol.BASELINE)
        self.assertTrue(any('--simulate' in args for args in calls))


if __name__ == '__main__':
    unittest.main(verbosity=2)
