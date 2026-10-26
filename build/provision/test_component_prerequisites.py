"""Offline failure/ownership tests; never use host systemd, root or KVM."""
import contextlib
import io
import os
from pathlib import Path
import pwd
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

import component_prerequisites as probe
from hhfab_release import Refusal


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.token = 'a' * 32

    def service(self, fail=None, marker=True, foreign=False):
        calls = []
        properties = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'exited',
                      'Result': 'success', 'ExecMainStatus': '0'}
        sequence = [{'LoadState': 'loaded' if foreign else 'not-found'}, properties,
                    {'LoadState': 'not-found'}]
        def run(args, seconds=15, limit=4096):
            calls.append(args)
            if args[0] == probe.SYSTEMD_RUN:
                if fail:
                    raise fail
                if marker:
                    (self.work / 'systemd-marker').write_text(self.token)
            return 0, b''
        return calls, run, sequence

    def test_systemd_exact_result_and_owned_cleanup(self):
        calls, run, sequence = self.service()
        with patch.object(probe, 'run', run), patch.object(probe, 'unit_properties', side_effect=sequence), \
                patch.object(probe.uuid, 'uuid4') as uuid:
            uuid.return_value.hex = self.token
            self.assertEqual(probe.systemd_probe(self.work)['marker'], 'matched')
        start = calls[0]
        for value in ('--property=Type=oneshot', '--property=TimeoutStartSec=10s',
                      '--property=TimeoutStopSec=5s', '--property=KillMode=control-group'):
            self.assertIn(value, start)
        unit = 'labapp-prereq-' + self.token + '.service'
        self.assertEqual(calls[-2:], [[probe.SYSTEMCTL, 'stop', unit],
                                      [probe.SYSTEMCTL, 'reset-failed', unit]])

    def test_foreign_unit_never_started_or_stopped(self):
        calls, run, sequence = self.service(foreign=True)
        with patch.object(probe, 'run', run), patch.object(probe, 'unit_properties', side_effect=sequence):
            with self.assertRaisesRegex(Refusal, 'already exists'):
                probe.systemd_probe(self.work)
        self.assertEqual(calls, [])

    def test_ambiguous_start_and_interrupt_clean_exact_unit(self):
        for error in (Refusal('command timeout'), Refusal('command output overflow'), KeyboardInterrupt()):
            calls, run, sequence = self.service(fail=error)
            with self.subTest(error=type(error).__name__), patch.object(probe, 'run', run), \
                    patch.object(probe, 'unit_properties', side_effect=[sequence[0], sequence[-1]]):
                with self.assertRaises(type(error)):
                    probe.systemd_probe(self.work)
            self.assertEqual([c[1] for c in calls[-2:]], ['stop', 'reset-failed'])

    def test_wrong_result_and_missing_marker_fail_with_cleanup(self):
        for wrong_status in (True, False):
            calls, run, sequence = self.service(marker=False)
            if wrong_status:
                sequence[1]['ExecMainStatus'] = '1'
            with self.subTest(wrong_status=wrong_status), patch.object(probe, 'run', run), \
                    patch.object(probe, 'unit_properties', side_effect=sequence):
                with self.assertRaisesRegex(Refusal, 'mismatch'):
                    probe.systemd_probe(self.work)
            self.assertEqual(calls[-2][1], 'stop')

    def test_uncertain_cleanup_cannot_pass(self):
        with patch.object(probe, 'run', return_value=(0, b'')), \
                patch.object(probe, 'unit_properties', return_value={'LoadState': 'loaded'}):
            with self.assertRaisesRegex(Refusal, 'still present'):
                probe.cleanup_unit('owned.service')
        with patch.object(probe, 'run', return_value=(1, b'')):
            with self.assertRaisesRegex(Refusal, 'stop failed'):
                probe.cleanup_unit('owned.service')

    def test_kvm_fd_cleanup_success_wrong_api_create_failure(self):
        import fcntl
        for results, expected in (([12, 42], [42, 41]), ([11], [41]),
                                  ([12, PermissionError()], [41])):
            with self.subTest(results=results), patch.object(os, 'open', return_value=41), \
                    patch.object(fcntl, 'ioctl', side_effect=results), patch.object(os, 'close') as close, \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    exec(probe.KVM, {})
                except (RuntimeError, PermissionError):
                    pass
                self.assertEqual([call.args[0] for call in close.call_args_list], expected)

    def test_non_systemd_and_missing_tool_refused(self):
        with patch.object(os, 'geteuid', return_value=0), patch.object(pwd, 'getpwuid') as owner, \
                patch.object(Path, 'read_text', return_value='init\n'):
            owner.return_value.pw_gid = 1000
            with self.assertRaisesRegex(Refusal, 'not systemd'):
                probe.preflight(1000, self.work / 'archive')
        with patch.object(os, 'geteuid', return_value=0), patch.object(pwd, 'getpwuid') as owner, \
                patch.object(Path, 'read_text', return_value='systemd\n'), patch.object(os, 'access', return_value=False):
            owner.return_value.pw_gid = 1000
            with self.assertRaisesRegex(Refusal, 'tool missing'):
                probe.preflight(1000, self.work / 'archive')

    def test_nonroot_and_uid_zero_refused(self):
        for euid, uid in ((1000, 1000), (0, 0)):
            with patch.object(os, 'geteuid', return_value=euid):
                with self.assertRaises(Refusal):
                    probe.preflight(uid, self.work / 'archive')

    def test_archive_symlink_and_wrong_hash_refused(self):
        archive = self.work / 'archive'
        archive.write_bytes(b'x')
        link = self.work / 'link'
        link.symlink_to(archive)
        with patch.object(os, 'geteuid', return_value=0), patch.object(pwd, 'getpwuid') as owner, \
                patch.object(Path, 'read_text', return_value='systemd\n'), patch.object(os, 'access', return_value=True):
            owner.return_value.pw_gid = 1000
            for path in (archive, link):
                with self.subTest(path=path.name), self.assertRaises(Refusal):
                    probe.preflight(1000, path)

    def test_owner_wrapper_actually_drops_identity_and_env(self):
        # Host needn't be root: use own identity with mocked setgroups/setgid/setuid
        # and inspect execve rather than executing privileged code.
        args = ['wrapper', '1234', '4321', str(self.work), '/usr/bin/true']
        with patch.object(sys, 'argv', args), patch.object(os, 'setgroups') as groups, \
                patch.object(os, 'setgid') as gid, patch.object(os, 'setuid') as uid, \
                patch.object(os, 'chdir'), patch.object(os, 'execve') as execute:
            exec(probe.DROP, {})
        groups.assert_called_once_with([])
        gid.assert_called_once_with(4321)
        uid.assert_called_once_with(1234)
        self.assertEqual(execute.call_args.args[2], dict(probe.ENV, HOME=str(self.work)))

    def test_unit_query_absence_vs_denial(self):
        with patch.object(probe, 'run', return_value=(1, b'LoadState=not-found\n')):
            self.assertEqual(probe.unit_properties('missing')['LoadState'], 'not-found')
        for reply in ((1, b'access denied'), (1, b'LoadState=loaded\n'), (4, b'LoadState=not-found\n')):
            with self.subTest(reply=reply), patch.object(probe, 'run', return_value=reply):
                with self.assertRaisesRegex(Refusal, 'unavailable'):
                    probe.unit_properties('unknown')

    def test_installer_assembly_rerun_identity_and_preserved_binary(self):
        owner = pwd.struct_passwd(('fixture', 'x', os.geteuid(), os.getegid(), '', '', ''))
        for outcome in ('success', 'rerun-mutated', 'bad-version'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                binary = workspace / 'install' / 'hhfab'
                calls = []
                def require(args, seconds=15, expected=None):
                    calls.append(args)
                    if len(calls) == 1:
                        binary.write_bytes(b'abc')
                        binary.chmod(0o755)
                    elif len(calls) == 2 and outcome == 'rerun-mutated':
                        other = binary.with_name('replacement')
                        other.write_bytes(b'abc')
                        other.chmod(0o755)
                        other.replace(binary)
                    return b'hhfab version v0.50.4\n' if outcome != 'bad-version' else b'SECRET'
                pin = (0, '', 3, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
                with patch.object(probe, 'require', require), patch.dict(probe.PINS, {probe.VERSION: pin}), \
                        patch.object(os, 'chown'):
                    if outcome == 'success':
                        result = probe.installer_probe(owner, workspace, Path('/archive'))
                        self.assertEqual(result['uid'], owner.pw_uid)
                        self.assertEqual(result['rerun'], 'unchanged')
                        self.assertEqual(calls[-1][-2:], [str(binary), '--version'])
                    else:
                        with self.assertRaisesRegex(Refusal, 'rerun changed|version mismatch'):
                            probe.installer_probe(owner, workspace, Path('/archive'))

    def test_real_bounded_timeout_and_overflow(self):
        for code, seconds, limit, reason in [('import time;time.sleep(5)', .1, 64, 'timeout'),
                                             ('print("X"*10000)', 2, 64, 'overflow')]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Refusal, reason):
                probe.run([sys.executable, '-c', code], seconds, limit)

    def test_failure_report_never_exports_exception_output(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['probe', '--owner-uid', '1234', '--archive', '/archive']), \
                patch.object(probe, 'probe', side_effect=RuntimeError('SECRET')), \
                patch.object(signal, 'signal'), patch.object(signal, 'alarm'), contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 1)
        self.assertNotIn('SECRET', output.getvalue())
        self.assertIn('operational', output.getvalue())


class PhaseTests(unittest.TestCase):
    """The failure JSON names the failing action; success and exit codes are unchanged."""

    def setUp(self):
        self.addCleanup(probe.stage, 'unknown')
        probe.stage('unknown')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def fail_main(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['probe', '--owner-uid', '1234', '--archive', '/archive']), \
                patch.object(signal, 'signal'), patch.object(signal, 'alarm'), \
                contextlib.redirect_stdout(output):
            code = probe.main()
        return code, output.getvalue()

    def test_each_stage_failure_names_that_phase_and_stops(self):
        stages = ['preflight', 'installer', 'systemd', 'kvm']
        for index, name in enumerate(stages):
            for error in (Refusal('prerequisite command failed'), Refusal('overall work deadline exceeded'),
                          RuntimeError('SECRET'), KeyboardInterrupt()):
                probe.STAGE = 'unknown'
                temp = tempfile.TemporaryDirectory(dir=self.temporary.name)
                with self.subTest(stage=name, error=type(error).__name__), \
                        patch.object(probe.tempfile, 'TemporaryDirectory', return_value=temp), \
                        patch.object(probe, 'preflight', side_effect=error if name == 'preflight' else
                                     (lambda *_: pwd.getpwuid(os.getuid()))), \
                        patch.object(probe, 'installer_probe', side_effect=error if name == 'installer' else
                                     (lambda *_: {})), \
                        patch.object(probe, 'systemd_probe', side_effect=error if name == 'systemd' else
                                     (lambda *_: {})) as systemd, \
                        patch.object(probe, 'require', side_effect=error if name == 'kvm' else
                                     (lambda *_, **__: b'')) as require:
                    with self.assertRaises(type(error)):
                        probe.probe(1234, Path('/archive'))
                    self.assertEqual(probe.STAGE, name)
                    if index < 2:
                        systemd.assert_not_called()
                    if index < 3:
                        require.assert_not_called()

    def test_failure_json_carries_only_allowlisted_phase(self):
        for stage_name, expected in (('kvm', 'kvm'), ('bogus /path SECRET', 'unknown')):
            probe.STAGE = stage_name
            with patch.object(probe, 'probe', side_effect=Refusal('prerequisite command failed')):
                code, text = self.fail_main()
            self.assertEqual(code, 1)
            data = json_loads(text)
            self.assertEqual(data, {'schema': 'labapp-component-prerequisites-v1', 'outcome': 'failed',
                                    'category': 'refusal', 'phase': expected, 'action': 'none', 'execution_mount': 'none'})
            self.assertNotIn('SECRET', text)

    def test_unexpected_exception_and_timeout_keep_stage_phase(self):
        for error in (RuntimeError('SECRET'), KeyboardInterrupt(), Refusal('overall work deadline exceeded')):
            probe.STAGE = 'installer'
            with patch.object(probe, 'probe', side_effect=error):
                code, text = self.fail_main()
            self.assertEqual((code, json_loads(text)['phase']), (1, 'installer'))
            self.assertNotIn('SECRET', text)

    def test_cleanup_failure_takes_precedence_over_original_error(self):
        # Original KVM-stage failure, then the unit cleanup raises: reported as cleanup.
        calls = []
        def run(args, seconds=15, limit=4096):
            calls.append(args[1] if len(args) > 1 else args[0])
            return (1, b'') if 'stop' in args else (0, b'')
        probe.STAGE = 'systemd'
        with patch.object(probe, 'run', run), \
                patch.object(probe, 'unit_properties', return_value={'LoadState': 'not-found'}), \
                patch.object(probe, 'require', side_effect=Refusal('prerequisite command failed')):
            with self.assertRaisesRegex(Refusal, 'stop failed'):
                probe.systemd_probe(Path(self.temporary.name))
        self.assertEqual(probe.STAGE, 'cleanup')

    def test_successful_cleanup_preserves_original_phase(self):
        probe.STAGE = 'systemd'
        with patch.object(probe, 'run', return_value=(0, b'')), \
                patch.object(probe, 'unit_properties', return_value={'LoadState': 'not-found'}), \
                patch.object(probe, 'require', side_effect=Refusal('prerequisite command failed')):
            with self.assertRaisesRegex(Refusal, 'prerequisite command failed'):
                probe.systemd_probe(Path(self.temporary.name))
        self.assertEqual(probe.STAGE, 'systemd')

    def test_workspace_cleanup_failure_is_cleanup_not_kvm(self):
        temp = tempfile.TemporaryDirectory(dir=self.temporary.name)
        temp.cleanup = mock_raise(OSError('SECRET'))
        owner = pwd.getpwuid(os.getuid())
        probe.STAGE = 'unknown'
        with patch.object(probe.tempfile, 'TemporaryDirectory', return_value=temp), \
                patch.object(probe, 'preflight', return_value=owner), \
                patch.object(probe, 'installer_probe', return_value={}), \
                patch.object(probe, 'systemd_probe', return_value={}), \
                patch.object(probe, 'require', return_value=b''):
            with self.assertRaises(OSError):
                probe.probe(1234, Path('/archive'))
        self.assertEqual(probe.STAGE, 'cleanup')

    def test_success_report_is_unchanged_and_exit_zero(self):
        owner = pwd.getpwuid(os.getuid())
        temp = tempfile.TemporaryDirectory(dir=self.temporary.name)
        with patch.object(probe.tempfile, 'TemporaryDirectory', return_value=temp), \
                patch.object(probe, 'preflight', return_value=owner), \
                patch.object(probe, 'installer_probe', return_value={}), \
                patch.object(probe, 'systemd_probe', return_value={}), \
                patch.object(probe, 'require', return_value=b''):
            report = probe.probe(1234, Path('/archive'))
        self.assertEqual(sorted(report), ['caller_uid', 'checks', 'python', 'schema'])
        self.assertEqual(sorted(report['checks']), ['installer', 'kvm', 'systemd'])
        self.assertNotIn('phase', report)


class InstallerDiagnosticTests(unittest.TestCase):
    setUp = PhaseTests.setUp
    fail_main = PhaseTests.fail_main
    # Reuse only test setup/report helper; no real installer, identity changes or privileged work.
    def exercise(self, action, failure, mount=0):
        owner = pwd.getpwuid(os.getuid())
        workspace = Path(self.temporary.name)
        calls = []
        def chown(*_):
            calls.append('chown')
            if action == 'chown':
                raise failure
        def run(args, seconds=15, limit=4096):
            name = ('firstinstall', 'rerun', 'cli')[sum(c in ('firstinstall', 'rerun', 'cli') for c in calls)]
            calls.append(name)
            if name == action:
                if isinstance(failure, BaseException):
                    raise failure
                return failure
            return 0, {'firstinstall': b'hhfab install: installed\n',
                       'rerun': b'hhfab install: unchanged\n', 'cli': b'hhfab version v0.50.4\n'}[name]
        def snapshot(*_):
            name = 'snapshot-rerun' if 'snapshot-first' in calls else 'snapshot-first'
            calls.append(name)
            if action == name:
                raise failure
            return (1, 2, 3, 4, 5)
        def operation(*_):
            probe.stage('installer')
            if action == 'mkdir':
                with patch.object(Path, 'mkdir', side_effect=failure):
                    return probe.installer_probe(owner, workspace, Path('/archive'))
            return probe.installer_probe(owner, workspace, Path('/archive'))
        with patch.object(probe, 'probe', operation), patch.object(probe, 'run', run), \
                patch.object(os, 'chown', chown), patch.object(probe, 'installed_snapshot', snapshot), \
                patch.object(os, 'statvfs', side_effect=mount if isinstance(mount, Exception) else None,
                             return_value=type('Flags', (), {'f_flag': mount})()):
            code, text = self.fail_main()
        data = json_loads(text)
        self.assertEqual(code, 1)
        self.assertEqual((data['phase'], data['action']), ('installer', action))
        self.assertNotIn('SECRET', text)
        self.assertNotIn('reason', data)
        self.assertEqual(data['execution_mount'], ('unknown' if isinstance(mount, Exception) else
                         'noexec' if mount & os.ST_NOEXEC else 'exec') if action == 'cli' else 'none')
        order = ['chown', 'firstinstall', 'snapshot-first', 'rerun', 'snapshot-rerun', 'cli']
        self.assertEqual(calls, [] if action == 'mkdir' else order[:order.index(action)+1])
        (workspace / 'install').rmdir() if (workspace / 'install').exists() else None
        return data['category']

    def test_actions_are_attributed_before_failure_and_stop_later_work(self):
        for action in ('mkdir', 'chown', 'firstinstall', 'snapshot-first', 'rerun', 'snapshot-rerun', 'cli'):
            for error, category in ((OSError('SECRET'), 'operational'), (PermissionError('SECRET'), 'permission'), (Refusal('SECRET'), 'refusal'),
                                    (KeyboardInterrupt(), 'interrupted'),
                                    (Refusal('overall work deadline exceeded'), 'timeout')):
                with self.subTest(action=action, category=category):
                    self.assertEqual(self.exercise(action, error), category)

    def test_command_status_output_and_snapshot_mismatches_are_distinct(self):
        for action in ('firstinstall', 'rerun', 'cli'):
            for reply, category in (((4, b'SECRET'), 'nonzero'), ((0, b'SECRET'), 'mismatch'),
                                     (Refusal('command timeout'), 'timeout'),
                                     (Refusal('command output overflow'), 'overflow')):
                with self.subTest(action=action, category=category):
                    self.assertEqual(self.exercise(action, reply), category)
        for action in ('snapshot-first', 'snapshot-rerun'):
            self.assertEqual(self.exercise(action, Refusal('installed binary verification failed')), 'mismatch')

    def test_real_tiny_child_helper_timeout_and_overflow_are_classified(self):
        for script, seconds, limit, expected in (
                ('import time; time.sleep(5)', .1, 64, 'timeout'),
                ('import os; os.write(2,b"SECRET"*10000)', 2, 64, 'overflow')):
            with self.subTest(expected=expected):
                with self.assertRaises(Refusal) as caught:
                    probe.run([sys.executable, '-I', '-B', '-c', script], seconds, limit)
                self.assertEqual(probe.failure_category(caught.exception), expected)

    def test_cli_mount_observation_is_fixed_and_failure_does_not_skip_cli(self):
        for mount in (0, os.ST_NOEXEC, PermissionError('SECRET')):
            self.assertEqual(self.exercise('cli', PermissionError('SECRET'), mount), 'permission')

    def test_probe_cleanup_preserves_cli_metadata_or_overrides_all_of_it(self):
        for cleanup_fails in (False, True):
            temporary = tempfile.TemporaryDirectory(dir=self.temporary.name)
            self.addCleanup(temporary.cleanup)
            def installer(*_):
                probe.stage('installer', 'cli', 'noexec')
                raise PermissionError('SECRET')
            with patch.object(probe.tempfile, 'TemporaryDirectory', return_value=temporary), \
                    patch.object(probe, 'preflight', return_value=pwd.getpwuid(os.getuid())), \
                    patch.object(probe, 'installer_probe', installer), \
                    patch.object(probe, 'systemd_probe') as systemd, \
                    patch.object(temporary, 'cleanup', side_effect=OSError('SECRET') if cleanup_fails else None):
                code, text = self.fail_main()
            data = json_loads(text)
            self.assertEqual(code, 1)
            expected = ('cleanup', 'none', 'none', 'operational') if cleanup_fails else \
                       ('installer', 'cli', 'noexec', 'permission')
            self.assertEqual(tuple(data[k] for k in ('phase', 'action', 'execution_mount', 'category')), expected)
            systemd.assert_not_called()
            self.assertNotIn('SECRET', text)

    def test_cleanup_restores_both_phase_and_installer_action(self):
        probe.stage('installer', 'rerun')
        previous = probe.stage('cleanup')
        self.assertEqual((probe.STAGE, probe.ACTION), ('cleanup', 'none'))
        probe.stage(*previous)
        self.assertEqual((probe.STAGE, probe.ACTION), ('installer', 'rerun'))
        self.assertEqual(probe.EXECUTION_MOUNT, 'none')
        probe.stage('installer', 'cli', 'noexec')
        previous = probe.stage('cleanup')
        self.assertEqual(probe.EXECUTION_MOUNT, 'none')
        probe.stage(*previous)
        self.assertEqual((probe.STAGE, probe.ACTION, probe.EXECUTION_MOUNT), ('installer', 'cli', 'noexec'))


def json_loads(text):
    import json
    return json.loads(text)


def mock_raise(error):
    def raiser(*_):
        raise error
    return raiser


if __name__ == '__main__':
    unittest.main()
