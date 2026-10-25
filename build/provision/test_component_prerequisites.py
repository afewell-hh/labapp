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
        self.assertIn('operational failure', output.getvalue())


if __name__ == '__main__':
    unittest.main()
