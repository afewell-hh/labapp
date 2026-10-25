"""Public synthetic trees only; no mounts, cloud, guest scripts or source data."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from . import collector, host_baseline as h, host_derive as d, synthetic_ext4


class HostCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'guest'
        self.root.mkdir()
        self.private = Path(self.temp.name) / 'private'
        self.private.mkdir(mode=0o700)

    def put(self, path, body=b''):
        path = self.root / path.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def test_fixed_profile_complete_and_private_boundary(self):
        synthetic_ext4.populate_fixture(self.root, h.PROFILE)
        output = self.private / 'report.json'
        summary = h.write_private(self.root, output)
        report = json.loads(output.read_text())
        d.validate(report)
        self.assertTrue(report['collection_complete'])
        self.assertEqual(summary['records'], 18)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('private_content', report['fixed_records'][0])
        with self.assertRaises(FileExistsError):
            h.write_private(self.root, output)
        with self.assertRaises(collector.Gap):
            h.write_private(self.root, self.root / 'bad.json')
        self.private.chmod(0o755)
        with self.assertRaises(collector.Gap):
            h.write_private(self.root, self.private / 'other.json')

    def test_root_alias_and_dotdot_cannot_write_inside_guest(self):
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        inside = self.root / 'private'
        inside.mkdir(mode=0o700)
        for root in (alias, self.root / '..' / 'guest'):
            with self.subTest(root=str(root)), self.assertRaises(collector.Gap):
                h.write_private(root, inside / 'refused')
        self.assertFalse((inside / 'refused').exists())

    def test_invalid_reads_and_timeout_spend_aggregate_budget(self):
        for identity in ('fabric', 'vlab', 'sysctl_bridge', 'modules_bridge', 'sysctl'):
            path = next(x[1] for x in h.MANIFEST if x[0] == identity)
            self.put(path, b'\xff' * h.TEXT_LIMIT)
        report = h.collect(self.root)
        self.assertEqual(report['fixed_records'][8]['status'], 'incomplete')
        self.assertEqual(report['fixed_records'][8]['reason'], 'byte_budget')
        self.assertNotIn('_consumed', json.dumps(report))
        d.validate(report)

    def test_direct_cli_sigterm_kills_and_reaps_owned_reader(self):
        pidfile = self.private / 'child.pid'
        code = """import sys,time,os
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from inspection import host_baseline as h
pidfile=sys.argv[2]
def sleeper():
    Path(pidfile).write_text(str(os.getpid()))
    time.sleep(10)
def replacement(*args):
    return h.watchdog(sleeper, (), 10)
h.write_private=replacement
sys.argv=['host_baseline','--root','unused','--private-output','unused']
h.main()
"""
        process = subprocess.Popen([sys.executable, '-c', code,
            str(Path(h.__file__).resolve().parents[1]), str(pidfile)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup_process():
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)
        self.addCleanup(cleanup_process)
        deadline = time.monotonic() + 2
        while (not pidfile.exists() or not pidfile.stat().st_size) and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(pidfile.exists() and pidfile.stat().st_size)
        child = int(pidfile.read_text())
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'Host collection refused; no source content is printed.\n')
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_empty_tree_is_explicit_incomplete_and_old_profile_unchanged(self):
        report = h.collect(self.root)
        self.assertFalse(report['collection_complete'])
        self.assertEqual([r['id'] for r in report['fixed_records']], [x[0] for x in h.MANIFEST])
        self.assertEqual(len(d.derive(report)['binary_identities']), 4)
        old = collector.collect(self.root)
        self.assertNotIn('profile', old)
        self.assertIn('records', old)

    def test_shell_and_binary_streaming_never_copy_payload(self):
        marker = b'SECRET_SYNTHETIC_MARKER'
        self.put('/usr/local/bin/hhfab', marker * 4000)
        self.put('/home/ubuntu/.bashrc', marker)
        captured = h.child_file(self.root, '/usr/local/bin/hhfab', 'binary', h.HASH_TOTAL)
        self.assertEqual(captured['length'], len(marker) * 4000)
        self.assertEqual(captured['sha256'], hashlib.sha256(marker * 4000).hexdigest())
        report = h.collect(self.root)
        self.assertNotIn(marker.decode(), json.dumps(report))
        self.assertNotIn(marker.decode(), json.dumps(d.derive(report)))

    def test_per_file_and_aggregate_budgets(self):
        self.put('/usr/local/bin/hhfab', b'abc')
        result = h.child_file(self.root, '/usr/local/bin/hhfab', 'binary', 2)
        self.assertEqual(result, {'status': 'incomplete', 'reason': 'byte_budget'})
        self.put('/etc/sysctl.conf', b'x' * (h.TEXT_LIMIT + 1))
        with self.assertRaisesRegex(collector.Gap, 'oversize'):
            h.child_file(self.root, '/etc/sysctl.conf', 'text', h.TEXT_TOTAL)
        with mock.patch.object(h, 'HASH_TOTAL', 2):
            report = h.collect(self.root)
        self.assertEqual(report['fixed_records'][0]['reason'], 'byte_budget')
        with mock.patch.object(h, 'TOTAL_SECONDS', 0):
            report = h.collect(self.root)
        self.assertTrue(all(r.get('reason') == 'total_deadline' for r in report['fixed_records']))

    def test_binary_oversize_sparse_no_read(self):
        path = self.put('/usr/local/bin/hhfab')
        with path.open('wb') as stream:
            stream.truncate(384 * h.MIB + 1)
        with self.assertRaisesRegex(collector.Gap, 'oversize'), mock.patch.object(os, 'read', side_effect=AssertionError):
            h.child_file(self.root, '/usr/local/bin/hhfab', 'binary', h.HASH_TOTAL)

    def test_pinned_fd_short_growing_replaced_and_metadata_changed(self):
        path = self.put('/etc/sysctl.conf', b'abc')
        real_read = os.read
        for action in ('short', 'grow', 'replace'):
            path.write_bytes(b'abc')
            called = False
            def changing(fd, amount):
                nonlocal called
                if not called:
                    called = True
                    if action == 'short':
                        return b''
                    if action == 'grow':
                        path.write_bytes(b'abcd')
                    else:
                        path.unlink()
                        path.write_bytes(b'abc')
                return real_read(fd, amount)
            with mock.patch.object(os, 'read', side_effect=changing):
                try:
                    value = h.child_file(self.root, '/etc/sysctl.conf', 'text', h.TEXT_TOTAL)
                except collector.Gap as error:
                    self.assertEqual(str(error), 'unreadable_or_changed')
                else:
                    self.assertEqual(value['status'], 'unreadable_or_changed')

    def test_symlink_every_component_and_nonregular(self):
        for component in ('usr', 'usr/local', 'usr/local/bin', 'usr/local/bin/hhfab'):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                target = root / component
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to('/does-not-exist')
                result = h.watchdog(h.child_file, (root, '/usr/local/bin/hhfab', 'binary', h.HASH_TOTAL), 1)
                self.assertEqual(result['status'], 'symlink_skipped')
        path = self.root / 'etc/sysctl.conf'
        path.parent.mkdir()
        os.mkfifo(path)
        result = h.watchdog(h.child_file, (self.root, '/etc/sysctl.conf', 'text', h.TEXT_TOTAL), 1)
        self.assertEqual(result['status'], 'not_regular')

    def test_include_exact_selection_and_overflows(self):
        self.put(h.INCLUDE + '/.dot.yaml', b'{}')
        self.put(h.INCLUDE + '/regular.yaml', b'{}')
        (self.root / h.INCLUDE.lstrip('/') / 'dir.yaml').mkdir()
        self.put(h.INCLUDE + '/nested/not-selected.yaml', b'{}')
        self.put(h.INCLUDE + '/ignore.yml', b'{}')
        self.put(h.INCLUDE + '/ignore.YAML', b'{}')
        (self.root / h.INCLUDE.lstrip('/') / 'link.yaml').symlink_to('/arbitrary')
        report = h.collect(self.root)
        self.assertEqual(report['include']['selected_count'], 4)
        self.assertEqual(report['include']['records'][-1]['basename'], 'regular.yaml')
        d.validate(report)
        self.assertFalse(report['collection_complete'])
        for n in range(33):
            self.put(h.INCLUDE + '/x%d.yaml' % n)
        result = h.child_entries(self.root)
        self.assertEqual(result['reason'], 'selection_limit')
        self.assertEqual(result['names'], [])
        for n in range(130):
            self.put(h.INCLUDE + '/ignored%d' % n)
        result = h.child_entries(self.root)
        self.assertEqual((result['entries_seen'], result['reason']), (129, 'entry_limit'))

    def test_watchdog_open_enumeration_timeout_and_owned_reap(self):
        for function, args, patched in ((h.child_file, (self.root, '/etc/a', 'text', 1), 'open'),
                                         (h.child_entries, (self.root,), 'open')):
            with mock.patch.object(h.Guest, patched, side_effect=lambda *a, **kw: time.sleep(10)):
                start = time.monotonic()
                result = h.watchdog(function, args, .05)
                self.assertEqual(result['status'], 'timeout')
                self.assertLess(time.monotonic() - start, 1)
        self.put(h.INCLUDE + '/file.yaml')
        with mock.patch.object(h.os, 'scandir', side_effect=lambda *a: time.sleep(10)):
            self.assertEqual(h.watchdog(h.child_entries, (self.root,), .05)['status'], 'timeout')
        with mock.patch.object(h, 'Guest', side_effect=lambda *a: time.sleep(10)):
            self.assertEqual(h.watchdog(h.child_entries, (self.root,), .05)['status'], 'timeout')
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_failed_reap_is_blocker_and_cancellation_reaps(self):
        with mock.patch.object(os, 'kill'), mock.patch.object(os, 'waitpid', return_value=(0, 0)), mock.patch.object(h.time, 'monotonic', side_effect=[0, 0, 2]), mock.patch.object(h.time, 'sleep'):
            with self.assertRaisesRegex(collector.Gap, 'reader_cleanup_required'):
                h.reap(999999)
        with mock.patch.object(h.select, 'select', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                h.watchdog(time.sleep, (2,), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_reader_diagnostics_and_invalid_utf8_are_fixed(self):
        self.put('/etc/sysctl.conf', b'\xffSECRET')
        self.assertEqual(h.child_file(self.root, '/etc/sysctl.conf', 'text', h.TEXT_TOTAL),
                         {'status': 'invalid', 'reason': 'nontext', '_consumed': 7})
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            result = h.watchdog(lambda: (_ for _ in ()).throw(ValueError('SECRET')), (), 1)
        self.assertEqual(result['status'], 'unreadable_or_changed')
        self.assertEqual(stream.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
