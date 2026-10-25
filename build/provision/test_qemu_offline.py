"""Data boundary, no-repair transaction and exact downloader ownership regressions."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hhfab_release import Refusal
import qemu_offline as protocol
import test_bridge_ipv4_harness as ownership


class BoundaryTests(unittest.TestCase):
    def test_fifo_link_hardlink_large_file_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'file'
            file.write_bytes(b'good')
            self.assertEqual(protocol.regular(file), b'good')
            for kind in ('fifo', 'symlink', 'hardlink', 'large'):
                path = root / kind
                if kind == 'fifo': os.mkfifo(path)
                if kind == 'symlink': path.symlink_to(file)
                if kind == 'hardlink': os.link(file, path)
                if kind == 'large': path.write_bytes(b'x' * 20)
                with self.subTest(kind=kind), self.assertRaises((Refusal, OSError)):
                    protocol.regular(path, 10)
                path.unlink()

    def test_json_duplicates_and_unbounded_receipt_rejected_before_hash(self):
        with self.assertRaisesRegex(Refusal, 'duplicate'):
            protocol.parse(b'{"pins":1,"pins":2}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / 'receipt.json'
            os.mkfifo(receipt)
            with self.assertRaisesRegex(Refusal, 'regular'):
                protocol.receive(root, '0'*64, root, protocol.BASE, '', {}, lambda *a: self.fail('command'))

    def test_unexpected_config_symlink_partial_and_count_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lists').mkdir()
            (root / 'archives').mkdir()
            bad = root / 'archives/apt.conf'
            bad.write_text('malicious')
            with self.assertRaisesRegex(Refusal, 'filename'):
                protocol.inventory(root)
            bad.unlink()
            (root / 'lists/partial').mkdir()
            (root / 'lists/partial/received').write_bytes(b'')
            with self.assertRaisesRegex(Refusal, 'working directory'):
                protocol.inventory(root)
            (root / 'lists/partial/received').unlink()
            for i in range(3):
                (root / f'archives/example{i}_amd64.deb').write_bytes(b'deb')
            with patch.object(protocol, 'MAX_FILES', 2), self.assertRaisesRegex(Refusal, 'count'):
                protocol.inventory(root)

    def test_preferences_parts_refused_and_auth_files_never_read(self):
        preference = Path('/etc/apt/preferences.d/site')
        with patch.object(Path, 'rglob', return_value=[preference]), \
             patch.object(Path, 'is_dir', return_value=False), \
             patch.object(protocol, 'regular', return_value=b'Package: *\nPin: release noble\n'):
            with self.assertRaisesRegex(Refusal, 'preferences unsupported'):
                protocol.policy_files()
        with patch.object(Path, 'rglob', return_value=[Path('/etc/apt/auth.conf')]), \
             patch.object(protocol, 'regular', side_effect=AssertionError('credential read')):
            self.assertEqual(protocol.policy_files(), {})

    def test_signature_requires_exact_three_fixed_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lists').mkdir()
            with self.assertRaisesRegex(Refusal, 'release set'):
                protocol.signatures(root, lambda *a: self.fail('command'))

    def test_fixed_config_disables_ambient_loading_before_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt, config = protocol.setup(root, '20261024T000000Z')
            text = Path(config).read_text()
            self.assertIn('Dir::Etc::main', text)
            self.assertIn('Dir::Etc::parts', text)
            self.assertTrue(any('AllowUnauthenticated=false' in item for item in apt))
            self.assertFalse(any('--allow-downgrades' == item for item in apt))

    def test_offline_target_drift_blocks_all_apt(self):
        module = runpy.run_path(str(Path(__file__).with_name('install-qemu.py')))
        globals_ = module['install'].__globals__
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def forbidden(*args): self.fail('APT invoked on drifted target')
            with patch.dict(globals_, {'call': forbidden}), \
                 patch.object(protocol, 'receive', return_value={'expected': 1}), \
                 patch.object(protocol, 'capture', return_value={'drifted': 1}), \
                 patch.dict(module['ENV'], {'APT_CONFIG': '/trusted-generated'}):
                with self.assertRaisesRegex(Refusal, 'state drift'):
                    module['_transaction'](root, ['/usr/bin/apt-get'], __import__('time').monotonic(), {},
                                           root, '0'*64, protocol.BASE)

    def test_no_download_rerun_never_invokes_install_transaction(self):
        module = runpy.run_path(str(Path(__file__).with_name('install-qemu.py')))
        calls = []
        def call(args, seconds=10):
            calls.append(args)
            if 'install' in args and '--simulate' not in args:
                self.fail('rerun transaction attempted')
            return b''
        pins = module['PINS']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'archives').mkdir()
            with patch.dict(module['install'].__globals__, {'call': call, 'installed': lambda: pins, 'verify_tools': lambda: None}), \
                 patch.object(protocol, 'receive', return_value={}), \
                 patch.object(protocol, 'capture', side_effect=AssertionError('stale fingerprint required')), \
                 patch.object(Path, 'is_file', return_value=True):
                module['_transaction'](root, ['/usr/bin/apt-get'], __import__('time').monotonic(), pins, root, '0'*64, protocol.BASE)
            apt = [args for args in calls if args[0] == '/usr/bin/apt-get']
            self.assertTrue(apt)
            self.assertTrue(all('--no-download' in args for args in apt))
            self.assertFalse(any('update' in args for args in apt))


class DownloaderOwnershipTests(unittest.TestCase):
    def run_helper(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'docker'
            source = ownership.FAKE_DOCKER.replace("elif key == 'reference':", "elif key == 'id':\n                match &= val == obj['id']\n            elif key == 'reference':")
            source = source.replace("elif a[0] == 'start':", "elif a[0] == 'cp':\n    pass\nelif a[0] == 'start':")
            source = source.replace("mode == 'create_lost' and 'prep' in name", "mode == 'create_lost'")
            # Stop after successful start, since no fake guest creates data.
            source = source.replace("pass  # Never execute the guest command on the host.", "save(); sys.exit(1)")
            fake.write_text(source)
            fake.chmod(0o755)
            state = root / 'daemon.json'
            state.write_text(json.dumps({'containers': {}, 'images': {}, 'calls': []}))
            captured = root / 'captured.json'
            captured.write_text('{}')
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                       FAKE_DOCKER_STATE=str(state), FAKE_DOCKER_MODE=mode)
            result = subprocess.run(['bash', str(Path(__file__).with_name('prepare-qemu-offline.sh')),
                                     str(captured), str(root/'bundle')], env=env, capture_output=True, timeout=10)
            return result, json.loads(state.read_text())

    def test_lost_create_and_start_failure_cleanup_exact_owned_only(self):
        for mode in ('create_lost', 'success'):
            with self.subTest(mode=mode):
                result, state = self.run_helper(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(state['containers'])
                self.assertTrue(all(obj['name'].endswith('-foreign') for obj in state['containers'].values()))
                self.assertTrue(any(a[0] == 'rm' for a in state['calls']))

    def test_daemon_failure_not_absence_and_foreign_label_never_deleted(self):
        for mode in ('daemon_down', 'name_collision'):
            with self.subTest(mode=mode):
                result, state = self.run_helper(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(a[0] == 'rm' for a in state['calls']))
                self.assertTrue(state['containers'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
