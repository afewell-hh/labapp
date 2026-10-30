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
import base64
import contextlib
import io
from unittest.mock import patch

from hhfab_release import Refusal
import qemu_offline as protocol
import test_bridge_ipv4_harness as ownership
import qemu_acquire as acquire_module
import qemu_offline_container as target


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
                policy = protocol.selection()
                protocol.receive(root, '0'*64, root, protocol.BASE, policy['snapshot'], policy['pins'], lambda *a: self.fail('command'))

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

    def test_preferences_hashed_without_import_and_auth_files_never_read(self):
        for name in ('preferences', 'preferences.d/site'):
            with self.subTest(name=name), \
                 patch.object(Path, 'rglob', return_value=[Path('/etc/apt') / name]), \
                 patch.object(Path, 'is_dir', return_value=False), \
                 patch.object(protocol, 'regular', return_value=b'Package: *\nPin: release noble\n'):
                self.assertEqual(protocol.policy_files(), {name:
                                 hashlib.sha256(b'Package: *\nPin: release noble\n').hexdigest()})
        with patch.object(Path, 'rglob', return_value=[Path('/etc/apt/auth.conf'),
                                                      Path('/etc/apt/auth.conf.d/site')]), \
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


class SelectionTests(unittest.TestCase):
    def state(self, selected):
        return {'format': 'labapp-qemu-state-v2', **protocol.selection(selected),
                'base': protocol.BASE, 'module': protocol.identity(),
                'status': base64.b64encode(b'Package: fixture\nStatus: install ok installed\n').decode(),
                'architecture': 'amd64', 'foreign': '', 'holds': '', 'audit': '',
                'selections_sha256': '1'*64, 'policy': {'preferences.d/site': '2'*64},
                'keyring': '3'*64, 'apt_config_sha256': '4'*64, 'os_release_sha256': '5'*64}

    def releases(self, root, selected):
        snapshot = protocol.selection(selected)['snapshot']
        for suite in ('noble', 'noble-updates', 'noble-security'):
            (root/'lists'/f'snapshot.ubuntu.com_ubuntu_{snapshot}_dists_{suite}_InRelease').write_bytes(b'synthetic signature')

    def test_fixed_selection_freshness_and_source_binding(self):
        baseline = protocol.selection(protocol.BASELINE)
        self.assertEqual(set(baseline['pins']), {'qemu-system-x86', 'qemu-utils'})
        self.assertEqual(set(baseline['pins'].values()), {'1:8.2.2+ds-0ubuntu1.11'})
        baseline['pins'].clear()
        self.assertEqual(len(protocol.selection(protocol.BASELINE)['pins']), 2)
        self.assertEqual(len(protocol.selection()['pins']), 4)
        self.assertEqual(set(protocol.identity()), {'install-qemu.py', 'qemu_offline.py', 'hhfab_release.py',
                                                   'qemu_acquire.py', 'prepare-qemu-offline.sh'})
        for invalid in ('latest', None, {}, 1):
            with self.subTest(invalid=invalid), self.assertRaises(Refusal):
                protocol.selection(invalid)

    def test_strict_state_schemas_types_and_cross_selection(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            good = self.state(selected)
            with patch.object(protocol, 'digest', return_value='3'*64), patch.object(protocol, 'identity', return_value=good['module']):
                self.assertTrue(protocol.check_state(good, protocol.BASE, selected))
                bad = [None, [], {}, {**good, 'format': 'labapp-qemu-state-v1'},
                       {**good, 'extra': 1}, {**good, 'pins': []}, {**good, 'status': 1},
                       {**good, 'status': ''}, {**good, 'policy': []},
                       {**good, 'policy': {'x': True}}, {**good, 'selections_sha256': 'A'*64},
                       {**good, 'base': 'gce-image:1'}, {**good, 'module': {}},
                       {**good, 'keyring': '0'*64}, {**good, 'snapshot': '20260115T000000Z'},
                       {**good, 'selection': protocol.BASELINE if selected == protocol.TEST else protocol.TEST}]
                for value in bad:
                    with self.subTest(selected=selected, value=value), self.assertRaises(Refusal):
                        protocol.check_state(value, protocol.BASE, selected)
                for key in good:
                    value = dict(good); del value[key]
                    with self.subTest(missing=key), self.assertRaises(Refusal):
                        protocol.check_state(value, protocol.BASE, selected)

    def test_actual_capture_binds_selected_descriptor_and_fingerprint(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            def call(args):
                if '--print-architecture' in args: return b'amd64\n'
                if '--get-selections' in args: return b'fixture install\n'
                if args[-1] == 'dump': return b'fixture APT config'
                return b''
            with patch.object(protocol, 'regular', return_value=b'fixture installed status'), \
                 patch.object(protocol, 'digest', return_value='3'*64), \
                 patch.object(protocol, 'policy_files', return_value={'preferences': '2'*64}):
                state = protocol.capture(call, protocol.BASE, selected)
                self.assertEqual({key:state[key] for key in ('selection','snapshot','pins')}, protocol.selection(selected))
                self.assertEqual(protocol.check_state(state, protocol.BASE, selected), b'fixture installed status')

    def test_selected_signature_set_and_actual_gpg_failure(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'lists').mkdir()
                self.releases(root, selected)
                calls = []
                protocol.signatures(root, lambda args: calls.append(args), selected)
                self.assertEqual(len(calls), 3)
                with self.assertRaisesRegex(Refusal, 'gpg failed'):
                    protocol.signatures(root, lambda args: (_ for _ in ()).throw(Refusal('gpg failed')), selected)
                wrong = root/'lists/snapshot.ubuntu.com_ubuntu_20000101T000000Z_dists_noble_InRelease'
                wrong.write_bytes(b'wrong snapshot')
                with self.assertRaisesRegex(Refusal, 'release set'):
                    protocol.signatures(root, lambda *a: self.fail('gpg before set validation'), selected)

    def test_actual_receive_positive_and_typed_inventory_refusals(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); bundle = root/'bundle'; bundle.mkdir()
                (bundle/'lists').mkdir(); (bundle/'archives').mkdir()
                self.releases(bundle, selected)
                (bundle/'archives/fixture_amd64.deb').write_bytes(b'fake archive')
                state = self.state(selected)
                receipt = {'format': 'labapp-qemu-bundle-v2', **protocol.selection(selected),
                           'state': state, 'files': protocol.inventory(bundle)}
                descriptor = protocol.selection(selected)
                def receive(value):
                    data = protocol.encoded(value); (bundle/'receipt.json').write_bytes(data)
                    destination = root/'destination'; destination.mkdir(exist_ok=True)
                    protocol.setup(destination, descriptor['snapshot'])
                    return protocol.receive(bundle, hashlib.sha256(data).hexdigest(), destination, protocol.BASE,
                                            descriptor['snapshot'], descriptor['pins'], lambda *a: None, selected)
                with patch.object(protocol, 'digest', return_value='3'*64), patch.object(protocol, 'identity', return_value=state['module']):
                    self.assertEqual(receive(receipt), state)
                    bad = [[], {**receipt, 'format': 'labapp-qemu-bundle-v1'},
                           {**receipt, 'files': []}, {**receipt, 'state': []},
                           {**receipt, 'pins': []}, {**receipt, 'extra': 1}]
                    for inventory in ({'x': {'bytes': True, 'sha256': '1'*64}},
                                      {'x': {'bytes': -1, 'sha256': '1'*64}},
                                      {'x': {'bytes': 1, 'sha256': False}}):
                        bad.append({**receipt, 'files': inventory})
                    for value in bad:
                        with self.subTest(value=value), self.assertRaises(Refusal):
                            receive(value)
                    other = protocol.BASELINE if selected == protocol.TEST else protocol.TEST
                    with self.assertRaisesRegex(Refusal, 'caller fixed'):
                        protocol.receive(bundle, '0'*64, root, protocol.BASE,
                                         descriptor['snapshot'], descriptor['pins'], lambda *a: self.fail('command'), other)

    def test_actual_acquisition_uses_state_selection_before_workspace(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); state = self.state(selected)
                bundle = root/'bundle'; exported = root/'exported'
                calls = []
                def path(value):
                    return {'/work/bundle': bundle, '/export-bundle': exported}.get(str(value), Path(value))
                def call(args, seconds):
                    calls.append((args, seconds))
                    if args[-1] == 'update':
                        self.releases(bundle, selected)
                    if '--download-only' in args:
                        (bundle/'archives/fixture_amd64.deb').write_bytes(b'fake archive')
                    return b''
                module = {'ENV': {}, 'call': call}
                with patch.object(acquire_module, 'Path', side_effect=path), \
                     patch.object(acquire_module.runpy, 'run_path', return_value=module), \
                     patch.object(protocol, 'load', return_value=state), \
                     patch.object(protocol, 'digest', return_value='3'*64), \
                     patch.object(protocol, 'identity', return_value=state['module']), contextlib.redirect_stdout(io.StringIO()):
                    acquire_module.acquire()
                receipt = protocol.load(exported/'receipt.json')
                self.assertEqual(receipt['selection'], selected)
                self.assertEqual(receipt['pins'], protocol.selection(selected)['pins'])
                for args, seconds in calls:
                    self.assertLessEqual(seconds, 180)
                    if 'install' in args:
                        self.assertEqual(args[args.index('install')+1:],
                                         [k+'='+v for k,v in protocol.selection(selected)['pins'].items()])
                        self.assertIn('Dir::State::status='+str(bundle/'status'), args)
                self.assertFalse((bundle/'status').exists())
        for state in ([], {}, {'selection': 'unknown'}, {**self.state(protocol.BASELINE), 'pins': {}}):
            with patch.object(protocol, 'load', return_value=state), \
                 patch.object(acquire_module.runpy, 'run_path', return_value={'ENV': {}, 'call': lambda *a: self.fail('APT')}), \
                 patch.object(Path, 'mkdir', side_effect=AssertionError('workspace created')), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(Refusal):
                    acquire_module.acquire()

    def test_actual_target_invocation_and_witness_boundary(self):
        for selected in (protocol.TEST, protocol.BASELINE):
            with patch.object(target, 'bounded', return_value=(0, b'{"changed": false}')) as child:
                self.assertEqual(target.invoke('1'*64, True, selected=selected), {'changed': False})
            self.assertEqual(child.call_args.args[1], 240)
            command = child.call_args.args[0]
            self.assertEqual(command[-2:], ['--selection', selected])
            self.assertIn('1'*64, command)
            with patch.object(target.qemu_witness, 'probe', return_value={}) as witness, contextlib.redirect_stdout(io.StringIO()):
                target.finish_runtime(selected)
            self.assertEqual(witness.call_count, int(selected == protocol.TEST))
        with patch.object(target.Path, 'iterdir', side_effect=AssertionError('target touched')):
            with self.assertRaisesRegex(Refusal, 'independent'):
                target.main(protocol.BASELINE, None)

    def test_actual_host_launcher_passes_trusted_digest_and_selection(self):
        # Run the maintained shell body, replacing only its external Docker and
        # trusted acquisition boundary. No fake branch executes guest commands.
        for selected in (protocol.TEST, protocol.BASELINE):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = root/'test-qemu-offline.sh'
                script.write_bytes(Path(__file__).with_name(script.name).read_bytes())
                helper = root/'prepare-qemu-offline.sh'
                helper.write_text('#!/bin/bash\nset -eu\nmkdir "$2"\nprintf \'{"receipt_sha256":"'+'a'*64+'"}\\n\'\n')
                source = ownership.FAKE_DOCKER.replace("elif key == 'reference':", "elif key == 'id':\n                match &= val == obj['id']\n            elif key == 'reference':")
                source = source.replace("elif a[0] == 'start':", "elif a[0] == 'exec':\n    pass\nelif a[0] == 'cp':\n    if a[-2].endswith(':/target-state.json'):\n        Path(a[-1]).write_text('{}')\nelif a[0] == 'start':")
                fake = root/'docker'; fake.write_text(source); fake.chmod(0o755)
                state = root/'daemon.json'; state.write_text(json.dumps({'containers': {}, 'images': {}, 'calls': []}))
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                           FAKE_DOCKER_STATE=str(state), FAKE_DOCKER_MODE='success')
                args = ['bash', str(script)] + ([] if selected == protocol.TEST else ['--selection', selected])
                result = subprocess.run(args, env=env, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = json.loads(state.read_text())['calls']
                capture = next(args for args in calls if '--capture-state' in args)
                actual = next(args for args in calls if '--receipt-sha256' in args)
                self.assertEqual(capture[-2:], ['--selection', selected])
                self.assertEqual(actual[-4:], ['--selection', selected, '--receipt-sha256', 'a'*64])
                self.assertTrue(all(obj['name'].endswith('-foreign') for obj in json.loads(state.read_text())['containers'].values()))

    def test_actual_finish_traps_preserve_primary_with_cleanup_failure(self):
        for name in ('test-qemu-offline.sh', 'prepare-qemu-offline.sh'):
            source = Path(__file__).with_name(name).read_text()
            finish = 'finish() {' + source.split('finish() {', 1)[1].split('\ntrap finish EXIT', 1)[0]
            for primary in (0, 1, 124, 130, 143):
                program = ('set -eu\noutput_owned=0\ncleanup() { return 1; }\n'+finish+
                           '\ntrap finish EXIT\nexit '+str(primary)+'\n')
                result = subprocess.run(['bash', '-c', program], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, primary or 1, (name, primary, result.stderr))


if __name__ == '__main__':
    unittest.main(verbosity=2)
