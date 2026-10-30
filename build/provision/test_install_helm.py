"""Synthetic actual-code Helm tests. Never fetch or execute Helm; fake children only."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import random
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import hhfab_release as release

spec = importlib.util.spec_from_file_location('helm_installer', Path(__file__).with_name('install-helm.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
PAYLOAD = b'synthetic Helm bytes, never execute'
CONTRACT = ((b'linux-amd64/', b'5', 0), (b'linux-amd64/LICENSE', b'0', 3),
            (b'linux-amd64/README.md', b'0', 2), (b'linux-amd64/helm', b'0', len(PAYLOAD)))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(payload=PAYLOAD, contract=CONTRACT):
    # Stdlib tar writer supplies an independent producer, including GNU magic.
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for index, ((name, kind, size), data) in enumerate(zip(contract, (b'', b'lic', b'rd', payload))):
            entry = tarfile.TarInfo(name.decode())
            entry.type, entry.size = kind, size
            entry.mode = 0o755 if index in (0, 3) else 0o644
            tar.addfile(entry, io.BytesIO(data))
    return out.getvalue()


def checksum(header):
    header[148:156] = b'        '
    header[148:156] = ('%06o\0 ' % sum(header)).encode()
    return header


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dest = self.root / 'bin'
        self.dest.mkdir(mode=0o700)
        self.target = self.dest / 'helm'
        self.archive = self.root / 'fixture.gz'
        self.raw = fixture()
        self.pin = {'url': 'https://example.invalid/helm', 'size': len(PAYLOAD), 'sha256': sha(PAYLOAD)}
        self.write(self.raw)
        for obj, name, value in ((h, 'MEMBERS', CONTRACT), (h, 'PINS', {'3.19.4': self.pin})):
            p = patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.old_alarm = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, self.old_alarm)

    def write(self, raw=None, compressed=None):
        data = gzip.compress(raw if raw is not None else self.raw, mtime=0) if compressed is None else compressed
        self.archive.write_bytes(data)
        self.pin.update(archive_size=len(data), archive_sha256=sha(data))

    def install(self, archive='default'):
        return h.install('3.19.4', 'linux/amd64', self.dest, self.archive if archive == 'default' else archive)

    def names(self):
        return sorted(p.name for p in self.dest.iterdir())

    def test_install_rerun_repair_and_result_identity(self):
        out = self.install()
        self.assertEqual(out['status'], 'installed')
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(self.names(), ['helm'])
        self.assertEqual(self.target.stat().st_nlink, 1)
        before = h.identity(self.target.stat())
        with patch.object(h, 'extract_helm', side_effect=AssertionError), patch.object(h, 'curl', side_effect=AssertionError):
            self.assertEqual(self.install(archive=None)['status'], 'unchanged')
            self.assertEqual(self.install(archive=self.root / 'missing')['status'], 'unchanged')
        self.assertEqual(before, h.identity(self.target.stat()))
        for mode in (0o644, 0o700, 0o4755):
            self.target.chmod(mode)
            inode = self.target.stat().st_ino
            self.assertEqual(self.install()['status'], 'mode-repaired')
            self.assertNotEqual(inode, self.target.stat().st_ino)
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(out['module_sha256'], release.digest(Path(h.__file__)))
        self.assertEqual(out['helper_sha256'], release.digest(Path(release.__file__)))
        self.assertEqual(out['archive_sha256'], self.pin['archive_sha256'])
        self.assertEqual(out['target_sha256'], sha(PAYLOAD))
        self.assertEqual(out['target'], str(self.target))
        self.assertFalse(out['executed'])
        self.assertIn('GPG', out['not_verified'])
        self.assertIn('no rollback', out['atomicity'])
        self.assertLessEqual(len(json.dumps(out).encode()) + 1, 4096)

    def test_drift_refused_without_input_or_mutation(self):
        for payload in (b'', b'other', PAYLOAD[:-1] + b'!'):
            self.target.write_bytes(payload)
            before = h.identity(self.target.stat())
            with patch.object(h, 'extract_helm', side_effect=AssertionError), self.assertRaisesRegex(release.Refusal, 'differs'):
                self.install()
            self.assertEqual(self.target.read_bytes(), payload)
            self.assertEqual(h.identity(self.target.stat()), before)

    def test_unsafe_target_shapes_and_owner(self):
        for shape in ('symlink', 'hardlink', 'directory', 'fifo'):
            if shape == 'symlink': self.target.symlink_to(self.archive)
            elif shape == 'hardlink': os.link(self.archive, self.target)
            elif shape == 'directory': self.target.mkdir()
            else: os.mkfifo(self.target)
            with self.assertRaises(release.Refusal): self.install()
            self.target.rmdir() if shape == 'directory' else self.target.unlink()
        self.target.write_bytes(PAYLOAD)
        with patch.object(h, 'directory'), patch.object(h.os, 'geteuid', return_value=os.geteuid()+1), self.assertRaises(release.Refusal):
            self.install()

    def test_unsafe_paths_platform_default_and_budget(self):
        link = self.root / 'link'
        link.symlink_to(self.dest)
        for dest in (link, Path('relative'), self.root / 'missing'):
            with self.assertRaises((release.Refusal, OSError)):
                h.install('3.19.4', 'linux/amd64', dest, self.archive)
        self.dest.chmod(0o777)
        with self.assertRaises(release.Refusal): self.install()
        self.dest.chmod(0o700)
        for version, platform_name in (('latest', 'linux/amd64'), ('3.19.4', 'linux/arm64')):
            with self.assertRaises(release.Refusal): h.install(version, platform_name, self.dest, self.archive)
        for attribute, value in (('system', 'Darwin'), ('machine', 'aarch64')):
            with patch.object(h.platform, attribute, return_value=value), self.assertRaises(release.Refusal): self.install()
        with patch.object(h.os, 'geteuid', return_value=1000), self.assertRaisesRegex(release.Refusal, 'requires root'):
            h.install('3.19.4', 'linux/amd64', Path('/usr/local/bin'), self.archive)
        with self.assertRaisesRegex(release.Refusal, 'result budget'):
            h.install('3.19.4', 'linux/amd64', Path('/' + 'x'*1100), self.archive)

    def test_unsafe_archive_paths(self):
        for shape in ('symlink', 'hardlink', 'fifo', 'directory', 'relative'):
            path = self.root / 'bad'
            if shape == 'symlink': path.symlink_to(self.archive)
            elif shape == 'hardlink': os.link(self.archive, path)
            elif shape == 'fifo': os.mkfifo(path)
            elif shape == 'directory': path.mkdir()
            else: path = Path('relative')
            with self.assertRaises((release.Refusal, OSError)): self.install(path)
            if shape == 'directory': path.rmdir()
            elif shape != 'relative': path.unlink()
            self.assertEqual(self.names(), [])

    def test_streaming_across_compressed_and_expanded_boundaries(self):
        payload = random.Random(332).randbytes(200000)
        contract = CONTRACT[:-1] + ((b'linux-amd64/helm', b'0', len(payload)),)
        self.pin.update(size=len(payload), sha256=sha(payload))
        self.write(fixture(payload, contract))
        self.assertGreater(self.pin['archive_size'], 128*1024)
        with patch.object(h, 'MEMBERS', contract):
            self.assertEqual(self.install()['status'], 'installed')
        self.assertEqual(self.target.read_bytes(), payload)
        self.assertEqual(self.names(), ['helm'])

    def test_wrong_compressed_hash_never_parses(self):
        self.pin['archive_sha256'] = '0'*64
        with patch.object(h, 'parse_helm', side_effect=AssertionError('parser reached')), self.assertRaisesRegex(release.Refusal, 'archive checksum'):
            self.install()
        self.assertEqual(self.names(), [])

    def refused_parser_fixture(self, raw=None, compressed=None):
        self.write(raw, compressed)
        self.target.write_bytes(PAYLOAD)
        self.target.chmod(0o644)  # deliberately defeat unchanged fast path
        before = h.identity(self.target.stat())
        actual = h.parse_helm
        with patch.object(h, 'parse_helm', wraps=actual) as parser, self.assertRaises(release.Refusal): self.install()
        self.assertEqual(parser.call_count, 1)
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(h.identity(self.target.stat()), before)
        self.assertEqual(self.names(), ['helm'])
        self.target.unlink()

    def test_physical_names_and_forbidden_types_reach_parser(self):
        for name in (b'../escape', b'/tmp/escape', b'linux-amd64/helm', b'linux-amd64\\escape'):
            raw = bytearray(self.raw)
            header = raw[:512]
            header[:100] = name.ljust(100, b'\0')
            raw[:512] = checksum(header)
            self.refused_parser_fixture(bytes(raw))
        for kind in (b'1', b'2', b'3', b'4', b'6', b'S', b'x', b'g', b'L', b'K', b'\0'):
            raw = bytearray(self.raw)
            header = raw[:512]
            header[156:157] = kind
            raw[:512] = checksum(header)
            self.refused_parser_fixture(bytes(raw))

    def test_header_size_checksum_prefix_link_magic_and_count(self):
        for start, data in ((0, b'X'), (100, b'0000644\0'), (124, b'00000000001\0'), (124, b'\x80' + b'\0'*11),
                            (157, b'link'), (345, b'prefix'), (257, b'badmagic'), (10, b'\0X')):
            raw = bytearray(self.raw)
            header = raw[:512]
            header[start:start+len(data)] = data
            raw[:512] = header if start == 0 else checksum(header)
            self.refused_parser_fixture(bytes(raw))
        # Missing and duplicate physical entries; no tarfile normalization hides them.
        self.refused_parser_fixture(self.raw[512:])
        self.refused_parser_fixture(self.raw[:512] + self.raw)
        end = 512 + 1024 + 1024 + 512 + ((len(PAYLOAD)+511)//512)*512
        self.refused_parser_fixture(self.raw[:end] + self.raw[:512] + b'\0'*1024)

    def test_member_padding_end_and_member_hash(self):
        raw = bytearray(self.raw)
        raw[512+512+3] = 1  # LICENSE padding
        self.refused_parser_fixture(bytes(raw))
        end = 512+1024+1024+512+512
        for tail in (b'', b'\0'*512, b'\0'*1025, b'\0'*1024+b'X'):
            self.refused_parser_fixture(self.raw[:end] + tail)
        raw = bytearray(self.raw)
        raw[3072] ^= 1  # selected binary data, size unchanged
        self.refused_parser_fixture(bytes(raw))

    def test_gzip_truncation_crc_trailing_concatenation_and_expanded_bound(self):
        data = self.archive.read_bytes()
        for broken in (data[:-1], data[:12], data[:-8] + b'XXXXXXXX', data+b'X', data+gzip.compress(b'')):
            self.refused_parser_fixture(compressed=broken)
        with patch.object(h, 'EXPANDED_LIMIT', 100): self.refused_parser_fixture(self.raw)

    def test_download_arguments_environment_and_output(self):
        calls = []
        def fake(args, seconds, **kwargs):
            calls.append((args, seconds, kwargs))
            Path(args[args.index('--output')+1]).write_bytes(self.archive.read_bytes())
            return 0, b''
        with patch.object(h, 'curl', return_value='/usr/bin/curl'), patch.object(h, 'bounded', fake), patch.dict(os.environ, HTTPS_PROXY='http://invalid', CURL_HOME='/invalid'):
            self.assertEqual(self.install(None)['status'], 'installed')
        (args, seconds, kwargs), = calls
        self.assertEqual(args[:2], ['/usr/bin/curl', '--disable'])
        for option, value in (('--proto','=https'), ('--proto-redir','=https'), ('--retry','0'), ('--max-time','120'), ('--max-filesize',str(self.pin['archive_size']))):
            self.assertEqual(args[args.index(option)+1], value)
        self.assertEqual(args[-1], self.pin['url'])
        self.assertEqual(seconds, 125)
        self.assertEqual(kwargs, {'env': {'PATH':'/usr/bin:/bin','LC_ALL':'C'}})
        self.assertTrue(Path(args[args.index('--output')+1]).is_absolute())

    def test_download_failure_missing_curl_and_cancellation_cleanup(self):
        for error in (release.Refusal('primary'), KeyboardInterrupt()):
            with patch.object(h, 'curl', return_value='/usr/bin/curl'), patch.object(h, 'bounded', side_effect=error), self.assertRaises(type(error)):
                self.install(None)
            self.assertEqual(self.names(), [])
        with patch.object(h, 'CURL_DIRS', (str(self.root / 'missing'),)), patch.object(h.tempfile, 'mkdtemp', side_effect=AssertionError), self.assertRaises(release.Refusal):
            self.install(None)
        for code, data in ((22, None), (0, b'bad archive')):
            def fake(args, seconds, **kwargs):
                if data is not None: Path(args[args.index('--output')+1]).write_bytes(data)
                return code, b''
            with patch.object(h, 'curl', return_value='/usr/bin/curl'), patch.object(h, 'bounded', fake), self.assertRaises(release.Refusal): self.install(None)
            self.assertEqual(self.names(), [])

    def test_real_bounded_child_cwd_env_stdin_timeout_and_overflow(self):
        args = [sys.executable, '-I', '-B', '-c', 'import os,sys;print(os.getcwd());print(dict(os.environ));print(repr(sys.stdin.read()))']
        code, output = h.bounded(args, 3, env=dict(h.CHILD_ENV))
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith(b'/\n'))
        self.assertNotIn(b'HOME', output)
        self.assertTrue(output.endswith(b"''\n"))
        for program, seconds, limit, expected in (('import time;time.sleep(10)', .1, 4096, 'timeout'), ('print("x"*10000)', 3, 100, 'overflow')):
            started = time.monotonic()
            with self.assertRaisesRegex(release.Refusal, expected): h.bounded([sys.executable, '-I', '-B', '-c', program], seconds, limit=limit, env=dict(h.CHILD_ENV))
            self.assertLess(time.monotonic()-started, 4)

    def test_alarm_main_cleans_stage(self):
        argv = ['x','--version','3.19.4','--platform','linux/amd64','--install-dir',str(self.dest)]
        with patch.object(sys, 'argv', argv), patch.object(h, 'TOTAL', 1), patch.object(h, 'curl', return_value='/usr/bin/curl'), patch.object(h, 'bounded', side_effect=lambda *a, **k:time.sleep(10)), self.assertRaisesRegex(release.Refusal, 'deadline'):
            h.main()
        self.assertEqual(signal.alarm(0), 0)
        self.assertEqual(self.names(), [])

    def test_target_races_no_clobber_or_replace(self):
        actual = h.extract_helm
        for existing in (False, True):
            if existing:
                self.target.write_bytes(PAYLOAD)
                self.target.chmod(0o644)
            def race(*args):
                actual(*args)
                replacement = self.root / 'replacement'
                replacement.write_bytes(b'racing writer')
                os.replace(replacement, self.target)
            with patch.object(h, 'extract_helm', race), self.assertRaisesRegex(release.Refusal, 'destination changed'): self.install()
            self.assertEqual(self.target.read_bytes(), b'racing writer')
            self.assertEqual(self.names(), ['helm'])
            self.target.unlink()

    def test_unknown_stage_child_retained_primary_error_preserved(self):
        def extra(archive, target, pin):
            (target.parent / 'unknown').symlink_to('/no/such/target')
            raise release.Refusal('primary')
        with patch.object(h, 'extract_helm', extra), self.assertRaisesRegex(release.Refusal, 'primary'): self.install()
        stage, = self.dest.iterdir()
        self.assertTrue((stage / 'unknown').is_symlink())
        (stage / 'unknown').unlink()
        stage.rmdir()

    def test_cleanup_failure_after_publication_refuses_success(self):
        actual = h.extract_helm
        def extra(*args):
            actual(*args)
            (args[1].parent / 'unknown').write_bytes(b'keep')
        with patch.object(h, 'extract_helm', extra), self.assertRaisesRegex(release.Refusal, 'cleanup failed'): self.install()
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        stage, = self.dest.glob('.helm-stage-*')
        self.assertEqual((stage / 'unknown').read_bytes(), b'keep')
        (stage / 'unknown').unlink()
        stage.rmdir()

    def test_result_observed_mutation_and_budget(self):
        self.install()
        actual = h.digest
        def changed(path):
            value = actual(path)
            self.target.chmod(0o644)
            return value
        with patch.object(h, 'digest', changed), self.assertRaises(release.Refusal): h.result('3.19.4', self.pin, self.target, 'unchanged')
        self.target.chmod(0o755)
        with patch.object(h, 'RESULT_LIMIT', 1), self.assertRaisesRegex(release.Refusal, 'output budget'): h.result('3.19.4', self.pin, self.target, 'unchanged')

    def test_actual_sigterm_entrypoint_cleans_owned_stage(self):
        # Only this inspected inline Python launches; the downloader is replaced
        # before main, so no curl or Helm is executed by this child.
        injection = ("\n    def fake_download(pin,target):\n"
                     "        target.write_bytes(b'partial');os.kill(os.getpid(),signal.SIGTERM)\n"
                     "    download=fake_download\n")
        marker = '    try:\n        main()'
        program = ("import os,signal,sys;from pathlib import Path;"
                   "sys.path.insert(0,sys.argv[1]);"
                   "source=Path(sys.argv[1])/'install-helm.py';code=source.read_text();"
                   + "code=code.replace(" + repr(marker) + "," + repr(injection + marker) + ");"
                   + "sys.argv=[str(source),'--version','3.19.4','--platform','linux/amd64','--install-dir',sys.argv[2]];"
                   "exec(compile(code,str(source),'exec'),{'__name__':'__main__','__file__':str(source)})")
        completed = subprocess.run([sys.executable, '-I', '-B', '-c', program,
                                    str(Path(h.__file__).parent), str(self.dest)],
                                   stdin=subprocess.DEVNULL, capture_output=True,
                                   env=dict(h.CHILD_ENV), cwd='/', timeout=5)
        self.assertEqual(completed.returncode, 130)
        self.assertIn(b'interrupted', completed.stderr)
        self.assertEqual(self.names(), [])

    def test_maintained_ci_cleanup_preserves_unknowns_and_primary(self):
        workflow = Path(__file__).parents[2] / '.github/workflows/ci.yml'
        text = workflow.read_text().split('      - name: Required Helm installer offline regressions',1)[1]
        text = text.split('      - name: Required kubectl',1)[0]
        lines = [line[10:] for line in text.splitlines() if line.startswith('          ')]
        prelude = '\n'.join(lines).split('env -i HOME=',1)[0]
        # Execute the actual maintained shell cleanup, replacing only test-root
        # creation and stopping before unittest to avoid recursive discovery.
        for code, unknown in ((0,False),(0,True),(17,True)):
            root = self.root / ('outer-%s-%s' % (code,unknown))
            root.mkdir(mode=0o700)
            script = prelude.replace('test_root=$(mktemp -d /tmp/labapp-helm-tests.XXXXXX)',
                                     'test_root=$1')
            script += ('\ntouch "$test_root/tmp/unknown"\n' if unknown else '\n') + 'exit %s\n' % code
            result = subprocess.run(['/bin/bash','-c',script,'helm-test',str(root)],
                                    stdin=subprocess.DEVNULL,capture_output=True,cwd=str(workflow.parents[2]),
                                    env=dict(h.CHILD_ENV),timeout=5)
            self.assertEqual(result.returncode, code if code else int(unknown))
            self.assertEqual(os.path.lexists(root), unknown)
            if unknown:
                self.assertTrue((root/'tmp/unknown').is_file())
                (root/'tmp/unknown').unlink()
                (root/'tmp').rmdir()
                root.rmdir()

    def test_stage_replacement_and_known_child_type_preserved(self):
        actual = h.extract_helm
        for mutation in ('directory-mode', 'known-child-link'):
            def changed(*args):
                actual(*args)
                stage = args[1].parent
                if mutation == 'directory-mode': stage.chmod(0o750)
                else: (stage / 'archive.tar.gz').symlink_to(self.root / 'missing')
            with patch.object(h, 'extract_helm', changed), self.assertRaisesRegex(release.Refusal, 'cleanup failed'):
                self.install()
            stage, = self.dest.glob('.helm-stage-*')
            if mutation == 'known-child-link':
                self.assertTrue((stage / 'archive.tar.gz').is_symlink())
                (stage / 'archive.tar.gz').unlink()
            stage.rmdir()
            self.target.unlink()

    def test_real_download_failure_and_group_cancellation(self):
        fake = self.root / 'fake-curl'
        # Fixed inspected shell script: fails immediately, never invokes network.
        fake.write_text('#!/bin/sh\nexit 22\n')
        fake.chmod(0o755)
        with patch.object(h, 'curl', return_value=str(fake)), self.assertRaisesRegex(release.Refusal, 'download failed'):
            self.install(None)
        self.assertEqual(self.names(), [])
        marker = self.root / 'child-pid'
        program = ('import os,signal,sys,time;from pathlib import Path;'
                   'Path(sys.argv[1]).write_text(str(os.getpid()));'
                   'os.kill(os.getppid(),signal.SIGALRM);time.sleep(10)')
        def interrupted(signum, frame): raise release.Refusal('fixture cancellation')
        signal.signal(signal.SIGALRM, interrupted)
        with self.assertRaisesRegex(release.Refusal, 'fixture cancellation'):
            h.bounded([sys.executable,'-I','-B','-c',program,str(marker)],3,env=dict(h.CHILD_ENV))
        pid = int(marker.read_text())
        with self.assertRaises(ProcessLookupError): os.kill(pid,0)

    def test_cli_json_and_explicit_choices(self):
        args = ['x','--version','3.19.4','--platform','linux/amd64','--install-dir',str(self.dest),'--archive',str(self.archive)]
        out = io.StringIO()
        with patch.object(sys, 'argv', args), contextlib.redirect_stdout(out): h.main()
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(out.getvalue())['status'], 'installed')
        for argv in (['x'], ['x','--version','3.19.4'], ['x','--version','latest','--platform','linux/amd64'], args+['--force'], ['x','--ver','3.19.4','--platform','linux/amd64']):
            with patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): h.main()


class PinTests(unittest.TestCase):
    def test_exact_source_pins_contract_limits(self):
        pin = h.PINS['3.19.4']
        self.assertEqual(pin['archive_size'], 18014603)
        self.assertEqual(pin['archive_sha256'], '759c656fbd9c11e6a47784ecbeac6ad1eb16a9e76d202e51163ab78504848862')
        self.assertEqual(pin['size'], 60182712)
        self.assertEqual(pin['sha256'], 'ea22096683b9b61005584501e36168a1eadc5b6883a89df299f5a55e4e2dd283')
        self.assertEqual(pin['url'], 'https://get.helm.sh/helm-v3.19.4-linux-amd64.tar.gz')
        self.assertEqual(h.MEMBERS, ((b'linux-amd64/',b'5',0), (b'linux-amd64/LICENSE',b'0',11373), (b'linux-amd64/README.md',b'0',3699), (b'linux-amd64/helm',b'0',60182712)))
        self.assertEqual((h.TRANSFER,h.CHILD,h.TOTAL,h.EXPANDED_LIMIT), (120,125,180,70*1024*1024))


if __name__ == '__main__': unittest.main()
