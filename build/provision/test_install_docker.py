"""Offline mocked regressions for install-docker.py; no APT, network, container or system change."""
import contextlib
import hashlib
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hhfab_release import Refusal

INSTALL = Path(__file__).with_name('install-docker.py')
V = '5:29.1.3-1~ubuntu.24.04~noble'
C = '2.2.1-1~ubuntu.24.04~noble'
GOOD_PLAN = (f'Inst containerd.io ({C} Docker:noble [amd64])\n'
             f'Inst docker-ce-cli ({V} Docker:noble [amd64])\n'
             f'Inst docker-ce ({V} Docker:noble [amd64])\n'
             'Inst iptables (1.8.10 Ubuntu:24.04/noble [amd64])\n')


class DockerTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(INSTALL))
        self.g = self.module['install'].__globals__
        # Synthetic installer workspaces stay inside the harness's private TMPDIR.
        self.g['WORKDIR'] = tempfile.gettempdir()

    def test_exact_pins_sources_key_and_budget(self):
        m = self.module
        self.assertEqual(m['PINS'], {'docker-ce': V, 'docker-ce-cli': V, 'containerd.io': C})
        self.assertEqual(m['KEY_SHA256'], '1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570')
        self.assertEqual((m['BUDGET'], m['CHILD_CAP'], m['ALARM']), (210, 180, 235))
        with tempfile.TemporaryDirectory() as d:
            apt, config, key = m['setup'](Path(d))
            sources = (Path(d) / 'sources.list').read_text()
            self.assertIn('https://download.docker.com/linux/ubuntu noble stable', sources)
            for suite in ('noble', 'noble-updates', 'noble-security'):
                self.assertIn(f'snapshot.ubuntu.com/ubuntu/20260114T000000Z/ {suite} main universe', sources)
            self.assertNotIn('trusted=yes', sources)
            self.assertEqual(sources.count('signed-by='), 4)
            self.assertTrue(config.startswith(d))
            self.assertIn('Dir::Etc::main "' + d + '/none"', Path(config).read_text())
            flat = ' '.join(apt)
            self.assertIn('Dir::State::lists=' + d, flat)
            self.assertIn('Dir::Cache::archives=' + d, flat)
            self.assertIn('Acquire::AllowInsecureRepositories=false', flat)
            self.assertIn('APT::Get::AllowUnauthenticated=false', flat)
            self.assertNotIn('/etc/apt', flat + sources + Path(config).read_text())
            prefs = (Path(d) / 'preferences/docker.pref').read_text()
            self.assertIn(f'Pin: version {V}', prefs)
            self.assertIn('Pin-Priority: -1', prefs)

    def preflight_env(self, audit=b'', holds=b'', arch=b'amd64\n', foreign=b'', packages=None,
                      release='ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble', exists=lambda p: False):
        def call(args, seconds=10, env=None):
            if args[0].endswith('dpkg'):
                if '--get-selections' in args:
                    return b'docker-ce\thold\n' if holds else b'dpkg\tinstall\n'
                if '--print-foreign-architectures' in args:
                    return foreign
                return arch if '--print-architecture' in args else audit
            if args[0].endswith('apt-mark'):
                return holds
            self.fail('unexpected command')
        stack = contextlib.ExitStack()
        stack.enter_context(patch('os.geteuid', return_value=0))
        # Target behavior is mocked explicitly; local tests may run on 3.10+.
        stack.enter_context(patch.object(sys, 'version_info', (3, 12)))
        stack.enter_context(patch.object(Path, 'read_text', return_value=release))
        stack.enter_context(patch.object(Path, 'is_file', return_value=True))
        stack.enter_context(patch('os.path.lexists', side_effect=exists))
        stack.enter_context(patch.dict(self.g, {'call': call, 'installed': lambda: packages or {},
                                                'system_paths': lambda: None, 'safe_tree': lambda *a, **k: None}))
        return stack

    def test_platform_and_state_refusals(self):
        cases = [({'arch': b'arm64'}, 'amd64'), ({'foreign': b'i386'}, 'foreign'),
                 ({'audit': b'x'}, 'broken'), ({'holds': b'x'}, 'held'),
                 ({'release': 'ID=debian'}, 'Ubuntu'),
                 ({'release': 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy'}, 'Ubuntu'),
                 ({'packages': {'docker-ce': '5:28.0.0-1'}}, 'drift'),
                 ({'packages': {'docker.io': '1'}}, 'conflicting'),
                 ({'packages': {'containerd': '1'}}, 'conflicting'),
                 ({'packages': {'docker-ce': V}}, 'partially'),
                 ({'exists': lambda p: p == '/usr/bin/docker'}, 'collision')]
        for override, reason in cases:
            with self.subTest(reason=reason, override=list(override)), self.preflight_env(**override):
                with self.assertRaisesRegex(Refusal, reason):
                    self.module['preflight']()

    def test_nonroot_refused_before_any_command(self):
        with patch('os.geteuid', return_value=1000), patch.dict(self.g, {'call': lambda *a, **k: self.fail('cmd')}):
            with self.assertRaisesRegex(Refusal, 'root'):
                self.module['preflight']()

    def test_python_version_refused_before_native_command(self):
        with patch('os.geteuid', return_value=0), patch.object(sys, 'version_info', (3, 10)), \
             patch.dict(self.g, {'call': lambda *a, **k: self.fail('native command')}):
            with self.assertRaisesRegex(Refusal, 'Python 3.12'):
                self.module['preflight']()

    def test_unsafe_trees_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'real').write_text('x')
            os.symlink(root / 'real', root / 'link')
            with self.assertRaisesRegex(Refusal, 'link'):
                self.module['safe_tree'](root, uids=(os.geteuid(),))
            (root / 'link').unlink()
            os.link(root / 'real', root / 'hard')
            with self.assertRaisesRegex(Refusal, 'link'):
                self.module['safe_tree'](root, uids=(os.geteuid(),))
            (root / 'hard').unlink()
            (root / 'real').chmod(0o666)
            with self.assertRaisesRegex(Refusal, 'writable'):
                self.module['safe_tree'](root, uids=(os.geteuid(),))
            (root / 'real').chmod(0o644)
            with self.assertRaisesRegex(Refusal, 'unowned'):
                self.module['safe_tree'](root, uids=(os.geteuid() + 1,))
            self.module['safe_tree'](root, uids=(os.geteuid(),))

    def test_key_hash_and_size_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / 'docker.asc'
            for data in (b'wrong', b'x' * 20000):
                def run(args, plain=False, data=data):
                    key.write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaisesRegex(Refusal, 'key SHA256'):
                    self.module['fetch_key'](run, key)
            good = b'k'
            with patch.dict(self.module['fetch_key'].__globals__,
                            {'KEY_SHA256': hashlib.sha256(good).hexdigest()}):
                self.module['fetch_key'](lambda args, plain=False: key.write_bytes(good), key)
            self.assertEqual(oct(key.stat().st_mode & 0o777), '0o644')

    def test_unsafe_simulation_plans(self):
        check = self.module['check_plan']
        check(GOOD_PLAN)
        bad = {
            'removal': GOOD_PLAN + 'Remv libfoo [1]\n',
            'purge': GOOD_PLAN + 'Purg libfoo [1]\n',
            'unrelated': GOOD_PLAN + 'Inst libc6 [2.39-0] (2.39-1 Ubuntu:24.04/noble [amd64])\n',
            'conflicting': GOOD_PLAN + 'Inst docker.io (1 Ubuntu [amd64])\n',
            'version': GOOD_PLAN.replace(C, '2.2.2-1~ubuntu.24.04~noble'),
            'missing': GOOD_PLAN.replace('Inst docker-ce (', 'Inst other ('),
            'garbage': GOOD_PLAN + 'Inst ???\n',
            'large': GOOD_PLAN + ''.join(f'Inst pkg{i} (1 O [amd64])\n' for i in range(40)),
        }
        for name, plan in bad.items():
            with self.subTest(name), self.assertRaises(Refusal):
                check(plan)
        check(GOOD_PLAN.replace('Inst docker-ce (', f'Inst docker-ce [{V}] ('))  # trio re-select tolerated

    def transaction(self, installed_values, plan=GOOD_PLAN, fail_on=None, digest_ok=True, md5_ok=True, after=None):
        log = []
        state = {'now': 0.0}
        g = self.g

        def call(args, seconds=10, env=None):
            log.append((args, seconds, env))
            joined = ' '.join(args)
            if fail_on and fail_on in joined:
                raise Refusal('command failed: ' + fail_on)
            if '--simulate' in args:
                return plan.encode()
            return b''

        def digest(path):
            return g['ARCHIVES'].get(Path(path).name.split('_')[0], 'f' * 64) if digest_ok else '0' * 64
        installed_iter = iter(installed_values)

        def payloads():
            if not md5_ok:
                raise Refusal('installed pinned artifact drift: docker-ce')
            return {'usr/bin/dockerd': 'a' * 64}

        def fetch_key(run, key):
            run(['/usr/bin/curl', 'x'], plain=True)
        def archives(root, reviewed, run):
            if not digest_ok:
                raise Refusal('trio archive digest mismatch')
            return []
        patches = {'call': call, 'preflight': lambda: next(installed_iter), 'installed': lambda: dict(self.module['PINS'] if after is None else after),
                   'health': lambda: None, 'verify_payloads': payloads, 'fetch_key': fetch_key,
                   'safe_tree': lambda *a, **k: None, 'digest': digest, 'apt_uid': lambda: 0,
                   'verify_archives': archives}
        return log, patches

    def run_install(self, before, **kw):
        log, patches = self.transaction([before], **kw)
        # fake archives so the exact-name glob finds them
        real_tmp = tempfile.TemporaryDirectory

        class Tmp(real_tmp):
            def __enter__(inner):
                path = super().__enter__()
                (Path(path) / 'archives').mkdir()
                for n, v in self.module['PINS'].items():
                    (Path(path) / 'archives' / f'{n}_{v.split(":")[-1]}_amd64.deb').write_bytes(b'd')
                return path
        with patch.dict(self.g, patches), patch('tempfile.TemporaryDirectory', Tmp):
            with patch('builtins.print') as printed:
                self.module['install']()
        return log, printed

    def test_clean_install_order_environment_and_receipt(self):
        log, printed = self.run_install({})
        words = ('update', 'check', '--simulate', '--download-only', '--no-download')
        verbs = ['curl' if a[0].endswith('curl') else next(w for w in words if w in a) for a, _, _ in log]
        self.assertEqual(verbs, ['curl', 'update', 'check', '--simulate', '--download-only', '--simulate', '--no-download', 'check'])
        for args, seconds, env in log:
            self.assertLessEqual(seconds, 180)
            self.assertEqual(env['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
            if args[0].endswith('apt-get'):
                self.assertTrue(env['APT_CONFIG'].endswith('fixed.conf'))
                self.assertIn('--no-remove', args if 'install' in args else ['--no-remove'])
                for forbidden in ('upgrade', 'dist-upgrade', 'purge', 'remove', 'autoremove'):
                    self.assertNotIn(forbidden, args)
            else:
                self.assertNotIn('APT_CONFIG', env)
        receipt = __import__('json').loads(printed.call_args[0][0])
        self.assertEqual(receipt['key_sha256'], self.module['KEY_SHA256'])
        self.assertTrue(receipt['changed'])
        self.assertEqual(set(receipt['module']), {'install-docker.py', 'hhfab_release.py'})

    def test_install_failures_stop_before_mutation(self):
        for name, kw in [('authentication', {'fail_on': 'update'}), ('check', {'fail_on': 'check'}),
                         ('digest', {'digest_ok': False}),
                         ('plan', {'plan': GOOD_PLAN + 'Remv x [1]\n'})]:
            with self.subTest(name):
                log = None
                with self.assertRaises(Refusal):
                    log, _ = self.run_install({}, **kw)
        # digest/plan failures must never reach the mutating --no-download install
        for kw in ({'digest_ok': False}, {'plan': GOOD_PLAN + 'Remv x [1]\n'}):
            logs, patches = self.transaction([{}], **kw)
            seen = []
            patches['call'] = (lambda inner: lambda a, s=10, env=None: (seen.append(a), inner(a, s, env))[1])(patches['call'])
            with patch.dict(self.g, patches), self.assertRaises(Refusal):
                self.module['install']()
            self.assertFalse(any('--no-download' in a for a in seen))

    def test_post_install_health_and_version_failures(self):
        with self.assertRaisesRegex(Refusal, 'drift'):
            self.run_install({}, md5_ok=False)
        with self.assertRaisesRegex(Refusal, 'version mismatch'):
            self.run_install({}, after={'docker-ce': 'wrong'})

    def test_post_install_audit_failure_is_not_success(self):
        log, patches = self.transaction([{}])
        patches['health'] = lambda: (_ for _ in ()).throw(Refusal('post audit failure'))
        with patch.dict(self.g, patches), self.assertRaisesRegex(Refusal, 'post audit'):
            self.module['install']()
        self.assertTrue(any('--yes' in a and '--no-download' in a for a, _, _ in log))

    def test_plan_change_stops_mutation(self):
        log, patches = self.transaction([{}])
        inner = patches['call']
        def call(args, seconds=10, env=None):
            answer = inner(args, seconds, env)
            return (GOOD_PLAN + 'Inst extra (1 Ubuntu [amd64])\n').encode() if '--simulate' in args and '--no-download' in args else answer
        patches['call'] = call
        with patch.dict(self.g, patches), self.assertRaisesRegex(Refusal, 'simulation changed'):
            self.module['install']()
        self.assertFalse(any('--yes' in a and '--no-download' in a for a, _, _ in log))

    def test_archives_encoded_epoch_metadata_and_closure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'archives').mkdir()
            archive = root / 'archives/docker-ce_5%3a29.1.3_amd64.deb'
            archive.write_bytes(b'synthetic archive; never executed')
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            calls = []
            def native(args, plain=False):
                calls.append(args)
                return f'Package: docker-ce\nVersion: {V}\nArchitecture: amd64\n'.encode()
            with patch.dict(self.g, {'ARCHIVES': {'docker-ce': sha}, 'safe_tree': lambda *a, **k: None}):
                report = self.module['verify_archives'](root, {'docker-ce': V}, native)
                self.assertEqual(report[0]['sha256'], sha)
                self.assertEqual(calls[0][0], '/usr/bin/dpkg-deb')
                with self.assertRaisesRegex(Refusal, 'cover'):
                    self.module['verify_archives'](root, {'docker-ce': V, 'dep': '1'}, native)
                with self.assertRaisesRegex(Refusal, 'reviewed simulation'):
                    self.module['verify_archives'](root, {'docker-ce': 'wrong'}, native)
            calls.clear()
            with patch.dict(self.g, {'safe_tree': lambda *a, **k: None}), self.assertRaisesRegex(Refusal, 'digest'):
                self.module['verify_archives'](root, {'docker-ce': V}, native)
            self.assertEqual(calls, [])  # reject wrong pinned bytes before dpkg-deb

    def test_payload_integrity_and_link_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            artifact = root / 'usr/bin/docker'
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b'synthetic payload')
            expected = hashlib.md5(artifact.read_bytes()).hexdigest()
            patches = {'PAYLOADS': {'docker-ce-cli': 'usr/bin/docker', 'containerd.io': 'usr/bin/docker'},
                       'EXTRA_PAYLOADS': (), 'call': lambda *a, **k: f'{expected}  usr/bin/docker\n'.encode()}
            with patch.dict(self.g, patches):
                self.assertEqual(set(self.module['verify_payloads'](root)), {'usr/bin/docker'})
                artifact.write_bytes(b'corrupt')
                with self.assertRaisesRegex(Refusal, 'drift'):
                    self.module['verify_payloads'](root)
                artifact.unlink()
                artifact.symlink_to('missing')
                with self.assertRaisesRegex(Refusal, 'link'):
                    self.module['verify_payloads'](root)

    def test_receipt_parent_refused_before_any_transaction(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            link = root / 'link'
            link.symlink_to(root, target_is_directory=True)
            with patch.dict(self.g, {'preflight': lambda: {}, 'call': lambda *a, **k: self.fail('native')}):
                with self.assertRaisesRegex(Refusal, 'parent'):
                    self.module['install'](link / 'receipt')

    def test_bounded_failures_propagate_and_cleanup(self):
        for failure in (Refusal('timeout'), Refusal('output overflow'), KeyboardInterrupt()):
            log, patches = self.transaction([{}])
            patches['call'] = lambda *a, failure=failure, **k: (_ for _ in ()).throw(failure)
            with tempfile.TemporaryDirectory() as d:
                real_tmp = tempfile.TemporaryDirectory
                class Tmp(real_tmp):
                    def __init__(inner, *a, **k):
                        super().__init__(prefix='owned-', dir=d)
                with patch.dict(self.g, patches), patch('tempfile.TemporaryDirectory', Tmp):
                    with self.assertRaises(type(failure)):
                        self.module['install']()
                self.assertEqual(list(Path(d).iterdir()), [])

    def test_cli_sigterm_reaps_python_child(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pidfile = root / 'pid'
            child = "import os,signal,time;from pathlib import Path;Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid()));os.kill(os.getppid(),signal.SIGTERM);time.sleep(10)"
            program = '''
import runpy,sys
sys.path.insert(0, sys.argv[1])
from hhfab_release import bounded
m=runpy.run_path(sys.argv[2]);main=m['main']
child=sys.argv[3]
main.__globals__['install']=lambda receipt: bounded([sys.executable,'-I','-B','-c',child],5)
sys.argv=['install-docker.py']
try:main()
except KeyboardInterrupt:sys.exit(130)
'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(INSTALL.parent), str(INSTALL), child], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 130, result.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_rerun_reauthenticates_without_install(self):
        full = dict(self.module['PINS'])
        log, _ = self.run_install(full)
        mutating = [a for a, _, _ in log if '-y' in a or '--yes' in a or 'install' in a]
        self.assertEqual(mutating, [])
        self.assertEqual(len(log), 4)  # key, authenticated update and health checks
        with self.assertRaisesRegex(Refusal, 'drift'):
            self.run_install(full, md5_ok=False)

    def test_receipt_create_compare_and_unsafe_path(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'r.json'
            receipt = {'a': 1}
            self.module['persist'](path, receipt)
            self.module['persist'](path, receipt)
            with self.assertRaisesRegex(Refusal, 'receipt does not match'):
                self.module['persist'](path, {'a': 2})
            link = Path(d) / 'link.json'
            os.symlink(path, link)
            with self.assertRaisesRegex(Refusal, 'link'):
                self.module['persist'](link, receipt)
            self.assertEqual([p.name for p in Path(d).iterdir() if p.name.startswith('.docker')], [])

    def test_deadline_exceeded_and_cleanup(self):
        log, patches = self.transaction([{}])
        times = iter([0.0, 300.0] + [300.0] * 20)
        created = []
        real_tmp = tempfile.TemporaryDirectory

        class Tmp(real_tmp):
            def __enter__(inner):
                path = super().__enter__()
                created.append(path)
                return path
        with patch.dict(self.g, patches), patch('time.monotonic', side_effect=lambda: next(times)), \
                patch('tempfile.TemporaryDirectory', Tmp):
            with self.assertRaisesRegex(Refusal, 'deadline'):
                self.module['install']()
        self.assertFalse(os.path.exists(created[0]))  # private workspace removed
        self.assertEqual(log, [])  # no child launched after budget exhausted

    def test_no_global_policy_mutation(self):
        text = INSTALL.read_text()
        for forbidden in ('trusted=yes', 'apt-mark hold', '"apt-mark", "hold"', 'AllowUnauthenticated": "true"',
                          '/etc/apt/', 'apt-key', 'sources.list.d', '--allow-unauthenticated',
                          'dist-upgrade', '--allow-downgrades'):
            self.assertNotIn(forbidden, text, forbidden)
        self.assertNotIn('"upgrade"', text)


if __name__ == '__main__':
    unittest.main()
