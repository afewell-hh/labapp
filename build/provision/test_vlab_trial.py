"""Fixed shared trial entrypoints, public temp files and fail-closed spies only.

No real package/systemd/hhfab/QEMU/sudo/network/process invocation. Production
paths are patched before mutating entrypoints; no credential fixtures exist.
"""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import hhfab_release
import vlab_trial as trial

REAL_REGULAR, REAL_ATOMIC = trial.regular, trial.atomic
NONCE = 'a' * 32
SENTINEL = 'PRIVATE-SENTINEL-kubeconfig-token-password'


class CoreFailure(Exception):
    def __init__(self, message='', code=1, uncertain=False):
        super().__init__(message)
        self.code = code
        if uncertain:
            self.cleanup_uncertain = True


def worker_state(state='failed', code=17, phase='stage', operation='install-docker',
                 category='child-exit', child=17, nonce=NONCE, seq=3):
    if state == 'running':
        code, detail = None, None
    elif state == 'succeeded':
        phase, operation, code, detail = 'persistence', 'complete', 0, dict(trial.SUCCESS)
    else:
        detail = {'origin': 'worker', 'phase': phase, 'operation': operation,
                  'category': category, 'child_status': child}
    return {'schema': 1, 'nonce': nonce, 'seq': seq, 'state': state, 'phase': phase,
            'operation': operation, 'code': code, 'diagnostic': detail}


def value():
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    return {'schema': 1, 'nonce': 'a' * 32, 'lease': '11111111-1111-4111-8111-111111111111',
            'epoch': 1, 'run_id': 1, 'attempt': 1, 'body_sha256': 'b' * 64,
            'vm_id': '123', 'boot_id': '456', 'image_id': '4575951068918267275',
            'admitted_at': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'deadline': (start+timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'boot_uuid': '22222222-2222-4222-8222-222222222222', 'source_sha': 'c' * 40}


class SharedTrial(unittest.TestCase):
    def setUp(self):
        original_umask = os.umask(0o077)
        os.umask(original_umask)
        self.addCleanup(os.umask, original_umask)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(trial.subprocess, 'Popen', side_effect=AssertionError('no real child')))
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-trial-offline-'))
        self.base = Path(self.temp)
        self.root = self.base / 'root'
        self.stack.enter_context(patch.object(trial, 'ROOT', self.root))
        self.stack.enter_context(patch.object(trial, 'UNIT_PATH', self.base / 'unit.service'))

    def test_phase_bounds_compose_and_backwards_clock_does_not_renew(self):
        v = value()
        start = trial.stamp(v['admitted_at'])
        wall, mono = [start + 34*60], [100.]
        clock = trial.Clock(v, lambda: wall[0], lambda: mono[0])
        self.assertEqual(clock.remaining('stage'), 60)
        wall[0] -= 500
        mono[0] += 61
        with self.assertRaises(trial.Failure) as failure: clock.remaining('stage')
        self.assertEqual(failure.exception.code, 124)
        self.assertGreater(clock.cleanup_remaining(), 0)
        mono[0] += 120*60
        with self.assertRaises(trial.Failure): clock.cleanup_remaining()

    def test_contract_rejects_changed_deadline_or_image(self):
        for field, replacement in (('deadline', '2028-01-01T00:00:00Z'), ('image_id', '7638370619126112785'),
                                    ('nonce', '../work'), ('epoch', True)):
            v = value()
            v[field] = replacement
            with self.assertRaises((trial.Failure, ValueError)): trial.contract(v)

    def test_exact_manifest_rejects_extra_path_wrong_tool_size_or_hash(self):
        files = {name: {'bytes': 1, 'sha256': 'a'*64} for name in trial.FILES}
        for name, (size, sha) in trial.PAYLOADS.items(): files[name] = {'bytes': size, 'sha256': sha}
        table = {'schema': 1, 'source_sha': 'c'*40, 'files': files}
        trial.manifest(table)
        files['../arbitrary'] = {'bytes': 1, 'sha256': 'a'*64}
        with self.assertRaises(trial.Failure): trial.manifest(table)
        del files['../arbitrary']
        files['hhfab.tar.gz']['sha256'] = '0'*64
        with self.assertRaises(trial.Failure): trial.manifest(table)

    def test_regular_rejects_symlink_hardlink_and_overflow(self):
        source = self.base / 'source'
        source.write_bytes(b'public')
        link = self.base / 'link'
        link.symlink_to(source)
        with self.assertRaises(trial.Failure): trial.regular(link, 10)
        link.unlink()
        os.link(source, link)
        with self.assertRaises(trial.Failure): trial.regular(source, 10)
        link.unlink()
        with self.assertRaises(trial.Failure): trial.regular(source, 1)

    def test_unsupported_entrypoint_arguments_cannot_provision(self):
        with patch.object(trial.os, 'geteuid', return_value=0), patch.object(trial, 'worker') as worker:
            with self.assertRaises(trial.Failure): trial.main(['worker', '--nonce', 'a'*32])
            worker.assert_not_called()

    def test_nonzero_child_preserves_primary_signal_and_timeout_codes(self):
        clock = Mock()
        clock.remaining.return_value = 60
        for code in (124, 130, 143, 17, -15):
            with patch.object(hhfab_release, 'bounded', return_value=(code, b'private diagnostic')):
                with self.assertRaises(trial.Failure) as caught: trial.run(['/fixed/tool'], clock, 'stage')
                self.assertEqual(caught.exception.code, 143 if code == -15 else code)
                self.assertNotIn('private', str(caught.exception))

    def test_auxiliary_plan_preserves_stock_and_refuses_solver_repairs(self):
        self.assertEqual(trial.auxiliary_plan(b'Inst socat (1.8.0.0 Ubuntu:24.04/noble [amd64])\n', {}), {'socat': '1.8.0.0'})
        for raw in (b'Remv sudo [1]\n', b'Purg less\n', b'Inst sudo [1] (2 Ubuntu [amd64])\n', b'Inst broken\n'):
            with self.assertRaises(trial.Failure): trial.auxiliary_plan(raw, {'sudo': '1'})

    def test_pressure_and_poststage_gates_are_distinct(self):
        fs = SimpleNamespace(f_bavail=100, f_frsize=trial.GIB, f_favail=10000)
        with patch.object(trial.os, 'statvfs', return_value=fs), patch.object(trial, 'memory_available', return_value=32*trial.GIB):
            trial.resources()
            with self.assertRaises(trial.Failure): trial.resources(poststage=True)
            fs.f_bavail = 63
            with self.assertRaises(trial.Failure): trial.resources()

    def test_unstarted_worker_refuses_before_package_action(self):
        self.root.mkdir(mode=0o700)
        (self.root / 'contract.json').write_bytes(trial.encoded(value()))
        with patch.object(trial.os, 'geteuid', return_value=0), \
                patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: p.read_bytes()), \
                patch.object(trial, 'provision_aux') as provision:
            with self.assertRaises(FileNotFoundError): trial.main(['worker'])
            provision.assert_not_called()

    def test_bootstrap_bad_hash_never_reserves_root_or_calls_systemd(self):
        incoming = self.base / 'incoming'
        incoming.mkdir(mode=0o700)
        (incoming / 'manifest.json').write_bytes(b'{}')
        original_match = trial.re.fullmatch
        def match(pattern, text, *args):
            return True if pattern == '/tmp/labapp-vlab-[a-f0-9]{32}' else original_match(pattern, text, *args)
        # Only path fixture location is adapted; hash and no-root-write logic
        # remain real. Nonroot guarded execution owns this public fixture.
        with patch.object(trial.os, 'geteuid', return_value=0), patch.object(trial.re, 'fullmatch', side_effect=match), \
                patch.object(trial, 'run') as run:
            with self.assertRaises(trial.Failure): trial.bootstrap(incoming, '0'*64)
            self.assertFalse(self.root.exists())
            run.assert_not_called()

    def test_containment_attempts_daemons_after_core_stop_failure(self):
        self.root.mkdir(mode=0o700)
        (self.root / 'daemon-intent.json').write_text('{}')
        calls = []
        def bounded(args, seconds, **kwargs):
            calls.append(args)
            return (1, b'') if 'vlab_core.py' in str(args) else (0, b'ActiveState=inactive\nSubState=dead\n')
        original_exists = Path.exists
        def exists(path):
            return True if str(path) == '/var/lib/labapp-vlab-core' else original_exists(path)
        with patch.object(Path, 'exists', exists), patch.object(hhfab_release, 'bounded', side_effect=bounded):
            with self.assertRaises(trial.Failure): trial.containment()
        self.assertTrue(any('docker.socket' in call for call in calls))
        self.assertFalse(any('remove' in str(call) or 'kill-stale' in str(call) for call in calls))

    def test_offline_allocation_is_bounded_and_refuses_links(self):
        directory = self.base / 'cache'
        directory.mkdir()
        (directory / 'public').write_bytes(b'fixture')
        clock = Mock()
        result = trial.bounded_allocations([directory], clock, 'stage')
        self.assertEqual(result['files'], 2)
        (directory / 'redirect').symlink_to('/etc')
        with self.assertRaises(trial.Failure): trial.bounded_allocations([directory], clock, 'stage')

    def test_nonce_refuses_collision_without_create(self):
        core, clock = Mock(), Mock()
        clock.remaining.return_value = 20
        core.kubectl.return_value = b'{"metadata":{"uid":"foreign"}}'
        nonce = trial.Nonce(core, clock, 'a'*32)
        with self.assertRaisesRegex(trial.Failure, 'collision'): nonce.create()
        self.assertFalse(any('create' in args.args[0] for args in core.kubectl.call_args_list))

    def test_nonce_cleanup_preserves_core_primary_for_create_and_remove(self):
        class CoreFailure(Exception):
            code = 143
        clock = Mock()
        clock.remaining.return_value = 20
        work = self.base / 'nonce-work'
        work.mkdir()
        self.root.mkdir()
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        for action in ('create', 'remove'):
            core = SimpleNamespace(WORK=work, Failure=CoreFailure, kubectl=Mock(side_effect=CoreFailure()))
            nonce = trial.Nonce(core, clock, ('a' if action == 'create' else 'b')*32)
            nonce.objects = [{'resource': 'vpcs.vpc.githedgehog.com', 'uid': 'public', 'spec': {}}]
            with patch.object(nonce, 'current', return_value=None), \
                 patch.object(nonce, 'verify'), patch.object(trial.os, 'chown'), \
                 patch.object(trial.pwd, 'getpwnam', return_value=user), \
                 patch.object(Path, 'unlink', side_effect=OSError('fixture cleanup failure')):
                if action == 'create':
                    core.kubectl.side_effect = [b'{"items":[]}', CoreFailure()]
                with self.assertRaises(trial.Failure) as caught: getattr(nonce, action)()
            self.assertEqual(caught.exception.code, 143)
            self.assertTrue(caught.exception.cleanup_uncertain)
        core = SimpleNamespace(Failure=CoreFailure, hhfab=Mock(side_effect=CoreFailure()))
        with self.assertRaises(trial.Failure) as caught: trial.strict_checks(core, clock, 'strict')
        self.assertEqual(caught.exception.code, 143)

    def test_nonce_uid_or_spec_replacement_blocks_deletion(self):
        core, clock = Mock(), Mock()
        clock.remaining.return_value = 20
        nonce = trial.Nonce(core, clock, 'a'*32)
        nonce.objects = [{'resource': 'vpcs.vpc.githedgehog.com', 'uid': 'original', 'spec': {'public': True}}]
        core.kubectl.return_value = b'{"metadata":{"uid":"replaced"},"spec":{"public":true}}'
        with self.assertRaisesRegex(trial.Failure, 'persistence'): nonce.remove()
        self.assertFalse(any('delete' in args.args[0] for args in core.kubectl.call_args_list))

    def guardian_fixture(self):
        self.root.mkdir(mode=0o700)
        v = value()
        (self.root / 'contract.json').write_bytes(trial.encoded(v))
        (self.root / 'phase.json').write_text('{"phase":"stage"}')
        (self.root / 'heartbeat.json').write_bytes(trial.encoded({'sequence': 1, 'received': time.monotonic()}))
        reader = trial.regular
        self.stack.enter_context(patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: reader(p, n)))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=v['boot_uuid']))
        self.stack.enter_context(patch.object(trial, 'guardian_processes', return_value={str(os.getpid()).encode()}))
        self.stack.enter_context(patch.object(trial, 'oom_count', return_value=0))
        self.stack.enter_context(patch.object(trial.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(trial.os, 'killpg'))
        return v

    def test_actual_guardian_starts_worker_only_after_binding_and_contains_exit(self):
        self.guardian_fixture()
        child = Mock(pid=999999)
        child.poll.return_value = 17
        with patch.object(trial.subprocess, 'Popen', return_value=child) as spawn, \
             patch.object(trial, 'resources', return_value={'free_bytes': 300*trial.GIB, 'available_memory': 100*trial.GIB}), \
             patch.object(trial, 'containment') as contain:
            self.assertEqual(trial.main(['guardian']), 17)
        self.assertIn('worker', spawn.call_args.args[0])
        self.assertTrue((self.root / 'started.json').exists())
        contain.assert_called_once_with()
        result = json.loads((self.root / 'result.json').read_text())
        self.assertEqual((result['code'], result['contained']), (17, True))

    def test_guardian_resource_timeout_preserves_primary_despite_reap_failure(self):
        self.guardian_fixture()
        child = Mock(pid=999999)
        child.wait.side_effect = TimeoutError('public fixture')
        with patch.object(trial.subprocess, 'Popen', return_value=child), \
             patch.object(trial, 'resources', side_effect=trial.Failure('cutoff', 124)), \
             patch.object(trial, 'containment') as contain:
            self.assertEqual(trial.main(['guardian']), 124)
        contain.assert_called_once_with()
        result = json.loads((self.root / 'result.json').read_text())
        self.assertEqual((result['code'], result['contained']), (124, False))

    def test_guardian_expired_initial_heartbeat_never_starts_privileged_worker(self):
        self.guardian_fixture()
        (self.root / 'heartbeat.json').write_bytes(trial.encoded({'sequence': 1, 'received': time.monotonic()-31}))
        with patch.object(trial.subprocess, 'Popen') as spawn, patch.object(trial, 'containment'):
            self.assertNotEqual(trial.main(['guardian']), 0)
        spawn.assert_not_called()

    def test_nonce_delete_uses_exact_uid_precondition_and_verifies_absence(self):
        core, clock = Mock(), Mock()
        clock.remaining.return_value = 20
        core.WORK = self.base
        nonce = trial.Nonce(core, clock, 'a'*32)
        nonce.objects = [{'resource': 'vpcs.vpc.githedgehog.com', 'uid': 'public-owned-uid', 'spec': {'public': True}}]
        deleted = []
        def kubectl(args, end):
            if args[0] == 'get':
                return b'' if deleted else b'{"metadata":{"uid":"public-owned-uid"},"spec":{"public":true}}'
            self.assertEqual(args[:2], ['delete', '--raw=/apis/vpc.githedgehog.com/v1beta1/namespaces/default/vpcs/' + nonce.name])
            body = json.loads(Path(args[-1]).read_text())
            self.assertEqual(body['preconditions'], {'uid': 'public-owned-uid'})
            deleted.append(True)
            return b'{}'
        core.kubectl.side_effect = kubectl
        with patch.object(trial.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())), \
             patch.object(trial.os, 'chown'):
            nonce.remove()
        self.assertEqual(deleted, [True])
        self.assertFalse((self.base / 'vpcs-delete-trial.json').exists())

    def test_actual_bootstrap_validates_copies_then_starts_guardian_before_any_installer(self):
        v = value()
        incoming = self.base / ('labapp-vlab-' + v['nonce'])
        incoming.mkdir(mode=0o700)
        names = {'vlab_trial.py', trial.UNIT, 'contract.json', 'fab.yaml'}
        raw_files = {'vlab_trial.py': b'PUBLIC_SOURCE_NOT_EXECUTED', trial.UNIT: b'[Service]\n',
                     'contract.json': trial.encoded(v), 'fab.yaml': b'PUBLIC_FAB'}
        table = {'schema': 1, 'source_sha': v['source_sha'], 'files': {}}
        for name, raw in raw_files.items():
            (incoming / name).write_bytes(raw)
            table['files'][name] = {'bytes': len(raw), 'sha256': trial.sha(raw)}
        (incoming / 'manifest.json').write_bytes(trial.encoded(table))
        unit_base, runtime_base = self.base / 'units', self.base / 'runtime'
        unit_base.mkdir()
        runtime_base.mkdir()
        calls = []
        def run(args, clock, phase, cap=30, **kwargs):
            calls.append(args)
            self.assertEqual(phase, 'stage')
            self.assertTrue((self.root / 'manifest.json').exists())
            self.assertEqual((self.root / 'fab.yaml').read_bytes(), b'PUBLIC_FAB')
            if args[1] == 'start':
                trial.exclusive(self.root / 'started.json', trial.encoded({'boot': v['boot_uuid'],
                          'lease': v['lease'], 'nonce': v['nonce'], 'guardian_pid': 999999}))
            if args[1] == 'show': return b'MainPID=999999\nActiveState=active\n'
            return b''
        original_match, original_regular = trial.re.fullmatch, trial.regular
        def match(pattern, text, *args):
            return True if pattern == '/tmp/labapp-vlab-[a-f0-9]{32}' else original_match(pattern, text, *args)
        with patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial, 'UNIT_PATH', unit_base / trial.UNIT), patch.object(trial, 'UNIT_BASES', (unit_base, runtime_base)), \
             patch.object(trial, 'RUNTIME_DROPIN', runtime_base / (trial.UNIT+'.d')), \
             patch.object(trial, 'FILES', names), patch.object(trial, 'PAYLOADS', {}), \
             patch.object(trial.re, 'fullmatch', side_effect=match), patch.object(trial, 'kernel_boot', return_value=v['boot_uuid']), \
             patch.object(trial, 'regular', side_effect=lambda p,n,uid=None: original_regular(p,n)), \
             patch.object(trial, 'run', side_effect=run), patch.object(trial.sys, 'path', list(trial.sys.path)):
            self.assertEqual(trial.main(['bootstrap', '--incoming', str(incoming), '--manifest-sha256', trial.sha(trial.encoded(table))]), 0)
        self.assertEqual([a[1] for a in calls], ['daemon-reload', 'start', 'show'])
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / 'fab.yaml').stat().st_mode), 0o600)
        self.assertTrue((runtime_base / (trial.UNIT+'.d') / '10-bound.conf').exists())

    def test_actual_aux_transaction_pins_full_closure_and_preserves_stock(self):
        self.root.mkdir(mode=0o700)
        before = {name: '1' for name in trial.AUX if name != 'socat'}
        after = dict(before, socat='1.8.0.0-4ubuntu0.1')
        calls = []
        def bounded(args, seconds, **kwargs):
            calls.append(args)
            self.assertLessEqual(seconds, 180)
            if '--simulate' in args:
                return 0, b'Inst socat (1.8.0.0-4ubuntu0.1 Ubuntu:24.04/noble [amd64])\n'
            return 0, b''
        clock = Mock()
        clock.remaining.return_value = 100
        with patch.object(trial, 'APT_TMP', self.base), patch.object(trial, 'installed', side_effect=[before, after]), \
             patch.object(trial, 'run', return_value=b''), patch.object(hhfab_release, 'bounded', side_effect=bounded):
            trial.provision_aux(clock)
        actual_install = next(c for c in calls if '--no-download' in c)
        self.assertIn('socat=1.8.0.0-4ubuntu0.1', actual_install)
        self.assertIn('--no-remove', actual_install)
        receipt = json.loads((self.root / 'aux-receipt.json').read_text())
        self.assertEqual(receipt['before'], before)
        self.assertEqual(receipt['after'], after)
        self.assertEqual(receipt['closure'], {'socat': '1.8.0.0-4ubuntu0.1'})
        self.assertFalse(list(self.base.glob('labapp-vlab-aux-*')))

    def test_actual_aux_failure_preserves_primary_even_when_exact_temp_cleanup_fails(self):
        import shutil
        self.root.mkdir(mode=0o700)
        clock = Mock()
        clock.remaining.return_value = 100
        with patch.object(trial, 'APT_TMP', self.base), patch.object(trial, 'installed', return_value={}), \
             patch.object(trial, 'run', return_value=b''), patch.object(hhfab_release, 'bounded', return_value=(143, b'private')), \
             patch.object(shutil, 'rmtree', side_effect=OSError('public fixture cleanup error')):
            with self.assertRaises(trial.Failure) as raised: trial.provision_aux(clock)
        self.assertEqual(raised.exception.code, 143)
        self.assertTrue(raised.exception.cleanup_uncertain)

    def test_actual_worker_full_sequence_uses_original_phases_and_public_core(self):
        self.root.mkdir(mode=0o700)
        v = value()
        for name, raw in {'contract.json': trial.encoded(v), 'fab.yaml': b'PUBLIC_FAB', 'manifest.json': b'PUBLIC_MANIFEST',
                          'started.json': trial.encoded({'lease': v['lease'], 'nonce': v['nonce'], 'boot': v['boot_uuid'],
                                                        'guardian_pid': os.getppid()})}.items():
            (self.root / name).write_bytes(raw)
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=1000, pw_dir='/home/ubuntu', pw_shell='/bin/bash')
        core = SimpleNamespace(WIRING_SHA='b'*64, validate_fab=Mock())
        receipt = {'schema': 1, 'source_sha256': 'a'*64, 'packages': {}, 'commands': {}}
        calls = []
        def command(args, clock, phase, cap=30, **kwargs):
            calls.append((args, phase, cap))
            self.assertGreater(clock.remaining(phase), 0)
            if len(args) > 1 and args[0] == trial.PYTHON and args[1].endswith('vlab_core.py'):
                self.assertIn(args[2], ('prepare', 'start-fresh', 'stop', 'activate-resume', 'start-resume'))
            return b''
        def packages(clock, selected):
            trial.exclusive(self.root / 'packages.json', trial.encoded(receipt))
            return receipt
        nonce = Mock()
        nonce.objects = []
        reader = trial.regular
        with patch.object(trial.os, 'geteuid', return_value=0), patch.object(trial, 'regular', side_effect=lambda p,n,uid=None: reader(p,n)), \
             patch.object(trial, 'own_cgroup', return_value='0::/system.slice/'+trial.UNIT), \
             patch.object(trial.pwd, 'getpwnam', return_value=user), patch.object(trial.grp, 'getgrnam', side_effect=KeyError), \
             patch.object(hhfab_release, 'bounded', return_value=(1,b'LoadState=not-found\n')), \
             patch.object(trial, 'run', side_effect=command), patch.object(trial, 'provision_aux') as aux, \
             patch.object(trial, 'docker_account'), patch.object(trial, 'guest_devices'), \
             patch.object(trial, 'load_sibling', return_value=core), patch.object(trial, 'package_receipt', side_effect=packages), \
             patch.object(trial, 'resources'), patch.object(trial, 'offline_observations') as offline, \
             patch.object(trial, 'strict_checks', return_value={'ca_sha256': 'c'*64, 'cluster_uid': 'public'}), \
             patch.object(trial, 'Nonce', return_value=nonce):
            self.assertEqual(trial.main(['worker']), 0)
        aux.assert_called_once()
        installers = [a for a,phase,cap in calls if len(a)>1 and str(a[1]).endswith(('install-qemu.py','install-docker.py','install-hhfab.py','install-kubectl.py'))]
        self.assertEqual(len(installers), 4)
        self.assertIn('baseline-20260114', installers[0])
        self.assertIn('linux/amd64', installers[3])
        operations = [(a[2],phase) for a,phase,cap in calls if len(a)>2 and str(a[1]).endswith('vlab_core.py')]
        self.assertEqual(operations, [('prepare','stage'), ('start-fresh','fresh'), ('stop','resume'),
                                     ('activate-resume','resume'), ('start-resume','resume'), ('stop','persistence')])
        self.assertEqual([call.kwargs.get('complete',False) for call in offline.call_args_list], [False,True])
        nonce.create.assert_called_once()
        nonce.verify.assert_called_once()
        nonce.remove.assert_called_once()
        self.assertTrue((self.root / 'success.json').exists())
        final = json.loads((self.root / 'worker-status.json').read_text())
        self.assertEqual((final['state'], final['phase'], final['operation'], final['code']),
                         ('succeeded', 'persistence', 'complete', 0))
        self.assertEqual(trial.worker_status(final, NONCE)['diagnostic'], trial.SUCCESS)

    # ---- issue #364: closed diagnostics, sole writers, truthful provenance -------
    def guardian_fault(self, spawn=None, status=None, raw_status=None, overrides=None, clock_effects=None):
        """Actual guardian with native actions patched; returns (exit, result|None, mocks)."""
        if self.root.exists():
            shutil.rmtree(self.root)
        self.guardian_fixture()
        if status is not None:
            (self.root / 'worker-status.json').write_bytes(trial.encoded(status))
        if raw_status is not None:
            (self.root / 'worker-status.json').write_bytes(raw_status)
        patches = {'resources': {'return_value': {'free_bytes': 300 * trial.GIB, 'available_memory': 100 * trial.GIB}},
                   'containment': {}}
        patches.update(overrides or {})
        mocks = {}
        with ExitStack() as local:
            for name, kwargs in patches.items():
                mocks[name] = local.enter_context(patch.object(trial, name, **kwargs))
            mocks['Popen'] = local.enter_context(patch.object(trial.subprocess, 'Popen', **(spawn or {})))
            if clock_effects is not None:
                local.enter_context(patch.object(trial.Clock, 'remaining', side_effect=clock_effects))
            code = trial.main(['guardian'])
        path = self.root / 'result.json'
        return code, (json.loads(path.read_text()) if path.exists() else None), mocks

    def exiting_child(self, poll):
        child = Mock(pid=999999)
        child.poll.return_value = poll
        return {'return_value': child}

    def test_guardian_truth_table_uses_actual_worker_termination_and_checks_terminal_status(self):
        def worker(op='install-docker', category='child-exit', child=137, code=137, phase='stage'):
            return {'origin': 'worker', 'phase': phase, 'operation': op, 'category': category, 'child_status': child}
        def guardian(category, child, phase='stage'):
            return {'origin': 'guardian', 'phase': phase, 'operation': 'worker-supervision',
                    'category': category, 'child_status': child}
        def unknown(op, child, phase='stage'):
            return {'origin': 'unknown', 'phase': phase, 'operation': op, 'category': 'status-invalid', 'child_status': child}
        succeeded = worker_state('succeeded')
        cases = (
            # internal child exit 137 and internal child signal -9 BOTH normalize to worker 137, yet differ
            ('internal exit 137', 137, worker_state(code=137, child=137), 137, worker(), True),
            ('internal signal -9', 137, worker_state(code=137, category='child-signal', child=-9), 137,
             worker(category='child-signal', child=-9), True),
            # a direct worker signal never claims an inner operation, even beside a failed status
            ('direct signal -9 with status', -9, worker_state(code=137, child=137), 137, guardian('child-signal', -9), True),
            ('direct signal -9 alone', -9, None, 137, guardian('child-signal', -9), True),
            ('direct signal -15', -15, None, 143, guardian('child-signal', -15), True),
            ('explicit timeout 124', 124, worker_state(code=124, category='child-timeout', child=None), 124,
             worker(category='child-timeout', child=None), True),
            ('ordinary child exit 124', 124, worker_state(code=124, child=124), 124, worker(child=124), True),
            ('success', 0, succeeded, 0, dict(trial.SUCCESS), True),
            ('exit 0 without status', 0, None, 1, guardian('status-invalid', 0), True),
            ('exit 0 with running status', 0, worker_state('running'), 1, guardian('status-invalid', 0), True),
            ('exit 0 with failed status', 0, worker_state(), 1, guardian('status-invalid', 0), True),
            ('exit 0 wrong nonce', 0, dict(succeeded, nonce='b' * 32), 1, guardian('status-invalid', 0), True),
            ('exit 17 no status', 17, None, 17, unknown('worker-supervision', 17), True),
            ('exit 17 stale running checkpoint is context only', 17, worker_state('running'), 17,
             unknown('install-docker', 17), True),
            ('exit 17 conflicting terminal code', 17, worker_state(code=18, child=18), 17, unknown('install-docker', 17), True),
            ('exit 17 matching terminal', 17, worker_state(code=17, child=17), 17, worker(child=17), True),
            ('exit 17 contradicts inner exit', 17, worker_state(code=17, child=18), 17,
             unknown('worker-supervision', 17), True),
            ('exit 17 contradicts inner signal', 17, worker_state(code=17, category='child-signal', child=-9), 17,
             unknown('worker-supervision', 17), True),
        )
        for name, poll, status, code, detail, contained in cases:
            with self.subTest(name):
                exit_code, result, mocks = self.guardian_fault(spawn=self.exiting_child(poll), status=status)
                self.assertEqual(exit_code, code if code else 0)
                self.assertEqual((result['schema'], result['code'], result['contained'], result['nonce']),
                                 (2, code, contained, NONCE))
                self.assertEqual(result['diagnostic'], detail)
                mocks['containment'].assert_called_once_with()
        for name, raw in (('corrupt', b'{'), ('duplicate', b'{"schema":1,"schema":1}'), ('oversize', b' ' * 4097),
                          ('nan', b'{"schema":NaN}'), ('extra field', trial.encoded(dict(succeeded, contained=True)))):
            with self.subTest('exit 0 with ' + name):
                exit_code, result, _ = self.guardian_fault(spawn=self.exiting_child(0), raw_status=raw)
                self.assertEqual((exit_code, result['code'], result['diagnostic']['category']), (1, 1, 'status-invalid'))

    def test_guardian_watchdog_failures_keep_guardian_provenance_and_codes(self):
        stale = trial.encoded({'sequence': 1, 'received': time.monotonic() - 31})
        running = self.exiting_child(None)
        boot = value()['boot_uuid']
        cases = (
            ('oom counter', dict(spawn=running, overrides={'oom_count': {'side_effect': [0, 1]}}),
             1, ('stage', 'worker-supervision', 'oom-event')),
            ('resource floor', dict(spawn=running, overrides={'resources': {'side_effect': trial.Failure('floor', 1, 'resource-floor')}}),
             1, ('stage', 'worker-supervision', 'resource-floor')),
            ('boot change', dict(spawn=running, overrides={'kernel_boot': {'side_effect': [boot, 'other']}}),
             1, ('stage', 'worker-supervision', 'boot-change')),
            ('phase cutoff', dict(spawn=running, clock_effects=[60, trial.Failure('cutoff', 124, 'phase-cutoff')]),
             124, ('stage', 'worker-supervision', 'phase-cutoff')),
            ('oom read fails early', dict(overrides={'oom_count': {'side_effect': OSError(SENTINEL)}}),
             1, ('startup', 'guardian-init', 'exception')),
            ('spawn fails', dict(spawn={'side_effect': OSError(SENTINEL)}),
             1, ('startup', 'worker-spawn', 'exception')),
            ('interrupted during spawn', dict(spawn={'side_effect': trial.Failure('signal', 143, 'interrupted')}),
             143, ('startup', 'worker-spawn', 'interrupted')),
        )
        for name, kwargs, code, (phase, operation, category) in cases:
            with self.subTest(name):
                exit_code, result, mocks = self.guardian_fault(**kwargs)
                self.assertEqual(exit_code, code)
                self.assertEqual(result['diagnostic'], {'origin': 'guardian', 'phase': phase, 'operation': operation,
                                                         'category': category, 'child_status': None})
                self.assertNotIn(SENTINEL, json.dumps(result))
                mocks['containment'].assert_called_once_with()
        with self.subTest('initial heartbeat'):
            if self.root.exists():
                shutil.rmtree(self.root)
            self.guardian_fixture()
            (self.root / 'heartbeat.json').write_bytes(stale)
            with patch.object(trial.subprocess, 'Popen') as spawn, patch.object(trial, 'containment'):
                self.assertEqual(trial.main(['guardian']), 1)
            spawn.assert_not_called()
            self.assertEqual(json.loads((self.root / 'result.json').read_text())['diagnostic'],
                             {'origin': 'guardian', 'phase': 'startup', 'operation': 'guardian-init',
                              'category': 'heartbeat-loss', 'child_status': None})

    def test_initial_clock_and_boot_failures_never_claim_a_writer(self):
        for source in ('Clock', 'kernel_boot'):
            with self.subTest(source=source):
                if self.root.exists(): shutil.rmtree(self.root)
                self.guardian_fixture()
                incumbent = b'PUBLIC-INCUMBENT-RESULT'
                (self.root / 'result.json').write_bytes(incumbent)
                with patch.object(trial, source, side_effect=RuntimeError(SENTINEL)), \
                     patch.object(trial, 'containment') as contain, patch.object(trial.subprocess, 'Popen') as spawn:
                    with self.assertRaises(RuntimeError):
                        trial.main(['guardian'])
                contain.assert_not_called()
                spawn.assert_not_called()
                self.assertFalse((self.root / 'started.json').exists())
                self.assertFalse((self.root / 'worker-status.json').exists())
                self.assertEqual((self.root / 'result.json').read_bytes(), incumbent)

    def test_guardian_keeps_last_valid_context_after_status_corruption(self):
        child = Mock(pid=999999)
        child.poll.side_effect = [None, 17]
        def corrupt(_seconds):
            (self.root / 'worker-status.json').write_bytes(SENTINEL.encode())
        with patch.object(trial.time, 'sleep', side_effect=corrupt):
            code, result, _ = self.guardian_fault(spawn={'return_value': child}, status=worker_state('running'))
        self.assertEqual(code, 17)
        self.assertEqual(result['diagnostic'], {'origin': 'unknown', 'phase': 'stage',
                         'operation': 'install-docker', 'category': 'status-invalid', 'child_status': 17})
        self.assertNotIn(SENTINEL, json.dumps(result))

    def test_guardian_cleanup_trouble_never_overwrites_primary_or_success_truth(self):
        # uncertain containment after genuine worker success: code 0, contained false, operational failure
        exit_code, result, _ = self.guardian_fault(spawn=self.exiting_child(0), status=worker_state('succeeded'),
                                                   overrides={'containment': {'side_effect': trial.Failure('uncertain')}})
        self.assertEqual((exit_code, result['code'], result['contained'], result['diagnostic']),
                         (1, 0, False, dict(trial.SUCCESS)))
        # primary worker failure survives containment failure and an unreapable child
        child = Mock(pid=999999)
        child.poll.return_value = 17
        child.wait.side_effect = TimeoutError(SENTINEL)
        exit_code, result, _ = self.guardian_fault(spawn={'return_value': child}, status=worker_state(),
                                                   overrides={'containment': {'side_effect': trial.Failure('uncertain')}})
        self.assertEqual((exit_code, result['code'], result['contained']), (17, 17, False))
        self.assertEqual(result['diagnostic']['category'], 'child-exit')
        # result serialization failure: primary code is still returned, no false receipt
        real = REAL_ATOMIC
        def atomic(path, value):
            if Path(path).name == 'result.json':
                raise OSError(SENTINEL)
            return real(path, value)
        exit_code, result, mocks = self.guardian_fault(spawn=self.exiting_child(17), status=worker_state(),
                                                       overrides={'atomic': {'side_effect': atomic}})
        self.assertEqual((exit_code, result), (17, None))
        mocks['containment'].assert_called_once_with()

    def test_guardian_reservation_collision_and_bad_contract_publish_no_result(self):
        self.guardian_fixture()
        incumbent = trial.encoded({'schema': 2, 'incumbent': True})
        (self.root / 'started.json').write_bytes(b'{}')
        (self.root / 'result.json').write_bytes(incumbent)
        with patch.object(trial.subprocess, 'Popen') as spawn, patch.object(trial, 'containment') as contain:
            with self.assertRaises(FileExistsError):
                trial.main(['guardian'])
        spawn.assert_not_called()
        contain.assert_not_called()
        self.assertEqual((self.root / 'result.json').read_bytes(), incumbent)
        (self.root / 'started.json').unlink()
        (self.root / 'result.json').unlink()
        (self.root / 'contract.json').write_bytes(b'{}')
        with patch.object(trial.subprocess, 'Popen') as spawn, patch.object(trial, 'containment') as contain:
            with self.assertRaises(trial.Failure):
                trial.main(['guardian'])
        contain.assert_not_called()
        self.assertFalse((self.root / 'result.json').exists())

    def test_final_record_degrades_to_closed_fallback_never_false_success(self):
        bad = {'origin': 'worker', 'phase': 'stage', 'operation': SENTINEL, 'category': 'none', 'child_status': None}
        record = trial.final_record(NONCE, 0, True, bad, 'stage')
        self.assertEqual((record['code'], record['diagnostic']['category']), (1, 'exception'))
        self.assertNotIn(SENTINEL, json.dumps(record))
        self.assertEqual(trial.final_record(NONCE, 0, True, dict(trial.SUCCESS), 'stage')['code'], 0)

    def test_validators_refuse_unreviewed_status_and_diagnostic_values(self):
        good = worker_state()
        self.assertEqual(trial.worker_status(good, NONCE)['diagnostic']['operation'], 'install-docker')
        cases = {
            'contained field': dict(good, contained=True), 'wrong nonce': dict(good, nonce='b' * 32),
            'bool seq': dict(good, seq=True), 'seq bound': dict(good, seq=1001), 'unknown state': dict(good, state='done'),
            'running with code': dict(worker_state('running'), code=1), 'failed code 0': dict(good, code=0),
            'bool code': dict(good, code=True), 'big code': dict(good, code=256),
            'succeeded at non-final op': dict(worker_state('succeeded'), phase='stage', operation='install-docker'),
            'illegal pair': dict(good, operation='nonce-create'), 'unknown operation': dict(good, operation=SENTINEL),
            'schema 2': dict(good, schema=2), 'missing field': {k: v for k, v in good.items() if k != 'diagnostic'},
            'guardian terminal': dict(good, diagnostic=dict(good['diagnostic'], origin='guardian', operation='worker-supervision')),
            'none category on failure': dict(good, diagnostic=dict(good['diagnostic'], category='none')),
            'diagnostic pair differs': dict(good, diagnostic=dict(good['diagnostic'], operation='install-qemu')),
        }
        for name, record in cases.items():
            with self.subTest(name), self.assertRaises(trial.Failure):
                trial.worker_status(record, NONCE)

    def test_failure_fields_reduce_any_exception_to_the_closed_set_without_text(self):
        self.assertEqual(trial.failure_fields(trial.Failure('x', 17, 'child-exit', 17), 'worker'), (17, 'child-exit', 17))
        self.assertEqual(trial.failure_fields(trial.Failure('x', 300, 'bogus'), 'worker'), (1, 'exception', None))
        self.assertEqual(trial.failure_fields(trial.Failure('x', 1, 'child-signal', 9), 'worker'), (1, 'exception', None))
        self.assertEqual(trial.failure_fields(trial.Failure('x', 1, 'child-exit', True), 'worker'), (1, 'exception', None))
        self.assertEqual(trial.failure_fields(trial.Failure('x', 1, 'capability'), 'guardian'), (1, 'exception', None))
        self.assertEqual(trial.failure_fields(trial.Failure('x', 9, 'none'), 'worker'), (9, 'exception', None))
        self.assertEqual(trial.failure_fields(KeyboardInterrupt(SENTINEL), 'worker'), (130, 'interrupted', None))
        self.assertEqual(trial.failure_fields(RuntimeError(SENTINEL), 'guardian'), (1, 'exception', None))
        self.assertEqual(trial.Failure('x', True).code, 1)
        self.assertEqual(trial.Failure(SENTINEL, 0).code, 1)

    def test_read_status_accepts_only_bounded_nonce_bound_closed_files(self):
        self.root.mkdir(mode=0o700)
        path = self.root / 'worker-status.json'
        with patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: REAL_REGULAR(p, n)):
            self.assertIsNone(trial.read_status(NONCE))
            path.write_bytes(trial.encoded(worker_state()))
            self.assertEqual(trial.read_status(NONCE)['code'], 17)
            self.assertIsNone(trial.read_status('b' * 32))
            for raw in (b'{', b'[' * 4000, b'{"schema":1,"schema":1}', b' ' * 4097,
                        trial.encoded(dict(worker_state(), extra=SENTINEL))):
                path.write_bytes(raw)
                self.assertIsNone(trial.read_status(NONCE))

    def worker_inputs(self):
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(mode=0o700)
        v = value()
        for name, raw in {'contract.json': trial.encoded(v), 'fab.yaml': b'PUBLIC_FAB', 'manifest.json': b'PUBLIC_MANIFEST',
                          'started.json': trial.encoded({'lease': v['lease'], 'nonce': v['nonce'], 'boot': v['boot_uuid'],
                                                        'guardian_pid': os.getppid()})}.items():
            (self.root / name).write_bytes(raw)

    def run_worker(self, bounded, atomic=None, *, real=(), core=None):
        """Actual worker orchestration; native actions patched. -> (raised|None, final status|None)."""
        self.worker_inputs()
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=1000, pw_dir='/home/ubuntu', pw_shell='/bin/bash')
        core = core or SimpleNamespace(WIRING_SHA='b' * 64, validate_fab=Mock())
        receipt = {'schema': 1, 'source_sha256': 'a' * 64, 'packages': {}, 'commands': {}}
        def packages(clock, selected):
            trial.exclusive(self.root / 'packages.json', trial.encoded(receipt))
            return receipt
        nonce = Mock()
        nonce.objects = []
        error = None
        actions = {'provision_aux': {}, 'docker_account': {}, 'guest_devices': {},
                   'load_sibling': {'return_value': core}, 'package_receipt': {'side_effect': packages},
                   'resources': {}, 'offline_observations': {},
                   'strict_checks': {'return_value': {'ca_sha256': 'c' * 64}}, 'Nonce': {'return_value': nonce}}
        for name in real:
            del actions[name]
        with ExitStack() as local:
            for item in (patch.object(trial.os, 'geteuid', return_value=0),
                         patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: REAL_REGULAR(p, n)),
                         patch.object(trial, 'own_cgroup', return_value='0::/system.slice/' + trial.UNIT),
                         patch.object(trial.pwd, 'getpwnam', return_value=user),
                         patch.object(trial.grp, 'getgrnam', side_effect=KeyError),
                         patch.object(hhfab_release, 'bounded', side_effect=bounded)):
                local.enter_context(item)
            for name, kwargs in actions.items():
                local.enter_context(patch.object(trial, name, **kwargs))
            if atomic is not None:
                local.enter_context(patch.object(trial, 'atomic', side_effect=atomic))
            try:
                trial.main(['worker'])
            except BaseException as caught:
                error = caught
        path = self.root / 'worker-status.json'
        return error, (json.loads(path.read_text()) if path.exists() else None)

    def fake_bounded(self, faults, seen):
        def bounded(args, seconds, **kwargs):
            if 'LoadState' in args:
                return 1, b'LoadState=not-found\n'
            status = json.loads((self.root / 'worker-status.json').read_text())
            seen.append((status['state'], status['operation'], tuple(map(str, args))))
            fault = faults.get(status['operation'])
            if isinstance(fault, BaseException):
                raise fault
            return fault if fault is not None else (0, b'')
        return bounded

    def test_worker_commits_each_checkpoint_before_its_side_effect(self):
        seen = []
        error, status = self.run_worker(self.fake_bounded({}, seen))
        self.assertIsNone(error)
        self.assertEqual([op for state, op, _ in seen],
                         ['install-qemu', 'install-docker', 'install-hhfab', 'install-kubectl', 'sudo-check',
                          'daemon-start', 'core-prepare', 'core-start-fresh', 'core-stop', 'core-activate-resume',
                          'core-start-resume', 'core-final-stop'])
        self.assertTrue(all(state == 'running' for state, _, _ in seen))
        for state, op, args in seen:  # each operation's own fixed argv ran under ITS checkpoint
            if op.startswith('install-'):
                self.assertTrue(any(a.endswith(op.replace('install-', 'install-') + '.py') for a in args))
        self.assertEqual((status['state'], status['phase'], status['operation'], status['code']),
                         ('succeeded', 'persistence', 'complete', 0))
        self.assertEqual(trial.worker_status(status, NONCE)['diagnostic'], trial.SUCCESS)

    def test_worker_fault_matrix_records_exact_operation_category_and_status(self):
        overflow = hhfab_release.Refusal('command output overflow')
        cases = (
            ('install-docker', (17, b'PRIVATE'), 17, 'stage', 'child-exit', 17),
            ('install-qemu', (137, b''), 137, 'stage', 'child-exit', 137),       # internal exit 137
            ('install-hhfab', (-9, b''), 137, 'stage', 'child-signal', -9),      # internal signal 9, same worker 137
            ('install-kubectl', (-15, b''), 143, 'stage', 'child-signal', -15),
            ('sudo-check', (1, b''), 1, 'stage', 'child-exit', 1),
            ('core-prepare', hhfab_release.Refusal('command timeout'), 124, 'stage', 'child-timeout', None),
            ('core-start-fresh', (124, b''), 124, 'fresh', 'child-exit', 124),   # ordinary exit 124 is NOT a timeout
            ('core-stop', overflow, 1, 'resume', 'output-overflow', None),
            ('core-activate-resume', hhfab_release.Refusal(SENTINEL), 1, 'resume', 'exception', None),
            ('core-start-resume', (-15, b'PRIVATE'), 143, 'resume', 'child-signal', -15),
            ('core-final-stop', (143, b''), 143, 'persistence', 'child-exit', 143),
        )
        for operation, fault, code, phase, category, child in cases:
            with self.subTest(operation):
                error, status = self.run_worker(self.fake_bounded({operation: fault}, []))
                self.assertIsInstance(error, trial.Failure)
                self.assertEqual(error.code, code)
                detail = {'origin': 'worker', 'phase': phase, 'operation': operation,
                          'category': category, 'child_status': child}
                self.assertEqual((status['state'], status['code'], status['diagnostic']), ('failed', code, detail))
                self.assertNotIn(SENTINEL, json.dumps(status))
                self.assertNotIn('PRIVATE', json.dumps(status))
                valid = trial.worker_status(status, NONCE)
                # worker -> guardian hand-off: the observed exit equals the terminal code
                self.assertEqual(trial.judge_worker(code, valid, valid, phase), (code, detail))
                if operation == 'core-start-resume':
                    self.serialized_failure(error, status, operation, category, code, child)
        with self.subTest('arbitrary exception text'):
            error, status = self.run_worker(self.fake_bounded({'daemon-start': RuntimeError(SENTINEL)}, []))
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual((status['code'], status['diagnostic']['operation'], status['diagnostic']['category'],
                              status['diagnostic']['child_status']), (1, 'daemon-start', 'exception', None))
            self.assertNotIn(SENTINEL, json.dumps(status))

    def test_checkpoint_write_failure_prevents_the_operation_and_terminal_failure_keeps_primary(self):
        def refuse_checkpoint(path, value):
            if Path(path).name == 'worker-status.json' and value['operation'] == 'install-docker':
                raise OSError(SENTINEL)
            return REAL_ATOMIC(path, value)
        seen = []
        error, status = self.run_worker(self.fake_bounded({}, seen), refuse_checkpoint)
        self.assertIsInstance(error, trial.Failure)
        self.assertEqual((error.code, error.category), (1, 'status-invalid'))
        self.assertNotIn(SENTINEL, str(error))
        self.assertFalse(any('install-docker.py' in ' '.join(args) for _, _, args in seen))
        self.assertEqual((status['state'], status['operation']), ('running', 'install-qemu'))
        def refuse_terminal(path, value):
            if Path(path).name == 'worker-status.json' and value['state'] != 'running':
                raise OSError(SENTINEL)
            return REAL_ATOMIC(path, value)
        error, status = self.run_worker(self.fake_bounded({'install-docker': (17, b'')}, []), refuse_terminal)
        self.assertIsInstance(error, trial.Failure)
        self.assertEqual((error.code, error.category, error.child_status), (17, 'child-exit', 17))
        self.assertEqual((status['state'], status['operation']), ('running', 'install-docker'))  # no false terminal

    def test_worker_claim_collision_and_binding_failure_never_replace_incumbent_checkpoint(self):
        self.worker_inputs()
        incumbent = trial.encoded(worker_state('running', seq=9))
        (self.root / 'worker-status.json').write_bytes(incumbent)
        with patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: REAL_REGULAR(p, n)), \
             patch.object(trial, 'own_cgroup', return_value='0::/system.slice/' + trial.UNIT), \
             patch.object(trial, 'provision') as provision:
            with self.assertRaises(FileExistsError):
                trial.main(['worker'])
            provision.assert_not_called()
            self.assertEqual((self.root / 'worker-status.json').read_bytes(), incumbent)
            (self.root / 'worker-status.json').unlink()
            v = value()
            (self.root / 'started.json').write_bytes(trial.encoded({'lease': v['lease'], 'nonce': v['nonce'],
                              'boot': v['boot_uuid'], 'guardian_pid': os.getppid() + 1}))
            with self.assertRaises(trial.Failure):
                trial.main(['worker'])
            provision.assert_not_called()
            self.assertFalse((self.root / 'worker-status.json').exists())

    def test_worker_wrong_cgroup_writes_nothing_with_or_without_incumbent(self):
        for incumbent in (None, trial.encoded(worker_state('running', seq=9))):
            with self.subTest(incumbent=incumbent is not None):
                self.worker_inputs()
                target = self.root / 'worker-status.json'
                if incumbent is not None: target.write_bytes(incumbent)
                with patch.object(trial.os, 'geteuid', return_value=0), \
                     patch.object(trial, 'regular', side_effect=lambda p, n, uid=None: REAL_REGULAR(p, n)), \
                     patch.object(trial, 'own_cgroup', return_value='0::/unowned.service'), \
                     patch.object(trial, 'provision') as provision:
                    with self.assertRaises(trial.Failure):
                        trial.main(['worker'])
                provision.assert_not_called()
                self.assertEqual(target.read_bytes() if target.exists() else None, incumbent)

    def persisted_operation(self, operation):
        """Read the committed file at a side-effect boundary, never just mark calls."""
        status = trial.worker_status(json.loads((self.root / 'worker-status.json').read_text()), NONCE)
        self.assertEqual((status['state'], status['operation']), ('running', operation))
        return status

    def serialized_failure(self, error, status, operation, category, code=17, child=17):
        """Actual terminal -> actual guardian -> host's independent byte validator."""
        self.assertIsNotNone(error)
        expected = {'origin': 'worker', 'phase': status['phase'], 'operation': operation,
                    'category': category, 'child_status': child}
        self.assertEqual((status['state'], status['code'], status['diagnostic']), ('failed', code, expected))
        self.assertNotIn(SENTINEL, json.dumps(status))
        observed, result, _ = self.guardian_fault(spawn=self.exiting_child(code), status=status)
        self.assertEqual((observed, result['diagnostic']), (code, expected))
        # The host imports its own guest module; validate serialized bytes again.
        from build.gcp.vlab_trial import guest_result
        state, accepted = guest_result(trial.encoded(result), NONCE)
        self.assertEqual((state, accepted['code'], accepted['diagnostic']), ('valid', code, expected))
        self.assertNotIn(SENTINEL, json.dumps(accepted))

    def test_real_auxiliary_checkpoints_precede_each_effect_and_faults_survive_serialization(self):
        import qemu_offline
        original_setup, original_inventory, original_remove = qemu_offline.setup, qemu_offline.inventory, shutil.rmtree
        before = {name: '1' for name in trial.AUX if name != 'socat'}
        after = dict(before, socat='1.8.0.0-4ubuntu0.1')
        operations = ('aux-inventory', 'aux-audit', 'aux-holds', 'aux-setup', 'aux-update', 'aux-check',
                      'aux-simulate', 'aux-simulate-exact', 'aux-download', 'aux-files', 'aux-install',
                      'aux-postcheck', 'aux-cleanup')
        for target in operations:
            seen = []
            def checkpoint(expected=None):
                status = json.loads((self.root / 'worker-status.json').read_text())
                operation = status['operation']
                self.persisted_operation(expected or operation)
                seen.append(operation)
                if operation == target:
                    raise trial.Failure(SENTINEL, 17, 'child-exit', 17)
                return operation
            def installed(clock):
                op = checkpoint()
                self.assertIn(op, ('aux-inventory', 'aux-postcheck'))
                return after if op == 'aux-postcheck' else before
            def setup(directory, snapshot):
                checkpoint('aux-setup')
                return original_setup(directory, snapshot)
            def inventory(directory):
                checkpoint('aux-files')
                return original_inventory(directory)
            def remove(path, *args, **kwargs):
                if Path(path).name.startswith('labapp-vlab-aux-'):
                    # During an existing failure, cleanup intentionally retains
                    # that failure's checkpoint; success must commit aux-cleanup.
                    checkpoint()
                return original_remove(path, *args, **kwargs)
            def bounded(args, seconds, **kwargs):
                if 'LoadState' in args: return 1, b'LoadState=not-found\n'
                op = checkpoint()
                self.assertIn(op, operations)
                if '--simulate' in args:
                    return 0, b'Inst socat (1.8.0.0-4ubuntu0.1 Ubuntu:24.04/noble [amd64])\n'
                return 0, b''
            with self.subTest(target=target), patch.object(trial, 'APT_TMP', self.base), \
                 patch.object(trial, 'installed', side_effect=installed), \
                 patch.object(qemu_offline, 'setup', side_effect=setup), \
                 patch.object(qemu_offline, 'inventory', side_effect=inventory), \
                 patch.object(shutil, 'rmtree', side_effect=remove):
                error, status = self.run_worker(bounded, real=('provision_aux',))
            self.assertIn(target, seen)
            # The auxiliary cleanup wrapper keeps earlier failures; its own
            # failure is a fixed policy refusal with no invented child status.
            category, code, child = ('policy', 1, None) if target == 'aux-cleanup' else ('child-exit', 17, 17)
            self.serialized_failure(error, status, target, category, code, child)
            # Failed cleanup deliberately leaves only this PUBLIC fake APT tree.
            apt = self.base / ('labapp-vlab-aux-' + str(os.getpid()))
            if apt.exists(): original_remove(apt)

    def test_real_parser_and_prerequisite_faults_have_persisted_checkpoints(self):
        test = self
        class BrokenParser:
            @property
            def __version__(self):
                test.persisted_operation('parser-check')
                raise RuntimeError(SENTINEL)
        with patch.dict(sys.modules, yaml=BrokenParser()):
            error, status = self.run_worker(self.fake_bounded({}, []))
        self.serialized_failure(error, status, 'parser-check', 'exception', 1, None)
        core = SimpleNamespace(WIRING_SHA='b' * 64, validate_fab=Mock(), PACKAGE_PINS={}, AUX={}, TOOL_PINS={})
        def prerequisite(receipt, deadline):
            self.persisted_operation('package-receipt')
            raise trial.Failure(SENTINEL, 1, 'policy')
        core.verify_prerequisites = prerequisite
        with patch.object(trial, 'installed', side_effect=lambda clock: self.persisted_operation('package-receipt') and {}):
            error, status = self.run_worker(self.fake_bounded({}, []), real=('package_receipt',), core=core)
        self.serialized_failure(error, status, 'package-receipt', 'policy', 1, None)

    def test_real_strict_api_and_nonce_faults_keep_checkpoint_and_ambiguous_core_provenance(self):
        for target in ('strict-inspect', 'strict-ssh', 'api-ready', 'nonce-create', 'nonce-verify', 'nonce-remove'):
            work = self.base / ('work-' + target)
            work.mkdir(mode=0o700)
            objects = {}
            def effect(operation):
                self.persisted_operation(operation)
                if operation == target:
                    error = CoreFailure('child command failed', 1, True)
                    error.__cause__ = RuntimeError(SENTINEL)
                    raise error
            def hhfab(args, *unused, **kwargs):
                effect('strict-inspect' if 'inspect-switches' in args else 'strict-ssh')
            def api_ready(deadline):
                effect('api-ready')
                return {'ca_sha256': 'c' * 64}
            def kubectl(args, deadline):
                operation = json.loads((self.root / 'worker-status.json').read_text())['operation']
                effect(operation)
                if args[0] == 'get':
                    if '-A' in args: return b'{"items":[]}'
                    doc = objects.get(args[1])
                    return trial.encoded(doc) if doc is not None else b''
                if args[0] == 'create':
                    doc = json.loads(Path(args[args.index('-f') + 1]).read_text())
                    doc['metadata']['uid'] = 'public-' + doc['kind']
                    resource = ('vpcs' if doc['kind'] == 'VPC' else 'vpcattachments') + '.vpc.githedgehog.com'
                    objects[resource] = doc
                    return trial.encoded(doc)
                self.assertEqual(args[0], 'delete')
                resource = ('vpcattachments' if '/vpcattachments/' in args[1] else 'vpcs') + '.vpc.githedgehog.com'
                del objects[resource]
                return b'{}'
            core = SimpleNamespace(WIRING_SHA='b' * 64, WORK=work, Failure=CoreFailure,
                                   validate_fab=Mock(), hhfab=hhfab, api_ready=api_ready, kubectl=kubectl)
            with self.subTest(target=target), patch.object(trial.os, 'chown'):
                error, status = self.run_worker(self.fake_bounded({}, []), real=('strict_checks', 'Nonce'), core=core)
            self.assertTrue(error.cleanup_uncertain)
            self.serialized_failure(error, status, target, 'core-refusal', 1, None)

    def recorded(self, operations):
        return patch.object(trial, 'mark', side_effect=lambda *args: operations.append(args))

    def test_auxiliary_operations_are_distinct_ordered_and_cleanup_never_relabels_a_failure(self):
        self.root.mkdir(mode=0o700)
        before = {name: '1' for name in trial.AUX if name != 'socat'}
        after = dict(before, socat='1.8.0.0-4ubuntu0.1')
        def bounded(args, seconds, **kwargs):
            if '--simulate' in args:
                return 0, b'Inst socat (1.8.0.0-4ubuntu0.1 Ubuntu:24.04/noble [amd64])\n'
            return 0, b''
        clock = Mock()
        clock.remaining.return_value = 100
        operations = []
        with patch.object(trial, 'APT_TMP', self.base), patch.object(trial, 'installed', side_effect=[before, after]), \
             patch.object(trial, 'run', return_value=b''), patch.object(hhfab_release, 'bounded', side_effect=bounded), \
             self.recorded(operations):
            trial.provision_aux(clock)
        self.assertEqual([op for _, op in operations],
                         ['aux-inventory', 'aux-audit', 'aux-holds', 'aux-setup', 'aux-update', 'aux-check', 'aux-simulate',
                          'aux-simulate-exact', 'aux-download', 'aux-files', 'aux-install', 'aux-postcheck', 'aux-cleanup'])
        self.assertTrue(all(phase == 'stage' and op in trial.OPERATIONS['stage'] for phase, op in operations))
        # primary failure at update, then temp-tree cleanup also fails: operation stays aux-update
        shutil.rmtree(self.root)
        self.root.mkdir(mode=0o700)
        status = trial.WorkerStatus(NONCE)
        status.claim()
        with patch.object(trial, '_WORKER', status), patch.object(trial, 'APT_TMP', self.base), \
             patch.object(trial, 'installed', return_value={}), patch.object(trial, 'run', return_value=b''), \
             patch.object(hhfab_release, 'bounded', return_value=(143, b'private')), \
             patch.object(shutil, 'rmtree', side_effect=OSError(SENTINEL)):
            with self.assertRaises(trial.Failure) as raised:
                trial.provision_aux(clock)
        self.assertEqual((raised.exception.code, raised.exception.category, raised.exception.child_status),
                         (143, 'child-exit', 143))
        self.assertTrue(raised.exception.cleanup_uncertain)
        self.assertEqual(status.operation, 'aux-update')

    def test_core_failures_map_only_fixed_literals_and_strict_checks_record_checkpoints(self):
        clock = Mock()
        clock.remaining.return_value = 20
        operations = []
        core = SimpleNamespace(Failure=CoreFailure, hhfab=Mock(), api_ready=Mock(return_value={'public': True}))
        with self.recorded(operations):
            self.assertEqual(trial.strict_checks(core, clock, 'persistence'), {'public': True})
        self.assertEqual(operations, [('persistence', 'strict-inspect'), ('persistence', 'strict-ssh'),
                                      ('persistence', 'api-ready')])
        for text, code, category, child in (('child command failed', 137, 'child-exit', 137),
                                            ('child command failed', 1, 'core-refusal', None),  # exit1/signal ambiguous
                                            ('child deadline exceeded', 124, 'child-timeout', None),
                                            ('deadline exceeded', 124, 'phase-cutoff', None),
                                            (SENTINEL, 143, 'core-refusal', None)):
            with self.subTest(text if text != SENTINEL else 'unmapped text'):
                core = SimpleNamespace(Failure=CoreFailure, hhfab=Mock(side_effect=CoreFailure(text, code, True)))
                operations = []
                with self.recorded(operations), self.assertRaises(trial.Failure) as caught:
                    trial.strict_checks(core, clock, 'strict')
                failure = caught.exception
                self.assertEqual((failure.code, failure.category, failure.child_status), (code, category, child))
                self.assertTrue(failure.cleanup_uncertain)
                self.assertNotIn(SENTINEL, str(failure))
                self.assertEqual(operations, [('strict', 'strict-inspect')])

    def test_device_and_nonce_checkpoints_and_capability_refusals(self):
        import fcntl
        operations = []
        with self.recorded(operations), patch.object(Path, 'stat', side_effect=FileNotFoundError(SENTINEL)):
            with self.assertRaises(trial.Failure) as caught:
                trial.guest_devices()
        self.assertEqual((caught.exception.category, operations), ('capability', [('stage', 'kvm-device')]))
        self.assertNotIn(SENTINEL, str(caught.exception))
        operations = []
        char = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        with self.recorded(operations), patch.object(Path, 'stat', return_value=char), \
             patch.object(trial.os, 'open', return_value=99), patch.object(trial.os, 'close') as close, \
             patch.object(fcntl, 'ioctl', return_value=0):
            with self.assertRaises(trial.Failure) as caught:
                trial.guest_devices()
        self.assertEqual(caught.exception.category, 'capability')
        close.assert_called_once_with(99)
        with patch.object(trial, 'mark'), patch.object(Path, 'stat', return_value=char), \
             patch.object(trial.os, 'open', side_effect=OSError(SENTINEL)):
            with self.assertRaises(OSError) as caught:
                trial.guest_devices()
        self.assertEqual(trial.failure_fields(caught.exception, 'worker'), (1, 'exception', None))
        core, clock = Mock(), Mock()
        clock.remaining.return_value = 20
        core.kubectl.return_value = b'{"metadata":{"uid":"foreign"}}'
        operations = []
        with self.recorded(operations), self.assertRaises(trial.Failure):
            trial.Nonce(core, clock, 'a' * 32).create()
        self.assertEqual(operations, [('strict', 'nonce-create')])
        nonce = trial.Nonce(core, clock, 'a' * 32)
        operations = []
        with self.recorded(operations):
            nonce.verify()
            nonce.remove()
        self.assertEqual(operations, [('persistence', 'nonce-verify'), ('persistence', 'nonce-verify'),
                                      ('persistence', 'nonce-remove')])

    def test_every_operation_label_is_a_reviewed_literal_and_no_checkpoint_runs_outside_a_worker(self):
        self.assertEqual(set(trial.OPERATIONS), set(trial.PHASE_NAMES))
        for phase, operations in trial.OPERATIONS.items():
            self.assertEqual(len(operations), len(set(operations)))
            self.assertTrue(all(op.replace('-', '').isalnum() and op == op.lower() for op in operations))
        self.root.mkdir(mode=0o700)
        trial.mark('stage', 'aux-inventory')  # no worker context: no file, no error
        self.assertFalse((self.root / 'worker-status.json').exists())
        status = trial.WorkerStatus(NONCE)
        status.claim()
        with self.assertRaises(trial.Failure):
            status.mark('stage', 'install-docker; rm -rf /')
        with self.assertRaises(trial.Failure):
            status.mark('persistence', 'install-docker')
        self.assertEqual(trial.worker_status(json.loads((self.root / 'worker-status.json').read_text()), NONCE)['seq'], 0)
