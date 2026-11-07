"""Source tests for vlab_image.py (issue #526). Fixtures are temp directories plus fakes only.

No real systemd, QEMU, hhfab, Docker, cloud or credential access: ``run``, ``unit_fields``,
``live_vlab_processes`` and ``load_core`` are replaced. The one credential-shaped value is a
synthetic canary that must never reach any output or receipt. AUTHOR TESTS: NOT RUN by the author.
"""
from contextlib import ExitStack, contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vlab_image as image
import vlab_trial as trial

NONCE, LEASE = 'a' * 32, '11111111-2222-3333-4444-555555555555'
BUILD, CLONE = '66666666-7777-8888-9999-000000000000', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
SOURCE, OP, INV = 'b' * 40, 'c' * 32, 'd' * 32
CANARY = 'PRIVATE-SENTINEL-lab-password-canary'
TOOL = image.sha(Path(image.__file__).read_bytes())
UNIT_TEXT = b'[Service]\nExecStart=/bin/true\n'


def write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


class World:
    """Temp trial root, fake systemd and fake core, wired into the module's path constants."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.boot = BUILD
        self.live = False
        self.trial = self.tmp / 'trial'
        self.units, self.lib, self.seal = self.tmp / 'units', self.tmp / 'lib', self.tmp / 'seal'
        self.home, self.dropin = self.tmp / 'home', self.tmp / 'run-dropin'
        self.docker = self.tmp / 'docker-config'
        self.work = self.tmp / 'home' / 'ubuntu' / 'hhfab'
        for d in (self.units, self.lib, self.home / 'ubuntu', self.work):
            d.mkdir(parents=True, mode=0o755)
        write(self.work / 'fab.yaml', CANARY.encode())  # preserved lab state; must stay untouched
        self.enabled = {image.RESUME_UNIT: 'enabled', image.CLONE_UNIT: 'disabled'}
        self.commands = []
        self.state = {'nonce': NONCE, 'phase': 'resumable', 'mode': 'resume', 'operation': OP,
                      'invocation': INV, 'stop_verified': {'operation': OP, 'invocation': INV},
                      'critical': {'x': 1}, 'cluster': {'y': 2}, 'boot': BUILD}
        self.critical = {'x': 1}
        self.build_trial()

    def build_trial(self):
        self.trial.mkdir(mode=0o700)
        contract = {'schema': 1, 'nonce': NONCE, 'lease': LEASE, 'epoch': 1, 'run_id': 1, 'attempt': 1,
                    'body_sha256': 'e' * 64, 'vm_id': '1', 'boot_id': '1', 'image_id': '4575951068918267275',
                    'admitted_at': '2026-01-01T00:00:00Z', 'deadline': '2099-01-01T00:00:00Z',
                    'boot_uuid': BUILD, 'source_sha': SOURCE}
        records = {
            'contract.json': contract, 'manifest.json': {'schema': 1, 'source_sha': SOURCE, 'files': {}},
            'started.json': {'boot': BUILD, 'lease': LEASE, 'nonce': NONCE, 'guardian_pid': 1, 'remaining': 1},
            'result.json': {'schema': 2, 'code': 0, 'contained': True, 'nonce': NONCE,
                            'diagnostic': dict(trial.SUCCESS)},
            'worker-status.json': {'schema': 1, 'nonce': NONCE, 'seq': 9, 'state': 'succeeded',
                                   'phase': 'persistence', 'operation': 'complete', 'code': 0,
                                   'diagnostic': dict(trial.SUCCESS)},
            'success.json': {'schema': 1, 'nonce': NONCE, 'cluster': {'k': 'v'}}}
        for name, value in records.items():
            write(self.trial / name, image.encoded(value))
        write(self.trial / 'fab.yaml', CANARY.encode())  # build copy of the lab identity
        write(self.trial / 'hhfab.tar.gz', b'payload')
        write(self.trial / image.TRIAL_UNIT, UNIT_TEXT)
        write(self.units / image.TRIAL_UNIT, UNIT_TEXT, 0o644)
        (self.trial / '__pycache__').mkdir(mode=0o700)
        write(self.trial / '__pycache__' / 'vlab_core.cpython-312.pyc', b'x')

    def rewrite(self, name, **changes):
        path = self.trial / name
        value = json.loads(path.read_bytes())
        value.update(changes)
        path.unlink()
        write(path, image.encoded(value))

    # fakes -----------------------------------------------------------------------------
    def run(self, argv, seconds):
        self.commands.append(list(argv))
        if argv[0] == image.SYSTEMCTL:
            action, unit = argv[1], argv[-1]
            if action == 'is-enabled':
                value = self.enabled.get(unit, 'not-found')
                return (0 if value == 'enabled' else 1), value.encode() + b'\n'
            if action in ('enable', 'disable'):
                if action == 'enable':
                    require_unit = (self.units / unit).exists()
                    assert require_unit
                self.enabled[unit] = action + 'd'
            return 0, b''
        if argv[-1] == 'start-resume':
            self.state.update(phase='ready', boot=self.boot, operation='f' * 32, invocation='9' * 32)
            return 0, b''
        return 0, b''

    def fields(self, unit, *properties):
        loaded = unit != image.TRIAL_UNIT or (self.units / unit).exists()
        table = {'ActiveState': 'inactive', 'MainPID': '0', 'LoadState': 'loaded' if loaded else 'not-found',
                 'FragmentPath': str(self.units / unit), 'NeedDaemonReload': 'no', 'DropInPaths': ''}
        return {p: table[p] for p in properties}

    @property
    def core(self):
        @contextmanager
        def locked(*_a, **_k):
            yield
        return SimpleNamespace(boot=lambda: self.boot, locked=locked, state=lambda: dict(self.state),
                               verify_contract=lambda v, d: None,
                               critical_snapshot=lambda d: self.critical)

    def args(self, **changes):
        base = dict(private_candidate=True, source_sha=SOURCE, nonce=NONCE, lease=LEASE,
                    build_boot=BUILD, tool_sha256=TOOL)
        base.update(changes)
        return SimpleNamespace(**base)

    def snapshot(self, root):
        return sorted(str(p.relative_to(root)) for p in root.rglob('*'))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.w = World(self.dir.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        w = self.w
        for name, value in (('TRIAL', w.trial), ('UNITS', w.units), ('LIB', w.lib), ('SEAL', w.seal),
                            ('HOME', w.home), ('ROOT_HOME', w.tmp / 'roothome'), ('RUNTIME_DROPIN', w.dropin), ('DOCKER_CONFIG', w.docker),
                            ('CGROUP', w.tmp / 'cgroup'), ('CREDENTIAL_FALLBACKS', (w.tmp / 'nofallback',)),
                            ('OSLOGIN_CACHES', ()), ('OWNER', os.geteuid())):
            self.stack.enter_context(patch.object(image, name, value))
        self.stack.enter_context(patch.object(image, 'run', w.run))
        self.stack.enter_context(patch.object(image, 'unit_fields', w.fields))
        self.stack.enter_context(patch.object(image, 'live_vlab_processes', lambda: w.live))
        self.stack.enter_context(patch.object(image, 'kernel_boot', lambda: w.boot))
        self.stack.enter_context(patch.object(image, 'load_core', lambda: w.core))

    def prepare(self, **changes):
        out = io.StringIO()
        with redirect_stdout(out):
            code = image.prepare(self.w.args(**changes))
        return code, out.getvalue()

    def refused(self, **changes):
        before = self.w.snapshot(self.w.tmp)
        with self.assertRaises(image.Refused):
            self.prepare(**changes)
        self.assertEqual(before, self.w.snapshot(self.w.tmp), 'a refusal must not mutate anything')


class RefusalTests(Base):
    def test_opt_in_and_binding_arguments_are_mandatory(self):
        self.refused(private_candidate=False)
        self.refused(nonce='z' * 32)
        self.refused(source_sha='b' * 39)
        self.refused(tool_sha256='0' * 64)  # not this tool's bytes
        with self.assertRaises(image.Refused):
            image.main(['prepare'])
        with self.assertRaises(image.Refused):
            image.main(['verify', '--nonce', NONCE])

    def test_wrong_source_nonce_lease_or_boot_binding(self):
        self.refused(source_sha='c' * 40)
        self.refused(nonce='b' * 32)
        self.refused(lease='11111111-2222-3333-4444-000000000000')
        self.refused(build_boot=CLONE)
        self.w.boot = CLONE  # operator binding right, but this is no longer the build boot
        self.refused()

    def test_failed_uncontained_or_stale_terminal_results(self):
        for name, change in (('result.json', {'code': 1}), ('result.json', {'contained': False}),
                             ('result.json', {'nonce': 'b' * 32}), ('result.json', {'schema': 1}),
                             ('worker-status.json', {'state': 'failed'}),
                             ('worker-status.json', {'phase': 'resume'}),
                             ('success.json', {'nonce': 'b' * 32}), ('started.json', {'lease': CLONE})):
            with self.subTest(name=name, change=change):
                setup = World(tempfile.mkdtemp(dir=self.dir.name))
                setup.rewrite(name, **change)
                with patch.object(image, 'TRIAL', setup.trial), patch.object(image, 'UNITS', setup.units):
                    with self.assertRaises(image.Refused):
                        image.trial_records(setup.args())

    def test_expired_original_deadline_is_not_renewed(self):
        self.w.rewrite('contract.json', deadline='2000-01-01T00:00:00Z')
        self.refused()

    def test_live_or_uncertain_vlab_is_refused(self):
        self.w.live = True
        self.refused()

    def test_unstopped_or_changed_core_state_is_refused(self):
        self.w.state['phase'] = 'ready'
        self.refused()
        self.w.state.update(phase='resumable', stop_verified={'operation': OP, 'invocation': 'e' * 32})
        self.refused()
        self.w.state['stop_verified'] = {'operation': OP, 'invocation': INV}
        self.w.critical = {'x': 2}
        self.refused()

    def test_foreign_symlink_and_hardlink_entries_are_refused_not_deleted(self):
        for make in (lambda t: write(t / 'authorized_keys', b'k'),
                     lambda t: (t / 'extra').symlink_to(t / 'fab.yaml'),
                     lambda t: os.link(t / 'fab.yaml', t / 'phase.json'),
                     lambda t: (t / 'dir').mkdir(),
                     lambda t: write(t / '__pycache__' / 'evil.txt', b'x')):
            with self.subTest():
                setup = World(tempfile.mkdtemp(dir=self.dir.name))
                make(setup.trial)
                with patch.object(image, 'TRIAL', setup.trial):
                    with self.assertRaises(image.Refused):
                        image.trial_inventory()
                self.assertTrue((setup.trial / 'fab.yaml').exists())

    def test_present_registry_credential_stores_are_refused(self):
        self.w.docker.mkdir()
        self.refused()
        self.w.docker.rmdir()
        fallback = self.w.tmp / 'nofallback'
        with patch.object(image, 'CREDENTIAL_FALLBACKS', (fallback,)):
            write(fallback, b'x')
            self.refused()

    def test_conflicting_installed_unit_or_tool_is_refused(self):
        write(self.w.units / image.CLONE_UNIT, b'other', 0o644)
        self.refused()

    def test_modified_installed_trial_unit_is_foreign(self):
        (self.w.units / image.TRIAL_UNIT).write_bytes(b'changed')
        self.refused()


class PrepareTests(Base):
    def test_sealed_result_and_postconditions(self):
        w = self.w
        code, out = self.prepare()
        self.assertEqual(0, code, out)
        self.assertFalse(w.trial.exists())
        self.assertFalse((w.units / image.TRIAL_UNIT).exists())
        self.assertEqual('disabled', w.enabled[image.RESUME_UNIT])
        self.assertEqual('enabled', w.enabled[image.CLONE_UNIT])
        self.assertEqual((w.work / 'fab.yaml').read_bytes(), CANARY.encode())  # preserved lab state
        receipt = image.load_receipt()
        self.assertEqual(('sealed', True, []), (receipt['state'], receipt['owned_sealed'], receipt['unmet']))
        self.assertIn('fab.yaml', receipt['removed'])
        self.assertEqual(OP, receipt['core_operation'])
        self.assertTrue((w.lib / 'vlab_image.py').exists() and (w.units / image.CLONE_UNIT).exists())

    def test_no_credential_content_in_output_or_receipt(self):
        code, out = self.prepare()
        self.assertNotIn(CANARY, out)
        self.assertNotIn(CANARY.encode(), (self.w.seal / image.RECEIPT).read_bytes())

    def test_unproven_access_material_is_reported_unmet_and_never_deleted(self):
        other = self.w.home / 'someone'
        (other / '.ssh').mkdir(parents=True)
        write(other / '.ssh' / 'authorized_keys', b'k')
        code, out = self.prepare()
        self.assertEqual(3, code)
        report = json.loads(out)
        self.assertEqual([image.UNMET_ACCESS], report['unmet'])
        self.assertEqual({'status': 'unproven', 'key_files': 1, 'other_home_dirs': 1, 'oslogin_caches': 0},
                         report['access'])
        self.assertTrue((other / '.ssh' / 'authorized_keys').exists())
        self.assertTrue(image.load_receipt()['owned_sealed'])  # owned portion is sealed regardless

    def test_second_prepare_after_seal_is_refused(self):
        self.prepare()
        with self.assertRaises(image.Refused):
            self.prepare()

    def test_interrupted_sealing_can_complete_without_the_removed_records(self):
        w = self.w
        original = image.remove_trial_unit
        with patch.object(image, 'remove_trial_unit', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                self.prepare()
        self.assertEqual('sealing', image.load_receipt()['state'])
        self.assertFalse(w.trial.exists())
        with patch.object(image, 'remove_trial_unit', original):
            code, _ = self.prepare()
        self.assertEqual(0, code)
        self.assertEqual('sealed', image.load_receipt()['state'])
        with self.assertRaises(image.Refused):
            self.prepare(nonce='b' * 32)

    def test_runtime_dropin_is_removed_only_when_exact(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        self.assertEqual(0, self.prepare()[0])
        self.assertFalse(self.w.dropin.exists())

    def test_foreign_runtime_dropin_is_refused_before_any_mutation(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nExecStart=/bin/sh\n')
        self.refused()


class CloneStartTests(Base):
    def sealed(self):
        self.assertEqual(0, self.prepare()[0])
        self.w.boot = CLONE

    def start(self):
        out = io.StringIO()
        with redirect_stdout(out):
            return image.clone_start(SimpleNamespace())

    def test_new_boot_gets_a_fresh_operation_via_the_unchanged_core(self):
        self.sealed()
        self.assertEqual(0, self.start())
        self.assertIn([image.PYTHON, str(image.LIB / 'vlab_core.py'), 'start-resume'], self.w.commands)
        started = json.loads((self.w.seal / image.CLONE_START).read_bytes())
        self.assertEqual(CLONE, started['boot'])
        self.assertNotEqual(OP, started['operation'])
        self.assertNotEqual(INV, started['invocation'])

    def test_same_boot_as_the_build_is_not_a_clone(self):
        self.sealed()
        self.w.boot = BUILD
        with self.assertRaises(image.Refused):
            self.start()

    def test_unsealed_or_sealing_image_is_refused(self):
        with self.assertRaises((image.Refused, FileNotFoundError)):
            self.start()

    def test_trial_authority_must_not_survive_to_the_clone(self):
        self.sealed()
        self.w.trial.mkdir(mode=0o700)  # a resurrected lease root
        with self.assertRaises(image.Refused):
            self.start()

    def test_changed_preserved_state_or_core_binding_is_refused(self):
        self.sealed()
        self.w.critical = {'x': 3}
        with self.assertRaises(image.Refused):
            self.start()
        self.w.critical = {'x': 1}
        self.w.state['operation'] = 'e' * 32
        self.w.state['stop_verified'] = {'operation': 'e' * 32, 'invocation': INV}
        with self.assertRaises(image.Refused):
            self.start()

    def test_core_must_report_ready_on_this_boot_with_new_identity(self):
        self.sealed()
        def stale(argv, seconds):
            self.w.commands.append(list(argv))
            self.w.state.update(phase='ready', boot=BUILD, operation=OP, invocation=INV)
            return 0, b''
        with patch.object(image, 'run', stale):
            with self.assertRaises(image.Refused):
                self.start()

    def test_core_failure_is_not_success_and_does_not_start_anything_else(self):
        self.sealed()
        real = self.w.run
        with patch.object(image, 'run', lambda argv, seconds: (1, b'') if argv[-1] == 'start-resume'
                          else real(argv, seconds)):
            with self.assertRaises(image.Refused):
                self.start()
        self.assertFalse((self.w.seal / image.CLONE_START).exists())


class ScopeTests(unittest.TestCase):
    def test_fixed_unit_scope(self):
        text = (Path(image.__file__).parent / image.CLONE_UNIT).read_text()
        self.assertIn('Type=oneshot', text)
        self.assertIn('ExecStart=/usr/bin/python3 /usr/local/lib/labapp/vlab_image.py clone-start', text)
        self.assertIn('ExecStop=/usr/bin/python3 /usr/local/lib/labapp/vlab_core.py stop', text)
        for forbidden in ('Wants=hhfab', 'Requires=', 'Restart=', 'EnvironmentFile', 'ExecStartPre',
                          'vlab_trial', 'init', 'ghcr'):
            self.assertNotIn(forbidden, text)
        self.assertIn('After=network-online.target hhfab-vlab-resume.service', text)

    def test_manifest_covers_every_trial_owned_name_and_success_shape_matches(self):
        self.assertEqual(trial.SUCCESS, image.SUCCESS)
        trial_names = {*trial.FILES, 'manifest.json'}
        self.assertLessEqual(trial_names, image.OWNED_NAMES)
        for name in (trial.AUTH_INTENT, trial.AUTH_BOUND, trial.AUTH_READY, trial.AUTH_REMOVED, trial.AUTH_CLOSED,
                     trial.AUTH_FILE, trial.AUTH_UNLINKED, trial.AUTH_DIR_REMOVED, trial.AUTH_GUARDIAN,
                     trial.AUTH_LOCK, trial.INSTALLER_FAILURE):
            self.assertIn(name, image.OWNED_NAMES)
        self.assertNotIn('authorized_keys', image.OWNED_NAMES)

    def test_core_default_resume_core_state_name_and_clone_never_use_old_deadline(self):
        source = Path(image.__file__).read_text()
        self.assertNotIn("['deadline']", source.split('def clone_start')[1])
        self.assertNotIn('heartbeat', source.split('def clone_start')[1])


if __name__ == '__main__':
    unittest.main()
