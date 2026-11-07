"""Source tests for vlab_image.py (issue #526). Fixtures are temp directories plus fakes only.

No real systemd, QEMU, hhfab, Docker, cloud or credential access: ``run``, ``unit_fields``,
``live_vlab_processes`` and ``load_core`` are replaced in the prepare/clone graph (the fake core
mirrors the state transitions of vlab_core.py ``unit_finished``/``_stop_owned_locked``/``unit_gate``
and a drift test pins the literals it relies on). ``RunTests`` runs the real ``run`` on tiny
``sys.executable`` children. The one credential-shaped value is a synthetic canary that must never
reach any output or receipt. AUTHOR TESTS: NOT RUN by the author; no systemd shutdown behavior
is proven here.
"""
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import owned_process
import vlab_image as image
import vlab_trial as trial

NONCE, LEASE = 'a' * 32, '11111111-2222-3333-4444-555555555555'
BUILD, CLONE = '66666666-7777-8888-9999-000000000000', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
CLONE2, CLONE3 = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', 'cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee'
SOURCE, OP, INV = 'b' * 40, 'c' * 32, 'd' * 32
CANARY = 'PRIVATE-SENTINEL-lab-password-canary'
HERE = Path(image.__file__).parent
TOOL = image.sha((HERE / 'vlab_image.py').read_bytes())
CLONE_BYTES = (HERE / image.CLONE_UNIT).read_bytes()
UNIT_SHA = image.sha(CLONE_BYTES)
UNIT_TEXT = b'[Service]\nExecStart=/bin/true\n'
EXPIRED = 4070908801  # one second after the 2099-01-01 fixture deadline
REAL_TIME = time.time


def write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


class World:
    """Temp trial root, fake systemd and fake core, wired into the module's path constants."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.boot = BUILD
        self.live = False
        self.resume_active = False
        self.unit_invocation = ''
        self.counter = 0
        self.core_stops = 0
        self.stop_fails = False
        self.controller_busy = False
        self.trial = self.tmp / 'trial'
        self.units, self.lib, self.seal = self.tmp / 'units', self.tmp / 'lib', self.tmp / 'seal'
        self.src = self.tmp / 'src'
        self.home, self.dropin = self.tmp / 'home', self.tmp / 'run-dropin'
        self.docker = self.tmp / 'docker-config'
        self.work = self.tmp / 'home' / 'ubuntu' / 'hhfab'
        for d in (self.units, self.lib, self.src, self.home / 'ubuntu', self.work):
            d.mkdir(parents=True, mode=0o755)
        write(self.work / 'fab.yaml', CANARY.encode())  # preserved lab state; must stay untouched
        write(self.src / image.CLONE_UNIT, CLONE_BYTES, 0o644)
        write(self.lib / 'owned_process.py', Path(owned_process.__file__).read_bytes(), 0o644)
        self.enabled = {image.RESUME_UNIT: 'enabled', image.CLONE_UNIT: 'disabled'}
        self.commands = []
        self.state = {'schema': 1, 'nonce': NONCE, 'phase': 'resumable', 'mode': 'resume',
                      'operation': OP, 'invocation': INV,
                      'stop_verified': {'operation': OP, 'invocation': INV},
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
    def run(self, argv, seconds, term_grace=0):
        self.commands.append(list(argv))
        if argv[0] == image.SYSTEMCTL:
            action, unit = argv[1], argv[-1]
            if action == 'is-enabled':
                value = self.enabled.get(unit, 'not-found')
                return (0 if value == 'enabled' else 1), value.encode() + b'\n'
            if action in ('enable', 'disable'):
                if action == 'enable':
                    assert (self.units / unit).exists()
                self.enabled[unit] = action + 'd'
            return 0, b''
        if argv[-1] == 'start-resume':  # mirrors vlab_core.unit_gate: only a verified resumable state
            if self.state['phase'] != 'resumable':
                return 1, b''
            self.counter += 1
            self.state.update(phase='ready', boot=self.boot, operation=f'{self.counter:032x}',
                              invocation=f'{self.counter + 1000:032x}')
            for key in ('stopping', 'stop_verified', 'service_result'):
                self.state.pop(key, None)
            self.resume_active = True
            self.unit_invocation = self.state['invocation']  # what systemd reports for the running unit
            return 0, b''
        if argv[-1] == 'stop':  # mirrors vlab_core._stop_owned_locked (serialized public stop)
            self.core_stops += 1
            state = self.state
            binding = {'operation': state['operation'], 'invocation': state['invocation']}
            if self.stop_fails:
                return 1, b''
            if state['phase'] == 'ready' and self.resume_active:  # owned intent, manager stop, commit
                state['stopping'] = binding
                self.shutdown()
            if state['phase'] == 'stop-observed' and state.get('stopping') == binding:
                state.update(phase='resumable', stop_verified=binding)
                return 0, b''
            if state['phase'] == 'starting':
                state['phase'] = 'failed'
                self.resume_active = False
                return 0, b''
            if state['phase'] == 'failed' or (state['phase'] == 'resumable'
                                              and state.get('stop_verified') == binding):
                self.resume_active = False
                return 0, b''
            return 1, b''
        return 0, b''

    def shutdown(self):
        """Mirrors vlab_core.unit_finished (ExecStopPost) for a manager-initiated stop."""
        value = self.state
        if value['phase'] in ('starting', 'ready'):
            owned = value.get('stopping') == {'operation': value['operation'],
                                              'invocation': value['invocation']}
            value['phase'] = 'stop-observed' if value['phase'] == 'ready' and owned else 'failed'
            value['service_result'] = ('owned-stop-process-termination' if owned
                                       else 'failed-or-unavailable')
        self.resume_active = False

    def fields(self, unit, *properties):
        loaded = unit != image.TRIAL_UNIT or (self.units / unit).exists()
        running = unit == image.RESUME_UNIT and self.resume_active
        table = {'ActiveState': 'active' if running else 'inactive',
                 'MainPID': '4242' if running else '0',
                 'InvocationID': self.unit_invocation if running else '',
                 'LoadState': 'loaded' if loaded else 'not-found',
                 'FragmentPath': str(self.units / unit), 'NeedDaemonReload': 'no', 'DropInPaths': ''}
        return {p: table[p] for p in properties}

    @property
    def core(self):
        @contextmanager
        def locked(*_a, **_k):
            yield

        @contextmanager
        def stop_controller():  # vlab_core.stop_controller: never waits, a second owner is refused
            if self.controller_busy:
                raise image.Refused('another stop controller is active')
            yield

        def save(value):
            self.state = dict(value)
        return SimpleNamespace(boot=lambda: self.boot, locked=locked, state=lambda: dict(self.state),
                               stop_controller=stop_controller,
                               save=save, verify_contract=lambda v, d: None,
                               critical_snapshot=lambda d: self.critical)

    def args(self, **changes):
        base = dict(private_candidate=True, source_sha=SOURCE, nonce=NONCE, lease=LEASE,
                    build_boot=BUILD, tool_sha256=TOOL, unit_sha256=UNIT_SHA)
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
                            ('SOURCE_DIR', w.src), ('HOME', w.home), ('ROOT_HOME', w.tmp / 'roothome'),
                            ('RUNTIME_DROPIN', w.dropin), ('DOCKER_CONFIG', w.docker),
                            ('CGROUP', w.tmp / 'cgroup'), ('CREDENTIAL_FALLBACKS', (w.tmp / 'nofallback',)),
                            ('OSLOGIN_CACHES', ()), ('AGENT_STATE', ()), ('OWNER', os.geteuid())):
            self.stack.enter_context(patch.object(image, name, value))
        self.stack.enter_context(patch.object(image, 'run', w.run))
        self.stack.enter_context(patch.object(image, 'unit_fields', w.fields))
        self.stack.enter_context(patch.object(image, 'live_vlab_processes', lambda: w.live))
        self.stack.enter_context(patch.object(image, 'kernel_boot', lambda: w.boot))
        self.stack.enter_context(patch.object(image, 'load_core', lambda: w.core))
        for number in (signal.SIGTERM, signal.SIGINT):  # clone_start installs/ignores these handlers
            self.addCleanup(signal.signal, number, signal.getsignal(number))

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

    def interrupted_unlink(self, nth):
        """Run prepare, raising RuntimeError instead of the nth os.unlink (like a crash)."""
        calls, real = [], os.unlink

        def fake(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == nth:
                raise RuntimeError('injected interruption')
            return real(*args, **kwargs)
        with patch.object(os, 'unlink', fake):
            with self.assertRaises(RuntimeError):
                self.prepare()


class RefusalTests(Base):
    def test_opt_in_and_binding_arguments_are_mandatory(self):
        self.refused(private_candidate=False)
        self.refused(nonce='z' * 32)
        self.refused(source_sha='b' * 39)
        self.refused(tool_sha256='0' * 64)  # not this tool's bytes
        self.refused(unit_sha256='0' * 64)  # not this unit's bytes
        self.refused(unit_sha256='nothex')
        with self.assertRaises(image.Refused):
            image.main(['prepare'])
        with self.assertRaises(image.Refused):
            image.main(['verify', '--nonce', NONCE])
        with self.assertRaises(image.Refused):
            image.main(['clone-stop', '--unit-sha256', UNIT_SHA])

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

    def test_owned_process_must_equal_the_installed_core_copy(self):
        (self.w.lib / 'owned_process.py').write_bytes(b'# different\n')
        self.refused()


class UnitPinTests(Base):
    """The sibling clone unit is installed as root: pinned by an operator hash and read safely."""

    def test_altered_sibling_unit_is_refused_before_mutation(self):
        (self.w.src / image.CLONE_UNIT).write_bytes(CLONE_BYTES + b'ExecStartPre=/bin/sh\n')
        self.refused()

    def test_symlinked_sibling_unit_is_refused(self):
        real = self.w.tmp / 'elsewhere.service'
        write(real, CLONE_BYTES, 0o644)
        (self.w.src / image.CLONE_UNIT).unlink()
        (self.w.src / image.CLONE_UNIT).symlink_to(real)
        self.refused()

    def test_group_or_world_writable_sibling_unit_is_refused(self):
        (self.w.src / image.CLONE_UNIT).chmod(0o666)
        self.refused()

    def test_hardlinked_sibling_unit_is_refused(self):
        os.link(self.w.src / image.CLONE_UNIT, self.w.tmp / 'second-link')
        self.refused()

    def test_missing_sibling_unit_is_refused(self):
        (self.w.src / image.CLONE_UNIT).unlink()
        with self.assertRaises((image.Refused, FileNotFoundError)):
            self.prepare()
        self.assertTrue(self.w.trial.exists())

    def test_foreign_owner_sibling_unit_is_refused(self):
        with patch.object(image, 'OWNER', os.geteuid() + 1):
            with self.assertRaises(image.Refused):
                image.private_file(self.w.src / image.CLONE_UNIT, 4096, None)


class PrepareTests(Base):
    def test_sealed_result_and_postconditions(self):
        w = self.w
        code, out = self.prepare()
        self.assertEqual(3, code, out)  # owned portion sealed; access provenance always unmet
        self.assertFalse(w.trial.exists())
        self.assertFalse((w.units / image.TRIAL_UNIT).exists())
        self.assertEqual('disabled', w.enabled[image.RESUME_UNIT])
        self.assertEqual('enabled', w.enabled[image.CLONE_UNIT])
        self.assertEqual((w.work / 'fab.yaml').read_bytes(), CANARY.encode())  # preserved lab state
        receipt = image.load_receipt()
        self.assertEqual(('sealed', True, [image.UNMET_ACCESS]),
                         (receipt['state'], receipt['owned_sealed'], receipt['unmet']))
        self.assertIn('fab.yaml', receipt['removed'])
        self.assertEqual(OP, receipt['core_operation'])
        self.assertEqual(UNIT_SHA, receipt['unit_sha256'])
        self.assertEqual(2099, time.gmtime(receipt['evidence']['deadline']).tm_year)
        self.assertEqual(CLONE_BYTES, (w.units / image.CLONE_UNIT).read_bytes())
        self.assertTrue((w.lib / 'vlab_image.py').exists())

    def test_no_credential_content_in_output_or_receipt(self):
        code, out = self.prepare()
        self.assertNotIn(CANARY, out)
        self.assertNotIn(CANARY.encode(), (self.w.seal / image.RECEIPT).read_bytes())

    def test_access_is_never_reported_absent_even_with_zero_counts(self):
        code, out = self.prepare()
        report = json.loads(out)
        self.assertEqual(3, code)
        self.assertEqual('unproven', report['access']['status'])
        self.assertEqual([image.UNMET_ACCESS], report['unmet'])
        self.assertEqual(0, report['access']['key_files'])

    def test_unproven_access_material_is_reported_unmet_and_never_deleted(self):
        other = self.w.home / 'someone'
        (other / '.ssh').mkdir(parents=True)
        write(other / '.ssh' / 'authorized_keys', b'k')
        code, out = self.prepare()
        self.assertEqual(3, code)
        report = json.loads(out)
        self.assertEqual([image.UNMET_ACCESS], report['unmet'])
        self.assertEqual({'status': 'unproven', 'key_files': 1, 'other_home_dirs': 1, 'symlinked_homes': 0,
                          'oslogin_caches': 0, 'agent_state_paths': 0}, report['access'])
        self.assertTrue((other / '.ssh' / 'authorized_keys').exists())
        self.assertTrue(image.load_receipt()['owned_sealed'])  # owned portion is sealed regardless

    def test_ubuntu_level_and_symlinked_and_agent_access_state_is_counted(self):
        write(self.w.home / 'ubuntu' / 'google_authorized_keys', b'k')
        (self.w.home / 'linked').symlink_to(self.w.work)
        agent = self.w.tmp / 'agent-state'
        agent.mkdir()
        with patch.object(image, 'AGENT_STATE', (agent, self.w.tmp / 'absent')):
            report = json.loads(self.prepare()[1])
        self.assertEqual((1, 1, 1), (report['access']['key_files'], report['access']['symlinked_homes'],
                                     report['access']['agent_state_paths']))
        self.assertEqual('unproven', report['access']['status'])
        self.assertTrue((self.w.home / 'ubuntu' / 'google_authorized_keys').exists())

    def test_verify_stays_unmet(self):
        self.prepare()
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(3, image.verify(SimpleNamespace()))
        self.assertEqual([image.UNMET_ACCESS], json.loads(out.getvalue())['unmet'])

    def test_second_prepare_after_seal_is_refused(self):
        self.prepare()
        with self.assertRaises(image.Refused):
            self.prepare()

    def test_runtime_dropin_is_removed_only_when_exact(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        self.assertEqual(3, self.prepare()[0])
        self.assertFalse(self.w.dropin.exists())

    def test_foreign_runtime_dropin_is_refused_before_any_mutation(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nExecStart=/bin/sh\n')
        self.refused()


class InterruptionTests(Base):
    """Crash injection at every kind of step; reruns use only the retained sealing intent."""

    def finish_after(self, nth):
        self.interrupted_unlink(nth)
        self.assertEqual('sealing', image.load_receipt()['state'])
        code, _ = self.prepare()
        self.assertEqual(3, code)
        self.assertEqual('sealed', image.load_receipt()['state'])
        self.assertFalse(self.w.trial.exists())
        self.assertEqual((self.w.work / 'fab.yaml').read_bytes(), CANARY.encode())

    def test_interrupted_before_any_terminal_record_is_removed(self):
        self.finish_after(2)

    def test_interrupted_at_first_middle_and_last_terminal_unlink(self):
        for nth in (5, 8, 10):  # success.json, started.json, contract.json (terminal order)
            with self.subTest(nth=nth):
                self.setUp()
                self.finish_after(nth)

    def test_interrupted_between_trial_unit_and_dropin_removal(self):
        write_dir = self.w.dropin
        write_dir.mkdir()
        write(write_dir / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        self.interrupted_unlink(12)  # 10 trial files, then the installed unit (11), then the drop-in
        self.assertFalse((self.w.units / image.TRIAL_UNIT).exists())
        self.assertTrue(self.w.dropin.exists())
        self.assertEqual(3, self.prepare()[0])
        self.assertFalse(self.w.dropin.exists())

    def test_interrupted_between_service_steps(self):
        real = self.w.run

        def failing(argv, seconds, term_grace=0):
            if argv[:2] == [image.SYSTEMCTL, 'enable']:
                raise RuntimeError('injected interruption')
            return real(argv, seconds, term_grace)
        with patch.object(image, 'run', failing):
            with self.assertRaises(RuntimeError):
                self.prepare()
        self.assertEqual('sealing', image.load_receipt()['state'])
        self.assertEqual(3, self.prepare()[0])
        self.assertEqual('enabled', self.w.enabled[image.CLONE_UNIT])

    def test_unknown_file_appearing_after_interruption_is_preserved_and_refused(self):
        self.interrupted_unlink(7)
        write(self.w.trial / 'authorized_keys', b'k')
        before = self.w.snapshot(self.w.trial)
        with self.assertRaises(image.Refused):
            self.prepare()
        self.assertEqual(before, self.w.snapshot(self.w.trial))
        self.assertEqual('sealing', image.load_receipt()['state'])

    def test_remaining_terminal_record_must_match_the_retained_hash(self):
        self.interrupted_unlink(8)  # started.json, manifest.json and contract.json remain
        self.w.rewrite('contract.json', deadline='2098-01-01T00:00:00Z')
        with self.assertRaises(image.Refused):
            self.prepare()
        self.assertTrue((self.w.trial / 'contract.json').exists())

    def test_a_name_outside_the_retained_intent_is_refused(self):
        self.interrupted_unlink(8)
        write(self.w.trial / 'phase.json', b'{}')  # an OWNED_NAMES name, but not in this intent
        with self.assertRaises(image.Refused):
            self.prepare()
        self.assertTrue((self.w.trial / 'phase.json').exists())

    def test_expired_original_deadline_blocks_a_retry_after_partial_removal(self):
        self.interrupted_unlink(8)
        before = self.w.snapshot(self.w.tmp)
        with patch.object(time, 'time', lambda: EXPIRED):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertEqual(before, self.w.snapshot(self.w.tmp))

    def test_deadline_expiring_between_two_unlinks_stops_the_removal(self):
        calls, real = [], os.unlink
        late = []

        def fake_unlink(*args, **kwargs):
            real(*args, **kwargs)
            calls.append(args[0])
            if len(calls) == 2:
                late.append(True)
        with patch.object(os, 'unlink', fake_unlink), \
                patch.object(time, 'time', lambda: EXPIRED if late else REAL_TIME()):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertTrue(self.w.trial.exists())
        self.assertEqual('sealing', image.load_receipt()['state'])
        self.assertEqual(2, len(calls))

    def test_deadline_expired_after_trial_is_gone_still_blocks_the_rest(self):
        self.interrupted_unlink(11)  # trial root gone, installed trial unit still present
        with patch.object(time, 'time', lambda: EXPIRED):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertTrue((self.w.units / image.TRIAL_UNIT).exists())


class CloneStartTests(Base):
    def sealed(self):
        self.assertEqual(3, self.prepare()[0])
        self.w.boot = CLONE

    def start(self):
        out = io.StringIO()
        with redirect_stdout(out):
            return image.clone_start(SimpleNamespace())

    def clean_shutdown(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, image.clone_stop(SimpleNamespace()))
        self.w.shutdown()

    def checkpoint(self):
        return json.loads((self.w.seal / image.CLONE_START).read_bytes())

    def test_new_boot_gets_a_fresh_operation_via_the_unchanged_core(self):
        self.sealed()
        self.assertEqual(0, self.start())
        self.assertIn([image.PYTHON, str(image.LIB / 'vlab_core.py'), 'start-resume'], self.w.commands)
        started = self.checkpoint()
        self.assertEqual(CLONE, started['boot'])
        self.assertNotEqual(OP, started['operation'])
        self.assertNotEqual(INV, started['invocation'])

    def test_second_and_third_verified_clean_boots_start(self):
        self.sealed()
        seen = set()
        for boot in (CLONE, CLONE2, CLONE3):
            self.w.boot = boot
            self.assertEqual(0, self.start())
            value = self.checkpoint()
            self.assertEqual(boot, value['boot'])
            self.assertNotIn(value['operation'], seen)
            seen.add(value['operation'])
            self.assertEqual('ready', self.w.state['phase'])
            self.clean_shutdown()
            self.assertEqual('stop-observed', self.w.state['phase'])
        cores = [c[-1] for c in self.w.commands if c[0] == image.PYTHON]
        # only the core's own public verified stop commits an observed shutdown; never init / start-fresh
        self.assertEqual(['start-resume', 'stop', 'start-resume', 'stop', 'start-resume'], cores)

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
        real = self.w.run

        def stale(argv, seconds, term_grace=0):
            if argv[-1] != 'start-resume':
                return real(argv, seconds, term_grace)
            self.w.commands.append(list(argv))
            self.w.state.update(phase='ready', boot=BUILD, operation=OP, invocation=INV)
            return 0, b''
        with patch.object(image, 'run', stale):
            with self.assertRaises(image.Refused):
                self.start()
        self.assertFalse((self.w.seal / image.CLONE_START).exists())

    def test_core_failure_is_not_success_and_does_not_start_anything_else(self):
        self.sealed()
        real = self.w.run
        with patch.object(image, 'run', lambda argv, seconds, term_grace=0: (1, b'')
                          if argv[-1] == 'start-resume' else real(argv, seconds, term_grace)):
            with self.assertRaises(image.Refused):
                self.start()
        self.assertFalse((self.w.seal / image.CLONE_START).exists())
        self.assertEqual([], [c for c in self.w.commands if c[-1] in ('init', 'start-fresh')])

    # ---- later boots: only a strict, owned, tied checkpoint plus an observed clean stop ----
    def first_boot_then_clean_shutdown(self):
        self.sealed()
        self.assertEqual(0, self.start())
        self.clean_shutdown()
        self.w.boot = CLONE2

    def test_stale_checkpoint_operation_is_refused(self):
        self.first_boot_then_clean_shutdown()
        value = self.checkpoint()
        (self.w.seal / image.CLONE_START).unlink()
        write(self.w.seal / image.CLONE_START, image.encoded({**value, 'operation': 'e' * 32}))
        with self.assertRaises(image.Refused):
            self.start()

    def test_foreign_or_malformed_checkpoint_is_refused(self):
        self.first_boot_then_clean_shutdown()
        value = self.checkpoint()
        path = self.w.seal / image.CLONE_START
        for make in (lambda: write(path, image.encoded({**value, 'extra': 1})),
                     lambda: write(path, image.encoded({**value, 'boot': 'not-a-uuid'})),
                     lambda: write(path, b'[]'),
                     lambda: write(path, image.encoded(value), 0o644),
                     lambda: (write(self.w.tmp / 'real.json', image.encoded(value)),
                              path.symlink_to(self.w.tmp / 'real.json')),
                     lambda: (write(self.w.tmp / 'real2.json', image.encoded(value)),
                              os.link(self.w.tmp / 'real2.json', path))):
            with self.subTest():
                path.unlink()
                make()
                with self.assertRaises(image.Refused):
                    self.start()
                path.unlink()
                write(path, image.encoded(value))

    def test_checkpoint_from_the_current_or_build_boot_is_refused(self):
        self.first_boot_then_clean_shutdown()
        value = self.checkpoint()
        for boot in (CLONE2, BUILD):
            with self.subTest(boot=boot):
                (self.w.seal / image.CLONE_START).unlink()
                write(self.w.seal / image.CLONE_START, image.encoded({**value, 'boot': boot}))
                with self.assertRaises(image.Refused):
                    self.start()

    def test_unclean_stop_leaves_failed_state_and_is_never_adopted(self):
        self.sealed()
        self.assertEqual(0, self.start())
        self.w.shutdown()  # no clone-stop intent: the core marks the invocation failed
        self.assertEqual('failed', self.w.state['phase'])
        self.w.boot = CLONE2
        with self.assertRaises(image.Refused):
            self.start()
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))

    def test_stop_observation_needs_the_exact_owned_intent_and_prior_boot(self):
        self.first_boot_then_clean_shutdown()
        good = dict(self.w.state)
        for change in ({'stopping': {'operation': 'e' * 32, 'invocation': good['invocation']}},
                       {'service_result': 'success'}, {'boot': BUILD}, {'nonce': 'f' * 32},
                       {'invocation': 'e' * 32}):
            with self.subTest(change=change):
                self.w.state = {**good, **change}
                with self.assertRaises(image.Refused):
                    self.start()
        self.assertNotIn('stop', [c[-1] for c in self.w.commands if c[0] == image.PYTHON])

    def test_stop_observation_without_any_checkpoint_is_refused(self):
        self.sealed()
        self.w.state.update(phase='stop-observed', stopping={'operation': OP, 'invocation': INV},
                            service_result='owned-stop-process-termination')
        with self.assertRaises(image.Refused):
            self.start()

    def test_core_stop_failure_blocks_the_start(self):
        self.first_boot_then_clean_shutdown()
        real = self.w.run
        with patch.object(image, 'run', lambda argv, seconds, term_grace=0: (1, b'')
                          if argv[-1] == 'stop' else real(argv, seconds, term_grace)):
            with self.assertRaises(image.Refused):
                self.start()
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))


class CloneStopTests(Base):
    def ready(self):
        self.assertEqual(3, self.prepare()[0])
        self.w.boot = CLONE
        with redirect_stdout(io.StringIO()):
            image.clone_start(SimpleNamespace())

    def stop(self):
        with redirect_stdout(io.StringIO()):
            return image.clone_stop(SimpleNamespace())

    def test_records_the_core_intent_and_never_stops_or_waits_on_the_unit(self):
        self.ready()
        before = len(self.w.commands)
        self.assertEqual(0, self.stop())
        self.assertEqual([], self.w.commands[before:])  # no systemctl stop/start/run of any kind
        self.assertEqual({'operation': self.w.state['operation'], 'invocation': self.w.state['invocation']},
                         self.w.state['stopping'])
        self.assertEqual('ready', self.w.state['phase'])  # the core's ExecStopPost makes the transition

    def test_nothing_is_marked_unless_ready_on_this_boot(self):
        self.ready()
        for phase in ('failed', 'starting', 'resumable', 'stop-observed'):
            self.w.state['phase'] = phase
            self.stop()
            self.assertNotIn('stopping', self.w.state)

    def test_a_different_resume_invocation_is_refused(self):
        self.ready()
        self.w.state['invocation'] = 'e' * 32  # the unit's InvocationID no longer matches
        with self.assertRaises(image.Refused):
            self.stop()
        self.assertNotIn('stopping', self.w.state)

    def test_state_from_another_boot_is_refused(self):
        self.ready()
        self.w.state['boot'] = BUILD
        with self.assertRaises(image.Refused):
            self.stop()


class Activated(Base):
    """Helpers for a sealed image on a new boot (fake core mirrors vlab_core.py transitions)."""

    def sealed(self):
        self.assertEqual(3, self.prepare()[0])
        self.w.boot = CLONE

    def start(self):
        with redirect_stdout(io.StringIO()):
            return image.clone_start(SimpleNamespace())

    def stop(self):
        with redirect_stdout(io.StringIO()):
            return image.clone_stop(SimpleNamespace())

    def checkpoint(self):
        return json.loads((self.w.seal / image.CLONE_START).read_bytes())

    def fail_checkpoint_once(self, error):
        real, calls = image.atomic, []

        def flaky(path, value):
            if Path(path).name == image.CLONE_START and not calls:
                calls.append(path)
                raise error
            return real(path, value)
        return patch.object(image, 'atomic', flaky)

    def stopped_cleanly(self):
        state = self.w.state
        return (not self.w.resume_active and state['phase'] == 'resumable'
                and state.get('stop_verified') == {'operation': state['operation'],
                                                   'invocation': state['invocation']})


class ActivationCleanupTests(Activated):
    """Failure/cancel AFTER the core CLI reported success must stop the independent resume unit."""

    def test_checkpoint_publication_failure_after_ready_stops_the_backend(self):
        self.sealed()
        with self.fail_checkpoint_once(OSError('injected checkpoint failure')):
            with self.assertRaises(OSError):  # the PRIMARY failure is preserved, not replaced
                self.start()
        self.assertTrue(self.stopped_cleanly())
        self.assertEqual(1, self.w.core_stops)
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))
        # the verified stop committed a new pair, so it is recorded (and only that exact pair)
        self.assertEqual((self.w.state['operation'], self.w.state['invocation']),
                         (self.checkpoint()['operation'], self.checkpoint()['invocation']))
        self.assertEqual(CLONE, self.checkpoint()['boot'])

    def test_late_interrupt_after_the_checkpoint_stops_the_backend_and_stays_cancelled(self):
        self.sealed()
        real = image.atomic

        def late(path, value):
            real(path, value)
            raise image.Cancelled()  # handled SIGTERM arriving after the last write
        with patch.object(image, 'atomic', late):
            with self.assertRaises(image.Cancelled):
                self.start()
        self.assertTrue(self.stopped_cleanly())
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))

    def test_startup_cancel_while_the_core_cli_runs_stops_without_restart(self):
        self.sealed()
        real = self.w.run

        def cancelled(argv, seconds, term_grace=0):
            if argv[-1] == 'start-resume':
                real(argv, seconds, term_grace)  # the core already made the unit ready ...
                raise image.Cancelled()          # ... when the handled signal arrived
            return real(argv, seconds, term_grace)
        with patch.object(image, 'run', cancelled):
            with self.assertRaises(image.Cancelled):
                self.start()
        self.assertTrue(self.stopped_cleanly())
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))
        # a second signal cannot cut the cleanup short
        self.assertEqual(signal.SIG_IGN, signal.getsignal(signal.SIGTERM))
        self.assertEqual(signal.SIG_IGN, signal.getsignal(signal.SIGINT))

    def test_cleanup_failure_is_reported_honestly_and_the_primary_failure_wins(self):
        self.sealed()
        self.w.stop_fails = True
        err = io.StringIO()
        with self.fail_checkpoint_once(OSError('injected checkpoint failure')), redirect_stderr(err):
            with self.assertRaises(OSError):
                self.start()
        self.assertIn('activation cleanup unverified', err.getvalue())
        self.assertTrue(self.w.resume_active)  # not claimed stopped
        self.assertFalse((self.w.seal / image.CLONE_START).exists())

    def test_backend_still_running_after_a_zero_core_stop_is_not_verified(self):
        self.sealed()
        real = self.w.run

        def liar(argv, seconds, term_grace=0):
            if argv[-1] == 'stop':
                return 0, b''  # core claims success but the unit stays up
            return real(argv, seconds, term_grace)
        err = io.StringIO()
        with self.fail_checkpoint_once(OSError('x')), patch.object(image, 'run', liar), redirect_stderr(err):
            with self.assertRaises(OSError):
                self.start()
        self.assertIn('activation cleanup unverified', err.getvalue())

    def test_failure_before_the_core_is_launched_stops_nothing(self):
        self.sealed()
        self.w.trial.mkdir(mode=0o700)
        with self.assertRaises(image.Refused):
            self.start()
        self.assertEqual(0, self.w.core_stops)
        self.assertEqual(signal.getsignal(signal.SIGTERM), image._cancel)  # handler installed, not ignored

    def test_core_refusal_runs_the_serialized_stop_and_keeps_the_refusal(self):
        self.sealed()
        real = self.w.run
        with patch.object(image, 'run', lambda argv, seconds, term_grace=0: (1, b'')
                          if argv[-1] == 'start-resume' else real(argv, seconds, term_grace)):
            with self.assertRaises(image.Refused):
                self.start()
        self.assertEqual(1, self.w.core_stops)
        self.assertFalse(self.w.resume_active)

    def test_signal_handler_raises_the_non_exception_cancel(self):
        with self.assertRaises(image.Cancelled):
            image._cancel(signal.SIGTERM, None)
        self.assertFalse(issubclass(image.Cancelled, Exception))


class StandaloneStopTests(Activated):
    def ready(self):
        self.sealed()
        self.assertEqual(0, self.start())

    def test_intent_is_bound_to_the_seal_boot_and_checkpointed_activation(self):
        self.ready()
        before = len(self.w.commands)
        self.assertEqual(0, self.stop())
        self.assertEqual([], self.w.commands[before:])  # never a systemctl/core stop from ExecStop
        self.assertEqual({'operation': self.w.state['operation'], 'invocation': self.w.state['invocation']},
                         self.w.state['stopping'])

    def test_missing_wrong_or_foreign_context_refuses_and_writes_nothing(self):
        self.ready()
        good_state, path = dict(self.w.state), self.w.seal / image.CLONE_START
        value = self.checkpoint()
        for label, mutate in (
                ('no checkpoint', lambda: path.unlink()),
                ('other operation', lambda: (path.unlink(), write(path, image.encoded({**value, 'operation': 'e' * 32})))),
                ('other invocation', lambda: (path.unlink(), write(path, image.encoded({**value, 'invocation': 'e' * 32})))),
                ('other boot', lambda: (path.unlink(), write(path, image.encoded({**value, 'boot': CLONE2})))),
                ('other nonce', lambda: self.w.state.update(nonce='f' * 32)),
                ('other mode', lambda: self.w.state.update(mode='fresh'))):
            with self.subTest(label):
                self.w.state = dict(good_state)
                if not path.exists():
                    write(path, image.encoded(value))
                mutate()
                with self.assertRaises(image.Refused):
                    self.stop()
                self.assertNotIn('stopping', self.w.state)

    def test_unsealed_receipt_refuses(self):
        self.ready()
        receipt = image.load_receipt()
        receipt.update(state='sealing', owned_sealed=False)
        image.atomic(self.w.seal / image.RECEIPT, receipt)
        with self.assertRaises(image.Refused):
            self.stop()

    def test_stop_serializes_with_an_active_core_stop_controller(self):
        self.ready()
        self.w.controller_busy = True
        with self.assertRaises(image.Refused):
            self.stop()
        self.assertNotIn('stopping', self.w.state)

    def test_standalone_stop_then_same_boot_restart_commits_only_through_the_core_stop(self):
        self.ready()
        first = self.checkpoint()
        self.assertEqual(0, self.stop())
        self.w.shutdown()  # the propagated stop job: ExecStopPost sees the intent
        self.assertEqual('stop-observed', self.w.state['phase'])
        self.assertFalse(self.w.resume_active)
        self.assertEqual(0, self.start())  # same boot: allowed only from OUR observed stop
        cores = [c[-1] for c in self.w.commands if c[0] == image.PYTHON]
        self.assertEqual(['start-resume', 'stop', 'start-resume'], cores)
        self.assertNotEqual(first['operation'], self.checkpoint()['operation'])
        self.assertTrue(self.w.resume_active)

    def test_same_boot_restart_is_refused_while_the_backend_still_runs(self):
        self.ready()
        with self.assertRaises(image.Refused):
            self.start()  # not stopped: offline gate fails, no second start-resume
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))

    def test_same_boot_restart_is_refused_after_an_unowned_failure(self):
        self.ready()
        self.w.shutdown()  # stop WITHOUT clone-stop intent: the core marks it failed
        self.assertEqual('failed', self.w.state['phase'])
        with self.assertRaises(image.Refused):
            self.start()
        self.assertEqual(1, [c[-1] for c in self.w.commands if c[0] == image.PYTHON].count('start-resume'))


class InstalledPinTests(Activated):
    """The ACTUAL installed unit/tool bytes and metadata are checked, not systemd's loaded view."""

    def edit_unit(self, raw=None, mode=0o644):
        path = self.w.units / image.CLONE_UNIT
        path.unlink()
        write(path, raw if raw is not None else CLONE_BYTES + b'ExecStartPre=/bin/sh\n', mode)

    def test_edited_and_reloaded_unit_fails_verify_clone_start_and_clone_stop(self):
        self.sealed()
        self.assertEqual(0, self.start())
        self.edit_unit()  # fake systemd reports NeedDaemonReload=no, i.e. the edit was reloaded
        with self.assertRaises(image.Refused):
            image.verify(SimpleNamespace())
        with self.assertRaises(image.Refused):
            self.stop()
        self.assertNotIn('stopping', self.w.state)
        self.w.shutdown()
        self.w.boot = CLONE2
        before = len(self.w.commands)
        with self.assertRaises(image.Refused):
            self.start()
        self.assertEqual([], [c for c in self.w.commands[before:] if c[0] == image.PYTHON])

    def test_unsafe_unit_or_tool_metadata_fails(self):
        self.sealed()
        for label, damage in (
                ('mode', lambda: (self.w.units / image.CLONE_UNIT).chmod(0o664)),
                ('hardlink', lambda: os.link(self.w.units / image.CLONE_UNIT, self.w.tmp / 'extra-link')),
                ('symlink', lambda: (self.edit_unit(), (self.w.units / image.CLONE_UNIT).unlink(),
                                     (self.w.units / image.CLONE_UNIT).symlink_to(self.w.src / image.CLONE_UNIT))),
                ('tool bytes', lambda: (self.w.lib / 'vlab_image.py').write_bytes(b'# other\n')),
                ('tool mode', lambda: (self.w.lib / 'vlab_image.py').chmod(0o666))):
            with self.subTest(label):
                receipt = image.load_receipt()
                self.edit_unit(CLONE_BYTES)
                write(self.w.lib / 'vlab_image.py', (HERE / 'vlab_image.py').read_bytes(), 0o644)
                image.unit_pin(receipt)  # pristine again
                damage()
                with self.assertRaises(image.Refused):
                    image.unit_pin(receipt)

    def test_unit_changed_between_install_and_postconditions_blocks_the_seal(self):
        real = self.w.run

        def edit_on_reload(argv, seconds, term_grace=0):
            if argv[:2] == [image.SYSTEMCTL, 'daemon-reload']:
                self.edit_unit()
            return real(argv, seconds, term_grace)
        with patch.object(image, 'run', edit_on_reload):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertEqual('sealing', image.load_receipt()['state'])


class OriginalClockTests(Activated):
    """One wall AND monotonic cutoff, clipped to the original deadline, checked at every mutation."""

    def test_receipt_retains_a_monotonic_cutoff_clipped_to_the_original_deadline(self):
        before = time.monotonic()
        with patch.object(time, 'time', lambda: EXPIRED - 100):  # 99 s of the original window left
            self.prepare()
        cutoff = image.load_receipt()['monotonic_deadline']
        self.assertLess(cutoff - before, 105)
        self.assertGreater(cutoff - before, 90)

    def test_expiry_after_the_postconditions_blocks_the_sealed_publication(self):
        late, real = [], image.owned_absent

        def then_expire(receipt):
            real(receipt)
            late.append(True)
        with patch.object(image, 'owned_absent', then_expire), \
                patch.object(time, 'time', lambda: EXPIRED if late else REAL_TIME()):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertEqual('sealing', image.load_receipt()['state'])  # never published as sealed

    def test_monotonic_expiry_holds_even_if_the_wall_clock_goes_backwards(self):
        late, real = [], os.unlink
        real_mono = time.monotonic

        def unlink_then_jump(*args, **kwargs):
            real(*args, **kwargs)
            late.append(True)
        with patch.object(os, 'unlink', unlink_then_jump), \
                patch.object(time, 'time', lambda: REAL_TIME() - (1000 if late else 0)), \
                patch.object(time, 'monotonic', lambda: real_mono() + (1e12 if late else 0)):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertEqual('sealing', image.load_receipt()['state'])
        self.assertTrue(self.w.trial.exists())

    def test_retry_keeps_the_original_cutoff_without_rebasing(self):
        self.interrupted_unlink(8)
        cutoff = image.load_receipt()['monotonic_deadline']
        real_mono = time.monotonic
        with patch.object(time, 'monotonic', lambda: real_mono() + 1e12):  # past the retained cutoff
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertEqual(cutoff, image.load_receipt()['monotonic_deadline'])
        self.assertEqual(3, self.prepare()[0])
        self.assertEqual(cutoff, image.load_receipt()['monotonic_deadline'])

    def test_expiry_between_the_trial_unit_unlink_and_the_dropin_unlink(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        late, real = [], os.unlink

        def fake(*args, **kwargs):
            real(*args, **kwargs)
            if Path(str(args[0])) == self.w.units / image.TRIAL_UNIT:
                late.append(True)
        with patch.object(os, 'unlink', fake), \
                patch.object(time, 'time', lambda: EXPIRED if late else REAL_TIME()):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertTrue((self.w.dropin / '10-bound.conf').exists())
        self.assertFalse((self.w.units / image.TRIAL_UNIT).exists())

    def test_expiry_between_dropin_unlink_and_rmdir_keeps_the_empty_directory(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        late, real = [], os.unlink

        def fake(*args, **kwargs):
            real(*args, **kwargs)
            if Path(str(args[0])) == self.w.dropin / '10-bound.conf':
                late.append(True)
        with patch.object(os, 'unlink', fake), \
                patch.object(time, 'time', lambda: EXPIRED if late else REAL_TIME()):
            with self.assertRaises(image.Refused):
                self.prepare()
        self.assertTrue(self.w.dropin.is_dir())
        self.assertEqual([], list(self.w.dropin.iterdir()))


class PublicationInterruptionTests(Activated):
    """Interruption at the precise windows inside multi-step mutators."""

    def test_interrupted_after_the_dropin_unlink_before_the_directory_rmdir(self):
        self.w.dropin.mkdir()
        write(self.w.dropin / '10-bound.conf', b'[Service]\nRuntimeMaxSec=6000\n')
        real = os.rmdir

        def fake(path, *args, **kwargs):
            if str(path) == str(self.w.dropin):
                raise RuntimeError('injected interruption')
            return real(path, *args, **kwargs)
        with patch.object(os, 'rmdir', fake):
            with self.assertRaises(RuntimeError):
                self.prepare()
        self.assertEqual([], list(self.w.dropin.iterdir()))  # exactly the attributable remainder
        self.assertEqual(3, self.prepare()[0])  # retry accepts it and finishes
        self.assertFalse(self.w.dropin.exists())

    def test_empty_or_unsafe_dropin_directory_is_accepted_only_when_attributable(self):
        self.w.dropin.mkdir()
        self.w.dropin.chmod(0o777)
        self.refused()  # group/world writable: foreign, preserved
        self.assertTrue(self.w.dropin.is_dir())
        self.w.dropin.chmod(0o755)
        write(self.w.dropin / 'other.conf', b'x')
        self.refused()
        self.assertTrue((self.w.dropin / 'other.conf').exists())

    def test_interrupted_final_file_write_leaves_no_partial_final_bytes(self):
        real, calls = os.fsync, []

        def fake(fd):
            calls.append(fd)
            if len(calls) == 2:  # 1 = receipt, 2 = the tool temporary
                raise RuntimeError('injected interruption')
            return real(fd)
        with patch.object(os, 'fsync', fake):
            with self.assertRaises(RuntimeError):
                self.prepare()
        self.assertFalse((self.w.lib / 'vlab_image.py').exists())  # never partial FINAL bytes
        self.assertTrue((self.w.lib / 'vlab_image.py.installing').exists())
        self.assertEqual(3, self.prepare()[0])
        self.assertEqual((HERE / 'vlab_image.py').read_bytes(), (self.w.lib / 'vlab_image.py').read_bytes())
        self.assertFalse((self.w.lib / 'vlab_image.py.installing').exists())

    def test_interrupted_rename_of_the_unit_is_retried_from_the_complete_temporary(self):
        real, calls = os.rename, []

        def fake(source, target, *args, **kwargs):
            calls.append(str(target))
            if str(target).endswith(image.CLONE_UNIT):
                raise RuntimeError('injected interruption')
            return real(source, target, *args, **kwargs)
        with patch.object(os, 'rename', fake):
            with self.assertRaises(RuntimeError):
                self.prepare()
        self.assertFalse((self.w.units / image.CLONE_UNIT).exists())
        self.assertEqual(CLONE_BYTES, (self.w.units / (image.CLONE_UNIT + '.installing')).read_bytes())
        self.assertEqual(3, self.prepare()[0])
        self.assertEqual(CLONE_BYTES, (self.w.units / image.CLONE_UNIT).read_bytes())
        self.assertEqual(0o644, (self.w.units / image.CLONE_UNIT).stat().st_mode & 0o7777)

    def test_a_foreign_temporary_is_preserved_and_refused(self):
        other = self.w.tmp / 'elsewhere'
        write(other, b'x')
        (self.w.lib / 'vlab_image.py.installing').symlink_to(other)
        with self.assertRaises(image.Refused):
            self.prepare()
        self.assertTrue((self.w.lib / 'vlab_image.py.installing').is_symlink())
        self.assertEqual(b'x', other.read_bytes())
        self.assertFalse((self.w.lib / 'vlab_image.py').exists())


class RunTests(unittest.TestCase):
    """The real ``run`` on tiny interpreter children (no systemd, no project code)."""

    def test_output_is_capped_while_captured(self):
        code, out = image.run([sys.executable, '-c', 'import sys;sys.stdout.write("x"*300000)'], 30)
        self.assertEqual((0, image.MAX_OUTPUT), (code, len(out)))

    def test_nonzero_exit_is_returned(self):
        self.assertEqual(3, image.run([sys.executable, '-c', 'raise SystemExit(3)'], 30)[0])

    def test_timeout_is_a_refusal_with_group_closed(self):
        started = time.monotonic()
        with self.assertRaisesRegex(image.Refused, 'child timeout'):
            image.run([sys.executable, '-c', 'import time;time.sleep(60)'], 1)
        self.assertLess(time.monotonic() - started, 20)

    def test_descendant_holding_the_pipe_is_killed_with_the_group(self):
        code = ('import subprocess,sys;'
                'subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])')
        started = time.monotonic()
        with self.assertRaisesRegex(image.Refused, 'child timeout'):
            image.run([sys.executable, '-c', code], 1)
        self.assertLess(time.monotonic() - started, 20)

    def test_uncertain_group_cleanup_is_not_success(self):
        with patch.object(owned_process.OwnedGroup, 'close', lambda self, *a, **k: False):
            with self.assertRaisesRegex(image.Refused, 'cleanup uncertain'):
                image.run([sys.executable, '-c', 'pass'], 30)

    def test_spawn_failure_is_a_refusal(self):
        with self.assertRaisesRegex(image.Refused, 'spawn'):
            image.run(['/nonexistent/labapp-image-test'], 5)


class ScopeTests(unittest.TestCase):
    def unit(self):
        return (HERE / image.CLONE_UNIT).read_text()

    def test_fixed_unit_scope(self):
        text = self.unit()
        self.assertIn('Type=oneshot', text)
        self.assertIn('ExecStart=/usr/bin/python3 /usr/local/lib/labapp/vlab_image.py clone-start', text)
        self.assertIn('ExecStop=/usr/bin/python3 /usr/local/lib/labapp/vlab_image.py clone-stop', text)
        for forbidden in ('Wants=hhfab', 'Requires=', 'Restart=', 'EnvironmentFile', 'ExecStartPre',
                          'vlab_trial', 'init', 'ghcr', 'systemctl', 'vlab_core.py stop', 'Before='):
            self.assertNotIn(forbidden, text)

    def test_signals_reach_only_the_helper_and_stop_is_propagated_one_way(self):
        text = self.unit()
        # mixed: SIGTERM only to the helper (its cancel cleanup runs the core stop); SIGKILL to the rest
        self.assertIn('KillMode=mixed', text)
        self.assertNotIn('KillMode=control-group', text)
        self.assertNotIn('KillMode=process', text)
        self.assertIn('PropagatesStopTo=hhfab-vlab-resume.service', text)
        self.assertNotIn('PartOf=', text)  # no restart propagation: nothing here may start the backend
        self.assertNotIn('BindsTo=', text)
        timeout = int(next(l for l in text.splitlines() if l.startswith('TimeoutStopSec=')).split('=')[1])
        self.assertGreaterEqual(timeout, image.CORE_TERM_GRACE + 70 + 45)  # grace + core stop + proof
        self.assertIn('After=network-online.target hhfab-vlab-resume.service', text)
        for line in text.splitlines():
            if line.startswith('Exec'):
                self.assertNotIn('resume', line)  # no start/stop of the resume unit from this unit

    def test_manifest_covers_every_trial_owned_name_and_success_shape_matches(self):
        self.assertEqual(trial.SUCCESS, image.SUCCESS)
        trial_names = {*trial.FILES, 'manifest.json'}
        self.assertLessEqual(trial_names, image.OWNED_NAMES)
        for name in (trial.AUTH_INTENT, trial.AUTH_BOUND, trial.AUTH_READY, trial.AUTH_REMOVED, trial.AUTH_CLOSED,
                     trial.AUTH_FILE, trial.AUTH_UNLINKED, trial.AUTH_DIR_REMOVED, trial.AUTH_GUARDIAN,
                     trial.AUTH_LOCK, trial.INSTALLER_FAILURE):
            self.assertIn(name, image.OWNED_NAMES)
        self.assertNotIn('authorized_keys', image.OWNED_NAMES)
        self.assertEqual(set(image.TERMINAL), set(image.TERMINAL_EVIDENCE))

    def test_clone_start_reads_no_build_lease_deadline_or_heartbeat_authority(self):
        import inspect
        source = inspect.getsource(image.clone_start)
        for forbidden in ("['deadline']", 'heartbeat', 'contract.json', 'TRIAL /', "'lease'", 'args.lease'):
            self.assertNotIn(forbidden, source)

    def test_fake_core_literals_still_exist_in_the_real_core(self):
        core = (HERE / 'vlab_core.py').read_text()
        for literal in ("'stop-observed'", "'owned-stop-process-termination'", "current['stopping'] = {'operation'",
                        "value.pop('stopping', None)", "'stop_verified'", "def unit_finished(", "def stop():"):
            self.assertIn(literal, core)


if __name__ == '__main__':
    unittest.main()
