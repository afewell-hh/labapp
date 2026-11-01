"""Fixed shared trial entrypoints, public temp files and fail-closed spies only.

No real package/systemd/hhfab/QEMU/sudo/network/process invocation. Production
paths are patched before mutating entrypoints. The only credential fixtures are the
synthetic non-deployable canaries of the #378 transient-registry-auth tests.
"""
import base64
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
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


def owned_json(nonce, uid, spec, annotation=None):
    """Public fixture JSON for a nonce-owned object; annotation defaults to the full nonce."""
    annotations = {} if annotation is False else {trial.Nonce.ANNOTATION: nonce.nonce if annotation is None else annotation}
    return json.dumps({'metadata': {'name': nonce.name, 'namespace': 'default', 'uid': uid,
                                    'annotations': annotations}, 'spec': spec}).encode()


class FakeAdmissionApi:
    """Deterministic model of the DOCUMENTED Fabric v0.96.2 VPC admission contract.

    Name <= 11 characters, lowercase RFC1123, namespace default. This is a model
    for the actual Nonce methods, NOT native validation of the live webhook.
    """
    KINDS = {'vpcs': 'VPC', 'vpcattachments': 'VPCAttachment'}

    def __init__(self):
        self.store, self.calls, self.counter = {}, [], 0
        self.response_annotations = {}  # Per-kind create-response mutations only.
        self.before_delete = None  # Race after the client's final GET, before UID enforcement.
        self.deletes = []

    def admit(self, doc):
        meta = doc['metadata']
        if doc['kind'] == 'VPC' and len(meta['name']) > 11:
            raise AssertionError('admission denied: VPC name longer than 11 characters')
        if not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*', meta['name']) or meta.get('namespace') != 'default':
            raise AssertionError('admission denied: metadata')

    def seed(self, kind, name, annotations, spec=None):
        self.counter += 1
        self.store[(kind, name)] = {'apiVersion': 'vpc.githedgehog.com/v1beta1', 'kind': kind,
                                    'metadata': {'name': name, 'namespace': 'default', 'uid': 'seed-%d' % self.counter,
                                                 'annotations': annotations}, 'spec': spec or {}}

    def kubectl(self, args, end):
        self.calls.append(list(args))
        if args[0] == 'get' and '-A' in args:
            return json.dumps({'items': [d for (k, _), d in self.store.items() if k == 'VPC']}).encode()
        if args[0] == 'get':
            found = self.store.get((self.KINDS[args[1].split('.')[0]], args[2]))
            return json.dumps(found).encode() if found else b''
        if args[0] == 'create':
            doc = json.loads(Path(args[2]).read_text())
            self.admit(doc)
            key = (doc['kind'], doc['metadata']['name'])
            if key in self.store:
                raise AssertionError('already exists; create must never overwrite')
            self.counter += 1
            doc['metadata']['uid'] = 'uid-%d' % self.counter
            self.store[key] = doc
            response = deepcopy(doc)
            replacement = self.response_annotations.get(doc['kind'])
            if replacement is False:
                response['metadata'].pop('annotations')
            elif replacement is not None:
                response['metadata']['annotations'][trial.Nonce.ANNOTATION] = replacement
            return json.dumps(response).encode()
        if args[0] == 'delete':
            assert args[1].startswith('--raw=/apis/vpc.githedgehog.com/v1beta1/namespaces/default/')
            assert args[2] == '-f' and len(args) == 4
            plural, name = args[1].rsplit('/', 2)[-2:]
            key = (self.KINDS[plural], name)
            options = json.loads(Path(args[3]).read_text())
            assert set(options) == {'apiVersion', 'kind', 'preconditions'}
            assert options['apiVersion'] == 'v1' and options['kind'] == 'DeleteOptions'
            assert set(options['preconditions']) == {'uid'}
            if self.before_delete is not None:
                self.before_delete(key)
            if options['preconditions']['uid'] != self.store[key]['metadata']['uid']:
                raise CoreFailure('UID precondition refused', 1)
            self.deletes.append((key, deepcopy(options)))
            del self.store[key]
            return b'{}'
        raise AssertionError('unexpected kubectl ' + repr(args))


class SharedTrial(unittest.TestCase):
    def nonce_fixture(self, nonce_value='a' * 32):
        # Fresh private root and work directory per fixture: exclusive creates never reuse a path.
        self.fixtures = getattr(self, 'fixtures', 0) + 1
        self.root = self.base / ('nonce-root-%d' % self.fixtures)
        self.root.mkdir(mode=0o700)
        self.stack.enter_context(patch.object(trial, 'ROOT', self.root))
        work = self.base / ('nonce-work-%d' % self.fixtures)
        work.mkdir(mode=0o700)
        api = FakeAdmissionApi()
        core = SimpleNamespace(WORK=work, Failure=CoreFailure, kubectl=api.kubectl)
        clock = Mock()
        clock.remaining.return_value = 20
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        for item in (patch.object(trial.os, 'chown'), patch.object(trial.pwd, 'getpwnam', return_value=user),
                     patch.object(trial.time, 'sleep'), patch.object(trial, 'mark')):
            self.stack.enter_context(item)
        return api, trial.Nonce(core, clock, nonce_value)

    def test_nonce_name_is_admissible_hash_locator_not_the_nonce(self):
        api, nonce = self.nonce_fixture()
        self.assertEqual(nonce.name, 'l' + hashlib.sha256(('a' * 32).encode()).hexdigest()[:10])
        self.assertEqual(len(nonce.name), 11)
        self.assertNotIn('a' * 32, nonce.name)
        with self.assertRaises(AssertionError): api.admit({'kind': 'VPC', 'metadata': {'name': 'labapp-trial-' + 'a' * 32, 'namespace': 'default'}})
        with self.assertRaises(AssertionError): api.admit({'kind': 'VPC', 'metadata': {'name': 'L' + 'a' * 10, 'namespace': 'default'}})
        with self.assertRaises(AssertionError): api.admit({'kind': 'VPC', 'metadata': {'name': nonce.name, 'namespace': 'other'}})

    def test_actual_create_verify_remove_carry_full_nonce_on_both_objects(self):
        api, nonce = self.nonce_fixture()
        nonce.create()
        for kind in ('VPC', 'VPCAttachment'):
            doc = api.store[(kind, nonce.name)]
            self.assertEqual(doc['metadata']['annotations'], {trial.Nonce.ANNOTATION: 'a' * 32})
        self.assertEqual([o['nonce'] for o in nonce.objects], ['a' * 32] * 2)
        self.assertEqual([o['name'] for o in nonce.objects], [nonce.name] * 2)
        self.assertEqual(json.loads((self.root / 'nonce-receipt.json').read_text()), nonce.objects)
        self.assertEqual(api.store[('VPCAttachment', nonce.name)]['spec']['subnet'], nonce.name + '/trial')
        nonce.verify()
        nonce.remove()
        self.assertEqual(api.store, {})
        deletes = [c for c in api.calls if c[0] == 'delete']
        self.assertEqual([c[1].rsplit('/', 2)[-2] for c in deletes], ['vpcattachments', 'vpcs'])
        self.assertTrue(all(c[0] != 'apply' and c[0] != 'replace' for c in api.calls))

    def test_each_create_response_annotation_failure_retains_only_prior_owned_receipts(self):
        for kind in ('VPC', 'VPCAttachment'):
            for replacement in (False, 'b' * 32, 'a' * 31, ''):
                with self.subTest(kind=kind, replacement=replacement):
                    api, nonce = self.nonce_fixture()
                    api.response_annotations[kind] = replacement
                    with self.assertRaisesRegex(trial.Failure, 'not owned'): nonce.create()
                    if kind == 'VPC':
                        self.assertEqual(nonce.objects, [])
                        self.assertFalse((self.root / 'nonce-receipt.json').exists())
                    else:
                        self.assertEqual(len(nonce.objects), 1)
                        receipt = nonce.objects[0]
                        self.assertEqual(receipt, {'resource': 'vpcs.vpc.githedgehog.com',
                            'name': nonce.name, 'nonce': nonce.nonce,
                            'uid': api.store[('VPC', nonce.name)]['metadata']['uid'],
                            'spec': api.store[('VPC', nonce.name)]['spec']})
                        self.assertEqual(json.loads((self.root / 'nonce-receipt.json').read_text()), [receipt])
                    self.assertFalse(any(c[0] == 'delete' for c in api.calls))

    def test_later_reads_fail_on_annotation_uid_or_spec_change_without_deleting(self):
        for mutate in (lambda d: d['metadata']['annotations'].pop(trial.Nonce.ANNOTATION),
                       lambda d: d['metadata']['annotations'].update({trial.Nonce.ANNOTATION: 'b' * 32}),
                       lambda d: d['metadata'].update({'annotations': ['malformed']}),
                       lambda d: d['metadata'].update({'uid': 'replaced'}),
                       lambda d: d['spec'].update({'extra': True})):
            for kind in ('VPC', 'VPCAttachment'):
                for action in ('verify', 'remove'):
                    api, nonce = self.nonce_fixture()
                    nonce.create()
                    mutate(api.store[(kind, nonce.name)])
                    with self.assertRaisesRegex(trial.Failure, 'persistence|ownership'): getattr(nonce, action)()
                    self.assertFalse(any(c[0] == 'delete' for c in api.calls))

    def test_annotation_change_while_awaiting_deletion_fails(self):
        api, nonce = self.nonce_fixture()
        nonce.create()
        real = api.kubectl
        def kubectl(args, end):
            result = real(args, end)
            if args[0] == 'delete':  # object lingers (finalizer) and is then re-annotated
                api.store[('VPCAttachment', nonce.name)] = {
                    'kind': 'VPCAttachment', 'spec': nonce.objects[1]['spec'],
                    'metadata': {'name': nonce.name, 'namespace': 'default', 'uid': nonce.objects[1]['uid'],
                                 'annotations': {trial.Nonce.ANNOTATION: 'c' * 32}}}
            return result
        nonce.core.kubectl = kubectl
        with self.assertRaisesRegex(trial.Failure, 'ownership'): nonce.remove()
        self.assertEqual(sum(c[0] == 'delete' for c in api.calls), 1)  # VPC delete never reached

    def test_vpc_same_uid_mutation_during_attachment_wait_blocks_vpc_delete(self):
        for field in ('annotation', 'spec'):
            with self.subTest(field=field):
                api, nonce = self.nonce_fixture()
                nonce.create()
                real = api.kubectl
                attachment_key, vpc_key = ('VPCAttachment', nonce.name), ('VPC', nonce.name)
                original_vpc = deepcopy(api.store[vpc_key])
                attachment = deepcopy(api.store[attachment_key])
                def kubectl(args, end):
                    result = real(args, end)
                    if args[0] == 'delete' and 'vpcattachments/' in args[1]:
                        api.store[attachment_key] = deepcopy(attachment)  # finalizer wait
                    return result
                def finish_attachment(_seconds):
                    if field == 'annotation':
                        api.store[vpc_key]['metadata']['annotations'][trial.Nonce.ANNOTATION] = 'c' * 32
                    else:
                        api.store[vpc_key]['spec']['extra'] = True
                    del api.store[attachment_key]
                nonce.core.kubectl = kubectl
                with patch.object(trial.time, 'sleep', side_effect=finish_attachment) as sleep:
                    with self.assertRaisesRegex(trial.Failure, 'ownership'): nonce.remove()
                sleep.assert_called_once()
                self.assertEqual(api.store[vpc_key]['metadata']['uid'], original_vpc['metadata']['uid'])
                self.assertEqual([key[0] for key, _ in api.deletes], ['VPCAttachment'])
                self.assertFalse(any(c[0] == 'delete' and '/vpcs/' in c[1] for c in api.calls))

    def test_uid_replacement_after_final_get_is_refused_by_actual_delete_options(self):
        for kind in ('VPC', 'VPCAttachment'):
            with self.subTest(kind=kind):
                api, nonce = self.nonce_fixture()
                nonce.create()
                key = (kind, nonce.name)
                replacement = deepcopy(api.store[key])
                replacement['metadata']['uid'] = 'replacement-uid'
                def replace(target):
                    if target == key:
                        api.store[key] = deepcopy(replacement)
                api.before_delete = replace
                with self.assertRaisesRegex(trial.Failure, 'API operation refused'): nonce.remove()
                self.assertEqual(api.store[key], replacement)
                self.assertEqual([k[0] for k, _ in api.deletes],
                                 ['VPCAttachment'] if kind == 'VPC' else [])

    def test_nonmapping_create_response_annotations_raise_controlled_failure_for_each_object(self):
        for kind in ('VPC', 'VPCAttachment'):
            for malformed in (['malformed'], 'malformed', 1):
                with self.subTest(kind=kind, malformed=malformed):
                    api, nonce = self.nonce_fixture()
                    real = api.kubectl
                    def kubectl(args, end):
                        raw = real(args, end)
                        if args[0] == 'create':
                            response = json.loads(raw)
                            if response['kind'] == kind:
                                response['metadata']['annotations'] = malformed
                                return json.dumps(response).encode()
                        return raw
                    nonce.core.kubectl = kubectl
                    with self.assertRaisesRegex(trial.Failure, 'not owned'): nonce.create()
                    self.assertEqual(len(nonce.objects), 0 if kind == 'VPC' else 1)
                    self.assertEqual(api.deletes, [])

    def test_forced_locator_collision_between_two_nonces_is_refused_without_mutation(self):
        api, first = self.nonce_fixture('a' * 32)
        second = trial.Nonce(first.core, first.clock, 'b' * 32)
        second.name = first.name  # force the 40-bit (ten hex characters) locator collision
        first.create()
        before = deepcopy(api.store)
        calls = len(api.calls)
        with self.assertRaisesRegex(trial.Failure, 'collision'): second.create()
        self.assertEqual(api.store, before)
        self.assertFalse(any(c[0] in ('create', 'delete') for c in api.calls[calls:]))
        # The first nonce's objects must not verify as the second nonce's.
        second.objects = [dict(o) for o in first.objects]
        with self.assertRaisesRegex(trial.Failure, 'ownership'): second.verify()

    def test_preexisting_objects_are_never_adopted_even_with_matching_annotation(self):
        for seeded in (('VPC',), ('VPCAttachment',), ('VPC', 'VPCAttachment')):
            for annotation in ({trial.Nonce.ANNOTATION: 'a' * 32}, {}):
                api, nonce = self.nonce_fixture()
                for kind in seeded: api.seed(kind, nonce.name, dict(annotation))
                before = deepcopy(api.store)
                with self.assertRaisesRegex(trial.Failure, 'collision'): nonce.create()
                self.assertEqual(api.store, before)
                self.assertEqual(nonce.objects, [])
                self.assertFalse(any(c[0] in ('create', 'delete') for c in api.calls))

    def test_long_legacy_name_is_not_used_and_fails_modeled_admission(self):
        api, nonce = self.nonce_fixture()
        nonce.name = 'labapp-trial-' + 'a' * 32  # simulate the old behaviour through the actual method
        with self.assertRaises(AssertionError): nonce.create()
        self.assertEqual(api.store, {})

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
            current = None if action == 'create' else json.loads(owned_json(nonce, 'public', {}))
            with patch.object(nonce, 'current', return_value=current), \
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
        core.kubectl.return_value = owned_json(nonce, 'replaced', {'public': True})
        with self.assertRaisesRegex(trial.Failure, 'ownership'): nonce.remove()
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
                return b'' if deleted else owned_json(nonce, 'public-owned-uid', {'public': True})
            self.assertEqual(args[:2], ['delete', '--raw=/apis/vpc.githedgehog.com/v1beta1/namespaces/default/vpcs/' + nonce.name])
            self.assertLessEqual(len(nonce.name), 11)
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


CANARY_USER = 'canary-user'
CANARY_TOKEN = 'ghp_SYNTHETIC_CANARY_0123456789'
CREDS = {'schema': 1, 'registry': 'ghcr.io', 'username': CANARY_USER, 'token': CANARY_TOKEN}
REAL_AUTH_READ = trial.auth_read_input
REAL_AUTH_DIR = trial.AUTH_DIR
REAL_AUTH_ACCOUNT = trial.auth_account


class TransientRegistryAuth(unittest.TestCase):
    """#378: actual auth functions against synthetic canaries in temporary trees.

    No real credential, /run, /proc, root, Docker or child process is used. The mount table,
    swap table, home and /run roots are temporary stand-ins for the fixed production paths.
    """
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(trial.subprocess, 'Popen', side_effect=AssertionError('no real child')))
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-auth-offline-')))
        self.root, self.run, self.home = self.base / 'root', self.base / 'run', self.base / 'home'
        self.run.mkdir(mode=0o755)
        self.home.mkdir()
        self.dir = self.run / 'labapp-vlab-docker'
        self.mountinfo, self.swaps = self.base / 'mountinfo', self.base / 'swaps'
        self.mounts()
        self.swap()
        self.v = value()
        self.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir='/home/ubuntu', pw_shell='/bin/bash')
        for name, replacement in (('ROOT', self.root), ('AUTH_MOUNT', self.run), ('AUTH_DIR', self.dir),
                                  ('AUTH_HOME', self.home), ('MOUNTINFO', self.mountinfo), ('SWAPS', self.swaps)):
            self.stack.enter_context(patch.object(trial, name, replacement))
        self.stack.enter_context(patch.object(trial, 'auth_account', return_value=self.user))
        # Native fixtures run unprivileged: only root identity constants are mapped
        # to the fixture owner; all modes, names, link counts and inode checks run.
        self.stack.enter_context(patch.object(trial, 'AUTH_OWNER', os.getuid()))
        self.stack.enter_context(patch.object(trial, 'AUTH_ROOT_GID', os.getgid()))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=self.v['boot_uuid']))
        self.stack.enter_context(patch.object(trial, 'guardian_processes', return_value={b'999999'}))
        self.stack.enter_context(patch.object(trial, 'auth_lock_ok', side_effect=lambda info:
            stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600))
        real_chown = os.fchown
        self.stack.enter_context(patch.object(trial.os, 'fchown', side_effect=lambda fd, uid, gid:
            real_chown(fd, os.getuid() if uid == 0 else uid, os.getgid() if gid == 0 else gid)))
        self.stack.enter_context(patch.object(
            trial, 'regular', side_effect=lambda p, n, uid=None, mode=None: REAL_REGULAR(p, n)))

    # -- fixtures -------------------------------------------------------------------
    def mounts(self, fstype='tmpfs', options='rw,nosuid', extra=''):
        self.mountinfo.write_text('1 0 0:1 / / rw - ext4 /dev/root rw\n'
                                  '40 1 0:30 / %s %s - %s tmpfs rw,size=1024k\n%s' % (self.run, options, fstype, extra))

    def swap(self, active=False):
        self.swaps.write_text('Filename\tType\tSize\tUsed\tPriority\n' + ('/swapfile\tfile\t1\t0\t-2\n' if active else ''))

    def arm(self):
        self.root.mkdir(mode=0o700, exist_ok=True)
        if (self.root / trial.AUTH_INTENT).exists():
            return
        trial.exclusive(self.root / trial.AUTH_INTENT, trial.encoded(
            {'schema': 1, 'nonce': self.v['nonce'], 'uid': os.getuid(), 'gid': os.getgid(),
             'until': time.monotonic() + 10, 'cleanup_until': time.monotonic() + 60}))
        trial.exclusive(self.root / trial.AUTH_LOCK, b'')
        trial.exclusive(self.root / 'contract.json', trial.encoded(self.v))
        trial.exclusive(self.root / 'manifest.json', trial.encoded(
            {'schema': 1, 'source_sha': self.v['source_sha'], 'files': {
                'contract.json': {'bytes': len(trial.encoded(self.v)), 'sha256': trial.sha(trial.encoded(self.v))}}}))
        started = {'boot': self.v['boot_uuid'], 'lease': self.v['lease'], 'nonce': self.v['nonce'], 'guardian_pid': 999999}
        for name in ('started.json', trial.AUTH_GUARDIAN):
            trial.exclusive(self.root / name, trial.encoded(started))
        trial.exclusive(self.root / 'heartbeat.json', trial.encoded({'sequence': 0, 'received': time.monotonic()}))

    def install(self):
        self.arm()
        with patch.object(trial, 'manifest', side_effect=lambda value: value):
            trial.auth_install(self.v, trial.auth_credentials(trial.encoded(CREDS)))

    def expected_config(self):
        pair = base64.b64encode((CANARY_USER + ':' + CANARY_TOKEN).encode()).decode()
        return {'auths': {'ghcr.io': {'auth': pair}}}

    def assert_secret_only_in_config(self):
        needles = (CANARY_TOKEN.encode(), base64.b64encode((CANARY_USER + ':' + CANARY_TOKEN).encode()))
        for path in self.base.rglob('*'):
            if path.is_file() and path != self.dir / 'config.json':
                for needle in needles:
                    self.assertNotIn(needle, path.read_bytes(), str(path.relative_to(self.base)))

    # -- closed input -------------------------------------------------------------
    def test_input_record_is_closed_bounded_and_refusals_never_echo_input(self):
        good = trial.encoded(CREDS)
        self.assertEqual(trial.auth_credentials(good), CREDS)
        bad = {
            'missing': {k: v for k, v in CREDS.items() if k != 'token'},
            'extra field': dict(CREDS, url='https://example.invalid'),
            'helper': dict(CREDS, credsStore='desktop'),
            'identity token': dict(CREDS, identitytoken=CANARY_TOKEN),
            'other registry': dict(CREDS, registry='docker.io'),
            'registry url': dict(CREDS, registry='https://ghcr.io'),
            'schema bool': dict(CREDS, schema=True),
            'schema 2': dict(CREDS, schema=2),
            'user path': dict(CREDS, username='../' + CANARY_USER),
            'user newline': dict(CREDS, username=CANARY_USER + '\n'),
            'token short': dict(CREDS, token='short'),
            'token colon': dict(CREDS, token=CANARY_TOKEN + ':x'),
            'token not str': dict(CREDS, token=12345678901234567890123),
            'token huge': dict(CREDS, token=CANARY_TOKEN + 'a' * 2000)}
        for name, record in bad.items():
            with self.subTest(name), self.assertRaises(trial.Failure) as failure:
                trial.auth_credentials(json.dumps(record).encode())
            self.assertEqual(str(failure.exception), 'GHCR credential input refused')
            self.assertNotIn(CANARY_TOKEN, repr(failure.exception))
            self.assertIsNone(failure.exception.__cause__)
        for raw in (b'', b'[]', b'null', good + b'x', good[:-1], b'\xff\xfe', b'{"schema":1,"schema":1}',
                    b'x' * (trial.AUTH_INPUT_LIMIT + 1), CANARY_TOKEN.encode()):
            with self.subTest(raw[:12]), self.assertRaises(trial.Failure) as failure:
                trial.auth_credentials(raw)
            self.assertNotIn(CANARY_TOKEN, str(failure.exception) + repr(failure.exception.__context__))

    def test_stdin_reader_requires_eof_within_bound_and_deadline(self):
        def feed(raw, close=True):
            read, write = os.pipe()
            self.addCleanup(os.close, read)
            os.write(write, raw)
            if close:
                os.close(write)
            else:
                self.addCleanup(os.close, write)
            return read
        self.assertEqual(REAL_AUTH_READ(feed(trial.encoded(CREDS))), CREDS)
        with self.assertRaises(trial.Failure):
            REAL_AUTH_READ(feed(b''))
        with self.assertRaises(trial.Failure):
            REAL_AUTH_READ(feed(b'x' * (trial.AUTH_INPUT_LIMIT + 1)))
        with patch.object(trial.select, 'select', return_value=([], [], [])), self.assertRaises(trial.Failure):
            REAL_AUTH_READ(feed(trial.encoded(CREDS), close=False), until=time.monotonic() + .2)
        with self.assertRaises(trial.Failure):
            REAL_AUTH_READ(feed(b'{"schema":1', close=True))

    def test_docker_config_is_exactly_one_ghcr_basic_auth_entry(self):
        self.assertEqual(json.loads(trial.auth_config(CREDS)), self.expected_config())

    def test_secret_process_hardening_disables_core_and_dumpability_or_refuses(self):
        import resource
        stored = {}
        libc = Mock()
        libc.prctl.return_value = 0
        with patch.object(resource, 'setrlimit', side_effect=lambda which, limits: stored.update({which: limits})), \
             patch.object(resource, 'getrlimit', side_effect=lambda which: stored[which]), \
             patch('ctypes.CDLL', return_value=libc):
            trial.harden_secret_process()
            libc.prctl.assert_called_once_with(4, 0, 0, 0, 0)
            self.assertEqual(stored[resource.RLIMIT_CORE], (0, 0))
            libc.prctl.return_value = -1
            with self.assertRaises(trial.Failure):
                trial.harden_secret_process()

    # -- volatile volume, fallbacks, preexisting paths -----------------------------
    def test_volume_must_be_standard_tmpfs_without_swap_or_with_noswap(self):
        trial.auth_volatile()
        self.mounts(fstype='ext4')
        with self.assertRaises(trial.Failure): trial.auth_volatile()
        self.mounts(extra='41 40 0:31 / %s rw - tmpfs tmpfs rw\n' % self.dir)  # mount at the target
        with self.assertRaises(trial.Failure): trial.auth_volatile()
        self.mounts(extra='42 40 0:32 / %s rw - ext4 /dev/x rw\n' % self.run)  # later overmount of /run
        with self.assertRaises(trial.Failure): trial.auth_volatile()
        self.mounts(options='rw,noswap')
        self.swap(True)
        trial.auth_volatile()
        self.mounts()
        with self.assertRaises(trial.Failure): trial.auth_volatile()  # tmpfs may swap
        self.mounts()
        self.mountinfo.write_text('garbage')
        with self.assertRaises(trial.Failure): trial.auth_volatile()

    def test_fallback_stores_and_preexisting_targets_are_refused_and_never_deleted(self):
        uid = self.user.pw_uid
        paths = [self.home / '.docker' / 'config.json', self.home / '.dockercfg',
                 self.home / '.config' / 'containers' / 'auth.json',
                 self.run / 'containers' / str(uid) / 'auth.json',
                 self.run / 'user' / str(uid) / 'containers' / 'auth.json']
        for path in paths:
            with self.subTest(path.name):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('PUBLIC-PREEXISTING')
                with self.assertRaises(trial.Failure): trial.auth_fallbacks_absent(uid)
                self.arm()
                with self.assertRaises(trial.Failure): trial.auth_install(self.v, CREDS)
                self.assertEqual(path.read_text(), 'PUBLIC-PREEXISTING')
                self.assertFalse(self.dir.exists())
                path.unlink()
        trial.auth_fallbacks_absent(uid)
        (self.home / '.docker' / 'config.json').symlink_to(self.base / 'dangling')  # dangling link counts
        with self.assertRaises(trial.Failure): trial.auth_fallbacks_absent(uid)
        (self.home / '.docker' / 'config.json').unlink()
        for target in ('dir', 'link', 'file'):
            with self.subTest(target):
                if target == 'dir': self.dir.mkdir()
                elif target == 'link': self.dir.symlink_to(self.base / 'elsewhere')
                else: self.dir.write_text('foreign')
                self.arm()
                with self.assertRaises(trial.Failure): trial.auth_install(self.v, CREDS)
                self.assertTrue(os.path.lexists(self.dir))
                with self.assertRaises(trial.Failure) as raised: trial.auth_remove()  # no binding: not provably ours
                self.assertTrue(raised.exception.cleanup_uncertain)
                self.assertTrue(os.path.lexists(self.dir))
                if target == 'dir': self.dir.rmdir()
                else: self.dir.unlink()

    # -- install / verify / remove ------------------------------------------------
    def test_install_creates_root_controlled_ubuntu_readonly_minimal_config(self):
        self.install()
        info, config = self.dir.stat(), self.dir / 'config.json'
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid), (0o750, trial.AUTH_OWNER, self.user.pw_gid))
        file_info = config.stat()
        self.assertEqual((stat.S_IMODE(file_info.st_mode), file_info.st_nlink, file_info.st_uid), (0o640, 1, trial.AUTH_OWNER))
        self.assertEqual(file_info.st_gid, self.user.pw_gid)
        self.assertEqual(stat.S_IMODE(info.st_mode) & 0o027, 0)
        self.assertEqual(stat.S_IMODE(file_info.st_mode) & 0o137, 0)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ['config.json'])
        self.assertEqual(json.loads(config.read_bytes()), self.expected_config())
        for name in (trial.AUTH_INTENT, trial.AUTH_BOUND, trial.AUTH_READY):
            self.assertTrue((self.root / name).exists())
        self.assert_secret_only_in_config()
        trial.auth_verify(self.v)

    def test_account_requires_an_exclusive_ubuntu_primary_group(self):
        user = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir='/home/ubuntu', pw_shell='/bin/bash')
        group = SimpleNamespace(gr_name='ubuntu', gr_mem=[])
        with patch.object(trial.pwd, 'getpwnam', return_value=user), \
             patch.object(trial.grp, 'getgrgid', return_value=group), \
             patch.object(trial.pwd, 'getpwall', return_value=[user]) as accounts:
            self.assertIs(REAL_AUTH_ACCOUNT(), user)
            group.gr_mem = ['other']
            with self.assertRaises(trial.Failure): REAL_AUTH_ACCOUNT()
            group.gr_mem = []
            accounts.return_value = [user, SimpleNamespace(pw_uid=1002, pw_gid=1001)]
            with self.assertRaises(trial.Failure): REAL_AUTH_ACCOUNT()
            accounts.return_value = [user]
            group.gr_name = 'shared'
            with self.assertRaises(trial.Failure): REAL_AUTH_ACCOUNT()

    def test_prewrite_name_or_mode_mutation_is_detected_before_any_secret_write(self):
        real_config = trial.auth_config
        for mutation in ('file-rename', 'directory-rename', 'chmod'):
            with self.subTest(mutation):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.dir, ignore_errors=True)
                moved = self.base / ('moved-' + mutation)
                self.arm()
                def mutate(credentials):
                    self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE((self.dir / trial.AUTH_NAME).stat().st_mode), 0o600)
                    if mutation == 'file-rename':
                        (self.dir / trial.AUTH_NAME).rename(moved)
                    elif mutation == 'directory-rename':
                        self.dir.rename(moved)
                    else:
                        (self.dir / trial.AUTH_NAME).chmod(0o666)
                    return real_config(credentials)
                with patch.object(trial, 'auth_config', side_effect=mutate), \
                     patch.object(trial, 'manifest', side_effect=lambda value: value), \
                     patch.object(trial.os, 'write') as write:
                    with self.assertRaises((trial.Failure, OSError)):
                        trial.auth_install(self.v, CREDS)
                write.assert_not_called()
                self.assertFalse((self.root / trial.AUTH_READY).exists())
                with self.assertRaises(trial.Failure) as raised:
                    trial.auth_remove()
                self.assertTrue(raised.exception.cleanup_uncertain)
                self.assert_secret_only_in_config()  # even the moved object has no canary

    def test_known_file_or_directory_disappearance_is_uncertain_without_unlink_receipts(self):
        for missing in ('file', 'directory'):
            with self.subTest(missing):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.dir, ignore_errors=True)
                self.install()
                moved = self.base / ('lost-' + missing)
                source = self.dir / trial.AUTH_NAME if missing == 'file' else self.dir
                source.rename(moved)
                for _ in range(2):
                    with self.assertRaises(trial.Failure) as raised:
                        trial.auth_remove()
                    self.assertTrue(raised.exception.cleanup_uncertain)
                self.assertFalse((self.root / trial.AUTH_UNLINKED).exists())
                survivor = moved if missing == 'file' else moved / trial.AUTH_NAME
                self.assertEqual(json.loads(survivor.read_bytes()), self.expected_config())
                self.assertFalse((self.root / trial.AUTH_DIR_REMOVED).exists())

    def test_verify_fails_closed_on_every_mutable_identity_or_content_change(self):
        def extra(config): (self.dir / 'extra').write_text('x')
        def link(config): config.unlink(); config.symlink_to(self.base / 'elsewhere')
        def replace(config): config.unlink(); config.write_text('{}')  # new identity, plausible owner/mode
        def hardlink(config): os.link(config, self.base / 'second-name')
        def mode(config): config.chmod(0o660)
        def dirmode(config): self.dir.chmod(0o770)
        def swap(config): self.swap(True)
        def fallback(config): (self.home / '.dockercfg').write_text('x')
        def other_nonce(config): self.v['nonce'] = 'f' * 32
        def removed(config): trial.exclusive(self.root / trial.AUTH_REMOVED, b'{}')
        def swapped_dir(config):
            os.rename(self.dir, self.base / 'old')
            self.dir.mkdir(mode=0o700)
            shutil.copy(self.base / 'old' / 'config.json', self.dir / 'config.json')
        for mutate in (extra, link, replace, hardlink, mode, dirmode, swap, fallback, other_nonce, removed, swapped_dir):
            with self.subTest(mutate.__name__):
                for leftover in (self.root, self.dir, self.base / 'old', self.base / 'second-name', self.home / '.dockercfg'):
                    if leftover.is_dir() and not leftover.is_symlink():
                        shutil.rmtree(leftover)
                    elif os.path.lexists(leftover):
                        leftover.unlink()
                self.swap(False)
                self.v['nonce'] = 'a' * 32
                self.install()
                trial.auth_verify(self.v)
                mutate(self.dir / 'config.json')
                with self.assertRaises((trial.Failure, OSError)):
                    trial.auth_verify(self.v)

    def test_remove_deletes_exact_owned_config_and_directory_and_is_idempotent(self):
        self.install()
        trial.auth_remove()
        trial.auth_absent()
        for name in (trial.AUTH_UNLINKED, trial.AUTH_DIR_REMOVED):
            self.assertTrue((self.root / name).exists())
        trial.auth_remove()  # repeated cleanup is safe
        trial.auth_absent()
        self.assert_secret_only_in_config()

    def test_cleanup_during_input_permanently_closes_late_publisher(self):
        self.arm()
        trial.auth_remove()  # ingress has not published any directory yet
        with patch.object(trial, 'manifest', side_effect=lambda value: value), self.assertRaises(trial.Failure):
            trial.auth_install(self.v, CREDS)
        trial.auth_remove()
        self.assertFalse(os.path.lexists(self.dir))
        self.assertTrue((self.root / trial.AUTH_CLOSED).exists())

    def test_new_fallback_after_removal_blocks_strict_and_resume_and_remains_untouched(self):
        self.install()
        trial.auth_remove()
        foreign = self.home / '.dockercfg'
        foreign.write_text('PUBLIC-FOREIGN')
        with self.assertRaises(trial.Failure):
            trial.auth_absent()
        self.assertEqual(foreign.read_text(), 'PUBLIC-FOREIGN')
        self.assertFalse(os.path.lexists(self.dir))

    def test_interruption_after_create_file_write_or_ready_is_exactly_cleanable(self):
        real_exclusive, real_write, real_chmod = trial.exclusive, os.write, os.fchmod
        for point in ('directory', 'file', 'write', 'file-grant', 'directory-grant', 'ready'):
            with self.subTest(point):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.dir, ignore_errors=True)
                self.arm()
                def receipt(path, raw, mode=0o600):
                    real_exclusive(path, raw, mode)
                    target = {'directory': trial.AUTH_BOUND, 'file': trial.AUTH_FILE, 'ready': trial.AUTH_READY}.get(point)
                    if Path(path).name == target:
                        raise KeyboardInterrupt()
                def write(fd, raw):
                    result = real_write(fd, raw)
                    if point == 'write':
                        raise KeyboardInterrupt()
                    return result
                def chmod(fd, mode):
                    real_chmod(fd, mode)
                    if (point == 'file-grant' and mode == 0o640
                            or point == 'directory-grant' and mode == 0o750):
                        raise KeyboardInterrupt()
                with patch.object(trial, 'exclusive', side_effect=receipt), \
                     patch.object(trial.os, 'write', side_effect=write), \
                     patch.object(trial.os, 'fchmod', side_effect=chmod), \
                     patch.object(trial, 'manifest', side_effect=lambda value: value), self.assertRaises(KeyboardInterrupt):
                    trial.auth_install(self.v, CREDS)
                trial.auth_remove()
                trial.auth_remove()
                self.assertFalse(os.path.lexists(self.dir))
                self.assert_secret_only_in_config()

    def test_unbound_partial_file_is_preserved_as_uncertain(self):
        self.install()
        (self.root / trial.AUTH_FILE).unlink()
        with self.assertRaises(trial.Failure) as raised:
            trial.auth_remove()
        self.assertTrue(raised.exception.cleanup_uncertain)
        self.assertTrue((self.dir / trial.AUTH_NAME).exists())

    def test_closed_state_during_locked_publication_blocks_ready_and_late_retry(self):
        self.arm()
        real_config = trial.auth_config
        def close(credentials):
            trial.exclusive(self.root / trial.AUTH_CLOSED,
                            trial.encoded({'schema': 1, 'nonce': self.v['nonce']}))
            return real_config(credentials)
        with patch.object(trial, 'auth_config', side_effect=close), \
             patch.object(trial, 'manifest', side_effect=lambda value: value), self.assertRaises(trial.Failure):
            trial.auth_install(self.v, CREDS)
        self.assertFalse((self.root / trial.AUTH_READY).exists())
        trial.auth_remove()
        with self.assertRaises(trial.Failure):
            trial.auth_install(self.v, CREDS)
        self.assertFalse(os.path.lexists(self.dir))

    def test_shared_lock_expires_without_waiting_past_original_cutoff(self):
        self.arm()
        ticks = [100.0]
        with patch.object(trial.time, 'monotonic', side_effect=lambda: ticks[0]), \
             patch.object(trial.time, 'sleep', side_effect=lambda seconds: ticks.__setitem__(0, ticks[0] + seconds)), \
             patch.object(trial.fcntl, 'flock', side_effect=BlockingIOError), self.assertRaises(trial.Failure):
            with trial.auth_locked(100.1):
                self.fail('blocked lock acquired')
        self.assertLessEqual(ticks[0], 100.1)

    def test_fresh_publish_binding_refuses_changed_guardian_boot_contract_source_and_cutoff(self):
        for mutation in ('guardian', 'missing-guardian', 'boot', 'contract', 'source', 'cutoff'):
            with self.subTest(mutation):
                shutil.rmtree(self.root, ignore_errors=True)
                self.arm()
                with ExitStack() as local:
                    local.enter_context(patch.object(trial, 'manifest', side_effect=lambda value: value))
                    if mutation == 'guardian':
                        record = json.loads((self.root / 'started.json').read_bytes())
                        record['guardian_pid'] = 888888
                        (self.root / 'started.json').write_bytes(trial.encoded(record))
                    elif mutation == 'missing-guardian':
                        local.enter_context(patch.object(trial, 'guardian_processes', return_value=set()))
                    elif mutation == 'boot':
                        local.enter_context(patch.object(trial, 'kernel_boot', return_value='changed'))
                    elif mutation == 'contract':
                        changed = dict(self.v, epoch=self.v['epoch'] + 1)
                        (self.root / 'contract.json').write_bytes(trial.encoded(changed))
                    elif mutation == 'source':
                        table = json.loads((self.root / 'manifest.json').read_bytes())
                        table['files']['contract.json']['sha256'] = '0' * 64
                        (self.root / 'manifest.json').write_bytes(trial.encoded(table))
                    else:
                        local.enter_context(patch.object(trial.time, 'monotonic', return_value=trial.auth_intent()['until']))
                    with self.assertRaises(trial.Failure):
                        trial.auth_install(self.v, CREDS)
                self.assertFalse(os.path.lexists(self.dir))

    def test_remove_is_noop_when_not_armed_and_never_touches_unarmed_foreign_directory(self):
        self.dir.mkdir()
        (self.dir / 'foreign').write_text('keep')
        trial.auth_remove()
        self.assertEqual((self.dir / 'foreign').read_text(), 'keep')

    def test_remove_refuses_foreign_entries_links_replacement_and_identity_change(self):
        for name in ('extra', 'symlink', 'regular-replacement', 'hardlink', 'replaced-dir', 'wrong-mode', 'missing-binding'):
            with self.subTest(name):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.dir, ignore_errors=True)
                self.install()
                config = self.dir / 'config.json'
                foreign = self.base / 'foreign-target'
                foreign.write_text('PUBLIC-FOREIGN')
                survivors = [foreign]
                if name == 'extra':
                    (self.dir / 'extra').write_text('x')
                    survivors.append(self.dir / 'extra')
                elif name == 'symlink':
                    config.unlink()
                    config.symlink_to(foreign)
                    survivors.append(config)
                elif name == 'hardlink':
                    os.link(config, self.base / 'alias')
                    survivors.append(self.base / 'alias')
                elif name == 'regular-replacement':
                    config.rename(self.base / 'old-config')  # keep old inode allocated
                    config.write_text('PUBLIC-FOREIGN-CONFIG')
                    config.chmod(0o640)
                    survivors.append(config)
                elif name == 'replaced-dir':
                    os.rename(self.dir, self.base / 'old-dir')
                    self.dir.mkdir(mode=0o700)
                    (self.dir / 'config.json').write_text('PUBLIC-FOREIGN-CONFIG')
                    survivors.append(self.dir / 'config.json')
                elif name == 'wrong-mode':
                    config.chmod(0o644)
                    survivors.append(config)
                else:
                    (self.root / trial.AUTH_BOUND).unlink()
                    survivors.append(config)
                with self.assertRaises(trial.Failure) as raised:
                    trial.auth_remove()
                self.assertTrue(raised.exception.cleanup_uncertain)
                self.assertEqual(str(raised.exception), 'credential cleanup uncertain')
                self.assertTrue(all(os.path.lexists(path) for path in survivors), name)
                self.assertEqual(foreign.read_text(), 'PUBLIC-FOREIGN')

    # -- containment / ExecStopPost / guardian ------------------------------------
    def test_actual_containment_and_execstoppost_remove_after_service_stop_and_stay_repeatable(self):
        self.install()
        calls = []
        def bounded(args, seconds, **kwargs):
            calls.append(args)
            return 0, b'ActiveState=inactive\nSubState=dead\n'
        (self.root / 'daemon-intent.json').write_text('{}')
        with patch.object(hhfab_release, 'bounded', side_effect=bounded), \
             patch.object(trial.Path, 'exists', lambda p: str(p).endswith('daemon-intent.json')), \
             patch.object(trial.os, 'geteuid', return_value=0):
            # The core path is absent here; the daemon stop and auth removal are real.
            trial.containment()
            self.assertFalse(os.path.lexists(self.dir))
            self.assertEqual(trial.main(['contain']), 0)  # ExecStopPost repeat
        self.assertTrue(any('docker.socket' in str(c) for c in calls))

    def test_containment_cleanup_uncertainty_withholds_containment(self):
        self.install()
        (self.dir / 'extra').write_text('foreign')
        with patch.object(hhfab_release, 'bounded', return_value=(0, b'')):
            with self.assertRaises(trial.Failure):
                trial.containment()
        self.assertTrue((self.dir / 'extra').exists())
        self.assertFalse((self.dir / 'config.json').exists())  # exact owned file is still removed

    def test_containment_removes_credentials_even_when_service_stop_fails(self):
        self.install()
        (self.root / 'daemon-intent.json').write_text('{}')
        with patch.object(hhfab_release, 'bounded', return_value=(1, b'')), \
             patch.object(trial.Path, 'exists', lambda p: str(p).endswith('daemon-intent.json')):
            with self.assertRaises(trial.Failure): trial.containment()
        self.assertFalse(os.path.lexists(self.dir))

    def guardian_run(self, poll=17, gate=None):
        self.root.mkdir(mode=0o700, exist_ok=True)
        (self.root / 'contract.json').write_bytes(trial.encoded(self.v))
        trial.exclusive(self.root / 'phase.json', b'{"phase":"stage"}')
        (self.root / 'heartbeat.json').write_bytes(trial.encoded({'sequence': 0, 'received': time.monotonic()}))
        (self.root / 'started.json').unlink(missing_ok=True)
        child = Mock(pid=999999)
        child.poll.return_value = poll
        with patch.object(trial, 'kernel_boot', return_value=self.v['boot_uuid']), \
             patch.object(trial, 'guardian_processes', return_value={str(os.getpid()).encode()}), \
             patch.object(trial, 'oom_count', return_value=0), patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial.os, 'killpg'), patch.object(trial.subprocess, 'Popen', return_value=child) as spawn, \
             patch.object(trial, 'resources', return_value={'free_bytes': 300 * trial.GIB, 'available_memory': 100 * trial.GIB}), \
             patch.object(trial, 'containment') as contain:
            if gate:
                gate()
            code = trial.main(['guardian'])
        return code, spawn, contain, json.loads((self.root / 'result.json').read_text())

    def test_guardian_never_spawns_worker_before_auth_ready_and_expiry_contains(self):
        self.arm()  # armed, but bootstrap never published readiness (lost channel/invalid input)
        now = time.monotonic()
        ticks = [now]
        with patch.object(trial.time, 'monotonic', side_effect=lambda: ticks[0]), \
             patch.object(trial.time, 'sleep', side_effect=lambda seconds: ticks.__setitem__(0, ticks[0] + 11)):
            code, spawn, contain, result = self.guardian_run()
        spawn.assert_not_called()
        contain.assert_called_once_with()
        self.assertEqual(code, 124)
        self.assertEqual((result['code'], result['diagnostic']['category'], result['diagnostic']['operation']),
                         (124, 'phase-cutoff', 'guardian-init'))

    def test_guardian_gate_releases_worker_only_after_verified_ready_and_races_fail_closed(self):
        self.install()
        code, spawn, contain, result = self.guardian_run()
        self.assertEqual(code, 17)
        spawn.assert_called_once()
        self.assertTrue(os.path.lexists(self.dir))  # guardian never removes on its own happy path before containment

    def test_guardian_gate_waits_for_late_ready_within_bound(self):
        self.arm()
        def late():
            def publish(seconds):  # readiness appears while the guardian is blocked at its gate
                if not (self.root / trial.AUTH_READY).exists():
                    current = (self.root / 'started.json').read_bytes()
                    (self.root / trial.AUTH_GUARDIAN).write_bytes(current)
                    with patch.object(trial, 'manifest', side_effect=lambda value: value):
                        trial.auth_install(self.v, CREDS)
            self.stack.enter_context(patch.object(trial.time, 'sleep', side_effect=publish))
        code, spawn, _, _ = self.guardian_run(gate=late)
        self.assertEqual(code, 17)
        spawn.assert_called_once()

    def test_guardian_gate_refuses_credentials_already_marked_removed(self):
        self.install()
        trial.exclusive(self.root / trial.AUTH_REMOVED, b'{}')  # credentials already marked removed
        code, spawn, contain, _ = self.guardian_run()
        spawn.assert_not_called()
        self.assertNotEqual(code, 0)

    def test_guardian_rechecks_boot_and_heartbeat_after_ready_before_spawn(self):
        real_gate = trial.auth_gate
        for change in ('boot', 'heartbeat'):
            with self.subTest(change):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.dir, ignore_errors=True)
                self.install()
                with ExitStack() as local:
                    def after_ready(value, clock):
                        real_gate(value, clock)
                        if change == 'boot':
                            local.enter_context(patch.object(trial, 'kernel_boot', return_value='changed'))
                        else:
                            (self.root / 'heartbeat.json').write_bytes(trial.encoded(
                                {'sequence': 0, 'received': time.monotonic() - 31}))
                    with patch.object(trial, 'auth_gate', side_effect=after_ready):
                        code, spawn, contain, result = self.guardian_run()
                spawn.assert_not_called()
                contain.assert_called_once_with()
                self.assertNotEqual(code, 0)
                self.assertEqual(result['diagnostic']['category'], 'boot-change' if change == 'boot' else 'heartbeat-loss')

    # -- bootstrap ordering --------------------------------------------------------
    def bootstrap_fixture(self, secret, started_pid=999999, mounts_ok=True):
        v = self.v
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
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        os.write(write, secret)
        os.close(write)
        events = []
        def run(args, clock, phase, cap=30, **kwargs):
            events.append(args[1])
            if args[1] == 'start':
                # Armed before the guardian can run; no credential and no readiness exists yet.
                self.assertTrue((self.root / trial.AUTH_INTENT).exists())
                self.assertFalse(os.path.lexists(self.dir))
                self.assertFalse((self.root / trial.AUTH_READY).exists())
                trial.exclusive(self.root / 'started.json', trial.encoded({'boot': v['boot_uuid'],
                          'lease': v['lease'], 'nonce': v['nonce'], 'guardian_pid': 999999}))
            if args[1] == 'show':
                return ('MainPID=%d\nActiveState=active\n' % started_pid).encode()
            return b''
        def read_secret(*, until):
            events.append('read-secret')
            self.assertFalse(os.path.lexists(self.dir))
            self.assertEqual(until, trial.auth_intent()['until'])
            return REAL_AUTH_READ(read, until=until)
        original_match = trial.re.fullmatch
        def match(pattern, text, *args):
            return True if pattern == '/tmp/labapp-vlab-[a-f0-9]{32}' else original_match(pattern, text, *args)
        patches = (patch.object(trial.os, 'geteuid', return_value=0),
                   patch.object(trial, 'UNIT_PATH', unit_base / trial.UNIT), patch.object(trial, 'UNIT_BASES', (unit_base, runtime_base)),
                   patch.object(trial, 'RUNTIME_DROPIN', runtime_base / (trial.UNIT + '.d')),
                   patch.object(trial, 'FILES', names), patch.object(trial, 'PAYLOADS', {}),
                   patch.object(trial.re, 'fullmatch', side_effect=match),
                   patch.object(trial, 'kernel_boot', return_value=v['boot_uuid']),
                   patch.object(trial, 'run', side_effect=run), patch.object(trial.sys, 'path', list(trial.sys.path)),
                   patch.object(trial, 'harden_secret_process'), patch.object(trial, 'auth_read_input', side_effect=read_secret))
        return incoming, table, events, patches

    def bootstrap(self, secret, **kwargs):
        incoming, table, events, patches = self.bootstrap_fixture(secret, **kwargs)
        with ExitStack() as local:
            for item in patches:
                local.enter_context(item)
            outcome = None
            try:
                trial.bootstrap(incoming, trial.sha(trial.encoded(table)), ('ghcr-auth',))
            except trial.Failure as error:
                outcome = error
        return events, outcome

    def test_bootstrap_arms_guardian_then_accepts_secret_then_publishes_ready(self):
        events, outcome = self.bootstrap(trial.encoded(CREDS))
        self.assertIsNone(outcome)
        self.assertEqual(events, ['daemon-reload', 'start', 'show', 'read-secret'])
        trial.auth_verify(self.v)
        self.assertEqual(json.loads((self.dir / 'config.json').read_bytes()), self.expected_config())
        self.assert_secret_only_in_config()
        self.assertEqual(json.loads((self.root / trial.AUTH_INTENT).read_bytes())['nonce'], self.v['nonce'])

    def test_bootstrap_input_failures_refuse_stop_unit_and_leave_no_credential(self):
        for name, secret in (('malformed', b'{"schema":1'), ('extra', trial.encoded(dict(CREDS, url='x'))),
                             ('oversize', b'x' * 2000), ('foreign registry', trial.encoded(dict(CREDS, registry='docker.io'))),
                             ('empty', b'')):
            with self.subTest(name):
                shutil.rmtree(self.root, ignore_errors=True)
                shutil.rmtree(self.base / ('labapp-vlab-' + self.v['nonce']), ignore_errors=True)
                shutil.rmtree(self.base / 'units', ignore_errors=True)
                shutil.rmtree(self.base / 'runtime', ignore_errors=True)
                events, outcome = self.bootstrap(secret)
                self.assertIsInstance(outcome, trial.Failure)
                self.assertEqual(str(outcome), 'GHCR credential input refused')
                self.assertEqual(events[:4], ['daemon-reload', 'start', 'show', 'read-secret'])
                self.assertEqual(events[-1], 'stop')
                self.assertFalse(os.path.lexists(self.dir))
                self.assertFalse((self.root / trial.AUTH_READY).exists())

    def test_bootstrap_never_reads_secret_when_guardian_binding_is_not_proven(self):
        events, outcome = self.bootstrap(trial.encoded(CREDS), started_pid=123456)
        self.assertIsInstance(outcome, trial.Failure)
        self.assertNotIn('read-secret', events)
        self.assertFalse(os.path.lexists(self.dir))

    def test_bootstrap_channel_interruption_closes_publication_preserving_primary(self):
        incoming, table, events, patches = self.bootstrap_fixture(trial.encoded(CREDS))
        with ExitStack() as local:
            for item in patches:
                local.enter_context(item)
            local.enter_context(patch.object(trial, 'auth_read_input', side_effect=KeyboardInterrupt))
            with self.assertRaises(KeyboardInterrupt):
                trial.bootstrap(incoming, trial.sha(trial.encoded(table)), ('ghcr-auth',))
        self.assertEqual(events[-1], 'stop')
        self.assertTrue((self.root / trial.AUTH_CLOSED).exists())
        with self.assertRaises(trial.Failure):
            trial.auth_install(self.v, CREDS)
        self.assertFalse(os.path.lexists(self.dir))

    def test_bootstrap_refuses_before_any_state_for_wrong_volume_swap_or_fallback(self):
        for name, setup in (('ext4', lambda: self.mounts(fstype='ext4')), ('swap', lambda: self.swap(True)),
                            ('fallback', lambda: (self.home / '.dockercfg').write_text('x')),
                            ('preexisting', lambda: self.dir.mkdir())):
            with self.subTest(name):
                shutil.rmtree(self.base / ('labapp-vlab-' + self.v['nonce']), ignore_errors=True)
                shutil.rmtree(self.base / 'units', ignore_errors=True)
                shutil.rmtree(self.base / 'runtime', ignore_errors=True)
                setup()
                events, outcome = self.bootstrap(trial.encoded(CREDS))
                self.assertIsInstance(outcome, trial.Failure)
                self.assertEqual(events, [])
                self.assertFalse(self.root.exists())
                self.mounts()
                self.swap(False)
                for leftover in (self.home / '.dockercfg',):
                    if leftover.exists(): leftover.unlink()
                if self.dir.exists(): self.dir.rmdir()

    def test_bootstrap_rejects_unknown_options_and_default_path_never_touches_credentials(self):
        with patch.object(trial.os, 'geteuid', return_value=0):
            for options in (('other',), ('ghcr-auth', 'x'), ('--ghcr-credentials',)):
                with self.subTest(options), self.assertRaises(trial.Failure):
                    trial.bootstrap(self.base / 'unused', 'a' * 64, options)
        self.assertFalse(trial.auth_armed())
        self.assertFalse(self.root.exists())

    def test_default_bootstrap_refuses_preexisting_auth_directory_before_state_or_read(self):
        incoming, table, events, patches = self.bootstrap_fixture(b'')
        self.dir.mkdir(mode=0o700)
        (self.dir / 'foreign').write_text('PUBLIC-FOREIGN')
        with ExitStack() as local:
            for item in patches:
                local.enter_context(item)
            with self.assertRaises(trial.Failure):
                trial.bootstrap(incoming, trial.sha(trial.encoded(table)))
        self.assertEqual(events, [])
        self.assertFalse(self.root.exists())
        self.assertEqual((self.dir / 'foreign').read_text(), 'PUBLIC-FOREIGN')

    # -- worker ordering -----------------------------------------------------------
    def worker_run(self, fault=None):
        self.install()
        v = self.v
        for name, raw in {'contract.json': trial.encoded(v), 'fab.yaml': b'PUBLIC_FAB', 'manifest.json': b'PUBLIC_MANIFEST',
                          'started.json': trial.encoded({'lease': v['lease'], 'nonce': v['nonce'], 'boot': v['boot_uuid'],
                                                        'guardian_pid': os.getppid()})}.items():
            (self.root / name).write_bytes(raw)
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=1000, pw_dir='/home/ubuntu', pw_shell='/bin/bash')
        core = SimpleNamespace(WIRING_SHA='b' * 64, validate_fab=Mock())
        receipt = {'schema': 1, 'source_sha256': 'a' * 64, 'packages': {}, 'commands': {}}
        events = []
        def command(args, clock, phase, cap=30, **kwargs):
            if len(args) > 1 and args[0] == trial.PYTHON and args[1].endswith('vlab_core.py'):
                action = args[2]
                events.append(action)
                if action in ('prepare', 'start-fresh'):
                    self.assertTrue((self.dir / 'config.json').exists(), action)
                    if action == 'start-fresh' and fault == 'extra':
                        (self.dir / 'extra').write_text('foreign')
                else:
                    self.assertFalse(os.path.lexists(self.dir), 'credentials visible to ' + action)
            return b''
        def strict(*args, **kwargs):
            events.append('strict')
            self.assertFalse(os.path.lexists(self.dir), 'credentials visible to strict checks')
            return {'ca_sha256': 'c' * 64, 'cluster_uid': 'public'}
        def packages(clock, selected):
            trial.exclusive(self.root / 'packages.json', trial.encoded(receipt))
            return receipt
        nonce = Mock()
        nonce.objects = []
        with patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial, 'own_cgroup', return_value='0::/system.slice/' + trial.UNIT), \
             patch.object(trial.pwd, 'getpwnam', return_value=user), patch.object(trial.grp, 'getgrnam', side_effect=KeyError), \
             patch.object(hhfab_release, 'bounded', return_value=(1, b'LoadState=not-found\n')), \
             patch.object(trial, 'run', side_effect=command), patch.object(trial, 'provision_aux'), \
             patch.object(trial, 'docker_account'), patch.object(trial, 'guest_devices'), \
             patch.object(trial, 'load_sibling', return_value=core), patch.object(trial, 'package_receipt', side_effect=packages), \
             patch.object(trial, 'resources'), patch.object(trial, 'offline_observations'), \
             patch.object(trial, 'strict_checks', side_effect=strict), patch.object(trial, 'Nonce', return_value=nonce):
            try:
                code = trial.main(['worker'])
                error = None
            except trial.Failure as caught:
                code, error = None, caught
        return code, error, events

    def test_worker_removes_and_verifies_credentials_before_strict_stop_resume_and_success(self):
        code, error, events = self.worker_run()
        self.assertEqual((code, error), (0, None))
        self.assertEqual(events[:3], ['prepare', 'start-fresh', 'strict'])
        self.assertEqual(events[3:], ['stop', 'activate-resume', 'start-resume', 'strict', 'stop'])
        self.assertTrue((self.root / trial.AUTH_REMOVED).exists())
        self.assertFalse(os.path.lexists(self.dir))
        self.assertTrue((self.root / 'success.json').exists())
        self.assert_secret_only_in_config()

    def test_worker_removal_uncertainty_is_the_primary_failure_before_strict_or_resume(self):
        code, error, events = self.worker_run(fault='extra')
        self.assertIsNone(code)
        self.assertEqual(str(error), 'credential cleanup uncertain')
        self.assertEqual(events, ['prepare', 'start-fresh'])
        status = json.loads((self.root / 'worker-status.json').read_text())
        self.assertEqual((status['state'], status['phase'], status['operation']), ('failed', 'fresh', 'auth-remove'))
        self.assertTrue((self.dir / 'extra').exists())  # foreign entry never deleted
        self.assertFalse((self.root / trial.AUTH_REMOVED).exists())

    def test_worker_refuses_provisioning_without_verified_credential_when_armed(self):
        self.arm()
        v = self.v
        for name, raw in {'contract.json': trial.encoded(v), 'fab.yaml': b'x', 'manifest.json': b'x',
                          'started.json': trial.encoded({'lease': v['lease'], 'nonce': v['nonce'], 'boot': v['boot_uuid'],
                                                        'guardian_pid': os.getppid()})}.items():
            (self.root / name).write_bytes(raw)
        with patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial, 'own_cgroup', return_value='0::/system.slice/' + trial.UNIT), \
             patch.object(trial, 'run') as run, patch.object(trial, 'provision_aux') as aux:
            with self.assertRaises((trial.Failure, OSError)):
                trial.main(['worker'])
        run.assert_not_called()
        aux.assert_not_called()

    def test_core_location_unit_limit_and_operation_vocabulary_agree(self):
        import vlab_core as core
        self.assertEqual(core.DOCKER_CONFIG, str(REAL_AUTH_DIR))
        self.assertEqual(core.SAFE_ENV['DOCKER_CONFIG'], str(REAL_AUTH_DIR))
        self.assertEqual(REAL_AUTH_DIR.parent, Path('/run'))
        unit = (Path(trial.__file__).parent / 'labapp-vlab-fresh.service').read_text()
        self.assertIn('\nLimitCORE=0\n', unit)
        self.assertIn('auth-check', trial.OPERATIONS['stage'])
        self.assertIn('auth-remove', trial.OPERATIONS['fresh'])


class FirstFailureExport(unittest.TestCase):
    """#368: real core writer -> fixed guest export -> strict bundle validator (offline fakes only)."""
    def setUp(self):
        import vlab_core as core
        self.core = core
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-export-')))
        self.root, self.state_root = self.base / 'trial', self.base / 'core'
        for path in (self.root, self.state_root):
            path.mkdir(mode=0o700)
        v = value()
        (self.root / 'contract.json').write_bytes(trial.encoded(v))
        reader = trial.regular
        # Production requires euid 0 (main refuses otherwise); fixtures own files as the test user.
        self.stack.enter_context(patch.object(trial, 'regular', side_effect=(
            lambda p, n, uid=None, mode=None: reader(p, n, None if uid == 0 else uid, mode))))
        for target, name, replacement in ((trial, 'ROOT', self.root), (core, 'ROOT', self.state_root),
                                          (core, 'ROOT_UID', os.getuid())):
            self.stack.enter_context(patch.object(target, name, replacement))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=v['boot_uuid']))
        self.stack.enter_context(patch.object(core, 'boot', return_value=v['boot_uuid']))
        self.stack.enter_context(patch.object(core, 'ubuntu', return_value=SimpleNamespace(pw_uid=os.getuid())))
        self.stack.enter_context(patch.object(trial, 'load_sibling', return_value=core))
        self.queries = []
        self.stack.enter_context(patch.object(core, 'diagnostic_run', side_effect=self.query))
        self.v = v
        self.operation, self.invocation = 'e' * 32, 'f' * 32
        self.value = {'schema': 1, 'nonce': NONCE, 'mode': 'fresh', 'operation': self.operation,
                      'phase': 'starting', 'invocation': self.invocation}
        core.atomic(self.state_root / 'state.json', self.value)

    def query(self, argv, end, keep):
        self.queries.append(list(argv))
        if argv[0] == self.core.SYSTEMCTL:
            return 'ok', ('InvocationID=' + self.invocation + '\n').encode(), False, 'confirmed'
        return 'ok', b'journal ' + SENTINEL.encode(), False, 'confirmed'

    def capture(self, value=True, error=None):
        error = error or self.core.Failure('child command failed', 1, b'primary ' + SENTINEL.encode())
        self.core.capture_first_failure('fresh', self.value if value else None, error, time.monotonic() + 60)

    def export(self):
        return trial.export_failure(NONCE)

    def test_real_writer_roundtrip_validates_and_binds_independent_envelope(self):
        self.capture()
        raw = self.export()
        first, _, rest = raw.partition(b'\n')
        envelope = json.loads(first)
        self.assertEqual(envelope, {'schema': 1, 'source_sha': 'c' * 40, 'nonce': NONCE, 'mode': 'fresh',
                                    'operation': self.operation, 'invocation': self.invocation,
                                    'boot': self.v['boot_uuid']})
        bundle = trial.first_failure_bundle(rest)
        self.assertEqual((bundle['stage'], bundle['operation'], bundle['invocation']),
                         ('unit', self.operation, self.invocation))
        self.assertLessEqual(len(rest), trial.FAILURE_LIMIT)
        # Bundle schema 2; the envelope/state/public schemas above are unchanged (1).
        self.assertEqual((bundle['schema'], bundle['unit_ready']),
                         (2, {'status': 'unavailable', 'message': None, 'code': None}))

    def test_real_unit_ready_record_roundtrips_through_capture_export_and_validator(self):
        core = self.core
        started = time.monotonic()
        value = dict(self.value, boot=self.v['boot_uuid'], started=started,
                     deadline=started + core.START_SECONDS['fresh'])
        core.atomic(self.state_root / 'state.json', value)

        def publish(message, code):
            record = {'schema': 1, 'source': 'vlab_core', 'action': 'unit-ready', 'nonce': NONCE,
                      'mode': 'fresh', 'operation': self.operation, 'invocation': self.invocation,
                      'boot': value['boot'], 'started': started, 'deadline': value['deadline'],
                      'message': message, 'code': code}
            core.write_first_failure(trial.encoded(record), core.UNIT_READY_FAILURE)

        publish('synthetic readiness refusal', 17)
        core.capture_first_failure('fresh', value, core.Failure('child command failed', 1, b'x'),
                                   time.monotonic() + 60)
        bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
        self.assertEqual(bundle['unit_ready'], {'status': 'ok', 'message': 'synthetic readiness refusal', 'code': 17})
        self.assertLessEqual(len((self.state_root / self.core.FIRST_FAILURE).read_bytes()), trial.FAILURE_LIMIT)

    def test_absent_and_every_binding_mismatch_is_refused_not_trusted(self):
        self.assertEqual(self.export(), b'absent')
        self.capture()
        for name, change in (('nonce', lambda s: dict(s, nonce='9' * 32)),
                             ('operation', lambda s: dict(s, operation='9' * 32)),
                             ('invocation', lambda s: dict(s, invocation='9' * 32)),
                             ('mode', lambda s: dict(s, mode='resume'))):
            with self.subTest(name):
                self.core.atomic(self.state_root / 'state.json', change(self.value))
                with self.assertRaises(trial.Failure):
                    self.export()
        self.core.atomic(self.state_root / 'state.json', self.value)
        with patch.object(trial, 'kernel_boot', return_value='33333333-3333-4333-8333-333333333333'), \
             self.assertRaises(trial.Failure):
            self.export()  # boot differs from the contract: a different/rebooted guest
        with self.assertRaises(trial.Failure):
            trial.export_failure('9' * 32)

    def test_missing_core_root_is_absent_only_after_contract_nonce_and_live_boot_checks(self):
        (self.state_root / 'state.json').unlink()
        self.state_root.rmdir()
        self.assertEqual(self.export(), b'absent')
        with self.assertRaises(trial.Failure):
            trial.export_failure('9' * 32)
        with patch.object(trial, 'kernel_boot', return_value='33333333-3333-4333-8333-333333333333'), \
             self.assertRaises(trial.Failure):
            self.export()
        (self.root / 'contract.json').write_bytes(b'{}')
        with self.assertRaises(trial.Failure):
            self.export()

    def test_unsafe_core_root_is_refused_even_when_bundle_is_absent(self):
        (self.state_root / 'state.json').unlink()
        self.state_root.rmdir()
        for target in (self.base / 'missing-target', self.root):
            with self.subTest(link=target.name):
                self.state_root.symlink_to(target)
                with self.assertRaises(trial.Failure):
                    self.export()
                self.state_root.unlink()
        self.state_root.write_bytes(b'PUBLIC-FIXTURE')
        with self.assertRaises(trial.Failure):
            self.export()
        self.state_root.unlink()
        self.state_root.mkdir(mode=0o700)
        for mode in (0o750, 0o777):
            self.state_root.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(trial.Failure):
                self.export()
        self.state_root.chmod(0o700)
        with patch.object(trial.os, 'geteuid', return_value=os.getuid() + 1), self.assertRaises(trial.Failure):
            self.export()

    def test_reservation_bundle_has_null_binding_and_runs_no_query(self):
        prepared = {'schema': 1, 'nonce': NONCE, 'phase': 'prepared'}
        self.core.atomic(self.state_root / 'state.json', prepared)
        self.capture(value=False, error=self.core.Failure('startup phase refused'))
        bundle = trial.first_failure_bundle((self.state_root / self.core.FIRST_FAILURE).read_bytes())
        self.assertEqual((bundle['stage'], bundle['operation'], bundle['invocation']), ('reserve', None, None))
        self.assertEqual(self.queries, [])
        self.assertIn(b'"operation":null', self.export().partition(b'\n')[0])
        for changes in ({'operation': self.operation}, {'invocation': self.invocation},
                        {'mode': 'fresh'}, {'phase': 'failed'}, {'operation': None}):
            with self.subTest(changes=changes):
                self.core.atomic(self.state_root / 'state.json', dict(prepared, **changes))
                with self.assertRaises(trial.Failure):
                    self.export()

    def test_unsafe_file_identity_is_refused(self):
        self.capture()
        path = self.state_root / self.core.FIRST_FAILURE
        raw = path.read_bytes()
        path.chmod(0o640)
        with self.assertRaises(trial.Failure):
            self.export()
        path.chmod(0o600)
        os.link(path, self.base / 'second')
        with self.assertRaises(trial.Failure):
            self.export()
        (self.base / 'second').unlink()
        path.unlink()
        target = self.base / 'foreign'
        target.write_bytes(raw)
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(trial.Failure):
            self.export()
        path.unlink()
        path.write_bytes(raw + b' ' * trial.FAILURE_LIMIT)
        path.chmod(0o600)
        with self.assertRaises(trial.Failure):
            self.export()

    def test_strict_validator_refuses_malformed_hostile_or_oversize_bundles(self):
        self.capture()
        good = json.loads((self.state_root / self.core.FIRST_FAILURE).read_bytes())
        import base64
        cases = {
            'extra key': dict(good, extra=1), 'missing key': {k: v for k, v in good.items() if k != 'journal'},
            'bool schema': dict(good, schema=True), 'wrong source': dict(good, source='other'),
            'bad stage': dict(good, stage='main-process'), 'bad nonce': dict(good, nonce='X' * 32),
            'reserve with operation': dict(good, stage='reserve'),
            'invocation without operation': dict(good, operation=None, stage='reserve'),
            'bad status': dict(good, journal=dict(good['journal'], status='captured')),
            'raw text not base64': dict(good, journal=dict(good['journal'], output='not base64!')),
            'oversize section': dict(good, journal=dict(good['journal'],
                                     output=base64.b64encode(b'x' * 8193).decode())),
            'output with unavailable': dict(good, manager=dict(good['manager'], status='unavailable')),
            'journal without invocation': dict(good, invocation=None),
            'stale manager without invocation': dict(good, invocation=None, stage='manager',
                                                     journal={'status': 'unavailable', 'output': ''}),
            'control char message': dict(good, primary=dict(good['primary'], message='bad\nline')),
            'code out of range': dict(good, primary=dict(good['primary'], code=256)),
            'context label': dict(good, command_context=dict(good['command_context'], label='first inner failure')),
            'context cap': dict(good, command_context=dict(good['command_context'], status='ok',
                               output=base64.b64encode(b'x' * 2049).decode())),
            'extra state field': dict(good, state=dict(good['state'], text=SENTINEL)),
            'legacy schema 1': dict(good, schema=1), 'future schema 3': dict(good, schema=3),
            'missing unit_ready': {k: v for k, v in good.items() if k != 'unit_ready'},
            'null unit_ready': dict(good, unit_ready=None),
            'unit_ready extra key': dict(good, unit_ready=dict(good['unit_ready'], extra=1)),
            'unit_ready missing key': dict(good, unit_ready={'status': 'unavailable', 'message': None}),
            'unit_ready bad status': dict(good, unit_ready={'status': 'captured', 'message': None, 'code': None}),
            'ok null message': dict(good, unit_ready={'status': 'ok', 'message': None, 'code': 1}),
            'ok null code': dict(good, unit_ready={'status': 'ok', 'message': 'x', 'code': None}),
            'ok bool code': dict(good, unit_ready={'status': 'ok', 'message': 'x', 'code': True}),
            'ok float code': dict(good, unit_ready={'status': 'ok', 'message': 'x', 'code': 1.0}),
            'ok negative code': dict(good, unit_ready={'status': 'ok', 'message': 'x', 'code': -1}),
            'ok long message': dict(good, unit_ready={'status': 'ok', 'message': 'x' * 129, 'code': 1}),
            'ok empty message': dict(good, unit_ready={'status': 'ok', 'message': '', 'code': 1}),
            'ok non-ascii message': dict(good, unit_ready={'status': 'ok', 'message': 'café', 'code': 1}),
            'unavailable with message': dict(good, unit_ready={'status': 'unavailable', 'message': 'x', 'code': None}),
            'invalid with code': dict(good, unit_ready={'status': 'invalid', 'message': None, 'code': 0}),
            'ok on reservation': dict(good, operation=None, invocation=None, stage='reserve',
                                      manager={'status': 'unavailable', 'output': ''},
                                      journal={'status': 'unavailable', 'output': ''},
                                      command_context=dict(good['command_context'], status='unavailable', output=''),
                                      unit_ready={'status': 'ok', 'message': 'x', 'code': 1}),
        }
        for name, bad in cases.items():
            with self.subTest(name), self.assertRaises(trial.Failure):
                trial.first_failure_bundle(trial.encoded(bad))
        for raw in (b'', b'[]', b'{"a":1,"a":2}', b'x' * (trial.FAILURE_LIMIT + 1), b'invalid'):
            with self.subTest(raw[:8]), self.assertRaises(trial.Failure):
                trial.first_failure_bundle(raw)

    def test_main_maps_any_export_failure_to_one_fixed_token_without_text(self):
        out = Mock()
        with patch.object(trial.sys, 'stdout', SimpleNamespace(buffer=out)), \
             patch.object(trial.os, 'geteuid', return_value=0), \
             patch.object(trial, 'export_failure', side_effect=OSError(SENTINEL)):
            self.assertEqual(trial.main(['export-failure', '--nonce', NONCE]), 0)
        out.write.assert_called_once_with(b'invalid')
        with patch.object(trial.os, 'geteuid', return_value=0), self.assertRaises(trial.Failure):
            trial.main(['export-failure', '--nonce', NONCE, '--sequence', '1'])
