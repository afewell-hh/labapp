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
REAL_SLEEP = time.sleep
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


def identity(info):
    """The exact tuple the actual regular() compares between its two descriptor observations."""
    return (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class DescriptorTap:
    """Runs one REAL filesystem action between the two real fstat observations of regular().

    It wraps os.open/os.fstat/os.replace and ALWAYS calls the original; it never fakes a
    stat result, a read or a Failure. After the first real fstat of the chosen descriptor,
    the second call first performs the action (the real trial.atomic, hence real
    exclusive() + real os.replace, or a real in-place append) and then returns the real
    fstat of the same descriptor. ``arm_on`` delays counting until that basename was opened.
    Optional ``actions`` maps zero-based read numbers to actions and records every read;
    this reuses the same descriptor observations for the #422 bounded recovery matrix.
    """
    def __init__(self, root, name, content=None, occurrence=1, action='replace', arm_on=None, actions=None):
        self.root, self.name, self.content = Path(root), name, content
        self.occurrence, self.action, self.arm_on = occurrence, action, arm_on
        self.armed, self.opened, self.fd, self.calls = arm_on is None, 0, None, 0
        self.before = self.after = None
        self.actions, self.reads = actions, 0
        self.replaced = []
        self.real_open, self.real_fstat, self.real_replace = os.open, os.fstat, os.replace

    def install(self, stack):
        stack.enter_context(patch.object(os, 'open', self.open))
        stack.enter_context(patch.object(os, 'fstat', self.fstat))
        stack.enter_context(patch.object(os, 'replace', self.replace))
        return self

    def open(self, path, *args, **kwargs):
        fd = self.real_open(path, *args, **kwargs)
        base = os.path.basename(os.fspath(path))
        if self.arm_on is not None and base == self.arm_on:
            self.armed = True
        if Path(path) == self.root / self.name and self.armed and self.fd is None \
                and (self.actions is not None or self.before is None):
            self.opened += 1
            if self.actions is not None or self.opened == self.occurrence:
                self.fd, self.calls = fd, 0
        return fd

    def replace(self, source, destination, *args, **kwargs):
        self.replaced.append((os.path.basename(os.fspath(source)), os.path.basename(os.fspath(destination))))
        return self.real_replace(source, destination, *args, **kwargs)

    def fstat(self, fd):
        if self.fd is None or fd != self.fd:
            return self.real_fstat(fd)
        self.calls += 1
        if self.calls == 1:
            self.reads += 1
            self.before = self.real_fstat(fd)
            return self.before
        self.fd = None
        if self.actions is not None:
            action = self.actions.get(self.reads - 1)
            if action is not None:
                REAL_SLEEP(0.05)  # reuse the assessed #418 timestamp separation
                action()
            self.after = self.real_fstat(fd)
            return self.after
        # A real pause so a coarse kernel timestamp tick cannot hide an inode-change effect.
        REAL_SLEEP(0.05)
        path = self.root / self.name
        if self.action == 'replace':
            REAL_ATOMIC(path, self.content() if callable(self.content) else self.content)
        else:
            with open(path, 'ab') as stream:
                stream.write(b' ')
        self.after = self.real_fstat(fd)
        return self.after

    def changed(self):
        return identity(self.before) != identity(self.after)

    def eligible(self):
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_uid', 'st_gid', 'st_mode')
        return (all(getattr(self.before, n) == getattr(self.after, n) for n in fields)
                and self.before.st_nlink == 1 and self.after.st_nlink == 0
                and self.before.st_ctime_ns != self.after.st_ctime_ns)

    def observation(self):
        return ('ino/size/mtime_ns/ctime_ns before=%r after=%r nlink_after=%d changed=%s replaced=%r' %
                (identity(self.before), identity(self.after), self.after.st_nlink, self.changed(), self.replaced))


class ReplaceTap(DescriptorTap):
    """Per-read actions using the same real open/fstat/replace tap as #418."""
    def __init__(self, target, actions):
        target = Path(target)
        super().__init__(target.parent, target.name, actions=actions)

    def __enter__(self):
        self.stack = ExitStack()
        return self.install(self.stack)

    def __exit__(self, *exc):
        return self.stack.__exit__(*exc)


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
    def guardian_fault(self, spawn=None, status=None, raw_status=None, overrides=None, clock_effects=None,
                       files=None, around=None, prepare=None):
        """Actual guardian with native actions patched; returns (exit, result|None, mocks).

        ``files`` replaces fixture files before the run; ``around`` is a context manager
        or an ExitStack callback active only while the actual guardian runs.
        ``prepare(root)`` retains the #418 fixture mutation hook."""
        if self.root.exists():
            shutil.rmtree(self.root)
        self.guardian_fixture()
        for name, raw in (files or {}).items():
            (self.root / name).write_bytes(raw)
        if prepare is not None:
            prepare(self.root)
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
            if around is not None:
                if callable(around):
                    around(local)
                else:
                    local.enter_context(around)
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

    # ---- issue #422: one bounded validated reread of REPLACED guardian mutable state ----
    # Recovery is discard-old/new-complete-validation. It does not prove who replaced the
    # file, and it does not explain the unknown native cause of canonical13.
    def old_beat(self):
        return trial.encoded({'sequence': 1, 'received': time.monotonic()})

    def publish(self, name, published, body=None, mode=0o600):
        """Action: a REAL atomic publication (exclusive temp + os.replace) of ``body``."""
        def action():
            raw = body() if callable(body) else body
            trial.exclusive(self.root / (name + '.next'), raw, mode)
            os.replace(self.root / (name + '.next'), self.root / name)
            published.append(raw)
        return action

    def recorded_state_bytes(self, seen):
        real = trial.data
        return {'data': {'side_effect': lambda raw: (seen.append(raw), real(raw))[1]}}

    def fresh_beat(self, sequence=2, shift=0):
        return lambda: trial.encoded({'sequence': sequence, 'received': time.monotonic() + shift})

    def host_accepts(self, result, code):
        from build.gcp.vlab_trial import guest_result
        raw = (self.root / 'result.json').read_bytes()
        self.assertEqual(json.loads(raw), result)
        state, accepted = guest_result(raw, NONCE)
        self.assertEqual((state, accepted), ('valid', result))
        self.assertEqual((state, accepted['code']), ('valid', code))
        return accepted

    def popen_child(self, poll=17):
        child = Mock(pid=999999)
        child.poll.return_value = poll
        return {'return_value': child}

    def test_replaced_initial_heartbeat_consumes_only_the_new_bytes_in_two_reads(self):
        old, published, seen = self.old_beat(), [], []
        tap = ReplaceTap(self.root / 'heartbeat.json', {0: self.publish('heartbeat.json', published, self.fresh_beat())})
        code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': old},
                                                  overrides=self.recorded_state_bytes(seen), around=tap)
        self.assertEqual(len(published), 1)
        # initial gate: attempt 1 (discarded) + attempt 2; then ONE ordinary loop read.
        self.assertEqual(tap.reads, 3)
        self.assertNotIn(old, seen)
        self.assertEqual(seen.count(published[0]), 2)  # attempt 2 and the later loop read of the same file
        mocks['Popen'].assert_called_once()
        self.assertEqual(code, 17)
        self.host_accepts(result, 17)

    def test_replaced_phase_consumes_new_phase_in_exactly_two_reads(self):
        old, published, seen = trial.encoded({'phase': 'stage'}), [], []
        tap = ReplaceTap(self.root / 'phase.json', {0: self.publish('phase.json', published, trial.encoded({'phase': 'fresh'}))})
        code, result, _ = self.guardian_fault(spawn=self.popen_child(), files={'phase.json': old},
                                              overrides=self.recorded_state_bytes(seen), around=tap)
        self.assertEqual(tap.reads, 2)
        self.assertNotIn(old, seen)
        self.assertIn(published[0], seen)
        self.assertEqual((code, result['diagnostic']['phase']), (17, 'fresh'))  # consumed the NEW phase
        self.host_accepts(result, 17)

    def test_replaced_post_auth_heartbeat_uses_stage_cutoff_and_new_bytes(self):
        old, published, seen, calls = self.old_beat(), [], [], []
        tap = ReplaceTap(self.root / 'heartbeat.json',
                         {1: self.publish('heartbeat.json', published, self.fresh_beat())})
        overrides = self.recorded_state_bytes(seen)
        overrides.update(auth_gate={'return_value': None}, auth_armed={'return_value': True})
        def clock(phase):
            calls.append(phase)
            return 100
        code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': old},
                                                  overrides=overrides, clock_effects=clock, around=tap)
        self.assertEqual((code, tap.reads, seen.count(old), seen.count(published[0])), (17, 4, 1, 2))
        self.assertEqual(calls, ['stage'] * 6)  # reservation, post-auth, retry pair, loop pair
        mocks['auth_gate'].assert_called_once()
        mocks['Popen'].assert_called_once()
        self.host_accepts(result, 17)

    def test_loop_heartbeat_replacement_is_recovered_with_consumed_phase_cutoff(self):
        published, seen, calls = [], [], []
        def clock(phase):
            calls.append(phase)
            return 100
        # initial gate read is untouched (read 0); the supervision heartbeat is read 1 -> replaced.
        tap = ReplaceTap(self.root / 'heartbeat.json', {1: self.publish('heartbeat.json', published, self.fresh_beat(3))})
        code, result, _ = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()},
                                              overrides=self.recorded_state_bytes(seen), clock_effects=clock, around=tap)
        self.assertEqual((code, tap.reads, seen.count(published[0])), (17, 3, 1))
        # started 'stage'; loop: phase 'stage' check, then recovery brackets use the consumed phase.
        self.assertEqual(calls, ['stage', 'stage', 'stage', 'stage', 'stage'])
        self.host_accepts(result, 17)

    def test_loop_heartbeat_cutoff_after_consumed_data_prevents_continuation(self):
        published, seen, calls = [], [], []
        child = Mock(pid=999999)
        def clock(phase):
            calls.append(phase)
            if len(calls) == 5:  # after retry checks AND consumed heartbeat parsing/freshness
                raise trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
            return 100
        tap = ReplaceTap(self.root / 'heartbeat.json',
                         {1: self.publish('heartbeat.json', published, self.fresh_beat())})
        code, result, mocks = self.guardian_fault(spawn={'return_value': child},
            overrides=self.recorded_state_bytes(seen), clock_effects=clock, around=tap)
        self.assertEqual((code, tap.reads, seen.count(published[0])), (124, 3, 1))
        self.assertEqual(calls, ['stage'] * 5)
        self.assertEqual(result['diagnostic'], {'origin': 'guardian', 'phase': 'stage',
                         'operation': 'worker-supervision', 'category': 'phase-cutoff', 'child_status': None})
        mocks['resources'].assert_not_called()
        child.poll.assert_not_called()
        mocks['containment'].assert_called_once_with()
        self.host_accepts(result, 124)

    def test_second_attempt_replaced_again_is_terminal_and_third_state_never_consumed(self):
        for name, first, later in (('heartbeat.json', self.fresh_beat(2), self.fresh_beat(3)),
                                   ('phase.json', trial.encoded({'phase': 'fresh'}), trial.encoded({'phase': 'strict'}))):
            with self.subTest(name):
                old = self.old_beat() if name == 'heartbeat.json' else trial.encoded({'phase': 'stage'})
                published, seen = [], []
                tap = ReplaceTap(self.root / name, {0: self.publish(name, published, first),
                                                    1: self.publish(name, published, later)})
                code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={name: old},
                                                          overrides=self.recorded_state_bytes(seen), around=tap)
                self.assertEqual((tap.reads, len(published)), (2, 2))  # never a third attempt
                for raw in (old, *published):
                    self.assertNotIn(raw, seen)
                self.assertEqual((code, result['diagnostic']['origin'], result['diagnostic']['category']),
                                 (1, 'guardian', 'policy'))
                self.assertEqual(mocks['Popen'].called, name == 'phase.json')
                self.host_accepts(result, 1)

    def test_observed_in_place_changes_are_terminal_without_retry(self):
        def append():
            with open(self.root / 'heartbeat.json', 'ab') as stream:
                stream.write(b' ')
        def truncate():
            os.truncate(self.root / 'heartbeat.json', 10)
        def overwrite():
            path = self.root / 'heartbeat.json'
            size = path.stat().st_size
            with open(path, 'r+b') as stream:
                stream.write(b' ' * size)
        def chmod():
            path = self.root / 'heartbeat.json'
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) ^ 0o100)
        def hardlink():
            os.link(self.root / 'heartbeat.json', self.root / 'extra-link')
        for name, action in (('append', append), ('truncate', truncate), ('same-size overwrite', overwrite),
                             ('mode', chmod), ('hardlink', hardlink)):
            with self.subTest(name):
                tap = ReplaceTap(self.root / 'heartbeat.json', {0: action})
                code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()},
                                                          around=tap)
                self.assertEqual((code, tap.reads), (1, 1))
                mocks['Popen'].assert_not_called()
                self.assertEqual(result['diagnostic']['category'], 'policy')

    def test_unsafe_or_invalid_replacements_fail_on_the_second_complete_read(self):
        def symlink():
            os.symlink(self.root / 'contract.json', self.root / 'heartbeat.json.next')
            os.replace(self.root / 'heartbeat.json.next', self.root / 'heartbeat.json')
        def fifo():
            os.mkfifo(self.root / 'heartbeat.json.next')
            os.replace(self.root / 'heartbeat.json.next', self.root / 'heartbeat.json')
        def hardlinked():
            trial.exclusive(self.root / 'heartbeat.json.next', self.fresh_beat()())
            os.link(self.root / 'heartbeat.json.next', self.root / 'extra-link')
            os.replace(self.root / 'heartbeat.json.next', self.root / 'heartbeat.json')
        dump = lambda raw: self.publish('heartbeat.json', [], raw)
        cases = (('symlink', symlink, 'policy'), ('fifo', fifo, 'policy'), ('hardlink', hardlinked, 'policy'),
                 ('oversize', dump(b' ' * 4097), 'policy'), ('malformed', dump(b'{'), 'exception'),
                 ('duplicate', dump(b'{"received":1,"received":2}'), 'policy'),
                 ('nonfinite', dump(b'{"received":NaN}'), 'policy'),
                 ('stale', dump(lambda: trial.encoded({'sequence': 2, 'received': time.monotonic() - 31})), 'heartbeat-loss'),
                 ('future', dump(lambda: trial.encoded({'sequence': 2, 'received': time.monotonic() + 100})), 'heartbeat-loss'))
        for name, action, category in cases:
            with self.subTest(name):
                tap = ReplaceTap(self.root / 'heartbeat.json', {0: action})
                code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()},
                                                          around=tap)
                mocks['Popen'].assert_not_called()
                self.assertEqual((code, result['diagnostic']['category']), (1, category))
                # a symlink is refused before any descriptor is opened; the rest are opened and refused
                self.assertEqual(tap.reads, 1 if name == 'symlink' else 2)
        for name, raw, category in (('invalid phase', b'{"phase":"bogus"}', 'policy'),
                                    ('malformed phase', b'{', 'exception'), ('oversize phase', b' ' * 4097, 'policy')):
            with self.subTest(name):
                tap = ReplaceTap(self.root / 'phase.json', {0: self.publish('phase.json', [], raw)})
                code, result, _ = self.guardian_fault(spawn=self.popen_child(), around=tap)
                self.assertEqual((code, result['diagnostic']['category'], result['diagnostic']['operation']),
                                 (1, category, 'worker-supervision'))

    def test_replacement_with_other_mode_is_accepted_because_these_sites_require_no_mode(self):
        # Documents unchanged behavior: guardian heartbeat/phase reads require uid 0 but NO mode.
        published = []
        tap = ReplaceTap(self.root / 'heartbeat.json',
                         {0: self.publish('heartbeat.json', published, self.fresh_beat(), mode=0o644)})
        code, _, _ = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()}, around=tap)
        self.assertEqual((code, tap.reads), (17, 3))

    def test_restored_history_replacement_is_accepted_as_a_documented_limit(self):
        # Actually mutate and restore the opened inode before unlinking it. The full
        # observed signature cannot prove that its bytes were never changed earlier.
        published, seen = [], []
        def restored_then_replaced():
            path = self.root / 'heartbeat.json'
            old, info = path.read_bytes(), path.stat()
            with path.open('r+b') as stream:
                stream.write(b' ' * len(old))
                stream.seek(0)
                stream.write(old)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(path.stat().st_mtime_ns, info.st_mtime_ns)
            self.publish('heartbeat.json', published, self.fresh_beat(sequence=0))()
        tap = ReplaceTap(self.root / 'heartbeat.json',
                         {0: restored_then_replaced})
        old = trial.encoded({'sequence': 9, 'received': time.monotonic()})
        code, result, _ = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': old},
                                              overrides=self.recorded_state_bytes(seen), around=tap)
        self.assertEqual((code, tap.reads), (17, 3))
        self.assertNotIn(old, seen)
        self.assertIn(published[0], seen)
        self.host_accepts(result, 17)

    def test_expiry_before_or_after_the_second_attempt_is_the_terminal_primary(self):
        for fail_at, reads, consumed in ((2, 1, False), (3, 2, False)):
            with self.subTest(fail_at):
                published, seen, calls = [], [], []
                def clock(phase):
                    calls.append(phase)
                    if len(calls) == fail_at:
                        raise trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
                    return 100
                tap = ReplaceTap(self.root / 'heartbeat.json', {0: self.publish('heartbeat.json', published, self.fresh_beat())})
                code, result, mocks = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()},
                                                          overrides=self.recorded_state_bytes(seen), clock_effects=clock, around=tap)
                self.assertEqual((code, tap.reads), (124, reads))
                self.assertEqual(published[0] in seen, consumed)
                self.assertEqual((result['diagnostic']['category'], calls), ('phase-cutoff', ['stage'] * fail_at))
                mocks['Popen'].assert_not_called()
                self.host_accepts(result, 124)

    def test_phase_transition_recovery_uses_persistence_cutoff_not_previous_phase(self):
        spawned, calls, published = [], [], []
        child = Mock(pid=999999)
        child.poll.return_value = 17
        def popen(*args, **kwargs):
            spawned.append(True)
            return child
        def clock(phase):
            if spawned:
                calls.append(phase)
                if phase == 'stage':  # the previous phase is long expired by now
                    raise trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
            return 100
        tap = ReplaceTap(self.root / 'phase.json', {0: self.publish('phase.json', published, trial.encoded({'phase': 'resume'}))})
        code, result, _ = self.guardian_fault(spawn={'side_effect': popen}, clock_effects=clock, around=tap)
        self.assertEqual(calls, ['persistence', 'persistence', 'resume', 'resume'])
        self.assertEqual((code, result['diagnostic']['phase']), (17, 'resume'))

    def test_expired_consumed_phase_is_terminal_after_recovery(self):
        spawned, published = [], []
        def popen(*args, **kwargs):
            spawned.append(True)
            return Mock(pid=999999)
        def clock(phase):
            if spawned and phase == 'resume':
                raise trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
            return 100
        tap = ReplaceTap(self.root / 'phase.json', {0: self.publish('phase.json', published, trial.encoded({'phase': 'resume'}))})
        code, result, mocks = self.guardian_fault(spawn={'side_effect': popen}, clock_effects=clock, around=tap)
        self.assertEqual((code, tap.reads, result['diagnostic']['category'], result['diagnostic']['phase']),
                         (124, 2, 'phase-cutoff', 'resume'))
        mocks['containment'].assert_called_once_with()

    def test_interrupts_at_recovery_boundaries_keep_signal_primary_and_cleanup(self):
        for name, exception, expected in (('SIGINT', KeyboardInterrupt(), 130),
                                          ('SIGTERM handler', trial.Failure('signal', 143, 'interrupted'), 143)):
            for boundary in (2, 3):  # before / after the second complete read
                with self.subTest((name, boundary)):
                    spawned, calls, published = [], [], []
                    def popen(*args, **kwargs):
                        spawned.append(True)
                        return Mock(pid=999999)
                    def clock(phase):
                        calls.append(phase)
                        if len(calls) == boundary and spawned:
                            raise exception
                        return 100
                    # clock call 1 is the start reservation; calls 2 and 3 bracket the phase reread
                    tap = ReplaceTap(self.root / 'phase.json', {0: self.publish(
                        'phase.json', published, trial.encoded({'phase': 'fresh'}))})
                    code, result, mocks = self.guardian_fault(spawn={'side_effect': popen}, clock_effects=clock, around=tap)
                    self.assertEqual((code, result['code']), (expected, expected))
                    self.assertEqual(result['diagnostic']['category'], 'interrupted')
                    mocks['containment'].assert_called_once_with()
                    self.host_accepts(result, expected)

    def test_interrupt_during_second_read_is_not_converted(self):
        published = []
        def interrupt():
            raise KeyboardInterrupt()
        tap = ReplaceTap(self.root / 'heartbeat.json', {0: self.publish('heartbeat.json', published, self.fresh_beat()),
                                                       1: interrupt})
        code, result, _ = self.guardian_fault(spawn=self.popen_child(), files={'heartbeat.json': self.old_beat()}, around=tap)
        self.assertEqual((code, tap.reads, result['diagnostic']['category']), (130, 2, 'interrupted'))

    def test_regular_marks_only_exact_replaced_inode_signature(self):
        path = self.base / 'signature.json'
        path.write_bytes(b'{}')
        real = os.fstat
        def run(**change):
            calls, opened = [], []
            real_open = os.open
            def tracked_open(name, *args, **kwargs):
                fd = real_open(name, *args, **kwargs)
                if Path(name) == path:
                    opened.append(fd)
                return fd
            def fstat(fd):
                info = real(fd)
                if not opened or fd != opened[-1]:
                    return info
                calls.append(fd)
                if len(calls) == 1:
                    return info
                fields = {n: getattr(info, n) for n in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                                                        'st_uid', 'st_gid', 'st_mode', 'st_nlink')}
                for key, update in change.items():
                    fields[key] = update(fields[key])
                return SimpleNamespace(**fields)
            with patch.object(os, 'open', tracked_open), patch.object(os, 'fstat', fstat):
                try:
                    return REAL_REGULAR(path, 4096)
                except trial.Failure as error:
                    return error
        signature = {'st_nlink': lambda v: 0, 'st_ctime_ns': lambda v: v + 1}
        eligible = run(**signature)
        self.assertIs(type(eligible), trial._ReplacedState)
        self.assertEqual((str(eligible), eligible.code, eligible.category, eligible.child_status),
                         ('file changed', 1, 'policy', None))
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_uid', 'st_gid', 'st_mode'):
            with self.subTest(field):
                error = run(**signature, **{field: lambda v: v ^ 1})
                self.assertIs(type(error), trial.Failure)
                self.assertEqual((str(error), error.code, error.category), ('file changed', 1, 'policy'))
        # Link count alone was never part of the ordinary stability tuple. Preserve
        # that strict-reader success when ctime and the compared fields did not change.
        self.assertEqual(run(st_nlink=lambda v: 0), b'{}')
        for name, change in (('link count 2', {'st_nlink': lambda v: 2, 'st_ctime_ns': lambda v: v + 1}),
                             ('ctime only', {'st_ctime_ns': lambda v: v + 1})):
            with self.subTest(name):
                self.assertIs(type(run(**change)), trial.Failure)

    def test_strict_regular_and_other_paths_never_use_the_guardian_recovery(self):
        path = self.base / 'result.json'
        path.write_bytes(trial.encoded({'a': 1}))
        os.chmod(path, 0o600)
        published = []
        def replace():
            trial.exclusive(self.base / 'result.json.next', b'{}')
            os.replace(self.base / 'result.json.next', path)
        tap = ReplaceTap(path, {0: replace})
        with tap, self.assertRaisesRegex(trial.Failure, 'file changed') as caught:
            REAL_REGULAR(path, 4096, os.getuid(), 0o600)
        self.assertEqual((tap.reads, type(caught.exception)), (1, trial._ReplacedState))  # strict: no reread
        with patch.object(trial, 'regular') as reader:
            for other in ('contract.json', 'result.json', 'worker-status.json'):
                with self.assertRaises(trial.Failure):
                    trial.guardian_state(self.root / other, lambda: None)
            reader.assert_not_called()

    def test_guardian_state_attempt_accounting_and_second_failure_is_terminal(self):
        path = self.root / 'phase.json'
        replaced = trial._ReplacedState('file changed', 1, 'policy')
        checks = []
        with patch.object(trial, 'regular', side_effect=[replaced, trial.Failure('file type/owner/size refused')]) as reader:
            with self.assertRaisesRegex(trial.Failure, 'owner'):
                trial.guardian_state(path, lambda: checks.append(1))
        self.assertEqual((reader.call_count, len(checks)), (2, 1))  # no after-check on a failed read
        with patch.object(trial, 'regular', side_effect=[replaced, b'{}']) as reader:
            self.assertEqual(trial.guardian_state(path, lambda: checks.append(1)), b'{}')
        self.assertEqual((reader.call_count, len(checks)), (2, 3))
        with patch.object(trial, 'regular', side_effect=[trial.Failure('file changed', 1, 'policy'), b'{}']) as reader:
            with self.assertRaises(trial.Failure):
                trial.guardian_state(path, lambda: checks.append(1))
        self.assertEqual(reader.call_count, 1)  # a plain 'file changed' (e.g. in-place) is never recovered
        ineligible = trial._ReplacedState('file changed', 1, 'policy')
        ineligible.eligible = False
        with patch.object(trial, 'regular', side_effect=ineligible) as reader:
            with self.assertRaises(trial._ReplacedState):
                trial.guardian_state(path, lambda: self.fail('no recovery for an ineligible flag'))
        self.assertEqual(reader.call_count, 1)

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

    # ---- issue #418: file-publication and policy failures, real functions, no VM ------
    # Offline reproduction of a CANDIDATE mechanism only. It makes no claim about the
    # unknown cause of the native13 failure and no attribution to any earlier change.
    # Hypothesis: the guardian's regular() compares ino/size/mtime/ctime of one open
    # descriptor before and after its read, so an os.replace() of the same path between
    # the two observations may unlink the old inode (ctime change) and be refused as
    # `file changed` (a policy Failure). Whether the assessed filesystem does that is
    # RECORDED, not assumed: expectations below follow the real descriptor observations.
    def test_real_regular_with_real_replace_between_descriptor_observations(self):
        self.root.mkdir(mode=0o700)
        cases = (('phase.json', {'phase': 'fresh'}, {'phase': 'strict'}),
                 ('heartbeat.json', {'sequence': 1, 'received': 1.0}, {'sequence': 2, 'received': 2.0}))
        for name, old, new in cases:
            with self.subTest(name):
                path = self.root / name
                path.write_bytes(trial.encoded(old))
                tap = DescriptorTap(self.root, name, content=new)
                with ExitStack() as local:
                    tap.install(local)
                    try:
                        outcome = REAL_REGULAR(path, 4096)
                    except trial.Failure as error:
                        outcome = error
                self.assertEqual(tap.calls, 2)  # exactly two real observations of one descriptor
                self.assertEqual(tap.replaced, [(name + '.next', name)])
                self.assertEqual(path.read_bytes(), trial.encoded(new))  # the replacement really happened
                self.assertFalse((self.root / (name + '.next')).exists())
                sys.stderr.write('\nOBSERVED #418 %s %s\n' % (name, tap.observation()))
                if tap.changed():
                    self.assertIsInstance(outcome, trial.Failure)
                    self.assertEqual((str(outcome), outcome.category, outcome.code, outcome.child_status),
                                     ('file changed', 'policy', 1, None))
                else:  # hypothesis negative on this filesystem: the old, consistent bytes are returned
                    self.assertEqual(outcome, trial.encoded(old))
        # In-place mutation between the same observations is the unambiguous control.
        path = self.root / 'phase.json'
        path.write_bytes(trial.encoded({'phase': 'fresh'}))
        tap = DescriptorTap(self.root, 'phase.json', action='append')
        with ExitStack() as local:
            tap.install(local)
            with self.assertRaisesRegex(trial.Failure, '^file changed$') as caught:
                REAL_REGULAR(path, 4096)
        self.assertEqual((caught.exception.category, caught.exception.child_status), ('policy', None))
        self.assertTrue(tap.changed())
        self.assertEqual(tap.replaced, [])
        # No interference: the same real function accepts the unmodified file.
        path.write_bytes(trial.encoded({'phase': 'fresh'}))
        self.assertEqual(REAL_REGULAR(path, 4096), trial.encoded({'phase': 'fresh'}))

    def test_real_regular_refuses_unsafe_files_and_accepts_the_matching_control(self):
        self.root.mkdir(mode=0o700)
        good = self.root / 'good.json'
        good.write_bytes(b'{"phase":"fresh"}')
        os.chmod(good, 0o600)
        self.assertEqual(REAL_REGULAR(good, 4096, os.getuid(), 0o600), b'{"phase":"fresh"}')
        self.assertEqual(REAL_REGULAR(good, len(b'{"phase":"fresh"}')), b'{"phase":"fresh"}')  # limit is inclusive
        with self.subTest('oversized'):
            with self.assertRaisesRegex(trial.Failure, 'file type/owner/size refused'):
                REAL_REGULAR(good, len(b'{"phase":"fresh"}') - 1)
        with self.subTest('owner'):
            with self.assertRaisesRegex(trial.Failure, 'file type/owner/size refused'):
                REAL_REGULAR(good, 4096, os.getuid() + 1)
        with self.subTest('mode'):
            with self.assertRaisesRegex(trial.Failure, 'file type/owner/size refused'):
                REAL_REGULAR(good, 4096, None, 0o640)
        with self.subTest('hardlink'):
            os.link(good, self.root / 'alias.json')
            for name in ('good.json', 'alias.json'):
                with self.assertRaisesRegex(trial.Failure, 'file type/owner/size refused'):
                    REAL_REGULAR(self.root / name, 4096)
            (self.root / 'alias.json').unlink()
            self.assertEqual(REAL_REGULAR(good, 4096), b'{"phase":"fresh"}')
        with self.subTest('symlink'):
            os.symlink(good, self.root / 'link.json')
            with self.assertRaisesRegex(trial.Failure, 'path link refused'):
                REAL_REGULAR(self.root / 'link.json', 4096)
        with self.subTest('symlinked parent'):
            (self.root / 'dir').mkdir()
            (self.root / 'dir' / 'f.json').write_bytes(b'{}')
            os.symlink(self.root / 'dir', self.root / 'dirlink')
            with self.assertRaisesRegex(trial.Failure, 'path link refused'):
                REAL_REGULAR(self.root / 'dirlink' / 'f.json', 4096)
            self.assertEqual(REAL_REGULAR(self.root / 'dir' / 'f.json', 4096), b'{}')
        with self.subTest('fifo and directory'):
            os.mkfifo(self.root / 'fifo.json')
            for name in ('fifo.json', 'dir'):
                with self.assertRaisesRegex(trial.Failure, 'file type/owner/size refused'):
                    REAL_REGULAR(self.root / name, 4096)
        with self.subTest('missing is not a policy Failure'):
            with self.assertRaises(FileNotFoundError):
                REAL_REGULAR(self.root / 'absent.json', 4096)

    def supervised_loop_fault(self, mutate=None, prepare=None, poll=(None, 17, 17), overrides=None, around=None):
        """Actual guardian; first loop pass reads genuine `fresh` phase, then `mutate` runs once."""
        child = Mock(pid=999999)
        child.poll.side_effect = list(poll)
        calls = []

        def sleeper(_seconds):
            calls.append(_seconds)
            if len(calls) == 1 and mutate is not None:
                mutate(self.root)

        def fixture(root):
            (root / 'phase.json').write_bytes(b'{"phase":"fresh"}')
            if prepare is not None:
                prepare(root)
        with patch.object(trial.time, 'sleep', side_effect=sleeper):
            return self.guardian_fault(spawn={'return_value': child}, prepare=fixture, overrides=overrides, around=around)

    def assert_supervision_failure(self, outcome, phase, category, code=1):
        exit_code, result, mocks = outcome
        self.assertEqual(exit_code, code)
        self.assertEqual((result['schema'], result['code'], result['contained'], result['nonce']), (2, code, True, NONCE))
        self.assertEqual(result['diagnostic'], {'origin': 'guardian', 'phase': phase, 'operation': 'worker-supervision',
                                                'category': category, 'child_status': None})
        self.assertEqual(trial.result_record(result, NONCE), result)  # actual final record validates
        mocks['containment'].assert_called_once_with()
        mocks['Popen'].assert_called_once()  # failure was observed during supervision, after spawn

    def test_guardian_supervision_maps_real_unsafe_inputs_to_policy_or_exception(self):
        def write(name, raw):
            return lambda root: (root / name).write_bytes(raw)

        def replace_with(name, action):
            def run(root):
                (root / name).unlink()
                action(root / name)
            return run
        heartbeat, phase = 'heartbeat.json', 'phase.json'
        cases = (
            ('heartbeat duplicate key', write(heartbeat, b'{"received":1,"received":2,"sequence":1}'), 'fresh', 'policy'),
            ('heartbeat NaN', write(heartbeat, b'{"received":NaN,"sequence":1}'), 'fresh', 'policy'),
            ('heartbeat Infinity', write(heartbeat, b'{"received":Infinity,"sequence":1}'), 'fresh', 'policy'),
            ('heartbeat oversized', write(heartbeat, b' ' * 4097), 'fresh', 'policy'),
            ('heartbeat hardlink', lambda root: os.link(root / heartbeat, root / 'heartbeat.alias'), 'fresh', 'policy'),
            ('heartbeat symlink', replace_with(heartbeat, lambda p: os.symlink(p.parent / 'contract.json', p)), 'fresh', 'policy'),
            ('heartbeat fifo', replace_with(heartbeat, os.mkfifo), 'fresh', 'policy'),
            ('heartbeat malformed JSON is an ordinary exception', write(heartbeat, b'{'), 'fresh', 'exception'),
            ('heartbeat missing field is an ordinary exception', write(heartbeat, b'{"sequence":1}'), 'fresh', 'exception'),
            ('heartbeat missing is an ordinary exception', lambda root: (root / heartbeat).unlink(), 'fresh', 'exception'),
            ('stale heartbeat is the explicit watchdog category',
             lambda root: (root / heartbeat).write_bytes(trial.encoded({'sequence': 1, 'received': time.monotonic() - 31})),
             'fresh', 'heartbeat-loss'),
            ('phase duplicate key', write(phase, b'{"phase":"fresh","phase":"fresh"}'), 'fresh', 'policy'),
            ('phase NaN', write(phase, b'{"phase":NaN}'), 'fresh', 'policy'),
            ('phase unknown name', write(phase, b'{"phase":"bogus"}'), 'fresh', 'policy'),
            ('phase startup has no cutoff', write(phase, b'{"phase":"startup"}'), 'startup', 'policy'),
            ('phase hardlink', lambda root: os.link(root / phase, root / 'phase.alias'), 'fresh', 'policy'),
            ('phase unhashable value is an ordinary exception', write(phase, b'{"phase":["fresh"]}'), 'fresh', 'exception'),
            ('phase missing key is an ordinary exception', write(phase, b'{}'), 'fresh', 'exception'),
            ('phase missing is an ordinary exception', lambda root: (root / phase).unlink(), 'fresh', 'exception'),
        )
        for label, mutate, expected_phase, category in cases:
            with self.subTest(label):
                self.assert_supervision_failure(self.supervised_loop_fault(mutate), expected_phase, category)

    def test_guardian_measurements_path_refusals_and_symlink_replacement(self):
        def link_next(root):
            os.symlink(root / 'contract.json', root / 'measurements.json.next')

        def regular_next(root):
            (root / 'measurements.json.next').write_bytes(b'PUBLIC-STALE-TEMP')
        self.assert_supervision_failure(self.supervised_loop_fault(prepare=link_next), 'fresh', 'policy')
        outcome = self.supervised_loop_fault(prepare=regular_next)  # O_EXCL collision is not a Failure
        self.assert_supervision_failure(outcome, 'fresh', 'exception')
        self.assertEqual((self.root / 'measurements.json.next').read_bytes(), b'PUBLIC-STALE-TEMP')

        # Reachable unsafe case: a symlink AT measurements.json is replaced by os.replace
        # (never followed), so the guardian is not refused and the symlink target is untouched.
        def link_target(root):
            (root / 'victim').write_bytes(b'PUBLIC-VICTIM')
            os.symlink(root / 'victim', root / 'measurements.json')
        exit_code, result, _ = self.supervised_loop_fault(prepare=link_target)
        self.assertEqual((self.root / 'victim').read_bytes(), b'PUBLIC-VICTIM')
        self.assertFalse((self.root / 'measurements.json').is_symlink())
        self.assertEqual((exit_code, result['diagnostic']['origin'], result['diagnostic']['category']),
                         (17, 'unknown', 'status-invalid'))

    def test_guardian_real_replace_between_observations_follows_actual_descriptor_evidence(self):
        # The guardian reads phase 'fresh' genuinely first; the tap then performs a real
        # os.replace between the real fstat observations of the NEXT read of the file.
        def fresh_heartbeat():
            return {'sequence': 2, 'received': time.monotonic()}
        plans = (('phase.json', lambda: {'phase': 'fresh'}, 2, None),
                 ('heartbeat.json', fresh_heartbeat, 1, 'phase.json'))
        for name, content, occurrence, arm_on in plans:
            with self.subTest(name):
                taps = []

                def around(stack):
                    taps.append(DescriptorTap(self.root, name, content, occurrence, arm_on=arm_on).install(stack))
                outcome = self.supervised_loop_fault(poll=(None, None, 17, 17), around=around)
                tap = taps[0]
                exit_code, result, mocks = outcome
                self.assertEqual(tap.calls, 2)
                self.assertIn((name + '.next', name), tap.replaced)
                sys.stderr.write('\nOBSERVED #418 guardian %s %s\n' % (name, tap.observation()))
                if tap.changed() and not tap.eligible():
                    self.assert_supervision_failure(outcome, 'fresh', 'policy')
                else:  # eligible replacement recovers; unchanged observations retain the negative control
                    self.assertEqual((exit_code, result['code'], result['contained']), (17, 17, True))
                    self.assertEqual(result['diagnostic'], {'origin': 'unknown', 'phase': 'fresh',
                                     'operation': 'worker-supervision', 'category': 'status-invalid', 'child_status': 17})
                    mocks['containment'].assert_called_once_with()
                # Validate the guardian's published bytes through the host's independent gate.
                from build.gcp.vlab_trial import guest_result
                raw = (self.root / 'result.json').read_bytes()
                self.assertEqual(json.loads(raw), result)
                self.assertEqual(guest_result(raw, NONCE), ('valid', result))

    def test_guardian_policy_primary_survives_cleanup_interruption_and_failed_final_write(self):
        def bogus_phase(root):
            (root / 'phase.json').write_bytes(b'{"phase":"bogus"}')

        def run(**overrides):
            child = Mock(pid=999999)
            child.poll.return_value = None
            return self.guardian_fault(spawn={'return_value': child}, prepare=bogus_phase, overrides=overrides)
        # Baseline: invalid phase at the first supervision read -> policy, phase still `startup`.
        self.assert_supervision_failure(run(), 'startup', 'policy')
        for label, trouble in (('Failure', trial.Failure('uncertain')), ('interrupt', KeyboardInterrupt()),
                               ('OSError', OSError(SENTINEL))):
            with self.subTest('containment ' + label):
                exit_code, result, mocks = run(containment={'side_effect': trouble})
                self.assertEqual((exit_code, result['code'], result['contained']), (1, 1, False))
                self.assertEqual(result['diagnostic'], {'origin': 'guardian', 'phase': 'startup',
                                 'operation': 'worker-supervision', 'category': 'policy', 'child_status': None})
                self.assertNotIn(SENTINEL, json.dumps(result))
                mocks['containment'].assert_called_once_with()

        def failing(path, value):
            if Path(path).name == 'result.json':
                raise OSError(SENTINEL)
            return REAL_ATOMIC(path, value)
        with self.subTest('failed final write'):
            exit_code, result, mocks = run(atomic={'side_effect': failing})
            self.assertEqual((exit_code, result), (1, None))  # primary preserved, no false receipt
            mocks['containment'].assert_called_once_with()
        with self.subTest('failed final write and containment trouble'):
            exit_code, result, _ = run(atomic={'side_effect': failing}, containment={'side_effect': KeyboardInterrupt()})
            self.assertEqual((exit_code, result), (1, None))

    def test_guardian_policy_failure_never_replaces_an_incumbent_when_reservation_collides(self):
        self.guardian_fixture()
        (self.root / 'phase.json').write_bytes(b'{"phase":"bogus"}')
        (self.root / 'started.json').write_bytes(b'{}')
        incumbent = trial.encoded({'schema': 2, 'incumbent': True})
        (self.root / 'result.json').write_bytes(incumbent)
        with patch.object(trial.subprocess, 'Popen') as spawn, patch.object(trial, 'containment') as contain:
            with self.assertRaises(FileExistsError):
                trial.main(['guardian'])
        spawn.assert_not_called()
        contain.assert_not_called()
        self.assertEqual((self.root / 'result.json').read_bytes(), incumbent)

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

    def test_actual_auth_publish_check_stays_strict_when_heartbeat_is_replaced(self):
        # #422: only the guardian's own heartbeat/phase reads recover; the credential
        # publish binding reads the same file strictly and refuses after ONE read.
        self.arm()
        def replace():
            trial.exclusive(self.root / 'heartbeat.json.next',
                            trial.encoded({'sequence': 0, 'received': time.monotonic()}))
            os.replace(self.root / 'heartbeat.json.next', self.root / 'heartbeat.json')
        with patch.object(trial, 'auth_open'), patch.object(trial, 'manifest', side_effect=lambda v: v), \
             ReplaceTap(self.root / 'heartbeat.json', {0: replace}) as tap:
            with self.assertRaisesRegex(trial.Failure, 'file changed'):
                trial.auth_publish_check(self.v, None)
        self.assertEqual(tap.reads, 1)

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
        started = time.monotonic()
        self.value = {'schema': 1, 'nonce': NONCE, 'mode': 'fresh', 'operation': self.operation,
                      'phase': 'starting', 'invocation': self.invocation, 'boot': v['boot_uuid'],
                      'started': started, 'deadline': started + core.START_SECONDS['fresh']}
        # reserve() returns before unit_gate publishes the invocation in current state.
        self.reserved = {key: item for key, item in self.value.items() if key != 'invocation'}
        core.atomic(self.state_root / 'state.json', self.value)

    def query(self, argv, end, keep):
        self.queries.append(list(argv))
        if argv[0] == self.core.SYSTEMCTL:
            return 'ok', ('InvocationID=' + self.invocation + '\n').encode(), False, 'confirmed'
        return 'ok', b'journal ' + SENTINEL.encode(), False, 'confirmed'

    def capture(self, value=True, error=None):
        error = error or self.core.Failure('child command failed', 1, b'primary ' + SENTINEL.encode())
        self.core.capture_first_failure('fresh', self.reserved if value else None, error, time.monotonic() + 60)

    def export(self):
        return trial.export_failure(NONCE)

    def test_real_writer_roundtrip_validates_and_binds_independent_envelope(self):
        self.assertNotIn('invocation', self.reserved)
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
        value = self.value

        def publish(message, code):
            record = {'schema': 1, 'source': 'vlab_core', 'action': 'unit-ready', 'nonce': NONCE,
                      'mode': 'fresh', 'operation': self.operation, 'invocation': self.invocation,
                      'boot': value['boot'], 'started': value['started'], 'deadline': value['deadline'],
                      'message': message, 'code': code}
            core.write_first_failure(trial.encoded(record), core.UNIT_READY_FAILURE)

        publish('synthetic readiness refusal', 17)
        self.assertNotIn('invocation', self.reserved)
        self.capture(error=core.Failure('child command failed', 1, b'x'))
        bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
        self.assertEqual(bundle['unit_ready'], {'status': 'ok', 'message': 'synthetic readiness refusal', 'code': 17})
        self.assertLessEqual(len((self.state_root / self.core.FIRST_FAILURE).read_bytes()), trial.FAILURE_LIMIT)

    def test_missing_current_clock_authority_invalidates_only_readiness_section(self):
        current = {key: item for key, item in self.value.items() if key != 'started'}
        self.core.atomic(self.state_root / 'state.json', current)
        self.capture()
        bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
        self.assertEqual(bundle['unit_ready'], {'status': 'invalid', 'message': None, 'code': None})
        self.assertEqual((bundle['primary']['message'], bundle['primary']['code']), ('child command failed', 1))
        self.assertEqual((bundle['manager']['status'], bundle['journal']['status']), ('ok', 'ok'))
        self.assertEqual(len(self.queries), 2)

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


class ResumeFailureLifecycleExport(unittest.TestCase):
    """#412: genuine fresh success -> owned stop -> activation -> committed resume failure.

    Uses the existing offline core fixture (fake systemctl/kubectl/hhfab only); the REAL core
    state machine, first-failure writer, guest exporter and host accepter run. Offline fakes do
    not show native systemd, journald or VLAB behaviour, and the native refusal stays unknown.
    """
    RESUME = {'origin': 'worker', 'phase': 'resume', 'operation': 'core-start-resume',
              'category': 'child-exit', 'child_status': 17}
    FRESH = {'origin': 'worker', 'phase': 'stage', 'operation': 'install-docker',
             'category': 'child-exit', 'child_status': 17}
    RESUME_INVOCATION = 'd' * 32

    def setUp(self):
        import vlab_core
        from test_vlab_core import GuestEnvironment
        self.core = vlab_core
        self.env = type('Env', (GuestEnvironment, unittest.TestCase), {'runTest': lambda s: None})()
        self.env.setUp()
        self.addCleanup(self.env.doCleanups)
        self.env.contract['nonce'] = NONCE
        self.env.write_contract()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # GuestEnvironment fakes privileged core entrypoints on the shared os module.
        # Export is read-only: retain its real filesystem ownership checks against
        # this unprivileged fixture user without changing the core's privilege stub.
        class ExportOS:
            def geteuid(self):
                return os.getuid()

            def __getattr__(self, name):
                return getattr(os, name)

        self.stack.enter_context(patch.object(trial, 'os', ExportOS()))
        self.v = value()
        self.root = self.env.base / 'trial'
        self.root.mkdir(mode=0o700)
        (self.root / 'contract.json').write_bytes(trial.encoded(self.v))
        reader = trial.regular
        self.stack.enter_context(patch.object(trial, 'regular', side_effect=(
            lambda p, n, uid=None, mode=None: reader(p, n, os.getuid() if uid == 0 else uid, mode))))
        for target, name, replacement in ((trial, 'ROOT', self.root),
                                          (trial, 'kernel_boot', lambda: self.v['boot_uuid']),
                                          (vlab_core, 'boot', lambda: self.v['boot_uuid']),
                                          (trial, 'load_sibling', lambda *_: vlab_core)):
            self.stack.enter_context(patch.object(target, name, replacement))

    def ready_failure(self):
        return patch.object(self.core, 'unit_ready', side_effect=self.core.Failure('synthetic ready failure', 17))

    def terminal(self, detail, **record):
        body = {'schema': 2, 'code': detail['child_status'], 'contained': True,
                'nonce': NONCE, 'diagnostic': detail, **record}
        path = self.root / 'result.json'
        path.unlink(missing_ok=True)
        path.write_bytes(trial.encoded(body))
        path.chmod(0o600)

    def committed_resume_failure(self):
        """Real fresh success, real owned stop + activation, then a committed resume reservation that fails."""
        core, env = self.core, self.env
        fresh = env.resumable()
        self.assertEqual((fresh['mode'], fresh['phase']), ('fresh', 'resumable'))
        self.assertEqual(fresh['stop_verified'], {'operation': fresh['operation'], 'invocation': fresh['invocation']})
        self.assertFalse((core.ROOT / core.FIRST_FAILURE).exists())
        with patch.dict(os.environ, {'INVOCATION_ID': self.RESUME_INVOCATION}), self.ready_failure():
            self.assertEqual(env.call('start-resume'), 17)
        failed = core.state()
        self.assertEqual((failed['mode'], failed['phase'], failed['invocation']),
                         ('resume', 'failed', self.RESUME_INVOCATION))
        self.assertNotEqual(failed['operation'], fresh['operation'])  # a NEW operation, never borrowed
        self.assertNotEqual(failed['invocation'], fresh['invocation'])
        return fresh, failed

    def host(self):
        import importlib
        with patch.object(sys, 'path', [str(Path(__file__).resolve().parents[2]), *sys.path]):
            return importlib.import_module('build.gcp.vlab_trial')

    def test_core_writer_guest_exporter_host_accepter_resume_roundtrip(self):
        fresh, failed = self.committed_resume_failure()
        written = (self.core.ROOT / self.core.FIRST_FAILURE).read_bytes()
        bundle = trial.first_failure_bundle(written)
        self.assertEqual((bundle['mode'], bundle['operation'], bundle['invocation']),
                         ('resume', failed['operation'], self.RESUME_INVOCATION))
        self.assertEqual(bundle['primary']['code'], 17)
        self.terminal(self.RESUME)
        raw = trial.export_failure(NONCE)
        first, _, rest = raw.partition(b'\n')
        self.assertEqual(json.loads(first), {'schema': 1, 'source_sha': 'c' * 40, 'nonce': NONCE, 'mode': 'resume',
                                             'operation': failed['operation'], 'invocation': self.RESUME_INVOCATION,
                                             'boot': self.v['boot_uuid']})
        self.assertEqual(rest, written)
        host = self.host()
        args = ('c' * 40, NONCE, self.v['boot_uuid'])
        self.assertEqual(host.accept_failure(raw, *args, 'resume'), ('captured', raw))
        self.assertEqual(host.accept_failure(raw, *args), ('invalid', None))  # fresh-only default unchanged
        self.assertEqual(host.accept_failure(raw, *args, 'fresh'), ('invalid', None))

    def test_exporter_rejects_resume_state_without_validated_resume_terminal_result(self):
        # Rejected at the REAL mode guard (bundle/live mode vs terminal-derived mode), not a missing API.
        self.committed_resume_failure()
        success = {'schema': 2, 'code': 0, 'contained': True, 'nonce': NONCE, 'diagnostic': dict(trial.SUCCESS)}
        cases = {
            'no terminal result': None,
            'fresh worker failure': lambda: self.terminal(self.FRESH),
            'resume phase, other operation': lambda: self.terminal(dict(self.RESUME, operation='core-stop')),
            'guardian-origin diagnostic': lambda: self.terminal({
                'origin': 'guardian', 'phase': 'resume', 'operation': 'worker-supervision',
                'category': 'child-signal', 'child_status': -9}, code=137),
            'foreign nonce': lambda: self.terminal(self.RESUME, nonce='9' * 32),
            'success record': lambda: (self.root / 'result.json').write_bytes(trial.encoded(success)),
            'malformed JSON': lambda: (self.root / 'result.json').write_bytes(b'{"schema":2'),
            'extra field': lambda: self.terminal(self.RESUME, extra=1),
            'oversize': lambda: (self.root / 'result.json').write_bytes(b' ' * (trial.MAX_RESULT + 1)),
            'invalid mismatched code': lambda: self.terminal(self.RESUME, code=2),
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                (self.root / 'result.json').unlink(missing_ok=True)
                if prepare:
                    prepare()
                    (self.root / 'result.json').chmod(0o600)
                if name == 'guardian-origin diagnostic':
                    record = trial.result_record(trial.data((self.root / 'result.json').read_bytes()), NONCE)
                    self.assertEqual((record['code'], record['diagnostic']['origin']), (137, 'guardian'))
                self.assertEqual(trial.terminal_mode(NONCE), 'fresh')
                with self.assertRaises(trial.Failure):
                    trial.export_failure(NONCE)

    def test_resume_terminal_does_not_vouch_for_stale_foreign_or_mismatched_state(self):
        _, failed = self.committed_resume_failure()
        self.terminal(self.RESUME)
        self.assertEqual(trial.export_failure(NONCE).partition(b'\n')[0].count(b'"mode":"resume"'), 1)
        for name, change in (('operation', {'operation': '9' * 32}), ('invocation', {'invocation': '9' * 32}),
                             ('nonce', {'nonce': '9' * 32}), ('fresh mode', {'mode': 'fresh'}),
                             ('no invocation', {'invocation': None})):
            with self.subTest(name):
                current = {k: v for k, v in dict(failed, **change).items() if v is not None}
                self.core.atomic(self.core.ROOT / 'state.json', current)
                with self.assertRaises(trial.Failure):
                    trial.export_failure(NONCE)
        self.core.atomic(self.core.ROOT / 'state.json', failed)
        with patch.object(trial, 'kernel_boot', return_value='33333333-3333-4333-8333-333333333333'), \
             self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)
        with self.assertRaises(trial.Failure):
            trial.export_failure('9' * 32)

    def test_unsafe_terminal_file_cannot_authorize_resume(self):
        self.committed_resume_failure()
        path = self.root / 'result.json'
        target = self.root / 'other-result'
        for unsafe in ('wide mode', 'hard link', 'symlink', 'directory', 'wrong owner'):
            with self.subTest(unsafe=unsafe), ExitStack() as local:
                self.terminal(self.RESUME)
                if unsafe == 'wide mode':
                    path.chmod(0o640)
                elif unsafe == 'hard link':
                    os.link(path, target)
                elif unsafe == 'symlink':
                    path.rename(target)
                    path.symlink_to(target)
                elif unsafe == 'directory':
                    path.unlink()
                    path.mkdir(mode=0o700)
                else:
                    original = os.fstat
                    inode = path.stat().st_ino
                    def foreign_owner(fd):
                        info = original(fd)
                        if info.st_ino != inode:
                            return info
                        fields = {name: getattr(info, name) for name in
                                  ('st_mode', 'st_nlink', 'st_uid', 'st_ino', 'st_size',
                                   'st_mtime_ns', 'st_ctime_ns')}
                        return SimpleNamespace(**dict(fields, st_uid=info.st_uid + 1))
                    local.enter_context(patch.object(os, 'fstat', side_effect=foreign_owner))
                self.assertEqual(trial.terminal_mode(NONCE), 'fresh')
                with self.assertRaises(trial.Failure):
                    trial.export_failure(NONCE)
                if unsafe == 'directory':
                    path.rmdir()
                else:
                    path.unlink()
                target.unlink(missing_ok=True)

    def test_terminal_read_preserves_explicit_signal_failure_and_base_interruptions(self):
        self.committed_resume_failure()
        self.terminal(self.RESUME)
        reader = trial.regular
        for error in (trial.Failure('signal', 130, 'interrupted'),
                      trial.Failure('signal', 143, 'interrupted'), KeyboardInterrupt(), SystemExit(143)):
            def interrupted(path, *args, **kwargs):
                if path == self.root / 'result.json':
                    raise error
                return reader(path, *args, **kwargs)
            with self.subTest(error=type(error).__name__, code=getattr(error, 'code', None)), \
                 patch.object(trial, 'regular', side_effect=interrupted):
                for call in (trial.terminal_mode, trial.export_failure):
                    with self.assertRaises(type(error)) as caught:
                        call(NONCE)
                    self.assertIs(caught.exception, error)

    def test_stale_fresh_null_reservation_stays_first_writer_and_is_not_rebound_to_resume(self):
        core, env = self.core, self.env
        env.prepared()
        core.capture_first_failure('fresh', None, core.Failure('startup phase refused'), time.monotonic() + 60)
        stale = (core.ROOT / core.FIRST_FAILURE).read_bytes()
        self.assertIsNone(trial.first_failure_bundle(stale)['operation'])
        self.assertEqual(env.call('start-fresh'), 0, env.stderr.getvalue())
        self.assertEqual(env.call('activate-resume'), 0, env.stderr.getvalue())
        with patch.dict(os.environ, {'INVOCATION_ID': self.RESUME_INVOCATION}), self.ready_failure():
            self.assertEqual(env.call('start-resume'), 17)
        self.assertEqual((core.ROOT / core.FIRST_FAILURE).read_bytes(), stale)  # first writer unchanged
        self.terminal(self.RESUME)
        with self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)

    def test_null_reservation_after_activation_writes_nothing_and_exports_absent(self):
        core, env = self.core, self.env
        env.resumable()
        core.capture_first_failure('resume', None, core.Failure('startup phase refused'), time.monotonic() + 60)
        self.assertFalse((core.ROOT / core.FIRST_FAILURE).exists())
        self.terminal(self.RESUME)
        self.assertEqual(trial.export_failure(NONCE), b'absent')

    def test_fresh_failure_export_is_unchanged_and_resume_terminal_cannot_retarget_it(self):
        core, env = self.core, self.env
        env.prepared()
        with patch.dict(os.environ, {'INVOCATION_ID': 'a' * 32}), self.ready_failure():
            self.assertEqual(env.call('start-fresh'), 17)
        self.assertEqual(core.state()['mode'], 'fresh')
        for name, prepare in (('no terminal', None), ('fresh worker terminal', lambda: self.terminal(self.FRESH))):
            with self.subTest(name):
                (self.root / 'result.json').unlink(missing_ok=True)
                if prepare:
                    prepare()
                first, _, rest = trial.export_failure(NONCE).partition(b'\n')
                self.assertEqual(json.loads(first)['mode'], 'fresh')
                self.assertEqual(trial.first_failure_bundle(rest)['mode'], 'fresh')
        self.terminal(self.RESUME)
        with self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)

    def test_expected_mode_derives_only_from_a_failed_worker_resume_core_start_diagnostic(self):
        guardian = {'origin': 'guardian', 'phase': 'resume', 'operation': 'worker-supervision',
                    'category': 'exception', 'child_status': None}
        self.assertEqual(trial.diagnostic(guardian), guardian)
        for detail, expected in ((self.RESUME, 'resume'), (self.FRESH, 'fresh'),
                                 (dict(self.RESUME, operation='core-stop'), 'fresh'),
                                 (dict(trial.SUCCESS), 'fresh'), (None, 'fresh'), (guardian, 'fresh')):
            with self.subTest(detail=detail):
                self.assertEqual(trial.terminal_export_mode(detail), expected)
