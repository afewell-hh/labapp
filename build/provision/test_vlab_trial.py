"""Fixed shared trial entrypoints, public temp files and fail-closed spies only.

No real package/systemd/hhfab/QEMU/sudo/network invocation. Installer evidence
controls launch only stdlib fixture children. Production paths are patched before
mutating entrypoints. The only credential fixtures are the
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
import signal
import tempfile
import time
import stat
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

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

    def test_installer_evidence_hook_is_docker_only_and_failed_capture_never_changes_status(self):
        calls = []
        def capture(value, clock, code, out):
            calls.append((value['nonce'], code, out))
        with patch.object(trial, 'capture_installer_failure', side_effect=capture):
            error, baseline = self.run_worker(self.fake_bounded({'install-docker': (17, b'native')}, []))
            self.assertEqual(calls, [(NONCE, 17, b'native')])
            for operation in ('install-qemu', 'install-hhfab', 'install-kubectl'):
                calls.clear()
                other, _ = self.run_worker(self.fake_bounded({operation: (5, b'other')}, []))
                self.assertEqual((other.code, other.category, other.child_status), (5, 'child-exit', 5))
                self.assertEqual(calls, [])  # other installers and every other call are unchanged
            calls.clear()
            self.run_worker(self.fake_bounded({'core-prepare': (5, b'other')}, []))
            self.run_worker(self.fake_bounded({'install-docker': hhfab_release.Refusal('command timeout')}, []))
            self.assertEqual(calls, [])  # no returned tuple, no capture
        primary = (error.code, error.category, error.child_status)
        self.assertEqual(primary, (17, 'child-exit', 17))
        self.assertEqual((baseline['state'], baseline['operation'], baseline['code']), ('failed', 'install-docker', 17))
        for fault in (OSError(SENTINEL), KeyboardInterrupt(), SystemExit(143), trial.Failure('signal', 143, 'interrupted')):
            with self.subTest(type(fault).__name__), patch.object(trial, 'capture_installer_failure', side_effect=fault):
                again, status = self.run_worker(self.fake_bounded({'install-docker': (17, b'native')}, []))
                self.assertEqual((again.code, again.category, again.child_status), primary)
                self.assertEqual(status, baseline)  # public worker status identical to the no-capture baseline

    def test_real_installer_writer_io_faults_through_docker_worker_hook_preserve_primary_and_status(self):
        # Inject only while the real Docker capture runs: checkpoints/terminal status stay real.
        original_capture, original_child = trial.capture_installer_failure, trial.child_failure
        real_write, real_close = os.write, os.close
        with patch.object(trial, 'capture_installer_failure', return_value=None):
            _, baseline = self.run_worker(self.fake_bounded({'install-docker': (17, b'native')}, []))
        for fault in ('open', 'partial-write', 'fsync', 'link', 'close'):
            with self.subTest(fault=fault):
                built, attempted, writes = [], [], []
                def make(code, message):
                    built.append(original_child(code, message))
                    return built[-1]
                def fail(*args, **kwargs):
                    attempted.append(fault)
                    raise OSError(SENTINEL)
                def partial(fd, view):
                    writes.append(fd)
                    if len(writes) == 1:
                        return real_write(fd, bytes(view[:5]))
                    return fail()
                def closing(fd):
                    real_close(fd)
                    return fail()
                def capture(v, clock, code, out):
                    with ExitStack() as local:
                        # run_worker models root; this private filesystem fixture belongs to its test uid.
                        local.enter_context(patch.object(os, 'geteuid', return_value=os.getuid()))
                        local.enter_context(patch.object(trial, 'kernel_boot', return_value=v['boot_uuid']))
                        name = {'open': 'open', 'partial-write': 'write', 'fsync': 'fsync',
                                'link': 'link', 'close': 'close'}[fault]
                        local.enter_context(patch.object(os, name, side_effect=(
                            partial if fault == 'partial-write' else closing if fault == 'close' else fail)))
                        original_capture(v, clock, code, out)
                with patch.object(trial, 'child_failure', side_effect=make), \
                     patch.object(trial, 'capture_installer_failure', side_effect=capture):
                    error, status = self.run_worker(self.fake_bounded({'install-docker': (17, b'native')}, []))
                self.assertEqual(attempted, [fault])  # reached the actual writer, not a preflight refusal
                self.assertEqual(len(built), 1)
                self.assertIs(error, built[0])
                self.assertIsNone(error.__context__)
                self.assertEqual((str(error), error.code, error.category, error.child_status),
                                 ('fixed child failed', 17, 'child-exit', 17))
                self.assertEqual(status, baseline)
                self.assertFalse((self.root / trial.INSTALLER_FAILURE).exists())
                self.assertFalse((self.root / (trial.INSTALLER_FAILURE + '.new')).exists())

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
        self.real_ubuntu = core.ubuntu
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
        # Raw started + duration loses the exact resume duration at this binary64 clock.
        self.stack.enter_context(patch.object(core.time, 'monotonic', return_value=128.0 + 2**-43))
        self.value = self.startup_value('fresh')
        # reserve() returns before unit_gate publishes the invocation in current state.
        self.reserved = {key: item for key, item in self.value.items() if key != 'invocation'}
        core.atomic(self.state_root / 'state.json', self.value)

    def startup_value(self, mode):
        duration = self.core.START_SECONDS[mode]
        deadline = time.monotonic() + duration
        # Match reserve(): derive started from EACH mode's already rounded deadline.
        return {'schema': 1, 'nonce': NONCE, 'mode': mode, 'operation': self.operation,
                'phase': 'starting', 'invocation': self.invocation, 'boot': self.v['boot_uuid'],
                'started': deadline - duration, 'deadline': deadline}

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
        # Bundle schema 3 (#430 route); the envelope/state/public schemas above are unchanged (1).
        self.assertEqual((bundle['schema'], bundle['unit_ready']),
                         (3, {'status': 'unavailable', 'message': None, 'code': None, 'route': None}))

    def test_real_unit_ready_record_roundtrips_through_capture_export_and_validator(self):
        core = self.core
        value = self.value

        def publish(message, code, route=None):
            record = {'schema': 2, 'source': 'vlab_core', 'action': 'unit-ready', 'nonce': NONCE,
                      'mode': 'fresh', 'operation': self.operation, 'invocation': self.invocation,
                      'boot': value['boot'], 'started': value['started'], 'deadline': value['deadline'],
                      'message': message, 'code': code, 'route': route}
            core.write_first_failure(trial.encoded(record), core.UNIT_READY_FAILURE)

        publish('synthetic readiness refusal', 17, 'api-final-switches')
        self.assertNotIn('invocation', self.reserved)
        self.capture(error=core.Failure('child command failed', 1, b'x'))
        bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
        self.assertEqual(bundle['unit_ready'], {'status': 'ok', 'message': 'synthetic readiness refusal',
                                                'code': 17, 'route': 'api-final-switches'})
        self.assertLessEqual(len((self.state_root / self.core.FIRST_FAILURE).read_bytes()), trial.FAILURE_LIMIT)

    def readiness_chain(self, mode, *, prelaunch=False, uncertain=False):
        """Actual executor -> unit_ready recorder -> capture -> export -> host, no staged records."""
        import importlib
        core = self.core
        for name in (core.FIRST_FAILURE, core.UNIT_READY_FAILURE):
            (self.state_root / name).unlink(missing_ok=True)
        original = self.startup_value(mode)
        reserved = {key: item for key, item in original.items() if key != 'invocation'}
        core.atomic(self.state_root / 'state.json', original)
        primary = core.Failure('child command failed', 1, b'PRIMARY_UNCHANGED')
        primary.cleanup_uncertain = True
        child = MagicMock()
        child.pid = 424242
        child.stdout.fileno.return_value = 123
        child.wait.return_value = 19
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [True]
        observed = []
        def body(*_):
            # Restore child-only observations before unit_ready reads/writes real files.
            with ExitStack() as child_scope:
                spawn = child_scope.enter_context(patch.object(core.subprocess, 'Popen', return_value=child))
                child_scope.enter_context(patch.object(core.selectors, 'DefaultSelector', return_value=selector))
                child_scope.enter_context(patch.object(core.os, 'read', side_effect=[b'CHILD_PRIVATE', b'']))
                kill = child_scope.enter_context(patch.object(core.os, 'killpg', side_effect=(
                    OSError('synthetic uncertainty') if uncertain else ProcessLookupError())))
                if prelaunch:
                    child_scope.enter_context(patch.object(core, 'ubuntu', self.real_ubuntu))
                    child_scope.enter_context(patch.object(core.pwd, 'getpwnam', return_value=SimpleNamespace(
                        pw_uid=0, pw_gid=0, pw_dir='/home/ubuntu')))
                else:
                    child_scope.enter_context(patch.object(core, 'ubuntu', return_value=SimpleNamespace(
                        pw_uid=os.getuid(), pw_gid=os.getgid())))
                    child_scope.enter_context(patch.object(core.os, 'getgrouplist', return_value=[os.getgid()]))
                try:
                    core.kubectl(['get', '--raw=/readyz'], original['deadline'], 'api-final-readyz')
                except core.Failure as error:
                    observed.append(error)
                    if prelaunch:
                        spawn.assert_not_called()
                        kill.assert_not_called()
                    else:
                        spawn.assert_called_once()
                        kill.assert_called_once_with(child.pid, core.signal.SIGKILL)
                        child.stdout.close.assert_called_once()
                    raise
        with patch.dict(os.environ, {'INVOCATION_ID': self.invocation}), \
             patch.object(core, 'ready_body', side_effect=body):
            with self.assertRaises(core.Failure) as raised:
                core.unit_ready(mode)
        error = raised.exception
        self.assertIs(error, observed[0])
        expected = ('ubuntu identity refused', 1, b'', None) if prelaunch else (
            'child command failed', 19, b'CHILD_PRIVATE', 'api-final-readyz')
        self.assertEqual((str(error), error.code, error.private_output, error.route), expected)
        self.assertEqual(getattr(error, 'cleanup_uncertain', False), uncertain)
        record_raw = (self.state_root / core.UNIT_READY_FAILURE).read_bytes()
        record = core.json_data(record_raw)
        self.assertEqual((record['message'], record['code'], record['route']), (expected[0], expected[1], expected[3]))
        self.assertLessEqual(len(record_raw), core.UNIT_READY_LIMIT)
        core.capture_first_failure(mode, reserved, primary, original['deadline'])
        written = (self.state_root / core.FIRST_FAILURE).read_bytes()
        bundle = trial.first_failure_bundle(written)
        self.assertEqual(bundle['unit_ready'], dict(status='ok', message=expected[0], code=expected[1], route=expected[3]))
        self.assertEqual((bundle['primary']['message'], bundle['primary']['code']), ('child command failed', 1))
        self.assertEqual(base64.b64decode(bundle['primary']['output']), b'PRIMARY_UNCHANGED')
        self.assertEqual((str(primary), primary.code, primary.private_output, primary.cleanup_uncertain),
                         ('child command failed', 1, b'PRIMARY_UNCHANGED', True))
        self.assertLessEqual(len(written), trial.FAILURE_LIMIT)
        detail = {'origin': 'worker', 'phase': mode, 'operation': 'core-start-' + mode,
                  'category': 'child-exit', 'child_status': 1}
        trial.atomic(self.root / 'result.json', {'schema': 2, 'code': 1, 'contained': True,
                                               'nonce': NONCE, 'diagnostic': detail})
        raw = trial.export_failure(NONCE)
        first, _, rest = raw.partition(b'\n')
        self.assertEqual(rest, written)  # exact writer bytes reach the host, no reconstructed bundle
        envelope = trial.data(first)
        self.assertEqual(envelope, {'schema': 1, 'source_sha': self.v['source_sha'], 'nonce': NONCE,
                                    'mode': mode, 'operation': self.operation, 'invocation': self.invocation,
                                    'boot': original['boot']})
        with patch.object(sys, 'path', [str(Path(__file__).resolve().parents[2]), *sys.path]):
            host = importlib.import_module('build.gcp.vlab_trial')
        args = (self.v['source_sha'], NONCE, original['boot'], mode)
        self.assertEqual(host.accept_failure(raw, *args), ('captured', raw))
        # Same genuine bytes refuse each independent host binding; mode's fresh default remains strict.
        for index, foreign in ((0, '9' * 40), (1, '9' * 32),
                               (2, '33333333-3333-4333-8333-333333333333'),
                               (3, 'resume' if mode == 'fresh' else 'fresh')):
            changed = list(args)
            changed[index] = foreign
            self.assertEqual(host.accept_failure(raw, *changed), ('invalid', None))
        for key in ('operation', 'invocation'):
            foreign = dict(envelope, **{key: '9' * 32})
            self.assertEqual(host.accept_failure(trial.encoded(foreign) + b'\n' + rest, *args), ('invalid', None))
        self.assertEqual((self.state_root / core.UNIT_READY_FAILURE).read_bytes(), record_raw)
        self.assertEqual((self.state_root / core.FIRST_FAILURE).read_bytes(), written)

    def test_rounding_sensitive_clock_refuses_raw_started_but_records_deadline_first(self):
        core, mode = self.core, 'resume'
        original = self.startup_value(mode)
        old = dict(original, started=time.monotonic())
        duration = core.START_SECONDS[mode]
        self.assertNotEqual(old['deadline'] - old['started'], duration)
        self.assertEqual(original['deadline'] - original['started'], duration)
        error = core.Failure('child command failed', 19, b'CHILD_PRIVATE')
        error.route = 'api-final-readyz'
        path = self.state_root / core.UNIT_READY_FAILURE
        with patch.dict(os.environ, {'INVOCATION_ID': self.invocation}):
            core.atomic(self.state_root / 'state.json', old)
            with self.assertRaisesRegex(core.Failure, '^operation clock refused$'):
                core.operation_deadline(old)
            with self.assertRaisesRegex(core.Failure, '^operation clock refused$'):
                core.record_unit_ready_failure(mode, old, error)
            self.assertFalse(path.exists())
            # The mocked startup snapshot formerly let this invalid pair reach the child.
            with patch.object(core, 'startup_snapshot', return_value=(old, old['deadline'])), \
                 patch.object(core, 'ready_body', side_effect=error):
                with self.assertRaises(core.Failure) as raised:
                    core.unit_ready(mode)
            self.assertIs(raised.exception, error)
            self.assertFalse(path.exists())
            core.atomic(self.state_root / 'state.json', original)
            with patch.object(core, 'ready_body', side_effect=error):
                with self.assertRaises(core.Failure) as raised:
                    core.unit_ready(mode)
            self.assertIs(raised.exception, error)
        record = core.json_data(path.read_bytes())
        core.valid_unit_ready(record, mode, original, self.invocation, original['boot'])
        with self.assertRaisesRegex(core.Failure, '^unit-ready clock refused$'):
            core.valid_unit_ready(dict(record, started=old['started']), mode, old,
                                  self.invocation, old['boot'])
        self.assertEqual(core.read_unit_ready(mode, original, self.invocation, original['boot']),
                         ('ok', 'child command failed', 19, 'api-final-readyz'))
        self.assertEqual((str(error), error.code, error.private_output, error.route),
                         ('child command failed', 19, b'CHILD_PRIVATE', 'api-final-readyz'))

    def test_real_executed_readiness_failure_whole_chain_fresh_and_resume(self):
        for mode in ('fresh', 'resume'):
            with self.subTest(mode=mode):
                self.readiness_chain(mode)

    def test_real_prelaunch_identity_refusal_whole_chain_has_null_route_in_both_modes(self):
        for mode in ('fresh', 'resume'):
            with self.subTest(mode=mode):
                self.readiness_chain(mode, prelaunch=True)

    def test_real_executed_cleanup_uncertainty_whole_chain_preserves_primary_in_both_modes(self):
        for mode in ('fresh', 'resume'):
            with self.subTest(mode=mode):
                self.readiness_chain(mode, uncertain=True)

    def test_every_closed_route_and_null_roundtrip_writer_to_export_and_unknown_routes_are_not_exported(self):
        core = self.core
        value = self.value
        def publish(route, schema=2):
            record = {'schema': schema, 'source': 'vlab_core', 'action': 'unit-ready', 'nonce': NONCE,
                      'mode': 'fresh', 'operation': self.operation, 'invocation': self.invocation,
                      'boot': value['boot'], 'started': value['started'], 'deadline': value['deadline'],
                      'message': 'synthetic readiness refusal', 'code': 124, 'route': route}
            core.write_first_failure(trial.encoded(record), core.UNIT_READY_FAILURE)
        self.assertEqual(tuple(trial.FAILURE_ROUTES), tuple(core.UNIT_READY_ROUTES))
        for route in (*core.UNIT_READY_ROUTES, None):
            with self.subTest(route=route):
                for name in (core.FIRST_FAILURE, core.UNIT_READY_FAILURE):
                    (self.state_root / name).unlink(missing_ok=True)
                publish(route)
                self.capture(error=core.Failure('child deadline exceeded', 124))
                bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
                self.assertEqual(bundle['unit_ready']['route'], route)
                self.assertEqual(bundle['unit_ready']['status'], 'ok')
        # Writer-side refusals reach the bundle as a null, status-coherent invalid/unavailable section.
        for name, route, schema in (('unknown', 'api-final-pods', 2), ('wrong type', 7, 2),
                                    ('legacy schema', 'svc-entry', 1)):
            with self.subTest(name):
                for fixed in (core.FIRST_FAILURE, core.UNIT_READY_FAILURE):
                    (self.state_root / fixed).unlink(missing_ok=True)
                publish(route, schema)
                self.capture(error=core.Failure('child deadline exceeded', 124))
                bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
                self.assertEqual(bundle['unit_ready'], {'status': 'invalid', 'message': None, 'code': None,
                                                        'route': None})
                self.assertEqual((bundle['primary']['message'], bundle['primary']['code']),
                                 ('child deadline exceeded', 124))

    def test_missing_current_clock_authority_invalidates_only_readiness_section(self):
        current = {key: item for key, item in self.value.items() if key != 'started'}
        self.core.atomic(self.state_root / 'state.json', current)
        self.capture()
        bundle = trial.first_failure_bundle(self.export().partition(b'\n')[2])
        self.assertEqual(bundle['unit_ready'], {'status': 'invalid', 'message': None, 'code': None, 'route': None})
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
        def ready(status, message=None, code=None, route=None):
            return {'status': status, 'message': message, 'code': code, 'route': route}
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
            'legacy schema 1': dict(good, schema=1), 'legacy schema 2': dict(good, schema=2),
            'future schema 4': dict(good, schema=4),
            'missing unit_ready': {k: v for k, v in good.items() if k != 'unit_ready'},
            'null unit_ready': dict(good, unit_ready=None),
            'unit_ready extra key': dict(good, unit_ready=dict(good['unit_ready'], extra=1)),
            'unit_ready missing key': dict(good, unit_ready={'status': 'unavailable', 'message': None,
                                                             'route': None}),
            'unit_ready legacy three keys': dict(good, unit_ready={'status': 'unavailable', 'message': None,
                                                                    'code': None}),
            'unit_ready missing route': dict(good, unit_ready={'status': 'ok', 'message': 'x', 'code': 1}),
            'unit_ready bad status': dict(good, unit_ready=ready('captured')),
            'ok null message': dict(good, unit_ready=ready('ok', None, 1)),
            'ok null code': dict(good, unit_ready=ready('ok', 'x', None)),
            'ok bool code': dict(good, unit_ready=ready('ok', 'x', True)),
            'ok float code': dict(good, unit_ready=ready('ok', 'x', 1.0)),
            'ok negative code': dict(good, unit_ready=ready('ok', 'x', -1)),
            'ok long message': dict(good, unit_ready=ready('ok', 'x' * 129, 1)),
            'ok empty message': dict(good, unit_ready=ready('ok', '', 1)),
            'ok non-ascii message': dict(good, unit_ready=ready('ok', 'café', 1)),
            'unavailable with message': dict(good, unit_ready=ready('unavailable', 'x', None)),
            'invalid with code': dict(good, unit_ready=ready('invalid', None, 0)),
            'unknown route': dict(good, unit_ready=ready('ok', 'x', 1, 'api-final-pods')),
            'generic route': dict(good, unit_ready=ready('ok', 'x', 1, 'kubectl-list')),
            'route wrong case': dict(good, unit_ready=ready('ok', 'x', 1, 'SVC-ENTRY')),
            'route empty': dict(good, unit_ready=ready('ok', 'x', 1, '')),
            'route int': dict(good, unit_ready=ready('ok', 'x', 1, 1)),
            'route bool': dict(good, unit_ready=ready('ok', 'x', 1, True)),
            'route list': dict(good, unit_ready=ready('ok', 'x', 1, ['svc-entry'])),
            'route dict': dict(good, unit_ready=ready('ok', 'x', 1, {'svc-entry': 1})),
            'route free text': dict(good, unit_ready=ready('ok', 'x', 1, '/usr/local/bin/kubectl get nodes')),
            'unavailable with route': dict(good, unit_ready=ready('unavailable', None, None, 'svc-entry')),
            'invalid with route': dict(good, unit_ready=ready('invalid', None, None, 'api-final-nodes')),
            'ok on reservation': dict(good, operation=None, invocation=None, stage='reserve',
                                      manager={'status': 'unavailable', 'output': ''},
                                      journal={'status': 'unavailable', 'output': ''},
                                      command_context=dict(good['command_context'], status='unavailable', output=''),
                                      unit_ready=ready('ok', 'x', 1)),
        }
        # Positive controls: the same shapes with exact closed values are accepted.
        for route in (None, *trial.FAILURE_ROUTES):
            accepted = trial.first_failure_bundle(trial.encoded(dict(good, unit_ready=ready('ok', 'x', 1, route))))
            self.assertEqual(accepted['unit_ready']['route'], route)
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
    # Not install-docker: that child exit/signal is the #439 file-only installer export mode.
    FRESH = {'origin': 'worker', 'phase': 'stage', 'operation': 'install-hhfab',
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


class InstallerFailureEvidence(unittest.TestCase):
    """#439: pure validators, REAL bounded stdlib child -> hook -> writer -> exporter.

    Offline only: children are `sys.executable` one-liners; no Docker, APT, systemd, network or VM.
    """
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-installer-')))
        self.root = self.base / 'trial'
        self.root.mkdir(mode=0o700)
        self.v = value()
        reader = trial.regular
        # Production requires euid 0; fixtures are owned by the unprivileged test user.
        self.stack.enter_context(patch.object(trial, 'regular', side_effect=(
            lambda p, n, uid=None, mode=None: reader(p, n, None if uid == 0 else uid, mode))))
        self.stack.enter_context(patch.object(trial, 'ROOT', self.root))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=self.v['boot_uuid']))
        (self.root / 'contract.json').write_bytes(trial.encoded(self.v))
        self.clock = trial.Clock(self.v)
        self.final = self.root / trial.INSTALLER_FAILURE
        self.temp = self.root / (trial.INSTALLER_FAILURE + '.new')

    def record(self, out=b'x', code=1, now=None, v=None):
        v = v or self.v
        return trial.installer_record(v, v['boot_uuid'], code, out, time.time() if now is None else now)

    def terminal(self, category='child-exit', status=17, operation='install-docker'):
        detail = {'origin': 'worker', 'phase': 'stage', 'operation': operation,
                  'category': category, 'child_status': status}
        path = self.root / 'result.json'
        path.unlink(missing_ok=True)
        path.write_bytes(trial.encoded({'schema': 2, 'code': status if category == 'child-exit' else 128 - status,
                                        'contained': True, 'nonce': NONCE, 'diagnostic': detail}))
        path.chmod(0o600)
        return detail

    def test_byte_shapes_and_caps_at_every_boundary(self):
        pattern = b'\x00\xffAB\n'
        for size, shape in ((0, ('empty', 0, 0, 0)), (1, ('ok', 1, 0, 0)), (13312, ('ok', 13312, 0, 0)),
                            (13313, ('truncated', 1024, 12288, 1)),
                            (1048576, ('truncated', 1024, 12288, 1048576 - 13312))):
            with self.subTest(size=size):
                out = (pattern * (size // len(pattern) + 1))[:size]
                raw = self.record(out)
                item = trial.installer_body(raw)
                self.assertEqual((item['output_status'], item['kept_head'], item['kept_tail'], item['omitted']), shape)
                self.assertEqual(item['observed'], size)
                self.assertIs(type(item['captured_at']), int)
                self.assertEqual(item['outcome'], 'exit')
                self.assertEqual(item['observed'], item['kept_head'] + item['kept_tail'] + item['omitted'])
                self.assertLessEqual(len(raw), trial.INSTALLER_LIMIT)
                self.assertEqual(base64.b64decode(item['head']), out[:item['kept_head']])
                self.assertEqual(base64.b64decode(item['tail']), out[size - item['kept_tail']:] if item['kept_tail'] else b'')
        for name, args in (('oversize', (b'x' * (1048576 + 1), 1)), ('text output', ('text', 1)),
                           ('zero code', (b'x', 0)), ('bool code', (b'x', True)), ('string code', (b'x', '1')),
                           ('exit 256', (b'x', 256)), ('signal -65', (b'x', -65))):
            with self.subTest(name), self.assertRaises(trial.Failure):
                self.record(*args)
        for code in (1, 255, -1, -64):
            with self.subTest(code=code):
                self.assertEqual(trial.installer_body(self.record(b'x', code))['status'], code)

    def test_strict_validator_rejects_hostile_shapes_types_and_encodings(self):
        good = json.loads(self.record(b'abc'))
        self.assertEqual(trial.installer_body(trial.encoded(good))['head'], 'YWJj')
        wrong = {
            'bool schema': dict(good, schema=True), 'schema 2': dict(good, schema=2),
            'float schema': dict(good, schema=1.0), 'kind': dict(good, kind='first-failure'),
            'phase': dict(good, phase='fresh'), 'operation': dict(good, operation='install-hhfab'),
            'short source': dict(good, source_sha='c' * 39), 'upper nonce': dict(good, nonce='A' * 32),
            'lease': dict(good, lease='x'), 'boot': dict(good, boot=None), 'captured fmt': dict(good, captured_at='x'),
            'captured UTC': dict(good, captured_at=self.v['admitted_at']),
            'captured bool': dict(good, captured_at=True), 'captured float': dict(good, captured_at=1.0),
            'outcome': dict(good, outcome='child-timeout'),
            'outcome vs status': dict(good, outcome='signal'), 'status zero': dict(good, status=0),
            'status bool': dict(good, status=True), 'status 256': dict(good, status=256),
            'status float': dict(good, status=1.0), 'float count': dict(good, observed=3.0),
            'bool count': dict(good, kept_tail=False), 'negative omitted': dict(good, omitted=-1),
            'count sum': dict(good, observed=4), 'tail on whole': dict(good, tail='YQ==', kept_tail=1, observed=4),
            'status shape': dict(good, output_status='truncated'), 'unknown status': dict(good, output_status='invalid'),
            'padless base64': dict(good, head='YWJ'), 'whitespace base64': dict(good, head='YWJj\n'),
            'url alphabet': dict(good, head='YW-_', kept_head=3), 'head type': dict(good, head=1),
            'head length lie': dict(good, kept_head=2, observed=2), 'extra': dict(good, extra=1),
            'missing': {k: v for k, v in good.items() if k != 'tail'},
        }
        for name, item in wrong.items():
            with self.subTest(name), self.assertRaises(trial.Failure):
                trial.installer_body(trial.encoded(item))
        text = trial.encoded(good)
        for name, raw in (('empty', b''), ('str', text.decode()), ('spaced', text.replace(b',"', b', "', 1)),
                          ('duplicate', text.replace(b'"tail":', b'"nonce":"' + b'a' * 32 + b'","tail":', 1)),
                          ('nan', text.replace(b'"observed":3', b'"observed":NaN')), ('array', b'[]'),
                          ('oversize', text + b' ' * trial.INSTALLER_LIMIT), ('trailing', text + b'\n'),
                          ('invalid json', text[:-1])):
            with self.subTest(name), self.assertRaises(trial.Failure):
                trial.installer_body(raw)
        zero = json.loads(self.record(b''))
        self.assertEqual((zero['output_status'], zero['head'], zero['tail'], zero['observed']), ('empty', '', '', 0))
        self.assertEqual(trial.installer_body(trial.encoded(zero))['observed'], 0)
        for wrong_status in ('ok', 'truncated'):
            with self.subTest(empty_status=wrong_status), self.assertRaises(trial.Failure):
                trial.installer_body(trial.encoded(dict(zero, output_status=wrong_status)))
        for legacy in ('child-exit', 'child-signal'):
            with self.subTest(legacy_outcome=legacy), self.assertRaises(trial.Failure):
                trial.installer_body(trial.encoded(dict(good, outcome=legacy)))

    def test_binding_and_time_window_use_contract_boot_and_absolute_stage_bounds(self):
        item = trial.installer_body(self.record())
        self.assertIs(trial.installer_bound(item, self.v, self.v['boot_uuid']), item)
        for key, other in (('source_sha', 'd' * 40), ('nonce', '9' * 32),
                           ('lease', '33333333-3333-4333-8333-333333333333'),
                           ('boot_uuid', '33333333-3333-4333-8333-333333333333')):
            with self.subTest(key), self.assertRaises(trial.Failure):
                trial.installer_bound(item, dict(self.v, **{key: other}), self.v['boot_uuid'])
        with self.assertRaises(trial.Failure):
            trial.installer_bound(item, self.v, '33333333-3333-4333-8333-333333333333')
        admitted = trial.stamp(self.v['admitted_at'])
        for now in (admitted - 5, admitted + 35 * 60, admitted + 36 * 60):
            with self.subTest(now=now - admitted), self.assertRaises(trial.Failure):
                self.record(now=now)
        self.record(now=admitted)
        self.record(now=admitted + 35 * 60 - 1)
        with self.assertRaises(trial.Failure):
            trial.installer_bound(item, self.v, self.v['boot_uuid'], 'signal', -9)

    def test_hook_receives_only_a_returned_nonzero_tuple_never_launch_or_cleanup_exceptions(self):
        seen = []
        hook = lambda code, out: seen.append((code, out))
        for fault, (code, out) in (('exit', (17, b'native')), ('installer preflight refusal', (2, b'refused: no network')),
                                   ('signal', (-9, b'')), ('exit 255', (255, bytes(range(256))))):
            with self.subTest(fault), patch.object(trial, 'call_bounded', return_value=(code, out)):
                with self.assertRaises(trial.Failure) as raised:
                    trial.run(['/bin/x'], self.clock, 'stage', 235, on_failure=hook)
                self.assertEqual((raised.exception.code, raised.exception.child_status),
                                 (code if code > 0 else 128 - code, code))
        self.assertEqual(seen, [(17, b'native'), (2, b'refused: no network'), (-9, b''), (255, bytes(range(256)))])
        seen.clear()
        with patch.object(trial, 'call_bounded', return_value=(0, b'ok')):
            self.assertEqual(trial.run(['/bin/x'], self.clock, 'stage', 235, on_failure=hook), b'ok')
        for fault in (hhfab_release.Refusal('command timeout'), hhfab_release.Refusal('command output overflow'),
                      hhfab_release.Refusal(SENTINEL), OSError(SENTINEL), KeyboardInterrupt(), SystemExit(143)):
            with self.subTest(type(fault).__name__), patch.object(hhfab_release, 'bounded', side_effect=fault), \
                 self.assertRaises(BaseException):
                trial.run(['/bin/x'], self.clock, 'stage', 235, on_failure=hook)
        expired = Mock()
        expired.remaining.side_effect = trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
        with patch.object(trial, 'call_bounded', side_effect=AssertionError('never launched')), \
             self.assertRaises(trial.Failure):
            trial.run(['/bin/x'], expired, 'stage', 235, on_failure=hook)
        self.assertEqual(seen, [])  # launch refusal, timeout, overflow, spawn: no tuple, no record

    def test_every_diagnostic_base_exception_preserves_the_same_original_failure(self):
        real = trial.child_failure
        built = []
        def make(code, message):
            built.append(real(code, message))
            return built[-1]
        for fault in (KeyboardInterrupt(SENTINEL), SystemExit(143), trial.Failure('signal', 143, 'interrupted'),
                      trial.Failure('signal', 130, 'interrupted'), OSError(SENTINEL), RuntimeError(SENTINEL),
                      MemoryError()):
            with self.subTest(type(fault).__name__):
                built.clear()
                before_hook = []
                def hook(code, out, fault=fault):
                    before_hook.append(len(built))  # (a failed assert here would be swallowed, so record it)
                    raise fault
                with patch.object(trial, 'call_bounded', return_value=(17, b'native')), \
                     patch.object(trial, 'child_failure', side_effect=make):
                    with self.assertRaises(trial.Failure) as raised:
                        trial.run(['/bin/x'], self.clock, 'stage', 235, on_failure=hook)
                self.assertEqual(before_hook, [1])  # the original is constructed BEFORE diagnostic work
                self.assertIs(raised.exception, built[0])
                self.assertEqual((str(raised.exception), raised.exception.code, raised.exception.category,
                                  raised.exception.child_status), ('fixed child failed', 17, 'child-exit', 17))

    def test_real_stdlib_child_stderr_to_bounded_to_writer(self):
        hook = lambda code, out: trial.capture_installer_failure(self.v, self.clock, code, out)
        binary = bytes(range(256))
        cases = (
            ('exit 1', "import sys; sys.stderr.write('boom'); sys.exit(1)", 1, 'child-exit', b'boom'),
            ('exit 255 binary', "import sys; sys.stderr.buffer.write(bytes(range(256))); sys.stderr.flush(); sys.exit(255)",
             255, 'child-exit', binary),
            ('signal', "import os, signal, sys; sys.stderr.write('before'); sys.stderr.flush(); "
                       "os.kill(os.getpid(), signal.SIGKILL)", -9, 'child-signal', b'before'),
            ('mixed streams', "import sys; sys.stdout.write('out'); sys.stdout.flush(); sys.stderr.write('err'); sys.exit(3)",
             3, 'child-exit', None),
            ('large', "import sys; sys.stdout.write('A' * 20000 + 'Z'); sys.exit(4)", 4, 'child-exit', b'A' * 20000 + b'Z'),
        )
        for name, program, status, outcome, expected in cases:
            with self.subTest(name):
                self.final.unlink(missing_ok=True)
                with self.assertRaises(trial.Failure) as raised:
                    trial.run([sys.executable, '-c', program], self.clock, 'stage', 30, on_failure=hook)
                self.assertEqual((raised.exception.category, raised.exception.child_status), (outcome, status))
                info = self.final.lstat()
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid), (0o600, 1, os.getuid()))
                self.assertFalse(self.temp.exists())
                item = trial.installer_body(self.final.read_bytes())
                self.assertEqual((item['outcome'], item['status'], item['source_sha'], item['nonce'], item['lease'],
                                  item['boot']), (outcome.removeprefix('child-'), status, self.v['source_sha'], NONCE, self.v['lease'],
                                                  self.v['boot_uuid']))
                head, tail = base64.b64decode(item['head']), base64.b64decode(item['tail'])
                if expected is None:
                    self.assertIn(b'out', head)
                    self.assertIn(b'err', head)
                elif len(expected) <= trial.INSTALLER_WHOLE:
                    self.assertEqual((head, tail, item['omitted']), (expected, b'', 0))
                else:
                    self.assertEqual((item['output_status'], item['observed'], head, tail, item['omitted']),
                                     ('truncated', len(expected), expected[:1024], expected[-12288:],
                                      len(expected) - 13312))

    def test_launched_installer_style_preflight_refusal_stderr_is_captured(self):
        # Stdlib-only CLI mirrors install-docker's Refusal handler; no package code executes.
        program = ("import sys\nclass Refusal(Exception): pass\n"
                   "def preflight(): raise Refusal('fixture preflight refused')\n"
                   "try: preflight()\nexcept Refusal as exc:\n"
                   " sys.stderr.write('docker install: ' + str(exc) + '\\n'); sys.exit(1)\n")
        hook = lambda code, out: trial.capture_installer_failure(self.v, self.clock, code, out)
        with self.assertRaises(trial.Failure) as raised:
            trial.run([sys.executable, '-c', program], self.clock, 'stage', 30, on_failure=hook)
        self.assertEqual((raised.exception.category, raised.exception.child_status), ('child-exit', 1))
        item = trial.installer_body(self.final.read_bytes())
        self.assertEqual((item['outcome'], item['status']), ('exit', 1))
        self.assertEqual(base64.b64decode(item['head']), b'docker install: fixture preflight refused\n')
        self.assertEqual((item['tail'], item['omitted']), ('', 0))

    def test_installer_writer_and_exporter_refuse_wrong_owner_root_and_record(self):
        self.terminal()
        raw = self.record(b'native', 17)
        original_lstat = Path.lstat
        def foreign_root(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path == self.root:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
            return info
        with patch.object(Path, 'lstat', foreign_root):
            with self.assertRaises(trial.Failure):
                trial.write_installer_failure(raw, self.clock)
            with self.assertRaises(trial.Failure):
                trial.export_failure(NONCE)
        self.assertFalse(self.final.exists() or self.temp.exists())
        trial.write_installer_failure(raw, self.clock)
        original_fstat = os.fstat
        inode = self.final.stat().st_ino
        seen = []
        def foreign_record(fd):
            info = original_fstat(fd)
            if info.st_ino == inode:
                seen.append(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_size=info.st_size, st_uid=os.geteuid() + 1)
            return info
        with patch.object(os, 'fstat', side_effect=foreign_record), \
             patch.object(trial, 'regular', side_effect=lambda p, n, uid=None, mode=None:
                          REAL_REGULAR(p, n, os.geteuid() if p == self.final else None, mode)), \
             self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.final.read_bytes(), raw)
        self.assertFalse(self.temp.exists())

    def test_installer_exporter_refuses_replaced_and_changed_open_descriptors_without_retry(self):
        self.terminal()
        raw = self.record(b'native', 17)
        for action in ('replace', 'append'):
            with self.subTest(action=action):
                self.final.unlink(missing_ok=True)
                trial.write_installer_failure(raw, self.clock)
                with ExitStack() as local:
                    tap = DescriptorTap(self.root, trial.INSTALLER_FAILURE, json.loads(raw), action=action).install(local)
                    with self.assertRaises(trial.Failure):
                        trial.export_failure(NONCE)
                self.assertEqual((tap.opened, tap.calls), (1, 2))  # strict immutable reader never recovers
                self.assertTrue(tap.changed())
                self.assertFalse(self.temp.exists())
                if action == 'replace':
                    self.assertIn((trial.INSTALLER_FAILURE + '.next', trial.INSTALLER_FAILURE), tap.replaced)
                    self.assertEqual(self.final.read_bytes(), raw)
                else:
                    self.assertEqual(self.final.read_bytes(), raw + b' ')

    def test_writer_first_record_wins_with_owner_mode_single_link_and_no_leftovers(self):
        first, second = self.record(b'one'), self.record(b'two')
        trial.write_installer_failure(first, self.clock)
        trial.write_installer_failure(second, self.clock)  # a later failure never replaces the first writer
        info = self.final.lstat()
        self.assertEqual((self.final.read_bytes(), stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid),
                         (first, 0o600, 1, os.getuid()))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['contract.json', trial.INSTALLER_FAILURE])
        self.assertEqual(trial.regular(self.final, trial.INSTALLER_LIMIT, 0, 0o600), first)

    def test_writer_io_failures_leave_no_partial_final_and_no_temp(self):
        real_write, real_close = os.write, os.close
        writes = []
        def partial(fd, view):
            writes.append(fd)
            if len(writes) == 1:
                return real_write(fd, bytes(view[:5]))
            raise OSError(SENTINEL)
        def closing(fd):
            real_close(fd)
            raise OSError(SENTINEL)
        faults = {
            'partial write': patch.object(os, 'write', side_effect=partial),
            'write error': patch.object(os, 'write', side_effect=OSError(SENTINEL)),
            'zero write': patch.object(os, 'write', return_value=0),
            'fsync': patch.object(os, 'fsync', side_effect=OSError(SENTINEL)),
            'fchmod': patch.object(os, 'fchmod', side_effect=OSError(SENTINEL)),
            'link': patch.object(os, 'link', side_effect=OSError(SENTINEL)),
            'close': patch.object(os, 'close', side_effect=closing),
        }
        raw = self.record(b'native')
        for name, fault in faults.items():
            with self.subTest(name):
                writes.clear()
                with fault, self.assertRaises(BaseException):
                    trial.write_installer_failure(raw, self.clock)
                self.assertFalse(self.final.exists() or self.final.is_symlink())
                self.assertFalse(self.temp.exists())
        with self.subTest('expired stage before publication'):
            expired = Mock()
            expired.remaining.side_effect = trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
            with self.assertRaises(trial.Failure):
                trial.write_installer_failure(raw, expired)
            self.assertFalse(self.final.exists() or self.temp.exists())
            with self.assertRaises(trial.Failure):
                trial.capture_installer_failure(self.v, expired, 17, b'x')
            self.assertFalse(self.final.exists() or self.temp.exists())
        with self.subTest('then a clean write still works'):
            trial.write_installer_failure(raw, self.clock)
            self.assertEqual(self.final.read_bytes(), raw)

    def test_writer_refuses_collisions_links_and_unsafe_root_without_adopting_them(self):
        raw = self.record(b'native')
        elsewhere = self.base / 'elsewhere'
        elsewhere.write_bytes(b'UNTOUCHED')
        self.temp.write_bytes(b'PARTIAL')
        with self.assertRaises(FileExistsError):  # a leftover temp is never adopted or published
            trial.write_installer_failure(raw, self.clock)
        self.assertEqual((self.temp.read_bytes(), self.final.exists()), (b'PARTIAL', False))
        self.temp.unlink()
        self.temp.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            trial.write_installer_failure(raw, self.clock)
        self.assertEqual(elsewhere.read_bytes(), b'UNTOUCHED')
        self.temp.unlink()
        self.final.symlink_to(elsewhere)  # an existing name (even a link) is an earlier writer; nothing follows it
        trial.write_installer_failure(raw, self.clock)
        self.assertEqual((elsewhere.read_bytes(), self.final.is_symlink(), self.temp.exists()),
                         (b'UNTOUCHED', True, False))
        self.final.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(trial.Failure):
            trial.write_installer_failure(raw, self.clock)
        self.root.chmod(0o700)
        link = self.base / 'rootlink'
        link.symlink_to(self.root)
        with patch.object(trial, 'ROOT', link), self.assertRaises(trial.Failure):
            trial.write_installer_failure(raw, self.clock)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['contract.json'])

    def test_exporter_builds_envelope_from_contract_boot_and_validated_terminal_only(self):
        detail = self.terminal()
        self.assertEqual(trial.export_failure(NONCE), b'absent')
        trial.capture_installer_failure(self.v, self.clock, 17, b'native \xff output')
        with patch.object(trial, 'load_sibling', side_effect=AssertionError('no core load')), \
             patch.object(trial.subprocess, 'Popen', side_effect=AssertionError('no query child')):
            raw = trial.export_failure(NONCE)
        first, separator, rest = raw.partition(b'\n')
        self.assertEqual(separator, b'\n')
        self.assertEqual(json.loads(first), {
            'schema': 2, 'kind': 'installer', 'source_sha': self.v['source_sha'], 'nonce': NONCE,
            'lease': self.v['lease'], 'boot': self.v['boot_uuid'], 'phase': 'stage', 'operation': 'install-docker',
            'outcome': 'exit', 'status': detail['child_status']})
        self.assertEqual(rest, self.final.read_bytes())
        self.assertEqual(trial.installer_body(rest)['status'], 17)
        self.terminal('child-signal', -9)
        self.final.unlink()
        trial.capture_installer_failure(self.v, self.clock, -9, b'')
        self.assertEqual(json.loads(trial.export_failure(NONCE).partition(b'\n')[0])['outcome'], 'signal')

    def test_exporter_refuses_every_mismatched_unsafe_or_stale_record(self):
        self.terminal()
        other = '33333333-3333-4333-8333-333333333333'
        admitted = trial.stamp(self.v['admitted_at'])
        def edited(**changes):
            return trial.encoded(dict(json.loads(self.record(b'native', code=17)), **changes))
        good = self.record(b'native', code=17)
        self.final.write_bytes(good)
        self.final.chmod(0o600)
        exported = trial.export_failure(NONCE)
        self.assertEqual(exported.partition(b'\n')[2], good)
        self.assertEqual(json.loads(exported.partition(b'\n')[0])['status'], 17)
        cases = {
            'foreign nonce': edited(nonce='9' * 32), 'foreign source': edited(source_sha='d' * 40),
            'foreign lease': edited(lease=other), 'foreign boot': edited(boot=other),
            'status vs terminal': edited(status=18), 'outcome vs terminal': edited(outcome='signal', status=-9),
            'captured before admission': edited(captured_at=int(admitted - 5)),
            'captured at stage cutoff': edited(captured_at=int(admitted + 35 * 60)),
            'extra field': edited(extra=1), 'bool schema': edited(schema=True),
            'cross kind': edited(kind='first-failure'), 'truncated file': good[:-1], 'empty file': b'',
            'oversize file': good + b' ' * trial.INSTALLER_LIMIT, 'legacy bundle name content': b'{}',
        }
        for name, raw in cases.items():
            with self.subTest(name):
                self.final.unlink(missing_ok=True)
                self.final.write_bytes(raw)
                self.final.chmod(0o600)
                with self.assertRaises(trial.Failure):
                    trial.export_failure(NONCE)
        for name in ('wide mode', 'hard link', 'symlink', 'directory'):
            with self.subTest(name):
                if self.final.is_dir() and not self.final.is_symlink():
                    self.final.rmdir()
                else:
                    self.final.unlink(missing_ok=True)
                extra = self.base / 'extra'
                extra.unlink(missing_ok=True)
                if name == 'symlink':
                    extra.write_bytes(good)
                    extra.chmod(0o600)
                    self.final.symlink_to(extra)
                elif name == 'directory':
                    self.final.mkdir(mode=0o700)
                else:
                    self.final.write_bytes(good)
                    self.final.chmod(0o640 if name == 'wide mode' else 0o600)
                    if name == 'hard link':
                        os.link(self.final, extra)
                with self.assertRaises((trial.Failure, OSError)):
                    trial.export_failure(NONCE)
        self.final.rmdir()  # the last unsafe fixture is a directory
        extra = self.base / 'extra'
        self.final.write_bytes(good)
        self.final.chmod(0o600)
        with self.assertRaises(trial.Failure):
            trial.export_failure('9' * 32)
        for wrong in (dict(self.v, boot_uuid=other),):
            (self.root / 'contract.json').write_bytes(trial.encoded(wrong))
            with self.assertRaises(trial.Failure):
                trial.export_failure(NONCE)
        (self.root / 'contract.json').write_bytes(trial.encoded(self.v))
        late = SimpleNamespace(time=lambda: trial.stamp(self.v['deadline']) + 1, monotonic=time.monotonic, sleep=time.sleep)
        with patch.object(trial, 'time', late), self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)
        self.terminal('child-signal', -9)  # terminal outcome differs from the exit record
        with self.assertRaises(trial.Failure):
            trial.export_failure(NONCE)

    def test_only_a_validated_installer_terminal_selects_the_file_only_mode(self):
        trial.capture_installer_failure(self.v, self.clock, 17, b'native')
        class Core(Exception):
            pass
        def foreign_nonce():
            detail = self.terminal()
            (self.root / 'result.json').write_bytes(trial.encoded(
                {'schema': 2, 'code': 17, 'contained': True, 'nonce': '9' * 32, 'diagnostic': detail}))
        def wide_mode():
            self.terminal()
            (self.root / 'result.json').chmod(0o644)
        for name, prepare in (('no terminal', lambda: None),
                              ('other stage operation', lambda: self.terminal(operation='install-hhfab')),
                              ('foreign nonce', foreign_nonce), ('unsafe file mode', wide_mode)):
            with self.subTest(name):
                (self.root / 'result.json').unlink(missing_ok=True)
                prepare()
                with patch.object(trial, 'load_sibling', side_effect=Core), self.assertRaises(Core):
                    trial.export_failure(NONCE)  # fell through to the unchanged core path, never the record
        self.assertFalse(trial.installer_terminal(None))
        for detail in ({'origin': 'worker', 'phase': 'stage', 'operation': 'install-docker', 'category': 'child-exit',
                        'child_status': None},
                       {'origin': 'guardian', 'phase': 'stage', 'operation': 'worker-supervision',
                        'category': 'child-exit', 'child_status': 17},
                       {'origin': 'worker', 'phase': 'stage', 'operation': 'install-docker', 'category': 'child-timeout',
                        'child_status': None},
                       {'origin': 'worker', 'phase': 'stage', 'operation': 'install-docker', 'category': 'child-exit',
                        'child_status': True}):
            with self.subTest(detail=detail):
                self.assertFalse(trial.installer_terminal(detail))
        self.assertTrue(trial.installer_terminal({'origin': 'worker', 'phase': 'stage', 'operation': 'install-docker',
                                                  'category': 'child-signal', 'child_status': -9}))

    # -- auxiliary APT update uses the same private record, bound to its own exact operation ----
    def aux_run(self, faults=None, capture=None):
        """Run the ACTUAL provision_aux; only the bounded child and package inventory are faked.

        -> (raised exception or None, ordered list of the apt step names that were launched).
        """
        faults, seen = faults or {}, []
        before = {name: '1' for name in trial.AUX if name != 'socat'}
        after = dict(before, socat='1.8.0.0-4ubuntu0.1')
        def bounded(args, seconds, **kwargs):
            step = 'update' if 'update' in args else 'check' if 'check' in args else 'other'
            seen.append(step)
            fault = faults.get(step)
            if isinstance(fault, BaseException):
                raise fault
            if fault is not None:
                return fault
            if '--simulate' in args:
                return 0, b'Inst socat (1.8.0.0-4ubuntu0.1 Ubuntu:24.04/noble [amd64])\n'
            return 0, b''
        error = None
        with ExitStack() as local:
            local.enter_context(patch.object(trial, 'APT_TMP', self.base))
            local.enter_context(patch.object(trial, 'installed', side_effect=[before, after]))
            local.enter_context(patch.object(trial, 'run', return_value=b''))
            local.enter_context(patch.object(hhfab_release, 'bounded', side_effect=bounded))
            if capture is not None:
                local.enter_context(patch.object(trial, 'capture_installer_failure', side_effect=capture))
            try:
                trial.provision_aux(self.clock, self.v)
            except BaseException as caught:
                error = caught
        return error, seen

    def test_actual_aux_update_exit_failure_writes_the_private_record_for_that_exact_operation(self):
        output = b'E: Failed to fetch https://example.invalid/ 503\n\xff\x00'
        error, seen = self.aux_run({'update': (100, output)})
        self.assertIsInstance(error, trial.Failure)
        self.assertEqual((str(error), error.code, error.category, error.child_status),
                         ('authenticated auxiliary APT refused', 100, 'child-exit', 100))
        self.assertEqual(seen, ['update'])  # the later steps never ran
        item = trial.installer_body(self.final.read_bytes())
        self.assertEqual((item['operation'], item['outcome'], item['status'], item['observed']),
                         ('aux-update', 'exit', 100, len(output)))
        self.assertEqual(base64.b64decode(item['head']), output)
        self.assertFalse(self.temp.exists())
        self.assertFalse(list(self.base.glob('labapp-vlab-aux-*')))  # cleanup still ran
        # the guest exporter binds the SAME operation from the validated terminal
        self.terminal('child-exit', 100, 'aux-update')
        exported = trial.export_failure(NONCE)
        self.assertEqual(json.loads(exported.partition(b'\n')[0])['operation'], 'aux-update')
        self.assertEqual(exported.partition(b'\n')[2], self.final.read_bytes())
        # signal exit from update is captured as a signal
        self.final.unlink()
        error, _ = self.aux_run({'update': (-9, b'')})
        self.assertEqual((error.code, error.category, error.child_status), (137, 'child-signal', -9))
        self.assertEqual(trial.installer_body(self.final.read_bytes())['outcome'], 'signal')

    def test_aux_update_capture_is_attached_only_to_the_update_invocation(self):
        calls = []
        for step in ('check', 'other'):
            calls.clear()
            error, seen = self.aux_run({step: (100, b'x')}, capture=lambda *a, **k: calls.append(a))
            self.assertIsInstance(error, trial.Failure)
            self.assertIn(step, seen)
            self.assertEqual(calls, [])
            self.assertFalse(self.final.exists())
        error, seen = self.aux_run(capture=lambda *a, **k: calls.append(a))
        self.assertIsNone(error)  # success captures nothing
        self.assertEqual(calls, [])
        self.assertFalse(self.final.exists())
        error, _ = self.aux_run({'update': (100, b'x')}, capture=lambda *a, **k: calls.append((a, k)))
        self.assertEqual(len(calls), 1)
        self.assertEqual((calls[0][0][2], calls[0][0][3]), (100, b'x'))
        self.assertIn('aux-update', calls[0][0][4:] + tuple(calls[0][1].values()))
        # without the trusted contract nothing can be captured
        with ExitStack() as local:
            local.enter_context(patch.object(trial, 'APT_TMP', self.base))
            local.enter_context(patch.object(trial, 'installed', return_value={}))
            local.enter_context(patch.object(trial, 'run', return_value=b''))
            local.enter_context(patch.object(hhfab_release, 'bounded', return_value=(100, b'x')))
            local.enter_context(patch.object(trial, 'capture_installer_failure', side_effect=AssertionError('no hook')))
            with self.assertRaises(trial.Failure):
                trial.provision_aux(self.clock)

    def test_aux_update_no_tuple_exceptions_create_no_record(self):
        for name, fault, expected in (
                ('timeout', hhfab_release.Refusal('command timeout'), (124, 'child-timeout')),
                ('overflow', hhfab_release.Refusal('command output overflow'), (1, 'output-overflow')),
                ('other refusal', hhfab_release.Refusal(SENTINEL), (1, 'exception')),
                ('spawn failure', OSError(SENTINEL), None)):
            with self.subTest(name):
                calls = []
                error, seen = self.aux_run({'update': fault}, capture=lambda *a, **k: calls.append(a))
                self.assertEqual(calls, [])
                self.assertFalse(self.final.exists() or self.temp.exists())
                if expected is None:
                    self.assertIsInstance(error, OSError)
                else:
                    self.assertEqual((error.code, error.category), expected)
                    self.assertNotIn(SENTINEL, str(error))

    def test_aux_update_hook_faults_never_replace_the_identical_original_failure(self):
        real_child, built = trial.child_failure, []
        def make(code, message):
            built.append(real_child(code, message))
            return built[-1]
        for fault in (OSError(SENTINEL), KeyboardInterrupt(), SystemExit(143), trial.Failure('signal', 143, 'interrupted'),
                      RuntimeError(SENTINEL)):
            with self.subTest(type(fault).__name__):
                built.clear()
                with patch.object(trial, 'child_failure', side_effect=make):
                    error, _ = self.aux_run({'update': (100, b'x')}, capture=fault)
                self.assertEqual(len(built), 1)
                self.assertIs(error, built[0])  # the SAME object, constructed before the hook ran
                self.assertIsNone(error.__context__)
                self.assertEqual((str(error), error.code, error.category, error.child_status),
                                 ('authenticated auxiliary APT refused', 100, 'child-exit', 100))
        # real writer I/O faults reached through the real hook
        real_capture, attempted = trial.capture_installer_failure, []
        for name in ('open', 'link', 'fsync'):
            def capture(v, clock, code, out, operation, name=name):
                # Inject only while the real aux-update capture runs; APT setup/cleanup stay real.
                with patch.object(os, name, side_effect=OSError(SENTINEL)) as injected:
                    try:
                        real_capture(v, clock, code, out, operation)
                    finally:
                        attempted.append((name, operation, injected.called))
            with self.subTest('writer ' + name):
                built.clear()
                with patch.object(trial, 'child_failure', side_effect=make):
                    error, _ = self.aux_run({'update': (100, b'x')}, capture=capture)
                self.assertEqual(attempted[-1], (name, 'aux-update', True))  # reached the real writer
                self.assertIs(error, built[0])
                self.assertEqual((error.code, error.category, error.child_status), (100, 'child-exit', 100))
                self.assertFalse(self.final.exists() or self.temp.exists())
        # a stage cutoff passed before capture: primary stays, no record
        expired = Mock()
        expired.remaining.side_effect = [100, trial.Failure('deadline', 124, 'phase-cutoff')] + [100] * 20
        with ExitStack() as local:
            local.enter_context(patch.object(trial, 'APT_TMP', self.base))
            local.enter_context(patch.object(trial, 'installed', return_value={}))
            local.enter_context(patch.object(trial, 'run', return_value=b''))
            local.enter_context(patch.object(hhfab_release, 'bounded', return_value=(100, b'x')))
            with self.assertRaises(trial.Failure) as raised:
                trial.provision_aux(expired, self.v)
        self.assertEqual((raised.exception.code, raised.exception.category), (100, 'child-exit'))
        self.assertFalse(self.final.exists())

    def test_operation_is_a_separate_closed_allowance_bound_identically_by_body_envelope_and_terminal(self):
        self.assertEqual(trial.INSTALLER_OPERATION, 'install-docker')  # scalar default unchanged
        self.assertEqual(trial.INSTALLER_OPERATIONS, ('install-docker', 'aux-update'))
        docker, aux = self.record(b'd', 100), trial.installer_record(
            self.v, self.v['boot_uuid'], 100, b'a', time.time(), 'aux-update')
        self.assertEqual(trial.installer_body(docker)['operation'], 'install-docker')
        self.assertEqual(trial.installer_body(aux)['operation'], 'aux-update')
        for operation in ('aux-check', 'install-hhfab', '', None, ['aux-update'], 'AUX-UPDATE'):
            with self.subTest(operation=operation), self.assertRaises(trial.Failure):
                trial.installer_record(self.v, self.v['boot_uuid'], 100, b'a', time.time(), operation)
            body = dict(json.loads(aux), operation=operation)
            with self.subTest(body=operation), self.assertRaises((trial.Failure, TypeError)):
                trial.installer_body(trial.encoded(body))
        for item_op, bound_op in (('install-docker', 'aux-update'), ('aux-update', 'install-docker')):
            item = trial.installer_body(docker if item_op == 'install-docker' else aux)
            with self.subTest(item=item_op, bound=bound_op), self.assertRaises(trial.Failure):
                trial.installer_bound(item, self.v, self.v['boot_uuid'], operation=bound_op)
        # exporter: stored body vs validated terminal, both directions, even though each is self-consistent
        for stored, terminal_op in ((docker, 'aux-update'), (aux, 'install-docker')):
            with self.subTest(stored=json.loads(stored)['operation'], terminal=terminal_op):
                self.final.unlink(missing_ok=True)
                self.final.write_bytes(stored)
                self.final.chmod(0o600)
                self.terminal('child-exit', 100, terminal_op)
                with self.assertRaises(trial.Failure):
                    trial.export_failure(NONCE)
        for stored, terminal_op in ((docker, 'install-docker'), (aux, 'aux-update')):
            self.final.unlink(missing_ok=True)
            self.final.write_bytes(stored)
            self.final.chmod(0o600)
            self.terminal('child-exit', 100, terminal_op)
            first = json.loads(trial.export_failure(NONCE).partition(b'\n')[0])
            self.assertEqual(first['operation'], terminal_op)
        # other auxiliary terminals never select the file-only installer mode
        for operation in ('aux-check', 'aux-download', 'aux-install', 'aux-setup'):
            self.assertFalse(trial.installer_terminal({'origin': 'worker', 'phase': 'stage', 'operation': operation,
                                                       'category': 'child-exit', 'child_status': 100}))
        self.assertTrue(trial.installer_terminal({'origin': 'worker', 'phase': 'stage', 'operation': 'aux-update',
                                                  'category': 'child-exit', 'child_status': 100}))
        for operation in (['aux-update'], None, b'aux-update'):
            self.assertFalse(trial.installer_terminal({'origin': 'worker', 'phase': 'stage', 'operation': operation,
                                                       'category': 'child-exit', 'child_status': 100}))


# ---- Fixed source-inactive management program (#506): synthetic only ---------------------------------
# No native k3d/Helm/kubectl/Docker/cloud child is ever started: call_bounded/stdin_bounded/http are
# replaced by in-memory models of the DOCUMENTED responses the program consumes. They model the
# interface; they are not native validation of Prometheus, Grafana, k3d or Helm behaviour.
import io
import subprocess
import urllib.parse


def load_management():
    import management_trial
    return management_trial


MGMT_BOOT = '22222222-2222-4222-8222-222222222222'


def is_push(args):
    return any(a.endswith('promtool') for a in args)


class ManagementModel:
    """Recorder plus deterministic stand-ins for kubectl, promtool, Prometheus and Grafana."""
    def __init__(self, m, test):
        self.m, self.test = m, test
        self.calls, self.envs, self.stdin = [], [], []
        self.samples, self.pushes, self.deleted = {}, 0, []
        self.uids = {'prometheus': 'p-1', 'grafana': 'g-1'}
        self.claims = {'prom-claim': {'uid': 'c-1', 'storage': '8Gi'}, 'graf-claim': {'uid': 'c-2', 'storage': '1Gi'}}
        self.query_error = False
        self.role, self.viewer_admin, self.viewer_settings, self.users = 'Viewer', False, 403, {}
        self.admin = None
        self.sample_age = 0
        self.datasources = [{'uid': 'prom-uid', 'type': 'prometheus'}, {'uid': 'am-uid', 'type': 'alertmanager'}]
        # Grafana assigns the UID at provisioning (the pinned chart source has uid ""); the stand-in generates one.
        self.generated_uid = 'Gx7-generated_01'
        self.search_status = 200
        self.search_rows = [{'uid': self.generated_uid, 'title': 'Prometheus / Overview', 'type': 'dash-db',
                             'tags': ['prometheus-mixin']}]
        self.dashboard = {'meta': {'canSave': False, 'canEdit': False, 'canAdmin': False},
                          'dashboard': {'uid': self.generated_uid, 'title': 'Prometheus / Overview',
                                        'templating': {'list': [{'name': 'datasource', 'type': 'datasource',
                                                                 'query': 'prometheus'}]},
                                        'panels': [{'id': 1, 'type': 'row', 'panels': [],
                                                    'title': 'Prometheus Stats'},
                                                   {'id': 7, 'title': 'Head Series', 'type': 'graph',
                                                    'datasource': '$datasource'}]}}

    def run(self, args, env=None, data=None):
        args = [str(a) for a in args]
        self.calls.append(args)
        self.envs.append(env)
        if data is not None:
            self.stdin.append(data)
        m = self.m
        if args[0] == m.K3D and args[1:3] == ['kubeconfig', 'write']:
            out = Path(args[args.index('--output') + 1])
            out.write_bytes(b'synthetic-private-kubeconfig')
            out.chmod(0o644)
        if 'LoadState' in args:
            return 0, b'LoadState=not-found\n'
        if 'get-contexts' in args:
            return 0, (m.CONTEXT + '\n').encode()
        if is_push(args):
            label, number = re.search(rb'nonce="([a-f0-9]{16})"\} ([0-9]+)', data).groups()
            self.pushes += 1
            self.samples[label.decode()] = (time.time() - self.sample_age, number.decode())
            return 0, b''
        if args[0] == m.KUBECTL and 'get' in args and '--selector' in args:
            kind = 'prometheus' if 'prometheus' in args[args.index('--selector') + 1] else 'grafana'
            return 0, json.dumps({'items': [{'metadata': {'name': kind + '-0', 'uid': self.uids[kind]},
                'status': {'phase': 'Running', 'containerStatuses': [{'ready': True}],
                           'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}).encode()
        if args[0] == m.KUBECTL and 'persistentvolumeclaims' in args:
            return 0, json.dumps({'items': [{'metadata': {'name': n, 'uid': c['uid']}, 'status': {'phase': 'Bound'},
                'spec': {'resources': {'requests': {'storage': c['storage']}}}} for n, c in self.claims.items()]}).encode()
        if args[0] == m.KUBECTL and 'delete' in args and 'pod' in args:
            name = args[args.index('pod') + 1]
            self.deleted.append(name)
            self.uids[name.split('-')[0]] += 'x'
        return 0, b''

    def http(self, method, url, *, auth=None, body=None, timeout=None):
        parsed = urllib.parse.urlparse(url)
        if parsed.port == 9090:
            if parsed.path == '/-/ready':
                return 200, b'ready'
            if self.query_error:
                return 400, b''
            query = urllib.parse.parse_qs(parsed.query)
            expression = query['query'][0]
            label = re.search(r'nonce="([a-f0-9]{16})"', expression).group(1)
            metric = {'__name__': self.m.PROBE_METRIC, 'nonce': label, 'job': 'promtool'}
            found = self.samples.get(label)
            if expression.endswith('[2m]'):
                rows = [] if found is None else [{'metric': metric, 'values': [[found[0], found[1]]]}]
                data = {'resultType': 'matrix', 'result': rows}
            else:
                rows = [] if found is None else [{'metric': metric, 'value': [float(query['time'][0]), found[1]]}]
                data = {'resultType': 'vector', 'result': rows}
            return 200, json.dumps({'status': 'success', 'data': data}).encode()
        path = parsed.path
        if path == '/api/health':
            return 200, b'{"database":"ok"}'
        if path == '/api/admin/users':
            self.test.assertEqual(auth, self.admin)
            self.users[body['login']] = body['password']
            return 200, b'{"id":2}'
        if path == '/api/org/users':
            self.test.assertEqual(auth, self.admin)
            return 200, json.dumps([{'login': 'admin', 'role': 'Admin'}] +
                                   [{'login': n, 'role': self.role} for n in self.users]).encode()
        if path == '/api/user':
            self.test.assertEqual(self.users.get(auth[0]), auth[1])
            return 200, json.dumps({'login': auth[0], 'isGrafanaAdmin': self.viewer_admin}).encode()
        if path == '/api/admin/settings':
            return self.viewer_settings, b'{}'
        if path == '/api/datasources':
            return 200, json.dumps(self.datasources).encode()
        if path == '/api/search':
            self.test.assertEqual(auth[0][:14], 'labapp-viewer-')  # discovery runs as the Viewer only
            query = urllib.parse.parse_qs(parsed.query)
            self.test.assertEqual((query['type'], query['tag'], query['query']),
                                  (['dash-db'], ['prometheus-mixin'], ['Prometheus / Overview']))
            return self.search_status, json.dumps(self.search_rows).encode()
        if path.startswith('/api/dashboards/uid/'):
            self.test.assertEqual(auth[0][:14], 'labapp-viewer-')
            self.test.assertEqual(path.rsplit('/', 1)[1], self.search_rows[0]['uid'])
            return 200, json.dumps(self.dashboard).encode()
        raise AssertionError('unmodelled endpoint ' + path)


class ManagementProgram(unittest.TestCase):
    def setUp(self):
        self.m = load_management()
        self.real_http = self.m.http
        original = os.umask(0o077)
        os.umask(original)
        self.addCleanup(os.umask, original)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-mgmt-')))
        self.root = self.temp / 'root'
        (self.root / 'work').mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        for name, path in (('MROOT', self.root), ('WORK', self.root / 'work'),
                           ('KUBECONFIG', self.root / 'work' / 'kubeconfig'), ('STORAGE', self.temp / 'storage')):
            self.stack.enter_context(patch.object(self.m, name, path))
        self.stack.enter_context(patch.object(trial, 'regular',
                                 side_effect=lambda p, limit, uid=None, mode=None: REAL_REGULAR(p, limit, None, mode)))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=MGMT_BOOT))
        self.stack.enter_context(patch.object(time, 'sleep'))
        self.stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('no native child')))
        self.model = ManagementModel(self.m, self)
        self.stack.enter_context(patch.object(trial, 'call_bounded',
                                 side_effect=lambda args, seconds, env=None: self.model.run(args, env)))
        self.stack.enter_context(patch.object(self.m, 'stdin_bounded',
                                 side_effect=lambda argv, seconds, data, env, limit=1024**2, watch=None:
                                 self.model.run(argv, env, data or None)))
        self.stack.enter_context(patch.object(self.m, 'http', side_effect=self.model.http))
        self.reset(value())

    def reset(self, contract):
        self.value = contract
        for name in ('contract.json', 'heartbeat.json', 'steps.json'):
            (self.root / name).unlink(missing_ok=True)
        trial.exclusive(self.root / 'contract.json', trial.encoded(contract))
        trial.exclusive(self.root / 'heartbeat.json', trial.encoded({'sequence': 0, 'received': time.monotonic()}))
        trial.exclusive(self.root / 'steps.json', trial.encoded(self.m.initial_state(NONCE)))

    def context(self):
        return self.m.Context(self.value, self.m.ManagementClock(self.value), self.m.load_state(NONCE))

    def admitted_ago(self, minutes):
        start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=minutes)
        contract = value()
        contract['admitted_at'] = start.strftime('%Y-%m-%dT%H:%M:%SZ')
        contract['deadline'] = (start + timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return contract

    def redaction_text(self):
        return json.dumps(self.m.public_record(self.m.load_state(NONCE)))

    # -- activation, tables, unchanged VLAB ---------------------------------------------------
    def test_activation_is_held_without_any_bypass(self):
        m = self.m
        self.assertTrue(m.ACTIVATION_BLOCKERS)
        with patch.dict(os.environ, {'LABAPP_MANAGEMENT_ACTIVE': '1', 'ACTIVATE': 'yes'}):
            for call in (m.refuse_activation, lambda: m.main(['step', '--nonce', NONCE, '--name', 'storage']),
                         lambda: m.bootstrap(self.temp, 'a' * 64)):
                with self.assertRaises(trial.Failure) as raised:
                    call()
                self.assertEqual(str(raised.exception), 'management activation held')
        import inspect
        self.assertEqual(list(inspect.signature(m.main).parameters), ['argv'])
        self.assertEqual(list(inspect.signature(m.bootstrap).parameters), ['incoming', 'expected_manifest'])
        self.assertEqual(self.model.calls, [])

    def test_fixed_closed_tables_and_unchanged_vlab(self):
        m = self.m
        self.assertEqual(set(m.STEP_FUNCTIONS), set(m.STEP_NAMES))
        self.assertEqual(len(m.STEP_NAMES), len(set(m.STEP_NAMES)))
        self.assertTrue(set(m.STEP_PHASE.values()) <= set(m.MGMT_PHASES))
        self.assertEqual(m.FILES, {*m.SOURCES, *m.PAYLOADS, 'contract.json', 'capsule.json'})
        self.assertEqual(set(m.UNIT_NAMES), {n for n in m.SOURCES if n.startswith('labapp-management-')})
        self.assertEqual(len(m.UNIT_NAMES), 3)
        for name, path in m.SOURCES.items():
            self.assertEqual(path, 'build/provision/' + name)
            self.assertTrue((Path(__file__).parent / name).is_file(), name)
        self.assertNotIn('k3d', m.PAYLOADS)  # size unpinned: runtime download, never a verified byte count
        self.assertIsNone(m.IMAGE_INVENTORY['k3d-loadbalancer'])
        self.assertEqual(m.IMAGE_INVENTORY['k3s-server'], 'docker.io/rancher/k3s@sha256:'
                         '81fc7349ba265f842f9b67311fabd9e7d72698798ba513b7cdf41ffdf1e923e4')
        self.assertEqual(m.MANAGEMENT_IMAGE, m.IMAGE_INVENTORY['k3s-server'])
        self.assertEqual(trial.PHASES, {'access': 15, 'stage': 35, 'fresh': 70, 'strict': 80, 'resume': 95, 'persistence': 105})
        self.assertEqual(set(trial.PAYLOADS), {'hhfab.tar.gz', 'kubectl'})
        self.assertFalse(any('management' in name for name in trial.SOURCES))

    def test_pins_reuse_accepted_ledgers_without_a_second_pin(self):
        import importlib.util
        for installer in ('install-helm.py', 'install-kubectl.py'):
            spec_ = importlib.util.spec_from_file_location('pin_' + installer[8:-3], Path(__file__).with_name(installer))
            module = importlib.util.module_from_spec(spec_)
            spec_.loader.exec_module(module)
            pin = module.PINS[module.VERSION]
            if installer == 'install-helm.py':
                self.assertEqual(self.m.PAYLOADS['helm.tar.gz'], (pin['archive_size'], pin['archive_sha256']))
            else:
                self.assertEqual(self.m.PAYLOADS['kubectl'], (pin['size'], pin['sha256']))
                self.assertIs(self.m.PAYLOADS['kubectl'], trial.PAYLOADS['kubectl'])
        ledger = Path(__file__).with_name('observability-inputs.yaml').read_text()
        chart = self.m.PAYLOADS['kube-prometheus-stack-65.2.0.tgz']
        self.assertIn('size: %d' % chart[0], ledger)
        self.assertIn('sha256: ' + chart[1], ledger)

    def test_manifest_rejects_foreign_missing_and_wrong_bytes(self):
        m = self.m
        files = {n: {'bytes': 5, 'sha256': 'b' * 64} for n in m.SOURCES}
        files['contract.json'] = {'bytes': 5, 'sha256': 'b' * 64}
        files['capsule.json'] = {'bytes': 5, 'sha256': 'b' * 64}
        for name, pin in m.PAYLOADS.items():
            files[name] = {'bytes': pin[0], 'sha256': pin[1]}
        good = {'schema': 1, 'source_sha': 'c' * 40, 'files': files}
        self.assertIs(m.manifest(good), good)
        for mutate in (lambda v: v['files'].pop('install-k3d.sh'), lambda v: v['files'].update(extra=files['contract.json']),
                       lambda v: v['files']['kubectl'].update(sha256='d' * 64),
                       lambda v: v['files']['helm.tar.gz'].update(bytes=1),
                       lambda v: v['files']['install-k3d.sh'].update(bytes=trial.MAX_SOURCE + 1),
                       lambda v: v.update(source_sha='x')):
            bad = deepcopy(good)
            mutate(bad)
            with self.assertRaises(trial.Failure):
                m.manifest(bad)

    # -- time ------------------------------------------------------------------------------------
    def test_management_clock_is_admission_anchored_clipped_and_never_renewed(self):
        m = self.m
        clock = m.ManagementClock(self.value)
        self.assertLess(clock.remaining('work'), 50 * 60)
        self.assertLess(clock.cleanup_remaining(), 60 * 60)
        self.assertLessEqual(m.CEILING_MINUTES, 60)
        self.assertGreater(m.CEILING_MINUTES, max(m.MGMT_PHASES.values()))
        with self.assertRaises(trial.Failure):
            clock.remaining('fresh')  # VLAB phase names are not management phases
        # a backwards wall jump cannot renew time: monotonic elapsed still counts
        wall, mono = [time.time()], [time.monotonic()]
        timed = m.ManagementClock(self.value, wall=lambda: wall[0], mono=lambda: mono[0])
        before = timed.remaining('work')
        wall[0] -= 3600
        mono[0] += 100
        self.assertLessEqual(timed.remaining('work'), before - 99)
        # the provider envelope itself is unchanged and still demanded of the contract
        bad = deepcopy(self.value)
        start = datetime.strptime(bad['admitted_at'], '%Y-%m-%dT%H:%M:%SZ')
        bad['deadline'] = (start + timedelta(minutes=60)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with self.assertRaises(trial.Failure):
            trial.contract(bad)

    def test_watch_http_and_poll_keep_the_original_context_clock_after_wall_rollback(self):
        m = self.m
        wall, mono = [time.time()], [time.monotonic()]
        clock = m.ManagementClock(self.value, wall=lambda: wall[0], mono=lambda: mono[0])
        ctx = m.Context(self.value, clock, m.load_state(NONCE))
        remaining = clock.remaining('work')
        watch = m.watcher(ctx, 'work', False)
        watch()
        m.ctx_gate(ctx)
        self.assertIs(m.gate(ctx.value, ctx.clock), clock)
        wall[0] -= 3600
        mono[0] += remaining + 1
        for check in (watch, lambda: m.ctx_gate(ctx), lambda: m.poll(ctx, 'work', 10, lambda: None)):
            with self.subTest(check=check), self.assertRaises(trial.Failure) as raised:
                check()
            self.assertEqual(raised.exception.category, 'phase-cutoff')
            self.assertIs(ctx.clock, clock)
        self.assertGreater(m.watcher(ctx, None, True)(), 0)

    def test_exhausted_work_keeps_the_cleanup_reserve_and_stops_new_steps(self):
        self.reset(self.admitted_ago(55))  # work ended at minute 37/38; cleanup runs to minute 60
        clock = self.m.ManagementClock(self.value)
        with self.assertRaises(trial.Failure) as raised:
            clock.remaining('work')
        self.assertEqual(raised.exception.code, 124)
        self.assertGreater(clock.cleanup_remaining(), 3 * 60)
        with self.assertRaises(trial.Failure):
            self.m.run_step(NONCE, 'install-docker')
        self.assertEqual(self.m.load_state(NONCE)['failure']['category'], 'phase-cutoff')
        self.assertEqual(self.model.calls, [])  # no child started after the cutoff
        self.assertEqual(self.m.teardown(NONCE), 1)  # cleanup still runs inside the reserve; never 'complete'
        self.assertTrue(self.m.load_state(NONCE)['private']['teardown_observed_clean'])
        self.reset(self.admitted_ago(61))
        with self.assertRaises(trial.Failure):
            self.m.ManagementClock(self.value).cleanup_remaining()

    # -- step gate: order, nonce, heartbeat, selector -------------------------------------------------
    def test_step_gate_order_nonce_heartbeat_and_no_arbitrary_selector(self):
        m = self.m
        with self.assertRaises(trial.Failure):
            m.run_step(NONCE, 'cluster')  # out of order
        with self.assertRaises(trial.Failure):
            m.run_step(NONCE, 'bash -c id')
        with self.assertRaises(trial.Failure):
            m.run_step('b' * 32, 'install-docker')  # wrong lease nonce
        self.assertEqual(self.model.calls, [])
        trial.atomic(self.root / 'heartbeat.json', {'sequence': 0, 'received': time.monotonic() - 60})
        with self.assertRaises(trial.Failure):
            m.run_step(NONCE, 'install-docker')
        state = m.load_state(NONCE)
        self.assertEqual((state['steps']['install-docker'], state['failure']['category']), ('failed', 'heartbeat-loss'))
        self.assertEqual(self.model.calls, [])
        with self.assertRaises(trial.Failure):
            m.run_step(NONCE, 'install-kubectl')  # sequence stopped after the first failure
        with patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
            m.dispatch(['step', '--nonce', NONCE, '--name', 'bash'])
        with patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
            m.dispatch(['run', '--nonce', NONCE])

    def test_boot_change_is_refused(self):
        with patch.object(trial, 'kernel_boot', return_value='33333333-3333-4333-8333-333333333333'):
            with self.assertRaises(trial.Failure):
                self.m.run_step(NONCE, 'install-docker')
        self.assertEqual(self.m.load_state(NONCE)['failure']['category'], 'boot-change')

    # -- native sequence -------------------------------------------------------------------------------
    def test_installers_use_accepted_pins_and_no_digest_or_url_override(self):
        m = self.m
        for name in ('install-docker', 'install-kubectl', 'install-helm', 'install-k3d', 'daemon-start'):
            m.STEP_FUNCTIONS[name](self.context())
        by_script = {c[1]: c for c in self.model.calls if c[0] in (m.PYTHON, m.BASH)}
        self.assertEqual(by_script[str(self.root / 'install-kubectl.py')][2:],
                         ['--version', '1.35.0', '--platform', 'linux/amd64', '--binary', str(self.root / 'kubectl')])
        self.assertEqual(by_script[str(self.root / 'install-helm.py')][2:],
                         ['--version', '3.19.4', '--platform', 'linux/amd64', '--archive', str(self.root / 'helm.tar.gz')])
        k3d_env = self.model.envs[self.model.calls.index(by_script[str(self.root / 'install-k3d.sh')])]
        self.assertFalse([k for k in k3d_env if k.startswith(('K3D_SHA', 'K3D_BASE', 'K3D_INSTALL', 'K3D_IMAGE', 'K3D_HELPER'))])
        self.assertIn('K3D_DOWNLOAD_TOTAL_TIMEOUT', k3d_env)

    def test_cluster_uses_private_kubeconfig_context_and_fixed_image(self):
        m = self.m
        m.step_storage(self.context())
        ctx = self.context()
        m.step_cluster(ctx)
        create = next(c for c in self.model.calls if c[:3] == [m.K3D, 'cluster', 'create'])
        env = self.model.envs[self.model.calls.index(create)]
        self.assertEqual(env['LABAPP_MANAGEMENT_IMAGE'], m.MANAGEMENT_IMAGE)
        self.assertEqual(env['LABAPP_PROMETHEUS_BIND_ADDRESS'], '127.0.0.1')
        self.assertIn('--kubeconfig-update-default=false', create)
        self.assertIn('--kubeconfig-switch-context=false', create)
        self.assertEqual(create[create.index('--config') + 1], str(self.root / 'management-cluster.yaml'))
        self.assertTrue(all('KUBECONFIG' not in (e or {}) for e in self.model.envs))
        self.assertEqual(stat.S_IMODE(m.KUBECONFIG.stat().st_mode), 0o600)
        self.assertTrue(ctx.state['observed']['cluster_context'])
        self.assertTrue(ctx.private['cluster_attempted'])

    def test_every_kubectl_and_helm_names_private_kubeconfig_and_context(self):
        m = self.m
        m.step_namespace(self.context())
        m.step_secret(self.context())
        m.step_helm(self.context())
        m.step_health(self.context())
        kubectls = [c for c in self.model.calls if c[0] == m.KUBECTL]
        self.assertGreaterEqual(len(kubectls), 4)
        for call in kubectls:
            self.assertEqual(call[1:5], ['--kubeconfig', str(m.KUBECONFIG), '--context', m.CONTEXT])
        helm = next(c for c in self.model.calls if c[0] == m.HELM)
        self.assertEqual(helm.count('--values'), 2)
        self.assertEqual(helm[helm.index('--kubeconfig') + 1], str(m.KUBECONFIG))
        self.assertEqual(helm[helm.index('--kube-context') + 1], m.CONTEXT)
        self.assertIn('--wait', helm)
        self.assertFalse(any(a in ('--set', '--set-string', '--set-file') for a in helm))

    def test_grafana_secret_is_generated_private_and_never_in_argv_state_or_result(self):
        m = self.m
        ctx = self.context()
        m.step_secret(ctx)
        m.save_state(ctx.state)
        password = (m.WORK / 'grafana-admin-password').read_text()
        self.assertGreaterEqual(len(password), 24)
        for name in ('grafana-admin-user', 'grafana-admin-password'):
            self.assertEqual(stat.S_IMODE((m.WORK / name).stat().st_mode), 0o600)
        self.assertFalse(any(password in part for call in self.model.calls for part in call))
        self.assertNotIn(password.encode(), (self.root / 'steps.json').read_bytes())
        self.assertNotIn(password, self.redaction_text())

    def push_and_read(self):
        ctx = self.context()
        self.m.step_probe_push(ctx)
        self.m.save_state(ctx.state)
        ctx = self.context()
        self.m.step_probe_read(ctx)
        self.m.save_state(ctx.state)
        return ctx

    def test_probe_is_unique_fresh_and_distinguishes_unused_nonce_from_query_error(self):
        m = self.m
        ctx = self.push_and_read()
        probe = ctx.private['probe']
        self.assertEqual(self.model.pushes, 1)
        push = next(c for c in self.model.calls if is_push(c))
        self.assertEqual(push[push.index('exec'):push.index('exec') + 4], ['exec', '-i', 'prometheus-0', '-c'])
        self.assertIn('--label=job=promtool', push)
        self.assertIn('--timeout=10s', push)
        self.assertEqual(push[-1], 'http://127.0.0.1:9090/api/v1/write')
        self.assertEqual(self.model.stdin[0].decode(),
                         m.PROBE_METRIC + '{nonce="%s"} %d\n' % (probe['label'], probe['value']))
        flags = ctx.state['observed']
        self.assertTrue(all(flags[k] for k in ('probe_pushed', 'probe_fresh', 'unused_nonce_empty', 'repeat_reads_stable')))
        self.assertAlmostEqual(probe['timestamp'], self.model.samples[probe['label']][0], places=3)
        # a successful EMPTY result for an unused nonce is not a query error
        self.assertEqual(m.prom(ctx, m.probe_query('f' * 16) + '[2m]')['result'], [])
        self.model.query_error = True
        with self.assertRaises(trial.Failure) as raised:
            m.prom(ctx, m.probe_query('f' * 16) + '[2m]')
        self.assertEqual(raised.exception.category, 'status-invalid')

    def test_stale_probe_sample_is_refused(self):
        self.model.sample_age = 600  # sample timestamp far outside the freshness window
        with self.assertRaises(trial.Failure):
            self.push_and_read()

    def test_native_probe_label_contract_refuses_missing_wrong_and_extra_labels(self):
        m = self.m
        ctx = self.push_and_read()
        probe = ctx.private['probe']
        labels = {'__name__': m.PROBE_METRIC, 'nonce': probe['label'], 'job': 'promtool'}
        for invalid in ({key: val for key, val in labels.items() if key != 'job'},
                        dict(labels, job='other'), dict(labels, unexpected='other')):
            with self.subTest(labels=invalid):
                with patch.object(m, 'prom', return_value={
                        'resultType': 'matrix', 'result': [{'metric': invalid,
                        'values': [[probe['timestamp'], str(probe['value'])]]}]}):
                    with self.assertRaises(trial.Failure):
                        m.probe_series(ctx, probe['label'], probe['value'])
                with patch.object(m, 'prom', return_value={
                        'resultType': 'vector', 'result': [{'metric': invalid,
                        'value': [probe['timestamp'], str(probe['value'])]}]}):
                    with self.assertRaises(trial.Failure):
                        m.step_historical(ctx)

    def test_pod_replacement_retries_empty_set_but_refuses_ambiguous_and_malformed_sets(self):
        m = self.m
        ctx = self.context()
        ready = m.kget(ctx, 'pods', '--selector', m.PROMETHEUS_SELECTOR)
        with patch.object(m, 'kget', side_effect=[{'items': []}, ready]) as reads:
            self.assertEqual(m.wait_pod(ctx, m.PROMETHEUS_SELECTOR, 10), ('prometheus-0', 'p-1'))
            self.assertEqual(reads.call_count, 2)
        for invalid in (ready['items'] * 2, {}, None):
            with self.subTest(items=invalid), patch.object(m, 'kget', return_value={'items': invalid}):
                with self.assertRaises(trial.Failure):
                    m.wait_pod(ctx, m.PROMETHEUS_SELECTOR, 10)

    def test_pod_poll_refuses_late_success_and_clips_attempt_and_sleep_budgets(self):
        m = self.m
        ctx = self.context()
        ready = m.kget(ctx, 'pods', '--selector', m.PROMETHEUS_SELECTOR)
        ticks = [time.monotonic()]

        def advance(seconds):
            ticks[0] += seconds

        with patch.object(m.time, 'monotonic', side_effect=lambda: ticks[0]), \
             patch.object(m.time, 'sleep', side_effect=advance) as sleeps:
            with patch.object(m, 'kget', side_effect=[{'items': []}, ready]) as reads:
                with self.assertRaises(trial.Failure) as raised:
                    m.wait_pod(ctx, m.PROMETHEUS_SELECTOR, 1)
                self.assertEqual(raised.exception.category, 'child-timeout')
                self.assertEqual(reads.call_count, 1)
                sleeps.assert_called_once_with(1)

            def late(*args):
                advance(2)
                return ready

            with patch.object(m, 'kget', side_effect=late):
                with self.assertRaises(trial.Failure) as raised:
                    m.wait_pod(ctx, m.PROMETHEUS_SELECTOR, 1)
                self.assertEqual(raised.exception.category, 'child-timeout')
            m.poll(ctx, 'work', 1, lambda: m.kubectl(ctx, ['get', 'pods']) == b'')
            self.assertLessEqual(m.stdin_bounded.call_args.args[1], 1)
            m.poll(ctx, 'work', 1, lambda: m._grafana_healthy(ctx))
            self.assertLessEqual(m.http.call_args.kwargs['timeout'], 1)
        self.assertEqual(ctx.poll_deadlines, [])

    def test_query_error_is_not_treated_as_not_yet_visible(self):
        ctx = self.context()
        self.m.step_probe_push(ctx)
        self.m.save_state(ctx.state)
        self.model.query_error = True
        with self.assertRaises(trial.Failure) as raised:
            self.m.step_probe_read(self.context())
        self.assertEqual(raised.exception.category, 'status-invalid')

    def test_restart_deletes_pods_only_keeps_claims_and_historical_query_never_repushes(self):
        m = self.m
        self.push_and_read()
        seeded = self.context()
        seeded.private['claims'] = m.claims(seeded)
        m.save_state(seeded.state)
        ctx = self.context()
        m.step_restart(ctx)
        self.assertEqual(self.model.deleted, ['prometheus-0', 'grafana-0'])
        deletes = [c[c.index('delete'):] for c in self.model.calls if 'delete' in c]
        self.assertEqual(len(deletes), 2)
        self.assertTrue(all(c[:2] == ['delete', 'pod'] for c in deletes))
        text = ' '.join(' '.join(c) for c in deletes)
        for forbidden in ('persistentvolumeclaim', 'pvc', 'namespace', 'cluster', 'secret', 'release', 'uninstall'):
            self.assertNotIn(forbidden, text)
        self.assertTrue(ctx.state['observed']['pvc_uid_unchanged'])
        m.save_state(ctx.state)
        historical = self.context()
        m.step_historical(historical)
        self.assertTrue(historical.state['observed']['historical_sample'])
        self.assertEqual(self.model.pushes, 1)  # retained sample proven without pushing again
        self.model.samples.clear()  # lost retention is a failure, not masked by instant-query lookback
        with self.assertRaises(trial.Failure):
            m.step_historical(self.context())

    def test_changed_claim_identity_fails_restart(self):
        m = self.m
        ctx = self.context()
        ctx.private['claims'] = m.claims(ctx)
        original = self.model.run

        def replace_claim(args, env=None, data=None):
            if 'delete' in args:
                self.model.claims['prom-claim']['uid'] = 'recreated'
            return original(args, env, data)
        with patch.object(self.model, 'run', side_effect=replace_claim):
            with self.assertRaises(trial.Failure):
                m.step_restart(ctx)

    def prepared_principal(self):
        m = self.m
        ctx = self.context()
        m.step_secret(ctx)
        m.save_state(ctx.state)
        self.model.admin = ('admin', (m.WORK / 'grafana-admin-password').read_text())
        ctx = self.context()
        m.step_principal(ctx)
        m.save_state(ctx.state)
        return ctx

    def test_test_principal_is_verified_viewer_and_credentials_stay_in_private_files(self):
        m = self.m
        ctx = self.prepared_principal()
        self.assertTrue(ctx.state['observed']['principal_viewer'])
        login, password = m.viewer_credentials()
        self.assertRegex(login, m.VIEWER_LOGIN)
        self.assertEqual(stat.S_IMODE((m.WORK / 'viewer.json').stat().st_mode), 0o600)
        text = ' '.join(' '.join(c) for c in self.model.calls)
        for secret in (password, self.model.admin[1]):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, self.redaction_text())
            self.assertNotIn(secret.encode(), (self.root / 'steps.json').read_bytes())
        m.step_persisted_principal(self.context())

    def test_non_viewer_or_admin_principal_is_refused_not_elevated(self):
        for change in ('role', 'admin', 'settings'):
            self.model.users.clear()
            self.model.role, self.model.viewer_admin, self.model.viewer_settings = 'Viewer', False, 403
            for name in ('viewer.json', 'grafana-admin-user', 'grafana-admin-password'):
                (self.m.WORK / name).unlink(missing_ok=True)
            if change == 'role':
                self.model.role = 'Editor'
            elif change == 'admin':
                self.model.viewer_admin = True
            else:
                self.model.viewer_settings = 200
            with self.assertRaises(trial.Failure):
                self.prepared_principal()

    def test_viewer_ready_discovers_the_generated_uid_as_viewer_and_hands_off_viewer_only(self):
        m = self.m
        self.prepared_principal()
        self.assertFalse(hasattr(m, 'VIEWER_PANEL'))  # no pinned/invented UID anywhere
        m.step_viewer_ready(self.context())
        record = trial.data((m.WORK / 'viewer-handoff.json').read_bytes())
        self.assertEqual(set(record), m.HANDOFF_FIELDS)
        self.assertEqual(record['path'], '/d/%s?viewPanel=7' % self.model.generated_uid)
        self.assertNotIn(self.model.admin[1], json.dumps(record))
        for bad in (dict(record, password='short'), dict(record, login='admin'), dict(record, port=3001),
                    dict(record, admin='x'), dict(record, nonce='b' * 32), dict(record, path='/api/admin')):
            with self.assertRaises(trial.Failure):
                m.validate_handoff(bad, NONCE)

    def test_viewer_dashboard_discovery_refuses_missing_duplicate_wrong_and_privileged(self):
        m = self.m
        self.prepared_principal()

        def dash():
            return self.model.dashboard['dashboard']
        row = dict(self.model.search_rows[0])
        cases = {
            'missing': lambda: setattr(self.model, 'search_rows', []),
            'duplicate': lambda: setattr(self.model, 'search_rows', [row, dict(row, uid='other')]),
            'wrong title': lambda: setattr(self.model, 'search_rows', [dict(row, title='Other')]),
            'wrong type': lambda: setattr(self.model, 'search_rows', [dict(row, type='dash-folder')]),
            'empty uid': lambda: setattr(self.model, 'search_rows', [dict(row, uid='')]),
            'unsafe uid': lambda: setattr(self.model, 'search_rows', [dict(row, uid='a/../b')]),
            'search denied': lambda: setattr(self.model, 'search_status', 403),
            'uid mismatch': lambda: dash().update(uid='other'),
            'wrong panel id': lambda: dash().update(panels=[dict(dash()['panels'][1], id=8)]),
            'duplicate panel': lambda: dash().update(panels=[dash()['panels'][1], dict(dash()['panels'][1])]),
            'wrong panel title': lambda: dash()['panels'][1].update(title='Head Chunks'),
            'wrong panel type': lambda: dash()['panels'][1].update(type='table'),
            'wrong datasource': lambda: dash()['panels'][1].update(datasource='loki'),
            'datasource variable absent': lambda: dash()['templating'].update(list=[]),
            'datasource variable wrong': lambda: dash()['templating']['list'][0].update(query='loki'),
            'viewer can save': lambda: self.model.dashboard['meta'].update(canSave=True),
            'viewer can edit': lambda: self.model.dashboard['meta'].update(canEdit=True),
            'viewer can admin': lambda: self.model.dashboard['meta'].update(canAdmin=True),
            'meta absent': lambda: self.model.dashboard.pop('meta'),
            'no prometheus datasource': lambda: setattr(self.model, 'datasources', [{'uid': 'a', 'type': 'loki'}]),
            'two prometheus datasources': lambda: setattr(
                self.model, 'datasources', [{'uid': 'a', 'type': 'prometheus'}, {'uid': 'b', 'type': 'prometheus'}]),
            'viewer role changed': lambda: setattr(self.model, 'role', 'Editor'),
            'viewer is admin': lambda: setattr(self.model, 'viewer_admin', True),
        }
        original = deepcopy((self.model.search_rows, self.model.dashboard, self.model.datasources))
        for name, mutate in cases.items():
            with self.subTest(name):
                self.model.search_rows, self.model.dashboard, self.model.datasources = deepcopy(original)
                self.model.search_status, self.model.role, self.model.viewer_admin = 200, 'Viewer', False
                mutate()
                with self.assertRaises(trial.Failure):
                    m.step_viewer_ready(self.context())
                self.assertFalse((m.WORK / 'viewer-handoff.json').exists())
        # a nested (collapsed-row) panel and the timeseries migration of the same panel are accepted
        self.model.search_rows, self.model.dashboard, self.model.datasources = deepcopy(original)
        self.model.search_status, self.model.role, self.model.viewer_admin = 200, 'Viewer', False
        nested = dash()['panels']
        dash()['panels'] = [{'id': 1, 'type': 'row', 'panels': [dict(nested[1], type='timeseries')]}]
        m.step_viewer_ready(self.context())
        self.assertTrue((m.WORK / 'viewer-handoff.json').exists())

    def test_http_is_loopback_only(self):
        for url in ('http://example.com/', 'http://127.0.0.1:8080/', 'http://127.0.0.1:9090.evil/x', 'file:///etc/passwd'):
            with self.assertRaises(trial.Failure):
                self.real_http('GET', url)

    # -- typed result, teardown ----------------------------------------------------------------------------
    def test_result_is_closed_typed_and_nonsecret(self):
        m = self.m
        record = m.public_record(m.initial_state(NONCE))
        self.assertEqual(m.validate_result(deepcopy(record), NONCE), record)
        self.assertFalse(m.succeeded(record))
        done = deepcopy(record)
        done['steps'] = {n: 'ok' for n in m.STEP_NAMES}
        done['observed'] = {k: True for k in m.OBSERVED}
        done['teardown'] = 'complete'
        self.assertTrue(m.succeeded(m.validate_result(done, NONCE)))
        failed = deepcopy(record)
        failed['steps'].update({'install-docker': 'ok', 'install-kubectl': 'failed'})
        failed['failure'] = {'step': 'install-kubectl', 'category': 'child-exit', 'child_status': 7}
        m.validate_result(failed, NONCE)
        mutations = [
            lambda v: v.update(extra=1), lambda v: v.update(nonce='b' * 32), lambda v: v.update(schema=1),  # no legacy fallback
            lambda v: v.pop('terminal'), lambda v: v.update(terminal=None),
            lambda v: v['terminal'].update(extra=1), lambda v: v['terminal'].pop('group'),
            lambda v: v['terminal'].update(status=17),                       # status without an observation origin
            lambda v: v['terminal'].update(origin='pre-close'),              # origin without a status
            lambda v: v['terminal'].update(status=17, origin='guessed'),
            lambda v: v['terminal'].update(group='absent'),
            lambda v: v['terminal'].update(status=True, origin='closure-window'),
            lambda v: v['terminal'].update(status='17', origin='closure-window'),
            lambda v: v['terminal'].update(status=17.0, origin='closure-window'),
            lambda v: v['terminal'].update(status=float('nan'), origin='closure-window'),
            lambda v: v['terminal'].update(status=256, origin='pre-close'),
            lambda v: v['terminal'].update(status=-65, origin='pre-close'),
            lambda v: v['terminal'].update(status=17, origin=['pre-close']),
            lambda v: v['steps'].update({'storage': 'ok'}),               # ok without earlier steps
            lambda v: v['steps'].update({'install-docker': 'maybe'}),
            lambda v: v['observed'].update({'probe_fresh': True}),        # observed without its step
            lambda v: v.update(teardown='done'),
            lambda v: v.update(failure={'step': 'storage', 'category': 'exception', 'child_status': None}),
        ]
        for mutate in mutations:
            bad = deepcopy(record)
            mutate(bad)
            with self.assertRaises(trial.Failure):
                m.validate_result(bad, NONCE)
        for change in (lambda f: f.update(step='install-docker'), lambda f: f.update(category='none'),
                       lambda f: f.update(category='child-signal', child_status=5), lambda f: f.update(argv='x')):
            bad = deepcopy(failed)
            change(bad['failure'])
            with self.assertRaises(trial.Failure):
                m.validate_result(bad, NONCE)
        later = deepcopy(failed)
        later['steps']['install-helm'] = 'ok'  # work after the first failure
        with self.assertRaises(trial.Failure):
            m.validate_result(later, NONCE)

    def test_teardown_removes_only_owned_state_and_is_idempotent(self):
        m = self.m
        ctx = self.context()
        m.step_storage(ctx)
        ctx.private.update(cluster_attempted=True, docker_started=True)
        m.save_state(ctx.state)
        for name in m.PRIVATE_FILES:
            trial.exclusive(m.WORK / name, b'private')
        with patch.object(m, 'daemons_absent', return_value=True):  # positive proof is tested in ManagementLifetime
            self.assertEqual(m.teardown(NONCE), 1)  # publication timeliness is unproved: never positive
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertIs(m.load_state(NONCE)['private']['teardown_observed_clean'], False)  # storage retained (#510)
        self.assertIs(m.load_state(NONCE)['private']['storage_retained'], True)
        self.assertTrue(m.STORAGE.exists())  # all cleanup-success inputs true: still never deleted
        self.assertFalse(any((m.WORK / name).exists() for name in m.PRIVATE_FILES))  # credentials still removed
        deletes = [c for c in self.model.calls if c[:3] == [m.K3D, 'cluster', 'delete']]
        self.assertEqual(deletes, [[m.K3D, 'cluster', 'delete', m.CLUSTER]])
        with patch.object(m, 'daemons_absent', return_value=True):
            self.assertEqual(m.teardown(NONCE), 1)  # a stored non-complete receipt is simply re-observed
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertTrue(m.STORAGE.exists())

    def test_teardown_never_removes_foreign_storage_and_cluster_failure_is_uncertain(self):
        m = self.m
        m.STORAGE.mkdir(mode=0o700)
        (m.STORAGE / 'foreign').write_text('keep')
        ctx = self.context()
        ctx.private['storage_ino'] = [0, 0]  # not the directory this program created
        m.save_state(ctx.state)
        self.assertEqual(m.teardown(NONCE), 1)
        self.assertTrue((m.STORAGE / 'foreign').exists())
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        ctx = self.context()
        ctx.state['teardown'] = 'pending'
        ctx.private.pop('storage_ino')
        ctx.private['cluster_attempted'] = True
        m.save_state(ctx.state)
        original = self.model.run
        with patch.object(self.model, 'run',
                          side_effect=lambda a, e=None, d=None: (1, b'') if 'delete' in a else original(a, e, d)):
            self.assertEqual(m.teardown(NONCE), 1)
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')


class ManagementBounded(unittest.TestCase):
    """stdin_bounded with stdlib fixture children only (no native tool)."""
    def setUp(self):
        self.m = load_management()

    def test_group_closure_is_the_sole_reaper_and_uncertainty_preserves_the_primary_failure(self):
        m = self.m
        echo = [sys.executable, '-I', '-c', 'print(7)']
        original = m.owned_process.OwnedGroup.close
        closures = []

        def uncertain(group, *args, **kwargs):
            closures.append((group.proc.returncode, group.reaping))
            self.assertTrue(original(group, *args, **kwargs))
            return False

        with patch.object(m.owned_process.OwnedGroup, 'close', uncertain):
            with self.assertRaises(trial.Failure) as raised:
                m.stdin_bounded(echo, 10, b'', {'PATH': '/usr/bin:/bin'})
            self.assertTrue(raised.exception.cleanup_uncertain)
            primary = trial.Failure('heartbeat lost', 1, 'heartbeat-loss')

            def lost():
                raise primary

            with self.assertRaises(trial.Failure) as raised:
                m.stdin_bounded(echo, 10, b'', {'PATH': '/usr/bin:/bin'}, watch=lost)
            self.assertIs(raised.exception, primary)
            self.assertTrue(primary.cleanup_uncertain)
            for script, status in (('import sys;sys.exit(17)', 17),
                                   ('import os,signal;os.kill(os.getpid(),signal.SIGTERM)', -15)):
                with self.subTest(status=status), self.assertRaises(trial.Failure) as raised:
                    m.stdin_bounded([sys.executable, '-I', '-c', script], 10, b'', {'PATH': '/usr/bin:/bin'})
                expected = trial.child_failure(status, 'fixed child failed')
                self.assertEqual((raised.exception.code, raised.exception.category, raised.exception.child_status),
                                 (expected.code, expected.category, expected.child_status))
                self.assertTrue(raised.exception.cleanup_uncertain)
        self.assertEqual(closures, [(None, False)] * 4)

    def test_stdin_is_delivered_and_output_and_time_are_bounded(self):
        echo = [sys.executable, '-I', '-c', 'import sys;sys.stdout.write(sys.stdin.read())']
        self.assertEqual(self.m.stdin_bounded(echo, 10, b'probe\n', {'PATH': '/usr/bin:/bin'}), (0, b'probe\n'))
        with self.assertRaises(trial.Failure) as raised:
            self.m.stdin_bounded(echo, 10, b'x' * 100, {'PATH': '/usr/bin'}, limit=10)
        self.assertEqual(raised.exception.category, 'output-overflow')
        sleeper = [sys.executable, '-I', '-c', 'import time;time.sleep(30)']
        started = time.monotonic()
        with self.assertRaises(trial.Failure) as raised:
            self.m.stdin_bounded(sleeper, .5, b'', {'PATH': '/usr/bin'})
        self.assertEqual((raised.exception.category, raised.exception.code), ('child-timeout', 124))
        self.assertLess(time.monotonic() - started, 10)
        with self.assertRaises(trial.Failure):
            self.m.stdin_bounded(echo, 10, b'x' * 5000, {'PATH': '/usr/bin'})


# Fixture child: records its own and a same-group descendant's pid, then stays alive.
LIVE_CHILD = ('import os,subprocess,sys,time\n'
              'g=subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(60)"],stdout=subprocess.DEVNULL)\n'
              'open(sys.argv[1],"w").write("%d %d"%(os.getpid(),g.pid))\n'
              'time.sleep(60)\n')
EXITING_CHILD = ('import os,subprocess,sys\n'
                 'g=subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(60)"],'
                 'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                 'open(sys.argv[1],"w").write("%d %d"%(os.getpid(),g.pid))\n')


def process_alive(pid):
    try:
        text = Path('/proc/%d/stat' % pid).read_text()
    except OSError:
        return False
    return text.rsplit(')', 1)[1].split()[0] != 'Z'  # a reaped-pending zombie is not running


class ManagementSupervision(unittest.TestCase):
    """Continuous supervision of a LIVE child (stdlib fixture children; no native tool, no network)."""
    def setUp(self):
        self.m = load_management()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-sup-')))
        self.root = self.temp / 'root'
        (self.root / 'work').mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.stack.enter_context(patch.object(self.m, 'MROOT', self.root))
        self.stack.enter_context(patch.object(self.m, 'WORK', self.root / 'work'))
        self.stack.enter_context(patch.object(trial, 'regular',
                                 side_effect=lambda p, limit, uid=None, mode=None: REAL_REGULAR(p, limit, None, mode)))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=MGMT_BOOT))
        self.pids = self.temp / 'pids'
        self.env = {'PATH': '/usr/bin:/bin'}
        self.fresh()

    def fresh(self, contract=None):
        self.value = contract or value()
        trial.atomic(self.root / 'heartbeat.json', {'sequence': 0, 'received': time.monotonic()})
        self.ctx = self.m.Context(self.value, self.m.ManagementClock(self.value), {'private': {}})

    def stale_after_child_starts(self):
        def lose():
            until = time.monotonic() + 10
            while not self.pids.exists() and time.monotonic() < until:
                REAL_SLEEP(.02)
            REAL_SLEEP(.2)
            trial.atomic(self.root / 'heartbeat.json', {'sequence': 0, 'received': time.monotonic() - 60})
        thread = threading.Thread(target=lose)
        thread.start()
        self.addCleanup(thread.join)

    def assert_group_gone(self):
        pids = [int(p) for p in self.pids.read_text().split()]
        until = time.monotonic() + 5
        while any(process_alive(p) for p in pids) and time.monotonic() < until:
            REAL_SLEEP(.05)
        self.assertEqual([p for p in pids if process_alive(p)], [])

    def run_live(self, phase='work', cap=30, cleanup=False):
        return self.m.run_tool(self.ctx, [sys.executable, '-I', '-c', LIVE_CHILD, str(self.pids)], phase, cap,
                               env=self.env, cleanup=cleanup)

    def test_heartbeat_loss_while_child_is_live_kills_the_exact_group(self):
        self.stale_after_child_starts()
        started = time.monotonic()
        with self.assertRaises(trial.Failure) as raised:
            self.run_live()
        self.assertEqual(raised.exception.category, 'heartbeat-loss')
        self.assertLess(time.monotonic() - started, 15)  # not the 60s child, not the 30s cap
        self.assert_group_gone()

    def test_phase_deadline_while_child_is_live_kills_the_exact_group(self):
        start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=36, seconds=57)  # work ends at 37
        contract = value()
        contract['admitted_at'] = start.strftime('%Y-%m-%dT%H:%M:%SZ')
        contract['deadline'] = (start + timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.fresh(contract)
        started = time.monotonic()
        with self.assertRaises(trial.Failure) as raised:
            self.run_live(cap=30)
        self.assertIn(raised.exception.category, ('phase-cutoff', 'child-timeout'))
        self.assertLess(time.monotonic() - started, 15)
        self.assert_group_gone()

    def test_boot_change_while_child_is_live_kills_the_exact_group(self):
        def reboot():
            until = time.monotonic() + 10
            while not self.pids.exists() and time.monotonic() < until:
                REAL_SLEEP(.02)
            REAL_SLEEP(.2)
            trial.kernel_boot.return_value = '33333333-3333-4333-8333-333333333333'
        thread = threading.Thread(target=reboot)
        thread.start()
        self.addCleanup(thread.join)
        with self.assertRaises(trial.Failure) as raised:
            self.run_live()
        self.assertEqual(raised.exception.category, 'boot-change')
        self.assert_group_gone()

    def test_cancel_or_interrupt_while_child_is_live_kills_the_exact_group(self):
        def cancel():
            if self.pids.exists():
                raise trial.Failure('signal', 143, 'interrupted')  # what the SIGTERM handler raises
        argv = [sys.executable, '-I', '-c', LIVE_CHILD, str(self.pids)]
        with self.assertRaises(trial.Failure) as raised:
            self.m.stdin_bounded(argv, 30, b'', self.env, watch=cancel)
        self.assertEqual(raised.exception.category, 'interrupted')
        self.assert_group_gone()
        self.pids.unlink()

        def interrupt():
            if self.pids.exists():
                raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.m.stdin_bounded(argv, 30, b'', self.env, watch=interrupt)
        self.assert_group_gone()

    def test_a_finished_step_leaves_no_descendant(self):
        code, _ = self.m.stdin_bounded([sys.executable, '-I', '-c', EXITING_CHILD, str(self.pids)], 30, b'',
                                       self.env, watch=self.m.watcher(self.ctx, 'work', False))
        self.assertEqual(code, 0)
        self.assert_group_gone()

    def test_teardown_children_ignore_heartbeat_loss_but_keep_the_ceiling(self):
        trial.atomic(self.root / 'heartbeat.json', {'sequence': 0, 'received': time.monotonic() - 60})
        out = self.m.run_tool(self.ctx, [sys.executable, '-I', '-c', 'print(7)'], None, 30, env=self.env, cleanup=True)
        self.assertEqual(out, b'7\n')
        with self.assertRaises(trial.Failure) as raised:  # the normal path refuses the same stale heartbeat
            self.m.run_tool(self.ctx, [sys.executable, '-I', '-c', 'print(7)'], 'work', 30, env=self.env)
        self.assertEqual(raised.exception.category, 'heartbeat-loss')
        start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=61)
        late = value()
        late['admitted_at'] = start.strftime('%Y-%m-%dT%H:%M:%SZ')
        late['deadline'] = (start + timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.fresh(late)
        with self.assertRaises(trial.Failure) as raised:
            self.m.run_tool(self.ctx, [sys.executable, '-I', '-c', 'print(7)'], None, 30, env=self.env, cleanup=True)
        self.assertEqual(raised.exception.category, 'phase-cutoff')


# ---- #508 fixed lifetime ownership: stdlib fixture processes and mocked unit operations ---------------------
# These tests do NOT prove systemd v255, cgroup, timer or daemon behavior. They exercise the source seams
# (capsule, gate, one worker, OwnedGroup closure, single-writer poststop) with stdlib children only.
WORKER_EXITS = 'open(%r, "a").write("w")\n'
WORKER_SIGKILL = 'import os,signal\nopen(%r, "a").write("w")\nos.kill(os.getpid(), signal.SIGKILL)\n'
WORKER_STOPPED = ('import os,signal,time\nopen(%r, "w").write(str(os.getpid()))\n'
                  'os.kill(os.getpid(), signal.SIGSTOP)\ntime.sleep(60)\n')


class ManagementLifetime(unittest.TestCase):
    def setUp(self):
        self.m = load_management()
        original = os.umask(0o077)
        os.umask(original)
        self.addCleanup(os.umask, original)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-life-')))
        self.root = self.temp / 'root'
        (self.root / 'work').mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.cg = self.temp / 'cg'
        self.cg.mkdir()
        for name, path in (('MROOT', self.root), ('WORK', self.root / 'work'), ('STORAGE', self.temp / 'storage'),
                           ('CGROUP_DIR', self.cg), ('CGROUP_PROCS', self.cg / 'cgroup.procs')):
            self.stack.enter_context(patch.object(self.m, name, path))
        self.stack.enter_context(patch.object(trial, 'regular',
                                 side_effect=lambda p, limit, uid=None, mode=None: REAL_REGULAR(p, limit, None, mode)))
        self.stack.enter_context(patch.object(trial, 'kernel_boot', return_value=MGMT_BOOT))
        self.value = value()
        self.capsule = self.make_capsule(self.value)
        trial.exclusive(self.root / 'contract.json', trial.encoded(self.value))
        trial.exclusive(self.root / 'capsule.json', trial.encoded(self.capsule))
        trial.exclusive(self.root / 'steps.json', trial.encoded(self.m.initial_state(NONCE)))
        self.beat()
        (self.cg / 'cgroup.procs').write_text('')

    def make_capsule(self, contract, nonce='e' * 32):
        clock = self.m.ManagementClock(contract)
        wall, mono = time.time(), time.monotonic()
        sample = {'boot': contract['boot_uuid'], 'nonce': nonce, 'wall': wall, 'mono': mono}
        return self.m.build_capsule(contract, clock, sample, nonce, (wall, mono), (time.time(), time.monotonic()))

    def beat(self, age=0.0):
        trial.atomic(self.root / 'heartbeat.json', {'sequence': 0, 'received': time.monotonic() - age})

    def open_gate(self):
        trial.exclusive(self.root / self.m.RELEASE_OPEN, trial.encoded({'nonce': NONCE, 'boot': MGMT_BOOT}))

    def worker_script(self, source):
        marker = self.temp / 'marker'
        (self.root / 'management_trial.py').write_text(source % str(marker))
        return marker

    def run_guardian(self, interrupt=None):
        thread = None
        if interrupt is not None:
            thread = threading.Thread(target=interrupt)
            thread.start()
        try:
            with patch.object(self.m, 'PYTHON', sys.executable):
                return self.m.guardian()
        finally:
            if thread is not None:
                thread.join(30)

    def outcome(self):
        return trial.data((self.root / 'outcome.json').read_bytes())

    def until(self, condition, seconds=15):
        end = time.monotonic() + seconds
        while not condition() and time.monotonic() < end:
            REAL_SLEEP(.02)
        return condition()

    # -- A2: capsule ---------------------------------------------------------------------------------
    def test_budget_and_phase_cutoffs_are_the_approved_source_policy(self):
        m = self.m
        self.assertEqual(m.MGMT_PHASES, {'access': 15, 'stage': 30, 'work': 37, 'persistence': 38})
        self.assertEqual((m.STOP_TIMEOUT_SECONDS, m.STOP_JITTER_SECONDS, m.EXTRA_SLACK_SECONDS, m.STOP_INTERVALS),
                         (240, 60, 60, 5))
        self.assertEqual(m.EXPIRY_RESERVE_SECONDS, 1320)
        # E + J + 5T <= D - 60 for the fixed expiry (= persistence cutoff) and the 60-minute ceiling D
        expiry, ceiling = m.MGMT_PHASES['persistence'] * 60, m.CEILING_MINUTES * 60
        self.assertLessEqual(expiry + m.STOP_JITTER_SECONDS + 5 * m.STOP_TIMEOUT_SECONDS, ceiling - 60)
        self.assertEqual(expiry, 38 * 60)
        self.assertLessEqual(180 + 60, m.STOP_TIMEOUT_SECONDS)  # native cleanup 120+30+30 plus 60s inside one interval
        self.assertLess(m.POSTSTOP_OUTER_SECONDS, m.STOP_TIMEOUT_SECONDS)
        self.assertEqual((m.CLOCK_ROUNDTRIP_MAX, m.CLOCK_SKEW_MAX), (10, 5))

    def test_capsule_binds_the_contract_and_refuses_every_tampering(self):
        m = self.m
        self.assertIs(m.validate_capsule(self.capsule, self.value), self.capsule)
        mutations = {
            'nonce': lambda c: c.update(nonce='b' * 32), 'lease': lambda c: c.update(lease='22222222-2222-4222-8222-222222222222'),
            'epoch': lambda c: c.update(epoch=2), 'deadline': lambda c: c.update(deadline='2030-01-01T00:00:00Z'),
            'stub': lambda c: c.update(stub_sha256='0' * 64), 'safety': lambda c: c.update(safety=0),
            'schema': lambda c: c.update(schema=2), 'extra': lambda c: c.update(extra=1),
            'sample boot': lambda c: c['sample'].update(boot='33333333-3333-4333-8333-333333333333'),
            'sample extra': lambda c: c['sample'].update(extra=1),
            'sample nonce': lambda c: c['sample'].update(nonce='short'),
            'roundtrip': lambda c: c['caller'].update(roundtrip=m.CLOCK_ROUNDTRIP_MAX + 1),
            'skew': lambda c: c['sample'].update(wall=c['caller']['recv_wall'] + m.CLOCK_SKEW_MAX + 1),
            'mapping': lambda c: c['cutoffs'].update(work=c['cutoffs']['work'] + 5),
            'order': lambda c: c['cutoffs'].update(access=c['cutoffs']['stage'] + 1, work=c['cutoffs']['work']),
            'reserve': lambda c: c['cutoffs'].update(persistence=c['cutoffs']['ceiling'] - 100),
            'missing phase': lambda c: c['cutoffs'].pop('ceiling'),
            'nan': lambda c: c['left'].update(access=float('nan')),
            'bool number': lambda c: c['left'].update(access=True)}
        for name, mutate in mutations.items():
            with self.subTest(name):
                bad = deepcopy(self.capsule)
                mutate(bad)
                with self.assertRaises(trial.Failure):
                    m.validate_capsule(bad, self.value)
        sample = self.capsule['sample']
        now = (sample['wall'] + 1, sample['mono'] + 1)
        self.assertIs(m.validate_capsule(self.capsule, self.value, now=now), self.capsule)
        for name, late in (('stale', (sample['wall'] + 400, sample['mono'] + 400)), ('future', (sample['wall'], sample['mono'] - 1)),
                           ('wall jump', (sample['wall'] + 100, sample['mono'] + 1)),
                           ('wall rollback', (sample['wall'] - 100, sample['mono'] + 1))):
            with self.subTest(name), self.assertRaises(trial.Failure):
                m.validate_capsule(self.capsule, self.value, now=late)

    def test_capsule_builder_is_conservative_and_refuses_slow_skewed_or_foreign_samples(self):
        m = self.m
        clock = m.ManagementClock(self.value)
        wall, mono = time.time(), time.monotonic()
        sample = {'boot': MGMT_BOOT, 'nonce': 'e' * 32, 'wall': wall, 'mono': 5000.0}
        capsule = m.build_capsule(self.value, clock, sample, 'e' * 32, (wall, mono), (wall + 4, mono + 4))
        self.assertEqual(capsule['cutoffs']['work'],
                         5000.0 + clock.left_at(37, wall + 4, mono + 4) - m.CLOCK_SAFETY_SECONDS)
        self.assertLess(capsule['cutoffs']['work'], 5000.0 + clock.left_at(37, wall, mono))  # RTT never added back
        for name, args in {'slow': ((wall, mono), (wall + 11, mono + 11), {}),
                           'ahead': ((wall, mono), (wall + 1, mono + 1), {'wall': wall + 60}),
                           'behind': ((wall, mono), (wall + 1, mono + 1), {'wall': wall - 60}),
                           'other boot': ((wall, mono), (wall + 1, mono + 1), {'boot': '33333333-3333-4333-8333-333333333333'}),
                           'other nonce': ((wall, mono), (wall + 1, mono + 1), {'nonce': 'f' * 32}),
                           'backwards reception': ((wall, mono), (wall + 1, mono - 1), {})}.items():
            with self.subTest(name), self.assertRaises(trial.Failure):
                m.build_capsule(self.value, clock, dict(sample, **args[2]), 'e' * 32, args[0], args[1])

    def test_capsule_cutoffs_are_absolute_boot_monotonic_and_a_fresh_process_cannot_renew(self):
        m = self.m
        cutoffs = self.capsule['cutoffs']
        now = [time.monotonic()]
        clock = m.ManagementClock(self.value, mono=lambda: now[0], capsule=self.capsule)
        self.assertGreater(clock.remaining('work'), 0)
        now[0] = cutoffs['work'] + 1
        with self.assertRaises(trial.Failure):
            clock.remaining('work')
        # a brand-new process/clock object (fresh started_* anchors) is bounded by the SAME absolute value
        fresh = m.ManagementClock(self.value, mono=lambda: now[0], capsule=self.capsule)
        with self.assertRaises(trial.Failure):
            fresh.remaining('work')
        now[0] = cutoffs['ceiling'] + 1
        with self.assertRaises(trial.Failure):
            fresh.cleanup_remaining()
        # a guest wall rollback cannot renew; a forward jump may only shorten
        now[0] = time.monotonic()
        wall = [time.time()]
        jumped = m.ManagementClock(self.value, wall=lambda: wall[0], mono=lambda: now[0], capsule=self.capsule)
        before = jumped.remaining('persistence')
        wall[0] -= 3600
        self.assertLessEqual(jumped.remaining('persistence'), before + 1)
        wall[0] += 7200 + m.MGMT_PHASES['persistence'] * 60
        with self.assertRaises(trial.Failure):
            jumped.remaining('persistence')
        # a missing or foreign capsule is never replaced by a per-process clock
        (self.root / 'capsule.json').unlink()
        with self.assertRaises((trial.Failure, OSError)):
            m.production_clock(self.value)

    # -- A1: fixed units, closed dispatch -----------------------------------------------------------------
    def test_exactly_three_fixed_units_with_the_approved_timeouts_and_no_selector(self):
        m = self.m
        here = Path(__file__).parent
        text = {name: (here / name).read_text() for name in m.UNIT_NAMES}
        guardian, timer, stop = (text[m.GUARDIAN_UNIT], text[m.TIMER_UNIT], text[m.STOP_UNIT])
        for needle in ('TimeoutStopSec=240', 'KillMode=control-group', 'SendSIGKILL=yes', 'Restart=no', 'User=root',
                       'ExecStart=/usr/bin/python3 /var/lib/labapp-management-trial/management_trial.py guardian',
                       'ExecStopPost=/usr/bin/python3 /var/lib/labapp-management-trial/management_trial.py poststop'):
            self.assertIn('\n' + needle + '\n', guardian)
        self.assertNotIn('RuntimeMaxSec', guardian)  # the independent timer, not the guardian, owns expiry
        self.assertNotIn('OnBootSec', timer)           # the single value is a bootstrap runtime drop-in
        for needle in ('AccuracySec=1us', 'RandomizedDelaySec=0', 'Persistent=no', 'Unit=' + m.STOP_UNIT):
            self.assertIn('\n' + needle + '\n', timer)
        self.assertIn('\nExecStart=/usr/bin/python3 /var/lib/labapp-management-trial/management_trial.py expire\n', stop)
        self.assertIn('\nType=oneshot\n', stop)
        for body in text.values():
            self.assertNotIn('%', body)  # no specifier/template selector
            self.assertNotIn('ExecStartPre', body)
        self.assertEqual(sorted(p.name for p in here.glob('labapp-management-*')), sorted(m.UNIT_NAMES))

    def test_dispatch_is_closed_and_unit_entrypoints_take_no_argument(self):
        m = self.m
        self.assertEqual(m.HOST_ACTIONS, ('heartbeat', 'export-viewer', 'result', 'cancel'))
        self.assertEqual(m.UNIT_ACTIONS, ('guardian', 'worker', 'poststop', 'expire'))
        with patch.object(m.os, 'geteuid', return_value=0):
            for argv in (['guardian', '--nonce', NONCE], ['worker', '--sequence', '1'], ['poststop', '--nonce', NONCE]):
                with self.assertRaises(trial.Failure):
                    m.dispatch(argv)
            for argv in (['result'], ['heartbeat', '--nonce', NONCE], ['cancel', '--nonce', NONCE, '--sequence', '1']):
                with self.assertRaises(trial.Failure):
                    m.dispatch(argv)
        for argv in (['step', '--nonce', NONCE], ['teardown', '--nonce', NONCE], ['guardian', '--name', 'storage']):
            with patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
                m.dispatch(argv)
        with self.assertRaises(trial.Failure):
            m.main(['guardian'])  # activation stays refused for every entrypoint

    def test_cancel_is_idempotent_and_bound_to_the_boot(self):
        m = self.m
        m.cancel(NONCE)
        m.cancel(NONCE)
        self.assertTrue((self.root / m.CANCEL_MARK).exists())
        with patch.object(trial, 'kernel_boot', return_value='33333333-3333-4333-8333-333333333333'):
            with self.assertRaises(trial.Failure):
                m.cancel(NONCE)

    # -- A1: bootstrap ordering --------------------------------------------------------------------------
    def bootstrap_fixture(self, timer_state='active', timer_next=None):
        m = self.m
        nonce = self.value['nonce']
        incoming = Path('/tmp/labapp-vlab-' + nonce)
        self.assertFalse(incoming.exists())
        incoming.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, incoming, True)
        units, runtime = self.temp / 'units', self.temp / 'run-units'
        units.mkdir()
        runtime.mkdir()
        pins = {'kubectl': b'k' * 10, 'helm.tar.gz': b'h' * 11, 'kube-prometheus-stack-65.2.0.tgz': b'c' * 12}
        pinned = {name: (len(raw), trial.sha(raw)) for name, raw in pins.items()}
        for item in (patch.object(m, 'PAYLOADS', pinned), patch.object(m, 'UNIT_DIR', units),
                     patch.object(m, 'RUNTIME_DIR', runtime), patch.object(trial, 'UNIT_BASES', (units, runtime)),
                     patch.object(m, 'FILES', {*m.SOURCES, *pinned, 'contract.json', 'capsule.json'}),
                     patch.object(m.os, 'geteuid', return_value=0), patch.object(sys, 'path', list(sys.path))):
            self.stack.enter_context(item)
        shutil.rmtree(self.root)  # bootstrap reserves the root itself
        files = {}
        here = Path(__file__).parent
        capsule = self.make_capsule(self.value)
        for name in m.FILES:
            if name in pins:
                raw = pins[name]
            elif name == 'contract.json':
                raw = trial.encoded(self.value)
            elif name == 'capsule.json':
                raw = trial.encoded(capsule)
            else:
                raw = (here / name).read_bytes()
            (incoming / name).write_bytes(raw)
            files[name] = {'bytes': len(raw), 'sha256': trial.sha(raw)}
        table = {'schema': 1, 'source_sha': self.value['source_sha'], 'files': files}
        raw = trial.encoded(table)
        (incoming / 'manifest.json').write_bytes(raw)
        events = []

        def systemctl(args, seconds, env=None):
            events.append(args[1:])
            if args[1:3] == ['show', m.TIMER_UNIT]:
                return 0, ('ActiveState=%s\nUnit=%s\nNextElapseUSecMonotonic=%s\n'
                           % (timer_state, m.STOP_UNIT, (timer_next(capsule) if callable(timer_next) else timer_next)
                              if timer_next is not None
                              else '%d' % (int(capsule['cutoffs']['persistence']) * 1000000))).encode()
            if args[1:3] == ['start', m.GUARDIAN_UNIT]:
                self.root.joinpath('guardian.json').write_bytes(trial.encoded(
                    {'boot': MGMT_BOOT, 'lease': self.value['lease'], 'nonce': nonce, 'guardian_pid': 4242}))
            if args[1:3] == ['show', m.GUARDIAN_UNIT]:
                return 0, b'MainPID=4242\nActiveState=active\n'
            return 0, b''
        self.stack.enter_context(patch.object(trial, 'call_bounded', side_effect=systemctl))
        return incoming, trial.sha(raw), events, capsule, units, runtime

    def test_bootstrap_arms_timer_then_binds_guardian_then_opens_the_gate_with_no_other_effect(self):
        m = self.m
        incoming, digest, events, capsule, units, runtime = self.bootstrap_fixture()
        m._bootstrap(incoming, digest)
        self.assertEqual(events, [['daemon-reload'], ['start', m.TIMER_UNIT],
                                  ['show', m.TIMER_UNIT, '-p', 'ActiveState', '-p', 'Unit',
                                   '-p', 'NextElapseUSecMonotonic'],
                                  ['start', m.GUARDIAN_UNIT], ['show', m.GUARDIAN_UNIT, '-p', 'MainPID', '-p', 'ActiveState']])
        self.assertEqual(sorted(p.name for p in units.iterdir()), sorted(m.UNIT_NAMES))
        for name in m.UNIT_NAMES:
            self.assertEqual(stat.S_IMODE((units / name).stat().st_mode), 0o644)
            self.assertEqual((units / name).read_bytes(), (Path(__file__).parent / name).read_bytes())
        dropin = (runtime / (m.TIMER_UNIT + '.d') / '10-bound.conf').read_text()
        self.assertEqual(dropin, '[Timer]\nOnBootSec=%ds\n' % int(capsule['cutoffs']['persistence']))
        self.assertEqual(m.gate_state(self.value), 'open')  # opened last; no worker, Docker or Secret effect exists
        self.assertTrue(all(call[0] in ('daemon-reload', 'start', 'show') for call in events))
        self.assertEqual(trial.data((self.root / 'steps.json').read_bytes())['steps'], {n: 'not-run' for n in m.STEP_NAMES})
        with self.assertRaises(trial.Failure):  # one-shot reservation: no reissue
            m._bootstrap(incoming, digest)

    def test_bootstrap_refuses_an_unconfirmed_timer_before_any_guardian_or_gate_and_keeps_the_reservation(self):
        m = self.m
        incoming, digest, events, _, _, _ = self.bootstrap_fixture(timer_state='inactive')
        with self.assertRaises(trial.Failure):
            m._bootstrap(incoming, digest)
        self.assertNotIn(['start', m.GUARDIAN_UNIT], events)
        self.assertEqual(events[-1], ['stop', m.GUARDIAN_UNIT])
        self.assertFalse((self.root / m.RELEASE_OPEN).exists())
        self.assertTrue(self.root.exists())  # the reservation is preserved, never deleted or retried

    def test_bootstrap_verifies_the_actual_loaded_deadline_not_any_nonempty_string(self):
        m = self.m
        for name, rendered in (('constant 38min', '38min'), ('wrong trigger', lambda c: '%d' % ((int(c['cutoffs']['persistence']) - 60) * 1000000)),('unknown format', 'soon'),
                               ('infinity', 'infinity'), ('empty', ''), ('mixed', '1h 3min 5xs')):
            with self.subTest(name):
                incoming, digest, events, _, units, runtime = self.bootstrap_fixture(timer_next=rendered)
                try:
                    with self.assertRaises(trial.Failure):
                        m._bootstrap(incoming, digest)
                    self.assertNotIn(['start', m.GUARDIAN_UNIT], events)
                    self.assertFalse((self.root / m.RELEASE_OPEN).exists())
                finally:
                    for directory in (self.root, incoming, units, runtime):
                        shutil.rmtree(directory, True)
                    self.root.mkdir(mode=0o700)
        self.assertAlmostEqual(m.timespan_seconds('37min 59s'), 2279.0)
        self.assertAlmostEqual(m.timespan_seconds('1h 3min 5.5s'), 3785.5)
        self.assertEqual(m.timespan_seconds('2280000000'), 2280.0)

    def test_bootstrap_refuses_a_stale_capsule_before_any_state_exists(self):
        m = self.m
        incoming, digest, events, _, units, _ = self.bootstrap_fixture()
        with patch.object(m, 'CAPSULE_MAX_AGE', -1), self.assertRaises(trial.Failure):  # any sample is now "late"
            m._bootstrap(incoming, digest)
        self.assertFalse(self.root.exists())
        self.assertEqual((events, list(units.iterdir())), ([], []))

    # -- A3: one worker, independent loss handling -------------------------------------------------------
    def test_worker_runs_all_eighteen_steps_in_order_with_one_context_and_preserves_the_native_failure(self):
        m = self.m
        seen = []
        table = {name: (lambda ctx, n=name: seen.append((n, id(ctx)))) for name in m.STEP_NAMES}
        with patch.dict(m.STEP_FUNCTIONS, table):
            m.worker()
        self.assertEqual([n for n, _ in seen], list(m.STEP_NAMES))
        self.assertEqual(len({i for _, i in seen}), 1)
        self.assertEqual(set(m.load_state(NONCE)['steps'].values()), {'ok'})
        trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))

        def fail(ctx):
            raise trial.Failure('fixed child failed', 17, 'child-exit', 17)
        seen.clear()
        with patch.dict(m.STEP_FUNCTIONS, dict(table, cluster=fail)):
            with self.assertRaises(trial.Failure) as raised:
                m.worker()
        self.assertEqual((raised.exception.code, raised.exception.child_status), (17, 17))
        state = m.load_state(NONCE)
        self.assertEqual(state['failure'], {'step': 'cluster', 'category': 'child-exit', 'child_status': 17})
        self.assertEqual(state['steps']['namespace'], 'not-run')
        self.assertEqual([n for n, _ in seen], list(m.STEP_NAMES[:m.STEP_NAMES.index('cluster')]))

    def test_guardian_waits_for_the_gate_runs_one_worker_and_holds_until_cancel(self):
        m = self.m
        marker = self.worker_script(WORKER_EXITS)
        self.open_gate()
        done = m.load_state(NONCE)
        done['steps'] = {n: 'ok' for n in m.STEP_NAMES}  # the Viewer hold is only for a COMPLETED worker
        trial.atomic(self.root / 'steps.json', done)

        def late_cancel():
            self.until(marker.exists)
            REAL_SLEEP(.6)  # the guardian polls every 0.2s: it has observed the worker exit by now
            m.cancel(NONCE)
        code = self.run_guardian(late_cancel)
        self.assertEqual(code, 0)
        self.assertEqual(marker.read_text(), 'w')  # exactly one worker was spawned
        self.assertEqual(self.outcome()['worker'], 0)
        self.assertIs(self.outcome()['closed'], True)
        self.assertEqual(trial.data((self.root / 'guardian.json').read_bytes())['guardian_pid'], os.getpid())
        self.assertEqual(m.load_state(NONCE)['teardown'], 'pending')  # the guardian never writes the state

    def test_closed_gate_prevents_any_worker_and_expiry_closure_is_permanent_and_idempotent(self):
        m = self.m
        marker = self.worker_script(WORKER_EXITS)
        self.open_gate()
        calls = []
        with patch.object(trial, 'call_bounded', side_effect=lambda a, s, env=None: calls.append(a) or (0, b'')):
            self.assertEqual(m.expire(), 0)
            self.assertEqual(m.expire(), 0)
        self.assertEqual(calls, [[m.SYSTEMCTL, 'stop', '--no-block', m.GUARDIAN_UNIT]] * 2)
        self.assertEqual(m.gate_state(self.value), 'closed')  # open marker still exists; closure wins forever
        code = self.run_guardian()
        self.assertNotEqual(code, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.outcome()['guardian']['category'], 'phase-cutoff')
        with patch.object(trial, 'call_bounded', return_value=(5, b'')):
            with self.assertRaises(trial.Failure):
                m.expire()

    def test_worker_sigkill_keeps_the_native_signal_and_closes_the_exact_group(self):
        marker = self.worker_script(WORKER_SIGKILL)
        self.open_gate()
        code = self.run_guardian()
        self.assertTrue(marker.exists())
        self.assertEqual(self.outcome()['worker'], -9)
        self.assertIs(self.outcome()['closed'], True)
        self.assertEqual(code, 128 + 9)

    def test_sigstopped_worker_is_killed_when_the_heartbeat_is_lost(self):
        pidfile = self.worker_script(WORKER_STOPPED)
        self.open_gate()

        def lose():
            self.until(pidfile.exists)
            REAL_SLEEP(.3)
            self.beat(age=60)
        code = self.run_guardian(lose)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.outcome()['guardian']['category'], 'heartbeat-loss')
        self.assertIs(self.outcome()['closed'], True)
        self.assertFalse(process_alive(int(pidfile.read_text())))

    def test_boot_change_while_the_worker_runs_ends_the_guardian_and_leaves_cleanup_to_poststop(self):
        m = self.m
        pidfile = self.worker_script(WORKER_STOPPED)
        self.open_gate()

        def reboot():
            self.until(pidfile.exists)
            REAL_SLEEP(.3)
            trial.kernel_boot.return_value = '33333333-3333-4333-8333-333333333333'
        self.assertNotEqual(self.run_guardian(reboot), 0)
        self.assertEqual(self.outcome()['guardian']['category'], 'boot-change')
        self.assertIs(self.outcome()['closed'], True)
        self.assertFalse(process_alive(int(pidfile.read_text())))
        self.assertEqual(m.load_state(NONCE)['teardown'], 'pending')  # poststop, not the guardian, finalizes

    # -- A3: serialized poststop --------------------------------------------------------------------------
    def with_storage(self, **private):
        m = self.m
        m.STORAGE.mkdir(mode=0o700)
        (m.STORAGE / 'nested').mkdir()
        (m.STORAGE / 'nested' / 'file').write_text('x')
        info = os.lstat(m.STORAGE)
        state = m.load_state(NONCE)
        state['private'].update(storage_ino=[info.st_dev, info.st_ino], **private)
        trial.atomic(self.root / 'steps.json', state)

    def write_outcome(self, **change):
        record = {'schema': 1, 'nonce': NONCE, 'worker': -9, 'closed': True, 'guardian': None}
        record.update(change)
        trial.atomic(self.root / 'outcome.json', record)

    def test_poststop_requires_independent_absence_before_removing_storage_and_is_single_writer(self):
        m = self.m
        self.with_storage()
        self.write_outcome()
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)  # never a positive completion
        state = m.load_state(NONCE)
        self.assertEqual((state['teardown'], state['private']['worker_exit']), ('uncertain', -9))
        self.assertIs(state['private']['teardown_observed_clean'], False)  # storage retained (#510)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())  # absence proofs held, storage still kept
        self.assertTrue((self.root / m.RELEASE_CLOSED).exists())
        with self.assertRaises(trial.Failure):  # the worker/any other writer is refused after the claim
            m.save_state(state)
        before = (self.root / 'steps.json').read_bytes()
        self.assertEqual(m.poststop(), 1)  # read-only duplicate, never positive
        self.assertEqual((self.root / 'steps.json').read_bytes(), before)

    def test_surviving_or_unreadable_worker_cgroup_withholds_storage_removal_and_clean_receipt(self):
        m = self.m
        for name, procs in (('survivor', '%d\n999999\n' % os.getpid()), ('unreadable', None)):
            with self.subTest(name):
                for stale in (m.STORAGE, self.root / m.POSTSTOP_CLAIM, self.root / m.RELEASE_CLOSED):
                    if stale.is_dir():
                        shutil.rmtree(stale)
                    else:
                        stale.unlink(missing_ok=True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                self.with_storage()
                self.write_outcome()
                if procs is None:
                    (self.cg / 'cgroup.procs').unlink(missing_ok=True)
                else:
                    (self.cg / 'cgroup.procs').write_text(procs)
                with patch.object(m, 'ABSENCE_SECONDS', .3):
                    self.assertEqual(m.poststop(), 1)
                state = m.load_state(NONCE)
                self.assertEqual(state['teardown'], 'uncertain')
                self.assertIs(state['private']['worker_uncertain'], True)
                self.assertTrue((m.STORAGE / 'nested' / 'file').exists())  # destructive removal refused

    def test_failed_guardian_closure_is_sticky_uncertainty_even_when_the_cgroup_looks_empty(self):
        m = self.m
        self.with_storage()
        self.write_outcome(closed=False, worker=None)
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)
        state = m.load_state(NONCE)
        self.assertEqual((state['teardown'], state['private']['worker_uncertain']), ('uncertain', True))
        self.assertTrue(m.STORAGE.exists())

    def test_one_outer_deadline_bounds_filesystem_work_and_never_follows_links(self):
        m = self.m
        outside = self.temp / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        tree = self.temp / 'tree'
        (tree / 'a' / 'b').mkdir(parents=True)
        (tree / 'a' / 'b' / 'f').write_text('x')
        (tree / 'link').symlink_to(outside)
        with self.assertRaises(trial.Failure):
            m.bounded_rmtree(tree, time.monotonic() - 1)
        self.assertTrue(tree.exists())
        m.bounded_rmtree(tree, time.monotonic() + 30)
        self.assertFalse(tree.exists())
        self.assertEqual((outside / 'keep').read_text(), 'keep')
        # teardown inside an elapsed outer deadline starts no child and reports uncertainty
        self.with_storage(cluster_attempted=True)
        calls = []
        with patch.object(m, 'stdin_bounded', side_effect=lambda *a, **k: calls.append(a) or (0, b'')):
            self.assertEqual(m.teardown(NONCE, outer=time.monotonic() - 1, final=False), 1)
        self.assertEqual(calls, [])
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertTrue(m.STORAGE.exists())

    # -- revision round 1 (R1-R9) ---------------------------------------------------------------------------
    def run_teardown(self, replies, daemons=True, **private):
        """teardown with scripted child replies keyed by argv[1:3]; returns (code, calls)."""
        m = self.m
        self.with_storage(cluster_attempted=True, docker_started=True, **private)
        calls = []

        def fake(argv, secs, *a, **k):
            calls.append(argv)
            key = (argv[1], argv[2]) if len(argv) > 2 else (argv[0],)
            return replies.get(key, (0, b''))
        with patch.object(m, 'stdin_bounded', side_effect=fake), \
                patch.object(m, 'daemons_absent', return_value=daemons):
            return m.teardown(NONCE, outer=time.monotonic() + 50, final=False), calls

    def test_r1_storage_is_removed_only_after_positive_cluster_container_and_daemon_absence(self):
        m = self.m
        ok = {}
        cases = {'cluster delete failed': ({('cluster', 'delete'): (1, b'')}, True),
                 'containers still listed': ({('ps', '--all'): (0, b'abc\n')}, True),
                 'container listing failed': ({('ps', '--all'): (1, b'')}, True),
                 'daemon stop failed': ({('stop', 'docker.socket'): (1, b'')}, True),
                 'daemon processes remain after a successful stop': (ok, False)}
        for name, (replies, daemons) in cases.items():
            with self.subTest(name):
                for stale in (m.STORAGE,):
                    shutil.rmtree(stale, True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                code, _ = self.run_teardown(replies, daemons)
                self.assertEqual(code, 1)
                self.assertTrue((m.STORAGE / 'nested' / 'file').exists())  # destructive removal withheld
                self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        shutil.rmtree(m.STORAGE, True)
        trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
        code, calls = self.run_teardown(ok, True)
        self.assertEqual(code, 1)  # observed clean, but a positive 'complete' is never published
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertIs(m.load_state(NONCE)['private']['teardown_observed_clean'], False)  # storage retained (#510)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        self.assertIn([m.SYSTEMCTL, 'stop', *m.DAEMON_UNITS], calls)

    def test_r1_daemon_absence_needs_an_observed_hierarchy_and_empty_daemon_cgroups(self):
        m = self.m
        slice_dir = self.temp / 'system.slice'
        slice_dir.mkdir()
        (slice_dir / 'cgroup.procs').write_text('')
        docker, containerd = slice_dir / 'docker.service', slice_dir / 'containerd.service'
        with patch.object(m, 'DAEMON_CGROUPS', (docker, containerd)):
            self.assertTrue(m.daemon_cgroups_empty(time.monotonic() + 5))  # units gone, hierarchy observed
            docker.mkdir()
            (docker / 'cgroup.procs').write_text('')
            (docker / 'sub').mkdir()
            (docker / 'sub' / 'cgroup.procs').write_text('4242\n')  # survivor in a SUBGROUP
            with self.assertRaises(trial.Failure):
                m.daemon_cgroups_empty(time.monotonic() + 5)
            self.assertFalse(m.daemons_absent(time.monotonic() + 5))
            (docker / 'sub' / 'cgroup.procs').write_text('')
            with self.assertRaises(trial.Failure):  # an empty SUBGROUP: quiescence is unprovable, never absence
                m.daemon_cgroups_empty(time.monotonic() + 5)
            shutil.rmtree(docker / 'sub')
            self.assertTrue(m.daemon_cgroups_empty(time.monotonic() + 5))
            (slice_dir / ('docker-' + 'a' * 64 + '.scope')).mkdir()  # a container scope outside the unit
            self.assertFalse(m.daemon_cgroups_empty(time.monotonic() + 5))
            (slice_dir / 'cgroup.procs').unlink()  # hierarchy unobserved is never absence
            with self.assertRaises(OSError):
                m.daemon_cgroups_empty(time.monotonic() + 5)
            with patch.object(m, 'ABSENCE_SECONDS', .2):
                self.assertFalse(m.daemons_absent(time.monotonic() + 5))

    def test_r2_worker_absence_covers_every_descendant_cgroup(self):
        m = self.m
        me = os.getpid()
        (self.cg / 'cgroup.procs').write_text('%d\n' % me)
        (self.cg / 'child').mkdir()
        (self.cg / 'child' / 'cgroup.procs').write_text('')
        (self.cg / 'child' / 'grand').mkdir()
        (self.cg / 'child' / 'grand' / 'cgroup.procs').write_text('999999\n')
        self.assertEqual(m.unit_processes(), {me, 999999})
        with patch.object(m, 'ABSENCE_SECONDS', .2):
            self.assertFalse(m.workers_absent(time.monotonic() + 5))
            (self.cg / 'child' / 'grand' / 'cgroup.procs').write_text('')
            # empty subgroups are NOT absence: a sequential walk cannot exclude a process migrating between
            # not-yet-read and already-read subgroups, so unknown quiescence stays uncertain
            self.assertFalse(m.workers_absent(time.monotonic() + 5))
            with self.assertRaises(trial.Failure):
                m.quiescent_processes(self.cg)
            (self.cg / 'child' / 'grand' / 'cgroup.procs').unlink()  # an unreadable subgroup is uncertainty
            self.assertFalse(m.workers_absent(time.monotonic() + 5))
            shutil.rmtree(self.cg / 'child')  # a flat cgroup holding only this process is the one accepted proof
            self.assertTrue(m.workers_absent(time.monotonic() + 5))
        (self.cg / 'child' / 'grand').mkdir(parents=True)
        (self.cg / 'child' / 'cgroup.procs').write_text('')
        # a subgroup survivor withholds storage removal through poststop as well
        (self.cg / 'child' / 'grand' / 'cgroup.procs').write_text('999999\n')
        self.with_storage()
        self.write_outcome()
        with patch.object(m, 'ABSENCE_SECONDS', .2):
            self.assertEqual(m.poststop(), 1)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')

    def test_r3_expiry_attempts_the_fixed_stop_even_when_contract_or_gate_io_fails(self):
        m = self.m
        calls = []
        stop = [m.SYSTEMCTL, 'stop', '--no-block', m.GUARDIAN_UNIT]
        with patch.object(m, 'close_release', side_effect=OSError('gate io')), \
                patch.object(trial, 'call_bounded', side_effect=lambda a, s, env=None: calls.append(a) or (0, b'')):
            with self.assertRaises(OSError):  # the original failure stays primary
                m.expire()
        self.assertEqual(calls, [stop])
        calls.clear()
        (self.root / 'contract.json').unlink()
        with patch.object(trial, 'call_bounded', side_effect=lambda a, s, env=None: calls.append(a) or (0, b'')):
            with self.assertRaises((trial.Failure, OSError)):
                m.expire()
        self.assertEqual(calls, [stop])  # a constant target: nothing from the unreadable contract selected it
        calls.clear()
        with patch.object(m, 'close_release', side_effect=OSError('gate io')), \
                patch.object(trial, 'call_bounded', side_effect=OSError('stop io')):
            with self.assertRaises(OSError):
                m.expire()

    def test_r4_poststop_deadline_starts_at_entry_restores_the_alarm_and_never_publishes_late_complete(self):
        m = self.m
        before = signal.getsignal(signal.SIGALRM)
        self.with_storage()
        self.write_outcome()
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        seen = []
        original = m._poststop
        with patch.object(m, '_poststop', side_effect=lambda entry, clip=None: seen.append(entry) or original(entry, clip)):
            start = time.monotonic()
            self.assertEqual(m.poststop(), 1)
        self.assertTrue(start <= seen[0] <= time.monotonic())
        self.assertIs(signal.getsignal(signal.SIGALRM), before)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        # a positive 'complete' is never published, in time or late, by any writer path
        for until in (time.monotonic() - 1, time.monotonic() + 30, None):
            state = m.load_state(NONCE)
            state['teardown'] = 'complete'
            m.save_state(state, poststop=True, until=until)
            self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        # enumeration itself is bounded by the same deadline
        tree = self.temp / 'wide'
        tree.mkdir()
        for index in range(20):
            (tree / str(index)).write_text('x')
        with self.assertRaises(trial.Failure):
            m.bounded_rmtree(tree, time.monotonic() - 1)
        self.assertEqual(len(list(tree.iterdir())), 20)

    def test_r5_storage_intent_is_durable_before_mkdir_and_an_unrecorded_creation_stays_uncertain(self):
        m = self.m
        ctx = m.Context(self.value, m.ManagementClock(self.value), m.load_state(NONCE))
        seen = []
        real = os.mkdir

        def crash(path, mode=0o777, **kw):
            if str(path) == str(m.STORAGE):
                seen.append(m.load_state(NONCE)['private'].get('storage_intent'))
                real(path, mode)  # the effect happens, then the process is lost before recording the inode
                raise OSError('lost between mkdir and save')
            return real(path, mode, **kw)
        with patch.object(m.os, 'mkdir', side_effect=crash), self.assertRaises(OSError):
            m.step_storage(ctx)
        self.assertEqual(seen, [True])
        state = m.load_state(NONCE)
        self.assertIsNone(state['private'].get('storage_ino'))
        self.assertTrue(m.STORAGE.exists())
        self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30, final=False), 1)  # never adopted
        self.assertTrue(m.STORAGE.exists())
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        shutil.rmtree(m.STORAGE)  # intent recorded but nothing created: nothing unresolved
        trial.atomic(self.root / 'steps.json', dict(m.load_state(NONCE), teardown='pending'))
        self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30, final=False), 1)
        self.assertIs(m.load_state(NONCE)['private']['teardown_observed_clean'], True)

    def test_r6_terminal_outcome_reaches_the_strict_public_receipt_with_native_precedence(self):
        m = self.m
        first = m.STEP_NAMES[0]
        cases = {'sigkill': ({'worker': -9, 'guardian': None}, ('child-signal', -9)),
                 'exit': ({'worker': 17, 'guardian': None}, ('child-exit', 17)),
                 'worker beats guardian': ({'worker': -9, 'guardian': {'category': 'heartbeat-loss', 'child_status': None}},
                                           ('child-signal', -9)),
                 'guardian loss': ({'worker': None, 'guardian': {'category': 'heartbeat-loss', 'child_status': None}},
                                   ('heartbeat-loss', None)),
                 'cancel': ({'worker': None, 'guardian': {'category': 'interrupted', 'child_status': None}},
                            ('interrupted', None)),
                 'forged category': ({'worker': None, 'guardian': {'category': 'none', 'child_status': None}},
                                     ('exception', None))}
        for name, (outcome, (category, status)) in cases.items():
            with self.subTest(name):
                state = m.initial_state(NONCE)
                m.apply_terminal(state, dict(outcome, nonce=NONCE))
                self.assertEqual(state['failure'], {'step': first, 'category': category, 'child_status': status})
                self.assertEqual(state['steps'][first], 'failed')
                m.validate_result(m.public_record(state), NONCE)
        recorded = m.initial_state(NONCE)
        recorded['steps'][first] = 'failed'
        recorded['failure'] = {'step': first, 'category': 'phase-cutoff', 'child_status': None}
        m.apply_terminal(recorded, {'worker': -9, 'guardian': None})
        self.assertEqual(recorded['failure']['category'], 'phase-cutoff')  # the worker's own primary is kept
        done = m.initial_state(NONCE)
        done['steps'] = {n: 'ok' for n in m.STEP_NAMES}
        m.apply_terminal(done, {'worker': 0, 'guardian': {'category': 'interrupted', 'child_status': None}})
        self.assertIsNone(done['failure'])  # nothing is invented once every step finished and the worker exited 0
        for status in (17, -15, -9):
            late = m.initial_state(NONCE)
            late['steps'] = {n: 'ok' for n in m.STEP_NAMES}
            late['observed'] = {k: True for k in m.OBSERVED}
            m.apply_terminal(late, {'worker': status, 'guardian': None})
            self.assertIsNone(late['failure'])  # all 18 successful step facts are NOT rewritten (#510)
            self.assertEqual(set(late['steps'].values()), {'ok'})
            m.record_terminal(late, {'worker': status, 'closed': True,
                                     'terminal': {'status': status, 'origin': 'pre-close', 'group': 'uncertain'}}, True)
            self.assertEqual(late['terminal'], {'status': status, 'origin': 'pre-close', 'group': 'closure-reported'})
            late['teardown'] = 'complete'
            self.assertFalse(m.succeeded(m.validate_result(m.public_record(late), NONCE)))  # nonzero terminal
        earlier = m.initial_state(NONCE)
        earlier['steps'] = {n: 'ok' for n in m.STEP_NAMES}
        earlier['steps'][m.STEP_NAMES[-1]] = 'failed'
        earlier['failure'] = {'step': m.STEP_NAMES[-1], 'category': 'phase-cutoff', 'child_status': None}
        m.apply_terminal(earlier, {'worker': 17, 'guardian': None})
        self.assertEqual(earlier['failure']['category'], 'phase-cutoff')  # an earlier primary always wins
        # through poststop: the public record carries the signal AND the sticky uncertainty
        self.with_storage()
        self.write_outcome(worker=-9, closed=False)
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)
        public = m.validate_result(m.public_record(m.load_state(NONCE)), NONCE)
        self.assertEqual((public['failure']['category'], public['failure']['child_status'], public['teardown']),
                         ('child-signal', -9, 'uncertain'))

    # -- #510: storage retention and independent closed terminal evidence ------------------------------------
    def test_s1_no_production_call_site_can_destroy_storage(self):
        source = Path(self.m.__file__).read_text()
        self.assertEqual(source.count('bounded_rmtree('), 1)  # the definition only: no production call
        for forbidden in ('shutil.rmtree', 'rmtree(STORAGE', 'os.removedirs'):
            self.assertNotIn(forbidden, source)

    def test_s1_storage_is_retained_with_every_cleanup_success_input_true_and_in_every_path(self):
        m = self.m
        self.write_outcome(worker=0)
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.with_storage()
        self.assertEqual(m.poststop(), 1)  # absence proofs true, matching inode, direct poststop entry
        state = m.load_state(NONCE)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        self.assertEqual((state['teardown'], state['private']['storage_ino'] is not None), ('uncertain', True))
        self.assertIs(state['private']['teardown_observed_clean'], False)
        self.assertIs(state['private']['storage_retained'], True)
        for storage_allowed in (True, False):  # direct teardown and a duplicate entry: same retention
            with patch.object(m, 'daemons_absent', return_value=True):
                self.assertEqual(m.teardown(NONCE, storage_allowed=storage_allowed, final=True,
                                            outer=time.monotonic() + 30), 1)
            self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
            self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertEqual(m.poststop(), 1)  # read-only duplicate
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())

    def test_s1_missing_foreign_unreadable_and_transient_cases_retain_storage_credentials_still_go(self):
        m = self.m
        cases = {'foreign inode': lambda s: s['private'].update(storage_ino=[0, 0]),
                 'missing inode record': lambda s: s['private'].pop('storage_ino'),
                 'intent only': lambda s: s['private'].update(storage_intent=True, storage_ino=None)}
        for name, change in cases.items():
            with self.subTest(name):
                shutil.rmtree(m.STORAGE, True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                self.with_storage()
                state = m.load_state(NONCE)
                change(state)
                trial.atomic(self.root / 'steps.json', state)
                trial.exclusive(m.WORK / 'viewer.json', b'secret') if not (m.WORK / 'viewer.json').exists() else None
                with patch.object(m, 'daemons_absent', return_value=True):
                    self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30), 1)
                self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
                self.assertFalse((m.WORK / 'viewer.json').exists())  # protective credential removal remains
                self.assertIs(m.load_state(NONCE)['private']['teardown_observed_clean'], False)
        shutil.rmtree(m.STORAGE, True)
        trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
        self.with_storage()
        real_present = m.present

        def unreadable(path):
            if path == m.STORAGE:
                raise OSError('EIO')
            return real_present(path)
        with patch.object(m, 'present', side_effect=unreadable), \
                patch.object(m, 'daemons_absent', return_value=True):  # unknown read error is never absence
            self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30), 1)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        (self.cg / 'sub').mkdir()  # a transient subgroup: quiescence unprovable, storage still retained
        (self.cg / 'sub' / 'cgroup.procs').write_text('')
        self.write_outcome(worker=0)
        with patch.object(m, 'ABSENCE_SECONDS', .3):
            self.assertEqual(m.poststop(), 1)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        self.assertIs(m.load_state(NONCE)['private']['worker_uncertain'], True)

    def fake_group(self, statuses, settled, closed=True, raises=False):
        """OwnedGroup stand-in with the real surface the guardian uses: ``status()`` (non-reaping), ``close()``
        and the settled ``proc.returncode``. ``close`` is the SOLE closure; nothing waits or polls again."""
        test = self

        class Group:
            def __init__(self, proc):
                self.proc, self.calls, self.closes = SimpleNamespace(returncode=None), 0, 0

            def status(self):
                self.calls += 1
                if self.calls == 1 and len(statuses) == 1:
                    test.beat(age=60)  # heartbeat loss after the first look: the guardian must close the group
                return statuses[self.calls - 1] if self.calls <= len(statuses) else None

            def close(self, *args, **kw):
                self.closes += 1
                self.proc.returncode = settled
                if raises:
                    raise RuntimeError('close failed')
                return closed
        return Group

    def run_fake_guardian(self, Group):
        for stale in ('guardian.json', 'outcome.json', self.m.RELEASE_OPEN, self.m.RELEASE_CLOSED):
            (self.root / stale).unlink(missing_ok=True)  # each run is a fresh one-shot guardian
        self.beat()
        self.worker_script(WORKER_EXITS)
        self.open_gate()
        with patch.object(self.m.owned_process, 'OwnedGroup', Group):
            return self.run_guardian()

    def test_s2_exit17_between_the_last_none_status_and_close_is_exposed_despite_close_false(self):
        for closed, raises in ((False, False), (True, False), (False, True)):
            with self.subTest((closed, raises)):
                self.beat()
                (self.root / 'outcome.json').unlink(missing_ok=True)
                self.run_fake_guardian(self.fake_group([None], 17, closed=closed, raises=raises))
                out = self.outcome()
                self.assertIsNone(out['worker'])
                self.assertEqual(out['terminal'], {'status': 17, 'origin': 'closure-window', 'group': 'uncertain'})

    def test_s2_preclose_status_wins_and_closure_window_is_never_promoted_to_preclose(self):
        self.run_fake_guardian(self.fake_group([None, -15], -9))  # a status seen before closure beats the settled one
        self.assertEqual(self.outcome()['terminal']['origin'], 'pre-close')
        for settled, expected in ((-15, ('closure-window', -15)), (-9, ('closure-window', -9)), (0, ('closure-window', 0))):
            with self.subTest(settled):
                self.beat()
                (self.root / 'outcome.json').unlink(missing_ok=True)
                self.run_fake_guardian(self.fake_group([None], settled))
                self.assertEqual((self.outcome()['terminal']['origin'], self.outcome()['terminal']['status']), expected)
        for settled in (None, True, 256, -65, '17', 17.0):  # unavailable or invalid status stays unobserved
            with self.subTest(settled):
                self.beat()
                (self.root / 'outcome.json').unlink(missing_ok=True)
                self.run_fake_guardian(self.fake_group([None], settled))
                self.assertEqual(self.outcome()['terminal'], {'status': None, 'origin': 'unobserved', 'group': 'uncertain'})

    def all_ok_state(self):
        state = self.m.load_state(NONCE)
        state['steps'] = {n: 'ok' for n in self.m.STEP_NAMES}
        state['observed'] = {k: True for k in self.m.OBSERVED}
        trial.atomic(self.root / 'steps.json', state)

    def test_s2_all18_ok_with_a_later_terminal_17_keeps_every_step_fact_and_exposes_the_terminal(self):
        m = self.m
        self.all_ok_state()
        self.with_storage()
        self.write_outcome(worker=None, closed=False,
                           terminal={'status': 17, 'origin': 'closure-window', 'group': 'uncertain'})
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)
        public = m.validate_result(m.public_record(m.load_state(NONCE)), NONCE)
        self.assertEqual(set(public['steps'].values()), {'ok'})
        self.assertIsNone(public['failure'])
        self.assertEqual(public['terminal'], {'status': 17, 'origin': 'closure-window', 'group': 'uncertain'})
        self.assertFalse(m.succeeded(public))
        self.assertEqual(json.loads(m.result(NONCE))['terminal']['status'], 17)  # guest export carries it too
        with self.assertRaises(trial.Failure):
            m.export_viewer(NONCE)  # an observed nonzero terminal status refuses the Viewer export

    def test_s2_earlier_primary_stays_primary_with_a_separate_secondary_terminal(self):
        m = self.m
        state = m.load_state(NONCE)
        state['steps'][m.STEP_NAMES[0]] = 'failed'
        state['failure'] = {'step': m.STEP_NAMES[0], 'category': 'phase-cutoff', 'child_status': None}
        trial.atomic(self.root / 'steps.json', state)
        self.write_outcome(worker=17, terminal={'status': 17, 'origin': 'pre-close', 'group': 'uncertain'})
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)
        public = m.validate_result(m.public_record(m.load_state(NONCE)), NONCE)
        self.assertEqual(public['failure'], {'step': m.STEP_NAMES[0], 'category': 'phase-cutoff', 'child_status': None})
        self.assertEqual(public['terminal'], {'status': 17, 'origin': 'pre-close', 'group': 'closure-reported'})

    def test_s2_group_uncertainty_is_independent_and_sticky_and_missing_or_invalid_outcomes_stay_unobserved(self):
        m = self.m
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.write_outcome(worker=0, terminal={'status': 0, 'origin': 'pre-close', 'group': 'uncertain'})
        self.assertEqual(m.poststop(), 1)
        self.assertEqual(m.load_state(NONCE)['terminal'], {'status': 0, 'origin': 'pre-close', 'group': 'closure-reported'})
        # missing outcome: unknown, sticky uncertain, never absence or success
        for stale in (self.root / m.POSTSTOP_CLAIM, self.root / 'outcome.json'):
            stale.unlink(missing_ok=True)
        trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
        self.assertEqual(m.poststop(), 1)
        state = m.load_state(NONCE)
        self.assertEqual(state['terminal'], {'status': None, 'origin': 'unobserved', 'group': 'uncertain'})
        self.assertIs(state['private']['worker_uncertain'], True)
        for bad in ({'status': '17', 'origin': 'pre-close', 'group': 'uncertain'},
                    {'status': True, 'origin': 'closure-window', 'group': 'uncertain'},
                    {'status': 17, 'origin': 'unobserved', 'group': 'uncertain'},
                    {'status': 999, 'origin': 'pre-close', 'group': 'uncertain'},
                    {'status': 17, 'origin': 'pre-close', 'group': 'uncertain', 'path': '/x'}, None, 'x'):
            with self.subTest(bad):
                (self.root / m.POSTSTOP_CLAIM).unlink(missing_ok=True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                self.write_outcome(worker=None, terminal=bad)
                self.assertEqual(m.poststop(), 1)
                self.assertEqual(m.load_state(NONCE)['terminal']['origin'], 'unobserved')

    def test_s2_a_genuine_earlier_preclose_observation_is_not_erased_by_a_later_unknown_origin(self):
        m = self.m
        state = m.load_state(NONCE)
        state['terminal'] = {'status': 17, 'origin': 'pre-close', 'group': 'uncertain'}
        trial.atomic(self.root / 'steps.json', state)
        self.write_outcome(worker=None, closed=False)  # this outcome observed nothing
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
        self.assertEqual(m.poststop(), 1)
        self.assertEqual(m.load_state(NONCE)['terminal']['status'], 17)

    def test_s2_signal_handler_exit17_is_an_observed_closure_window_17_not_a_causal_claim(self):
        m = self.m
        self.run_fake_guardian(self.fake_group([None], 17))  # a handler that answers our SIGTERM with 17
        terminal = self.outcome()['terminal']
        self.assertEqual((terminal['status'], terminal['origin']), (17, 'closure-window'))
        self.assertNotEqual(terminal['origin'], 'pre-close')
        self.assertTrue(m.terminal_ok(terminal))

    def test_r7_guardian_enforces_the_current_phase_cutoff_independently_of_worker_progress(self):
        m = self.m
        now = time.monotonic()
        late = deepcopy(self.capsule)
        late['cutoffs']['stage'] = now - 1  # only the stage cutoff has passed
        clock = m.ManagementClock(self.value, capsule=late)
        with self.assertRaises(trial.Failure) as raised:  # a stuck stage step is killed at ITS cutoff
            m.supervise_worker(self.value, clock)
        self.assertEqual(raised.exception.category, 'phase-cutoff')
        state = m.load_state(NONCE)
        for name in m.STEP_NAMES[:m.STEP_NAMES.index('storage')]:
            state['steps'][name] = 'ok'
        trial.atomic(self.root / 'steps.json', state)
        m.supervise_worker(self.value, clock)  # the first unfinished step is a work step: its own cutoff governs
        gone = deepcopy(self.capsule)
        gone['cutoffs']['work'] = now - 1
        with self.assertRaises(trial.Failure):  # nothing the worker runs outlives the work cutoff
            m.supervise_worker(self.value, m.ManagementClock(self.value, capsule=gone))
        state['steps'] = {n: 'ok' for n in m.STEP_NAMES}
        trial.atomic(self.root / 'steps.json', state)
        with self.assertRaises(trial.Failure):
            m.supervise_worker(self.value, m.ManagementClock(self.value, capsule=gone))

    def test_r7_a_worker_that_exits_cleanly_before_finishing_gets_no_persistence_hold(self):
        marker = self.worker_script(WORKER_EXITS)
        self.open_gate()
        code = self.run_guardian()  # steps are still not-run: there is no Viewer to hold
        self.assertTrue(marker.exists())
        self.assertNotEqual(code, 0)
        self.assertEqual(self.outcome()['guardian']['category'], 'status-invalid')
        self.assertIs(self.outcome()['closed'], True)

    def test_r9_correlation_uses_the_original_effective_bracket_not_the_raw_caller_wall(self):
        m = self.m
        clock = m.ManagementClock(self.value)
        wall, mono = time.time(), time.monotonic()
        sample = {'boot': MGMT_BOOT, 'nonce': 'e' * 32, 'wall': wall - 3600, 'mono': 5000.0}
        # a caller wall rolled back an hour (retained monotonic-derived wall unchanged) cannot legitimise
        # a guest sample from that earlier wall time
        with self.assertRaises(trial.Failure):
            m.build_capsule(self.value, clock, sample, 'e' * 32, (wall - 3600, mono), (wall - 3599, mono + 1))
        ok = m.build_capsule(self.value, clock, dict(sample, wall=wall), 'e' * 32, (wall, mono), (wall + 1, mono + 1))
        self.assertAlmostEqual(ok['caller']['recv_eff'] - ok['caller']['send_eff'], ok['caller']['roundtrip'])
        forged = deepcopy(ok)
        forged['sample']['wall'] = wall - 3600
        forged['caller'].update(send_wall=wall - 3600, recv_wall=wall - 3599)
        with self.assertRaises(trial.Failure):
            m.validate_capsule(forged, self.value)

    # -- revision round 2 (final): F1-F6 --------------------------------------------------------------------
    def poststop_fixture(self, **outcome):
        self.with_storage()
        self.write_outcome(**outcome)
        (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())

    def test_f1_slow_publication_crossing_the_deadline_and_every_path_never_publish_complete(self):
        m = self.m
        self.poststop_fixture()
        self.assertEqual(m.poststop(), 1)
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        published, real = [], trial.atomic

        def slow(path, value):
            published.append(value['teardown'])
            REAL_SLEEP(.3)  # the write itself crosses the deadline
            return real(path, value)
        state = m.load_state(NONCE)
        state['teardown'] = 'complete'
        with patch.object(trial, 'atomic', side_effect=slow):
            m.save_state(state, poststop=True, until=time.monotonic() + .1)
        self.assertEqual(published, ['uncertain'])
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')
        self.assertEqual(m.poststop(), 1)  # the duplicate path is never positive either
        stored = m.load_state(NONCE)
        stored['teardown'] = 'complete'  # a stored 'complete' is not trusted by a direct teardown
        trial.atomic(self.root / 'steps.json', stored)
        (self.root / m.POSTSTOP_CLAIM).unlink()
        self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30, final=False), 1)
        self.assertEqual(m.load_state(NONCE)['teardown'], 'uncertain')

    def test_f1_the_interruptible_alarm_is_clipped_to_the_original_remaining_deadline_and_never_renewed(self):
        m = self.m
        self.poststop_fixture()
        calls, real = [], signal.setitimer

        def record(which, seconds, *rest):
            calls.append(seconds)
            return real(which, seconds, *rest)
        with patch.object(m.ManagementClock, 'cleanup_remaining', return_value=7.0), \
                patch.object(signal, 'setitimer', side_effect=record):
            m.poststop()
        self.assertEqual(calls[0], m.POSTSTOP_OUTER_SECONDS)
        self.assertTrue(0 < calls[1] <= 7.0)  # clipped to the clock-derived remainder, only ever shorter
        self.assertEqual(calls[2:], [0])      # no later read re-arms or extends it
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_f2_native_failure_after_all_steps_ok_reaches_the_public_receipt_with_sticky_uncertainty(self):
        m = self.m
        for status, expected in ((17, ('child-exit', 17)), (-15, ('child-signal', -15))):
            with self.subTest(status):
                for stale in (self.root / m.POSTSTOP_CLAIM, self.root / m.RELEASE_CLOSED):
                    stale.unlink(missing_ok=True)
                shutil.rmtree(m.STORAGE, True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                self.poststop_fixture(worker=status, closed=True)
                done = m.load_state(NONCE)
                done['steps'] = {n: 'ok' for n in m.STEP_NAMES}
                done['observed'] = {k: True for k in m.OBSERVED}
                trial.atomic(self.root / 'steps.json', done)
                self.assertEqual(m.poststop(), 1)
                public = m.validate_result(m.public_record(m.load_state(NONCE)), NONCE)
                self.assertEqual((public['failure']['category'], public['failure']['child_status']), expected)
                self.assertEqual(public['failure']['step'], m.STEP_NAMES[-1])
                self.assertFalse(m.succeeded(public))
                self.assertEqual(m.load_state(NONCE)['private']['worker_exit'], status)

    def test_f2_missing_or_invalid_outcome_is_unknown_and_sticky_uncertain(self):
        m = self.m
        for name, writer in (('missing', lambda: None), ('invalid', lambda: (self.root / 'outcome.json').write_text('{'))):
            with self.subTest(name):
                for stale in (self.root / m.POSTSTOP_CLAIM, self.root / m.RELEASE_CLOSED, self.root / 'outcome.json'):
                    stale.unlink(missing_ok=True)
                shutil.rmtree(m.STORAGE, True)
                trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
                self.with_storage()
                (self.cg / 'cgroup.procs').write_text('%d\n' % os.getpid())
                writer()
                with patch.object(m, 'ABSENCE_SECONDS', .3):
                    self.assertEqual(m.poststop(), 1)
                state = m.load_state(NONCE)
                self.assertEqual(state['teardown'], 'uncertain')
                self.assertIs(state['private']['worker_uncertain'], True)
                self.assertTrue((m.STORAGE / 'nested' / 'file').exists())  # no destructive removal without evidence

    def test_f2_an_already_exited_native_status_is_observed_before_a_concurrent_cutoff_can_obscure_it(self):
        m = self.m
        marker = self.worker_script('import sys\nopen(%r, "a").write("w")\nsys.exit(17)\n')
        self.open_gate()
        real = m.owned_process.OwnedGroup

        class Exited(real):
            def status(self):  # the worker has already exited when the guardian first looks
                end = time.monotonic() + 10
                while True:
                    seen = super().status()
                    if seen is not None or time.monotonic() > end:
                        return seen
                    REAL_SLEEP(.02)
        cutoff = trial.Failure('absolute phase cutoff', 124, 'phase-cutoff')
        with patch.object(m.owned_process, 'OwnedGroup', Exited), patch.object(m, 'supervise_worker', side_effect=cutoff):
            code = self.run_guardian()
        self.assertEqual(marker.read_text(), 'w')
        self.assertEqual(code, 17)
        self.assertEqual(self.outcome()['worker'], 17)
        self.assertIsNone(self.outcome()['guardian'])  # the cutoff did not replace the native status

    def test_f3_only_a_genuine_missing_path_is_absent(self):
        m = self.m
        self.assertFalse(m.present(self.temp / 'missing'))
        self.assertTrue(m.present(self.temp))
        for error in (PermissionError(13, 'denied'), OSError(5, 'io'), NotADirectoryError(20, 'notdir')):
            with patch.object(m.os, 'lstat', side_effect=error), self.assertRaises(OSError):
                m.present(self.temp / 'x')
        # storage that cannot be observed is never deleted and never reported clean
        self.with_storage()
        real = os.lstat

        def lstat(path, *args, **kwargs):
            if str(path) == str(m.STORAGE):
                raise PermissionError(13, 'denied')
            return real(path, *args, **kwargs)
        with patch.object(m.os, 'lstat', side_effect=lstat):
            self.assertEqual(m.teardown(NONCE, outer=time.monotonic() + 30, final=False), 1)
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        state = m.load_state(NONCE)
        self.assertEqual(state['teardown'], 'uncertain')
        self.assertIs(state['private']['teardown_observed_clean'], False)
        # an unrecorded creation whose path cannot be observed also stays unresolved
        shutil.rmtree(m.STORAGE)
        fresh = m.initial_state(NONCE)
        fresh['private']['storage_intent'] = True
        trial.atomic(self.root / 'steps.json', fresh)
        with patch.object(m.os, 'lstat', side_effect=lstat):
            m.teardown(NONCE, outer=time.monotonic() + 30, final=False)
        self.assertIs(m.load_state(NONCE)['private']['teardown_observed_clean'], False)
        # an unobservable daemon cgroup is unknown, never absence
        slice_dir = self.temp / 'system.slice'
        slice_dir.mkdir()
        (slice_dir / 'cgroup.procs').write_text('')
        with patch.object(m, 'DAEMON_CGROUPS', (slice_dir / 'docker.service', slice_dir / 'containerd.service')), \
                patch.object(m, 'present', side_effect=PermissionError(13, 'denied')), \
                patch.object(m, 'ABSENCE_SECONDS', .2):
            with self.assertRaises(OSError):
                m.daemon_cgroups_empty(time.monotonic() + 5)
            self.assertFalse(m.daemons_absent(time.monotonic() + 5))

    def test_f4_a_process_moving_between_subgroups_is_never_proven_absent(self):
        m = self.m
        me = os.getpid()
        (self.cg / 'cgroup.procs').write_text('%d\n' % me)
        for name in ('a', 'b'):
            (self.cg / name).mkdir()
            (self.cg / name / 'cgroup.procs').write_text('')
        real = m.cgroup_processes
        moved = []

        def migrate(directory, deadline=None):
            found = real(directory, deadline)
            if not moved:  # the survivor hops from the not-yet-read subgroup into the already-read one
                moved.append(True)
                (self.cg / 'a' / 'cgroup.procs').write_text('424242\n')
            return found
        with patch.object(m, 'cgroup_processes', side_effect=migrate), patch.object(m, 'ABSENCE_SECONDS', .2):
            self.assertFalse(m.workers_absent(time.monotonic() + 5))
        self.poststop_fixture()
        with patch.object(m, 'ABSENCE_SECONDS', .2):
            self.assertEqual(m.poststop(), 1)  # subgroups present: unknown quiescence, no destructive removal
        self.assertTrue((m.STORAGE / 'nested' / 'file').exists())
        self.assertIs(m.load_state(NONCE)['private']['worker_uncertain'], True)

    def test_f5_the_native_stop_is_requested_before_and_independent_of_blocking_gate_io(self):
        m = self.m
        events = []

        def stop(argv, seconds, env=None):
            events.append(('stop', argv))
            return 0, b''

        def blocked():
            events.append(('contract',))
            raise OSError('blocked gate io')
        with patch.object(trial, 'call_bounded', side_effect=stop), patch.object(m, 'contract_any', side_effect=blocked):
            with self.assertRaises(OSError):  # the gate failure stays primary
                m.expire()
        self.assertEqual(events, [('stop', [m.SYSTEMCTL, 'stop', '--no-block', m.GUARDIAN_UNIT]), ('contract',)])
        events.clear()
        with patch.object(trial, 'call_bounded', side_effect=stop), patch.object(m, 'close_release'):
            with self.assertRaises(trial.Failure):  # closure that cannot be confirmed is a failure, not success
                m.expire()
        self.assertEqual([e[0] for e in events], ['stop'])
        events.clear()
        with patch.object(trial, 'call_bounded', side_effect=stop):
            self.assertEqual(m.expire(), 0)  # normal path: stop first, then permanent closure verified
        self.assertEqual(m.gate_state(self.value), 'closed')

    def test_f6_intent_is_file_rename_and_directory_fsynced_before_mkdir_and_failure_refuses_the_effect(self):
        m = self.m
        events = []
        real_fsync, real_replace, real_mkdir = os.fsync, os.replace, os.mkdir

        def fsync(fd):
            events.append('fsync-dir' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'fsync-file')
            return real_fsync(fd)

        def replace(source, target, *args, **kwargs):
            events.append('replace')
            return real_replace(source, target, *args, **kwargs)

        def mkdir(path, mode=0o777, **kwargs):
            if str(path) == str(m.STORAGE):
                events.append('mkdir')
            return real_mkdir(path, mode, **kwargs)
        ctx = m.Context(self.value, m.ManagementClock(self.value), m.load_state(NONCE))
        with patch.object(os, 'fsync', side_effect=fsync), patch.object(os, 'replace', side_effect=replace), \
                patch.object(os, 'mkdir', side_effect=mkdir):
            m.step_storage(ctx)
        self.assertEqual(events[:4], ['fsync-file', 'replace', 'fsync-dir', 'mkdir'])
        shutil.rmtree(m.STORAGE)
        trial.atomic(self.root / 'steps.json', m.initial_state(NONCE))
        ctx = m.Context(self.value, m.ManagementClock(self.value), m.load_state(NONCE))

        def failing(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, 'directory fsync failed')
            return real_fsync(fd)
        with patch.object(os, 'fsync', side_effect=failing), self.assertRaises(OSError):
            m.step_storage(ctx)
        self.assertFalse(m.STORAGE.exists())  # a failed durable publication refuses the effect

    def test_teardown_children_run_inside_the_single_outer_deadline(self):
        m = self.m
        self.with_storage(cluster_attempted=True)
        seconds = []
        with patch.object(m, 'stdin_bounded',
                          side_effect=lambda argv, secs, *a, **k: seconds.append(secs) or (0, b'')):
            m.teardown(NONCE, outer=time.monotonic() + 50, final=False)
        self.assertTrue(seconds and all(0 < s <= 50 for s in seconds))
