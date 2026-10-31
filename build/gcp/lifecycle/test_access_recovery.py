"""Required failed-disposal entrypoint tests: fake HTTP/CAS, no native/cloud.

Run: python3 -B -m unittest discover -s build/gcp/lifecycle -t build/gcp -p test_access_recovery.py -v
Local process evidence is a trusted lead-review fixture, not OS attestation.
"""
import copy
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from . import spec
from .access_records import AccessError, Context, GcsAccessRecords, KINDS, canonical, digest
from .access_recovery import (FailedAccessRecovery, GcsFailedDisposals, LIMIT,
                              OWNER_SELF, OwnerRecovery, ReadCloud, path, validate_proof)
from .auth_http import HttpResponse
from .cloud import ApiError, ForbiddenOperation
from .controller import Controller, Refused
from .gcs import StoreError
from .oslogin import OwnKeyImport, SelfLogin
from .test_access import BUCKET, GCS, key
from .test_lifecycle import U1, U2
from .test_vlab_trial_profile import FIELDS, world

TRIAL = 'a' * 40
POLICY_SOURCE = 'b' * 40


class Profile:
    def __init__(self):
        self.value = {'name': OWNER_SELF, 'posixAccounts': [dict(username='owner', uid='1234', gid='1234',
                    homeDirectory='/home/owner', operatingSystemType='LINUX')], 'sshPublicKeys': {}}
        self.calls = []
        self.status = 200
        self.on_get = None

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        assert method == 'GET'
        assert unquote(urlsplit(url).path) == '/v1/users/art@githedgehog.com/loginProfile'
        if self.on_get:
            self.on_get()
        return HttpResponse(self.status, canonical(self.value))

    def add(self, text, expiry='0', fp='opaque'):
        self.value['sshPublicKeys'][fp] = dict(key=text, expirationTimeUsec=expiry,
            fingerprint=fp, name=OWNER_SELF + '/sshPublicKeys/' + fp)


class Fixture:
    def __init__(self):
        self.w = world()
        self.w.started()
        self.gcs = GCS(self.w)
        self.records = GcsAccessRecords(BUCKET, token_provider=lambda: 'fake', transport=self.gcs)
        self.w.ctl = Controller(self.w.store, self.w.cloud, self.w.cfg, access_records=self.records)
        rec = self.w.record()
        self.context = self.w.ctl.register_access(U1, producer_run_id=1, producer_attempt=1,
            self_user=OWNER_SELF, public_key_text=key(), expected_trial={k: rec[k] for k in FIELDS})
        self.profile = Profile()
        self.login = SelfLogin.for_owner(OWNER_SELF, token_provider=lambda: 'fake', transport=self.profile)
        self.producer = OwnKeyImport(self.records, self.context, self.login,
                                     producer_run_id=1, producer_attempt=1, now=self.w.clock.now)
        self.intent, self.intent_gen = self.producer.prepare(key())
        self.original = self.w.record()
        assert self.w.ctl.reconcile(U1).status == 'blocked'
        # FakeCloud's old delete fake omits targetId. Supply the genuine provider
        # field explicitly; recovery must refuse when it is missing/wrong.
        for op in self.w.raw.ops.values():
            op['targetLink'] = 'https://compute.googleapis.com/compute/v1/projects/' + spec.PROJECT + '/zones/' + spec.ZONE + '/instances/' + self.original['names']['instance']
            if op['operationType'] == 'delete':
                op['targetId'] = self.original['ids']['instance']
        self.w.clock.advance(21)
        self.expected = self.w.store.read(self.w.cfg.key)
        self.decision = dict(reference='https://github.com/afewell-hh/labapp/issues/361#issuecomment-123',
            trial_source_sha=TRIAL, policy_source_sha=POLICY_SOURCE, local_evidence_sha256='c'*64)
        self.local = dict(lease=U1, source_sha=TRIAL, coordinator_sha256='d'*64, registration_sha256='e'*64,
            evidence_sha256='c'*64, terminated_at=spec.rfc3339(self.w.clock.now()-timedelta(minutes=1)),
            checked_at=spec.rfc3339(self.w.clock.now()),
            result='coordinator-children-terminated-private-files-absent')
        self.run = dict(id=1, run_attempt=1, path='.github/workflows/labapp-lifecycle-inspect.yml',
            event='workflow_dispatch', head_branch='main', head_sha=TRIAL,
            repository={'full_name': 'afewell-hh/labapp'}, status='completed', conclusion='cancelled')
        self.latest = dict(self.run, jobs_url='https://api.github.com/repos/afewell-hh/labapp/actions/runs/1/jobs',
            logs_url='https://api.github.com/repos/afewell-hh/labapp/actions/runs/1/logs')
        self.run.update(jobs_url='https://api.github.com/repos/afewell-hh/labapp/actions/runs/1/attempts/1/jobs',
            logs_url='https://api.github.com/repos/afewell-hh/labapp/actions/runs/1/attempts/1/logs')
        self.command_calls, self.github_calls, self.approvals = [], [], []
        self.account = 'art@githedgehog.com'
        self.impersonation, self.dirty, self.head = '(unset)', '', POLICY_SOURCE
        self.checkout = str(Path(__file__).resolve().parents[3])
        self.proofs = GcsFailedDisposals(BUCKET, token_provider=lambda: 'fake', transport=self.gcs)
        collector = OwnerRecovery.collector(local_review=lambda s, d: copy.deepcopy(self.local),
            command=self.command, github=self.github)
        self.engine = FailedAccessRecovery(self.w.store, self.w.cloud, self.records, self.proofs,
            self.login, collect=collector, approve=self.approve, now=self.w.clock.now)
        self.facade = OwnerRecovery(self.engine)

    def command(self, argv, seconds):
        self.command_calls.append(argv)
        choices = {
            ('gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'): self.account,
            ('gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'): self.impersonation,
            ('git', 'rev-parse', 'HEAD'): self.head,
            ('git', 'rev-parse', '--show-toplevel'): self.checkout,
            ('git', 'status', '--porcelain', '--untracked-files=normal'): self.dirty}
        return choices[tuple(argv)].encode()

    def github(self, endpoint):
        self.github_calls.append(endpoint)
        assert endpoint in ('actions/runs/1', 'actions/runs/1/attempts/1')
        return copy.deepcopy(self.latest if endpoint == 'actions/runs/1' and self.latest else self.run)

    def approve(self, sha, decision):
        self.approvals.append((sha, decision))
        return sha

    def proof(self):
        return self.facade.prepare(self.expected, self.decision)

    def recover(self, proof=None):
        return self.facade.recover_failed_access(self.expected, proof or self.proof(), self.decision)

    def refresh_expected(self):
        self.expected = self.w.store.read(self.w.cfg.key)


class Recovery(unittest.TestCase):
    def test_positive_before_original_work_and_vm_deadlines_preserves_failed_history(self):
        f = Fixture()
        proof = f.proof()
        calls = len(f.w.raw.calls)
        writes = len(f.w.store.writes)
        self.assertEqual(f.recover(proof).status, 'failed-disposed')
        self.assertEqual(len(f.w.store.writes), writes+1)
        self.assertFalse([c for c in f.w.raw.calls[calls:] if c[1] in ('insert', 'delete')])
        self.assertTrue(all(c[0] == 'GET' for c in f.profile.calls))
        free = f.w.record()
        self.assertEqual(free['last_release']['outcome'], 'FAILED_DISPOSED')
        retained = free['access_history'][0]
        self.assertEqual((retained['trial'], retained['import_status']), ('FAILED', 'UNKNOWN'))
        self.assertEqual(retained['binding']['deadline'], f.original['deadline'])
        self.assertLess(f.w.clock.now(), spec_time(f.original['access']['binding']['work_deadline']))
        self.assertEqual(proof['slot'], f.expected[0])
        self.assertEqual(proof['slot_generation'], f.expected[1])
        stored, _ = f.proofs.read(f.context)
        self.assertEqual(stored, proof)
        for kind in KINDS[1:]:
            self.assertEqual(retained['archive'][kind]['observation'], 'observed-absent')
            self.assertEqual(f.records.read(f.context, kind), (None, 0))
        self.assertEqual(f.approvals[-1][0], digest(proof))
        self.assertNotEqual(proof['observations']['creator']['sha256'],
                            proof['observations']['creator']['latest_sha256'])

    def test_normal_reconcile_still_blocks_even_with_proof_after_all_deadlines(self):
        f = Fixture()
        proof = f.proof()
        f.proofs.create(f.context, proof)
        f.w.clock.advance(200)
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
        self.assertEqual(f.w.record()['state'], 'CLEANUP_FAILED')

    def test_ttl_is_strict_and_does_not_require_work_or_vm_deadline(self):
        f = Fixture()
        f.w.clock.t = spec_time(f.intent['created_at']) + timedelta(minutes=20)
        f.local['checked_at'] = spec.rfc3339(f.w.clock.now())
        with self.assertRaises(AccessError): f.proof()
        f.w.clock.advance(1/60)
        f.local['checked_at'] = spec.rfc3339(f.w.clock.now())
        self.assertEqual(f.recover().status, 'failed-disposed')

    def test_receipt_absence_and_original_intent_ref_are_mandatory(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                f = Fixture()
                if kind == 'intent':
                    del f.gcs.objects[f.context.path(kind)]
                else:
                    f.gcs.put(f.context.path(kind), {})
                with self.assertRaises(AccessError): f.proof()
                self.assertEqual(f.w.record()['state'], 'CLEANUP_FAILED')

    def test_present_duplicate_foreign_partial_error_or_baseline_drift_blocks(self):
        changes = [lambda f: f.profile.add(key(), f.intent['expiration_usec']),
                   lambda f: (f.profile.add(key(2)), f.profile.add(key(2), fp='duplicate')),
                   lambda f: f.profile.value.update(name='users/foreign'),
                   lambda f: f.profile.value.pop('posixAccounts'),
                   lambda f: setattr(f.profile, 'status', 403),
                   lambda f: f.profile.add(key(2)),
                   lambda f: f.profile.value['posixAccounts'][0].update(uid='1')]
        for change in changes:
            f = Fixture()
            change(f)
            with self.assertRaises(AccessError): f.proof()

    def test_local_cleanup_unknown_live_stale_wrong_source_or_private_digest_blocks(self):
        for field, value in [('result', 'unknown'), ('result', 'running'), ('result', True),
                             ('source_sha', 'f'*40), ('evidence_sha256', 'f'*64),
                             ('checked_at', '2026-10-24T20:00:00Z'),
                             ('terminated_at', '2026-10-24T23:00:00Z')]:
            f = Fixture()
            f.local[field] = value
            with self.assertRaises(AccessError): f.proof()

    def test_fixed_owner_no_impersonation_clean_reviewed_policy_source(self):
        for field, value in [('account', 'other@example.com'), ('impersonation', 'other@example.com'),
                             ('head', 'f'*40), ('dirty', ' M source.py'), ('checkout', '/tmp/foreign-checkout')]:
            f = Fixture()
            setattr(f, field, value)
            with self.assertRaises(AccessError): f.proof()
        f = Fixture()
        with patch.dict('os.environ', {'CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT': 'foreign'}):
            with self.assertRaises(AccessError): f.proof()

    def test_cancel_acceptance_in_progress_rerun_replacement_or_untrusted_creator_blocks(self):
        for field, value in [('status', 'in_progress'), ('conclusion', None), ('run_attempt', 2),
                             ('run_attempt', True), ('id', True),
                             ('head_sha', 'f'*40), ('path', 'other.yml'), ('event', 'pull_request'),
                             ('head_branch', 'other'), ('id', 2)]:
            f = Fixture()
            f.run[field] = value
            with self.assertRaises(AccessError): f.proof()
        f = Fixture()
        f.latest = dict(f.run, run_attempt=2)
        with self.assertRaises(AccessError): f.proof()
        f = Fixture()
        f.latest['conclusion'] = 'failure'
        with self.assertRaises(AccessError): f.proof()

    def test_terminal_original_insert_and_exact_delete_are_required(self):
        for target in ('insert', 'delete'):
            for change in ('missing', 'target', 'error', 'pending', 'foreign_link'):
                f = Fixture()
                name, op = next((n, o) for n, o in f.w.raw.ops.items() if o['operationType'] == target)
                if change == 'missing': del f.w.raw.ops[name]
                if change == 'target': op['targetId'] = '999'
                if change == 'error': op['error'] = {'errors': [{}]}
                if change == 'pending': op['status'] = 'RUNNING'
                if change == 'foreign_link': op['targetLink'] = op['targetLink'].replace(spec.PROJECT, 'foreign')
                with self.assertRaises((AccessError, ApiError, Refused)): f.proof()

    def test_actual_404_not_none_errors_or_name_replacement(self):
        for kind in ('instances', 'disks'):
            f = Fixture()
            f.w.raw.add_foreign(kind, f.original['names']['instance' if kind == 'instances' else 'boot'])
            with self.assertRaises(AccessError): f.proof()
        f = Fixture()
        original = f.w.raw.call
        def bad(resource, verb, **kw):
            if (resource, verb) == ('instances', 'get'): return None
            return original(resource, verb, **kw)
        with patch.object(f.w.raw, 'call', side_effect=bad):
            with self.assertRaises(AccessError): f.proof()
        with patch.object(f.w.raw, '_instances_get', side_effect=ApiError(403)):
            with self.assertRaises(ApiError): f.proof()

    def test_complete_census_and_foreign_pending_operation_errors_block(self):
        for change in ('pending', 'unreachable', 'list_error', 'foreign_disk'):
            f = Fixture()
            if change == 'pending': f.w.raw._op('delete', 'foreign', status='RUNNING')
            if change == 'unreachable': f.w.raw.unreachables = ['zones/other']
            if change == 'list_error': f.w.raw.list_error.add(('disks', 'aggregatedList'))
            if change == 'foreign_disk': f.w.raw.add_foreign('disks', 'foreign')
            with self.assertRaises((AccessError, Refused)): f.proof()
        f = Fixture()
        f.w.raw.page_size = 1
        self.assertEqual(f.recover().status, 'failed-disposed')

    def test_stale_generation_source_binding_capture_and_state_changes_block(self):
        for field, value in [('epoch', 2), ('deadline', '2026-10-24T23:00:00Z'),
                             ('body_hash', 'f'*64), ('state', 'ACTIVE'), ('capture', {'unexpected': True})]:
            f = Fixture()
            rec = copy.deepcopy(f.expected[0])
            rec[field] = value
            f.w.store.write(f.w.cfg.key, rec, if_generation_match=f.expected[1])
            with self.assertRaises(AccessError): f.recover()
        f = Fixture()
        f.w.store.write(f.w.cfg.key, f.expected[0], if_generation_match=f.expected[1])
        with self.assertRaises(AccessError): f.proof()

    def test_decision_data_alone_cannot_approve_proof(self):
        f = Fixture()
        proof = f.proof()
        with patch.object(f.engine, '_FailedAccessRecovery__approve', return_value='f'*64):
            with self.assertRaises(AccessError): f.recover(proof)
        other = dict(f.decision, policy_source_sha='f'*40)
        with self.assertRaises(AccessError):
            f.facade.recover_failed_access(f.expected, proof, other)

    def test_changed_proof_immutable_ref_and_bounded_depth_size_refuse(self):
        f = Fixture()
        proof = f.proof()
        altered = copy.deepcopy(proof)
        altered['slot']['epoch'] += 1
        with self.assertRaises(AccessError): f.recover(altered)
        altered = copy.deepcopy(proof)
        altered['unexpected'] = 'x'*LIMIT
        with self.assertRaises(AccessError): validate_proof(altered)
        altered = copy.deepcopy(proof)
        for _ in range(34): altered = {'nested': altered}
        with self.assertRaises(StoreError): validate_proof(altered)
        with patch.object(f.proofs, 'create', return_value={'path': 'foreign', 'generation': 1, 'sha256': digest(proof)}):
            with self.assertRaises(AccessError): f.recover(proof)

    def test_cas_conflict_and_successor_never_rebase_or_duplicate_history(self):
        f = Fixture()
        proof = f.proof()
        def compete(name, free):
            rec = copy.deepcopy(f.expected[0])
            rec['reason'] = 'another-cleanup'
            f.w.store.write(name, rec, if_generation_match=f.expected[1])
        f.w.store.before_write = compete
        with self.assertRaises(AccessError): f.recover(proof)
        self.assertEqual(f.w.record()['reason'], 'another-cleanup')
        self.assertEqual(f.w.record()['access_history'], [])
        self.assertIsNotNone(f.proofs.read(f.context)[0])
        f = Fixture()
        proof = f.proof()
        f.recover(proof)
        with self.assertRaises(AccessError): f.recover(proof)
        f.w.ctl.admit(2, 1, U2)
        successor = f.w.record()
        with self.assertRaises(AccessError): f.recover(proof)
        self.assertEqual(f.w.record(), successor)
        self.assertEqual(len(f.w.record()['access_history']), 1)

    def test_lost_free_ack_exact_readback_only_no_replay(self):
        for committed in (False, True):
            f = Fixture()
            proof = f.proof()
            original = f.w.store.write
            calls = []
            def lost(name, value, **kw):
                calls.append(value)
                if committed: original(name, value, **kw)
                raise StoreError('lost reply')
            with patch.object(f.w.store, 'write', side_effect=lost):
                if committed: self.assertEqual(f.recover(proof).status, 'failed-disposed')
                else:
                    with self.assertRaises(AccessError): f.recover(proof)
            self.assertEqual(len(calls), 1)

    def test_late_post_before_cas_blocks_and_after_release_keeps_unknown_retired_key(self):
        f = Fixture()
        proof = f.proof()
        f.profile.on_get = lambda: f.profile.add(key(), f.intent['expiration_usec'])
        with self.assertRaises(AccessError): f.recover(proof)
        f = Fixture()
        f.recover()
        f.profile.add(key(), f.intent['expiration_usec'])  # delayed original POST after release
        self.assertEqual(f.w.record()['access_history'][0]['import_status'], 'UNKNOWN')
        self.assertLess(int(f.intent['expiration_usec']), int(f.w.clock.now().timestamp()*1_000_000))
        f.w.started(run=2, uuid=U2)
        rec = f.w.record()
        with self.assertRaises(Refused):
            f.w.ctl.register_access(U2, producer_run_id=2, producer_attempt=1, self_user=OWNER_SELF,
                public_key_text=key(), expected_trial={k: rec[k] for k in FIELDS})
        f.w.ctl.register_access(U2, producer_run_id=2, producer_attempt=1, self_user=OWNER_SELF,
            public_key_text=key(2), expected_trial={k: rec[k] for k in FIELDS})

    def test_final_revalidation_catches_late_post_and_changed_intent_after_proof_upload(self):
        for change in ('post', 'intent', 'resource', 'clock'):
            f = Fixture()
            proof = f.proof()
            def after_metadata(name):
                self.assertEqual(name, path(f.context))
                if change == 'post': f.profile.add(key(), f.intent['expiration_usec'])
                if change == 'intent': f.gcs.put(f.context.path('intent'), f.intent)
                if change == 'resource': f.w.raw.add_foreign('disks', f.original['names']['boot'])
                if change == 'clock': f.w.clock.advance(-2)
            f.gcs.after_metadata = after_metadata
            # Skip record metadata hooks until proof metadata is reached.
            original_request = f.gcs.request
            def request(method, url, **kw):
                hook = f.gcs.after_metadata
                if '/proof.json' not in url.replace('%2F', '/'):
                    f.gcs.after_metadata = None
                    result = original_request(method, url, **kw)
                    f.gcs.after_metadata = hook
                    return result
                return original_request(method, url, **kw)
            with patch.object(f.gcs, 'request', side_effect=request):
                with self.assertRaises(AccessError): f.recover(proof)
            self.assertEqual(f.w.record()['state'], 'CLEANUP_FAILED')
            self.assertIsNotNone(f.proofs.read(f.context)[0])

    def test_delayed_old_receipt_upload_cannot_revise_failed_history_or_successor(self):
        f = Fixture()
        f.recover()
        retained = copy.deepcopy(f.w.record()['access_history'])
        f.gcs.put(f.context.path('import'), {'late': 'untrusted'})
        f.w.ctl.admit(2, 1, U2)
        self.assertEqual(f.w.record()['access_history'], retained)
        self.assertEqual(f.w.ctl.reconcile(U2).status, 'released')
        self.assertEqual(f.w.record()['access_history'], retained)

    def test_history_limit_never_pruned_and_quarantine_capture_accounting_preserved(self):
        f = Fixture()
        rec, gen = f.expected
        rec['used_capture_ids'] = [U2]
        f.w.store.write(f.w.cfg.key, rec, if_generation_match=gen)
        f.refresh_expected()
        f.recover()
        self.assertEqual(f.w.record()['used_capture_ids'], [U2])
        f.w.started(run=2, uuid=U2)
        rec = f.w.record()
        rec['access_history'] *= 16
        f.w.store.write(f.w.cfg.key, rec, if_generation_match=f.w.store.read(f.w.cfg.key)[1])
        with self.assertRaises(Refused):
            f.w.ctl.register_access(U2, producer_run_id=2, producer_attempt=1, self_user=OWNER_SELF,
                public_key_text=key(2), expected_trial={k: rec[k] for k in FIELDS})

    def test_read_boundary_has_no_mutation_or_generic_selector(self):
        f = Fixture()
        for resource, verb in [('instances', 'delete'), ('disks', 'delete'), ('images', 'insert')]:
            with self.assertRaises(ForbiddenOperation): ReadCloud(f.w.cloud).call(resource, verb)
        for name in ('admit', 'submit', 'capture', 'reconcile', 'delete', 'import_once'):
            self.assertFalse(hasattr(f.facade, name))


class ProofTransport(unittest.TestCase):
    def test_one_fixed_create_pinned_readback_and_lost_ack_reconciliation(self):
        for mode in ('ok', 'lost'):
            f = Fixture()
            proof = f.proof()
            f.gcs.upload_mode = mode
            ref = f.proofs.create(f.context, proof)
            self.assertEqual(ref['path'], path(f.context))
            self.assertEqual(f.proofs.read(f.context)[0], proof)
            posts = [c for c in f.gcs.calls if c[0] == 'POST' and '/proof.json' in c[1].replace('%2F', '/')]
            self.assertEqual(len(posts), 1)
            self.assertNotIn('public_key', canonical(proof).decode())

    def test_pending_lost_ack_conflicting_proof_and_denial_are_not_replayed(self):
        f = Fixture()
        proof = f.proof()
        f.gcs.upload_mode = 'pending'
        with self.assertRaises(AccessError): f.recover(proof)
        self.assertEqual(f.w.record()['state'], 'CLEANUP_FAILED')
        f.gcs.finish()
        self.assertEqual(f.recover(proof).status, 'failed-disposed')
        f = Fixture()
        proof = f.proof()
        f.proofs.create(f.context, proof)
        changed = copy.deepcopy(proof)
        changed['decision']['reference'] = changed['decision']['reference'][:-3] + '456'
        with self.assertRaises(AccessError): f.proofs.create(f.context, changed)
        f = Fixture()
        proof = f.proof()
        f.gcs.explicit_upload_error = 403
        with self.assertRaises(AccessError): f.proofs.create(f.context, proof)

    def test_metadata_disappearance_size_identity_duplicate_json_block(self):
        for mode in ('disappear', 'badmeta', 'duplicate', 'error'):
            f = Fixture()
            proof = f.proof()
            f.proofs.create(f.context, proof)
            f.gcs.get_mode = mode
            with self.assertRaises((AccessError, StoreError)): f.proofs.read(f.context)


def spec_time(value):
    from .access_records import timestamp
    return timestamp(value)
