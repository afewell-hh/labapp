"""Finite inline ledger regressions: actual offline transitions, never cloud.

These tests are source-authored, not worker execution evidence. ROOT must run
the lifecycle suite after staging both fixed source-fetch lists.
"""
import copy
import unittest
from datetime import timedelta
from unittest.mock import patch

from . import inline_history as inline, spec, test_access
from .access_records import AccessError, Context, GcsAccessRecords, canonical, digest
from .access_recovery import FailedAccessRecovery, GcsFailedDisposals, OWNER_SELF, validate_proof
from .controller import Controller, Refused
from .gcs import GcsSlotStore, MAX_RECORD_BYTES
from .oslogin import OwnKeyImport, SelfLogin, cleanup_own_key
from .store import PreconditionFailed
from .test_access import BUCKET, GCS, OS, key
from .test_access_recovery import FIELDS, POLICY_SOURCE, TRIAL, world
from .test_gcs import ObjectServer


def lease(number):
    return f'{number:08x}-0000-4000-8000-000000000001'


class Flows:
    """One durable generation-CAS world; distinct genuine access transitions."""
    def __init__(self):
        self.w = world()
        self.http = ObjectServer()
        self.w.store = GcsSlotStore(BUCKET, token_provider=lambda: 'fake', transport=self.http)
        self.gcs = GCS(self.w)
        self.records = GcsAccessRecords(BUCKET, token_provider=lambda: 'fake', transport=self.gcs)
        self.proofs = GcsFailedDisposals(BUCKET, token_provider=lambda: 'fake', transport=self.gcs)
        self.w.ctl = Controller(self.w.store, self.w.cloud, self.w.cfg, access_records=self.records)

    def begin(self, number, *, started=False):
        self.number = number
        if not started:
            self.w.started(run=number, uuid=lease(number))
        rec = self.w.record()
        self.context = self.w.ctl.register_access(lease(number), producer_run_id=number,
            producer_attempt=1, self_user=OWNER_SELF, public_key_text=key(number),
            expected_trial={k: rec[k] for k in FIELDS})
        self.os = OS()
        self.login = SelfLogin(OWNER_SELF, token_provider=lambda: 'fake', transport=self.os)
        self.session = OwnKeyImport(self.records, self.context, self.login, producer_run_id=number,
                                   producer_attempt=1, now=self.w.clock.now)
        self.session.prepare(key(number))

    def finish(self, failed=False):
        if not failed:
            self.session.import_once()
            cleanup_own_key(self.records, self.context, self.login, now=self.w.clock.now)
            assert self.w.ctl.reconcile(lease(self.number)).status == 'released'
            return
        original = self.w.record()
        assert self.w.ctl.reconcile(lease(self.number)).status == 'blocked'
        # Supply fields omitted by the historical FakeCloud delete operation.
        # The real recovery validates these provider identities, not this comment.
        target = (f'projects/{spec.PROJECT}/zones/{spec.ZONE}/instances/'
                  + original['names']['instance'])
        for operation in self.w.raw.ops.values():
            if operation['targetLink'].rsplit('/', 1)[-1] == original['names']['instance']:
                operation['targetLink'] = 'https://compute.googleapis.com/compute/v1/' + target
                if operation['operationType'] == 'delete':
                    operation['targetId'] = original['ids']['instance']
        self.w.clock.advance(21)
        expected = self.w.store.read(self.w.cfg.key)
        decision = dict(reference='https://github.com/afewell-hh/labapp/issues/455#issuecomment-123',
                        trial_source_sha=TRIAL, policy_source_sha=POLICY_SOURCE,
                        local_evidence_sha256='c'*64)
        terminated = spec.rfc3339(self.w.clock.now() - timedelta(minutes=1))

        def collect(slot, reviewed):
            assert reviewed == decision and slot == expected[0]
            return dict(
                creator=dict(run_id=self.number, attempt=1, source_sha=TRIAL,
                             sha256='d'*64, latest_sha256='e'*64, conclusion='cancelled'),
                local=dict(lease=lease(self.number), source_sha=TRIAL, coordinator_sha256='f'*64,
                           registration_sha256='a'*64, evidence_sha256='c'*64,
                           terminated_at=terminated, checked_at=spec.rfc3339(self.w.clock.now()),
                           result='coordinator-children-terminated-private-files-absent'))

        engine = FailedAccessRecovery(self.w.store, self.w.cloud, self.records, self.proofs,
            self.login, collect=collect, approve=lambda sha, _: sha, now=self.w.clock.now)
        proof = engine.prepare(expected, decision)
        validate_proof(proof)
        self.last_proof = proof
        assert engine.recover_failed_access(expected, proof, decision).status == 'failed-disposed'

    def trial(self, number, failed=False):
        self.begin(number)
        self.finish(failed)

    def migrate_in_fixture(self):
        before, generation = self.w.store.read(self.w.cfg.key)
        plan = inline.plan_migration(before, generation)
        assert self.w.store.read(self.w.cfg.key) == (before, generation)
        # TEST ONLY: the pure planner does not perform this CAS or authorize it.
        self.w.store.write(self.w.cfg.key, plan['replacement'], if_generation_match=generation)
        return before, plan


@patch.object(test_access, 'SELF', OWNER_SELF)
class InlineFlows(unittest.TestCase):
    @staticmethod
    def common(record):
        return {k: record[k] for k in ('schema', 'slot', 'epoch', 'access_history',
                                       'legacy_history', 'quarantine', 'used_capture_ids')}

    def candidate(self):
        f = Flows()
        f.trial(1)
        old, generation = f.w.store.read(f.w.cfg.key)
        return f, inline.plan_migration(old, generation)['replacement']

    @staticmethod
    def prefix_digest(record):
        count = record['legacy_history']['count']
        record['legacy_history']['sha256'] = digest(record['access_history'][:count])

    def test_distinct_mixed_legacy16_then_schema2_through_ceiling(self):
        f = Flows()
        for number in range(1, 17):
            f.trial(number, failed=number % 2 == 0)
        old, generation = f.w.store.read(f.w.cfg.key)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused):
            f.w.ctl.admit(17, 1, lease(17))
        self.assertEqual(f.w.store.read(f.w.cfg.key), (old, generation))
        self.assertEqual(len(f.w.raw.calls), calls)
        # A pre-fix occupied legacy lease with full history is still cleanable.
        cleanup = Flows()
        cleanup.w.started(run=17, uuid=lease(17))
        existing, old_generation = cleanup.w.store.read(cleanup.w.cfg.key)
        existing['access_history'] = copy.deepcopy(old['access_history'])
        cleanup.w.store.write(cleanup.w.cfg.key, existing, if_generation_match=old_generation)
        self.assertEqual(cleanup.w.ctl.reconcile(lease(17)).status, 'released')
        self.assertEqual(cleanup.w.record()['access_history'], old['access_history'])
        self.assertEqual((cleanup.w.raw.instances, cleanup.w.raw.disks), ({}, {}))
        before, plan = f.migrate_in_fixture()
        self.assertEqual(plan['expected'], before)
        self.assertEqual(plan['expected_generation'], generation)
        self.assertEqual(plan['expected_sha256'], digest(before))
        self.assertEqual(plan['replacement']['last_release'], before['last_release'])
        self.assertEqual(plan['replacement']['access_history'], before['access_history'])
        prefix = canonical(before['access_history'])
        for number in range(17, 25):
            f.trial(number, failed=number % 2 == 0)
            rec = f.w.record()
            self.assertEqual(rec['schema'], 2)
            self.assertEqual(canonical(rec['access_history'][:16]), prefix)
            self.assertEqual(rec['legacy_history'], plan['replacement']['legacy_history'])
            self.assertEqual(len(rec['access_history']), number)
            self.assertLessEqual(len(canonical(rec)), MAX_RECORD_BYTES)
        rec, generation = f.w.store.read(f.w.cfg.key)
        self.assertEqual(len({h['binding']['lease'] for h in rec['access_history']}), 24)
        self.assertEqual(len({h['binding']['key_sha256'] for h in rec['access_history']}), 24)
        self.assertEqual(sum(h.get('import_status') == 'UNKNOWN' for h in rec['access_history']), 12)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused): f.w.ctl.admit(25, 1, lease(25))
        self.assertEqual(len(f.w.raw.calls), calls)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (rec, generation))
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))

    def test_migration_is_pure_exact_and_conflicting_cas_does_not_rebase(self):
        f = Flows()
        f.trial(1, failed=True)
        before, generation = f.w.store.read(f.w.cfg.key)
        before['used_capture_ids'] = [lease(99)]
        f.w.store.write(f.w.cfg.key, before, if_generation_match=generation)
        before, generation = f.w.store.read(f.w.cfg.key)
        plan = inline.plan_migration(before, generation)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (before, generation))
        self.assertEqual(plan['replacement']['used_capture_ids'], [lease(99)])
        f.w.store.write(f.w.cfg.key, before, if_generation_match=generation)
        with self.assertRaises(PreconditionFailed):
            f.w.store.write(f.w.cfg.key, plan['replacement'], if_generation_match=generation)
        self.assertEqual(f.w.record()['schema'], 1)

    def test_history_semantic_failure_still_deletes_exact_owned_resources(self):
        for schema in (1, 2):
            f = Flows()
            f.trial(1)
            if schema == 2: f.migrate_in_fixture()
            f.begin(2)
            rec, generation = f.w.store.read(f.w.cfg.key)
            rec['access_history'][0]['binding']['epoch'] = True
            opaque = copy.deepcopy(rec['access_history'])
            f.w.store.write(f.w.cfg.key, rec, if_generation_match=generation)
            self.assertEqual(f.w.ctl.reconcile(lease(2)).status, 'blocked')
            self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
            self.assertNotEqual(f.w.record()['state'], 'FREE')
            self.assertEqual(f.w.record()['access_history'], opaque)
            with self.assertRaises((AccessError, Refused)):
                f.w.ctl.register_access(lease(2), producer_run_id=2, producer_attempt=1,
                    self_user=OWNER_SELF, public_key_text=key(3))

    def test_ownership_corruption_does_not_use_history_failure_to_allow_delete(self):
        f = Flows()
        f.trial(1)
        f.migrate_in_fixture()
        f.begin(2)
        rec, generation = f.w.store.read(f.w.cfg.key)
        rec['body_hash'] = '0'*64
        rec['access_history'] = 'malformed'
        f.w.store.write(f.w.cfg.key, rec, if_generation_match=generation)
        deleted = len(f.w.deletes())
        self.assertEqual(f.w.ctl.reconcile(lease(2)).status, 'blocked')
        self.assertEqual(len(f.w.deletes()), deleted)
        self.assertTrue(f.w.raw.instances)

    def test_capacity_corruption_does_not_block_owned_delete_before_id_persistence(self):
        f = Flows()
        f.trial(1)
        f.migrate_in_fixture()
        f.w.ctl.admit(2, 1, lease(2))
        self.assertEqual(f.w.ctl.submit(lease(2)).status, 'accepted')
        rec, generation = f.w.store.read(f.w.cfg.key)
        self.assertEqual(rec['ids'], {'instance': None, 'boot': None})
        rec['access_history'][0]['opaque'] = ''
        rec['access_history'][0]['opaque'] = 'x' * (MAX_RECORD_BYTES - len(canonical(rec)))
        self.assertEqual(len(canonical(rec)), MAX_RECORD_BYTES)
        opaque = copy.deepcopy(rec['access_history'])
        f.w.store.write(f.w.cfg.key, rec, if_generation_match=generation)
        self.assertEqual(f.w.ctl.reconcile(lease(2)).status, 'blocked')
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertNotEqual(f.w.record()['state'], 'FREE')
        self.assertEqual(f.w.record()['access_history'], opaque)

    def test_no_downgrade_no_prefix_rewrite_or_key_reuse(self):
        f = Flows()
        f.trial(1, failed=True)
        f.migrate_in_fixture()
        f.w.started(run=2, uuid=lease(2))
        previous, generation = f.w.store.read(f.w.cfg.key)
        for change in (lambda r: r.update(schema=1),
                       lambda r: r['access_history'][0].update(import_status='SUCCESS'),
                       lambda r: r['legacy_history'].update(count=0)):
            altered = copy.deepcopy(previous)
            change(altered)
            with self.assertRaises((Refused, inline.HistoryError)):
                f.w.ctl._cas(previous, altered, generation)
        with self.assertRaises(Refused):
            f.w.ctl.register_access(lease(2), producer_run_id=2, producer_attempt=1,
                self_user=OWNER_SELF, public_key_text=key(1),
                expected_trial={k: previous[k] for k in FIELDS})
        self.assertNotIn('access', f.w.record())

    def test_planner_refuses_unknown_or_nonfree_inventory_without_dropping_it(self):
        f = Flows()
        f.trial(1)
        before, generation = f.w.store.read(f.w.cfg.key)
        for changes in ({'extra': {'preserve': 'unknown'}}, {'quarantine': [{}]},
                        {'access': {}}, {'capture': {}}, {'schema': 2},
                        {'state': 'ACTIVE'}, {'epoch': True}):
            value = copy.deepcopy(before)
            value.update(changes)
            original = canonical(value)
            with self.assertRaises(inline.HistoryError): inline.plan_migration(value, generation)
            self.assertEqual(canonical(value), original)
        missing = dict(before)
        del missing['quarantine']
        with self.assertRaises(inline.HistoryError): inline.plan_migration(missing, generation)
        unknown_release = copy.deepcopy(before)
        unknown_release['last_release']['unrecognized'] = 'must not disappear'
        original = canonical(unknown_release)
        with self.assertRaises(inline.HistoryError):
            inline.plan_migration(unknown_release, generation)
        self.assertEqual(canonical(unknown_release), original)
        for invalid in (True, 0, -1, 2**64):
            with self.assertRaises(inline.HistoryError): inline.plan_migration(before, invalid)

    def test_schema2_unsupported_profile_and_capture_refuse_without_api_effects(self):
        f = Flows()
        f.trial(1)
        f.migrate_in_fixture()
        f.w.cfg.profile = spec.UBUNTU_BASE_BUILD
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused): f.w.ctl.admit(2, 1, lease(2))
        self.assertEqual(len(f.w.raw.calls), calls)
        f.w.cfg.profile = spec.UBUNTU_VLAB_CORE
        f.w.started(run=2, uuid=lease(2))
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused): f.w.ctl.prepare_capture(lease(2), lease(90))
        self.assertEqual(len(f.w.raw.calls), calls)

    def test_exact_disposal_byte_boundary_and_one_over_before_reservation(self):
        f, candidate = self.candidate()
        candidate['access_history'][0]['legacy_opaque'] = ''
        self.prefix_digest(candidate)
        # Analytical upper bound, not a dummy maximum continuation fixture.
        limit = (MAX_RECORD_BYTES - inline.LIVE_BYTES - inline.EVIDENCE_BYTES
                 - inline.PROOF_EXTRA_BYTES - 64)
        amount = limit - len(canonical(self.common(candidate)))
        self.assertGreater(amount, 0)
        candidate['access_history'][0]['legacy_opaque'] = 'x' * amount
        self.prefix_digest(candidate)
        self.assertEqual(len(canonical(self.common(candidate))), limit)
        inline.validate(candidate, reserve=True, adding=True)
        rec, generation = f.w.store.read(f.w.cfg.key)
        f.w.store.write(f.w.cfg.key, candidate, if_generation_match=generation)
        reserved = f.w.ctl.admit(2, 1, lease(2))
        self.assertEqual(reserved['schema'], 2)
        self.assertEqual(f.w.ctl.submit(lease(2)).status, 'accepted')
        self.assertEqual(f.w.ctl.confirm_created(lease(2)).status, 'created')
        f.begin(2, started=True)
        f.finish()
        self.assertEqual(f.w.record()['state'], 'FREE')
        self.assertEqual(len(f.w.record()['access_history']), 2)
        # Current disposal may consume its reserve. Do not demand capacity for
        # the NEXT VM as a condition of releasing this physically disposed one.
        with self.assertRaises(inline.HistoryError):
            inline.validate(f.w.record(), reserve=True, adding=True)
        candidate['access_history'][0]['legacy_opaque'] += 'x'
        self.prefix_digest(candidate)
        with self.assertRaises(inline.HistoryError):
            inline.validate(candidate, reserve=True, adding=True)
        current, generation = f.w.store.read(f.w.cfg.key)
        f.w.store.write(f.w.cfg.key, candidate, if_generation_match=generation)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused): f.w.ctl.admit(3, 1, lease(3))
        self.assertEqual(len(f.w.raw.calls), calls)
        self.assertEqual(f.w.record(), candidate)

    def test_escaped_legacy_bytes_preserved_and_charged_not_character_count(self):
        _, candidate = self.candidate()
        candidate['access_history'][0]['legacy_opaque'] = '\x00' * 7000
        self.prefix_digest(candidate)
        inline.validate(candidate, reserve=True, adding=True)
        retained = canonical(candidate['access_history'])
        self.assertGreater(len(retained), 42000)
        self.assertEqual(digest(candidate['access_history']), candidate['legacy_history']['sha256'])
        candidate['access_history'][0]['legacy_opaque'] += '\x00' * 1000
        self.prefix_digest(candidate)
        self.assertLess(len(canonical(candidate)), MAX_RECORD_BYTES)
        with self.assertRaises(inline.HistoryError):
            inline.validate(candidate, reserve=True, adding=True)

    def test_depth30_reserves_proof_and_wrapper_but31_refuses_admission(self):
        from .gcs import _record
        _, candidate = self.candidate()
        value = 'leaf'
        for _ in range(27): value = [value]
        candidate['access_history'][0]['legacy_opaque'] = value
        self.prefix_digest(candidate)
        inline.validate(candidate, reserve=True, adding=True)
        # root.history[0].legacy_opaque: depth3; 27 containers -> leaf depth30.
        wrapper = dict(schema=1, slot=candidate['slot'], state='FREE', epoch=0,
                       payload={'slot': candidate})
        _record(wrapper, candidate['slot'])
        candidate['access_history'][0]['legacy_opaque'] = [value]
        self.prefix_digest(candidate)
        _record(candidate, candidate['slot'])  # ownership reader still accepts it
        with self.assertRaises(inline.HistoryError):
            inline.validate(candidate, reserve=True, adding=True)

    def test_actual_evidence_aggregate_boundary_and_one_over(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.w.ctl.admit(2, 1, lease(2))
        occupied = f.w.record()
        occupied['evidence'] = ['x' * (inline.EVIDENCE_BYTES - len(canonical([''])))]
        inline.validate(occupied, reserve=True, adding=True)
        occupied['evidence'][0] += 'x'
        with self.assertRaises(inline.HistoryError):
            inline.validate(occupied, reserve=True, adding=True)
        current, generation = f.w.store.read(f.w.cfg.key)
        f.w.store.write(f.w.cfg.key, occupied, if_generation_match=generation)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused): f.w.ctl.submit(lease(2))
        self.assertEqual(len(f.w.raw.calls), calls)

    def test_registration_rechecks_actual_retained_bytes_before_api_reads(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.w.started(run=2, uuid=lease(2))
        rec, generation = f.w.store.read(f.w.cfg.key)
        rec['access_history'][0]['legacy_opaque'] = ''
        self.prefix_digest(rec)
        limit = (MAX_RECORD_BYTES - inline.LIVE_BYTES - inline.EVIDENCE_BYTES
                 - inline.PROOF_EXTRA_BYTES - 64)
        rec['access_history'][0]['legacy_opaque'] = 'x' * (
            limit + 1 - len(canonical(self.common(rec))))
        self.prefix_digest(rec)
        f.w.store.write(f.w.cfg.key, rec, if_generation_match=generation)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused):
            f.w.ctl.register_access(lease(2), producer_run_id=2, producer_attempt=1,
                self_user=OWNER_SELF, public_key_text=key(2),
                expected_trial={k: rec[k] for k in FIELDS})
        self.assertEqual(len(f.w.raw.calls), calls)
        self.assertNotIn('access', f.w.record())

    def test_normal_archive_storage_generations_keep_unsigned64_domain(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.begin(2)
        f.gcs.seq = 2**63 - 1
        f.finish()
        archived = f.w.record()['access_history'][-1]['archive']
        self.assertEqual(archived['import']['generation'], 2**63)
        self.assertEqual(archived['removed']['generation'], 2**63 + 1)
        inline.validate(f.w.record())

    def test_actual_fixed_live_aggregate_boundary_and_one_over(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.w.ctl.admit(2, 1, lease(2))
        occupied = f.w.record()
        occupied.update(state='CLEANUP_FAILED', reason='')
        fixed = {k: v for k, v in occupied.items() if k not in self.common(occupied) and k != 'evidence'}
        occupied['reason'] = 'x' * (inline.LIVE_BYTES - len(canonical(fixed)))
        inline.validate(occupied, reserve=True, adding=True)
        occupied['reason'] += 'x'
        with self.assertRaises(inline.HistoryError):
            inline.validate(occupied, reserve=True, adding=True)

    def test_suffix_unknown_fields_duplicates_and_boolean_domains_fail_closed(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.trial(2)
        original = f.w.record()
        for change in (lambda r: r['access_history'][1].update(extra='unrecognized'),
                       lambda r: r['access_history'][1]['binding'].update(epoch=True),
                       lambda r: r['access_history'][1]['archive']['intent'].update(generation=True),
                       lambda r: r['access_history'].append(copy.deepcopy(r['access_history'][1])),
                       lambda r: r['legacy_history'].update(count=True),
                       lambda r: r.update(extra='unrecognized')):
            bad = copy.deepcopy(original)
            change(bad)
            with self.assertRaises(inline.HistoryError): inline.validate(bad)

    def test_tombstones_reject_nonuuid_unhashable_and_duplicate_values(self):
        _, candidate = self.candidate()
        for values in ([{}], [[]], [True], ['invalid'], [lease(99), lease(99)]):
            bad = copy.deepcopy(candidate)
            bad['used_capture_ids'] = values
            with self.assertRaises(inline.HistoryError): inline.validate(bad)

    def test_current_access_binding_cannot_diverge_from_occupied_identity(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.begin(2)
        original = f.w.record()
        for changes in ({'lease': lease(3)}, {'epoch': original['epoch'] + 1},
                        {'run_id': 3}, {'vm_id': '999999'},
                        {'work_deadline': original['deadline']}):
            bad = copy.deepcopy(original)
            bad['access']['binding'].update(changes)
            with self.assertRaises(AccessError): Context.from_slot(bad)

    def test_new_free_release_is_typed_without_retroactive_legacy_residual_cap(self):
        _, candidate = self.candidate()
        inline.free_budget(candidate)
        for changes in ({'run_id': True}, {'request_id': 'invalid'}, {'ids': {}},
                        {'released_at': 'invalid'}, {'evidence': [42]}):
            bad = copy.deepcopy(candidate)
            bad['last_release'].update(changes)
            with self.assertRaises(inline.HistoryError): inline.free_budget(bad)
        legacy = copy.deepcopy(candidate)
        legacy['last_release']['evidence'] = ['x' * inline.LIVE_BYTES]
        inline.validate(legacy, reserve=True, adding=True)
        with self.assertRaises(inline.HistoryError): inline.free_budget(legacy)

    def test_actual_proof_extra_aggregate_boundary_and_one_over(self):
        f, _ = self.candidate()
        f.migrate_in_fixture()
        f.trial(2, failed=True)
        proof = copy.deepcopy(f.last_proof)
        residual = {k: v for k, v in proof.items() if k != 'slot'}
        amount = inline.PROOF_EXTRA_BYTES - len(canonical(residual))
        self.assertGreater(amount, 0)
        proof['decision']['reference'] += '9' * amount
        validate_proof(proof)
        proof['decision']['reference'] += '9'
        with self.assertRaises(AccessError): validate_proof(proof)


if __name__ == '__main__':
    unittest.main()
