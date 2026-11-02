"""SOURCE-authored cleanup regressions; execution belongs to ROOT/isolated CI.

Run: python3 -B -m unittest discover -s build/gcp/lifecycle -t build/gcp -p test_cleanup_history_bounds.py -v
Uses the actual controllers, codecs, access/recovery and generation-CAS adapters
with existing offline transports. No live migration or cloud authority.
"""
import copy
import unittest
from unittest.mock import patch

from . import inline_history as inline, spec, test_access
from .access_records import canonical, digest
from .access_recovery import OWNER_SELF, validate_proof
from .cloud import ApiError, Uncertain
from .controller import Refused
from .gcs import MAX_RECORD_BYTES
from .oslogin import cleanup_own_key
from .test_inline_history import Flows, lease


@patch.object(test_access, 'SELF', OWNER_SELF)
class CleanupHistoryBounds(unittest.TestCase):
    def write(self, f, record):
        _, generation = f.w.store.read(f.w.cfg.key)
        f.w.store.write(f.w.cfg.key, record, if_generation_match=generation)

    def fixture(self, *, maximum_common=False):
        f = Flows()
        f.trial(1, failed=True)
        f.trial(2)
        f.migrate_in_fixture()
        if maximum_common:
            record = f.w.record()
            record['access_history'][0]['opaque_fixture_padding'] = ''
            common = lambda: {k: record[k] for k in inline.COMMON2}
            limit = (MAX_RECORD_BYTES - inline.LIVE_BYTES - inline.EVIDENCE_BYTES
                     - inline.PROOF_EXTRA_BYTES - 2 * inline.ENVELOPE_SLACK)
            amount = limit - len(canonical(common()))
            record['access_history'][0]['opaque_fixture_padding'] = 'x' * amount
            record['legacy_history']['sha256'] = digest(record['access_history'])
            self.assertEqual(len(canonical(common())), limit)
            inline.validate(record, reserve=True, adding=True)
            # Fixture-only installation; the planner grants no write authority.
            self.write(f, record)
        return f

    def pad_evidence_reserve(self, record):
        record['evidence'].append('')
        amount = inline.EVIDENCE_BYTES - inline.cleanup_evidence_bound(record)
        self.assertGreaterEqual(amount, 0)
        record['evidence'][-1] = 'x' * amount
        self.assertEqual(inline.cleanup_evidence_bound(record), inline.EVIDENCE_BYTES)
        inline.cleanup_budget(record)

    def alternating(self, *, failed=False, maximum=False):
        f = self.fixture(maximum_common=maximum)
        history = canonical(f.w.record()['access_history'])
        metadata = canonical(f.w.record()['legacy_history'])
        immutable = copy.deepcopy(f.gcs.objects)
        f.begin(3)
        if not failed:
            f.session.import_once()
            cleanup_own_key(f.records, f.context, f.login, now=f.w.clock.now)
        record = f.w.record()
        record['evidence'] = ['old escaped "\\\n\x00é', 'old duplicate', 'old duplicate']
        if maximum:
            self.pad_evidence_reserve(record)
        self.write(f, record)
        prefix = copy.deepcopy(record['evidence'])
        prefix_bytes = canonical(prefix)
        vm, boot = record['names']['instance'], record['names']['boot']
        deleted = inline.cleanup_fact('instance', vm, record['ids']['instance'])
        absent = inline.cleanup_fact('instance', vm)
        boot_deleted = inline.cleanup_fact('boot', boot, record['ids']['boot'])
        f.w.raw.leak_disks = True
        old_accumulation = list(prefix)
        attempts = inline.EVIDENCE_BYTES // len(canonical(absent)) + 3
        counter = 0

        def reject(*_args):
            nonlocal counter
            counter += 1
            if counter % 2:
                raise ApiError(500, 'boot delete unavailable')
            raise Uncertain('boot delete uncertain')

        with patch.object(f.w.raw, '_disks_delete', side_effect=reject):
            for attempt in range(attempts):
                result = f.w.ctl.reconcile(lease(3))
                self.assertEqual(result.status, 'cleanup-failed', result.detail)
                self.assertFalse(f.w.raw.instances)
                self.assertIn(boot, f.w.raw.disks)
                current = f.w.record()
                old_accumulation.append(deleted if attempt == 0 else absent)
                self.assertEqual(current['evidence'],
                                 inline.cleanup_evidence(prefix, [deleted] + ([absent] if attempt else [])))
                self.assertEqual(canonical(current['evidence'][:len(prefix)]), prefix_bytes)
                self.assertEqual(canonical(current['access_history']), history)
                self.assertEqual(canonical(current['legacy_history']), metadata)
                self.assertLessEqual(len(canonical(current['evidence'])), inline.EVIDENCE_BYTES)
                f.w.ctl._accounting(current, reserve=True, adding=True)
        self.assertEqual(counter, attempts)
        # The actual old append-per-changed-reason algorithm would now exceed4096.
        self.assertGreater(len(canonical(old_accumulation)), inline.EVIDENCE_BYTES)
        if failed:
            f.finish(failed=True)
            proof = f.last_proof
            validate_proof(proof)  # includes the real depth32 validation wrapper
            inline.proof_budget(proof)
            self.assertLessEqual(len(canonical(proof)), MAX_RECORD_BYTES)
            self.assertEqual(proof['slot']['evidence'],
                             inline.cleanup_evidence(prefix, [deleted, absent, boot_deleted]))
            self.assertEqual(canonical(proof['slot']['access_history']), history)
        else:
            result = f.w.ctl.reconcile(lease(3))
            self.assertEqual(result.status, 'released', result.detail)
        free = f.w.record()
        self.assertEqual(free['state'], 'FREE')
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertEqual(free['last_release']['evidence'],
                         inline.cleanup_evidence(prefix, [deleted, absent, boot_deleted]))
        self.assertEqual(canonical(free['access_history'][:2]), history)
        self.assertEqual(canonical(free['legacy_history']), metadata)
        inline.free_budget(free)
        self.assertLessEqual(len(canonical(free)), MAX_RECORD_BYTES)
        for name, value in immutable.items():
            self.assertEqual(f.gcs.objects[name], value, name)
        if maximum:
            with self.assertRaises(inline.HistoryError):
                inline.validate(free, reserve=True, adding=True)

    def test_alternating_failures_beyond_old_limit_then_normal_release(self):
        self.alternating()

    def test_alternating_failures_preserve_maximum_failed_proof_and_free_headroom(self):
        self.alternating(failed=True, maximum=True)

    def test_maximum_common_and_evidence_reserves_still_allow_normal_release(self):
        self.alternating(maximum=True)

    def test_exact_future_evidence_bound_and_one_over_refuse_before_submission(self):
        f = self.fixture()
        f.w.ctl.admit(3, 1, lease(3))
        record = f.w.record()
        self.pad_evidence_reserve(record)
        exact = copy.deepcopy(record)
        self.write(f, record)
        f.w.ctl._accounting(record, reserve=True, adding=True)
        record['evidence'][-1] += 'x'
        self.write(f, record)
        before = f.w.store.read(f.w.cfg.key)
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused):
            f.w.ctl.submit(lease(3))
        self.assertEqual(f.w.store.read(f.w.cfg.key), before)
        self.assertEqual(len(f.w.raw.calls), calls)
        self.write(f, exact)
        self.assertEqual(f.w.ctl.submit(lease(3)).status, 'accepted')
        self.assertEqual(f.w.ctl.confirm_created(lease(3)).status, 'created')
        self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'released')

    def test_four_fact_bound_uses_source_names_uint64_and_no_placeholder_dedup(self):
        f = self.fixture()
        f.w.ctl.admit(999999999999999, 999, lease(3))
        record = f.w.record()
        self.assertEqual(len(record['names']), 2)
        unknown_bound = inline.cleanup_evidence_bound(record)
        record['ids'] = {kind: str(inline.UINT64) for kind in record['ids']}
        facts = [inline.cleanup_fact(kind, name) for kind, name in record['names'].items()]
        facts += [inline.cleanup_fact(kind, record['names'][kind], value)
                  for kind, value in record['ids'].items()]
        self.assertEqual(len(set(facts)), 4)
        self.assertLessEqual(len(canonical(facts)), unknown_bound)
        record['evidence'] = list(facts)
        self.assertEqual(inline.cleanup_evidence_bound(record), len(canonical(facts)))
        # An opaque old string matching the largest-ID placeholder must NOT
        # remove the reserve for a different subsequently adopted actual ID.
        record['ids'] = {kind: None for kind in record['ids']}
        before = inline.cleanup_evidence_bound(record)
        record['ids'] = {kind: '1' for kind in record['ids']}
        self.assertLessEqual(inline.cleanup_evidence_bound(record), before)
        inline.cleanup_budget(record)

    def test_physical_cas_refuses_evidence_rewrite_duplicate_and_untyped_facts(self):
        f = self.fixture()
        f.w.started(run=3, uuid=lease(3))
        record = f.w.record()
        record['evidence'] = ['old', 'old']
        self.write(f, record)
        before, generation = f.w.store.read(f.w.cfg.key)
        absent = inline.cleanup_fact('instance', before['names']['instance'])
        for evidence in (['old'], ['changed', 'old'], ['old', 'old', 'old'],
                         ['old', 'old', absent, absent], ['old', 'old', 'invented fact']):
            changed = copy.deepcopy(before)
            changed['evidence'] = evidence
            with self.subTest(evidence=evidence), self.assertRaises(Refused):
                f.w.ctl._physical_cas(before, changed, generation)
            self.assertEqual(f.w.store.read(f.w.cfg.key), (before, generation))

    def test_same_failure_reason_still_retains_new_distinct_facts(self):
        f = self.fixture()
        f.w.started(run=3, uuid=lease(3))
        record, generation = f.w.store.read(f.w.cfg.key)
        one = inline.cleanup_fact('instance', record['names']['instance'])
        two = inline.cleanup_fact('boot', record['names']['boot'])
        f.w.ctl._fail(record, generation, 'delete-boot-op-error', [one])
        record, generation = f.w.store.read(f.w.cfg.key)
        f.w.ctl._fail(record, generation, 'delete-boot-op-error', [one, two])
        record, generation = f.w.store.read(f.w.cfg.key)
        self.assertEqual(record['evidence'], [one, two])
        f.w.ctl._fail(record, generation, 'delete-boot-op-error', [one, two])
        self.assertEqual(f.w.store.read(f.w.cfg.key), (record, generation))

    def bad_accounting(self, *, full_media=False):
        f = self.fixture()
        f.w.ctl.admit(3, 1, lease(3))
        self.assertEqual(f.w.ctl.submit(lease(3)).status, 'accepted')
        record = f.w.record()  # deliberately no confirm/adoption
        self.assertEqual(record['ids'], {'instance': None, 'boot': None})
        if full_media:
            record['access_history'][0]['opaque_bad_accounting'] = ''
            record['access_history'][0]['opaque_bad_accounting'] = 'x' * (
                MAX_RECORD_BYTES - len(canonical(record)))
            self.assertEqual(len(canonical(record)), MAX_RECORD_BYTES)
        else:
            record['evidence'] = ['x' * inline.EVIDENCE_BYTES]
        self.write(f, record)
        before = canonical(record)
        f.w.raw.leak_disks = True
        result = f.w.ctl.reconcile(lease(3))
        self.assertEqual(result.status, 'blocked', result.detail)
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertNotEqual(f.w.record()['state'], 'FREE')
        self.assertEqual(canonical(f.w.record()), before)

    def test_overfull_existing_evidence_does_not_prevent_unadopted_owned_deletion(self):
        self.bad_accounting()

    def test_full_media_bad_history_does_not_prevent_unadopted_owned_deletion(self):
        self.bad_accounting(full_media=True)

    def test_semantically_bad_history_keeps_old_bytes_and_physical_progress_not_free(self):
        f = self.fixture()
        f.begin(3)
        record = f.w.record()
        record['access_history'][0]['binding']['epoch'] = True
        history = canonical(record['access_history'])
        metadata = canonical(record['legacy_history'])
        self.write(f, record)
        f.w.raw.leak_disks = True
        result = f.w.ctl.reconcile(lease(3))
        self.assertEqual(result.status, 'blocked', result.detail)
        current = f.w.record()
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertNotEqual(current['state'], 'FREE')
        self.assertEqual(canonical(current['access_history']), history)
        self.assertEqual(canonical(current['legacy_history']), metadata)
        self.assertEqual(len(current['evidence']), 2)
        self.assertTrue(all('deleted, 404 confirmed' in fact for fact in current['evidence']))

    def test_successful_progress_survives_later_pending_operation_or_failed_read(self):
        for mode in ('pending', 'read-error'):
            with self.subTest(mode=mode):
                f = self.fixture()
                f.w.started(run=3, uuid=lease(3))
                record = f.w.record()
                boot = record['names']['boot']
                f.w.raw.leak_disks = True
                original_delete = f.w.raw._disks_delete
                original_get = f.w.raw._disks_get
                seen = 0

                def pending(*args):
                    operation = original_delete(*args)
                    f.w.raw.op_stuck.add(operation['name'])
                    return operation

                def unavailable(name, *args):
                    nonlocal seen
                    seen += 1
                    if seen == 2:  # preflight succeeded, immediate delete read failed
                        raise Uncertain('boot identity read unavailable')
                    return original_get(name, *args)

                target = '_disks_delete' if mode == 'pending' else '_disks_get'
                with patch.object(f.w.raw, target,
                                  side_effect=pending if mode == 'pending' else unavailable):
                    result = f.w.ctl.reconcile(lease(3))
                self.assertEqual(result.status, 'pending-operation' if mode == 'pending' else 'blocked')
                self.assertEqual(f.w.record()['evidence'], [
                    inline.cleanup_fact('instance', record['names']['instance'], record['ids']['instance'])])
                self.assertNotEqual(f.w.record()['state'], 'FREE')
                f.w.raw.op_stuck.clear()
                self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'released')

    def test_unbounded_transport_diagnostic_is_returned_not_persisted(self):
        f = self.fixture()
        f.w.started(run=3, uuid=lease(3))
        diagnostic = 'escaped "\n' * inline.LIVE_BYTES
        with patch.object(f.w.raw, '_instances_delete', side_effect=Uncertain(diagnostic)):
            result = f.w.ctl.reconcile(lease(3))
        self.assertEqual(result.status, 'cleanup-failed')
        self.assertIn(diagnostic, result.detail)
        record = f.w.record()
        self.assertEqual(record['reason'], 'delete-instance:uncertain')
        f.w.ctl._accounting(record, reserve=True, adding=True)
        self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'released')

    def test_all_physical_delete_failure_forms_keep_bounded_disposal_available(self):
        for kind in ('instance', 'boot'):
            for mode in ('api-error', 'op-error', 'still-exists'):
                with self.subTest(kind=kind, mode=mode):
                    f = self.fixture()
                    f.w.started(run=3, uuid=lease(3))
                    record = f.w.record()
                    name = record['names'][kind]
                    f.w.raw.leak_disks = True
                    if mode == 'api-error':
                        f.w.raw.delete_fail.add(name)
                    else:
                        f.w.raw.delete_noop.add(name)
                        if mode == 'op-error':
                            f.w.raw.delete_op_error.add(name)
                    result = f.w.ctl.reconcile(lease(3))
                    self.assertEqual(result.status, 'cleanup-failed', result.detail)
                    f.w.ctl._accounting(f.w.record(), reserve=True, adding=True)
                    f.w.raw.delete_fail.clear()
                    f.w.raw.delete_noop.clear()
                    f.w.raw.delete_op_error.clear()
                    self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'released')
