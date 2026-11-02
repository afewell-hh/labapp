"""SOURCE-authored producer/cleanup separation; execution belongs to ROOT/CI.

Uses real access upload, OS Login and controller paths with existing transports.
No project execution, cloud credentials or migration authority is implied.
"""
import copy
import unittest
from unittest.mock import patch

from . import inline_history as inline, test_access
from .access_records import AccessError, Context, canonical, digest, validate_record
from .access_recovery import OWNER_SELF
from .oslogin import OwnKeyImport, SelfLogin, cleanup_own_key
from .test_access import OS, key
from .test_access_recovery import FIELDS
from .test_inline_history import Flows, lease


@patch.object(test_access, 'SELF', OWNER_SELF)
class AccessProducerCapacity(unittest.TestCase):
    def fixture(self, *, prepared=True):
        f = Flows()
        f.trial(1)
        f.migrate_in_fixture()
        record = f.w.started(run=2, uuid=lease(2))
        f.context = f.w.ctl.register_access(
            lease(2), producer_run_id=2, producer_attempt=1,
            self_user=OWNER_SELF, public_key_text=key(2),
            expected_trial={k: record[k] for k in FIELDS})
        f.os = OS()
        f.login = SelfLogin(OWNER_SELF, token_provider=lambda: 'fake', transport=f.os)
        f.session = OwnKeyImport(f.records, f.context, f.login,
                                producer_run_id=2, producer_attempt=1, now=f.w.clock.now)
        if prepared:
            f.session.prepare(key(2))
        return f

    def write(self, f, record):
        _, generation = f.w.store.read(f.w.cfg.key)
        return f.w.store.write(f.w.cfg.key, record, if_generation_match=generation)

    def opaque_full(self, f):
        record = f.w.record()
        original = copy.deepcopy(record['evidence'])
        record['evidence'] = original + ['opaque "\\\n\x00é', '']
        record['evidence'][-1] = 'x' * (
            inline.EVIDENCE_BYTES - len(canonical(record['evidence'])))
        self.assertEqual(record['evidence'][:len(original)], original)
        self.assertEqual(len(canonical(record['evidence'])), 4096)
        self.assertGreater(inline.cleanup_evidence_bound(record), 4096)
        # Isolate the missing prospective gate: all preexisting reader and
        # aggregate-continuation checks still accept the exact same slot.
        inline.validate(record, reserve=True, adding=True)
        self.assertEqual(Context.from_slot(record), f.context)
        generation = self.write(f, record)
        return record, generation

    def mutations(self, f):
        return ([c for c in f.gcs.calls if c[0] == 'POST'],
                [c for c in f.os.calls if c[0] in ('POST', 'DELETE')])

    def test_readers_accept_actual_bytes_but_producer_refuses_future_facts(self):
        f = self.fixture()
        record, generation = self.opaque_full(f)
        self.assertEqual(f.context.current(f.records.slot()), record)
        with self.assertRaisesRegex(AccessError, 'cleanup facts'):
            f.context.producer_current(f.records.slot())
        self.assertEqual(f.w.store.read(f.w.cfg.key), (record, generation))

    def test_changed_reserve_before_prepare_creates_no_intent_or_key(self):
        f = self.fixture(prepared=False)
        before = copy.deepcopy(f.gcs.objects)
        expected = self.opaque_full(f)
        mutations = self.mutations(f)
        with self.assertRaisesRegex(AccessError, 'cleanup facts'):
            f.session.prepare(key(2))
        self.assertEqual(self.mutations(f), mutations)
        self.assertEqual(f.gcs.objects, before)
        self.assertEqual(f.records.read(f.context, 'intent'), (None, 0))
        self.assertEqual(f.w.store.read(f.w.cfg.key), expected)

    def test_changed_reserve_during_profile_read_blocks_actual_intent_upload(self):
        f = self.fixture(prepared=False)
        original = f.login.profile
        expected = []

        def changed_profile():
            result = original()
            expected.append(self.opaque_full(f))
            return result

        mutations = self.mutations(f)
        with patch.object(f.login, 'profile', side_effect=changed_profile):
            with self.assertRaisesRegex(AccessError, 'cleanup facts'):
                f.session.prepare(key(2))
        self.assertEqual(len(expected), 1)
        self.assertEqual(self.mutations(f), mutations)
        self.assertEqual(f.records.read(f.context, 'intent'), (None, 0))
        self.assertEqual(f.w.store.read(f.w.cfg.key), expected[0])

    def test_changed_reserve_blocks_each_actual_noncleanup_upload(self):
        control = self.fixture()
        imported = control.session.import_once()
        for kind in ('intent', 'import', 'seal'):
            with self.subTest(kind=kind):
                f = self.fixture()
                intent, generation = f.records.read(f.context, 'intent')
                ref = dict(intent_generation=generation, intent_sha256=digest(intent))
                values = {
                    'intent': intent,
                    'import': dict(imported, binding=f.context.binding, **ref),
                    'seal': dict(schema=1, kind='seal', binding=f.context.binding, **ref,
                                 provenance_sha256='1' * 64, manifest_sha256='2' * 64,
                                 postcondition_sha256='3' * 64, nonce='4' * 64, result='sealed')}
                value = values[kind]
                validate_record(value, f.context, kind)
                expected = self.opaque_full(f)
                objects = copy.deepcopy(f.gcs.objects)
                mutations = self.mutations(f)
                with self.assertRaisesRegex(AccessError, 'cleanup facts'):
                    f.records.create(f.context, kind, value)
                self.assertEqual(self.mutations(f), mutations)
                self.assertEqual(f.gcs.objects, objects)
                self.assertEqual(f.w.store.read(f.w.cfg.key), expected)

    def test_changed_reserve_after_prepare_blocks_actual_import_and_consumes_permit(self):
        f = self.fixture()
        expected = self.opaque_full(f)
        objects = copy.deepcopy(f.gcs.objects)
        mutations = self.mutations(f)
        with self.assertRaisesRegex(AccessError, 'cleanup facts'):
            f.session.import_once()
        with self.assertRaisesRegex(AccessError, 'one-shot'):
            f.session.import_once()
        self.assertEqual(self.mutations(f), mutations)
        self.assertEqual(f.gcs.objects, objects)
        self.assertEqual(f.os.profile['sshPublicKeys'], {})
        self.assertEqual(f.w.store.read(f.w.cfg.key), expected)

    def test_changed_reserve_during_intent_read_blocks_actual_import(self):
        f = self.fixture()
        original = f.records.read
        expected = []

        def changed_read(context, kind):
            result = original(context, kind)
            if kind == 'intent':
                expected.append(self.opaque_full(f))
            return result

        mutations = self.mutations(f)
        with patch.object(f.records, 'read', side_effect=changed_read):
            with self.assertRaisesRegex(AccessError, 'cleanup facts'):
                f.session.import_once()
        self.assertEqual(len(expected), 1)
        self.assertEqual(self.mutations(f), mutations)
        self.assertEqual(f.os.profile['sshPublicKeys'], {})
        self.assertEqual(f.w.store.read(f.w.cfg.key), expected[0])

    def test_invalid_producer_reserve_allows_key_removal_receipt_and_physical_disposal(self):
        f = self.fixture()
        imported = f.session.import_once()
        retained = copy.deepcopy(f.gcs.objects)
        expected = self.opaque_full(f)
        mutations = self.mutations(f)
        receipt = cleanup_own_key(f.records, f.context, f.login, now=f.w.clock.now)
        self.assertEqual(receipt['outcome'], 'removed')
        self.assertEqual(receipt['server_name'], imported['server_name'])
        self.assertEqual(f.records.read(f.context, 'removed')[0], receipt)
        self.assertEqual(f.os.profile['sshPublicKeys'], {})
        uploads, login_mutations = self.mutations(f)
        self.assertEqual(len(uploads), len(mutations[0]) + 1)
        self.assertEqual(len(login_mutations), len(mutations[1]) + 1)
        self.assertEqual(login_mutations[-1][0], 'DELETE')
        self.assertIn(f.context.path('removed').replace('/', '%2F'), uploads[-1][1])
        # Repeated cleanup verifies the terminal receipt without another mutation.
        self.assertEqual(cleanup_own_key(f.records, f.context, f.login,
                                        now=f.w.clock.now), receipt)
        self.assertEqual(self.mutations(f), (uploads, login_mutations))
        f.w.raw.leak_disks = True
        result = f.w.ctl.reconcile(lease(2))
        self.assertEqual(result.status, 'blocked', result.detail)
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertEqual(f.w.store.read(f.w.cfg.key), expected)
        self.assertNotEqual(f.w.record()['state'], 'FREE')
        for name, value in retained.items():
            self.assertEqual(f.gcs.objects[name], value)

    def test_exact_prospective_bound_allows_import_cleanup_and_normal_release(self):
        f = self.fixture()
        record = f.w.record()
        record['evidence'].append('')
        record['evidence'][-1] = 'x' * (
            inline.EVIDENCE_BYTES - inline.cleanup_evidence_bound(record))
        self.assertEqual(inline.cleanup_evidence_bound(record), 4096)
        self.assertLess(len(canonical(record['evidence'])), 4096)
        f.context.producer_current(record)
        self.write(f, record)
        self.assertIsNotNone(f.session.import_once())
        cleanup_own_key(f.records, f.context, f.login, now=f.w.clock.now)
        self.assertEqual(f.w.ctl.reconcile(lease(2)).status, 'released')
        free = f.w.record()
        self.assertEqual(free['last_release']['evidence'][:len(record['evidence'])],
                         record['evidence'])
        self.assertEqual(free['access_history'][:-1], record['access_history'])
        self.assertEqual(free['legacy_history'], record['legacy_history'])
        inline.free_budget(free)
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))

    def test_one_over_prospective_bound_blocks_import_below_actual_evidence_cap(self):
        f = self.fixture()
        record = f.w.record()
        record['evidence'].append('')
        record['evidence'][-1] = 'x' * (
            inline.EVIDENCE_BYTES + 1 - inline.cleanup_evidence_bound(record))
        self.assertEqual(inline.cleanup_evidence_bound(record), 4097)
        self.assertLess(len(canonical(record['evidence'])), 4096)
        inline.validate(record, reserve=True, adding=True)
        generation = self.write(f, record)
        mutations = self.mutations(f)
        with self.assertRaisesRegex(AccessError, 'cleanup facts'):
            f.session.import_once()
        self.assertEqual(self.mutations(f), mutations)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (record, generation))

    def test_schema1_access_keeps_existing_behavior_without_schema2_gate(self):
        f = test_access.Fixture()
        with patch.object(inline, 'cleanup_budget', side_effect=AssertionError('schema2 only')):
            f.imported()
            self.assertEqual(f.clean()['outcome'], 'removed')
        self.assertEqual(f.w.record()['schema'], 1)


if __name__ == '__main__':
    unittest.main()
