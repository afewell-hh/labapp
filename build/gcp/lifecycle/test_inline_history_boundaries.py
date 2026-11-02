"""SOURCE-only boundary/interleaving probes; execution belongs to ROOT.

Policy allocations are not provider maxima. In particular, the closed new-entry
grammar cannot express 2048/2049-byte valid entries: its widest normal/failed
entries are 1354/1517 bytes. Do not pad them with forbidden fields and mistake
an unrelated shape refusal for a byte-boundary proof.
"""
import copy
import json
import unittest
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from . import inline_history as inline, spec, test_access
from .access_records import AccessError, Context, KINDS, canonical, digest, validate_binding
from .access_recovery import FailedAccessRecovery, OWNER_SELF, bounded, path, validate_proof
from .controller import Refused
from .gcs import MAX_RECORD_BYTES, StoreError, _record
from .oslogin import cleanup_own_key
from .test_access import key
from .test_access_recovery import FIELDS, POLICY_SOURCE, TRIAL
from .test_inline_history import Flows, lease


COMMON_LIMIT = 44_992
TEXT = ('"\\/' + ''.join(chr(n) for n in range(32))
        + '\u007f\u0080\u00e9\u2028\u2029\u4e2d\U0001f600'
        + '\ud800-\udfff\uffff\U0010ffff')


def common(record):
    return {k: record[k] for k in inline.COMMON2}


def live(record):
    return {k: v for k, v in record.items()
            if k not in inline.COMMON2 and k != 'evidence'}


def prefix_digest(record):
    count = record['legacy_history']['count']
    record['legacy_history']['sha256'] = digest(record['access_history'][:count])


class SlotWire:
    """Interleave real adapter POSTs, retaining actual wire generation checks."""
    def __init__(self, server):
        self.server = server
        self.calls = []
        self.before_post = None

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == 'POST' and self.before_post is not None:
            hook, self.before_post = self.before_post, None
            hook(json.loads(kwargs['body']))
        return self.server.request(method, url, **kwargs)


class RecoveryCase:
    """Existing positive fixture's actual deletion/observation/proof composition."""
    def __init__(self, flow, number):
        self.f, self.number = flow, number
        original = flow.w.record()
        assert flow.w.ctl.reconcile(lease(number)).status == 'blocked'
        target = (f'https://compute.googleapis.com/compute/v1/projects/{spec.PROJECT}'
                  f'/zones/{spec.ZONE}/instances/' + original['names']['instance'])
        for operation in flow.w.raw.ops.values():
            if operation['targetLink'].rsplit('/', 1)[-1] == original['names']['instance']:
                operation['targetLink'] = target
                if operation['operationType'] == 'delete':
                    operation['targetId'] = original['ids']['instance']
        flow.w.clock.advance(21)
        self.expected = flow.w.store.read(flow.w.cfg.key)
        self.decision = dict(
            reference='https://github.com/afewell-hh/labapp/issues/455#issuecomment-123',
            trial_source_sha=TRIAL, policy_source_sha=POLICY_SOURCE,
            local_evidence_sha256='c' * 64)
        self.approved = []
        self.engine = FailedAccessRecovery(
            flow.w.store, flow.w.cloud, flow.records, flow.proofs, flow.login,
            collect=self.collect, approve=self.approve, now=flow.w.clock.now)

    def collect(self, slot, decision):
        assert slot == self.expected[0] and decision == self.decision
        return dict(
            creator=dict(run_id=self.number, attempt=1, source_sha=TRIAL,
                         sha256='d' * 64, latest_sha256='e' * 64, conclusion='cancelled'),
            local=dict(
                lease=lease(self.number), source_sha=TRIAL, coordinator_sha256='f' * 64,
                registration_sha256='a' * 64, evidence_sha256='c' * 64,
                terminated_at=spec.rfc3339(self.f.w.clock.now() - timedelta(minutes=1)),
                checked_at=spec.rfc3339(self.f.w.clock.now()),
                result='coordinator-children-terminated-private-files-absent'))

    def approve(self, sha, decision):
        assert decision == self.decision
        self.approved.append(sha)
        return sha

    def prepare(self):
        proof = self.engine.prepare(self.expected, self.decision)
        validate_proof(proof)
        return proof

    def recover(self, proof):
        return self.engine.recover_failed_access(self.expected, proof, self.decision)


@patch.object(test_access, 'SELF', OWNER_SELF)
class InlineBoundaries(unittest.TestCase):
    def seed(self):
        f = Flows()
        f.trial(1)
        f.trial(2, failed=True)
        f.migrate_in_fixture()
        inline.validate(f.w.record(), reserve=True, adding=True)
        return f

    def write(self, f, record):
        _, generation = f.w.store.read(f.w.cfg.key)
        result = f.w.store.write(f.w.cfg.key, record, if_generation_match=generation)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (record, result))
        return result

    def fill_common(self, record, *, depth=30):
        value = 'leaf'
        for _ in range(depth - 3):
            value = [value]
        record['used_capture_ids'] = [lease(n) for n in range(1000, 1512)]
        record['access_history'][0].update(boundary_depth=value, escaped=TEXT, padding='')
        prefix_digest(record)
        amount = COMMON_LIMIT - len(canonical(common(record)))
        self.assertGreater(amount, 0)
        record['access_history'][0]['padding'] = 'x' * amount
        prefix_digest(record)
        self.assertEqual(len(canonical(common(record))), COMMON_LIMIT)
        inline.validate(record, reserve=True, adding=True)
        if record['state'] == 'FREE':
            legacy = copy.deepcopy(record)
            legacy['schema'] = 1
            del legacy['legacy_history']
            plan = inline.plan_migration(legacy, 101)
            self.assertEqual(plan['expected'], legacy)
            self.assertEqual(plan['replacement'], record)

    def fill_occupied(self, record):
        # Actual-byte proof/reader envelope, not a prospective producer fixture.
        record['evidence'] = [TEXT, '']
        record['evidence'][-1] = 'x' * (
            inline.EVIDENCE_BYTES - len(canonical(record['evidence'])))
        record.update(state='CLEANUP_FAILED', reason='')
        record['reason'] = 'x' * (inline.LIVE_BYTES - len(canonical(live(record))))
        self.assertEqual(len(canonical(live(record))), 8192)
        self.assertEqual(len(canonical(record['evidence'])), 4096)
        inline.validate(record, reserve=True, adding=True)
        Context.from_slot(record)

    def fill_producer_occupied(self, record):
        # Charge opaque existing evidence AND all still-unobserved facts. Do not
        # insert hypothetical observations just to deduplicate their reserve.
        original = copy.deepcopy(record['evidence'])
        record['evidence'] = original + [TEXT, '']
        amount = inline.EVIDENCE_BYTES - inline.cleanup_evidence_bound(record)
        self.assertGreater(amount, 0)
        record['evidence'][-1] = 'x' * amount
        record.update(state='CLEANUP_FAILED', reason='')
        record['reason'] = 'x' * (inline.LIVE_BYTES - len(canonical(live(record))))
        self.assertEqual(len(canonical(live(record))), inline.LIVE_BYTES)
        self.assertEqual(record['evidence'][:len(original)], original)
        self.assertLess(len(canonical(record['evidence'])), inline.EVIDENCE_BYTES)
        self.assertEqual(inline.cleanup_evidence_bound(record), inline.EVIDENCE_BYTES)
        inline.validate(record, reserve=True, adding=True)
        inline.cleanup_budget(record)
        Context.from_slot(record).producer_current(record)
        over = copy.deepcopy(record)
        over['evidence'][-1] += 'x'
        inline.validate(over, reserve=True, adding=True)
        self.assertEqual(inline.cleanup_evidence_bound(over), inline.EVIDENCE_BYTES + 1)
        with self.assertRaisesRegex(inline.HistoryError, 'cleanup facts'):
            inline.cleanup_budget(over)

    def assert_failed_release(self, f, case, proof):
        stored_proof, proof_generation = f.proofs.read(f.context)
        self.assertEqual(stored_proof, proof)
        free = f.w.record()
        inline.free_budget(free)
        self.assertEqual((free['schema'], free['state']), (2, 'FREE'))
        self.assertEqual(free['legacy_history'], case.expected[0]['legacy_history'])
        self.assertEqual(free['access_history'][:-1], case.expected[0]['access_history'])
        self.assertEqual(free['used_capture_ids'], case.expected[0]['used_capture_ids'])
        retained = free['access_history'][-1]
        self.assertEqual(retained['binding'], f.context.binding)
        self.assertEqual((retained['trial'], retained['import_status'], retained['disposition']),
                         ('FAILED', 'UNKNOWN', 'FAILED_DISPOSED'))
        self.assertEqual(retained['archive'], proof['observations']['receipts'])
        ref = dict(path=path(f.context), generation=proof_generation, sha256=digest(proof))
        self.assertEqual(retained['recovery'], ref)
        self.assertEqual(free['last_release']['recovery'], ref)
        self.assertEqual(free['last_release']['import_status'], 'UNKNOWN')
        self.assertEqual(proof['slot'], case.expected[0])
        self.assertEqual(proof['slot_generation'], case.expected[1])
        self.assertEqual(proof['slot_sha256'], digest(case.expected[0]))
        for kind in KINDS:
            value, generation = f.records.read(f.context, kind)
            receipt = retained['archive'][kind]
            self.assertEqual(receipt['path'], f.context.path(kind))
            self.assertEqual(receipt['generation'], generation)
            self.assertEqual(receipt['sha256'], digest(value) if value is not None else None)
            self.assertEqual(receipt['observation'],
                             'present' if kind == 'intent' else 'observed-absent')
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))

    def test_closed_entry_maxima_expose_unexpressible_2048_boundary(self):
        f = self.seed()
        f.trial(3)
        f.trial(4, failed=True)
        produced = f.w.record()
        inline.validate(produced, reserve=True, adding=True)
        for index, expected_size in ((2, 1354), (3, 1517)):
            with self.subTest(phase=produced['access_history'][index]['phase']):
                entry = copy.deepcopy(produced['access_history'][index])
                # Widen only typed, bounded fields. This is a validator-domain
                # upper envelope, not an attested receipt or a provider measurement.
                entry['binding'].update(
                    epoch=2**63 - 1, run_id=2**63 - 1, attempt=2**63 - 1,
                    vm_id=str(2**64 - 1), boot_id=str(2**64 - 1),
                    self_user='users/' + 'a' * 128)
                validate_binding(entry['binding'])
                for kind, ref in entry['archive'].items():
                    if entry['phase'] == 'archived' or kind == 'intent':
                        ref.update(generation=2**64 - 1, sha256='f' * 64)
                if entry['phase'] == 'failed-disposed':
                    entry['recovery'].update(generation=2**64 - 1)
                candidate = copy.deepcopy(produced)
                candidate['access_history'][index] = entry
                inline.validate(candidate, reserve=True, adding=True)
                self.assertEqual(len(canonical(entry)), expected_size)
                self.assertLess(expected_size, inline.NEW_ENTRY_BYTES)
                # No valid variable-width field remains to reach 2048 or 2049.
                # A forbidden filler would test closed fields, NOT the byte cap.
        self.assertEqual(inline.NEW_ENTRY_BYTES, 2048)

    def test_tombstones_512_roundtrip_and_513_refuse_before_admission(self):
        f = self.seed()
        candidate = f.w.record()
        candidate['used_capture_ids'] = [lease(n) for n in range(1000, 1512)]
        inline.validate(candidate, reserve=True, adding=True)
        self.write(f, candidate)
        f.trial(3)
        self.assertEqual(f.w.record()['used_capture_ids'], candidate['used_capture_ids'])
        self.assertEqual(len(set(candidate['used_capture_ids'])), 512)
        bad = f.w.record()
        bad['used_capture_ids'].append(lease(1512))
        generation = self.write(f, bad)
        calls = len(f.w.raw.calls)
        with self.assertRaisesRegex(inline.HistoryError, 'used_capture_ids'):
            inline.validate(bad, reserve=True, adding=True)
        with self.assertRaisesRegex(Refused, 'used_capture_ids'):
            f.w.ctl.admit(4, 1, lease(4))
        self.assertEqual(f.w.store.read(f.w.cfg.key), (bad, generation))
        self.assertEqual(len(f.w.raw.calls), calls)

    def test_unicode_and_json_escaping_charge_actual_wire_bytes(self):
        f = self.seed()
        candidate = f.w.record()
        self.fill_common(candidate)
        encoded = canonical(candidate)
        self.assertEqual(json.loads(encoded)['access_history'][0]['escaped'], TEXT)
        for token in (b'\\"', b'\\\\', b'\\b', b'\\f', b'\\n', b'\\r', b'\\t',
                      b'\\u0000', b'\\u001f', b'\\u007f', b'\\u0080', b'\\u00e9',
                      b'\\u2028', b'\\u4e2d', b'\\ud83d\\ude00'):
            self.assertIn(token, encoded)
        self.assertGreater(len(canonical(TEXT)), len(TEXT.encode('utf-8', errors='surrogatepass')))
        self.write(f, candidate)
        self.assertEqual(f.http.data, encoded)
        good, generation = f.w.store.read(f.w.cfg.key)
        good['access_history'][0]['padding'] += 'x'
        prefix_digest(good)
        self.assertEqual(len(canonical(common(good))), COMMON_LIMIT + 1)
        # All entries and the physical media still validate: only the prospective
        # continuation reserve is over, not some unrelated syntax/depth gate.
        inline.validate(good)
        _record(good, f.w.cfg.key)
        self.assertLess(len(canonical(good)), MAX_RECORD_BYTES)
        with self.assertRaisesRegex(inline.HistoryError, 'reserved failed proof'):
            inline.validate(good, reserve=True, adding=True)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (candidate, generation))

    def test_simultaneous_common_live_evidence_normal_constructor_release(self):
        f = self.seed()
        candidate = f.w.record()
        self.fill_common(candidate)
        self.write(f, candidate)
        f.begin(3)
        occupied = f.w.record()
        self.fill_producer_occupied(occupied)
        self.write(f, occupied)
        evidence = copy.deepcopy(occupied['evidence'])
        # Actual bytes and prospective allocation are deliberately different.
        future_bytes = inline.cleanup_evidence_bound(occupied) - len(canonical(evidence))
        self.assertGreater(future_bytes, 0)
        self.assertEqual(len(canonical(evidence)) + future_bytes, 4096)
        history = copy.deepcopy(occupied['access_history'])
        f.session.import_once()
        cleanup_own_key(f.records, f.context, f.login, now=f.w.clock.now)
        receipts = {kind: f.records.read(f.context, kind) for kind in KINDS}
        self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'released')
        free = f.w.record()
        inline.free_budget(free)
        self.assertEqual(free['access_history'][:-1], history)
        self.assertEqual(free['legacy_history'], occupied['legacy_history'])
        self.assertEqual(free['used_capture_ids'], occupied['used_capture_ids'])
        expected_facts = [
            inline.cleanup_fact('instance', occupied['names']['instance'], occupied['ids']['instance']),
            inline.cleanup_fact('boot', occupied['names']['boot'])]
        self.assertEqual(free['last_release']['evidence'], evidence + expected_facts)
        self.assertLessEqual(len(canonical(free['last_release']['evidence'])), 4096)
        for kind, (value, generation) in receipts.items():
            self.assertEqual(free['access_history'][-1]['archive'][kind],
                             dict(path=f.context.path(kind), generation=generation,
                                  sha256=digest(value) if value is not None else None))
        self.assertLess(len(canonical(free)), MAX_RECORD_BYTES)
        self.assertLess(len(canonical({k: v for k, v in free.items()
                                     if k not in inline.COMMON2})), inline.LIVE_BYTES)
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        # Actual FREE does not consume all 8192 residual bytes: reason/operation
        # are not copied by the constructor. No fabricated maximum-FREE claim.
        calls = len(f.w.raw.calls)
        with self.assertRaises(Refused):
            f.w.ctl.admit(4, 1, lease(4))
        self.assertEqual(len(f.w.raw.calls), calls)

    def test_simultaneous_maximum_failed_proof_depth31_wrapper32(self):
        f = self.seed()
        candidate = f.w.record()
        self.fill_common(candidate)
        self.write(f, candidate)
        f.begin(3)
        case = RecoveryCase(f, 3)
        occupied = f.w.record()
        # Real operation objects are renamed, not replaced with proof-validator
        # stand-ins; prepare/recover still perform exact original/delete reads.
        original_name = occupied['operation']
        original = f.w.raw.ops.pop(original_name)
        original['name'] = 'I' * 200
        f.w.raw.ops[original['name']] = original
        occupied['operation'] = original['name']
        deleted_name, deleted = next((name, op) for name, op in f.w.raw.ops.items()
                                    if op['operationType'] == 'delete'
                                    and op.get('targetId') == occupied['ids']['instance'])
        del f.w.raw.ops[deleted_name]
        deleted['name'] = 'D' * 200
        f.w.raw.ops[deleted['name']] = deleted
        self.fill_occupied(occupied)
        self.write(f, occupied)
        case.expected = f.w.store.read(f.w.cfg.key)
        baseline = case.prepare()
        residual_size = len(canonical({k: v for k, v in baseline.items() if k != 'slot'}))
        self.assertLess(residual_size, inline.PROOF_EXTRA_BYTES)
        # The decision-reference regex has no digit-count cap. Exercise that
        # actual supported grammar through prepare(), not a copied proof model.
        # This synthetic reference is NOT externally authenticated lead approval.
        case.decision['reference'] += '9' * (inline.PROOF_EXTRA_BYTES - residual_size)
        proof = case.prepare()
        self.assertEqual(len(canonical(common(proof['slot']))), 44992)
        self.assertEqual(len(canonical(live(proof['slot']))), 8192)
        self.assertEqual(len(canonical(proof['slot']['evidence'])), 4096)
        self.assertEqual(len(canonical({k: v for k, v in proof.items() if k != 'slot'})), 8192)
        self.assertEqual(len(canonical(proof)), 65491)
        self.assertEqual(proof['slot']['operation'], 'I' * 200)
        self.assertEqual(proof['observations']['compute']['delete_operation'], 'D' * 200)
        bounded(proof)  # actual ledger wrapper: deepest leaf at depth32
        self.assertEqual(case.recover(proof).status, 'failed-disposed')
        self.assert_failed_release(f, case, proof)
        too_large = copy.deepcopy(proof)
        too_large['decision']['reference'] += '9'
        self.assertLess(len(canonical(too_large)), MAX_RECORD_BYTES)
        with self.assertRaisesRegex(AccessError, 'proof residual'):
            validate_proof(too_large)
        deeper = copy.deepcopy(proof)
        deeper['slot']['access_history'][0]['boundary_depth'] = [
            deeper['slot']['access_history'][0]['boundary_depth']]
        prefix_digest(deeper['slot'])
        # Semantic accounting rejects depth31; the physical reader still accepts.
        _record(deeper['slot'], f.w.cfg.key)
        with self.assertRaisesRegex(inline.HistoryError, 'nesting'):
            inline.validate(deeper['slot'], reserve=True, adding=True)
        with self.assertRaisesRegex(StoreError, 'nesting'):
            bounded(deeper)  # proof32, actual validation wrapper33

    def test_gcs_media_65536_65537_and_physical_depth32_33(self):
        f = self.seed()
        candidate = f.w.record()
        candidate['access_history'][0]['physical_media_padding'] = ''
        candidate['access_history'][0]['physical_media_padding'] = 'x' * (
            MAX_RECORD_BYTES - len(canonical(candidate)))
        prefix_digest(candidate)
        self.assertEqual(len(canonical(candidate)), 65536)
        inline.validate(candidate)
        generation = self.write(f, candidate)
        self.assertEqual(len(f.http.data), 65536)
        with self.assertRaises(inline.HistoryError):
            inline.validate(candidate, reserve=True, adding=True)
        candidate['access_history'][0]['physical_media_padding'] += 'x'
        with self.assertRaisesRegex(StoreError, 'size limit'):
            f.w.store.write(f.w.cfg.key, candidate, if_generation_match=generation)
        self.assertEqual(f.http.generation, generation)
        depth = f.w.record()
        depth['access_history'][0].pop('physical_media_padding')
        value = 'leaf'
        for _ in range(29):
            value = [value]
        depth['access_history'][0]['physical_depth'] = value
        prefix_digest(depth)
        self.write(f, depth)  # leaf32 is readable for independently owned cleanup
        with self.assertRaisesRegex(inline.HistoryError, 'nesting'):
            inline.validate(depth)
        depth['access_history'][0]['physical_depth'] = [value]
        with self.assertRaisesRegex(StoreError, 'nesting'):
            self.write(f, depth)

    def test_submission_cas_loses_to_release_and_new_schema2_reservation(self):
        f = self.seed()
        f.trial(3)  # genuine schema2 submission/registration/release control
        previous = f.w.record()
        f.w.ctl.admit(4, 1, lease(4))
        _, captured_generation = f.w.store.read(f.w.cfg.key)
        wire = SlotWire(f.http)
        f.w.store.http = wire

        def compete(candidate):
            self.assertEqual((candidate['request_id'], candidate['submit_attempts']), (lease(4), 1))
            self.assertEqual(f.w.ctl.reconcile(lease(4)).status, 'released')
            f.w.ctl.admit(5, 1, lease(5))

        wire.before_post = compete
        inserts = sum(verb == 'insert' for _, verb, _ in f.w.raw.calls)
        with self.assertRaisesRegex(Refused, 'lease changed before submit'):
            f.w.ctl.submit(lease(4))
        winner = f.w.record()
        self.assertEqual((winner['schema'], winner['request_id'], winner['submit_attempts']),
                         (2, lease(5), 0))
        self.assertEqual(winner['access_history'], previous['access_history'])
        self.assertEqual(winner['legacy_history'], previous['legacy_history'])
        self.assertEqual(sum(verb == 'insert' for _, verb, _ in f.w.raw.calls), inserts)
        attempted = next(c for c in wire.calls if c[0] == 'POST')
        self.assertEqual(parse_qs(urlsplit(attempted[1]).query)['ifGenerationMatch'],
                         [str(captured_generation)])
        self.assertNotEqual(winner['state'], 'FREE')

    def test_submission_rechecks_changed_common_before_insert(self):
        f = self.seed()
        f.trial(3)
        candidate = f.w.ctl.admit(4, 1, lease(4))
        self.fill_common(candidate)
        self.write(f, candidate)
        candidate['access_history'][0]['padding'] += 'x'
        prefix_digest(candidate)
        inline.validate(candidate)
        generation = self.write(f, candidate)
        calls = len(f.w.raw.calls)
        with self.assertRaisesRegex(Refused, 'reserved failed proof'):
            f.w.ctl.submit(lease(4))
        self.assertEqual(len(f.w.raw.calls), calls)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (candidate, generation))
        self.assertEqual(candidate['submit_attempts'], 0)
        self.assertIsNone(candidate['operation'])
        self.assertEqual(candidate['ids'], {'instance': None, 'boot': None})

    def test_registration_cas_loses_without_publishing_access_or_receipts(self):
        f = self.seed()
        f.trial(3)
        f.w.started(run=4, uuid=lease(4))
        captured, generation = f.w.store.read(f.w.cfg.key)
        wire = SlotWire(f.http)
        f.w.store.http = wire
        objects = copy.deepcopy(f.gcs.objects)

        def compete(candidate):
            self.assertEqual(candidate['access']['phase'], 'registered')
            self.assertEqual(f.w.ctl.reconcile(lease(4)).status, 'released')
            f.w.ctl.admit(5, 1, lease(5))

        wire.before_post = compete
        with self.assertRaisesRegex(Refused, 'registration lost ownership'):
            f.w.ctl.register_access(
                lease(4), producer_run_id=4, producer_attempt=1,
                self_user=OWNER_SELF, public_key_text=key(4),
                expected_trial={k: captured[k] for k in FIELDS})
        winner, actual = f.w.store.read(f.w.cfg.key)
        self.assertGreater(actual, generation)
        self.assertEqual((winner['schema'], winner['request_id']), (2, lease(5)))
        self.assertNotIn('access', winner)
        self.assertEqual(winner['access_history'], captured['access_history'])
        self.assertEqual(winner['legacy_history'], captured['legacy_history'])
        self.assertEqual(f.gcs.objects, objects)

    def test_failed_recovery_stale_generation_and_post_upload_cas_never_free(self):
        positive = self.seed()
        positive.begin(3)
        control = RecoveryCase(positive, 3)
        proof = control.prepare()
        self.assertEqual(control.recover(proof).status, 'failed-disposed')
        self.assert_failed_release(positive, control, proof)
        for race in ('before-observation', 'after-proof-upload'):
            with self.subTest(race=race):
                f = self.seed()
                f.begin(3)
                case = RecoveryCase(f, 3)
                proof = case.prepare()
                captured, generation = case.expected
                if race == 'before-observation':
                    self.write(f, captured)  # identical bytes, genuinely new generation
                else:
                    wire = SlotWire(f.http)
                    f.w.store.http = wire

                    def compete(candidate):
                        self.assertEqual(candidate['last_release']['import_status'], 'UNKNOWN')
                        self.write(f, captured)

                    wire.before_post = compete
                calls = len(f.w.raw.calls)
                with self.assertRaisesRegex(AccessError, 'generation changed|CAS conflict'):
                    case.recover(proof)
                current, actual = f.w.store.read(f.w.cfg.key)
                self.assertEqual(current, captured)
                self.assertEqual(actual, generation + 1)
                self.assertNotEqual(current['state'], 'FREE')
                self.assertEqual(current['operation'], proof['slot']['operation'])
                self.assertEqual(case.approved, [digest(proof)])
                self.assertFalse([c for c in f.w.raw.calls[calls:]
                                  if c[1] in ('insert', 'delete')])
                stored, stored_generation = f.proofs.read(f.context)
                if race == 'after-proof-upload':
                    self.assertEqual(stored, proof)
                    self.assertGreater(stored_generation, 0)
                else:
                    self.assertEqual((stored, stored_generation), (None, 0))
                for kind in KINDS[1:]:
                    self.assertEqual(f.records.read(f.context, kind), (None, 0))

    def test_failed_recovery_new_valid_receipt_invalidates_absence_proof(self):
        normal = self.seed()
        normal.begin(3)
        normal.session.import_once()
        self.assertIsNotNone(normal.records.read(normal.context, 'import')[0])
        f = self.seed()
        f.begin(3)
        # The real producer constructs the receipt, but its transport delays the
        # one upload. It can arrive after proof preparation without another import.
        f.gcs.upload_mode = 'pending'
        with self.assertRaises(AccessError):
            f.session.import_once()
        self.assertEqual(len(f.gcs.pending), 1)
        case = RecoveryCase(f, 3)
        # Fake OS Login does not expire keys itself; model the now-elapsed TTL at
        # the provider boundary. Recovery still validates the complete profile.
        f.os.profile['sshPublicKeys'].clear()
        proof = case.prepare()
        self.assertEqual(f.context.binding, normal.context.binding)
        self.assertEqual(f.records.read(f.context, 'import'), (None, 0))
        f.gcs.finish()
        imported, generation = f.records.read(f.context, 'import')
        self.assertIsNotNone(imported)
        self.assertGreater(generation, proof['observations']['receipts']['intent']['generation'])
        with self.assertRaisesRegex(AccessError, 'unexpected original access receipt'):
            case.recover(proof)
        self.assertEqual(f.w.store.read(f.w.cfg.key), case.expected)
        self.assertEqual(f.proofs.read(f.context), (None, 0))
        self.assertNotEqual(f.w.record()['state'], 'FREE')

    def test_actual_access_adapter_rechecks_schema2_context_before_upload(self):
        f = self.seed()
        f.begin(3)
        intent, generation = f.records.read(f.context, 'intent')
        self.assertGreater(generation, 0)
        # Positive create-only replay traverses validation and current-slot gates.
        self.assertEqual(f.records.create(f.context, 'intent', intent), (generation, False))
        corrupted = f.w.record()
        corrupted['legacy_history']['sha256'] = '0' * 64
        self.write(f, corrupted)
        posts = len([c for c in f.gcs.calls if c[0] == 'POST'])
        with self.assertRaisesRegex(AccessError, 'legacy prefix digest mismatch'):
            f.records.create(f.context, 'intent', intent)
        self.assertEqual(len([c for c in f.gcs.calls if c[0] == 'POST']), posts)
        self.assertEqual(f.w.ctl.reconcile(lease(3)).status, 'blocked')
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
        self.assertEqual(f.w.record()['legacy_history'], corrupted['legacy_history'])
        self.assertNotEqual(f.w.record()['state'], 'FREE')

    def test_changed_capacity_blocks_actual_import_before_oslogin_mutation(self):
        control = self.seed()
        control.begin(3)
        control.session.import_once()
        self.assertEqual(len([c for c in control.os.calls if c[0] == 'POST']), 1)
        f = self.seed()
        f.begin(3)
        candidate = f.w.record()
        self.fill_common(candidate)
        candidate['access_history'][0]['padding'] += 'x'
        prefix_digest(candidate)
        generation = self.write(f, candidate)
        objects = copy.deepcopy(f.gcs.objects)
        os_calls = len(f.os.calls)
        gcs_posts = len([c for c in f.gcs.calls if c[0] == 'POST'])
        with self.assertRaisesRegex(AccessError, 'reserved failed proof'):
            f.session.import_once()
        # Authenticated GCS reads are necessary to check actual current capacity.
        # This asserts mutation order, not a universal prohibition of reads.
        self.assertEqual(len(f.os.calls), os_calls)
        self.assertEqual(len([c for c in f.gcs.calls if c[0] == 'POST']), gcs_posts)
        self.assertEqual(f.gcs.objects, objects)
        self.assertEqual(f.w.store.read(f.w.cfg.key), (candidate, generation))
        self.assertNotEqual(f.w.record()['state'], 'FREE')

    def test_failed_recovery_preserves_unsigned64_proof_and_receipt_generations(self):
        f = self.seed()
        f.http.generation = 2**64 - 20
        f.gcs.seq = 2**64 - 3
        # Intent upload uses uint64 storage, but the actual producer refuses to
        # mint a capability for a generation outside signed63 receipt references.
        with self.assertRaisesRegex(AccessError, 'intent generation cannot be represented'):
            f.begin(3)
        self.assertFalse([c for c in f.os.calls if c[0] == 'POST'])
        case = RecoveryCase(f, 3)
        proof = case.prepare()
        self.assertGreater(proof['slot_generation'], 2**63 - 1)
        self.assertEqual(proof['observations']['receipts']['intent']['generation'], 2**64 - 2)
        self.assertEqual(case.recover(proof).status, 'failed-disposed')
        self.assert_failed_release(f, case, proof)
        free = f.w.record()
        self.assertEqual(free['access_history'][-1]['recovery']['generation'], 2**64 - 1)
        for invalid in (True, 2**64):
            bad = copy.deepcopy(free)
            bad['access_history'][-1]['recovery']['generation'] = invalid
            with self.assertRaisesRegex(inline.HistoryError, 'recovery reference'):
                inline.validate(bad)
        self.assertEqual(f.w.record(), free)

    def test_actual_owner_constructor_registers_and_capacity_gate_precedes_cloud(self):
        from build.gcp import vlab_trial as host

        for oversized in (False, True):
            with self.subTest(oversized=oversized):
                f = self.seed()
                rec = f.w.started(run=3, uuid=lease(3))
                snapshot = {k: rec[k] for k in host.SNAPSHOT_FIELDS}
                snapshot.update(source_sha=TRIAL, self_user=OWNER_SELF)
                snapshot['preflight'] = dict(
                    lease=rec['request_id'], vm_id=rec['ids']['instance'],
                    source_sha=TRIAL, checked_at=rec['reserved_at'],
                    **{k: 'c' * 64 for k in
                       ('quota_sha256', 'network_sha256', 'images_sha256',
                        'access_sha256', 'egress_sha256')})
                body = spec.build_body(
                    boot_image=spec.COMPONENT_IMAGE, request_id=lease(3),
                    run_id=3, attempt=1,
                    deadline=f.w.clock.now() + timedelta(minutes=120),
                    profile=spec.UBUNTU_VLAB_CORE)
                inst = f.w.raw.instances[rec['names']['instance']]
                inst.update({k: body[k] for k in
                             ('metadata', 'advancedMachineFeatures', 'minCpuPlatform',
                              'canIpForward', 'deletionProtection')})
                inst['machineType'] = 'projects/' + spec.PROJECT + '/' + body['machineType']
                inst['networkInterfaces'] = [
                    {'subnetwork': 'projects/' + spec.PROJECT + '/'
                     + body['networkInterfaces'][0]['subnetwork']}]
                boot = f.w.raw.disks[rec['names']['boot']]
                boot.update(sizeGb='500', type=f'projects/{spec.PROJECT}/zones/'
                            f'{spec.ZONE}/diskTypes/pd-balanced')
                with patch.object(host.time, 'time', return_value=f.w.clock.now().timestamp() + 1):
                    owner = host.OwnerRegistration(f.w.store, f.w.cloud, f.records, snapshot)
                    owner._OwnerRegistration__controller.cfg.now = f.w.clock.now
                    self.assertEqual(owner.current(), rec)
                    if not oversized:
                        context = owner.register(key(3))
                        registered = f.w.record()
                        self.assertEqual(context.binding, registered['access']['binding'])
                        self.assertEqual(registered['schema'], 2)
                        self.assertEqual(registered['legacy_history'], rec['legacy_history'])
                        self.assertEqual(registered['access_history'], rec['access_history'])
                        self.assertEqual(registered['operation'], rec['operation'])
                        self.assertFalse([c for c in f.gcs.calls if c[0] == 'POST'
                                          and lease(3) in c[1]])
                    else:
                        self.fill_common(rec)
                        rec['access_history'][0]['padding'] += 'x'
                        prefix_digest(rec)
                        generation = self.write(f, rec)
                        calls = len(f.w.raw.calls)
                        with self.assertRaisesRegex(host.Refused, 'reserved failed proof'):
                            owner.register(key(3))
                        self.assertEqual(len(f.w.raw.calls), calls)
                        self.assertEqual(f.w.store.read(f.w.cfg.key), (rec, generation))
                        self.assertNotIn('access', rec)


if __name__ == '__main__':
    unittest.main()
