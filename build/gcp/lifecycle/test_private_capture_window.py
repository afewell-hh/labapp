"""Owner-private capture window regressions (#533). AUTHORED UNRUN.

Offline fakes only. These are source-authored tests, not execution evidence; the
lead runs them in isolation. The window is bounded stop/imaging time for an
owner-private caller, NOT a managed capture gate, seal or lease renewal.
"""
import copy
import unittest
from datetime import timedelta
from unittest.mock import patch

from . import inline_history as inline, spec
from .access_records import GcsAccessRecords
from .access_recovery import OWNER_SELF
from .controller import Controller, Refused
from .test_access import BUCKET, GCS, key
from .test_access_recovery import FIELDS, world
from .test_lifecycle import U1

SOURCE = 'a' * 40
RECEIPT_SHA = 'b' * 64


def receipt(lease=U1, **over):
    value = {'schema': 1, 'code': 0, 'contained': True, 'process_absent': True,
             'phase': 'guest-result', 'failure_category': 'none',
             'host_operation': 'result-validate', 'own_key_absent': True,
             'local_files_absent': True, 'independent_cleanup_dispatched': False,
             'lease': lease, 'guest_diagnostic_status': 'valid',
             'guest_diagnostic': {'origin': 'worker', 'phase': 'persistence',
                                  'operation': 'complete', 'category': 'none',
                                  'child_status': None},
             'guest_service': None, 'private_diagnostic': 'skipped',
             'success_handoff': 'ready', 'image_preparation': 'partial-owned'}
    value.update(over)
    return value


@patch('build.gcp.lifecycle.test_access.SELF', OWNER_SELF)
class Window(unittest.TestCase):
    def setUp(self):
        self.w = world()
        self.w.started()
        self.gcs = GCS(self.w)
        records = GcsAccessRecords(BUCKET, token_provider=lambda: 'fake', transport=self.gcs)
        self.w.ctl = Controller(self.w.store, self.w.cloud, self.w.cfg, access_records=records)
        rec = self.w.record()
        self.w.ctl.register_access(U1, producer_run_id=1, producer_attempt=1,
                                   self_user=OWNER_SELF, public_key_text=key(),
                                   expected_trial={k: rec[k] for k in FIELDS})

    def arm(self, **over):
        rec = self.w.record()
        kw = dict(receipt=receipt(), source_sha=SOURCE, receipt_sha256=RECEIPT_SHA,
                  vm_id=rec['ids']['instance'], boot_id=rec['ids']['boot'],
                  expected_trial={k: rec[k] for k in FIELDS})
        kw.update(over)
        return self.w.ctl.arm_private_capture_window(U1, **kw)

    def stop(self):
        self.w.raw.instances[spec.names(1, 1, spec.UBUNTU_VLAB_CORE)['instance']]['status'] = 'TERMINATED'

    def test_default_stopped_vm_is_still_due(self):
        self.stop()
        self.assertNotEqual(self.w.ctl.reconcile().status, 'not-due')

    def test_valid_window_defers_only_nonforced_janitor(self):
        before = self.w.record()
        window = self.arm()
        after = self.w.record()
        self.assertEqual({k: v for k, v in after.items() if k != 'private_capture_window'}, before)
        for name in ('deadline', 'reserved_at', 'body_hash', 'profile', 'request_id'):
            self.assertEqual(after[name], before[name])
        self.stop()
        self.assertEqual(self.w.ctl.reconcile().status, 'not-due')
        self.assertEqual(self.w.deletes(), [])
        self.assertEqual(window, after['private_capture_window'])
        self.assertEqual(self.w.ctl.reconcile(U1).status == 'not-due', False)

    def test_window_ten_minutes_and_clipped_before_cleanup_reserve(self):
        window = self.arm()
        self.assertEqual(inline._timestamp(window['ends_at'], 'e') -
                         inline._timestamp(window['armed_at'], 'a'), timedelta(minutes=10))

    def test_clipping_and_no_room(self):
        self.w.clock.advance(120 - 15 - 5)  # five minutes of room
        window = self.arm()
        rec = self.w.record()
        self.assertEqual(inline._timestamp(window['ends_at'], 'e'),
                         inline._timestamp(rec['deadline'], 'd') - timedelta(minutes=15))

    def test_inadequate_room_refused(self):
        self.w.clock.advance(120 - 15 - 1)
        with self.assertRaises(Refused):
            self.arm()
        self.assertNotIn('private_capture_window', self.w.record())

    def test_expiry_and_original_deadline_restore_cleanup(self):
        self.arm()
        self.stop()
        self.w.clock.advance(10)
        self.assertNotEqual(self.w.ctl.reconcile().status, 'not-due')

    def test_force_cancel_and_cleanup_failed_keep_priority(self):
        self.arm()
        self.stop()
        self.assertNotEqual(self.w.ctl.reconcile(U1).status, 'not-due')
        rec = self.w.record()
        if rec and rec['state'] != 'FREE':
            self.assertEqual(rec['state'], 'CLEANUP_FAILED')
            self.assertEqual(self.w.ctl.reconcile().status == 'not-due', False)

    def test_original_deadline_wins(self):
        self.arm()
        self.stop()
        self.w.clock.advance(121)
        self.assertNotEqual(self.w.ctl.reconcile().status, 'not-due')

    def test_invalid_or_foreign_window_never_suppresses(self):
        self.arm()
        self.stop()
        rec, gen = self.w.store.read(self.w.cfg.key)
        for field, value in (('vm_id', '999'), ('lease', U1[:-1] + '2'), ('epoch', 99),
                             ('source_sha', 'bad'), ('ends_at', 'tomorrow')):
            bad = copy.deepcopy(rec)
            bad['private_capture_window'][field] = value
            self.assertFalse(self.w.ctl._window_open(bad, {'id': rec['ids']['instance'],
                                                           'name': rec['names']['instance']}), field)
        bad = copy.deepcopy(rec)
        bad['private_capture_window']['extra'] = 1
        self.assertFalse(self.w.ctl._window_open(bad, {'id': rec['ids']['instance'],
                                                       'name': rec['names']['instance']}))
        # A different instance identity is not covered by this window.
        self.assertFalse(self.w.ctl._window_open(rec, {'id': '1', 'name': rec['names']['instance']}))

    def test_exact_closed_receipt_and_nonbools(self):
        cases = [receipt(code=False), receipt(code=1), receipt(code=0.0),
                 receipt(contained=1), receipt(process_absent=1), receipt(local_files_absent=None),
                 receipt(own_key_absent='true'), receipt(independent_cleanup_dispatched=0),
                 receipt(schema=True), receipt(schema=2), receipt(phase='preflight'),
                 receipt(failure_category='guest'), receipt(guest_diagnostic_status='pending'),
                 receipt(guest_diagnostic={'origin': 'worker'}), receipt(success_handoff='refused'),
                 receipt(image_preparation='refused'), receipt(private_diagnostic='captured'),
                 receipt(lease=U1[:-1] + '2'), receipt(extra=1), receipt(guest_service={'x': 1})]
        missing = receipt()
        del missing['image_preparation']
        cases.append(missing)
        cases.append('not a dict')
        for bad in cases:
            with self.assertRaises(Refused, msg=bad):
                self.arm(receipt=bad)
        self.assertNotIn('private_capture_window', self.w.record())

    def test_foreign_ids_source_digest_snapshot(self):
        rec = self.w.record()
        snap = {k: rec[k] for k in FIELDS}
        for kw in (dict(vm_id='1'), dict(boot_id='1'), dict(source_sha='A' * 40),
                   dict(source_sha='a' * 39), dict(receipt_sha256='b' * 63),
                   dict(expected_trial=dict(snap, epoch=snap['epoch'] + 1))):
            with self.assertRaises(Refused, msg=kw):
                self.arm(**kw)
        self.assertNotIn('private_capture_window', self.w.record())

    def test_one_time_immutability_and_cas_loss(self):
        self.arm()
        with self.assertRaises(Refused):
            self.arm()
        rec, gen = self.w.store.read(self.w.cfg.key)
        for mutate in (lambda r: r['private_capture_window'].update(ends_at=r['deadline']),
                       lambda r: r.pop('private_capture_window')):
            new = copy.deepcopy(rec)
            mutate(new)
            with self.assertRaises(AssertionError):
                self.w.ctl._cas(rec, new, gen)

    def test_cas_loss_never_claims_armed(self):
        def rival(_key, _record):
            rec, gen = self.w.store.read(self.w.cfg.key)
            other = copy.deepcopy(rec)
            other['reason'] = 'rival'
            self.w.store.write(self.w.cfg.key, other, if_generation_match=gen)
        self.w.store.before_write = rival
        with self.assertRaises(Refused):
            self.arm()
        self.assertNotIn('private_capture_window', self.w.record())

    def test_refuses_after_cleanup_failed_or_wrong_state(self):
        rec, gen = self.w.store.read(self.w.cfg.key)
        failed = copy.deepcopy(rec)
        failed.update(state='CLEANUP_FAILED', reason='x')
        self.w.store.write(self.w.cfg.key, failed, if_generation_match=gen)
        with self.assertRaises(Refused):
            self.arm()

    def test_schema2_validation_size_depth_and_free(self):
        self.arm()
        rec = self.w.record()
        inline.validate(rec, reserve=True)
        inline.cleanup_budget(rec)
        self.assertEqual(rec['schema'], 2)
        self.assertNotIn('capture', rec)  # supported capture inventory stays forbidden
        bad = copy.deepcopy(rec)
        bad['private_capture_window']['armed_at'] = '2000-01-01T00:00:00Z'
        with self.assertRaises(inline.HistoryError):
            inline.validate(bad)
        bad = copy.deepcopy(rec)
        bad['unknown'] = 1
        with self.assertRaises(inline.HistoryError):
            inline.validate(bad)
        # Window disappears only through normal exact cleanup to FREE.
        self.w.clock.advance(121)
        self.stop()
        history = rec['access_history']
        self.w.ctl.reconcile()
        free = self.w.record()
        if free['state'] == 'FREE':
            self.assertNotIn('private_capture_window', free)
            self.assertEqual(free['access_history'][:len(history)], history)


if __name__ == '__main__':
    unittest.main()
