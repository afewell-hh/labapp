"""Owner-private capture window regressions (#533). AUTHORED UNRUN.

Offline fakes only; source-authored tests, not execution evidence. The lead runs
them in isolation with the lifecycle suite
(``-s build/gcp/lifecycle -t build/gcp``; modules import as ``lifecycle.*``).
Positive cases start from the genuine FREE schema-1 ``Flows`` fixture (a complete
fake access lifecycle), take the pure migration plus the fixture-only CAS to
schema 2, then run the current canonical admit/confirm/register access path.
The window is bounded stop/imaging time only, NOT a managed capture gate, seal or
lease renewal.
"""
import copy
import unittest
from datetime import timedelta
from unittest.mock import patch

from . import inline_history as inline, spec, test_access
from .access_records import canonical
from .access_recovery import OWNER_SELF
from .controller import Refused
from .gcs import MAX_RECORD_BYTES
from .oslogin import cleanup_own_key
from .test_access_recovery import FIELDS
from .test_inline_history import Flows, lease

SOURCE = 'a' * 40
RECEIPT_SHA = 'b' * 64
U = lease(2)
SERVICE = {'active_state': 'inactive', 'result': 'success', 'exec_code': 1, 'exec_status': 0}


def receipt(**over):
    value = {'schema': 1, 'code': 0, 'contained': True, 'process_absent': True,
             'phase': 'guest-result', 'failure_category': 'none',
             'host_operation': 'result-validate', 'own_key_absent': True,
             'local_files_absent': True, 'independent_cleanup_dispatched': False,
             'lease': U, 'guest_diagnostic_status': 'valid',
             'guest_diagnostic': {'origin': 'worker', 'phase': 'persistence',
                                  'operation': 'complete', 'category': 'none',
                                  'child_status': None},
             'guest_service': None, 'private_diagnostic': 'skipped',
             'success_handoff': 'ready', 'image_preparation': 'partial-owned'}
    value.update(over)
    return value


class Base(unittest.TestCase):
    """ACTIVE schema-2 canonical 120 minute lease with registered access."""
    def setUp(self):
        patcher = patch.object(test_access, 'SELF', OWNER_SELF)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.f = Flows()
        self.f.trial(1)                      # genuine FREE schema-1 fixture + history
        self.f.migrate_in_fixture()          # pure plan + fixture-only CAS to schema 2
        self.f.begin(2)                      # current admit/confirm/register access
        self.w = self.f.w
        self.old_history = copy.deepcopy(self.w.record()['access_history'])
        rec = self.w.record()
        self.assertEqual((rec['schema'], rec['state'], rec['access']['phase']),
                         (2, 'ACTIVE', 'registered'))
        self.assertEqual(len(self.old_history), 1)

    def read(self):
        return self.w.store.read(self.w.cfg.key)

    def arm(self, **over):
        rec = self.w.record()
        kw = dict(receipt=receipt(), source_sha=SOURCE, receipt_sha256=RECEIPT_SHA,
                  vm_id=rec['ids']['instance'], boot_id=rec['ids']['boot'],
                  expected_trial={k: rec[k] for k in FIELDS})
        kw.update(over)
        return self.w.ctl.arm_private_capture_window(U, **kw)

    def stop(self):
        self.w.raw.instances[self.w.record()['names']['instance']]['status'] = 'TERMINATED'

    def owner_done(self):
        """The owner's genuine fake import and own-key removal receipts."""
        self.f.session.import_once()
        cleanup_own_key(self.f.records, self.f.context, self.f.login, now=self.w.clock.now)

    def instance(self):
        return self.w.ctl._get('instances', self.w.record()['names']['instance'])

    def assert_refused_unchanged(self, **kw):
        before, deletes = self.read(), len(self.w.deletes())
        with self.assertRaises(Refused):
            self.arm(**kw)
        self.assertEqual(self.read(), before)
        self.assertEqual(len(self.w.deletes()), deletes)

    def assert_released(self):
        rec = self.w.record()
        self.assertEqual(rec['state'], 'FREE')
        self.assertNotIn('private_capture_window', rec)
        self.assertEqual((self.w.raw.instances, self.w.raw.disks), ({}, {}))
        self.assertTrue(self.w.deletes())
        count = len(self.old_history)
        self.assertEqual(rec['access_history'][:count], self.old_history)
        self.assertEqual(len(rec['access_history']), count + 1)
        self.assertEqual(rec['access_history'][-1]['binding']['lease'], U)


class Window(Base):
    def test_default_no_window_stopped_vm_is_due_and_released(self):
        self.stop()
        self.owner_done()
        self.assertEqual(self.w.ctl.reconcile().status, 'released')
        self.assert_released()

    def test_schema1_stays_refused(self):
        legacy = Flows()
        legacy.begin(1)
        rec = legacy.w.record()
        self.assertEqual(rec['schema'], 1)
        before = legacy.w.store.read(legacy.w.cfg.key)
        with self.assertRaises(Refused):
            legacy.w.ctl.arm_private_capture_window(
                lease(1), receipt=receipt(lease=lease(1)), source_sha=SOURCE,
                receipt_sha256=RECEIPT_SHA, vm_id=rec['ids']['instance'],
                boot_id=rec['ids']['boot'], expected_trial={k: rec[k] for k in FIELDS})
        self.assertEqual(legacy.w.store.read(legacy.w.cfg.key), before)

    def test_valid_window_single_cas_defers_only_nonforced_janitor(self):
        before, gen = self.read()
        earlier_deletes = list(self.w.deletes())
        with patch.object(self.w.store, 'write', wraps=self.w.store.write) as write:
            window = self.arm()
        self.assertEqual(write.call_count, 1)
        after, new_gen = self.read()
        self.assertNotEqual(new_gen, gen)           # the one CAS advances storage generation
        self.assertEqual({k: v for k, v in after.items() if k != 'private_capture_window'}, before)
        self.assertEqual(window, after['private_capture_window'])
        for name in ('deadline', 'reserved_at', 'body_hash', 'profile', 'request_id', 'epoch',
                     'ids', 'names', 'operation'):
            self.assertEqual(after[name], before[name])
        self.stop()
        self.assertEqual(self.w.ctl.reconcile().status, 'not-due')
        self.assertEqual(self.w.deletes(), earlier_deletes)
        self.assertEqual(self.read(), (after, new_gen))

    def test_ten_minutes_and_clipped_before_cleanup_reserve(self):
        window = self.arm()
        self.assertEqual(inline._timestamp(window['ends_at'], 'e') -
                         inline._timestamp(window['armed_at'], 'a'), timedelta(minutes=10))

    def test_clipped_window(self):
        self.w.clock.advance(120 - 15 - 5)
        window = self.arm()
        rec = self.w.record()
        self.assertEqual(inline._timestamp(window['ends_at'], 'e'),
                         inline._timestamp(rec['deadline'], 'd') - timedelta(minutes=15))

    def test_inadequate_room_refused_unchanged(self):
        self.w.clock.advance(120 - 15 - 1)
        self.assert_refused_unchanged()

    def test_window_open_bounds_before_arm_exact_arm_expiry_rollback(self):
        window = self.arm()
        rec = self.w.record()
        ctl = self.w.ctl
        self.assertTrue(ctl._window_open(rec, self.instance()))            # exact arm
        self.w.clock.advance(9.5)
        self.assertTrue(ctl._window_open(rec, self.instance()))            # inside
        self.w.clock.advance(0.5)                                          # exact expiry
        self.assertEqual(self.w.clock.now().strftime('%Y-%m-%dT%H:%M:%SZ'), window['ends_at'])
        self.assertFalse(ctl._window_open(rec, self.instance()))
        self.w.clock.advance(-10.5)                                        # rollback before arm
        self.assertFalse(ctl._window_open(rec, self.instance()))
        self.stop()
        self.assertTrue(ctl._is_due(rec, False))                           # cleanup not suppressed

    def test_expiry_restores_cleanup_to_free_with_history(self):
        self.arm()
        self.stop()
        self.assertEqual(self.w.ctl.reconcile().status, 'not-due')
        self.owner_done()
        self.w.clock.advance(10)                                           # exact expiry
        self.assertEqual(self.w.ctl.reconcile().status, 'released')
        self.assert_released()

    def test_force_cancel_inside_window_deletes_and_releases(self):
        self.arm()
        self.stop()
        self.owner_done()
        self.assertEqual(self.w.ctl.reconcile(U).status, 'released')       # still inside window
        self.assert_released()

    def test_original_deadline_wins_over_window(self):
        self.arm()
        self.stop()
        self.owner_done()
        self.w.clock.advance(120)
        self.assertEqual(self.w.ctl.reconcile().status, 'released')
        self.assert_released()

    def test_cleanup_failed_retains_window(self):
        window = self.arm()
        self.stop()
        # Forced cleanup before the owner's removal receipt blocks at access finalizing.
        self.assertEqual(self.w.ctl.reconcile(U).status, 'blocked')
        rec = self.w.record()
        self.assertEqual(rec['state'], 'CLEANUP_FAILED')
        self.assertEqual(rec['private_capture_window'], window)
        inline.validate(rec)
        self.assertFalse(self.w.ctl._window_open(rec, {'id': rec['ids']['instance'],
                                                       'name': rec['names']['instance']}))
        self.assertTrue(self.w.ctl._is_due(rec, False))

    def test_invalid_or_foreign_window_never_suppresses(self):
        self.arm()
        rec = self.w.record()
        inst = {'id': rec['ids']['instance'], 'name': rec['names']['instance']}
        self.assertTrue(self.w.ctl._window_open(rec, inst))
        for field, value in (('vm_id', '999'), ('boot_id', '999'), ('lease', lease(3)),
                             ('epoch', 99), ('run_id', 99), ('attempt', 9),
                             ('source_sha', 'bad'), ('receipt_sha256', 'bad'),
                             ('armed_at', 'yesterday'), ('ends_at', 'tomorrow')):
            bad = copy.deepcopy(rec)
            bad['private_capture_window'][field] = value
            self.assertFalse(self.w.ctl._window_open(bad, inst), field)
        for mutate in (lambda r: r['private_capture_window'].update(extra=1),
                       lambda r: r.update(state='CLEANUP_FAILED'),
                       lambda r: r.update(schema=1), lambda r: r.update(capture={}),
                       lambda r: r.update(profile='other'),
                       lambda r: r['private_capture_window'].update(ends_at=r['deadline'])):
            bad = copy.deepcopy(rec)
            mutate(bad)
            self.assertFalse(self.w.ctl._window_open(bad, inst))
        self.assertFalse(self.w.ctl._window_open(rec, dict(inst, id='1')))
        self.assertFalse(self.w.ctl._window_open(rec, dict(inst, name='other')))

    def test_exact_closed_receipt_and_nonbools(self):
        missing = receipt()
        del missing['image_preparation']
        cases = [receipt(code=False), receipt(code=1), receipt(code=0.0),
                 receipt(contained=1), receipt(process_absent=1), receipt(local_files_absent=None),
                 receipt(own_key_absent='true'), receipt(independent_cleanup_dispatched=0),
                 receipt(schema=True), receipt(schema=2), receipt(phase='preflight'),
                 receipt(failure_category='guest'), receipt(guest_diagnostic_status='pending'),
                 receipt(guest_diagnostic={'origin': 'worker'}), receipt(success_handoff='refused'),
                 receipt(image_preparation='refused'), receipt(private_diagnostic='captured'),
                 receipt(lease=lease(3)), receipt(extra=1), missing, 'not a dict',
                 receipt(host_operation='other'), receipt(host_operation=''),
                 receipt(host_operation=None), receipt(host_operation='result-validate '),
                 receipt(guest_service={'x': 1}),
                 receipt(guest_service=dict(SERVICE, active_state='bogus')),
                 receipt(guest_service=dict(SERVICE, active_state=None)),
                 receipt(guest_service=dict(SERVICE, result='bogus')),
                 receipt(guest_service=dict(SERVICE, exec_code=True)),
                 receipt(guest_service=dict(SERVICE, exec_status=False)),
                 receipt(guest_service=dict(SERVICE, exec_code=8)),
                 receipt(guest_service=dict(SERVICE, exec_code=-1)),
                 receipt(guest_service=dict(SERVICE, exec_status=256)),
                 receipt(guest_service=dict(SERVICE, exec_status='0')),
                 receipt(guest_service=dict(SERVICE, extra=1)),
                 receipt(guest_service={k: v for k, v in SERVICE.items() if k != 'result'})]
        for bad in cases:
            self.assert_refused_unchanged(receipt=bad)

    def test_diagnostic_guest_service_values_are_accepted(self):
        # Observation is diagnostic: closed domains only, no inactive/success gate.
        self.arm(receipt=receipt(guest_service=dict(
            active_state='failed', result='exit-code', exec_code=1, exec_status=255)))
        self.assertIn('private_capture_window', self.w.record())

    def test_foreign_ids_digests_snapshot(self):
        rec = self.w.record()
        snap = {k: rec[k] for k in FIELDS}
        for kw in (dict(vm_id='1'), dict(boot_id='1'), dict(source_sha='A' * 40),
                   dict(source_sha='a' * 39), dict(source_sha=None), dict(receipt_sha256='b' * 63),
                   dict(receipt_sha256='B' * 64),
                   dict(expected_trial=dict(snap, epoch=snap['epoch'] + 1))):
            self.assert_refused_unchanged(**kw)

    def test_one_time_immutability_and_no_mutation_before_free(self):
        self.arm()
        self.assert_refused_unchanged()          # re-arm refused
        rec, gen = self.read()
        window = rec['private_capture_window']
        shorter = (inline._timestamp(window['ends_at'], 'e') - timedelta(minutes=1))
        controls = (
            (AssertionError, lambda r: r.pop('private_capture_window')),
            (AssertionError, lambda r: r['private_capture_window'].update(
                ends_at=spec.rfc3339(shorter))),                            # alter/renew
            (AssertionError, lambda r: r['private_capture_window'].update(source_sha='c' * 40)),
            (Refused, lambda r: r['private_capture_window'].update(ends_at=r['deadline'])))
        for error, mutate in controls:
            new = copy.deepcopy(rec)
            mutate(new)
            with self.assertRaises(error):
                self.w.ctl._cas(rec, new, gen)
            self.assertEqual(self.read(), (rec, gen))

    def test_lost_cas_never_claims_armed(self):
        rec, gen = self.read()
        real = self.w.store.write
        state = {'rival': False}

        def write(key, record, **kw):
            if not state['rival']:
                state['rival'] = True
                real(key, rec, if_generation_match=gen)   # rival bumps the generation
            return real(key, record, **kw)
        with patch.object(self.w.store, 'write', side_effect=write):
            with self.assertRaises(Refused):
                self.arm()
        after, new_gen = self.read()
        self.assertNotEqual(new_gen, gen)
        self.assertEqual(after, rec)
        self.assertNotIn('private_capture_window', after)
        self.stop()
        self.assertNotEqual(self.w.ctl.reconcile().status, 'not-due')    # no window suppresses

    def test_refuses_cleanup_failed_state(self):
        self.stop()
        self.assertEqual(self.w.ctl.reconcile(U).status, 'blocked')
        self.assertEqual(self.w.record()['state'], 'CLEANUP_FAILED')
        self.assert_refused_unchanged()

    def test_size_and_headroom_with_the_optional_field(self):
        self.arm()
        rec = self.w.record()
        inline.validate(rec, reserve=True)
        inline.cleanup_budget(rec)
        self.assertLessEqual(len(canonical(rec)), MAX_RECORD_BYTES)
        live = {k: v for k, v in rec.items() if k not in inline.COMMON2 and k != 'evidence'}
        bare = {k: v for k, v in live.items() if k != 'private_capture_window'}
        self.assertGreater(len(canonical(live)), len(canonical(bare)))
        # Exactly enough room for the record without the field refuses once it is present.
        without = {k: v for k, v in rec.items() if k != 'private_capture_window'}
        with patch.object(inline, 'LIVE_BYTES', len(canonical(bare))):
            inline.validate(without)
            with self.assertRaises(inline.HistoryError):
                inline.validate(rec)

    def test_arm_refused_without_headroom_for_the_field(self):
        rec = self.w.record()
        live = {k: v for k, v in rec.items() if k not in inline.COMMON2 and k != 'evidence'}
        before = self.read()
        with patch.object(inline, 'LIVE_BYTES', len(canonical(live))):
            with self.assertRaises((Refused, inline.HistoryError)):
                self.arm()
        self.assertEqual(self.read(), before)

    def test_depth_with_the_optional_field(self):
        self.arm()
        rec = self.w.record()
        inline._depth(rec, inline.MAX_DEPTH)
        with patch.object(inline, 'MAX_DEPTH', 1):
            with self.assertRaises(inline.HistoryError):
                inline.validate(rec)

    def test_unknown_field_capture_inventory_and_stale_window_are_invalid(self):
        self.arm()
        rec = self.w.record()
        inline.validate(rec)
        for mutate in (lambda r: r.update(unknown=1), lambda r: r.update(capture={}),
                       lambda r: r['private_capture_window'].update(
                           armed_at='2000-01-01T00:00:00Z')):
            bad = copy.deepcopy(rec)
            mutate(bad)
            with self.assertRaises(inline.HistoryError):
                inline.validate(bad)


if __name__ == '__main__':
    unittest.main()
