"""Offline tests for the single-slot lease controller (no cloud, no network).

Run from the repository root:
    python3 -m unittest discover -s build/gcp/lifecycle -t build/gcp -v
"""
from __future__ import annotations

import copy
import threading
import unittest
from datetime import timedelta

from . import spec
from .cloud import ALLOWED, ForbiddenOperation, PolicyCloud
from .controller import (ACTIVE, CLEANUP_FAILED, FREE, RESERVED, Config,
                         Controller, Refused)
from .fakes import FakeClock, FakeCloud
from .store import MemoryStore

BOOT_IMAGE = "projects/ubuntu-os-cloud/global/images/ubuntu-2404-test-pinned"
U0 = "00000000-0000-4000-8000-000000000000"
U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"


class World:
    def __init__(self, **cfg_kw):
        self.clock = FakeClock()
        self.store = MemoryStore()
        self.raw = FakeCloud(self.clock)
        self.cloud = PolicyCloud(self.raw, spec.PROJECT, spec.ZONE)
        self.cfg = Config(boot_image=BOOT_IMAGE, now=self.clock.now,
                          sleep=self.clock.sleep, **cfg_kw)
        self.ctl = Controller(self.store, self.cloud, self.cfg)

    def record(self):
        return self.store.read(self.cfg.key)[0]

    def started(self, run=1, uuid=U1):
        """Admit, submit and confirm: an ACTIVE lease with IDs recorded."""
        self.ctl.admit(run, 1, uuid)
        out = self.ctl.submit(uuid)
        assert out.status == "accepted", out
        out = self.ctl.confirm_created(uuid)
        assert out.status == "created", out
        return self.record()

    def deletes(self):
        return [c for c in self.raw.calls if c[1] == "delete"]


class T(unittest.TestCase):
    # ------------------------------------------------------------ admission
    def test_competing_claims_one_winner(self):
        w = World()
        w.ctl.admit(0, 9, U0)  # creates the persistent slot
        w.ctl.reconcile(U0)    # back to FREE
        results = []

        def competitor(_key, _rec):
            # The rival finishes its entire admission before our write lands.
            results.append(w.ctl.admit(2, 1, U2)["run_id"])

        w.store.before_write = competitor
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)
        self.assertEqual(results, [2])
        self.assertEqual(w.record()["run_id"], 2)

    def test_competing_claims_threads(self):
        w = World()
        w.ctl.admit(0, 1, U0)
        w.ctl.reconcile(U0)
        barrier, wins, losses = threading.Barrier(4), [], []

        def go(n):
            barrier.wait()
            try:
                w.ctl.admit(n, 1, f"{n:08d}-0000-4000-8000-000000000000")
                wins.append(n)
            except Refused:
                losses.append(n)

        threads = [threading.Thread(target=go, args=(n,)) for n in range(1, 5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(losses), 3)

    def test_released_slot_is_reusable(self):
        w = World()
        w.started(run=1, uuid=U1)
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual(w.record()["state"], FREE)
        self.assertEqual(w.raw.instances, {})
        self.assertEqual(w.raw.disks, {})
        w.ctl.admit(2, 1, U2)  # a generation-zero-only claim would deadlock
        self.assertEqual(w.record()["epoch"], 2)

    def test_fixed_short_pilot_lease_keeps_submission_margin(self):
        w = World(lease_minutes=5, min_submit_minutes=1)
        rec = w.started()
        self.assertEqual(rec["deadline"],
                         spec.rfc3339(w.clock.now() + timedelta(minutes=5)))

    def test_lease_bound_and_margin_reject_invalid_configuration(self):
        for duration in (0, -1, 61, True, "5", 5.5):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                World(lease_minutes=duration, min_submit_minutes=0)
        with self.assertRaises(ValueError):
            World(lease_minutes=5)

    def test_modified_lease_bound_is_checked_before_admission(self):
        w = World()
        w.cfg.lease_minutes = 61
        with self.assertRaises(ValueError):
            w.ctl.admit(1, 1, U1)
        self.assertEqual(w.store.writes, [])

    def test_occupied_slot_refuses_every_state(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        for state in (RESERVED, ACTIVE, CLEANUP_FAILED):
            rec, gen = w.store.read(w.cfg.key)
            rec["state"] = state
            w.store.write(w.cfg.key, rec, if_generation_match=gen)
            with self.assertRaises(Refused):
                w.ctl.admit(2, 1, U2)

    def test_unknown_ownership_blocks_admission(self):
        w = World()
        w.raw.add_foreign("instances", "mystery-vm")
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)
        self.assertEqual(w.record()["state"], FREE)
        self.assertEqual(w.deletes(), [])

    def test_unknown_disk_and_prefix_lookalike_block_admission(self):
        for kind, name in (("disks", "orphan-disk"),
                           ("instances", "labapp-lc-s1-r7-a1")):
            w = World()
            w.raw.add_foreign(kind, name)
            with self.assertRaises(Refused):
                w.ctl.admit(1, 1, U1)

    def test_baseline_requires_matching_immutable_id(self):
        w = World()
        pid = w.raw.add_foreign("instances", "protected-prod")
        w.cfg.baseline["protected-prod"] = pid
        w.ctl.admit(1, 1, U1)  # known, protected: allowed to coexist
        w2 = World()
        w2.raw.add_foreign("instances", "protected-prod")
        w2.cfg.baseline["protected-prod"] = "wrong-id"
        with self.assertRaises(Refused):
            w2.ctl.admit(1, 1, U1)

    def test_foreign_pending_operation_blocks_admission(self):
        w = World()
        w.raw._op("insert", "other", status="RUNNING")
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)

    # ------------------------------------------------------- create handling
    def test_intent_is_persisted_before_any_cloud_call(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        rec = w.record()
        self.assertFalse([c for c in w.raw.calls if c[1] == "insert"])
        self.assertEqual(rec["request_id"], U1)
        self.assertEqual(rec["state"], RESERVED)
        body = spec.build_body(boot_image=BOOT_IMAGE, request_id=U1, run_id=1,
                               attempt=1,
                               deadline=w.clock.now() + timedelta(minutes=60))
        self.assertEqual(rec["body_hash"], spec.body_hash(body))
        self.assertEqual(rec["names"], spec.names(1, 1))

    def test_uncertain_create_with_late_vm_is_never_released_early(self):
        w = World()
        w.raw.insert_mode = "timeout_pending"
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.ctl.submit(U1).status, "uncertain")
        with self.assertRaises(Refused):  # same UUID, no second attempt
            w.ctl.submit(U1)
        self.assertEqual(w.record()["request_id"], U1)
        # Operation still running and no VM yet (404): the slot stays held.
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        self.assertNotEqual(w.record()["state"], FREE)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)
        # The VM lands late; cleanup deletes it and both disks, then releases.
        w.raw.finish_pending(success=True)
        terminal_insert = next(op for op in w.raw.ops.values() if op.get("clientOperationId") == U1)
        self.assertEqual(terminal_insert["targetId"], w.raw.instances[spec.names(1, 1)["instance"]]["id"])
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_pending_operation_then_404_is_not_failed_create_proof(self):
        w = World()
        w.raw.insert_mode = "timeout_pending"
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        self.assertNotIn(spec.names(1, 1)["instance"], w.raw.instances)
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        w.raw.finish_pending(success=False)  # operation DONE with error
        self.assertEqual(w.ctl.reconcile(U1).status, "released")

    def test_http_500_or_timeout_without_operation_never_released_by_time(self):
        for mode in ("http500", "timeout_nothing"):
            w = World()
            w.raw.insert_mode = mode
            w.ctl.admit(1, 1, U1)
            self.assertEqual(w.ctl.submit(U1).status, "uncertain")
            self.assertEqual(w.ctl.reconcile(U1).status, "settling")
            self.assertEqual(w.record()["state"], RESERVED)
            w.clock.advance(61)  # deadline alone is not terminal evidence
            self.assertEqual(w.ctl.reconcile().status, "blocked")
            self.assertNotEqual(w.record()["state"], FREE)
            with self.assertRaises(Refused):
                w.ctl.admit(2, 1, U2)

    def test_pending_operation_missing_across_deadline_stays_occupied(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.raw.insert_mode = "timeout_pending"
        w.ctl.submit(U1)
        ops, w.raw.ops = w.raw.ops, {}  # operation aged out / not listed
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "blocked")
        self.assertNotEqual(w.record()["state"], FREE)
        # The create lands late and the operation is visible again: cleanup
        # deletes VM and both disks, then releases on terminal evidence.
        w.raw.ops = ops
        w.raw.finish_pending(success=True)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertEqual(w.record()["state"], FREE)

    def test_pending_operation_across_deadline_stays_pending(self):
        w = World()
        w.raw.insert_mode = "timeout_pending"
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "pending-operation")
        self.assertNotEqual(w.record()["state"], FREE)

    def test_terminal_current_request_failure_releases_without_resources(self):
        w = World()
        w.raw.insert_mode = "timeout_pending"
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        w.raw.finish_pending(success=False)
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_bounded_retry_reuses_same_uuid_and_body(self):
        w = World(max_submit_attempts=2)
        w.raw.insert_mode = "timeout_nothing"
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.ctl.submit(U1).status, "uncertain")
        w.raw.insert_mode = "ok"
        self.assertEqual(w.ctl.submit(U1).status, "accepted")
        self.assertEqual(w.record()["request_id"], U1)
        self.assertEqual(w.record()["submit_attempts"], 2)
        with self.assertRaises(Refused):
            w.ctl.submit(U1)

    def test_tampered_body_hash_refuses_submit(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        rec, gen = w.store.read(w.cfg.key)
        rec["body_hash"] = "0" * 64
        w.store.write(w.cfg.key, rec, if_generation_match=gen)
        with self.assertRaises(Refused):
            w.ctl.submit(U1)
        self.assertFalse([c for c in w.raw.calls if c[1] == "insert"])

    def test_submit_refused_without_time_left_or_for_other_lease(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        with self.assertRaises(Refused):
            w.ctl.submit(U2)
        w.clock.advance(55)
        with self.assertRaises(Refused):
            w.ctl.submit(U1)

    def test_confirm_records_vm_and_both_disk_ids(self):
        w = World()
        rec = w.started()
        self.assertEqual(rec["ids"]["instance"], w.raw.ops[rec["operation"]]["targetId"])
        for kind in ("instance", "boot", "data"):
            self.assertTrue(rec["ids"][kind], kind)
        self.assertEqual(rec["deadline"],
                         spec.rfc3339(w.clock.now() + timedelta(minutes=60)))

    # -------------------------------------------------------------- cleanup
    def test_janitor_does_not_touch_a_healthy_unexpired_lease(self):
        w = World()
        w.started()
        self.assertEqual(w.ctl.reconcile().status, "not-due")
        self.assertEqual(w.deletes(), [])

    def test_stopped_vm_is_cleaned_before_deadline(self):
        w = World()
        w.started()
        w.raw.instances[spec.names(1, 1)["instance"]]["status"] = "TERMINATED"
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_expired_lease_is_cleaned_by_janitor(self):
        w = World()
        w.started()
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "released")

    def test_missing_vm_but_both_disks_remain(self):
        w = World()
        w.started()
        names = spec.names(1, 1)
        del w.raw.instances[names["instance"]]  # VM gone, disks leaked
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual(w.raw.disks, {})
        self.assertEqual({c[2] for c in w.deletes()},
                         {names["boot"], names["data"]})

    def test_leaked_disks_after_vm_delete_are_removed(self):
        w = World()
        w.started()
        w.raw.leak_disks = True  # Packer-like autoDelete=false behavior
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual(w.raw.disks, {})

    def test_normal_vm_delete_retains_readonly_copy_until_explicit_cleanup(self):
        w = World()
        rec = w.started()
        names, ids = rec["names"], rec["ids"]
        original_delete = w.raw._disks_delete
        observed = []

        def delete_data(name, *args):
            # No leak injection: VM delete auto-deleted boot, but not data.
            self.assertEqual(name, names["data"])
            self.assertNotIn(names["instance"], w.raw.instances)
            self.assertNotIn(names["boot"], w.raw.disks)
            self.assertEqual(w.raw.disks[name]["id"], ids["data"])
            self.assertEqual(w.record()["state"], ACTIVE)
            observed.append(name)
            return original_delete(name, *args)

        def before_free(key, record, **kwargs):
            if record["state"] == FREE:
                self.assertEqual(observed, [names["data"]])
                self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
                evidence = record["last_release"]["evidence"]
                self.assertTrue(any(f"data {names['data']} id {ids['data']}: "
                                    "deleted, 404 confirmed" == e for e in evidence))
            return original_write(key, record, **kwargs)

        original_write = w.store.write
        w.store.write = before_free
        w.raw._disks_delete = delete_data
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual(w.deletes(), [("instances", "delete", names["instance"]),
                                       ("disks", "delete", names["data"])])
        self.assertEqual(w.record()["state"], FREE)

    def test_cloud_vm_expiry_leaves_readonly_copy_for_janitor(self):
        w = World()
        rec = w.started()
        names = rec["names"]
        w.clock.advance(61)
        # Model Compute's deadline DELETE using its normal attachment flags.
        w.cloud.call("instances", "delete", name=names["instance"])
        self.assertEqual(set(w.raw.disks), {names["data"]})
        self.assertEqual(w.record()["state"], ACTIVE)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertIn(("disks", "delete", names["data"]), w.deletes())
        self.assertEqual(w.raw.disks, {})

    def test_one_disk_that_will_not_delete_keeps_capacity(self):
        w = World()
        w.started()
        w.raw.delete_noop.add(spec.names(1, 1)["data"])  # DONE but present
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.record()["state"], CLEANUP_FAILED)
        self.assertEqual(w.raw.instances, {})
        self.assertEqual(set(w.raw.disks), {spec.names(1, 1)["data"]})
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)

    def test_readonly_copy_delete_failure_keeps_capacity_until_janitor(self):
        w = World()
        rec = w.started()
        name = rec["names"]["data"]
        w.raw.delete_fail.add(name)
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.raw.instances, {})
        self.assertEqual(set(w.raw.disks), {name})
        self.assertEqual(w.record()["state"], CLEANUP_FAILED)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)
        w.raw.delete_fail.clear()
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual(w.raw.disks, {})

    def test_readonly_copy_pending_delete_operation_prevents_release(self):
        w = World()
        rec = w.started()
        name = rec["names"]["data"]
        original = w.raw._disks_delete

        def pending(name, *args):
            op = original(name, *args)
            w.raw.ops[op["name"]]["status"] = "RUNNING"
            return op

        w.raw._disks_delete = pending
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertNotEqual(w.record()["state"], FREE)
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)
        for op in w.raw.ops.values():
            op["status"] = "DONE"
        self.assertEqual(w.ctl.reconcile(U1).status, "released")

    def test_failed_cleanup_retained_then_janitor_recovers(self):
        w = World()
        w.started()
        w.raw.delete_fail.add(spec.names(1, 1)["instance"])
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.ctl.reconcile().status, "cleanup-failed")
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)
        w.raw.delete_fail.clear()
        self.assertEqual(w.ctl.reconcile().status, "released")  # janitor mode
        w.ctl.admit(2, 1, U2)

    def test_delete_operation_error_keeps_capacity(self):
        w = World()
        w.started()
        w.raw.delete_op_error.add(spec.names(1, 1)["instance"])
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.record()["state"], CLEANUP_FAILED)

    def test_unfinished_delete_operation_keeps_slot_occupied(self):
        w = World()
        w.started()
        original = w.raw._op

        def stuck(*a, **k):
            op = original(*a, **k)
            w.raw.op_stuck.add(op["name"])  # get() reports RUNNING forever
            return op
        w.raw._op = stuck
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        self.assertNotEqual(w.record()["state"], FREE)

    def test_foreign_pending_operation_blocks_release_not_deletion(self):
        w = World()
        w.started()
        w.raw._op("insert", "someone-else", status="RUNNING")
        self.assertEqual(w.ctl.reconcile(U1).status, "blocked")
        self.assertEqual(w.raw.instances, {})  # own resources still removed
        self.assertNotEqual(w.record()["state"], FREE)

    # ----------------------------------------------------- runner death / CAS
    def test_runner_death_after_admit_is_recoverable(self):
        w = World()
        w.ctl.admit(1, 1, U1)  # runner dies here
        self.assertEqual(w.ctl.reconcile().status, "not-due")
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual(w.deletes(), [])

    def test_runner_death_after_create_before_ids_recorded(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)  # dies before confirm_created: no IDs persisted
        self.assertIsNone(w.record()["ids"]["instance"])
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_concurrent_cleanup_loser_sees_released_slot(self):
        w = World()
        w.started()
        janitor = Controller(w.store, w.cloud, w.cfg)
        seen, original = [], w.store.write

        def write(key, record, **kw):
            # Right before the normal cleanup's FREE write, a rival finishes.
            if record["state"] == FREE and not seen:
                seen.append(None)
                seen[0] = janitor.reconcile(U1).status
            return original(key, record, **kw)
        w.store.write = write
        out = w.ctl.reconcile(U1)
        self.assertEqual(seen, ["released"])
        self.assertEqual(out.status, "free")  # lost the CAS, re-read, done
        self.assertEqual(w.record()["state"], FREE)
        self.assertEqual(w.record()["epoch"], 1)  # released exactly once

    def test_stale_cleanup_cannot_touch_a_newer_lease(self):
        w = World()
        w.started(run=1, uuid=U1)
        original, fired = w.store.write, []

        def write(key, record, **kw):
            if record["state"] == FREE and not fired:
                fired.append(1)
                # Another actor releases lease 1, then creates lease 2.
                other = Controller(w.store, w.cloud, w.cfg)
                other.reconcile(U1)
                other.admit(2, 1, U2)
                other.submit(U2)
                other.confirm_created(U2)
            return original(key, record, **kw)
        w.store.write = write
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.status, "superseded")
        rec = w.record()
        self.assertEqual((rec["run_id"], rec["state"]), (2, ACTIVE))
        new = spec.names(2, 1)
        self.assertIn(new["instance"], w.raw.instances)
        self.assertNotIn(new["instance"], {c[2] for c in w.deletes()})

    def test_deadline_and_identity_fields_are_immutable(self):
        w = World()
        w.started()
        before = w.record()["deadline"]
        w.ctl.reconcile()
        self.assertEqual(w.record()["deadline"], before)
        rec, gen = w.store.read(w.cfg.key)
        prev = copy.deepcopy(rec)
        rec["deadline"] = spec.rfc3339(w.clock.now() + timedelta(days=1))
        with self.assertRaises(AssertionError):
            w.ctl._cas(prev, rec, gen)

    # ------------------------------------------------- identity / protection
    def test_label_mismatch_is_not_deleted(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        # An impostor with our exact name but a different lease label.
        w.raw.add_foreign("instances", spec.names(1, 1)["instance"],
                          {spec.LABEL_LEASE: U2})
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.status, "cleanup-failed")
        self.assertTrue(out.detail.startswith("identity-mismatch:instance"))
        self.assertEqual(w.deletes(), [])
        self.assertIn(spec.names(1, 1)["instance"], w.raw.instances)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)

    def test_id_mismatch_after_ids_recorded_is_not_deleted(self):
        w = World()
        w.started()
        w.raw.instances[spec.names(1, 1)["instance"]]["id"] = "999"
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.deletes(), [])

    def _assert_nothing_deleted(self, w):
        """Zero delete calls and every resource still present."""
        self.assertEqual(w.deletes(), [])
        names = spec.names(1, 1)
        self.assertIn(names["instance"], w.raw.instances)
        self.assertIn(names["boot"], w.raw.disks)
        self.assertIn(names["data"], w.raw.disks)
        self.assertEqual(w.record()["state"], CLEANUP_FAILED)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)

    def test_disk_identity_mismatch_blocks_vm_delete_with_autodelete(self):
        # VM delete would remove boot; every child must still verify before it.
        for kind, mutate in (
                ("data-label", lambda w, n: w.raw.disks[n["data"]][
                    "labels"].update({spec.LABEL_LEASE: U2})),
                ("boot-label", lambda w, n: w.raw.disks[n["boot"]][
                    "labels"].update({spec.LABEL_LEASE: U2})),
                ("data-id", lambda w, n: w.raw.disks[n["data"]].update(
                    id="different-incarnation")),
                ("boot-id", lambda w, n: w.raw.disks[n["boot"]].update(
                    id="different-incarnation"))):
            w = World()
            w.started()
            self.assertFalse(w.raw.leak_disks)
            mutate(w, spec.names(1, 1))
            out = w.ctl.reconcile(U1)
            self.assertEqual(out.status, "cleanup-failed", kind)
            self.assertTrue(out.detail.startswith("identity-mismatch:"), kind)
            self._assert_nothing_deleted(w)

    def test_unowned_extra_attachment_blocks_vm_delete(self):
        w = World()
        w.started()
        foreign = "protected-unowned-data"
        w.raw.add_foreign("disks", foreign)
        w.raw.instances[spec.names(1, 1)["instance"]]["disks"].append(
            {"source": f"https://compute/zones/{spec.ZONE}/disks/{foreign}",
             "autoDelete": True, "boot": False, "mode": "READ_ONLY"})
        w.cfg.baseline[foreign] = w.raw.disks[foreign]["id"]
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.detail, "identity-mismatch:instance:attachments")
        self._assert_nothing_deleted(w)
        self.assertIn(foreign, w.raw.disks)

    def test_swapped_or_wrong_mode_attachment_blocks_vm_delete(self):
        foreign = "protected-unowned-data"
        for label, mutate, reason in (
                ("foreign source",
                 lambda att, w: att[1].update(
                     source=f"https://compute/zones/{spec.ZONE}/disks/"
                            f"{foreign}"),
                 "attachment-unexpected"),
                ("writable data", lambda att, w: att[1].update(
                    mode="READ_WRITE"), "attachment-mode"),
                ("data auto-delete", lambda att, w: att[1].update(
                    autoDelete=True), "attachment-autodelete"),
                ("boot retained", lambda att, w: att[0].update(
                    autoDelete=False), "attachment-autodelete"),
                ("data missing auto-delete", lambda att, w: att[1].pop(
                    "autoDelete"), "attachment-autodelete"),
                ("boot flag", lambda att, w: att[1].update(boot=True),
                 "attachment-boot-flag"),
                ("other zone", lambda att, w: att[1].update(
                    source="https://compute/zones/europe-west1-b/disks/"
                           + spec.names(1, 1)["data"]), "attachment-zone"),
                ("duplicate", lambda att, w: att[1].update(
                    source=att[0]["source"]), "attachment-unexpected"),
                ("no inventory", lambda att, w: att.clear(), "attachments")):
            w = World()
            w.started()
            w.raw.add_foreign("disks", foreign)
            inst = w.raw.instances[spec.names(1, 1)["instance"]]
            mutate(inst["disks"], w)
            out = w.ctl.reconcile(U1)
            self.assertEqual(out.detail, f"identity-mismatch:instance:{reason}",
                             label)
            self._assert_nothing_deleted(w)
            self.assertIn(foreign, w.raw.disks, label)

    def test_missing_identity_is_adopted_only_with_operation_proof(self):
        # Runner died before ids were persisted. Matching labels and a fresh
        # timestamp are not proof; the operation record is removed here (as if
        # not retained), so nothing may be deleted.
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        w.raw.ops.clear()
        self.assertIsNone(w.record()["ids"]["instance"])
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.detail,
                         "identity-mismatch:instance:unproven-ownership")
        self.assertEqual(w.deletes(), [])
        self.assertIn(spec.names(1, 1)["instance"], w.raw.instances)

    def test_proof_requires_this_requests_client_operation_id(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        for op in w.raw.ops.values():
            op["clientOperationId"] = U2  # someone else's insert
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.status, "cleanup-failed")
        self.assertEqual(w.deletes(), [])

    def test_confirm_refuses_operation_for_another_request(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        for op in w.raw.ops.values():
            op["clientOperationId"] = U2
        self.assertEqual(w.ctl.confirm_created(U1).status, "operation-mismatch")
        self.assertIsNone(w.record()["ids"]["instance"])

    def test_confirm_rejects_replaced_vm_before_any_ids_recorded(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        operation = w.raw.ops[w.record()["operation"]]
        original_id = operation["targetId"]
        inst = w.raw.instances[spec.names(1, 1)["instance"]]
        self.assertEqual(inst["id"], original_id)
        inst["id"] = w.raw._id()  # same name/labels/timestamp, new incarnation
        self.assertEqual(operation["targetId"], original_id)  # evidence immutable
        out = w.ctl.confirm_created(U1)
        self.assertEqual(out.status, "identity-mismatch")
        self.assertIn("operation-target-id", out.detail)
        self.assertTrue(all(value is None for value in w.record()["ids"].values()))
        self.assertEqual(w.deletes(), [])

    def test_cleanup_rejects_replaced_vm_before_any_ids_recorded(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        inst = w.raw.instances[spec.names(1, 1)["instance"]]
        original_id = w.raw.ops[w.record()["operation"]]["targetId"]
        inst["id"] = w.raw._id()
        self.assertNotEqual(inst["id"], original_id)
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.status, "cleanup-failed")
        self.assertIn("operation-target-id", out.detail)
        self.assertTrue(all(value is None for value in w.record()["ids"].values()))
        self.assertEqual(w.deletes(), [])
        self.assertNotEqual(w.record()["state"], FREE)

    def test_missing_insert_target_id_never_authorizes_adoption_or_deletion(self):
        for action in ("confirm_created", "reconcile"):
            for missing in (None, ""):
                w = World()
                w.ctl.admit(1, 1, U1)
                w.ctl.submit(U1)
                operation = w.raw.ops[w.record()["operation"]]
                if missing is None:
                    del operation["targetId"]
                else:
                    operation["targetId"] = missing
                out = getattr(w.ctl, action)(U1)
                self.assertIn(out.status, ("operation-mismatch", "cleanup-failed"))
                self.assertTrue(all(value is None for value in w.record()["ids"].values()))
                self.assertEqual(w.deletes(), [])
                self.assertNotEqual(w.record()["state"], FREE)

    def test_conflicting_current_request_target_ids_block_cleanup(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        other = w.raw._op("insert", spec.names(1, 1)["instance"], client_id=U1)
        other["targetId"] = w.raw._id()
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.status, "cleanup-failed")
        self.assertIn("conflicting-insert-target-ids", out.detail)
        self.assertEqual(w.deletes(), [])
        self.assertTrue(all(value is None for value in w.record()["ids"].values()))

    def test_confirm_refuses_unowned_attachment_and_records_nothing(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        w.raw.instances[spec.names(1, 1)["instance"]]["disks"].append(
            {"source": "x/disks/other", "autoDelete": True})
        self.assertEqual(w.ctl.confirm_created(U1).status, "identity-mismatch")
        self.assertIsNone(w.record()["ids"]["instance"])

    def test_target_only_insert_does_not_resolve_an_uncertain_create(self):
        w = World()
        w.raw.insert_mode = "timeout_nothing"
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.ctl.submit(U1).status, "uncertain")
        # A retained DONE insert for the same (reused) name, older lease.
        w.raw._op("insert", spec.names(1, 1)["instance"], client_id=U2)
        self.assertEqual(w.ctl.reconcile(U1).status, "settling")
        self.assertNotEqual(w.record()["state"], FREE)
        w.clock.advance(61)
        self.assertEqual(w.ctl.reconcile().status, "blocked")
        self.assertNotEqual(w.record()["state"], FREE)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)

    def test_vm_appearing_after_preflight_is_not_deleted(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        name = spec.names(1, 1)["instance"]
        inst = w.raw.instances.pop(name)
        original = w.ctl._inspect

        def inspect(rec, proof):
            result = original(rec, proof)
            w.raw.instances[name] = inst  # lands right after the preflight
            return result
        w.ctl._inspect = inspect
        out = w.ctl.reconcile(U1)
        self.assertEqual(out.detail,
                         "identity-mismatch:instance:appeared-during-cleanup")
        self.assertEqual([c for c in w.deletes() if c[2] == name], [])

    # ----------------------------------------------- project-wide capacity
    def test_four_baseline_vms_cannot_authorize_a_fifth(self):
        w = World()
        for i in range(4):
            name = f"existing-test-{i}"
            w.cfg.baseline[name] = w.raw.add_foreign("instances", name)
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)
        self.assertEqual(w.record()["state"], FREE)

    def test_ceiling_counts_all_zones_and_stopped_vms(self):
        w = World()
        for name, zone in (("a", spec.ZONE), ("b", "europe-west1-b"),
                           ("c", "asia-east1-a")):
            w.cfg.baseline[name] = w.raw.add_foreign("instances", name,
                                                     zone=zone)
        w.raw.instances["a"]["status"] = "TERMINATED"
        with self.assertRaises(Refused) as ctx:
            w.ctl.admit(1, 1, U1)
        self.assertIn("ceiling", str(ctx.exception))

    def test_two_baseline_vms_leave_room_for_one_lease(self):
        w = World()
        for name, zone in (("a", spec.ZONE), ("b", "europe-west1-b")):
            w.cfg.baseline[name] = w.raw.add_foreign("instances", name,
                                                     zone=zone)
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.record()["state"], RESERVED)

    def test_unknown_resource_in_another_zone_blocks_admission(self):
        for kind in ("instances", "disks"):
            w = World()
            w.raw.add_foreign(kind, "stray", zone="europe-west1-b")
            with self.assertRaises(Refused):
                w.ctl.admit(1, 1, U1)

    def test_baseline_in_another_zone_is_tolerated_and_never_deleted(self):
        w = World()
        w.cfg.baseline["far"] = w.raw.add_foreign("instances", "far",
                                                  zone="europe-west1-b")
        w.started()
        w.ctl.reconcile(U1)
        self.assertIn("far", w.raw.remote["europe-west1-b"]["instances"])
        self.assertNotIn("far", {c[2] for c in w.deletes()})

    def test_census_follows_every_page(self):
        w = World()
        w.raw.page_size = 1
        w.raw.add_foreign("instances", "p1", zone="z-1")
        w.raw.add_foreign("instances", "p2", zone="z-2")
        w.cfg.baseline.update(p1=w.raw.remote["z-1"]["instances"]["p1"]["id"])
        # p2 is unknown and lives on a later page.
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)

    def test_census_pending_operation_blocks_across_pages(self):
        w = World()
        w.raw.page_size = 1
        for i in range(3):
            w.raw.add_foreign("disks", f"d{i}", zone=f"z-{i}")
            w.cfg.baseline[f"d{i}"] = w.raw.remote[f"z-{i}"]["disks"][
                f"d{i}"]["id"]
        w.raw._op("insert", "x", status="RUNNING")
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)

    def test_census_fails_closed_on_list_errors_and_unreachable_scopes(self):
        w = World()
        w.raw.unreachables = ["zones/us-east1-b"]
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)
        for key in (("instances", "aggregatedList"), ("disks", "aggregatedList"),
                    ("globalOperations", "aggregatedList")):
            w = World()
            w.raw.list_error.add(key)
            with self.assertRaises(Refused):
                w.ctl.admit(1, 1, U1)
            self.assertEqual(w.record()["state"], FREE)

    def test_runaway_paging_fails_closed(self):
        w = World(max_pages=2)
        w.raw.page_size = 1
        for i in range(3):
            w.raw.add_foreign("disks", f"d{i}", zone=f"z-{i}")
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)

    def test_cleanup_reads_all_operation_pages_before_release(self):
        w = World()
        w.started()
        w.raw.page_size = 1
        w.raw._op("insert", "someone-else", status="RUNNING")  # last page
        self.assertEqual(w.ctl.reconcile(U1).status, "blocked")
        self.assertNotEqual(w.record()["state"], FREE)

    def test_cleanup_blocks_when_operation_listing_fails(self):
        w = World()
        w.started()
        w.raw.list_error.add(("zoneOperations", "list"))
        self.assertEqual(w.ctl.reconcile(U1).status, "blocked")
        self.assertEqual(w.deletes(), [])
        self.assertNotEqual(w.record()["state"], FREE)

    def test_preexisting_and_published_resources_never_deleted(self):
        w = World()
        pid = w.raw.add_foreign("instances", "prod-appliance")
        did = w.raw.add_foreign("disks", "prod-disk")
        w.cfg.baseline.update({"prod-appliance": pid, "prod-disk": did})
        w.started()
        w.ctl.reconcile(U1)
        self.assertTrue({c[2] for c in w.deletes()} <=
                        set(spec.names(1, 1).values()))
        self.assertIn("prod-appliance", w.raw.instances)
        self.assertIn("prod-disk", w.raw.disks)

    # -------------------------------------------------- forbidden operations
    def test_policy_blocks_every_unreviewed_operation(self):
        w = World()
        for res, verb in (("images", "delete"), ("images", "insert"),
                          ("snapshots", "insert"), ("snapshots", "delete"),
                          ("addresses", "insert"), ("addresses", "delete"),
                          ("globalAddresses", "insert"),
                          ("firewalls", "insert"), ("projects", "setMetadata"),
                          ("instances", "stop"), ("instances", "start"),
                          ("instances", "setScheduling"),
                          ("instances", "setMetadata"),
                          ("instances", "setServiceAccount"),
                          ("disks", "insert"), ("disks", "createSnapshot"),
                          ("disks", "setIamPolicy"),
                          ("regions", "setQuota")):
            with self.assertRaises(ForbiddenOperation, msg=f"{res}.{verb}"):
                w.cloud.call(res, verb, name="x")
        with self.assertRaises(ForbiddenOperation):
            w.cloud.call("instances", "get", name="x", project="other")
        with self.assertRaises(ForbiddenOperation):
            w.cloud.call("instances", "get", name="x", zone="europe-west1-b")
        self.assertEqual(w.raw.calls, [])

    def test_policy_scope_is_pinned_to_the_approved_project_and_zone(self):
        raw = FakeCloud(FakeClock())
        for project, zone in (("other-project", spec.ZONE),
                              (spec.PROJECT, "europe-west1-b"),
                              ("other-project", "europe-west1-b")):
            with self.assertRaises(ForbiddenOperation):
                PolicyCloud(raw, project, zone)
        PolicyCloud(raw, spec.PROJECT, spec.ZONE)

    def test_full_scenarios_only_use_allowlisted_calls(self):
        w = World()
        w.started()
        w.raw.leak_disks = True
        w.ctl.reconcile(U1)
        used = {(c[0], c[1]) for c in w.raw.calls}
        self.assertTrue(used <= ALLOWED, used - ALLOWED)

    # --------------------------------------------------------------- the spec
    def test_body_matches_reviewed_envelope(self):
        deadline = FakeClock().now() + timedelta(minutes=60)
        body = spec.build_body(boot_image=BOOT_IMAGE, request_id=U1, run_id=5,
                               attempt=1, deadline=deadline)
        self.assertEqual(body["serviceAccounts"], [])
        self.assertEqual(body["metadata"], {"items": [
            {"key": "block-project-ssh-keys", "value": "TRUE"},
            {"key": "enable-oslogin", "value": "TRUE"},
            {"key": "enable-guest-attributes", "value": "TRUE"},
            {"key": "labapp-stage", "value": "none"}]})
        self.assertNotIn("accessConfigs", body["networkInterfaces"][0])
        self.assertTrue(body["machineType"].endswith("/e2-standard-2"))
        self.assertEqual(body["scheduling"]["terminationTime"],
                         spec.rfc3339(deadline))
        self.assertEqual(body["scheduling"]["instanceTerminationAction"],
                         "DELETE")
        self.assertNotIn("maxRunDuration", body["scheduling"])
        self.assertEqual([d["autoDelete"] for d in body["disks"]], [True, False])
        self.assertEqual([d["boot"] for d in body["disks"]], [True, False])
        # The source copy is read-only; there is no writable alternative.
        self.assertEqual([d["mode"] for d in body["disks"]],
                         ["READ_WRITE", "READ_ONLY"])
        sizes = [d["initializeParams"]["diskSizeGb"] for d in body["disks"]]
        self.assertEqual(sizes, ["10", "300"])
        self.assertTrue(all(d["initializeParams"]["diskType"].endswith(
            "/pd-standard") for d in body["disks"]))
        self.assertEqual(body["disks"][1]["initializeParams"]["sourceImage"],
                         spec.SOURCE_IMAGE)
        self.assertEqual(spec.body_hash(body),
                         spec.body_hash(copy.deepcopy(body)))

    def test_validator_rejects_envelope_violations(self):
        deadline = FakeClock().now() + timedelta(minutes=60)

        def fresh():
            return spec.build_body(boot_image=BOOT_IMAGE, request_id=U1,
                                   run_id=5, attempt=1, deadline=deadline)

        mutations = {
            "external ip": lambda b: b["networkInterfaces"][0].update(
                accessConfigs=[{"type": "ONE_TO_ONE_NAT"}]),
            "service account": lambda b: b.update(
                serviceAccounts=[{"email": "x", "scopes": []}]),
            "missing metadata": lambda b: b.pop("metadata"),
            "missing guest attributes": lambda b: b["metadata"]["items"].pop(2),
            "disabled guest attributes": lambda b: b["metadata"]["items"][2].update(value="FALSE"),
            "disabled OS Login": lambda b: b["metadata"]["items"][1].update(value="FALSE"),
            "project SSH keys": lambda b: b["metadata"]["items"][0].update(value="FALSE"),
            "duplicate metadata": lambda b: b["metadata"]["items"].append(
                {"key": "enable-guest-attributes", "value": "FALSE"}),
            "startup script": lambda b: b["metadata"]["items"].append(
                {"key": "startup-script", "value": "true"}),
            "gpu": lambda b: b.update(guestAccelerators=[{}]),
            "autoDelete off": lambda b: b["disks"][0].update(autoDelete=False),
            "read-only autoDelete on": lambda b: b["disks"][1].update(autoDelete=True),
            "read-only autoDelete missing": lambda b: b["disks"][1].pop("autoDelete"),
            "read-only autoDelete nonboolean": lambda b: b["disks"][1].update(autoDelete=0),
            "duration": lambda b: b["scheduling"].update(
                maxRunDuration={"seconds": "3300"}),
            "no termination time": lambda b: b["scheduling"].pop(
                "terminationTime"),
            "terminate not delete": lambda b: b["scheduling"].update(
                instanceTerminationAction="STOP"),
            "big machine": lambda b: b.update(
                machineType="zones/z/machineTypes/n2-standard-32"),
            "foreign name": lambda b: b.update(name="prod-appliance"),
            "ssd": lambda b: b["disks"][1]["initializeParams"].update(
                diskType="zones/z/diskTypes/pd-ssd"),
            "wrong size": lambda b: b["disks"][1]["initializeParams"].update(
                diskSizeGb="500"),
            "writable source copy": lambda b: b["disks"][1].update(
                mode="READ_WRITE"),
            "source copy without mode": lambda b: b["disks"][1].pop("mode"),
            "source copy as boot": lambda b: b["disks"][1].update(boot=True),
            "read-only boot": lambda b: b["disks"][0].update(mode="READ_ONLY"),
            "third disk": lambda b: b["disks"].append(
                copy.deepcopy(b["disks"][0])),
        }
        for label, mutate in mutations.items():
            body = fresh()
            mutate(body)
            with self.assertRaises(ValueError, msg=label):
                spec.validate_body(body)

    def test_unpinned_or_bad_inputs_rejected(self):
        d = FakeClock().now()
        for image in ("projects/p/global/images/family/ubuntu-2404-lts",
                      "ubuntu-2404"):
            with self.assertRaises(ValueError):
                spec.build_body(boot_image=image, request_id=U1, run_id=1,
                                attempt=1, deadline=d)
        with self.assertRaises(ValueError):
            spec.build_body(boot_image=BOOT_IMAGE, request_id="not-a-uuid",
                            run_id=1, attempt=1, deadline=d)
        with self.assertRaises(ValueError):
            spec.names("1; rm -rf", 1)

    def test_owned_name_pattern(self):
        self.assertTrue(spec.is_owned_name("labapp-lc-s1-r12-a1-src"))
        for bad in ("labapp-lc-s1", "prod-labapp-lc-s1-r1-a1",
                    "labapp-lc-s1-r1-a1-extra", "hedgehog-vaidc-v20260114"):
            self.assertFalse(spec.is_owned_name(bad), bad)


if __name__ == "__main__":
    unittest.main()
