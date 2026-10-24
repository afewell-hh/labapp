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

    def test_http_500_or_timeout_without_operation_settles_until_deadline(self):
        for mode in ("http500", "timeout_nothing"):
            w = World()
            w.raw.insert_mode = mode
            w.ctl.admit(1, 1, U1)
            self.assertEqual(w.ctl.submit(U1).status, "uncertain")
            self.assertEqual(w.ctl.reconcile(U1).status, "settling")
            self.assertEqual(w.record()["state"], RESERVED)
            w.clock.advance(61)  # past terminationTime: a late create is rejected
            self.assertEqual(w.ctl.reconcile().status, "released")

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

    def test_one_disk_that_will_not_delete_keeps_capacity(self):
        w = World()
        w.started()
        w.raw.leak_disks = True
        w.raw.delete_noop.add(spec.names(1, 1)["data"])  # DONE but present
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertEqual(w.record()["state"], CLEANUP_FAILED)
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)

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

    def test_disk_identity_mismatch_stops_before_that_disk_is_deleted(self):
        w = World()
        w.started()
        w.raw.leak_disks = True  # keep disks after the VM delete
        data = spec.names(1, 1)["data"]
        w.raw.disks[data]["labels"][spec.LABEL_LEASE] = U2
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertNotIn(data, {c[2] for c in w.deletes()})
        self.assertIn(data, w.raw.disks)

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
        self.assertNotIn("accessConfigs", body["networkInterfaces"][0])
        self.assertTrue(body["machineType"].endswith("/e2-standard-2"))
        self.assertEqual(body["scheduling"]["terminationTime"],
                         spec.rfc3339(deadline))
        self.assertEqual(body["scheduling"]["instanceTerminationAction"],
                         "DELETE")
        self.assertNotIn("maxRunDuration", body["scheduling"])
        self.assertEqual([d["autoDelete"] for d in body["disks"]], [True, True])
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
            "gpu": lambda b: b.update(guestAccelerators=[{}]),
            "autoDelete off": lambda b: b["disks"][0].update(autoDelete=False),
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
