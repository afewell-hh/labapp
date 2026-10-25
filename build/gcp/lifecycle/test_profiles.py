"""Offline fixed-profile lifecycle and HTTP boundary regressions; no cloud."""
from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from . import spec
from .cloud import ApiError, ForbiddenOperation
from .controller import Config, Controller, FREE, Refused
from .test_lifecycle import U1, U2, World
from .test_compute import call, response, transport


class ComponentWorld(World):
    def __init__(self):
        # World's old inspector fixture intentionally stays unchanged.
        super().__init__(profile=spec.INSPECTOR)
        self.cfg = Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_COMPONENT,
                          now=self.clock.now, sleep=self.clock.sleep)
        self.ctl = Controller(self.store, self.cloud, self.cfg)


def world():
    return ComponentWorld()


class Profiles(unittest.TestCase):
    def mutate_record(self, w, mutate):
        rec, gen = w.store.read(w.cfg.key)
        mutate(rec)
        w.store.write(w.cfg.key, rec, if_generation_match=gen)

    def test_default_bounds_and_invalid_shape(self):
        self.assertEqual(World().cfg.lease_minutes, 60)
        self.assertEqual(world().cfg.lease_minutes, 30)
        for kwargs in ({"lease_minutes": 31}, {"lease_minutes": True},
                       {"profile": "arbitrary"}, {"boot_image": "projects/p/global/images/other"}):
            values = dict(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_COMPONENT)
            values.update(kwargs)
            with self.assertRaises(ValueError):
                Config(**values)

    def test_fixed_component_body_and_persisted_intent(self):
        w = world()
        rec = w.ctl.admit(1, 1, U1)
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1,
                               run_id=1, attempt=1, deadline=w.clock.now()+timedelta(minutes=30),
                               profile=spec.UBUNTU_COMPONENT)
        spec.validate_body(body)
        self.assertEqual(body["machineType"], "zones/us-central1-a/machineTypes/n2-standard-2")
        self.assertEqual(body["minCpuPlatform"], "Intel Cascade Lake")
        self.assertEqual(body["advancedMachineFeatures"], {"enableNestedVirtualization": True})
        self.assertEqual(body["scheduling"], {"provisioningModel": "STANDARD", "onHostMaintenance": "TERMINATE",
                         "automaticRestart": False, "terminationTime": rec["deadline"], "instanceTerminationAction": "DELETE"})
        self.assertEqual(body["disks"], [{"boot": True, "autoDelete": True, "mode": "READ_WRITE",
                         "deviceName": "boot", "type": "PERSISTENT", "initializeParams": {
                         "diskName": "labapp-lc-s1-r1-a1-boot", "sourceImage": spec.COMPONENT_IMAGE,
                         "diskSizeGb": "20", "diskType": "zones/us-central1-a/diskTypes/pd-standard",
                         "labels": {"labapp-owner": "lifecycle-v1", "labapp-lease": U1, "labapp-run": "1"}}}])
        self.assertEqual(body["serviceAccounts"], [])
        self.assertEqual(body["networkInterfaces"], [{"subnetwork": "regions/us-central1/subnetworks/default"}])
        self.assertEqual(rec["profile"], "ubuntu-component-v1")
        self.assertEqual(rec["boot_image_id"], "4575951068918267275")
        self.assertEqual(set(rec["names"]), {"instance", "boot"})
        self.assertEqual(set(rec["ids"]), {"instance", "boot"})
        self.assertEqual(rec["children"], {"boot": body["disks"][0]["initializeParams"]})
        self.assertEqual(rec["body_hash"], spec.body_hash(body))
        self.assertFalse([c for c in w.raw.calls if c[1] == "insert"])

    def test_component_body_rejects_all_extra_configuration(self):
        w = world()
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1, run_id=1, attempt=1,
                               deadline=w.clock.now(), profile=spec.UBUNTU_COMPONENT)
        mutations = [lambda b: b.update(arbitrary=True),
                     lambda b: b["advancedMachineFeatures"].update(threadsPerCore=1),
                     lambda b: b.pop("advancedMachineFeatures"),
                     lambda b: b.update(minCpuPlatform="Intel Ice Lake"),
                     lambda b: b["disks"].append(copy.deepcopy(b["disks"][0])),
                     lambda b: b["disks"][0]["initializeParams"].update(sourceImage=spec.SOURCE_IMAGE),
                     lambda b: b["disks"][0]["initializeParams"].update(diskSizeGb="300"),
                     lambda b: b["metadata"]["items"].append({"key":"startup-script", "value":"true"}),
                     lambda b: b["networkInterfaces"][0].update(accessConfigs=[]),
                     lambda b: b.update(serviceAccounts=[{}]),
                     lambda b: b["disks"][0].update(autoDelete=1)]
        for mutate in mutations:
            changed = copy.deepcopy(body)
            mutate(changed)
            with self.assertRaises(ValueError):
                spec.validate_body(changed)

    def test_inspector_body_unchanged_and_legacy_ledger_compatible(self):
        w = World()
        rec = w.started()
        # SHA256 of the pre-profile inspector request, fixed test inputs.
        self.assertEqual(rec["body_hash"], "d9989e2886aa750bdb4c274616b7c9c1b9db92acbb624ebcd64dccbf9b5e080f")
        self.mutate_record(w, lambda r: (r.pop("profile"), r.pop("children")))
        # Cleanup configured for the new profile must still use recorded inspector intent.
        other = Controller(w.store, w.cloud, world().cfg)
        self.assertEqual(other.reconcile(U1).status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertEqual(set(w.record()["last_release"]["ids"]), {"instance", "boot", "data"})

    def test_legacy_reserved_inspector_submits_and_confirms_unchanged(self):
        w = World()
        w.ctl.admit(1, 1, U1)
        self.mutate_record(w, lambda r: (r.pop("profile"), r.pop("children")))
        self.assertEqual(w.ctl.submit(U1).status, "accepted")
        self.assertEqual(w.ctl.confirm_created(U1).status, "created")
        self.assertEqual(w.ctl.reconcile(U1).status, "released")

    def test_image_pin_checked_at_admission_and_again_before_submission(self):
        for field, value in (("id", "reused-name"), ("name", "other"), ("status", "PENDING"),
                             ("architecture", "ARM64"), ("diskSizeGb", "30")):
            for phase in ("admit", "submit"):
                w = world()
                if phase == "submit":
                    w.ctl.admit(1, 1, U1)
                original = w.raw._images_get
                w.raw._images_get = lambda *a: dict(original(*a), **{field: value})
                with self.assertRaises(Refused):
                    w.ctl.admit(1, 1, U1) if phase == "admit" else w.ctl.submit(U1)
                self.assertFalse([c for c in w.raw.calls if c[1] == "insert"])
                if phase == "submit":
                    self.assertEqual(w.record()["submit_attempts"], 0)

    def test_image_read_denial_is_not_proof(self):
        w = world()
        def denied(*_):
            raise ApiError(403, "denied")
        w.raw._images_get = denied
        with self.assertRaises(Refused):
            w.ctl.admit(1, 1, U1)
        self.assertEqual(w.record()["state"], FREE)

    def test_lost_insert_response_and_late_materialization_keep_slot(self):
        w = world()
        w.raw.insert_mode = "timeout_pending"
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.ctl.submit(U1).status, "uncertain")
        self.assertEqual(w.ctl.reconcile(U1).status, "pending-operation")
        with self.assertRaises(Refused):
            w.ctl.admit(2, 1, U2)
        w.raw.finish_pending()
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_unknown_insert_is_not_resolved_by_expiry_or_404(self):
        w = world()
        w.raw.insert_mode = "timeout_nothing"
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        self.assertEqual(w.ctl.reconcile(U1).status, "settling")
        w.clock.advance(31)
        self.assertEqual(w.ctl.reconcile().status, "blocked")
        self.assertNotEqual(w.record()["state"], FREE)

    def test_unsubmitted_cancellation_and_expired_cleanup(self):
        w = world()
        w.ctl.admit(1, 1, U1)
        self.assertEqual(w.ctl.reconcile(U1).status, "released")
        rec = w.started(run=2, uuid=U2)
        self.assertEqual(w.ctl.reconcile().status, "not-due")
        w.clock.advance(31)
        self.assertEqual(w.ctl.reconcile().status, "released")
        self.assertEqual(rec["deadline"], "2026-10-24T20:30:00Z")

    def test_interrupted_cleanup_leaked_boot_reconciles_without_vm(self):
        w = world()
        rec = w.started()
        w.raw.leak_disks = True
        w.raw.delete_fail.add(rec["names"]["boot"])
        self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
        self.assertFalse(w.raw.instances)
        self.assertIn(rec["names"]["boot"], w.raw.disks)
        self.assertNotEqual(w.record()["state"], FREE)
        w.raw.delete_fail.clear()
        self.assertEqual(w.ctl.reconcile().status, "released")

    def test_pending_delete_and_still_existing_boot_hold_slot(self):
        for mode in ("pending", "noop"):
            w = world()
            rec = w.started()
            w.raw.leak_disks = True
            if mode == "noop":
                w.raw.delete_noop.add(rec["names"]["boot"])
            else:
                original = w.raw._disks_delete
                def pending(*args):
                    op = original(*args)
                    w.raw.op_stuck.add(op["name"])
                    return op
                w.raw._disks_delete = pending
            self.assertIn(w.ctl.reconcile(U1).status, {"pending-operation", "cleanup-failed"})
            self.assertNotEqual(w.record()["state"], FREE)

    def test_stale_ids_names_foreign_attachment_and_image_binding_block_all_deletes(self):
        mutations = [lambda w, r: w.raw.instances[r["names"]["instance"]].update(id="reused"),
                     lambda w, r: w.raw.disks[r["names"]["boot"]].update(id="reused"),
                     lambda w, r: w.raw.disks[r["names"]["boot"]].update(sourceImageId="other"),
                     lambda w, r: w.raw.disks[r["names"]["boot"]].update(sourceImage=spec.SOURCE_IMAGE),
                     lambda w, r: w.raw.instances[r["names"]["instance"]]["disks"].append({
                         "source": "zones/us-central1-a/disks/foreign", "boot": False,
                         "mode": "READ_WRITE", "autoDelete": True})]
        for mutate in mutations:
            w = world()
            rec = w.started()
            mutate(w, rec)
            self.assertEqual(w.ctl.reconcile(U1).status, "cleanup-failed")
            self.assertEqual(w.deletes(), [])
            self.assertNotEqual(w.record()["state"], FREE)

    def test_unconfirmed_boot_provenance_refused_before_ids_adopted(self):
        w = world()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        name = w.record()["names"]["boot"]
        w.raw.disks[name]["sourceImageId"] = "wrong"
        self.assertEqual(w.ctl.confirm_created(U1).status, "identity-mismatch")
        self.assertEqual(w.record()["ids"], {"instance": None, "boot": None})
        self.assertEqual(w.deletes(), [])

    def test_bad_persisted_profiles_and_mixed_children_block_without_cloud_mutation(self):
        mutations = [lambda r: r.update(profile="unknown"), lambda r: r.pop("profile"),
                     lambda r: r.update(boot_image_id="wrong"), lambda r: r.pop("children"),
                     lambda r: r["names"].update(data="labapp-lc-s1-r1-a1-src"),
                     lambda r: r["ids"].update(data=None),
                     lambda r: r["children"]["boot"].update(diskSizeGb="300"),
                     lambda r: r.update(deadline="2026-09-01T01:30:00Z")]
        for mutate in mutations:
            w = world()
            w.ctl.admit(1, 1, U1)
            self.mutate_record(w, mutate)
            with self.assertRaises(Refused):
                w.ctl.submit(U1)
            self.assertEqual(w.ctl.reconcile(U1).status, "blocked")
            self.assertEqual(w.deletes(), [])
            self.assertFalse([c for c in w.raw.calls if c[1] == "insert"])
            self.assertNotEqual(w.record()["state"], FREE)

    def test_foreign_pending_operation_prevents_release(self):
        w = world()
        w.started()
        w.raw._op("insert", "foreign", status="RUNNING")
        self.assertEqual(w.ctl.reconcile(U1).status, "blocked")
        self.assertNotEqual(w.record()["state"], FREE)

    def test_fixed_image_read_http_routing_and_mutation_denial(self):
        adapter, http = transport(response({"id": spec.COMPONENT_IMAGE_ID}))
        self.assertEqual(call(adapter, "images", "get", name=spec.COMPONENT_IMAGE.rsplit("/", 1)[-1]),
                         {"id": spec.COMPONENT_IMAGE_ID})
        self.assertEqual(http.calls[0][0:2], ("GET", "https://compute.googleapis.com/compute/v1/" + spec.COMPONENT_IMAGE))
        for verb, kwargs in (("delete", {}), ("list", {}), ("get", {"name":"other"}),
                             ("get", {"name":spec.COMPONENT_IMAGE.rsplit("/", 1)[-1], "request_id": U1}),
                             ("get", {"name":spec.COMPONENT_IMAGE.rsplit("/", 1)[-1], "body": {}}),
                             ("get", {"name":spec.COMPONENT_IMAGE.rsplit("/", 1)[-1], "page_token": "page"})):
            with self.assertRaises(ForbiddenOperation):
                call(adapter, "images", verb, **kwargs)
        with self.assertRaises(ForbiddenOperation):
            adapter.call("images", "get", project="other", zone=spec.ZONE,
                         name=spec.COMPONENT_IMAGE.rsplit("/", 1)[-1])
        self.assertEqual(len(http.calls), 1)
        w = world()
        with self.assertRaises(ForbiddenOperation):
            w.cloud.call("images", "get", name="other")
        for extra in ({"project": "other"}, {"body": {}}, {"request_id": U1}, {"page_token": "page"}):
            with self.assertRaises(ForbiddenOperation):
                w.cloud.call("images", "get", name=spec.COMPONENT_IMAGE.rsplit("/", 1)[-1], **extra)


if __name__ == "__main__":
    unittest.main()
