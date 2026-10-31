"""Single-slot VM lease state machine shared by creator, cleanup and janitor.

One persistent slot record (generation-matched writes) moves through

    FREE -> RESERVED -> ACTIVE -> FREE
                 \\-> CLEANUP_FAILED -> FREE      (any occupied state)

Only ``reconcile`` can return a slot to FREE, and only after the VM and all
intended owned disks are confirmed absent (404 after the delete operation is DONE) and
no create can still land. Normal cleanup and the janitor call the same method.
Every state change is a compare-and-swap on the slot's generation, so a stale
actor loses instead of overwriting a newer lease.

Capacity is never released optimistically: unexpected pending operations,
identity mismatches, delete failures or an unresolved create keep the slot
occupied. See ../README.md for the guarantees and the unverified assumptions.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from . import spec
from .access_records import AccessError, Context, KINDS, digest, public_key
from .oslogin import check_receipt
from .cloud import ApiError, NotFound, PolicyCloud, Uncertain
from .store import PreconditionFailed, SlotStore

FREE, RESERVED, ACTIVE, CLEANUP_FAILED = (
    "FREE", "RESERVED", "ACTIVE", "CLEANUP_FAILED")
NOT_RUNNING = frozenset({"STOPPING", "STOPPED", "TERMINATED", "SUSPENDING",
                         "SUSPENDED", "REPAIRING"})
# Fields that must never change while a lease is held (absolute deadline etc.).
IMMUTABLE = ("slot", "epoch", "project", "zone", "run_id", "attempt",
             "request_id", "body_hash", "names", "boot_image", "reserved_at",
             "deadline", "max_submit_attempts", "profile", "children", "boot_image_id")


class Refused(Exception):
    """Admission or submission is not allowed; nothing was changed."""


class _Conflict(Exception):
    """A generation-matched write lost; re-read and re-evaluate."""


@dataclass
class Outcome:
    status: str
    detail: str = ""


@dataclass
class Config:
    boot_image: str
    profile: str = spec.INSPECTOR
    project: str = spec.PROJECT
    zone: str = spec.ZONE
    key: str = "slots/slot-1.json"
    # Protected preexisting resources: name -> immutable id. Anything else
    # found at admission is unknown ownership and blocks the lease.
    baseline: dict = field(default_factory=dict)
    # Project-wide VM ceiling (all zones, protected + temporary, any state).
    max_vm_slots: int = 3
    max_pages: int = 100
    max_submit_attempts: int = 1  # same-UUID retry semantics are unverified
    lease_minutes: Optional[int] = None
    min_submit_minutes: int = 10
    poll_attempts: int = 30
    poll_seconds: float = 5.0
    cas_retries: int = 5
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def __post_init__(self) -> None:
        spec.kinds(self.profile)
        if self.lease_minutes is None:
            self.lease_minutes = spec.lease_limit(self.profile)
        self.validate_lease()

    def validate_lease(self) -> None:
        spec.kinds(self.profile)
        maximum = spec.lease_limit(self.profile)
        if self.profile in spec.UBUNTU_PROFILES and self.boot_image != spec.COMPONENT_IMAGE:
            raise ValueError("Ubuntu boot image must match the reviewed pin")
        if (type(self.lease_minutes) is not int or
                not 1 <= self.lease_minutes <= maximum):
            raise ValueError(f"lease_minutes must be an integer from 1 to {maximum}")
        if self.profile == spec.UBUNTU_VLAB_CORE and self.lease_minutes != spec.VLAB_LEASE_MINUTES:
            raise ValueError("canonical trial requires the fixed 120 minute lease")
        if (type(self.min_submit_minutes) is not int or
                not 0 <= self.min_submit_minutes < self.lease_minutes):
            raise ValueError("submission margin must be shorter than the lease")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class Controller:
    def __init__(self, store: SlotStore, cloud: PolicyCloud, cfg: Config, *, access_records=None):
        self.store, self.cloud, self.cfg = store, cloud, cfg
        self.access_records = access_records

    # ---------------------------------------------------------------- helpers
    def _cas(self, prev: dict, rec: dict, gen: int) -> int:
        if prev.get("state") != FREE and rec.get("state") != FREE:
            for name in IMMUTABLE:
                if prev.get(name) != rec.get(name):
                    raise AssertionError(f"immutable field {name} changed")
        old_access = prev.get("access")
        if old_access is not None and rec.get("state") != FREE:
            new_access = rec.get("access")
            if new_access is None or old_access["binding"] != new_access["binding"]:
                raise AssertionError("immutable access binding changed")
            phases = {"registered": 0, "finalizing": 1, "archived": 2}
            if phases[new_access["phase"]] < phases[old_access["phase"]]:
                raise AssertionError("access phase cannot regress")
            if old_access["archive"] and old_access["archive"] != new_access["archive"]:
                raise AssertionError("access archive changed")
        old_capture, new_capture = prev.get("capture"), rec.get("capture")
        if old_capture is not None and rec.get("state") != FREE:
            if new_capture is None:
                raise AssertionError("capture intent removed")
            mutable = {"submitted", "operation", "image_id", "insert_receipt",
                       "delete_submitted", "delete_operation", "delete_receipt"}
            if ({k: v for k, v in old_capture.items() if k not in mutable} !=
                    {k: v for k, v in new_capture.items() if k not in mutable}):
                raise AssertionError("immutable capture intent changed")
            for key in ("submitted", "delete_submitted"):
                if old_capture[key] and not new_capture[key]:
                    raise AssertionError("capture intent cannot regress")
            if old_capture.get("image_id") not in (None, new_capture.get("image_id")):
                raise AssertionError("capture image ID changed")
        try:
            return self.store.write(self.cfg.key, rec, if_generation_match=gen)
        except PreconditionFailed as exc:
            raise _Conflict(str(exc)) from exc

    def _lease_kinds(self, rec: dict) -> tuple:
        """Validate persisted intent before reading or deleting its children.

        Missing profile/children means the original schema-1 inspector record;
        never normalize it in place (old CAS immutable fields stay unchanged).
        """
        try:
            profile = rec.get("profile", spec.INSPECTOR)
            kinds = spec.kinds(profile)
            expected_names = spec.names(rec["run_id"], rec["attempt"], profile)
            if (rec["project"] != spec.PROJECT or rec["zone"] != spec.ZONE or
                    rec["names"] != expected_names or set(rec["ids"]) != set(expected_names)):
                raise ValueError("mixed child inventory")
            body = spec.build_body(boot_image=rec["boot_image"], request_id=rec["request_id"],
                                   run_id=rec["run_id"], attempt=rec["attempt"],
                                   deadline=_parse(rec["deadline"]), profile=profile)
            expected_children = {k: body["disks"][i]["initializeParams"]
                                 for i, (k, _) in enumerate(kinds[1:])}
            if "profile" in rec or "children" in rec:
                if rec.get("profile") != profile or rec.get("children") != expected_children:
                    raise ValueError("mixed child intent")
            if profile in spec.UBUNTU_PROFILES and rec.get("boot_image_id") != spec.COMPONENT_IMAGE_ID:
                raise ValueError("Ubuntu immutable image pin mismatch")
            if spec.body_hash(body) != rec["body_hash"]:
                raise ValueError("persisted body hash mismatch")
            minutes = (_parse(rec["deadline"]) - _parse(rec["reserved_at"])).total_seconds() / 60
            maximum = spec.lease_limit(profile)
            if not 0 < minutes <= maximum:
                raise ValueError("persisted deadline outside profile")
            if profile == spec.UBUNTU_VLAB_CORE and minutes != spec.VLAB_LEASE_MINUTES:
                raise ValueError('persisted trial deadline must be exactly 120 minutes')
            return kinds
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise Refused("invalid persisted profile or child inventory") from exc

    def _check_component_image(self):
        try:
            image = self.cloud.call("images", "get", name=spec.COMPONENT_IMAGE.rsplit("/", 1)[-1])
        except (ApiError, Uncertain) as exc:
            raise Refused("fixed component image verification unavailable") from exc
        if (image.get("name") != spec.COMPONENT_IMAGE.rsplit("/", 1)[-1] or
                image.get("id") != spec.COMPONENT_IMAGE_ID or image.get("status") != "READY" or
                image.get("architecture") != "X86_64" or str(image.get("diskSizeGb")) != "10"):
            raise Refused("fixed component image identity/status/minimum mismatch")

    def _get(self, resource: str, name: str) -> Optional[dict]:
        try:
            return self.cloud.call(resource, "get", name=name)
        except NotFound:
            return None

    def _wait(self, op_name: str, *, deadline: Optional[float] = None) -> Optional[dict]:
        for _ in range(self.cfg.poll_attempts):
            if deadline is not None and time.monotonic() >= deadline:
                return None
            try:
                op = self.cloud.call("zoneOperations", "get", name=op_name)
            except NotFound:
                return None
            if deadline is not None and time.monotonic() >= deadline:
                return None
            if op.get("status") == "DONE":
                return op
            pause = self.cfg.poll_seconds
            if deadline is not None:
                pause = min(pause, max(0.0, deadline - time.monotonic()))
            self.cfg.sleep(pause)
        return None

    def _verify(self, kind: str, res: dict, rec: dict,
                proof: Optional[str]) -> Optional[str]:
        """Return None if res provably belongs to this lease, else a reason.

        A resource whose immutable id is not yet recorded is accepted only
        with ``proof``: the immutable targetId from this request's completed
        insert. The fetched VM must match that exact incarnation; labels and
        a matching target name alone are never enough.
        """
        if res.get("name") != rec["names"][kind] or \
                not spec.is_owned_name(res.get("name", "")):
            return "name"
        if res.get("labels", {}).get(spec.LABEL_LEASE) != rec["request_id"]:
            return "lease-label"
        if res.get("zone", "").rsplit("/", 1)[-1] != rec["zone"]:
            return "zone"
        if kind == "instance" and proof is not None and res.get("id") != proof:
            return "operation-target-id"
        if kind == "boot" and rec.get("profile") in spec.UBUNTU_PROFILES:
            source = res.get("sourceImage", "")
            if (source not in (spec.COMPONENT_IMAGE, "https://www.googleapis.com/compute/v1/" + spec.COMPONENT_IMAGE,
                               "https://compute.googleapis.com/compute/v1/" + spec.COMPONENT_IMAGE) or
                    res.get("sourceImageId") != spec.COMPONENT_IMAGE_ID):
                return "source-image"
        known = rec["ids"].get(kind)
        if known:
            if res.get("id") != known:
                return "id"
        else:
            if not proof:
                return "unproven-ownership"
            if _parse(res.get("creationTimestamp", "1970-01-01T00:00:00Z")) < \
                    _parse(rec["reserved_at"]):
                return "predates-lease"
        return None

    def _insert_target_id(self, rec: dict, operations: list):
        """Keep current-request immutable target evidence, not a truthy flag."""
        successful = [op for op in operations if not op.get("error")]
        if not successful:
            return None, None  # failed/no retained insert gives no adoption proof
        ids = set()
        for op in successful:
            target_id = op.get("targetId")
            if op.get("status") != "DONE" or op.get("operationType") != "insert" or \
                    op.get("clientOperationId") != rec["request_id"] or \
                    op.get("targetLink", "").rsplit("/", 1)[-1] != rec["names"]["instance"] or \
                    not isinstance(target_id, str) or not target_id:
                return None, "missing-or-mismatched-insert-target"
            ids.add(target_id)
        if len(ids) != 1:
            return None, "conflicting-insert-target-ids"
        return ids.pop(), None

    def _inventory(self, inst: dict, rec: dict) -> Optional[str]:
        """The VM must carry exactly its fixed profile's intended disks.

        Deleting a VM also deletes its autoDelete disks, so this runs before
        the VM delete and any unexpected or mismatched child blocks it.
        """
        attached = inst.get("disks")
        children = self._lease_kinds(rec)[1:]
        if not isinstance(attached, list) or len(attached) != len(children):
            return "attachments"
        names = rec["names"]
        want = {names[kind]: kind == "boot" for kind, _ in children}
        seen = set()
        for att in attached:
            src = att.get("source", "")
            name = src.rsplit("/", 1)[-1]
            if name not in want or name in seen:
                return "attachment-unexpected"
            seen.add(name)
            if "/zones/" in src and \
                    src.split("/zones/", 1)[1].split("/", 1)[0] != rec["zone"]:
                return "attachment-zone"
            if "/projects/" in src and \
                    src.split("/projects/", 1)[1].split("/", 1)[0] != \
                    rec["project"]:
                return "attachment-project"
            if bool(att.get("boot")) != want[name]:
                return "attachment-boot-flag"
            expected = "READ_WRITE" if want[name] else "READ_ONLY"
            if att.get("mode", "READ_WRITE") != expected:
                return "attachment-mode"
            # Base-build boot and inspector source copy survive VM deletion.
            auto_delete = want[name] and rec.get("profile") != spec.UBUNTU_BASE_BUILD
            if att.get("autoDelete") is not auto_delete:
                return "attachment-autodelete"
        return None

    def _inspect(self, rec: dict, proof: Optional[str]):
        """Fetch and verify the lease's intended resources without changing any.

        Returns (reason, found). reason is None only when every resource that
        exists is provably this lease's and an existing VM has exactly the
        intended disks attached (each of which must then exist and verify).
        """
        found = {}
        for kind, resource in self._lease_kinds(rec):
            res = self._get(resource, rec["names"][kind])
            if res is not None:
                found[kind] = res
        for kind, res in found.items():
            reason = self._verify(kind, res, rec, proof)
            if reason:
                return f"{kind}:{reason}", found
        if "instance" in found:
            reason = self._inventory(found["instance"], rec)
            if reason:
                return f"instance:{reason}", found
            for kind, _ in self._lease_kinds(rec)[1:]:
                if kind not in found:
                    return f"{kind}:attached-but-missing", found
        return None, found

    def _adopt(self, rec: dict, gen: int, found: dict):
        """Record immutable ids of already-verified resources (one CAS)."""
        new = {k: res["id"] for k, res in found.items()
               if rec["ids"].get(k) is None}
        if new:
            prev = dict(rec)
            rec["ids"] = dict(rec["ids"], **new)
            gen = self._cas(prev, rec, gen)
        return rec, gen

    # -------------------------------------------------------------- admission
    def _pages(self, resource: str, verb: str, **kw):
        """Yield every page; any failure or runaway paging blocks the caller."""
        token = None
        for _ in range(self.cfg.max_pages):
            try:
                page = self.cloud.call(resource, verb, page_token=token, **kw)
            except (ApiError, Uncertain) as exc:
                raise Refused(f"cannot list {resource}.{verb}: {exc}") from exc
            yield page
            token = page.get("nextPageToken")
            if not token:
                return
        raise Refused(f"{resource}.{verb} exceeded {self.cfg.max_pages} pages")

    def _list_all(self, resource: str, **kw) -> list:
        return [i for p in self._pages(resource, "list", **kw)
                for i in p.get("items", [])]

    def _aggregate(self, resource: str, key: str) -> list:
        """All items of a project-wide list across every zone."""
        out = []
        for page in self._pages(resource, "aggregatedList"):
            if page.get("unreachables"):
                raise Refused(f"{resource}: unreachable scopes "
                              f"{page['unreachables']}")
            for scope, data in (page.get("items") or {}).items():
                warning = data.get("warning")
                if warning and warning.get("code") != "NO_RESULTS_ON_PAGE":
                    raise Refused(f"{resource} {scope}: {warning.get('code')}")
                out.extend(data.get(key, []))
        return out

    def _census(self) -> None:
        """Fail closed on any resource or operation we cannot attribute.

        Covers every zone of the project. Protected baseline resources are
        allowed to exist but still count toward the VM ceiling, as do stopped
        VMs and half-cleaned leases; unknown ownership blocks admission.
        """
        base = self.cfg.baseline
        current, _ = self.store.read(self.cfg.key)
        quarantines = self._quarantines(current or {})
        if quarantines:
            images = self._list_all("images", capture=quarantines[0])
            allowed = {}
            for c in quarantines:
                allowed.update(c["preexisting_images"])
                allowed[c["name"]] = c["image_id"]
                if self.cfg.now() >= _parse(c["retain_until"]):
                    raise Refused("overdue quarantine blocks admission")
            for image in images:
                if allowed.get(image["name"]) != image.get("id"):
                    raise Refused("foreign or replaced image blocks admission")
                for c in quarantines:
                    if image["name"] == c["name"]:
                        self._verify_image(c, image, c["image_id"])
        vms = self._aggregate("instances", "instances")
        for resource, items in (
                ("instances", vms),
                ("disks", self._aggregate("disks", "disks"))):
            for item in items:
                if base.get(item["name"]) != item.get("id"):
                    raise Refused(
                        f"unknown {resource} {item['name']}: ownership not "
                        "established, admission blocked")
        for op in self._aggregate("globalOperations", "operations"):
            if op.get("status") != "DONE":
                raise Refused(f"pending operation {op.get('name')} in project")
        if len(vms) + 1 > self.cfg.max_vm_slots:
            raise Refused(f"{len(vms)} VMs exist; ceiling is "
                          f"{self.cfg.max_vm_slots} including this lease")

    def admit(self, run_id: int, attempt: int, request_id: str) -> dict:
        """Persist the full intent (UUID, body hash, names, deadline) first."""
        cfg = self.cfg
        cfg.validate_lease()
        rec, gen = self.store.read(cfg.key)
        if rec is None:
            free = {"schema": 1, "slot": cfg.key, "state": FREE, "epoch": 0}
            try:
                self.store.write(cfg.key, free, if_generation_match=0)
            except PreconditionFailed:
                pass
            rec, gen = self.store.read(cfg.key)
        if rec["state"] != FREE:
            raise Refused(f"slot is {rec['state']}")
        self._quarantines(rec)
        self._census()
        if cfg.profile in spec.UBUNTU_PROFILES:
            self._check_component_image()
        now = cfg.now()
        deadline = now + timedelta(minutes=cfg.lease_minutes)
        body = spec.build_body(boot_image=cfg.boot_image, request_id=request_id,
                               run_id=run_id, attempt=attempt, deadline=deadline, profile=cfg.profile)
        lease = {
            "schema": 1, "slot": cfg.key, "state": RESERVED,
            "quarantine": rec.get("quarantine", []),
            "used_capture_ids": rec.get("used_capture_ids", []),
            "access_history": rec.get("access_history", []),
            "epoch": rec["epoch"] + 1, "project": cfg.project, "zone": cfg.zone,
            "run_id": run_id, "attempt": attempt, "request_id": request_id,
            "body_hash": spec.body_hash(body), "boot_image": cfg.boot_image,
            "profile": cfg.profile,
            "names": spec.names(run_id, attempt, cfg.profile),
            "children": {kind: body["disks"][i]["initializeParams"]
                         for i, (kind, _) in enumerate(spec.kinds(cfg.profile)[1:])},
            "reserved_at": spec.rfc3339(now), "deadline": spec.rfc3339(deadline),
            "submit_attempts": 0, "max_submit_attempts": cfg.max_submit_attempts,
            "operation": None, "ids": {kind: None for kind, _ in spec.kinds(cfg.profile)},
            "reason": None, "evidence": [],
        }
        if cfg.profile in spec.UBUNTU_PROFILES:
            lease["boot_image_id"] = spec.COMPONENT_IMAGE_ID
        try:
            self._cas(rec, lease, gen)
        except _Conflict as exc:
            raise Refused(f"lost the slot race: {exc}") from exc
        return lease

    # ----------------------------------------------------------------- create
    def submit(self, request_id: str) -> Outcome:
        """Send the persisted body with the persisted UUID, at most N times."""
        cfg = self.cfg
        rec, gen = self.store.read(cfg.key)
        if rec is None or rec["state"] != RESERVED or \
                rec["request_id"] != request_id:
            raise Refused("no RESERVED lease with this request id to submit")
        self._lease_kinds(rec)
        if rec.get("profile") in spec.UBUNTU_PROFILES:
            self._check_component_image()
        deadline = _parse(rec["deadline"])
        if cfg.now() + timedelta(minutes=cfg.min_submit_minutes) > deadline:
            raise Refused("too little lease time left to create")
        if rec["submit_attempts"] >= rec["max_submit_attempts"]:
            raise Refused("submit attempts exhausted; reconcile instead")
        body = spec.build_body(
            boot_image=rec["boot_image"], request_id=rec["request_id"],
            run_id=rec["run_id"], attempt=rec["attempt"], deadline=deadline,
            profile=rec.get("profile", spec.INSPECTOR))
        if spec.body_hash(body) != rec["body_hash"]:
            raise Refused("persisted body hash mismatch")
        prev = dict(rec)
        rec["submit_attempts"] += 1
        try:
            gen = self._cas(prev, rec, gen)  # attempt recorded BEFORE sending
        except _Conflict as exc:
            raise Refused(f"lease changed before submit: {exc}") from exc
        try:
            op = self.cloud.call("instances", "insert", body=body,
                                 request_id=rec["request_id"])
        except (ApiError, Uncertain) as exc:
            # Never classify as failed here and never mint a new UUID: the
            # request may have been applied. reconcile() resolves it.
            return Outcome("uncertain", str(exc))
        for _ in range(cfg.cas_retries):
            rec, gen = self.store.read(cfg.key)
            if rec is None or rec["request_id"] != body["labels"][spec.LABEL_LEASE] \
                    or rec["state"] != RESERVED:
                return Outcome("superseded", "lease changed during create")
            prev = dict(rec)
            rec.update(state=ACTIVE, operation=op["name"])
            try:
                self._cas(prev, rec, gen)
                return Outcome("accepted", op["name"])
            except _Conflict:
                continue
        return Outcome("uncertain", "could not record the operation")

    def confirm_created(self, request_id: str, *, timeout_seconds: Optional[int] = None) -> Outcome:
        """Wait for the insert and persist IDs; optional elapsed polling budget.

        The budget spans CAS retries and includes time spent in API calls.
        It is checked between calls: one in-flight read can overrun it, and
        post-operation identity reads still run. Workflow timeout is the final
        runner bound. Cleanup operation waits retain their existing defaults.
        """
        if timeout_seconds is not None and (type(timeout_seconds) is not int or
                                            not 1 <= timeout_seconds <= 3600):
            raise Refused("confirmation timeout must be an integer from 1 to 3600")
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        for _ in range(self.cfg.cas_retries):
            rec, gen = self.store.read(self.cfg.key)
            if rec is None or rec["state"] != ACTIVE or \
                    rec["request_id"] != request_id:
                raise Refused("no ACTIVE lease with this request id")
            self._lease_kinds(rec)
            done = self._wait(rec["operation"], deadline=deadline)
            if done is None:
                return Outcome("pending-operation", rec["operation"])
            if done.get("error"):
                return Outcome("create-failed", str(done["error"]))
            # Ownership proof: the completed insert for this exact request.
            if done.get("operationType") != "insert" or \
                    done.get("clientOperationId") != request_id or \
                    done.get("targetLink", "").rsplit("/", 1)[-1] != \
                    rec["names"]["instance"]:
                return Outcome("operation-mismatch", rec["operation"])
            proof, error = self._insert_target_id(rec, [done])
            if error:
                return Outcome("operation-mismatch", error)
            try:
                reason, found = self._inspect(rec, proof)
                if reason:
                    return Outcome("identity-mismatch", reason)
                for kind, _resource in self._lease_kinds(rec):
                    if kind not in found:
                        return Outcome("missing", kind)
                rec, gen = self._adopt(rec, gen, found)
                return Outcome("created", "ids recorded")
            except _Conflict:
                continue
        raise Refused("persistent write conflicts")

    # ---------------------------------------------------------------- cleanup
    def reconcile(self, request_id: Optional[str] = None) -> Outcome:
        """Clean up the current lease; the one transition path to FREE.

        With ``request_id`` (normal/failure/cancel cleanup of that run's own
        lease) cleanup is forced, but only while the slot still holds that
        lease; a newer lease is reported as "superseded" and left alone.
        Without it (janitor) cleanup happens only when the lease is expired,
        its VM is not running, or a previous cleanup failed.
        """
        force = request_id is not None
        for _ in range(self.cfg.cas_retries):
            rec, gen = self.store.read(self.cfg.key)
            if rec is None or rec["state"] == FREE:
                return Outcome("free")
            if force and rec["request_id"] != request_id:
                return Outcome("superseded", "slot holds a different lease")
            try:
                self._lease_kinds(rec)
                return self._reconcile_once(rec, gen, force)
            except (Refused, ApiError, Uncertain, AccessError) as exc:
                return Outcome("blocked", str(exc))
            except _Conflict:
                continue
        return Outcome("blocked", "persistent write conflicts")

    def _is_due(self, rec: dict, force: bool) -> bool:
        if force or rec["state"] == CLEANUP_FAILED or \
                self.cfg.now() >= _parse(rec["deadline"]):
            return True
        inst = self._get("instances", rec["names"]["instance"])
        return inst is not None and inst.get("status") in NOT_RUNNING

    def _fail(self, rec: dict, gen: int, reason: str, ev: list) -> Outcome:
        if not (rec["state"] == CLEANUP_FAILED and rec["reason"] == reason):
            prev = dict(rec)
            rec.update(state=CLEANUP_FAILED, reason=reason,
                       evidence=(rec["evidence"] + ev)[-50:])
            self._cas(prev, rec, gen)
        return Outcome("cleanup-failed", reason)

    def _delete_owned(self, rec, gen, kind, resource, found, proof, ev):
        """Delete one resource by exact name after identity verification.

        Only resources that passed the all-or-nothing preflight (``found``)
        may be deleted; anything that appears later blocks instead.
        Returns (rec, gen, None) when it is confirmed absent, or
        (rec, gen, Outcome) when the slot must stay occupied.
        """
        name = rec["names"][kind]
        res = self._get(resource, name)
        if res is None:
            ev.append(f"{kind} {name}: absent (404)")
            return rec, gen, None
        reason = None if kind in found else "appeared-during-cleanup"
        reason = reason or self._verify(kind, res, rec, proof)
        if kind == "instance" and not reason:  # recheck right before delete
            reason = self._inventory(res, rec)
        if reason:  # no delete call is made for an unverified resource
            return rec, gen, self._fail(
                rec, gen, f"identity-mismatch:{kind}:{reason}", ev)
        try:
            op = self.cloud.call(resource, "delete", name=name)
        except (ApiError, Uncertain) as exc:
            return rec, gen, self._fail(rec, gen, f"delete-{kind}:{exc}", ev)
        done = self._wait(op["name"])
        if done is None:
            return rec, gen, Outcome("pending-operation", op["name"])
        if done.get("error"):
            return rec, gen, self._fail(rec, gen, f"delete-{kind}-op-error", ev)
        if self._get(resource, name) is not None:
            return rec, gen, self._fail(rec, gen, f"{kind}-still-exists", ev)
        ev.append(f"{kind} {name} id {res['id']}: deleted, 404 confirmed")
        return rec, gen, None

    def _reconcile_once(self, rec: dict, gen: int, force: bool) -> Outcome:
        cfg, ev = self.cfg, []
        if not self._is_due(rec, force):
            return Outcome("not-due")
        self._quarantines(rec)
        if rec.get("capture"):
            self._capture_intent(rec)
            # Fence concurrent explicit capture before observing/deleting any
            # resources. A stale capture submitter must lose its next CAS.
            prev = dict(rec)
            rec.update(state=CLEANUP_FAILED, reason="capture-cleanup")
            gen = self._cas(prev, rec, gen)
        owned = set(rec["names"].values())
        related, foreign_pending = [], []
        try:
            all_ops = self._list_all("zoneOperations")
        except Refused as exc:
            return Outcome("blocked", str(exc))
        for op in all_ops:
            target = op.get("targetLink", "").rsplit("/", 1)[-1]
            if op.get("clientOperationId") == rec["request_id"] or \
                    target in owned:
                related.append(op)
            elif op.get("status") != "DONE":
                foreign_pending.append(op)
        if any(op.get("status") != "DONE" for op in related):
            return Outcome("pending-operation", "owned operation still running")
        # Only an insert tied to THIS request id resolves the create; an
        # operation that merely targets a reused name stays blocking evidence.
        own_inserts = [op for op in related
                       if op.get("operationType") == "insert"
                       and op.get("clientOperationId") == rec["request_id"]]
        proof, error = self._insert_target_id(rec, own_inserts)
        if error:
            return self._fail(rec, gen, f"operation-mismatch:{error}", ev)
        # Preflight: verify the VM's whole attachment inventory and every
        # child identity BEFORE any delete, because deleting the VM also
        # deletes its autoDelete disks.
        reason, found = self._inspect(rec, proof)
        if reason:
            return self._fail(rec, gen, f"identity-mismatch:{reason}", ev)
        rec, gen = self._adopt(rec, gen, found)
        quarantine = list(rec.get("quarantine", []))
        if rec.get("capture"):
            c, image = self._capture_status(self._capture_intent(rec))
            prev = dict(rec)
            rec["capture"] = c
            gen = self._cas(prev, rec, gen)
            if image is not None and c["retain_until"] and cfg.now() < _parse(c["retain_until"]):
                if image.get("status") != "READY" or not c.get("insert_receipt"):
                    return Outcome("blocked", "candidate not ready for quarantine")
                if any(x["name"] == c["name"] or x["image_id"] == c["image_id"] for x in quarantine):
                    return Outcome("blocked", "duplicate candidate quarantine")
                quarantine.append(c)
            else:
                rec, gen, c = self._dispose_image(rec, gen, c, image)
        for kind, resource in self._lease_kinds(rec):
            rec, gen, blocked = self._delete_owned(
                rec, gen, kind, resource, found, proof, ev)
            if blocked:
                return blocked
        create_resolved = (
            rec["submit_attempts"] == 0 or rec["ids"]["instance"] is not None
            or bool(own_inserts))
        if not create_resolved:
            # 404, an empty/aged-out operation list or elapsed time is not
            # proof the create failed: an accepted async create may still land.
            # Only a terminal insert tied to this request id resolves it; until
            # then stay occupied (blocked past the deadline: needs the lead).
            if cfg.now() >= _parse(rec["deadline"]):
                return Outcome("blocked", "submitted create has no terminal "
                               "current-request operation; manual review")
            return Outcome("settling", "create outcome unproven")
        if foreign_pending:
            return Outcome("blocked", "unexpected pending operation in zone")
        if "access" in rec:
            rec, gen = self._archive_access(rec, gen)
        history = list(rec.get("access_history", []))
        if "access" in rec:
            history.append(rec["access"])
        free = {"schema": 1, "slot": rec["slot"], "state": FREE,
                "epoch": rec["epoch"], "quarantine": quarantine,
                "access_history": history,
                "used_capture_ids": rec.get("used_capture_ids", []),
                "last_release": {
                    "run_id": rec["run_id"], "attempt": rec["attempt"],
                    "request_id": rec["request_id"], "ids": rec["ids"],
                    "released_at": spec.rfc3339(cfg.now()),
                    "evidence": (rec["evidence"] + ev)[-50:]}}
        self._cas(rec, free, gen)
        return Outcome("released", "; ".join(ev))

    # ---------------------------------------------- immutable access evidence
    def register_access(self, request_id, *, producer_run_id, producer_attempt,
                        self_user, public_key_text, expected_trial=None):
        """B registers one A producer/key before access; no runner is enabled.

        History is retained and never pruned here. At 16 access leases admission
        of another access producer stops for the later retention/accounting gate.
        The key is consumed at registration, even if import never happens.
        """
        from .access_records import validate_binding
        rec, gen = self.store.read(self.cfg.key)
        if (rec is None or rec.get("state") != ACTIVE or rec["request_id"] != request_id or
                rec.get("profile") not in (spec.UBUNTU_BASE_BUILD, spec.UBUNTU_VLAB_CORE) or "access" in rec or
                rec.get("capture") or self.access_records is None):
            raise Refused("access requires confirmed current build and record adapter")
        self._lease_kinds(rec)
        if rec['profile'] == spec.UBUNTU_VLAB_CORE and (producer_run_id, producer_attempt) != (rec['run_id'], rec['attempt']):
            raise Refused("owner registration requires exact creator correlation")
        if rec['profile'] == spec.UBUNTU_VLAB_CORE:
            # Trusted owner-local CAS only. No admission or general controller
            # selector is exposed by the owner entrypoint. Bind its captured
            # creator correlation; this is not a GitHub execution attestation.
            fields = ('profile', 'request_id', 'epoch', 'run_id', 'attempt',
                      'body_hash', 'ids', 'boot_image', 'boot_image_id',
                      'reserved_at', 'deadline', 'operation')
            if expected_trial != {k: rec.get(k) for k in fields}:
                raise Refused('owner registration snapshot changed')
            op = self.cloud.call('zoneOperations', 'get', name=rec['operation'])
            proof, error = self._insert_target_id(rec, [op])
            if error or proof != rec['ids']['instance'] or op.get('error'):
                raise Refused('owner registration requires terminal original insert')
        reason, found = self._inspect(rec, rec["ids"]["instance"])
        if reason or set(found) != {"instance", "boot"}:
            raise Refused("access requires current exact VM/boot ownership")
        _, sha = public_key(public_key_text)
        history = rec.get("access_history", [])
        if not isinstance(history, list) or len(history) >= 16:
            raise Refused("access retention/accounting limit reached")
        for item in history:
            try:
                validate_binding(item["binding"])
                if (item["binding"]["key_sha256"] == sha or
                        item["binding"]["lease"] == request_id):
                    raise Refused("access lease/key must never be reused")
            except (KeyError, TypeError, AccessError):
                raise Refused("invalid retained access accounting") from None
        work = _parse(rec["deadline"]) - timedelta(minutes=15)
        if self.cfg.now() >= work:
            raise Refused("insufficient access work/cleanup budget")
        binding = dict(lease=request_id, epoch=rec["epoch"], run_id=producer_run_id,
                       attempt=producer_attempt, vm_id=rec["ids"]["instance"],
                       boot_id=rec["ids"]["boot"], source_image_id=rec["boot_image_id"],
                       deadline=rec["deadline"], work_deadline=spec.rfc3339(work),
                       self_user=self_user, key_sha256=sha)
        validate_binding(binding)
        prev = dict(rec)
        rec["access"] = dict(binding=binding, phase="registered", archive={})
        context = Context.from_slot(rec)
        # The UUID namespace is immutable. Existing objects are collisions, even
        # if someone claims their contents are equal; never recover import here.
        if any(self.access_records.read(context, k)[0] is not None for k in KINDS):
            raise Refused("access UUID namespace already occupied")
        try:
            self._cas(prev, rec, gen)
        except _Conflict as exc:
            raise Refused("access registration lost ownership") from exc
        return context

    def _access_evidence(self, rec, *, sealed=False):
        if self.access_records is None:
            raise AccessError("access evidence adapter missing; keep occupied")
        context = Context.from_slot(rec)
        values, refs = {}, {}
        for kind in KINDS:
            value, generation = self.access_records.read(context, kind)
            if value is None:
                if kind != "seal" or sealed:
                    raise AccessError("required access receipt missing")
                refs[kind] = {"path": context.path(kind), "generation": 0, "sha256": None}
                continue
            # Adapter validation is repeated here so a fake/alternate adapter
            # cannot accidentally bypass domain binding checks.
            from .access_records import validate_record
            validate_record(value, context, kind)
            if type(generation) is not int or not 0 < generation <= 2**64 - 1:
                raise AccessError("invalid access evidence generation")
            values[kind] = value
            refs[kind] = {"path": context.path(kind), "generation": generation, "sha256": digest(value)}
        intent = values["intent"]
        for kind in ("import", "removed") + (("seal",) if "seal" in values else ()):
            check_receipt(values[kind], context, kind, intent, refs["intent"]["generation"])
        imported, removed = values["import"], values["removed"]
        if (removed["server_name"] != imported["server_name"] or
                removed["fingerprint"] != imported["fingerprint"]):
            raise AccessError("removal receipt server-key mismatch")
        return refs

    def _archive_access(self, rec, gen):
        Context.from_slot(rec)
        # An occupied CAS phase archives receipt references, not producer
        # quiescence. Late writes stay in this lease's retained UUID namespace.
        if rec["access"]["phase"] == "registered":
            prev = dict(rec)
            rec["access"] = dict(rec["access"], phase="finalizing")
            rec.update(state=CLEANUP_FAILED, reason="access-finalizing")
            gen = self._cas(prev, rec, gen)
        refs = self._access_evidence(rec)
        if rec["access"]["phase"] != "archived":
            prev = dict(rec)
            rec["access"] = dict(rec["access"], phase="archived", archive=refs)
            gen = self._cas(prev, rec, gen)
        else:
            # Already archived records are immutable; no replacement is adopted.
            old = rec["access"]["archive"]
            if any(old[k]["generation"] and old[k] != refs[k] for k in KINDS):
                raise AccessError("archived access evidence changed")
        return rec, gen

    def _access_capture_gate(self, rec):
        if "access" not in rec:
            return
        try:
            self._access_evidence(rec, sealed=True)
        except AccessError as exc:
            raise Refused(str(exc)) from exc
        # No trusted pre-login provenance or supported installed sealing manifest
        # implementation has been accepted. Data-only seal hashes cannot invent
        # that authority. A later reviewed implementation must replace this hold.
        raise Refused("trusted pre-login ownership/sealing manifest gate unresolved")

    # ---------------------------------------------------------- image capture
    def _capture_intent(self, rec):
        c = rec.get("capture")
        try:
            spec.validate_capture(c)
            if (rec.get("profile") != spec.UBUNTU_BASE_BUILD or
                    c["lease_id"] != rec["request_id"] or c["run_id"] != rec["run_id"] or
                    c["attempt"] != rec["attempt"] or c["deadline"] != rec["deadline"] or
                    c["source_disk_id"] != rec["ids"]["boot"]):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise Refused("capture does not match owned build record") from None
        return c

    def _quarantines(self, rec):
        entries = rec.get("quarantine", [])
        try:
            import uuid
            used = rec.get("used_capture_ids", [])
            if (not isinstance(used, list) or len(used) > 512 or len(set(used)) != len(used) or
                    any(str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0 for value in used)):
                raise ValueError()
            if not isinstance(entries, list) or len(entries) > 32:
                raise ValueError()
            for c in entries:
                spec.validate_capture(c)
                if c["request_id"] not in used:
                    raise ValueError()
                if not c["submitted"] or not c.get("image_id") or not c.get("insert_receipt") or not c["retain_until"]:
                    raise ValueError()
            if (len({c["name"] for c in entries}) != len(entries) or
                    len({c["image_id"] for c in entries}) != len(entries) or
                    len({c["request_id"] for c in entries}) != len(entries)):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise Refused("invalid or duplicate quarantine inventory") from None
        return entries

    def _image(self, c):
        try:
            return self.cloud.call("images", "get", name=c["name"], capture=c)
        except NotFound:
            return None

    def _verify_image(self, c, image, target_id):
        if (image.get("name") != c["name"] or image.get("id") != target_id or
                target_id in c["preexisting_images"].values() or
                image.get("labels") != spec.capture_body(c)["labels"] or
                image.get("sourceDiskId") != c["source_disk_id"] or
                not spec.resource_link(c["source_disk"], image.get("sourceDisk")) or
                image.get("family") or image.get("sourceImage") or image.get("sourceSnapshot")):
            raise Refused("candidate immutable identity/provenance mismatch")

    def _capture_operations(self, c):
        # aggregatedList is operations.aggregatedList and includes global,
        # regional and zonal operations. Never mistake zoneOperations.list
        # for an enumeration of global images.insert operations.
        ops = self._aggregate("globalOperations", "operations")
        related = []
        path = f"projects/{spec.PROJECT}/global/images/{c['name']}"
        for op in ops:
            own = (op.get("clientOperationId") in
                   (c["request_id"], c["delete_request_id"]) or
                   op.get("targetLink", "").rsplit("/", 1)[-1] == c["name"])
            if own:
                current = self.cloud.call("globalOperations", "get", name=op["name"], capture=c)
                if not spec.resource_link(path, current.get("targetLink")):
                    raise Refused("capture operation target mismatch")
                related.append(current)
            elif op.get("status") != "DONE":
                raise Refused("unexpected pending project operation")
        for field in ("operation", "delete_operation"):
            name = c.get(field)
            receipt = c.get("insert_receipt" if field == "operation" else "delete_receipt")
            if (name and not (receipt and receipt.get("name") == name) and
                    not any(op.get("name") == name for op in related)):
                # Direct GET closes list visibility lag; 404 is uncertainty.
                op = self.cloud.call("globalOperations", "get", name=name, capture=c)
                if not spec.resource_link(path, op.get("targetLink")):
                    raise Refused("capture operation target mismatch")
                related.append(op)
        if any(op.get("status") != "DONE" for op in related):
            raise Refused("capture operation pending")
        return related

    def _capture_status(self, c):
        """Resolve only terminal request-correlated insertion + exact source ID."""
        ops = self._capture_operations(c)
        inserts = [op for op in ops if op.get("operationType") == "insert" and
                   op.get("clientOperationId") == c["request_id"]]
        if c.get("insert_receipt"):
            inserts.append(c["insert_receipt"])
        if c["submitted"] and not inserts:
            raise Refused("capture insert outcome unproven")
        successes = [op for op in inserts if not op.get("error")]
        if successes and len(successes) != len(inserts):
            raise Refused("conflicting capture operation outcomes")
        ids = {op.get("targetId") for op in successes}
        if successes and (len(ids) != 1 or not all(isinstance(i, str) and i.isdecimal() and int(i) > 0 for i in ids)):
            raise Refused("capture target ID missing or conflicting")
        new = dict(c)
        if successes:
            target_id = next(iter(ids))
            if c.get("image_id") not in (None, target_id):
                raise Refused("capture image incarnation changed")
            if target_id in c["preexisting_images"].values():
                raise Refused("capture target is a protected preflight image ID")
            new.update(image_id=target_id, insert_receipt=successes[0])
        image = self._image(new)
        if image is not None:
            if not successes:
                raise Refused("candidate exists without request-correlated creation proof")
            self._verify_image(new, image, new["image_id"])
        if c["delete_submitted"]:
            deletes = [op for op in ops if op.get("operationType") == "delete" and
                       op.get("clientOperationId") == c["delete_request_id"]]
            if c.get("delete_receipt"):
                deletes.append(c["delete_receipt"])
            if (not deletes or any(op.get("error") or op.get("targetId") != new["image_id"]
                                   for op in deletes)):
                raise Refused("candidate deletion outcome unproven or failed")
            new["delete_receipt"] = deletes[0]
            if image is not None:
                raise Refused("candidate remains after terminal deletion")
        return new, image

    def prepare_capture(self, request_id, capture_id, *, retain_until=None):
        """Explicit opt-in. No guest sealing or image publication is implied."""
        import uuid
        rec, gen = self.store.read(self.cfg.key)
        if rec is None or rec.get("state") != ACTIVE or rec["request_id"] != request_id:
            raise Refused("capture requires current ACTIVE build")
        self._lease_kinds(rec)
        self._quarantines(rec)
        self._access_capture_gate(rec)
        if (rec.get("profile") != spec.UBUNTU_BASE_BUILD or rec.get("capture") or
                capture_id in rec.get("used_capture_ids", []) or
                len(rec.get("used_capture_ids", [])) >= 512):
            raise Refused("capture requires unused name and retained build without previous intent")
        if self.cfg.now() + timedelta(minutes=spec.CAPTURE_RESERVE_MINUTES) >= _parse(rec["deadline"]):
            raise Refused("insufficient capture/cleanup budget")
        if not all(rec["ids"].values()):
            raise Refused("capture requires confirmed immutable build IDs")
        ops = self._list_all("zoneOperations")
        if any(op.get("status") != "DONE" for op in ops):
            raise Refused("build operations pending")
        proof, error = self._insert_target_id(rec, [op for op in ops if
            op.get("operationType") == "insert" and op.get("clientOperationId") == request_id])
        if error or proof != rec["ids"]["instance"]:
            raise Refused("build insertion proof unavailable")
        reason, found = self._inspect(rec, proof)
        if reason or "boot" not in found:
            raise Refused("source boot identity unresolved")
        c = dict(request_id=capture_id, lease_id=request_id, run_id=rec["run_id"],
                 attempt=rec["attempt"], name="labapp-candidate-" + capture_id,
                 source_disk=f"projects/{spec.PROJECT}/zones/{spec.ZONE}/disks/{rec['names']['boot']}",
                 source_disk_id=rec["ids"]["boot"], deadline=rec["deadline"],
                 prepared_at=spec.rfc3339(self.cfg.now()),
                 retain_until=spec.rfc3339(retain_until) if retain_until is not None else None,
                 preexisting_images={}, submitted=False, operation=None,
                 image_id=None, insert_receipt=None, delete_submitted=False,
                 delete_request_id=str(uuid.uuid5(uuid.UUID(capture_id), "delete")),
                 delete_operation=None, delete_receipt=None)
        c["body_hash"] = spec.body_hash(spec.capture_body(c))
        try:
            spec.validate_capture(c)
            images = self._list_all("images", capture=c)
            c["preexisting_images"] = {im["name"]: im["id"] for im in images}
            spec.validate_capture(c)
            # Read exact output before committing intent; existing names/IDs
            # are never adopted even if they carry plausible labels.
            if self._image(c) is not None:
                raise Refused("candidate output already exists")
            self._capture_operations(c)
        except ValueError as exc:
            raise Refused(str(exc)) from exc
        prev = dict(rec)
        rec["capture"] = c
        rec["used_capture_ids"] = rec.get("used_capture_ids", []) + [capture_id]
        try:
            self._cas(prev, rec, gen)
        except _Conflict as exc:
            raise Refused("capture preparation lost ownership") from exc
        return Outcome("capture-prepared", c["name"])

    def capture(self, request_id):
        """Delete builder retaining boot, fence submission, then insert once.

        Cancellation CAS-fences ACTIVE before cleanup. A paused actor cannot
        resume insertion after cancellation or after another submission.
        """
        rec, gen = self.store.read(self.cfg.key)
        if rec is None or rec.get("state") != ACTIVE or rec["request_id"] != request_id:
            raise Refused("capture requires current ACTIVE build")
        self._lease_kinds(rec)
        self._access_capture_gate(rec)
        c = self._capture_intent(rec)
        if c["submitted"]:
            raise Refused("capture already submitted; reconcile instead")
        if self.cfg.now() + timedelta(minutes=spec.CAPTURE_RESERVE_MINUTES) >= _parse(c["deadline"]):
            raise Refused("insufficient capture/cleanup budget")
        ops = self._list_all("zoneOperations")
        if any(op.get("status") != "DONE" for op in ops):
            return Outcome("pending-operation")
        proof, error = self._insert_target_id(rec, [op for op in ops if
            op.get("operationType") == "insert" and op.get("clientOperationId") == request_id])
        if error or proof != rec["ids"]["instance"]:
            raise Refused("build insertion proof unavailable")
        reason, found = self._inspect(rec, proof)
        if reason or "boot" not in found:
            raise Refused("source boot identity unresolved")
        self._capture_operations(c)
        if self._image(c) is not None:
            raise Refused("candidate output collision")
        rec, gen, blocked = self._delete_owned(rec, gen, "instance", "instances", found, proof, [])
        if blocked:
            return blocked
        # Both the absolute budget and exact retained disk are rechecked AFTER
        # deletion. No forceCreate is accepted; the source must be unattached.
        if self._get("instances", rec["names"]["instance"]) is not None:
            raise Refused("builder is still present")
        disk = self._get("disks", rec["names"]["boot"])
        if disk is None or self._verify("boot", disk, rec, proof) or disk.get("users"):
            raise Refused("source boot changed or attached")
        if self.cfg.now() + timedelta(minutes=spec.CAPTURE_RESERVE_MINUTES) >= _parse(c["deadline"]):
            raise Refused("insufficient capture/cleanup budget")
        prev = dict(rec)
        c = dict(c, submitted=True)
        rec["capture"] = c
        try:
            gen = self._cas(prev, rec, gen)  # only winner may POST
        except _Conflict as exc:
            raise Refused("capture submission lost ownership") from exc
        try:
            op = self.cloud.call("images", "insert", body=spec.capture_body(c),
                                 request_id=c["request_id"], capture=c)
        except (ApiError, Uncertain) as exc:
            return Outcome("uncertain", str(exc))
        prev = dict(rec)
        rec["capture"] = dict(c, operation=op["name"])
        try:
            self._cas(prev, rec, gen)
        except _Conflict:
            return Outcome("uncertain", "capture operation not persisted; reconcile")
        disk = self._get("disks", rec["names"]["boot"])
        if disk is None or self._verify("boot", disk, rec, proof) or disk.get("users"):
            return Outcome("blocked", "source boot changed after capture")
        return Outcome("capture-submitted", op["name"])

    def _dispose_image(self, rec, gen, c, image, *, quarantine_index=None):
        """Persist delete intent before sending; unknown deletes hold identity."""
        if image is None:
            return rec, gen, c
        if image.get("status") != "READY":
            raise Refused("candidate image not READY")
        if c["delete_submitted"]:
            raise Refused("candidate delete already submitted but unresolved")
        c = dict(c, delete_submitted=True)
        prev = dict(rec)
        if quarantine_index is None:
            rec["capture"] = c
        else:
            rec["quarantine"] = list(rec["quarantine"])
            rec["quarantine"][quarantine_index] = c
        gen = self._cas(prev, rec, gen)
        # Recheck exact incarnation immediately before delete (API has no
        # numeric-ID conditional delete; isolated owned namespace is a live gate).
        latest = self._image(c)
        if latest is None:
            raise Refused("candidate disappeared before delete submission")
        self._verify_image(c, latest, c["image_id"])
        op = self.cloud.call("images", "delete", name=c["name"],
                             request_id=c["delete_request_id"], capture=c)
        prev = dict(rec)
        c = dict(c, delete_operation=op["name"])
        if quarantine_index is None:
            rec["capture"] = c
        else:
            rec["quarantine"] = list(rec["quarantine"])
            rec["quarantine"][quarantine_index] = c
        gen = self._cas(prev, rec, gen)
        c, image = self._capture_status(c)
        if image is not None:
            raise Refused("candidate deletion not confirmed")
        prev = dict(rec)
        if quarantine_index is None:
            rec["capture"] = c
        else:
            rec["quarantine"] = list(rec["quarantine"])
            rec["quarantine"][quarantine_index] = c
        gen = self._cas(prev, rec, gen)  # retain terminal proof across op expiry
        return rec, gen, c

    def reconcile_quarantine(self):
        """Independent expiry entry point, including while a VM owns the slot.

        No scheduler/monitor is installed here. A future trusted runner must
        call independently, monitor overdue/failures and escalate uncertainty.
        """
        for _ in range(self.cfg.cas_retries):
            rec, gen = self.store.read(self.cfg.key)
            if rec is None:
                return Outcome("free")
            try:
                entries = self._quarantines(rec)
                for index, c in enumerate(entries):
                    if self.cfg.now() < _parse(c["retain_until"]):
                        continue
                    current, image = self._capture_status(c)
                    rec, gen, current = self._dispose_image(rec, gen, current, image,
                                                            quarantine_index=index)
                    prev = dict(rec)
                    rec["quarantine"] = [x for x in rec["quarantine"] if x["request_id"] != c["request_id"]]
                    self._cas(prev, rec, gen)
                    return Outcome("quarantine-deleted", c["name"])
                return Outcome("not-due")
            except _Conflict:
                continue
            except (Refused, ApiError, Uncertain, AccessError) as exc:
                return Outcome("blocked", str(exc))
        return Outcome("blocked", "persistent quarantine conflicts")
