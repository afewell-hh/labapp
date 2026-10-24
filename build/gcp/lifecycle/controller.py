"""Single-slot VM lease state machine shared by creator, cleanup and janitor.

One persistent slot record (generation-matched writes) moves through

    FREE -> RESERVED -> ACTIVE -> FREE
                 \\-> CLEANUP_FAILED -> FREE      (any occupied state)

Only ``reconcile`` can return a slot to FREE, and only after the VM and both
owned disks are confirmed absent (404 after the delete operation is DONE) and
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
from .cloud import ApiError, NotFound, PolicyCloud, Uncertain
from .store import PreconditionFailed, SlotStore

KINDS = (("instance", "instances"), ("boot", "disks"), ("data", "disks"))
FREE, RESERVED, ACTIVE, CLEANUP_FAILED = (
    "FREE", "RESERVED", "ACTIVE", "CLEANUP_FAILED")
NOT_RUNNING = frozenset({"STOPPING", "STOPPED", "TERMINATED", "SUSPENDING",
                         "SUSPENDED", "REPAIRING"})
# Fields that must never change while a lease is held (absolute deadline etc.).
IMMUTABLE = ("slot", "epoch", "project", "zone", "run_id", "attempt",
             "request_id", "body_hash", "names", "boot_image", "reserved_at",
             "deadline", "max_submit_attempts")


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
    lease_minutes: int = spec.LEASE_MINUTES
    min_submit_minutes: int = 10
    poll_attempts: int = 30
    poll_seconds: float = 5.0
    cas_retries: int = 5
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def __post_init__(self) -> None:
        self.validate_lease()

    def validate_lease(self) -> None:
        if (type(self.lease_minutes) is not int or
                not 1 <= self.lease_minutes <= spec.LEASE_MINUTES):
            raise ValueError("lease_minutes must be an integer from 1 to 60")
        if (type(self.min_submit_minutes) is not int or
                not 0 <= self.min_submit_minutes < self.lease_minutes):
            raise ValueError("submission margin must be shorter than the lease")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class Controller:
    def __init__(self, store: SlotStore, cloud: PolicyCloud, cfg: Config):
        self.store, self.cloud, self.cfg = store, cloud, cfg

    # ---------------------------------------------------------------- helpers
    def _cas(self, prev: dict, rec: dict, gen: int) -> int:
        if prev.get("state") != FREE and rec.get("state") != FREE:
            for name in IMMUTABLE:
                if prev.get(name) != rec.get(name):
                    raise AssertionError(f"immutable field {name} changed")
        try:
            return self.store.write(self.cfg.key, rec, if_generation_match=gen)
        except PreconditionFailed as exc:
            raise _Conflict(str(exc)) from exc

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
        """The VM must carry exactly the two intended disks, nothing else.

        Deleting a VM also deletes its autoDelete disks, so this runs before
        the VM delete and any unexpected or mismatched child blocks it.
        """
        attached = inst.get("disks")
        if not isinstance(attached, list) or len(attached) != 2:
            return "attachments"
        names = rec["names"]
        want = {names["boot"]: True, names["data"]: False}
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
            # Only the read-write boot disk may auto-delete. The READ_ONLY
            # copy must survive VM deletion for explicit verified disk cleanup.
            if att.get("autoDelete") is not want[name]:
                return "attachment-autodelete"
        return None

    def _inspect(self, rec: dict, proof: Optional[str]):
        """Fetch and verify the lease's three resources without changing any.

        Returns (reason, found). reason is None only when every resource that
        exists is provably this lease's and an existing VM has exactly the two
        intended disks attached (each of which must then exist and verify).
        """
        found = {}
        for kind, resource in KINDS:
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
            for kind in ("boot", "data"):
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
    def _pages(self, resource: str, verb: str):
        """Yield every page; any failure or runaway paging blocks the caller."""
        token = None
        for _ in range(self.cfg.max_pages):
            try:
                page = self.cloud.call(resource, verb, page_token=token)
            except (ApiError, Uncertain) as exc:
                raise Refused(f"cannot list {resource}.{verb}: {exc}") from exc
            yield page
            token = page.get("nextPageToken")
            if not token:
                return
        raise Refused(f"{resource}.{verb} exceeded {self.cfg.max_pages} pages")

    def _list_all(self, resource: str) -> list:
        return [i for p in self._pages(resource, "list")
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
        self._census()
        now = cfg.now()
        deadline = now + timedelta(minutes=cfg.lease_minutes)
        body = spec.build_body(boot_image=cfg.boot_image, request_id=request_id,
                               run_id=run_id, attempt=attempt, deadline=deadline)
        lease = {
            "schema": 1, "slot": cfg.key, "state": RESERVED,
            "epoch": rec["epoch"] + 1, "project": cfg.project, "zone": cfg.zone,
            "run_id": run_id, "attempt": attempt, "request_id": request_id,
            "body_hash": spec.body_hash(body), "boot_image": cfg.boot_image,
            "names": spec.names(run_id, attempt),
            "reserved_at": spec.rfc3339(now), "deadline": spec.rfc3339(deadline),
            "submit_attempts": 0, "max_submit_attempts": cfg.max_submit_attempts,
            "operation": None, "ids": {"instance": None, "boot": None,
                                       "data": None},
            "reason": None, "evidence": [],
        }
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
        deadline = _parse(rec["deadline"])
        if cfg.now() + timedelta(minutes=cfg.min_submit_minutes) > deadline:
            raise Refused("too little lease time left to create")
        if rec["submit_attempts"] >= rec["max_submit_attempts"]:
            raise Refused("submit attempts exhausted; reconcile instead")
        body = spec.build_body(
            boot_image=rec["boot_image"], request_id=rec["request_id"],
            run_id=rec["run_id"], attempt=rec["attempt"], deadline=deadline)
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
                for kind, _resource in KINDS:
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
                return self._reconcile_once(rec, gen, force)
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
        for kind, resource in KINDS:
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
        free = {"schema": 1, "slot": rec["slot"], "state": FREE,
                "epoch": rec["epoch"],
                "last_release": {
                    "run_id": rec["run_id"], "attempt": rec["attempt"],
                    "request_id": rec["request_id"], "ids": rec["ids"],
                    "released_at": spec.rfc3339(cfg.now()),
                    "evidence": (rec["evidence"] + ev)[-50:]}}
        self._cas(rec, free, gen)
        return Outcome("released", "; ".join(ev))
