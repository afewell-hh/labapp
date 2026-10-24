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
    max_submit_attempts: int = 1  # same-UUID retry semantics are unverified
    min_submit_minutes: int = 10
    poll_attempts: int = 30
    poll_seconds: float = 5.0
    cas_retries: int = 5
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


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

    def _wait(self, op_name: str) -> Optional[dict]:
        for _ in range(self.cfg.poll_attempts):
            try:
                op = self.cloud.call("zoneOperations", "get", name=op_name)
            except NotFound:
                return None
            if op.get("status") == "DONE":
                return op
            self.cfg.sleep(self.cfg.poll_seconds)
        return None

    def _verify(self, kind: str, res: dict, rec: dict) -> Optional[str]:
        """Return None if res provably belongs to this lease, else a reason."""
        if res.get("name") != rec["names"][kind] or \
                not spec.is_owned_name(res.get("name", "")):
            return "name"
        if res.get("labels", {}).get(spec.LABEL_LEASE) != rec["request_id"]:
            return "lease-label"
        if res.get("zone", "").rsplit("/", 1)[-1] != rec["zone"]:
            return "zone"
        known = rec["ids"].get(kind)
        if known:
            if res.get("id") != known:
                return "id"
        elif _parse(res.get("creationTimestamp", "1970-01-01T00:00:00Z")) < \
                _parse(rec["reserved_at"]):
            return "predates-lease"
        return None

    def _adopt(self, rec: dict, gen: int, kind: str, res: dict):
        if rec["ids"].get(kind) is None:
            prev = dict(rec)
            rec["ids"] = dict(rec["ids"], **{kind: res["id"]})
            gen = self._cas(prev, rec, gen)
        return rec, gen

    # -------------------------------------------------------------- admission
    def _census(self) -> None:
        """Fail closed on any resource or operation we cannot attribute."""
        base = self.cfg.baseline
        for resource in ("instances", "disks"):
            for item in self.cloud.call(resource, "list").get("items", []):
                if base.get(item["name"]) != item.get("id"):
                    raise Refused(
                        f"unknown {resource} {item['name']}: ownership not "
                        "established, admission blocked")
        for op in self.cloud.call("zoneOperations", "list").get("items", []):
            if op.get("status") != "DONE":
                raise Refused(f"pending operation {op.get('name')} in zone")

    def admit(self, run_id: int, attempt: int, request_id: str) -> dict:
        """Persist the full intent (UUID, body hash, names, deadline) first."""
        cfg = self.cfg
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
        deadline = now + timedelta(minutes=spec.LEASE_MINUTES)
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

    def confirm_created(self, request_id: str) -> Outcome:
        """Wait for the insert and persist VM + both disk IDs."""
        for _ in range(self.cfg.cas_retries):
            rec, gen = self.store.read(self.cfg.key)
            if rec is None or rec["state"] != ACTIVE or \
                    rec["request_id"] != request_id:
                raise Refused("no ACTIVE lease with this request id")
            done = self._wait(rec["operation"])
            if done is None:
                return Outcome("pending-operation", rec["operation"])
            if done.get("error"):
                return Outcome("create-failed", str(done["error"]))
            try:
                for kind, resource in (("instance", "instances"),
                                       ("boot", "disks"), ("data", "disks")):
                    res = self._get(resource, rec["names"][kind])
                    if res is None:
                        return Outcome("missing", kind)
                    reason = self._verify(kind, res, rec)
                    if reason:
                        return Outcome("identity-mismatch", f"{kind}:{reason}")
                    rec, gen = self._adopt(rec, gen, kind, res)
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

    def _delete_owned(self, rec, gen, kind, resource, ev):
        """Delete one resource by exact name after identity verification.

        Returns (rec, gen, None) when it is confirmed absent, or
        (rec, gen, Outcome) when the slot must stay occupied.
        """
        name = rec["names"][kind]
        res = self._get(resource, name)
        if res is None:
            ev.append(f"{kind} {name}: absent (404)")
            return rec, gen, None
        reason = self._verify(kind, res, rec)
        if reason:  # no delete call is made for an unverified resource
            return rec, gen, self._fail(
                rec, gen, f"identity-mismatch:{kind}:{reason}", ev)
        rec, gen = self._adopt(rec, gen, kind, res)
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
        for op in self.cloud.call("zoneOperations", "list").get("items", []):
            target = op.get("targetLink", "").rsplit("/", 1)[-1]
            if op.get("clientOperationId") == rec["request_id"] or \
                    target in owned:
                related.append(op)
            elif op.get("status") != "DONE":
                foreign_pending.append(op)
        if any(op.get("status") != "DONE" for op in related):
            return Outcome("pending-operation", "owned operation still running")
        for kind, resource in (("instance", "instances"), ("boot", "disks"),
                               ("data", "disks")):
            rec, gen, blocked = self._delete_owned(rec, gen, kind, resource, ev)
            if blocked:
                return blocked
        inserts = [op for op in related if op.get("operationType") == "insert"]
        create_resolved = (
            rec["submit_attempts"] == 0 or rec["ids"]["instance"] is not None
            or bool(inserts) or cfg.now() >= _parse(rec["deadline"]))
        if not create_resolved:
            # 404 / empty operation list is not proof a create failed: it may
            # still land. The past-deadline terminationTime rejects late ones.
            return Outcome("settling", "create outcome unproven before deadline")
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
