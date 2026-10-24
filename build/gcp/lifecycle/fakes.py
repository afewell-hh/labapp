"""In-memory fake of the allowlisted Compute calls, with failure injection.

The fake models documented behavior (operations, 404s, autoDelete) and the
failure modes the controller must survive. It is NOT evidence of how the real
API behaves; see the README for the live-pilot gates.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from . import spec
from .cloud import ApiError, NotFound, Uncertain


class FakeClock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 24, 20, 0, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.t

    def advance(self, minutes: float) -> None:
        self.t += timedelta(minutes=minutes)

    def sleep(self, _seconds: float) -> None:
        self.t += timedelta(seconds=1)


class FakeCloud:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.instances: dict = {}
        self.disks: dict = {}
        self.ops: dict = {}
        self.calls: list = []  # (resource, verb, name)
        self._seq = 100
        self._pending_bodies: dict = {}
        # Failure injection.
        self.insert_mode = "ok"  # ok | http500 | timeout_nothing | timeout_pending
        self.delete_fail: set = set()      # kinds/names whose delete raises 500
        self.delete_noop: set = set()      # names that report DONE but remain
        self.leak_disks = False            # VM delete leaves autoDelete disks
        self.op_stuck: set = set()         # op names that never reach DONE
        self.delete_op_error: set = set()  # names whose delete op ends in error

    # ------------------------------------------------------------ test setup
    def _id(self) -> str:
        self._seq += 1
        return str(self._seq * 7919)

    def _stamp(self) -> str:
        return spec.rfc3339(self.clock.now())

    def add_foreign(self, kind: str, name: str, labels: Optional[dict] = None) -> str:
        res = self._make(name, labels or {})
        (self.instances if kind == "instances" else self.disks)[name] = res
        return res["id"]

    def _make(self, name: str, labels: dict) -> dict:
        return {"name": name, "id": self._id(), "labels": dict(labels),
                "zone": f"https://compute/zones/{spec.ZONE}",
                "creationTimestamp": self._stamp(), "status": "RUNNING"}

    def _op(self, kind: str, target: str, status: str = "DONE",
            client_id: Optional[str] = None, error: bool = False) -> dict:
        name = f"operation-{self._id()}"
        op = {"name": name, "status": status, "operationType": kind,
              "targetLink": f"https://compute/zones/{spec.ZONE}/instances/{target}",
              "clientOperationId": client_id}
        if error:
            op["error"] = {"errors": [{"code": "FAKE"}]}
        self.ops[name] = op
        return op

    def _materialize(self, body: dict) -> None:
        inst = self._make(body["name"], body["labels"])
        inst["disks"] = []
        for d in body["disks"]:
            p = d["initializeParams"]
            disk = self._make(p["diskName"], p["labels"])
            self.disks[disk["name"]] = disk
            inst["disks"].append({"source": disk["name"],
                                  "autoDelete": d["autoDelete"]})
        self.instances[inst["name"]] = inst

    def finish_pending(self, success: bool = True) -> None:
        """Late completion of a create that the caller saw time out."""
        for opname, body in list(self._pending_bodies.items()):
            if success:
                self._materialize(body)
                self.ops[opname]["status"] = "DONE"
            else:
                self.ops[opname].update(status="DONE", error={"errors": [1]})
            del self._pending_bodies[opname]

    # --------------------------------------------------------------- dispatch
    def call(self, resource: str, verb: str, *, project: str, zone: str,
             name: Optional[str] = None, body: Optional[dict] = None,
             request_id: Optional[str] = None) -> dict:
        assert project == spec.PROJECT and zone == spec.ZONE
        self.calls.append((resource, verb, name or (body or {}).get("name")))
        return getattr(self, f"_{resource}_{verb}")(name, body, request_id)

    def _instances_list(self, *_):
        return {"items": list(self.instances.values())}

    def _disks_list(self, *_):
        return {"items": list(self.disks.values())}

    def _zoneOperations_list(self, *_):
        return {"items": list(self.ops.values())}

    def _zoneOperations_get(self, name, *_):
        if name not in self.ops:
            raise NotFound(name)
        op = dict(self.ops[name])
        if name in self.op_stuck:
            op["status"] = "RUNNING"
        return op

    def _instances_get(self, name, *_):
        if name not in self.instances:
            raise NotFound(name)
        return dict(self.instances[name])

    def _disks_get(self, name, *_):
        if name not in self.disks:
            raise NotFound(name)
        return dict(self.disks[name])

    def _instances_insert(self, _name, body, request_id):
        if self.insert_mode == "http500":
            raise ApiError(500, "backend error")
        if self.insert_mode == "timeout_nothing":
            raise Uncertain("timeout; request never applied")
        if self.insert_mode == "timeout_pending":
            op = self._op("insert", body["name"], "RUNNING", request_id)
            self._pending_bodies[op["name"]] = body
            raise Uncertain("timeout; request may be applied")
        op = self._op("insert", body["name"], "DONE", request_id)
        self._materialize(body)
        return dict(op)

    def _instances_delete(self, name, *_):
        if name in self.delete_fail:
            raise ApiError(500, "delete failed")
        inst = self.instances.get(name)
        if inst is None:
            raise NotFound(name)
        op = self._op("delete", name, error=name in self.delete_op_error)
        if name in self.delete_noop:
            return dict(op)
        del self.instances[name]
        if not self.leak_disks:
            for d in inst.get("disks", []):
                if d["autoDelete"]:
                    self.disks.pop(d["source"], None)
        return dict(op)

    def _disks_delete(self, name, *_):
        if name in self.delete_fail:
            raise ApiError(500, "delete failed")
        if name not in self.disks:
            raise NotFound(name)
        op = self._op("delete", name, error=name in self.delete_op_error)
        if name not in self.delete_noop:
            del self.disks[name]
        return dict(op)
