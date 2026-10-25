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
        self.images: dict = {}
        self.image_ops: dict = {}
        self.capture_mode = "ok"
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
        self.remote: dict = {}             # other zone -> {kind: {name: res}}
        self.page_size: Optional[int] = None  # paginate list responses
        self.unreachables: list = []       # aggregatedList scopes that failed
        self.list_error: set = set()       # (resource, verb) that raise 500

    # ------------------------------------------------------------ test setup
    def _id(self) -> str:
        self._seq += 1
        return str(self._seq * 7919)

    def _stamp(self) -> str:
        return spec.rfc3339(self.clock.now())

    def add_foreign(self, kind: str, name: str, labels: Optional[dict] = None,
                    zone: Optional[str] = None) -> str:
        res = self._make(name, labels or {}, zone or spec.ZONE)
        if zone and zone != spec.ZONE:
            store = self.remote.setdefault(
                zone, {"instances": {}, "disks": {}})[kind]
        else:
            store = self.instances if kind == "instances" else self.disks
        store[name] = res
        return res["id"]

    def _make(self, name: str, labels: dict, zone: str = spec.ZONE) -> dict:
        return {"name": name, "id": self._id(), "labels": dict(labels),
                "zone": f"https://compute/zones/{zone}",
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

    def _materialize(self, body: dict) -> str:
        inst = self._make(body["name"], body["labels"])
        inst["scheduling"] = dict(body["scheduling"])
        inst["disks"] = []
        for d in body["disks"]:
            p = d["initializeParams"]
            disk = self._make(p["diskName"], p["labels"])
            disk["sourceImage"] = p["sourceImage"]
            if p["sourceImage"] == spec.COMPONENT_IMAGE:
                disk["sourceImageId"] = spec.COMPONENT_IMAGE_ID
            self.disks[disk["name"]] = disk
            inst["disks"].append({
                "source": f"https://compute/zones/{spec.ZONE}/disks/"
                          f"{disk['name']}",
                "autoDelete": d["autoDelete"], "boot": d["boot"],
                "mode": d["mode"], "deviceName": d["deviceName"]})
        self.instances[inst["name"]] = inst
        return inst["id"]

    def finish_pending(self, success: bool = True) -> None:
        """Late completion of a create that the caller saw time out."""
        for opname, body in list(self._pending_bodies.items()):
            if success:
                target_id = self._materialize(body)
                self.ops[opname].update(status="DONE", targetId=target_id)
            else:
                self.ops[opname].update(status="DONE", error={"errors": [1]})
            del self._pending_bodies[opname]

    # --------------------------------------------------------------- dispatch
    def call(self, resource: str, verb: str, *, project: str, zone: str,
             name: Optional[str] = None, body: Optional[dict] = None,
             request_id: Optional[str] = None,
             page_token: Optional[str] = None, capture: Optional[dict] = None) -> dict:
        assert project == spec.PROJECT and zone == spec.ZONE
        self.calls.append((resource, verb, name or (body or {}).get("name")))
        if (resource, verb) in self.list_error:
            raise ApiError(500, "list failed")
        if verb in ("list", "aggregatedList"):
            return getattr(self, f"_{resource}_{verb}")(page_token)
        return getattr(self, f"_{resource}_{verb}")(name, body, request_id)

    def _paginate(self, seq: list, token: Optional[str]):
        if not self.page_size:
            return seq, None
        start = int(token or 0)
        end = start + self.page_size
        return seq[start:end], (str(end) if end < len(seq) else None)

    def _list(self, values, token):
        page, nxt = self._paginate(list(values), token)
        out = {"items": page}
        if nxt:
            out["nextPageToken"] = nxt
        return out

    def _aggregate(self, key: str, local: list, remote_kind: Optional[str],
                   token: Optional[str]) -> dict:
        scopes = {f"zones/{spec.ZONE}": local}
        for zone, kinds in self.remote.items():
            scopes[f"zones/{zone}"] = (
                list(kinds[remote_kind].values()) if remote_kind else [])
        names, nxt = self._paginate(list(scopes), token)
        items = {}
        for scope in names:
            items[scope] = ({key: scopes[scope]} if scopes[scope] else
                            {"warning": {"code": "NO_RESULTS_ON_PAGE"}})
        out = {"items": items}
        if self.unreachables:
            out["unreachables"] = list(self.unreachables)
        if nxt:
            out["nextPageToken"] = nxt
        return out

    def _instances_list(self, token):
        return self._list(self.instances.values(), token)

    def _disks_list(self, token):
        return self._list(self.disks.values(), token)

    def _zoneOperations_list(self, token):
        return self._list(self.ops.values(), token)

    def _instances_aggregatedList(self, token):
        return self._aggregate("instances", list(self.instances.values()),
                               "instances", token)

    def _disks_aggregatedList(self, token):
        return self._aggregate("disks", list(self.disks.values()), "disks",
                               token)

    def _globalOperations_aggregatedList(self, token):
        return self._aggregate("operations", list(self.ops.values()) + list(self.image_ops.values()), None,
                               token)

    def _zoneOperations_get(self, name, *_):
        if name not in self.ops:
            raise NotFound(name)
        op = dict(self.ops[name])
        if name in self.op_stuck:
            op["status"] = "RUNNING"
        return op

    def _images_get(self, name, *_):
        if name != spec.COMPONENT_IMAGE.rsplit("/", 1)[-1]:
            if name not in self.images:
                raise NotFound(name)
            return dict(self.images[name])
        return {"name": name, "id": spec.COMPONENT_IMAGE_ID, "status": "READY",
                "architecture": "X86_64", "diskSizeGb": "10"}

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
        op["targetId"] = self._materialize(body)
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
                # A normal VM delete removes boot, retains the READ_ONLY copy.
                # leak_disks additionally models a failed boot auto-delete.
                if d.get("autoDelete") is True:
                    self.disks.pop(d["source"].rsplit("/", 1)[-1], None)
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


    def _images_list(self, token):
        return self._list(self.images.values(), token)

    def _globalOperations_get(self, name, *_):
        if name not in self.image_ops:
            raise NotFound(name)
        op = dict(self.image_ops[name])
        if name in self.op_stuck:
            op["status"] = "RUNNING"
        return op

    def _image_op(self, verb, name, request_id, target_id):
        op = self._op(verb, name, client_id=request_id)
        del self.ops[op["name"]]
        op.update(targetLink=f"https://compute.googleapis.com/compute/v1/projects/{spec.PROJECT}/global/images/{name}",
                  targetId=target_id)
        self.image_ops[op["name"]] = op
        return dict(op)

    def _images_insert(self, _name, body, request_id):
        if self.capture_mode == "timeout_nothing":
            raise Uncertain("lost capture response")
        if body["name"] in self.images:
            raise ApiError(409, "image exists")
        disk = self.disks[body["sourceDisk"].rsplit("/", 1)[-1]]
        image = dict(body, id=self._id(), sourceDiskId=disk["id"], status="READY")
        self.images[image["name"]] = image
        op = self._image_op("insert", image["name"], request_id, image["id"])
        if self.capture_mode == "pending":
            self.image_ops[op["name"]]["status"] = "RUNNING"
        if self.capture_mode == "lost":
            raise Uncertain("capture response lost after creation")
        return op

    def _images_delete(self, name, _body, request_id):
        if name in self.delete_fail:
            raise ApiError(500, "image delete failed")
        if name not in self.images:
            raise NotFound(name)
        op = self._image_op("delete", name, request_id, self.images[name]["id"])
        if name in self.delete_op_error:
            self.image_ops[op["name"]]["error"] = {"errors": [1]}
        if name not in self.delete_noop:
            del self.images[name]
        return op
