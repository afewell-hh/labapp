"""Cloud transport boundary: a single allowlisted call surface.

The controller never talks to a cloud client directly. Every call goes through
``PolicyCloud``, which rejects any resource/verb outside the reviewed set and
any project/zone outside the fixed scope. The fixed public Ubuntu image read
remains separate from identity-bound candidate capture/get/delete and its census. Snapshots, addresses,
firewalls, IAM, and instance stop/start/setScheduling/setMetadata are absent
by construction.
"""
from __future__ import annotations

from typing import Any, Optional, Protocol

from . import spec


class ApiError(Exception):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class NotFound(ApiError):
    def __init__(self, what: str = "") -> None:
        super().__init__(404, what)


class Uncertain(Exception):
    """Timeout / connection loss: the request may or may not have been applied."""


class ForbiddenOperation(Exception):
    pass


ALLOWED: frozenset = frozenset({
    ("images", "get"), ("images", "list"),
    ("images", "insert"), ("images", "delete"),
    ("globalOperations", "get"),
    ("instances", "insert"), ("instances", "get"),
    ("instances", "list"), ("instances", "delete"),
    ("disks", "get"), ("disks", "list"), ("disks", "delete"),
    ("zoneOperations", "get"), ("zoneOperations", "list"),
    # Read-only project-wide views used only by the admission census.
    ("instances", "aggregatedList"), ("disks", "aggregatedList"),
    ("globalOperations", "aggregatedList"),
})


class RawTransport(Protocol):
    def call(self, resource: str, verb: str, *, project: str, zone: str,
             name: Optional[str] = None, body: Optional[dict] = None,
             request_id: Optional[str] = None,
             page_token: Optional[str] = None,
             capture: Optional[dict] = None) -> dict:
        ...


class PolicyCloud:
    def __init__(self, raw: RawTransport, project: str, zone: str) -> None:
        # The policy boundary is the reviewed constant, not the caller's input.
        if (project, zone) != (spec.PROJECT, spec.ZONE):
            raise ForbiddenOperation(
                "PolicyCloud scope must be the approved project and zone")
        self._raw = raw
        self.project = project
        self.zone = zone

    def call(self, resource: str, verb: str, **kw: Any) -> dict:
        if (resource, verb) not in ALLOWED:
            raise ForbiddenOperation(f"{resource}.{verb} is not permitted")
        if kw.get("project", self.project) != self.project or \
                kw.get("zone", self.zone) != self.zone:
            raise ForbiddenOperation("project/zone outside the fixed scope")
        if resource == "images" and not (verb == "get" and
                kw.get("name") == spec.COMPONENT_IMAGE.rsplit("/", 1)[-1] and
                set(kw) == {"name"}):
            validate_image_call(verb, kw)
        if resource == "globalOperations" and verb == "get":
            try:
                spec.validate_capture(kw.get("capture"))
            except ValueError as exc:
                raise ForbiddenOperation(str(exc)) from exc
        kw["project"], kw["zone"] = self.project, self.zone
        return self._raw.call(resource, verb, **kw)


def validate_image_call(verb, kw):
    try:
        c = kw.get("capture")
        spec.validate_capture(c)
        if set(kw) - {"name", "body", "request_id", "page_token", "capture", "project", "zone"}:
            raise ValueError("unexpected image parameters")
        if verb != "list" and kw.get("page_token") is not None:
            raise ValueError("unexpected image page token")
        if kw.get("name") != (None if verb in ("insert", "list") else c["name"]):
            raise ValueError("image name outside capture")
        if verb == "insert":
            if (kw.get("body") != spec.capture_body(c) or
                    kw.get("request_id") != c["request_id"] or not c["submitted"]):
                raise ValueError("image insert outside intent")
        elif verb == "delete" and (c.get("image_id") is None or not c["delete_submitted"] or
                kw.get("request_id") != c["delete_request_id"]):
            raise ValueError("image deletion requires immutable identity")
        elif verb not in ("get", "delete", "list"):
            raise ValueError("unsupported image operation")
        if verb != "insert" and (kw.get("body") is not None or
                (verb in ("get", "list") and kw.get("request_id") is not None)):
            raise ValueError("unexpected image parameters")
    except ValueError as exc:
        raise ForbiddenOperation(str(exc)) from exc
