"""Cloud transport boundary: a single allowlisted call surface.

The controller never talks to a cloud client directly. Every call goes through
``PolicyCloud``, which rejects any resource/verb outside the reviewed set and
any project/zone outside the fixed scope. Images, snapshots, addresses,
firewalls, IAM, and instance stop/start/setScheduling/setMetadata are absent
by construction. No real transport exists in this change.
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
             page_token: Optional[str] = None) -> dict:
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
        kw["project"], kw["zone"] = self.project, self.zone
        return self._raw.call(resource, verb, **kw)
