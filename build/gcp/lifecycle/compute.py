"""Allowlisted Compute v1 transport; no cloud access occurs on import.

Call through PolicyCloud. Requests never retry automatically, mutate a create
body, or manufacture request IDs. Each list call returns one raw API page;
the controller owns bounded traversal. Mutations stay in one zone.
Runtime defaults depend on the separately reviewed shared auth_http adapter.
Official contracts: https://cloud.google.com/compute/docs/reference/rest/v1/
instances/insert, instances/aggregatedList, disks/aggregatedList,
zoneOperations/list, globalOperations/aggregatedList. Offline contracts do not prove live IAM/API behavior.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Callable, Optional
from urllib.parse import urlencode

from . import spec
from .cloud import ALLOWED, ApiError, ForbiddenOperation, NotFound, Uncertain

BASE = "https://compute.googleapis.com/compute/v1"
_NAME = re.compile(r"[a-zA-Z0-9_-]{1,200}\Z")
MAX_PAGE_ITEMS = 500


class ComputeRestTransport:
    """Inject HTTP and header providers for offline tests; defaults use gcloud.

    A supplied http implements auth_http.HttpTransport.request. header_provider
    is a trusted composition hook, not task input. Production defaults validate
    fresh short-lived bearer credentials through the shared helper each request.
    """
    def __init__(self, http=None, *, token_provider: Optional[Callable[[], str]] = None,
                 header_provider: Optional[Callable[[], dict]] = None):
        self.http = http
        self.token_provider = token_provider
        self.header_provider = header_provider

    def _request(self, method, url, body=None):
        try:
            if self.header_provider is not None:
                headers = dict(self.header_provider())
            else:
                from .auth_http import bearer_headers, gcloud_token
                headers = bearer_headers(self.token_provider or gcloud_token)
            if self.http is None:
                from .auth_http import HttpTransport
                self.http = HttpTransport()
            headers["Accept"] = "application/json"
            if body is not None:
                headers["Content-Type"] = "application/json"
            response = self.http.request(method, url, headers=headers, body=body,
                                         timeout=20, max_bytes=1_048_576)
        except Exception:
            # Do not chain transport/auth exceptions that may contain tokens.
            # A mutation may have reached the server; leave the lease occupied.
            raise Uncertain("Compute transport/auth outcome unavailable") from None
        if response.status == 404:
            raise NotFound("Compute resource not found")
        if response.status in (408, 429) or response.status >= 500:
            raise Uncertain(f"Compute HTTP {response.status}; outcome unavailable")
        if not 200 <= response.status < 300:
            # Never echo server text: errors can include request/metadata values.
            raise ApiError(response.status, "Compute request rejected")
        try:
            data = json.loads(response.body)
            if not isinstance(data, dict):
                raise ValueError("not a successful resource")
        except (ValueError, TypeError, UnicodeError):
            raise Uncertain("Invalid Compute response; outcome unavailable") from None
        return data

    def _list_page(self, resource, url, aggregate, page_token):
        query = {"maxResults": MAX_PAGE_ITEMS}
        if aggregate:
            # A failed/unreachable scope must block admission, not disappear.
            query["returnPartialSuccess"] = "false"
        if page_token is not None:
            query["pageToken"] = page_token
        data = self._request("GET", url + "?" + urlencode(query))
        if data.get("unreachables") or data.get("error"):
            raise Uncertain("Compute census contains failed/unreachable scopes")
        warning = data.get("warning")
        if warning and (not isinstance(warning, dict) or warning.get("code") != "NO_RESULTS_ON_PAGE"):
            raise Uncertain("Compute census warning; admission blocked")
        page = data.get("items", {} if aggregate else [])
        count = 0
        if aggregate:
            if not isinstance(page, dict):
                raise Uncertain("Invalid aggregated Compute census")
            key = "operations" if resource == "globalOperations" else resource
            for block in page.values():
                if not isinstance(block, dict):
                    raise Uncertain("Invalid Compute census scope")
                warning = block.get("warning")
                if warning and (not isinstance(warning, dict) or warning.get("code") != "NO_RESULTS_ON_PAGE"):
                    raise Uncertain("Compute census warning; admission blocked")
                values = block.get(key, [])
                if not isinstance(values, list) or not all(isinstance(x, dict) for x in values):
                    raise Uncertain("Invalid Compute census items")
                count += len(values)
        else:
            if not isinstance(page, list) or not all(isinstance(x, dict) for x in page):
                raise Uncertain("Invalid Compute zonal list")
            count = len(page)
        if count > MAX_PAGE_ITEMS:
            raise Uncertain("Compute page item bound exceeded")
        token = data.get("nextPageToken")
        if token not in (None, "") and not self._valid_page_token(token):
            raise Uncertain("Invalid Compute next-page token")
        # Preserve scoped items, all operation identity/error fields, and token.
        # No filtering, flattening, or implicit second HTTP request occurs here.
        return data

    @staticmethod
    def _valid_page_token(token):
        return isinstance(token, str) and 0 < len(token) <= 4096 and all(32 <= ord(c) < 127 for c in token)

    def call(self, resource: str, verb: str, *, project: str, zone: str,
             name: Optional[str] = None, body: Optional[dict] = None,
             request_id: Optional[str] = None,
             page_token: Optional[str] = None) -> dict:
        if (resource, verb) not in ALLOWED:
            raise ForbiddenOperation("Compute resource/verb outside allowlist")
        if project != spec.PROJECT or zone != spec.ZONE:
            raise ForbiddenOperation("Compute project/zone outside fixed scope")
        if request_id is not None:
            try:
                parsed = uuid.UUID(request_id)
                valid = str(parsed) == request_id and parsed.int != 0
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ForbiddenOperation("Invalid persisted Compute request ID")
        if page_token is not None and (verb not in ("list", "aggregatedList") or not self._valid_page_token(page_token)):
            raise ForbiddenOperation("Unexpected/invalid Compute page token")
        if resource == "images":
            if (verb != "get" or name != spec.COMPONENT_IMAGE.rsplit("/", 1)[-1] or
                    body is not None or request_id is not None or page_token is not None):
                raise ForbiddenOperation("only the fixed public Ubuntu image read is permitted")
            return self._request("GET", BASE + "/" + spec.COMPONENT_IMAGE)
        project_url = f"{BASE}/projects/{spec.PROJECT}"
        endpoint = "operations" if resource in ("zoneOperations", "globalOperations") else resource
        zonal_url = f"{project_url}/zones/{spec.ZONE}/{endpoint}"
        if verb in ("list", "aggregatedList"):
            if name is not None or body is not None or request_id is not None:
                raise ForbiddenOperation("Unexpected Compute list parameters")
            aggregate = verb == "aggregatedList"
            url = f"{project_url}/aggregated/{endpoint}" if aggregate else zonal_url
            return self._list_page(resource, url, aggregate, page_token)
        if verb == "insert":
            if resource != "instances" or name is not None or body is None or request_id is None:
                raise ForbiddenOperation("Create requires persisted body and request ID")
            # Validation and serialization leave the persisted body unchanged.
            spec.validate_body(body)
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            return self._request("POST", zonal_url + "?" + urlencode({"requestId": request_id}), payload)
        if not isinstance(name, str) or not _NAME.fullmatch(name) or body is not None:
            raise ForbiddenOperation("Invalid Compute resource name/body")
        if verb == "get" and request_id is not None:
            raise ForbiddenOperation("Unexpected request ID on resource read")
        if verb == "delete" and not spec.is_owned_name(name):
            raise ForbiddenOperation("Deletion name outside lifecycle pattern")
        url = zonal_url + "/" + name
        if request_id is not None:
            url += "?" + urlencode({"requestId": request_id})
        return self._request("DELETE" if verb == "delete" else "GET", url)
