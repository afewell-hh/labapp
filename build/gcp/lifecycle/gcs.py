"""Generation-CAS Cloud Storage SlotStore adapter (stdlib, #161).

Usage: GcsSlotStore(bucket, token_provider=gcloud_token). The bucket must already
exist; this adapter cannot list/delete objects or manage buckets/IAM. Only the
configured slot keys are accessible (default: slots/slot-1.json).

A read fetches metadata, then data pinned to that exact generation. Replacement
between those requests either yields the matching old revision or triggers a
bounded fresh read. Once a revision was observed, a 404 never becomes absence
within that call. Writes submit once with ifGenerationMatch; 412 is a CAS
conflict, while timeout/HTTP/schema failures propagate as StoreError. A caller
must re-read after an uncertain write; the adapter never blindly retries it.

Current envelope schema follows PR158; domain invariants remain the controller's
responsibility. This adapter plus mocked tests is not live-cloud readiness.
Sources checked 2026-10-24:
https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get
https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert
https://docs.cloud.google.com/storage/docs/request-preconditions
"""
from __future__ import annotations

import json
import re
from typing import Callable
from urllib.parse import quote, urlencode

from .auth_http import HttpTransport, bearer_headers, gcloud_token
from .store import PreconditionFailed


class StoreError(Exception):
    """Uncertain or invalid ledger access: callers must fail closed."""


MAX_RECORD_BYTES = 65_536
MAX_METADATA_BYTES = 8_192
_KEY = re.compile(r"slots/slot-[1-3]\.json\Z")
_STATES = frozenset({"FREE", "RESERVED", "ACTIVE", "CLEANUP_FAILED"})


def _integer(value, *, zero: bool = False) -> int:
    # JSON API generations and sizes are decimal strings, never float/bool.
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise StoreError("invalid ledger object metadata")
    result = int(value)
    if result > 2**64 - 1 or (not zero and result == 0):
        raise StoreError("invalid ledger object metadata")
    return result


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError("non-finite JSON number")


def _decode(body: bytes, limit: int):
    try:
        if not isinstance(body, bytes) or not 0 < len(body) <= limit:
            raise ValueError("invalid response size")
        return json.loads(body.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_bad_constant)
    except Exception:
        raise StoreError("invalid ledger JSON response") from None


def _record(record, key: str) -> None:
    # Validate the shared versioned envelope, not a second controller model.
    # Unknown versions/states and occupied records missing core fields block
    # access instead of being treated as FREE. Nested JSON is bounded below.
    if (not isinstance(record, dict) or type(record.get("schema")) is not int or
            record["schema"] != 1 or record.get("slot") != key or
            not isinstance(record.get("state"), str) or record["state"] not in _STATES or
            type(record.get("epoch")) is not int or record["epoch"] < 0):
        raise StoreError("invalid ledger record envelope")
    if record["state"] != "FREE":
        core = {"project": str, "zone": str, "run_id": int, "attempt": int,
                "request_id": str, "body_hash": str, "boot_image": str,
                "names": dict, "reserved_at": str, "deadline": str,
                "submit_attempts": int, "max_submit_attempts": int,
                "ids": dict, "evidence": list}
        if (any(type(record.get(k)) is not t for k, t in core.items()) or
                "operation" not in record or "reason" not in record):
            raise StoreError("invalid occupied ledger record")
    elif "last_release" in record and not isinstance(record["last_release"], dict):
        raise StoreError("invalid ledger release record")
    def visit(value, depth=0):
        if depth > 32:
            raise StoreError("ledger record nesting exceeds limit")
        if isinstance(value, dict):
            if any(not isinstance(k, str) for k in value):
                raise StoreError("invalid ledger JSON key")
            for v in value.values():
                visit(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                visit(v, depth + 1)
        elif value is not None and type(value) not in (str, int, bool):
            # The controller uses no floating-point fields.
            raise StoreError("invalid ledger JSON value")
    visit(record)


class GcsSlotStore:
    def __init__(self, bucket: str, *, token_provider: Callable[[], str] = gcloud_token,
                 transport=None, allowed_keys=("slots/slot-1.json",),
                 max_read_attempts: int = 3):
        # Deliberately support the simple lowercase-hyphen bucket-name subset.
        if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
            raise ValueError("invalid ledger bucket")
        if (not isinstance(allowed_keys, (tuple, list, set, frozenset)) or
                not 1 <= len(allowed_keys) <= 3 or
                any(not isinstance(k, str) or not _KEY.fullmatch(k)
                                    for k in allowed_keys)):
            raise ValueError("invalid allowed slot keys")
        if type(max_read_attempts) is not int or not 1 <= max_read_attempts <= 5:
            raise ValueError("read attempts must be between one and five")
        self.bucket, self.token_provider = bucket, token_provider
        self.http = transport if transport is not None else HttpTransport()
        self.allowed_keys = frozenset(allowed_keys)
        self.max_read_attempts = max_read_attempts

    def _key(self, key: str) -> None:
        if not isinstance(key, str) or key not in self.allowed_keys:
            raise ValueError("slot key is not allowlisted")

    def _request(self, method, url, *, body=None, limit=MAX_METADATA_BYTES):
        try:
            headers = bearer_headers(self.token_provider)
            headers["Accept-Encoding"] = "identity"
            if body is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            response = self.http.request(method, url, headers=headers, body=body,
                                         timeout=20, max_bytes=limit)
            if (type(response.status) is not int or not isinstance(response.body, bytes) or
                    len(response.body) > limit):
                raise ValueError("invalid transport response")
            return response
        except Exception:
            raise StoreError("ledger HTTP request failed; outcome may be uncertain") from None

    def _metadata(self, response, key):
        meta = _decode(response.body, MAX_METADATA_BYTES)
        if (not isinstance(meta, dict) or meta.get("bucket") != self.bucket or
                meta.get("name") != key):
            raise StoreError("ledger object identity mismatch")
        gen, size = _integer(meta.get("generation")), _integer(meta.get("size"))
        if size > MAX_RECORD_BYTES:
            raise StoreError("ledger object exceeds size limit")
        return gen, size

    def read(self, key: str) -> tuple[dict | None, int]:
        self._key(key)
        base = f"https://storage.googleapis.com/storage/v1/b/{self.bucket}/o/{quote(key, safe='')}"
        seen = False
        for _ in range(self.max_read_attempts):
            meta = self._request("GET", base + "?" + urlencode({
                "fields": "bucket,name,generation,size"}))
            if meta.status == 404:
                if not seen:
                    return None, 0
                continue
            if meta.status != 200:
                raise StoreError("ledger metadata read failed")
            seen = True
            generation, size = self._metadata(meta, key)
            media = self._request("GET", base + "?" + urlencode({
                "alt": "media", "generation": str(generation)}), limit=MAX_RECORD_BYTES)
            if media.status in (404, 412):
                continue
            if media.status != 200 or len(media.body) != size:
                raise StoreError("ledger generation data read failed")
            record = _decode(media.body, MAX_RECORD_BYTES)
            _record(record, key)
            return record, generation
        raise StoreError("ledger changed during bounded read; retry from caller")

    def write(self, key: str, record: dict, *, if_generation_match: int) -> int:
        self._key(key)
        if (type(if_generation_match) is not int or
                not 0 <= if_generation_match <= 2**64 - 1):
            raise ValueError("invalid generation precondition")
        _record(record, key)
        try:
            body = json.dumps(record, sort_keys=True, separators=(",", ":"),
                              allow_nan=False).encode("utf-8")
        except Exception:
            raise StoreError("ledger record cannot be serialized") from None
        if len(body) > MAX_RECORD_BYTES:
            raise StoreError("ledger record exceeds size limit")
        url = f"https://storage.googleapis.com/upload/storage/v1/b/{self.bucket}/o?" + urlencode({
            "uploadType": "media", "name": key,
            "ifGenerationMatch": str(if_generation_match),
            "fields": "bucket,name,generation,size"})
        response = self._request("POST", url, body=body)
        if response.status == 412:
            raise PreconditionFailed("ledger generation conflict")
        if response.status not in (200, 201):
            raise StoreError("ledger write failed; outcome may be uncertain")
        generation, size = self._metadata(response, key)
        if size != len(body) or generation == if_generation_match:
            raise StoreError("ledger write acknowledgment mismatch")
        return generation
