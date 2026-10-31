"""Offline HTTP contracts; no token command or cloud call is executed."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlsplit

from . import spec
from .cloud import ApiError, ForbiddenOperation, NotFound, Uncertain
from .compute import ComputeRestTransport

UUID = "9a0da012-1234-4678-8abc-123456789012"
BOOT = "projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20261024"


def response(data, status=200):
    return SimpleNamespace(status=status, body=json.dumps(data).encode())


class HttpStub:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def transport(*replies):
    http = HttpStub(*replies)
    adapter = ComputeRestTransport(http, header_provider=lambda: {"Authorization": "Bearer dummy"})
    return adapter, http


def call(adapter, resource, verb, **kwargs):
    return adapter.call(resource, verb, project=spec.PROJECT, zone=spec.ZONE, **kwargs)


def body():
    return spec.build_body(boot_image=BOOT, request_id=UUID, run_id=1, attempt=1,
                           deadline=datetime(2026, 10, 25, tzinfo=timezone.utc))


class ComputeContracts(unittest.TestCase):
    def test_insert_exact_body_request_id_and_no_retries(self):
        original = body()
        saved = copy.deepcopy(original)
        operation = {"name": "operation-1", "status": "PENDING", "clientOperationId": UUID,
                     "targetId": "8123456789012345678", "targetLink": "fixed-target"}
        adapter, http = transport(response(operation))
        self.assertEqual(call(adapter, "instances", "insert", body=original, request_id=UUID), operation)
        method, url, kwargs = http.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(urlsplit(url).path, f"/compute/v1/projects/{spec.PROJECT}/zones/{spec.ZONE}/instances")
        self.assertEqual(parse_qs(urlsplit(url).query), {"requestId": [UUID]})
        self.assertEqual(kwargs["body"], json.dumps(original, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(original, saved)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(kwargs["timeout"], 20)
        self.assertEqual(kwargs["max_bytes"], 1_048_576)
        self.assertEqual(len(http.calls), 1)

    def test_insert_requires_persisted_nonzero_uuid_before_http(self):
        for invalid in (None, "00000000-0000-0000-0000-000000000000", "bad?requestId=changed"):
            adapter, http = transport()
            with self.assertRaises(ForbiddenOperation):
                call(adapter, "instances", "insert", body=body(), request_id=invalid)
            self.assertEqual(http.calls, [])

    def test_forbidden_project_zone_endpoint_or_name_never_authenticates(self):
        adapter, http = transport()
        for resource, verb in [("images", "delete"), ("snapshots", "get"),
                               ("addresses", "list"), ("instances", "start"),
                               ("instances", "setMetadata"), ("iam", "setIamPolicy")]:
            with self.assertRaises(ForbiddenOperation):
                call(adapter, resource, verb)
        for project, zone in [("production-other", spec.ZONE), (spec.PROJECT, "europe-west1-b")]:
            with self.assertRaises(ForbiddenOperation):
                adapter.call("instances", "get", project=project, zone=zone, name="example")
        for invalid in ("../instances", "https://evil.example", "name?x=1", "name%2Fother"):
            with self.assertRaises(ForbiddenOperation):
                call(adapter, "instances", "get", name=invalid)
        self.assertEqual(http.calls, [])

    def test_delete_only_fixed_zone_owned_names_and_no_payload(self):
        name = spec.names(1, 1)["instance"]
        adapter, http = transport(response({"name": "operation-delete"}))
        call(adapter, "instances", "delete", name=name)
        method, url, kwargs = http.calls[0]
        self.assertEqual(method, "DELETE")
        self.assertTrue(url.endswith(f"/zones/{spec.ZONE}/instances/{name}"))
        self.assertIsNone(kwargs["body"])
        with self.assertRaises(ForbiddenOperation):
            call(adapter, "disks", "delete", name="preexisting-production-disk")
        self.assertEqual(len(http.calls), 1)

    def test_get_operation_preserves_failure_and_identity_fields(self):
        operation = {"name": "operation-1", "status": "DONE", "targetId": "991234567890123456",
                     "targetLink": "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/vm",
                     "clientOperationId": UUID, "error": {"errors": [{"code": "RESOURCE_ERROR"}]}}
        adapter, http = transport(response(operation))
        self.assertEqual(call(adapter, "zoneOperations", "get", name="operation-1"), operation)
        self.assertEqual(http.calls[0][0], "GET")
        self.assertIn(f"/zones/{spec.ZONE}/operations/operation-1", http.calls[0][1])

    def test_json_404_maps_to_notfound_without_payload_disclosure(self):
        adapter, _ = transport(response({"error": {"code": 404, "message": "private-value"}}, 404))
        with self.assertRaises(NotFound) as caught:
            call(adapter, "disks", "get", name="missing")
        self.assertEqual(caught.exception.status, 404)
        self.assertNotIn("private-value", str(caught.exception))

    def test_rejected_http_errors_are_sanitized(self):
        for status in (400, 401, 403, 409, 412):
            adapter, http = transport(response({"error": {"message": "private-metadata"}}, status))
            with self.assertRaises(ApiError) as caught:
                call(adapter, "instances", "get", name="existing")
            self.assertEqual(caught.exception.status, status)
            self.assertNotIn("private-metadata", str(caught.exception))
            self.assertEqual(len(http.calls), 1)

    def test_timeouts_5xx_and_rate_limits_are_uncertain_no_retry(self):
        for reply in (TimeoutError("token-secret"), OSError("token-secret"),
                      response({}, 500), response({}, 503), response({}, 429), response({}, 408)):
            adapter, http = transport(reply)
            with self.assertRaises(Uncertain) as caught:
                call(adapter, "instances", "insert", body=body(), request_id=UUID)
            self.assertNotIn("token-secret", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertEqual(len(http.calls), 1)

    def test_invalid_success_json_never_becomes_empty_census(self):
        for data in (b'{"truncated":', b'[]', b'null'):
            adapter, _ = transport(SimpleNamespace(status=200, body=data))
            with self.assertRaises(Uncertain):
                call(adapter, "instances", "get", name="existing")

    def test_aggregate_page_paths_shapes_and_tokens_are_preserved(self):
        for resource, key, endpoint in [("instances", "instances", "instances"),
                                        ("disks", "disks", "disks"),
                                        ("globalOperations", "operations", "operations")]:
            foreign = {"id": "12345678901234567890", "name": "foreign", "zone": "zones/europe-west1-b"}
            page = {"items": {"zones/europe-west1-b": {key: [foreign]}}, "nextPageToken": "opaque+/=="}
            last = {"items": {"zones/us-central1-a": {"warning": {"code": "NO_RESULTS_ON_PAGE"}}}, "nextPageToken": ""}
            adapter, http = transport(response(page), response(last))
            self.assertEqual(call(adapter, resource, "aggregatedList"), page)
            self.assertEqual(len(http.calls), 1)  # controller, not adapter, traverses
            self.assertEqual(call(adapter, resource, "aggregatedList", page_token=page["nextPageToken"]), last)
            self.assertEqual(urlsplit(http.calls[1][1]).path, f"/compute/v1/projects/{spec.PROJECT}/aggregated/{endpoint}")
            self.assertEqual(parse_qs(urlsplit(http.calls[1][1]).query),
                             {"maxResults": ["500"], "returnPartialSuccess": ["false"], "pageToken": ["opaque+/=="]})

    def test_zonal_operation_page_preserves_all_fields_and_pagination(self):
        op = {"name": "operation-1", "clientOperationId": UUID, "targetId": "777777777777777777",
              "targetLink": "intended-target", "status": "RUNNING"}
        page = {"items": [op], "nextPageToken": "second"}
        adapter, http = transport(response(page))
        self.assertEqual(call(adapter, "zoneOperations", "list", page_token="first"), page)
        self.assertEqual(urlsplit(http.calls[0][1]).path,
                         f"/compute/v1/projects/{spec.PROJECT}/zones/{spec.ZONE}/operations")
        self.assertEqual(parse_qs(urlsplit(http.calls[0][1]).query),
                         {"maxResults": ["500"], "pageToken": ["first"]})

    def test_census_failed_scopes_schema_or_oversized_pages_fail_closed(self):
        pages = [
            {"unreachables": ["zones/x"]},
            {"items": {"zones/x": {"warning": {"code": "UNREACHABLE"}}}},
            {"warning": {"code": "PARTIAL_RESULT"}},
            {"items": []},
            {"items": {"zones/x": {"instances": "not-a-list"}}},
            {"items": {"zones/x": {"instances": [{}] * 501}}},
            {"nextPageToken": []}, {"nextPageToken": "bad\ncontrol"}]
        for page in pages:
            adapter, _ = transport(response(page))
            with self.assertRaises(Uncertain):
                call(adapter, "instances", "aggregatedList")

    def test_page_token_rejected_on_mutation_or_if_invalid_before_http(self):
        adapter, http = transport()
        for token in ("bad\ncontrol", {}, "x" * 4097):
            with self.assertRaises(ForbiddenOperation):
                call(adapter, "zoneOperations", "list", page_token=token)
        with self.assertRaises(ForbiddenOperation):
            call(adapter, "instances", "delete", name=spec.names(1, 1)["instance"], page_token="not-allowed")
        self.assertEqual(http.calls, [])

    def test_shared_auth_uses_injected_fresh_tokens_without_gcloud(self):
        issued = []
        def tokens():
            issued.append(True)
            return f"valid-dummy-token-{len(issued)}"
        http = HttpStub(response({"id": "1"}), response({"id": "2"}))
        adapter = ComputeRestTransport(http, token_provider=tokens)
        call(adapter, "instances", "get", name="one")
        call(adapter, "instances", "get", name="two")
        self.assertEqual(len(issued), 2)
        self.assertEqual(http.calls[1][2]["headers"]["Authorization"], "Bearer valid-dummy-token-2")
        self.assertNotIn("Authorization", adapter.__dict__)

    def test_headers_are_obtained_per_request_and_not_persisted(self):
        supplied = []
        def headers():
            supplied.append(True)
            return {"Authorization": f"Bearer dummy-{len(supplied)}"}
        http = HttpStub(response({"id": "1"}), response({"id": "2"}))
        adapter = ComputeRestTransport(http, header_provider=headers)
        call(adapter, "instances", "get", name="one")
        call(adapter, "instances", "get", name="two")
        self.assertEqual(len(supplied), 2)
        self.assertNotEqual(http.calls[0][2]["headers"]["Authorization"],
                            http.calls[1][2]["headers"]["Authorization"])
        self.assertNotIn("Authorization", adapter.__dict__)


if __name__ == "__main__":
    unittest.main()
