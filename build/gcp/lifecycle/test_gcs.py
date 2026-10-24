"""Offline HTTP-contract tests for GCS CAS and shared transport; no cloud/auth calls."""
from __future__ import annotations

import io
import json
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from .auth_http import (HttpResponse, HttpTransport, TransportError,
                        _NoRedirect, bearer_headers, gcloud_token)
from .gcs import GcsSlotStore, MAX_RECORD_BYTES, StoreError
from .store import PreconditionFailed

KEY = "slots/slot-1.json"
BUCKET = "test-ledger-bucket"
FREE = {"schema": 1, "slot": KEY, "state": "FREE", "epoch": 0}


def body(record=FREE):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def metadata(gen="101", *, record=FREE, **extra):
    value = {"bucket": BUCKET, "name": KEY, "generation": gen,
             "size": str(len(body(record)))}
    value.update(extra)
    return HttpResponse(200, json.dumps(value).encode())


class HTTP:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected HTTP retry")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class GcsTests(unittest.TestCase):
    def store(self, *responses, **kw):
        self.http = HTTP(*responses)
        return GcsSlotStore(BUCKET, token_provider=lambda: "dummy-token",
                            transport=self.http, **kw)

    def test_absent_initial_metadata_is_only_absence_path(self):
        self.assertEqual(self.store(HttpResponse(404, b"{}")).read(KEY), (None, 0))
        self.assertEqual(len(self.http.calls), 1)

    def test_read_pairs_exact_generation_and_encodes_object_path(self):
        store = self.store(metadata(), HttpResponse(200, body()))
        self.assertEqual(store.read(KEY), (FREE, 101))
        self.assertIn("/o/slots%2Fslot-1.json?", self.http.calls[0][1])
        self.assertEqual(parse_qs(urlsplit(self.http.calls[1][1]).query),
                         {"alt": ["media"], "generation": ["101"]})
        self.assertTrue(all(call[2]["timeout"] == 20 for call in self.http.calls))

    def test_replaced_revision_retries_new_metadata_and_returns_new_generation(self):
        newer = dict(FREE, epoch=1)
        store = self.store(metadata(), HttpResponse(404, b"{}"),
                           metadata("102", record=newer), HttpResponse(200, body(newer)))
        self.assertEqual(store.read(KEY), (newer, 102))
        self.assertIn("generation=101", self.http.calls[1][1])
        self.assertIn("generation=102", self.http.calls[3][1])

    def test_deleted_after_metadata_never_claims_absence(self):
        store = self.store(metadata(), HttpResponse(404, b"{}"),
                           HttpResponse(404, b"{}"), HttpResponse(404, b"{}"))
        with self.assertRaises(StoreError):
            store.read(KEY)
        self.assertEqual(len(self.http.calls), 4)

    def test_read_contention_is_bounded(self):
        store = self.store(*([metadata(), HttpResponse(412, b"{}")] * 3))
        with self.assertRaises(StoreError):
            store.read(KEY)
        self.assertEqual(len(self.http.calls), 6)

    def test_old_revision_can_be_read_then_stale_write_conflicts(self):
        store = self.store(metadata(), HttpResponse(200, body()), HttpResponse(412, b"{}"))
        record, generation = store.read(KEY)
        with self.assertRaises(PreconditionFailed):
            store.write(KEY, dict(record, epoch=1), if_generation_match=generation)
        self.assertEqual(parse_qs(urlsplit(self.http.calls[2][1]).query)["ifGenerationMatch"], ["101"])

    def test_create_and_replace_preconditions_and_acknowledged_generation(self):
        for match in (0, 99):
            with self.subTest(match=match):
                store = self.store(metadata())
                self.assertEqual(store.write(KEY, FREE, if_generation_match=match), 101)
                method, url, args = self.http.calls[0]
                self.assertEqual(method, "POST")
                self.assertIn("/upload/storage/v1/b/test-ledger-bucket/o?", url)
                self.assertEqual(parse_qs(urlsplit(url).query)["uploadType"], ["media"])
                self.assertEqual(parse_qs(urlsplit(url).query)["ifGenerationMatch"], [str(match)])
                self.assertEqual(json.loads(args["body"]), FREE)
                self.assertIn("application/json", args["headers"]["Content-Type"])

    def test_412_maps_only_write_to_cas_conflict(self):
        with self.assertRaises(PreconditionFailed):
            self.store(HttpResponse(412, b"{}")).write(KEY, FREE, if_generation_match=0)
        with self.assertRaises(StoreError):
            self.store(HttpResponse(412, b"{}")).read(KEY)

    def test_uncertain_write_is_not_retried_or_reported_success(self):
        store = self.store(TimeoutError("secret-diagnostic"), metadata())
        with self.assertRaises(StoreError) as caught:
            store.write(KEY, FREE, if_generation_match=0)
        self.assertEqual(len(self.http.calls), 1)
        self.assertNotIn("secret-diagnostic", str(caught.exception))

    def test_http_errors_do_not_become_absence(self):
        for status in (301, 401, 403, 429, 500, 503):
            with self.subTest(status=status):
                with self.assertRaises(StoreError):
                    self.store(HttpResponse(status, b"{}")).read(KEY)
                with self.assertRaises(StoreError):
                    self.store(HttpResponse(status, b"{}")).write(KEY, FREE, if_generation_match=0)

    def test_network_read_failure_is_not_absence(self):
        with self.assertRaises(StoreError):
            self.store(OSError("untrusted diagnostic")).read(KEY)

    def test_metadata_identity_generation_and_size_validation(self):
        for changes in ({"bucket": "other"}, {"name": "other"}, {"generation": 101},
                        {"generation": "0"}, {"generation": "1e3"},
                        {"generation": "18446744073709551616"}, {"size": "0"},
                        {"size": str(MAX_RECORD_BYTES + 1)}, {"size": True}):
            with self.subTest(changes=changes):
                with self.assertRaises(StoreError):
                    self.store(metadata(**changes)).read(KEY)

    def test_size_mismatch_or_partial_content_fails_closed(self):
        for response in (HttpResponse(200, body() + b" "), HttpResponse(206, body())):
            with self.assertRaises(StoreError):
                self.store(metadata(), response).read(KEY)

    def test_ack_identity_size_and_reused_generation_fail_closed(self):
        for response in (metadata(bucket="other"), metadata(size="1"), metadata("99")):
            with self.assertRaises(StoreError):
                self.store(response).write(KEY, FREE, if_generation_match=99)

    def test_bad_json_duplicate_keys_and_unknown_schema_are_rejected(self):
        bad = [b"[]", b"not-json", b'{}', b'\xff',
               b'{"schema":1,"schema":1,"slot":"slots/slot-1.json","state":"FREE","epoch":0}',
               body(dict(FREE, schema=2)), body(dict(FREE, epoch=True)),
               body(dict(FREE, state="OTHER")), body(dict(FREE, epoch=-1)),
               body(dict(FREE, state="ACTIVE")), body(dict(FREE, extra=float("nan")))]
        for raw in bad:
            with self.subTest(raw=raw[:100]):
                with self.assertRaises(StoreError):
                    self.store(metadata(size=str(len(raw))), HttpResponse(200, raw)).read(KEY)

    def test_keys_and_generations_fail_before_network(self):
        store = self.store()
        for key in ("other.json", "../slots/slot-1.json", "slots/slot-2.json", "slots/slot-1.json?x=1"):
            with self.assertRaises(ValueError):
                store.read(key)
        for gen in (-1, True, "101", 2**64):
            with self.assertRaises(ValueError):
                store.write(KEY, FREE, if_generation_match=gen)
        self.assertEqual(self.http.calls, [])

    def test_invalid_configuration_fails_before_network(self):
        for bucket in ("https://bad", "a/b", "Bucket", "aa"):
            with self.assertRaises(ValueError):
                GcsSlotStore(bucket)
        for keys in ([], ["../escape"], ["slots/slot-4.json"]):
            with self.assertRaises(ValueError):
                GcsSlotStore(BUCKET, allowed_keys=keys)
        for attempts in (0, 6, True):
            with self.assertRaises(ValueError):
                GcsSlotStore(BUCKET, max_read_attempts=attempts)

    def test_write_bounds_and_nesting_are_checked_before_network(self):
        store = self.store()
        bad_records = [dict(FREE, slot="other"), dict(FREE, extra="x" * MAX_RECORD_BYTES),
                       dict(FREE, extra=1.0), dict(FREE, extra={1: "invalid JSON key"})]
        nested = []
        for _ in range(35):
            nested = [nested]
        bad_records.append(dict(FREE, extra=nested))
        for record in bad_records:
            with self.assertRaises(StoreError):
                store.write(KEY, record, if_generation_match=0)
        self.assertEqual(self.http.calls, [])

    def test_oversized_injected_response_is_also_rejected(self):
        with self.assertRaises(StoreError):
            self.store(HttpResponse(200, b"x" * 8193)).read(KEY)

    def test_fresh_token_for_each_request_and_errors_do_not_expose_token(self):
        tokens = iter(["first-dummy", "second-dummy"])
        http = HTTP(metadata(), HttpResponse(200, body()))
        store = GcsSlotStore(BUCKET, transport=http, token_provider=lambda: next(tokens))
        store.read(KEY)
        self.assertEqual([c[2]["headers"]["Authorization"] for c in http.calls],
                         ["Bearer first-dummy", "Bearer second-dummy"])
        store.token_provider = lambda: (_ for _ in ()).throw(RuntimeError("sensitive"))
        with self.assertRaises(StoreError) as caught:
            store.read(KEY)
        self.assertNotIn("sensitive", str(caught.exception))


class FakeResponse(io.BytesIO):
    code = 200


class Opener:
    def __init__(self, raw):
        self.raw = raw
        self.calls = []

    def open(self, req, **kw):
        self.calls.append((req, kw))
        return FakeResponse(self.raw)


class AuthHttpTests(unittest.TestCase):
    def test_transport_reads_at_most_bound_plus_one(self):
        opener = Opener(b"1234")
        http = HttpTransport(opener=opener)
        with self.assertRaises(TransportError):
            http.request("GET", "https://storage.googleapis.com/x", headers={}, max_bytes=3)
        self.assertEqual(len(opener.calls), 1)

    def test_transport_admits_only_fixed_https_hosts_and_no_redirect_following(self):
        opener = Opener(b"{}")
        http = HttpTransport(opener=opener)
        for url in ("http://storage.googleapis.com/x", "https://evil.invalid/x",
                    "https://storage.googleapis.com.evil/x", "https://user@storage.googleapis.com/x",
                    "https://storage.googleapis.com:443/x", "https://storage.googleapis.com/x#fragment"):
            with self.assertRaises(TransportError):
                http.request("GET", url, headers={})
        self.assertEqual(opener.calls, [])
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.invalid"))
        self.assertEqual(http.request("GET", "https://compute.googleapis.com/x", headers={}), HttpResponse(200, b"{}"))

    def test_http_status_is_returned_without_diagnostics(self):
        from urllib.error import HTTPError
        class ErrorOpener:
            def open(self, req, **kw):
                raise HTTPError(req.full_url, 412, "precondition", {}, io.BytesIO(b"{}"))
        result = HttpTransport(opener=ErrorOpener()).request(
            "POST", "https://storage.googleapis.com/x", headers={})
        self.assertEqual(result, HttpResponse(412, b"{}"))

    def test_gcloud_provider_is_captured_bounded_and_never_logs_diagnostics(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "dummy-token\n", "")) as run:
            self.assertEqual(gcloud_token(), "dummy-token")
            args, kw = run.call_args
            self.assertEqual(args[0], ["gcloud", "auth", "print-access-token", "--quiet"])
            self.assertEqual(kw["timeout"], 30)
            self.assertTrue(kw["capture_output"])
        with patch("subprocess.run", side_effect=RuntimeError("private-token")):
            with self.assertRaises(TransportError) as caught:
                gcloud_token()
            self.assertNotIn("private-token", str(caught.exception))

    def test_header_injection_and_nonstring_token_are_rejected(self):
        for token in ("x\r\nOther: injected", "", None, "x" * 4097):
            with self.assertRaises(TransportError):
                bearer_headers(lambda: token)


class ObjectServer:
    """Tiny fake implementing wire-level generations, not the SlotStore API."""
    def __init__(self):
        self.data = None
        self.generation = 0

    def request(self, method, url, **kwargs):
        query = parse_qs(urlsplit(url).query)
        if method == "POST":
            match = int(query["ifGenerationMatch"][0])
            if match != self.generation:
                return HttpResponse(412, b"{}")
            self.data = kwargs["body"]
            self.generation += 1
        elif self.data is None:
            return HttpResponse(404, b"{}")
        elif query.get("alt") == ["media"]:
            if int(query["generation"][0]) != self.generation:
                return HttpResponse(404, b"{}")
            return HttpResponse(200, self.data)
        return metadata(str(self.generation), size=str(len(self.data)))


class ControllerInteropTests(unittest.TestCase):
    def test_actual_controller_round_trips_all_states_and_release_evidence(self):
        from .cloud import PolicyCloud
        from .controller import Controller, Config
        from .fakes import FakeClock, FakeCloud
        from . import spec
        clock = FakeClock()
        store = GcsSlotStore(BUCKET, transport=ObjectServer(),
                             token_provider=lambda: "dummy")
        config = Config(boot_image="projects/ubuntu-os-cloud/global/images/pinned-test",
                        now=clock.now, sleep=clock.sleep)
        controller = Controller(store, PolicyCloud(FakeCloud(clock), spec.PROJECT, spec.ZONE), config)
        uuid = "11111111-1111-4111-8111-111111111111"
        controller.admit(1, 1, uuid)
        self.assertEqual(store.read(KEY)[0]["state"], "RESERVED")
        self.assertEqual(controller.submit(uuid).status, "accepted")
        self.assertEqual(controller.confirm_created(uuid).status, "created")
        self.assertEqual(store.read(KEY)[0]["state"], "ACTIVE")
        self.assertEqual(controller.reconcile(uuid).status, "released")
        record = store.read(KEY)[0]
        self.assertEqual(record["state"], "FREE")
        self.assertEqual(record["last_release"]["request_id"], uuid)


if __name__ == "__main__":
    unittest.main()
