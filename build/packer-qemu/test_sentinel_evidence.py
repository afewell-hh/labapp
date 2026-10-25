"""Synthetic status JSON only; never invoke cloud-init or guest operations."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "sentinel_evidence", Path(__file__).parent / "guest" / "sentinel-evidence.py")
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)


class SummaryTests(unittest.TestCase):
    def test_normalizes_known_24x_nested_records_without_retaining_peer_text(self):
        body = {"status": "done", "errors": [], "recoverable_errors": {},
                "detail": {"modules-final": {"errors": [], "recoverable_errors": {"WARNING": []}}},
                "boot_status_code": "enabled-by-generator", "arbitrary": "PEER_TEXT"}
        raw = json.dumps(body).encode()
        self.assertEqual(se.summary(raw), {"status": "done", "errors": 0, "recoverable_errors": 0})
        line = se.record(raw, "a" * 64, "b" * 64)
        self.assertNotIn("PEER_TEXT", line)
        self.assertIn("nonce=" + "a" * 64 + " inputs=" + "b" * 64, line)
        self.assertLess(len(line), 4096)

    def test_rejects_size_shape_errors_non_done_and_duplicate_fields(self):
        bad = [b'{"status":"done"}' + b" " * se.STATUS_CAP,
               b'{"status":"done","status":"done"}', b'{"status":"running"}',
               b'{"status":"done","errors":false}', b'{"status":"done","errors":0}',
               b'{"status":"done","errors":["SECRET"]}',
               b'{"status":"done","recoverable_errors":{"WARNING":["SECRET"]}}',
               b'{"status":"done","detail":{"init":{"errors":["SECRET"]}}}',
               b'{"status":"done","exit_code":1}', b'{"status":"done","x":NaN}',
               b'[]', b'not json']
        for raw in bad:
            with self.subTest(raw=raw[:100]), self.assertRaises(ValueError):
                se.summary(raw)

    def test_malformed_identity_never_emits_a_record(self):
        for nonce, inputs in (("invalid", "b" * 64), ("a" * 64, "b" * 65)):
            with self.assertRaises(ValueError):
                se.record(b'{"status":"done"}', nonce, inputs)
