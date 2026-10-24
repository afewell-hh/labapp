"""Real unchanged helper; run ONLY inside the disposable test namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

HELPER = str(Path(__file__).with_name("ensure-bridge-ipv4.py"))


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, timeout=3).stdout


def invoke(bridge="testbr0", cidr="198.51.100.2/24", wait="2"):
    return subprocess.run([sys.executable, HELPER, "--bridge", bridge, "--cidr", cidr,
                           "--wait-seconds", wait, "--poll-ms", "50"],
                          capture_output=True, timeout=4, cwd="/tmp", text=True)


class NamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("LABAPP_DISPOSABLE_NETNS_TEST") != "1":
            raise RuntimeError("Use test-bridge-ipv4.sh; isolated namespace required")

    def test_real_bridge_contract(self):
        # All names/addresses are public synthetic fixtures in this container.
        ip("link", "add", "testbr0", "type", "bridge")
        ip("address", "add", "192.0.2.22/27", "dev", "testbr0")
        unrelated = json.loads(ip("-j", "-4", "address", "show", "dev", "testbr0"))[0]["addr_info"]
        result = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        first = ip("-j", "-4", "address", "show", "dev", "testbr0")
        entries = json.loads(first)[0]["addr_info"]
        self.assertTrue(all(entry in entries for entry in unrelated))
        self.assertIn(("198.51.100.2", 24), [(a["local"], a["prefixlen"]) for a in entries])
        self.assertEqual(invoke().returncode, 0)
        self.assertEqual(ip("-j", "-4", "address", "show", "dev", "testbr0"), first)
        conflict = invoke(cidr="198.51.100.2/25")
        self.assertEqual(conflict.returncode, 1)
        self.assertIn("address has a conflicting prefix", conflict.stderr)
        self.assertEqual(ip("-j", "-4", "address", "show", "dev", "testbr0"), first)

    def test_delayed_creation(self):
        errors = []
        def create():
            try:
                time.sleep(0.2)
                ip("link", "add", "laterbr0", "type", "bridge")
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=create)
        thread.start()
        try:
            result = invoke(bridge="laterbr0")
        finally:
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonbridge(self):
        ip("link", "add", "dummytest0", "type", "dummy")
        before = ip("-j", "-4", "address", "show", "dev", "dummytest0")
        result = invoke(bridge="dummytest0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not a Linux bridge", result.stderr)
        self.assertEqual(ip("-j", "-4", "address", "show", "dev", "dummytest0"), before)

    def test_absent_deadline(self):
        start = time.monotonic()
        result = invoke(bridge="absentbr0", wait="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("timed out", result.stderr)
        self.assertLess(time.monotonic()-start, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
