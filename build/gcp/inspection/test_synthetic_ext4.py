"""Offline ownership checks only; no loop allocation, mount, cloud or source data."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from .mounted_collect import Refused
from .synthetic_ext4 import SIZE, verify_loop


class SyntheticLoopProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.backing = Path(self.temp.name) / "owned.ext4"
        with self.backing.open("xb") as stream:
            stream.truncate(SIZE)
        info = self.backing.stat()
        self.identity = info.st_dev, info.st_ino
        self.item = {"name": "/dev/loop99", "back-file": str(self.backing),
                     "back-ino": info.st_ino,
                     "back-maj:min": f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
                     "maj:min": "7:99", "offset": 0, "sizelimit": SIZE, "ro": True}

    def prove(self, item=None):
        return verify_loop(json.dumps({"loopdevices": [item or self.item]}),
                           self.backing, self.identity, "/dev/loop99")

    def test_exact_loop(self):
        self.assertEqual(self.prove(), ("/dev/loop99", "7:99"))

    def test_conflicting_mapping_fields(self):
        for key, value in (("name", "/dev/loop98"), ("back-file", "/unowned"),
                           ("back-ino", self.identity[1] + 1), ("back-maj:min", "0:0"),
                           ("offset", 1), ("sizelimit", 0), ("ro", False),
                           ("maj:min", "invalid")):
            with self.subTest(key=key), self.assertRaises(Refused):
                self.prove(dict(self.item, **{key: value}))

    def test_changed_backing_size(self):
        self.backing.write_bytes(b"tiny")
        with self.assertRaises(Refused):
            self.prove()

    def test_symlink_backing(self):
        other = self.backing.with_name("other")
        self.backing.rename(other)
        self.backing.symlink_to(other)
        with self.assertRaises(Refused):
            self.prove()

    def test_ambiguous_or_missing_mapping(self):
        for entries in ([], [self.item, self.item]):
            with self.subTest(count=len(entries)), self.assertRaises(Refused):
                verify_loop(json.dumps({"loopdevices": entries}), self.backing,
                            self.identity, "/dev/loop99")

    def test_invalid_json(self):
        with self.assertRaises(Refused):
            verify_loop("invalid", self.backing, self.identity)


if __name__ == "__main__":
    unittest.main()
