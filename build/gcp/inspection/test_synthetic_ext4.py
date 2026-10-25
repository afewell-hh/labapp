"""Offline ownership checks only; no loop allocation, mount, cloud or source data."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from .mounted_collect import Refused
from .synthetic_ext4 import SIZE, verify_loop
from . import synthetic_ext4 as synthetic


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


class FixturePreparationCleanupTests(unittest.TestCase):
    def test_mid_population_exception_cleans_exact_predeclared_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / 'work'
            work.mkdir(mode=0o700)
            original = Path.write_bytes
            calls = 0
            def fail_mid_population(path, body):
                nonlocal calls
                calls += 1
                result = original(path, body)
                if calls == 2:
                    raise OSError('synthetic preparation failure')
                return result
            with mock.patch.object(synthetic.os, 'geteuid', return_value=0), \
                 mock.patch.object(synthetic.os, 'access', return_value=True), \
                 mock.patch.object(synthetic.tempfile, 'mkdtemp', return_value=str(work)), \
                 mock.patch.object(synthetic, 'validate_namespace'), \
                 mock.patch.object(synthetic, 'command', side_effect=AssertionError('kernel command forbidden')), \
                 mock.patch.object(Path, 'write_bytes', fail_mid_population):
                with self.assertRaisesRegex(OSError, 'synthetic preparation failure'):
                    synthetic.run('host-baseline-v1')
            self.assertEqual(calls, 2)
            self.assertFalse(work.exists())

    def test_real_sigterm_mid_population_cleans_without_kernel_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            work, ready = Path(temp) / 'work', Path(temp) / 'ready'
            work.mkdir(mode=0o700)
            code = """import os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from inspection import synthetic_ext4 as s
work,ready=sys.argv[2:]
s.os.geteuid=lambda:0
s.os.access=lambda *a:True
s.tempfile.mkdtemp=lambda **kw:work
s.validate_namespace=lambda *a:None
def forbidden(*args): raise AssertionError('kernel command forbidden')
s.command=forbidden
real=Path.write_bytes
def pause(path,body):
    result=real(path,body)
    Path(ready).write_text('ready')
    time.sleep(10)
    return result
Path.write_bytes=pause
sys.argv=['synthetic_ext4','--profile','host-baseline-v1']
s.main()
"""
            process = subprocess.Popen([sys.executable, '-c', code,
                str(Path(synthetic.__file__).resolve().parents[1]), str(work), str(ready)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists())
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(stdout, b'')
                self.assertEqual(stderr, b'Synthetic kernel proof refused; owned cleanup may be required.\n')
                self.assertFalse(work.exists())
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
