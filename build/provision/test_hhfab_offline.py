"""Public synthetic integrity/bounds and Docker-ownership regression tests."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import hhfab_test as subject
import test_bridge_ipv4_harness as ownership


class IntegrityTests(unittest.TestCase):
    def archive(self, root, name="hhfab-linux-amd64/hhfab", kind=tarfile.REGTYPE, extra=False):
        path = root / "release.tgz"
        with tarfile.open(path, "w:gz") as tar:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 4 if kind == tarfile.REGTYPE else 0
            tar.addfile(member, io.BytesIO(b"test") if member.size else None)
            if extra:
                tar.addfile(tarfile.TarInfo("unexpected"))
        return path, (path.stat().st_size, subject.digest(path), 4, hashlib.sha256(b"test").hexdigest())

    def test_distribution_csafe_loader_accepts_yaml_separation_tab(self):
        import yaml
        self.assertEqual(yaml.load("ip:\tdhcp # public upstream template\n", Loader=yaml.CSafeLoader), {"ip": "dhcp"})

    def test_extract_exact_member(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            subject.extract(archive, root / "binary", pin)
            self.assertEqual((root / "binary").read_bytes(), b"test")
            self.assertEqual((root / "binary").stat().st_mode & 0o777, 0o755)

    def test_bad_archive_digest_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            pin = (pin[0], "0" * 64, *pin[2:])
            with self.assertRaisesRegex(subject.Refusal, "archive checksum"):
                subject.extract(archive, root / "binary", pin)
            self.assertFalse((root / "binary").exists())

    def test_bad_member_digest_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            with self.assertRaisesRegex(subject.Refusal, "member checksum"):
                subject.extract(archive, root / "binary", (*pin[:3], "0" * 64))

    def test_unsafe_or_multiple_members_refused(self):
        for member, kind, extra in [("../escape", tarfile.REGTYPE, False),
                                    ("hhfab-linux-amd64/hhfab", tarfile.SYMTYPE, False),
                                    ("hhfab-linux-amd64/hhfab", tarfile.REGTYPE, True)]:
            with self.subTest(member=member, kind=kind, extra=extra), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                archive, pin = self.archive(root, member, kind, extra)
                with self.assertRaisesRegex(subject.Refusal, "archive member"):
                    subject.extract(archive, root / "binary", pin)
                self.assertFalse((root / "binary").exists())

    def test_timeout_and_overflow_actual_children(self):
        for code, seconds, limit, reason in [("import time; time.sleep(10)", .1, 1024, "timeout"),
                                             ("print('x'*10000)", 2, 1024, "overflow")]:
            with self.subTest(reason=reason), self.assertRaisesRegex(subject.Refusal, reason):
                subject.bounded([sys.executable, "-c", code], seconds, limit)

    def test_interruption_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "pid"
            child = ("import os,signal,time; from pathlib import Path; "
                     "Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); "
                     "os.kill(os.getppid(),signal.SIGINT); time.sleep(10)")
            program = ("import sys; sys.path.insert(0,sys.argv[1]); import hhfab_test as h; "
                       "h.bounded([sys.executable,'-c',sys.argv[2]],2)")
            proc = subprocess.run([sys.executable, "-c", program, str(Path(__file__).parent), child],
                                  capture_output=True, timeout=4)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b"KeyboardInterrupt", proc.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)


class OwnershipTests(ownership.CleanupTests):
    """Reuse established daemon model; synthetic runs prove ownership, not CLI."""
    def run_harness(self, mode):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "docker"
            source = ownership.FAKE_DOCKER.replace("elif a[0] == 'start':", "elif a[0] == 'cp':\n    pass\nelif a[0] == 'start':")
            source = source.replace("elif a[0] == 'inspect':\n    print('0')",
                                    "elif a[0] == 'inspect':\n    print('1' if mode == 'lane_failed' and 'runtime' in s['containers'][a[-1]]['name'] else '0')")
            # Inject explicit deletion refusal, retained object must cause failure.
            source = source.replace("obj = s['containers'].pop(a[-1])", "\n    if mode == 'remove_denied':\n        save(); sys.exit(1)\n    obj = s['containers'].pop(a[-1])")
            fake.write_text(source)
            fake.chmod(0o755)
            # No downloads/CLI in ownership-only model; integrity tested separately.
            python = root / "python3"
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            state_path = root / "state.json"
            state_path.write_text(json.dumps({"containers": {}, "images": {}, "calls": []}))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       FAKE_DOCKER_STATE=str(state_path), FAKE_DOCKER_MODE=mode)
            result = subprocess.run(["bash", str(Path(__file__).with_name("test-hhfab-offline.sh"))],
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, json.loads(state_path.read_text())

    def assert_owned_removed(self, state):
        # Parent asserts exact nonce name/tag + conjunction label on all queries.
        import json
        adjusted = json.loads(json.dumps(state).replace("labapp.hhfab-test.run=", "labapp.bridge-test.run=")
                              .replace("labapp-hhfab-test:", "labapp-bridge-test:"))
        super().assert_owned_removed(adjusted)

    def test_daemon_query_failure_is_cleanup_failure_not_absence(self):
        result, state = self.run_harness("daemon_down")
        self.assertEqual(result.returncode, 1)
        self.assertIn("owned cleanup failed", result.stderr)
        self.assertTrue(any(not obj["name"].endswith("-foreign") for obj in state["containers"].values()))
        first_query = next(i for i, args in enumerate(state["calls"]) if args[:2] == ["container", "ls"])
        self.assertFalse(any(a[0] == "rm" or a[:2] == ["image", "rm"] for a in state["calls"][first_query:]))

    def test_failed_lane_is_aggregate_failure_and_second_lane_runs(self):
        result, state = self.run_harness("lane_failed")
        self.assertEqual(result.returncode, 1)
        runtimes = [args for args in state["calls"] if args[0] == "create" and any("runtime" in arg for arg in args)]
        self.assertEqual(len(runtimes), 2)
        self.assert_owned_removed(state)

    def test_remove_denied_is_failure(self):
        result, state = self.run_harness("remove_denied")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owned cleanup failed", result.stderr)
        self.assertTrue(any(not obj["name"].endswith("-foreign") for obj in state["containers"].values()))


if __name__ == "__main__":
    unittest.main()
