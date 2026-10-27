"""Offline synthetic tests for install-kubectl.py. No network, no real kubectl, no execution of installed bytes."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import hhfab_release as release

spec = importlib.util.spec_from_file_location("kinstaller", Path(__file__).with_name("install-kubectl.py"))
kinstaller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kinstaller)

PAYLOAD = b"synthetic kubectl bytes, never executed"
OLD = b"old kubectl-like bytes"


def pin_for(data, url="https://example.invalid/kubectl"):
    return {"url": url, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class PinTests(unittest.TestCase):
    def test_exact_pin(self):
        self.assertEqual(list(kinstaller.PINS), ["1.35.0"])
        self.assertEqual(kinstaller.PINS["1.35.0"], {
            "url": "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl",
            "size": 58597560,
            "sha256": "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989"})
        self.assertEqual(kinstaller.PLATFORM, "linux/amd64")
        self.assertEqual((kinstaller.TRANSFER, kinstaller.CHILD, kinstaller.TOTAL), (120, 125, 180))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "bin"
        self.destination.mkdir(mode=0o700)
        self.target = self.destination / "kubectl"
        self.binary = self.root / "input-kubectl"
        self.binary.write_bytes(PAYLOAD)
        handler = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, handler)
        self.pin = pin_for(PAYLOAD)
        patcher = patch.dict(kinstaller.PINS, {"1.35.0": self.pin})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_install(self, binary="default", version="1.35.0", platform_name="linux/amd64"):
        return kinstaller.install(version, platform_name, self.destination,
                                  self.binary if binary == "default" else binary)

    def names(self):
        return sorted(p.name for p in self.destination.iterdir())

    # --- drift contract -------------------------------------------------
    def test_absent_install_unchanged_rerun_and_result(self):
        outcome = self.run_install()
        self.assertEqual(outcome["status"], "installed")
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(self.names(), ["kubectl"])
        inode = self.target.stat().st_ino
        self.assertEqual(self.run_install()["status"], "unchanged")
        self.assertEqual(self.target.stat().st_ino, inode)

    def test_unchanged_does_not_need_input_or_downloader(self):
        self.run_install()
        with patch.object(kinstaller, "bounded", side_effect=AssertionError("must not run")):
            self.assertEqual(self.run_install(binary=None)["status"], "unchanged")
            self.assertEqual(self.run_install(binary=self.root / "missing")["status"], "unchanged")

    def test_matching_bytes_wrong_mode_repaired_atomically(self):
        for mode in (0o644, 0o700, 0o4755):
            self.target.write_bytes(PAYLOAD)
            self.target.chmod(mode)
            before = self.target.stat().st_ino
            outcome = self.run_install()
            self.assertEqual(outcome["status"], "mode-repaired")
            self.assertEqual(outcome["target_mode"], "0755")
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
            self.assertEqual(self.target.read_bytes(), PAYLOAD)
            self.assertNotEqual(self.target.stat().st_ino, before)  # replaced, not chmod-ed in place
            self.assertEqual(self.names(), ["kubectl"])
            self.target.unlink()

    def test_mismatched_existing_bytes_refused_without_mutation(self):
        for data in (OLD, PAYLOAD[:-1], PAYLOAD[:-1] + b"X", b""):
            self.target.write_bytes(data)
            self.target.chmod(0o755 if data == OLD else 0o644)
            before = self.target.stat()
            with self.assertRaisesRegex(release.Refusal, "differs from the pin"):
                self.run_install()
            self.assertEqual(self.target.read_bytes(), data)
            self.assertEqual(self.target.stat().st_ino, before.st_ino)
            self.assertEqual(self.names(), ["kubectl"])

    def test_existing_target_owned_by_other_user_refused(self):
        self.target.write_bytes(PAYLOAD)
        real = os.geteuid()
        with patch.object(kinstaller.os, "geteuid", return_value=real + 1), \
                patch.object(kinstaller, "directory"), self.assertRaisesRegex(release.Refusal, "caller-owned"):
            self.run_install()

    # --- unsafe shapes ---------------------------------------------------
    def test_unsafe_targets_refused(self):
        for shape in ("symlink", "directory", "hardlink", "fifo"):
            with contextlib.suppress(FileNotFoundError, IsADirectoryError):
                self.target.unlink()
            if self.target.is_dir():
                self.target.rmdir()
            if shape == "symlink":
                self.target.symlink_to(self.binary)
            elif shape == "directory":
                self.target.mkdir()
            elif shape == "hardlink":
                os.link(self.binary, self.target)
            else:
                os.mkfifo(self.target)
            with self.assertRaises(release.Refusal, msg=shape):
                self.run_install()
            self.assertEqual(self.names(), ["kubectl"])
        self.assertEqual(self.binary.read_bytes(), PAYLOAD)

    def test_unsafe_parents_refused(self):
        link = self.root / "linked-bin"
        link.symlink_to(self.destination)
        for bad in (link, Path("relative/bin"), self.root / "missing"):
            with self.assertRaises((release.Refusal, FileNotFoundError)):
                kinstaller.install("1.35.0", "linux/amd64", bad, self.binary)
        self.destination.chmod(0o777)
        with self.assertRaises(release.Refusal):
            self.run_install()
        self.destination.chmod(0o770)
        with self.assertRaises(release.Refusal):
            self.run_install()
        self.assertEqual(self.names(), [])

    def test_unsupported_version_platform_refused(self):
        with self.assertRaises(release.Refusal):
            self.run_install(version="1.35.1")
        with self.assertRaises(release.Refusal):
            self.run_install(platform_name="linux/arm64")
        for name, value in (("system", "Darwin"), ("machine", "aarch64")):
            with patch.object(kinstaller.platform, name, return_value=value), self.assertRaises(release.Refusal):
                self.run_install()
        self.assertEqual(self.names(), [])

    # --- offline input ---------------------------------------------------
    def test_bad_binary_inputs_refused_before_any_mutation(self):
        link = self.root / "link"
        link.symlink_to(self.binary)
        hard = self.root / "hard"
        os.link(self.binary, hard)
        short = self.root / "short"
        short.write_bytes(PAYLOAD[:-1])
        wrong = self.root / "wrong"
        wrong.write_bytes(PAYLOAD[:-1] + b"X")
        big = self.root / "big"
        big.write_bytes(PAYLOAD + b"X")
        for bad in (link, hard, short, wrong, big, self.root / "missing", self.root, Path("relative")):
            with patch.object(kinstaller.tempfile, "mkdtemp", side_effect=AssertionError("mutation")), \
                    self.assertRaises((release.Refusal, FileNotFoundError), msg=str(bad)):
                self.run_install(binary=bad)
            self.assertEqual(self.names(), [])

    def test_input_changed_after_validation_refused_and_cleaned(self):
        real = kinstaller.copy_binary

        def swap(source, target, pin):
            source.write_bytes(PAYLOAD[:-1] + b"X")
            return real(source, target, pin)
        with patch.object(kinstaller, "copy_binary", swap), self.assertRaises(release.Refusal):
            self.run_install()
        self.assertEqual(self.names(), [])

    # --- download contract ----------------------------------------------
    def fake_download(self, writer, calls):
        def fake(args, seconds, **kwargs):
            calls.append((args, seconds, kwargs))
            return writer(Path(args[args.index("--output") + 1]))
        return fake

    def test_download_argv_env_and_deadline_and_no_execution(self):
        calls = []

        def write(path):
            path.write_bytes(PAYLOAD)
            return 0, b""
        with patch.object(kinstaller, "bounded", self.fake_download(write, calls)), \
                patch.object(kinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.dict(os.environ, {"HTTPS_PROXY": "http://x", "CURL_HOME": "/x", "KUBECONFIG": "/x",
                                        "HOME": "/x", "SSL_CERT_FILE": "/x"}):
            outcome = self.run_install(binary=None)
        (args, seconds, kwargs), = calls
        self.assertEqual(outcome["status"], "installed")
        self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
        self.assertEqual(args[-1], self.pin["url"])
        for flag in ("--fail", "--proto", "--proto-redir", "--retry", "--max-time", "--max-filesize", "--output"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
        self.assertEqual(args[args.index("--retry") + 1], "0")
        self.assertEqual(args[args.index("--max-time") + 1], "120")
        self.assertEqual(args[args.index("--max-filesize") + 1], str(self.pin["size"]))
        self.assertNotIn("--insecure", args)
        self.assertNotIn("-k", args)
        self.assertNotIn("--user", args)
        self.assertEqual(seconds, 125)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self.assertTrue(Path(args[args.index("--output") + 1]).is_absolute())
        self.assertEqual(self.names(), ["kubectl"])

    def test_download_failures_preserve_target_and_remove_stage(self):
        outcomes = {
            "nonzero": lambda p: (22, b""),
            "oversize": lambda p: (p.write_bytes(PAYLOAD + b"X"), 0)[1:] + (b"",),
            "short": lambda p: (p.write_bytes(PAYLOAD[:-1]), 0)[1:] + (b"",),
            "badhash": lambda p: (p.write_bytes(PAYLOAD[:-1] + b"X"), 0)[1:] + (b"",),
            "missing": lambda p: (0, b""),
            "symlink": lambda p: (p.symlink_to(self.binary), 0)[1:] + (b"",),
        }
        for name, writer in outcomes.items():
            for prior in (None, "wrong-mode"):
                if prior is None:
                    with contextlib.suppress(FileNotFoundError):
                        self.target.unlink()
                else:
                    # Mismatched bytes refuse earlier; a matching wrong-mode target reaches the download.
                    self.target.write_bytes(PAYLOAD)
                    self.target.chmod(0o644)
                calls = []
                with patch.object(kinstaller, "bounded", self.fake_download(writer, calls)), \
                        patch.object(kinstaller, "curl", return_value="/usr/bin/curl"), \
                        self.assertRaises((release.Refusal, OSError), msg=name):
                    self.run_install(binary=None)
                self.assertEqual(len(calls), 1)
                if prior is None:
                    self.assertEqual(self.names(), [])
                else:
                    self.assertEqual(self.names(), ["kubectl"])
                    self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
                    self.assertEqual(self.target.read_bytes(), PAYLOAD)

    def test_real_child_timeout_and_overflow_are_bounded_and_clean(self):
        fake_dir = self.root / "fakebin"
        fake_dir.mkdir()
        curl = fake_dir / "curl"
        for script in ("sleep 10", "yes x | head -c 2000000; sleep 0"):
            curl.write_text("#!/bin/sh\n" + script + "\n")
            curl.chmod(0o755)
            real = release.bounded
            with patch.object(kinstaller, "CURL_DIRS", (str(fake_dir),)), \
                    patch.object(kinstaller, "bounded", lambda a, s, **k: real(a, 0.3, **k)):
                started = time.monotonic()
                with self.assertRaises(release.Refusal):
                    self.run_install(binary=None)
                self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(self.names(), [])

    def test_missing_curl_refused_before_staging(self):
        with patch.object(kinstaller, "CURL_DIRS", (str(self.root / "none"),)), \
                patch.object(kinstaller.tempfile, "mkdtemp", side_effect=AssertionError("mutation")), \
                self.assertRaisesRegex(release.Refusal, "curl"):
            self.run_install(binary=None)

    # --- cancellation / deadline / concurrency / cleanup -----------------
    def test_keyboard_interrupt_removes_exact_stage(self):
        (self.destination / "other").write_text("unrelated")
        with patch.object(kinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.object(kinstaller, "bounded", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.run_install(binary=None)
        self.assertEqual(self.names(), ["other"])

    def test_total_deadline_alarm_cancels_and_cleans(self):
        old = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        (self.destination / "other").write_text("unrelated")
        with patch.object(kinstaller, "TOTAL", 1), patch.object(kinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.object(kinstaller, "bounded", lambda *a, **k: time.sleep(5)), \
                patch.object(sys, "argv", ["x", "--version", "1.35.0", "--platform", "linux/amd64",
                                           "--install-dir", str(self.destination)]):
            with self.assertRaisesRegex(release.Refusal, "deadline exceeded"):
                kinstaller.main()
        self.assertEqual(signal.alarm(0), 0)
        self.assertEqual(self.names(), ["other"])

    def test_destination_change_during_install_refused(self):
        # Absent target: a file appearing before publication is never clobbered.
        real = kinstaller.copy_binary

        def appear(source, target, pin):
            real(source, target, pin)
            self.target.write_bytes(b"racing writer")
        with patch.object(kinstaller, "copy_binary", appear), \
                self.assertRaisesRegex(release.Refusal, "destination changed"):
            self.run_install()
        self.assertEqual(self.target.read_bytes(), b"racing writer")
        self.assertEqual(self.names(), ["kubectl"])
        # Existing wrong-mode target: replacement or modification during staging is detected.
        self.target.write_bytes(PAYLOAD)
        self.target.chmod(0o644)

        def mutate(source, target, pin):
            real(source, target, pin)
            self.target.unlink()
            self.target.write_bytes(PAYLOAD)
        with patch.object(kinstaller, "copy_binary", mutate), \
                self.assertRaisesRegex(release.Refusal, "destination changed"):
            self.run_install()
        self.assertEqual(self.names(), ["kubectl"])

    def test_cleanup_failure_does_not_mask_primary_error(self):
        self.target.write_bytes(PAYLOAD)
        self.target.chmod(0o644)
        with patch.object(kinstaller.shutil, "rmtree", side_effect=OSError("cleanup")), \
                patch.object(kinstaller, "copy_binary", side_effect=release.Refusal("primary")), \
                self.assertRaisesRegex(release.Refusal, "primary"):
            self.run_install()

    # --- bounded structured result --------------------------------------
    def test_result_binds_identity_and_states_limits(self):
        outcome = self.run_install()
        self.assertEqual({k: outcome[k] for k in ("tool", "version", "platform", "source_url",
                                                  "pinned_size", "pinned_sha256", "status", "target_mode")},
                         {"tool": "kubectl", "version": "1.35.0", "platform": "linux/amd64",
                          "source_url": self.pin["url"], "pinned_size": self.pin["size"],
                          "pinned_sha256": self.pin["sha256"], "status": "installed", "target_mode": "0755"})
        self.assertEqual(outcome["target_sha256"], self.pin["sha256"])
        self.assertEqual(outcome["target"], str(self.target))
        self.assertEqual(outcome["module_sha256"], hashlib.sha256(
            Path(__file__).with_name("install-kubectl.py").read_bytes()).hexdigest())
        self.assertEqual(outcome["helper_sha256"], hashlib.sha256(
            Path(release.__file__).read_bytes()).hexdigest())
        self.assertIs(outcome["executed"], False)
        self.assertIn("signature", outcome["not_verified"])
        self.assertIn("baseline-path", outcome["not_verified"])
        self.assertIn("no rollback", outcome["atomicity"])
        self.assertLess(len(json.dumps(outcome)), 2048)

    def test_cli_prints_one_json_line_and_requires_explicit_pin(self):
        argv = ["x", "--version", "1.35.0", "--platform", "linux/amd64", "--install-dir", str(self.destination),
                "--binary", str(self.binary)]
        out = io.StringIO()
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(out):
            kinstaller.main()
        self.assertEqual(json.loads(out.getvalue())["status"], "installed")
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        for bad in (["x"], ["x", "--version", "1.35.0"], ["x", "--version", "latest", "--platform", "linux/amd64"],
                    ["x", "--version", "1.35.0", "--platform", "linux/arm64"],
                    ["x", "--version=1.35.0", "--platform", "linux/amd64", "--force"],
                    ["x", "--ver", "1.35.0", "--platform", "linux/amd64"]):
            with patch.object(sys, "argv", bad), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                kinstaller.main()


if __name__ == "__main__":
    unittest.main()
