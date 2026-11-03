"""Offline synthetic tests for install-kubectl-fabric.py. No network, no real hhfctl, no execution of any bytes."""
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
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import hhfab_release as release

spec = importlib.util.spec_from_file_location("kfinstaller", Path(__file__).with_name("install-kubectl-fabric.py"))
kfinstaller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kfinstaller)

PAYLOAD = b"synthetic hhfctl bytes, never executed"
OLD = b"old kubectl-fabric-like bytes"
MEMBER = "hhfctl-linux-amd64/hhfctl"


def build_archive(path, members=((MEMBER, PAYLOAD),), kind=tarfile.REGTYPE, link=None):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.linkname = link or "elsewhere"
                tar.addfile(info)
    return Path(path)


def pin_for(path, url="https://example.invalid/hhfctl.tar.gz"):
    data = Path(path).read_bytes()
    return {"url": url, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class PinTests(unittest.TestCase):
    def test_exact_public_pin(self):
        self.assertEqual(list(kfinstaller.PINS), ["0.96.2"])
        self.assertEqual(kfinstaller.PINS["0.96.2"], {
            "url": "https://github.com/githedgehog/fabric/releases/download/v0.96.2/"
                   "hhfctl-linux-amd64-v0.96.2.tar.gz",
            "size": 13620070,
            "sha256": "379b7ae4210f766fab733024bbb3313333135bfbde04ecf1bdf1d38e735aabca"})
        self.assertEqual((kfinstaller.PLATFORM, kfinstaller.NAME, kfinstaller.MEMBER),
                         ("linux/amd64", "kubectl-fabric", MEMBER))
        self.assertEqual((kfinstaller.TRANSFER, kfinstaller.CHILD, kfinstaller.TOTAL), (120, 125, 180))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "bin"
        self.destination.mkdir(mode=0o700)
        self.target = self.destination / "kubectl-fabric"
        self.archive = build_archive(self.root / "input.tar.gz")
        handler = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, handler)
        self.pin = pin_for(self.archive)
        patcher = patch.dict(kfinstaller.PINS, {"0.96.2": self.pin})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_install(self, archive="default", version="0.96.2", platform_name="linux/amd64"):
        return kfinstaller.install(version, platform_name, self.destination,
                                   self.archive if archive == "default" else archive)

    def names(self):
        return sorted(p.name for p in self.destination.iterdir())

    def repin(self, archive):
        self.pin.update(pin_for(archive))

    # --- install / rerun / conflict ----------------------------------------
    def test_absent_install_rerun_and_derived_result(self):
        outcome = self.run_install()
        self.assertEqual(outcome["status"], "installed")
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(self.names(), ["kubectl-fabric"])
        inode = self.target.stat().st_ino
        self.assertEqual(self.run_install()["status"], "unchanged")
        self.assertEqual(self.target.stat().st_ino, inode)
        self.assertEqual(self.names(), ["kubectl-fabric"])
        self.assertEqual(outcome["member_size"], len(PAYLOAD))
        self.assertEqual(outcome["member_sha256"], hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(outcome["target_sha256"], outcome["member_sha256"])
        self.assertEqual(outcome["archive_sha256"], self.pin["sha256"])
        self.assertEqual(outcome["archive_size"], self.pin["size"])
        self.assertEqual(outcome["target_mode"], "0755")
        self.assertEqual(outcome["target"], str(self.target))
        self.assertIs(outcome["executed"], False)
        self.assertIn("signature", outcome["not_verified"])
        self.assertIn("runtime compatibility", outcome["not_verified"])
        self.assertIn("derived", outcome["verified"])
        self.assertIn("no rollback", outcome["atomicity"])
        self.assertEqual(outcome["module_sha256"], hashlib.sha256(
            Path(__file__).with_name("install-kubectl-fabric.py").read_bytes()).hexdigest())
        self.assertLess(len(json.dumps(outcome)), 4096)

    def test_rerun_needs_the_verified_archive_again(self):
        self.run_install()
        for bad in (None, self.root / "missing"):
            with patch.object(kfinstaller, "curl", return_value="/usr/bin/curl"), \
                    patch.object(kfinstaller, "bounded", return_value=(22, b"")), \
                    self.assertRaises((release.Refusal, FileNotFoundError)):
                self.run_install(archive=bad)
        self.assertEqual(self.names(), ["kubectl-fabric"])

    def test_matching_bytes_wrong_mode_repaired_atomically(self):
        for mode in (0o644, 0o700, 0o4755):
            self.target.write_bytes(PAYLOAD)
            self.target.chmod(mode)
            before = self.target.stat().st_ino
            outcome = self.run_install()
            self.assertEqual(outcome["status"], "mode-repaired")
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
            self.assertEqual(self.target.read_bytes(), PAYLOAD)
            self.assertNotEqual(self.target.stat().st_ino, before)
            self.assertEqual(self.names(), ["kubectl-fabric"])
            self.target.unlink()

    def test_conflicting_existing_bytes_refused_and_preserved(self):
        for data in (OLD, PAYLOAD[:-1], PAYLOAD + b"X", PAYLOAD[:-1] + b"X", b""):
            self.target.write_bytes(data)
            self.target.chmod(0o644)
            before = self.target.stat()
            with self.assertRaisesRegex(release.Refusal, "differs from the archive member"):
                self.run_install()
            self.assertEqual(self.target.read_bytes(), data)
            self.assertEqual(self.target.stat().st_ino, before.st_ino)
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
            self.assertEqual(self.names(), ["kubectl-fabric"])

    def test_existing_target_owned_by_other_user_refused(self):
        self.target.write_bytes(PAYLOAD)
        real = os.geteuid()
        with patch.object(kfinstaller.os, "geteuid", return_value=real + 1), \
                patch.object(kfinstaller, "directory"), self.assertRaisesRegex(release.Refusal, "caller-owned"):
            self.run_install()

    # --- unsafe shapes --------------------------------------------------------
    def test_unsafe_targets_refused(self):
        other = self.root / "other"
        other.write_bytes(PAYLOAD)
        for shape in ("symlink", "directory", "hardlink", "fifo"):
            with contextlib.suppress(FileNotFoundError):
                self.target.unlink()
            if self.target.is_dir():
                self.target.rmdir()
            if shape == "symlink":
                self.target.symlink_to(other)
            elif shape == "directory":
                self.target.mkdir()
            elif shape == "hardlink":
                os.link(other, self.target)
            else:
                os.mkfifo(self.target)
            with self.assertRaises(release.Refusal, msg=shape):
                self.run_install()
            self.assertEqual(self.names(), ["kubectl-fabric"])
        self.assertEqual(other.read_bytes(), PAYLOAD)

    def test_unsafe_parents_and_unsupported_values_refused(self):
        link = self.root / "linked-bin"
        link.symlink_to(self.destination)
        for bad in (link, Path("relative/bin"), self.root / "missing"):
            with self.assertRaises((release.Refusal, FileNotFoundError)):
                kfinstaller.install("0.96.2", "linux/amd64", bad, self.archive)
        self.destination.chmod(0o770)
        with self.assertRaises(release.Refusal):
            self.run_install()
        self.destination.chmod(0o700)
        with self.assertRaises(release.Refusal):
            self.run_install(version="0.96.1")
        with self.assertRaises(release.Refusal):
            self.run_install(platform_name="linux/arm64")
        for name, value in (("system", "Darwin"), ("machine", "aarch64")):
            with patch.object(kfinstaller.platform, name, return_value=value), self.assertRaises(release.Refusal):
                self.run_install()
        self.assertEqual(self.names(), [])

    def test_default_requires_root_and_long_path_refused_early(self):
        with patch.object(kfinstaller.os, "geteuid", return_value=1000), \
                patch.object(kfinstaller, "directory", side_effect=AssertionError("must refuse early")), \
                self.assertRaisesRegex(release.Refusal, "requires root"):
            kfinstaller.install("0.96.2", "linux/amd64", Path("/usr/local/bin"), self.archive)
        with patch.object(kfinstaller, "directory", side_effect=AssertionError("must refuse early")), \
                self.assertRaisesRegex(release.Refusal, "result budget"):
            kfinstaller.install("0.96.2", "linux/amd64", Path("/" + "x" * 1100), self.archive)

    # --- archive validation -----------------------------------------------------
    def test_bad_archive_inputs_refused_before_staging(self):
        link = self.root / "link"
        link.symlink_to(self.archive)
        hard = self.root / "hard"
        os.link(self.archive, hard)
        data = self.archive.read_bytes()
        short = self.root / "short"
        short.write_bytes(data[:-1])
        wrong = self.root / "wrong"
        wrong.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        big = self.root / "big"
        big.write_bytes(data + b"X")
        for bad in (link, hard, short, wrong, big, self.root / "missing", self.root, Path("relative")):
            with patch.object(kfinstaller.tempfile, "mkdtemp", side_effect=AssertionError("mutation")), \
                    self.assertRaises((release.Refusal, FileNotFoundError), msg=str(bad)):
                self.run_install(archive=bad)
            self.assertEqual(self.names(), [])
        self.assertEqual(self.archive.read_bytes(), data)

    def test_unexpected_unsafe_or_duplicate_members_refused(self):
        cases = {
            "wrong-name": build_archive(self.root / "a1.tgz", ((("hhfctl-linux-amd64/other"), PAYLOAD),)),
            "traversal": build_archive(self.root / "a2.tgz", (("../hhfctl-linux-amd64/hhfctl", PAYLOAD),)),
            "absolute": build_archive(self.root / "a3.tgz", (("/hhfctl-linux-amd64/hhfctl", PAYLOAD),)),
            "extra": build_archive(self.root / "a4.tgz", ((MEMBER, PAYLOAD), ("README", b"x"))),
            "duplicate": build_archive(self.root / "a5.tgz", ((MEMBER, PAYLOAD), (MEMBER, PAYLOAD))),
            "symlink": build_archive(self.root / "a6.tgz", ((MEMBER, b""),), kind=tarfile.SYMTYPE),
            "hardlink": build_archive(self.root / "a7.tgz", ((MEMBER, b""),), kind=tarfile.LNKTYPE),
            "directory": build_archive(self.root / "a8.tgz", ((MEMBER, b""),), kind=tarfile.DIRTYPE),
            "empty-member": build_archive(self.root / "a9.tgz", ((MEMBER, b""),)),
            "empty-archive": build_archive(self.root / "a10.tgz", ()),
        }
        for name, path in cases.items():
            self.repin(path)
            with self.assertRaises(release.Refusal, msg=name):
                self.run_install(archive=path)
            self.assertEqual(self.names(), [], msg=name)

    def test_oversize_member_refused_by_bound(self):
        with patch.object(kfinstaller, "MEMBER_LIMIT", len(PAYLOAD) - 1), \
                self.assertRaisesRegex(release.Refusal, "bounded limit"):
            self.run_install()
        self.assertEqual(self.names(), [])
        with patch.object(kfinstaller, "MEMBER_LIMIT", len(PAYLOAD)):
            self.assertEqual(self.run_install()["status"], "installed")

    def test_corrupt_and_truncated_archives_with_matching_pin_refused(self):
        data = self.archive.read_bytes()
        for name, content in (("truncated", data[: len(data) // 2]), ("garbage", b"not gzip at all" * 20),
                              ("corrupt", data[:-12] + bytes(b ^ 0xFF for b in data[-12:]))):
            path = self.root / name
            path.write_bytes(content)
            self.repin(path)
            with self.assertRaises(release.Refusal, msg=name):
                self.run_install(archive=path)
            self.assertEqual(self.names(), [], msg=name)

    def test_declared_member_larger_than_content_refused(self):
        raw = self.root / "raw.tar"
        with tarfile.open(raw, "w") as tar:
            info = tarfile.TarInfo(MEMBER)
            info.size = len(PAYLOAD)
            tar.addfile(info, io.BytesIO(PAYLOAD))
        content = raw.read_bytes()[: 512 + len(PAYLOAD) // 2]
        import gzip
        short = self.root / "cut.tgz"
        short.write_bytes(gzip.compress(content))
        self.repin(short)
        with self.assertRaises(release.Refusal):
            self.run_install(archive=short)
        self.assertEqual(self.names(), [])

    def test_input_changed_after_validation_refused_and_cleaned(self):
        real = kfinstaller.copy_archive

        def swap(source, target, pin):
            source.write_bytes(source.read_bytes()[:-1] + b"X")
            return real(source, target, pin)
        with patch.object(kfinstaller, "copy_archive", swap), self.assertRaises(release.Refusal):
            self.run_install()
        self.assertEqual(self.names(), [])

    # --- download contract ---------------------------------------------------
    def fake_download(self, writer, calls):
        def fake(args, seconds, **kwargs):
            calls.append((args, seconds, kwargs))
            return writer(Path(args[args.index("--output") + 1]))
        return fake

    def test_download_argv_env_deadline_and_install(self):
        calls = []

        def write(path):
            path.write_bytes(self.archive.read_bytes())
            return 0, b""
        with patch.object(kfinstaller, "bounded", self.fake_download(write, calls)), \
                patch.object(kfinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.dict(os.environ, {"HTTPS_PROXY": "http://x", "CURL_HOME": "/x", "KUBECONFIG": "/x",
                                        "HOME": "/x", "SSL_CERT_FILE": "/x"}):
            outcome = self.run_install(archive=None)
        (args, seconds, kwargs), = calls
        self.assertEqual(outcome["status"], "installed")
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
        self.assertEqual(args[-1], self.pin["url"])
        for flag in ("--fail", "--proto", "--proto-redir", "--retry", "--max-time", "--max-filesize", "--output"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
        self.assertEqual(args[args.index("--retry") + 1], "0")
        self.assertEqual(args[args.index("--max-time") + 1], "120")
        self.assertEqual(args[args.index("--max-filesize") + 1], str(self.pin["size"]))
        for forbidden in ("--insecure", "-k", "--user", "--proxy", "--netrc"):
            self.assertNotIn(forbidden, args)
        self.assertEqual(seconds, 125)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self.assertTrue(Path(args[args.index("--output") + 1]).is_absolute())
        self.assertEqual(self.names(), ["kubectl-fabric"])

    def test_download_failures_preserve_target_and_remove_stage(self):
        data = self.archive.read_bytes()
        outcomes = {
            "nonzero": lambda p: (22, b""),
            "oversize": lambda p: (p.write_bytes(data + b"X"), 0)[1:] + (b"",),
            "short": lambda p: (p.write_bytes(data[:-1]), 0)[1:] + (b"",),
            "badhash": lambda p: (p.write_bytes(data[:-1] + b"X"), 0)[1:] + (b"",),
            "missing": lambda p: (0, b""),
            "symlink": lambda p: (p.symlink_to(self.archive), 0)[1:] + (b"",),
        }
        for name, writer in outcomes.items():
            for prior in (None, "wrong-mode"):
                if prior is None:
                    with contextlib.suppress(FileNotFoundError):
                        self.target.unlink()
                else:
                    self.target.write_bytes(PAYLOAD)
                    self.target.chmod(0o644)
                calls = []
                with patch.object(kfinstaller, "bounded", self.fake_download(writer, calls)), \
                        patch.object(kfinstaller, "curl", return_value="/usr/bin/curl"), \
                        self.assertRaises((release.Refusal, OSError), msg=name):
                    self.run_install(archive=None)
                self.assertEqual(len(calls), 1)
                if prior is None:
                    self.assertEqual(self.names(), [])
                else:
                    self.assertEqual(self.names(), ["kubectl-fabric"])
                    self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
                    self.assertEqual(self.target.read_bytes(), PAYLOAD)

    def test_missing_curl_refused_before_staging(self):
        with patch.object(kfinstaller, "CURL_DIRS", (str(self.root / "none"),)), \
                patch.object(kfinstaller.tempfile, "mkdtemp", side_effect=AssertionError("mutation")), \
                self.assertRaisesRegex(release.Refusal, "curl"):
            self.run_install(archive=None)

    # --- cleanup / races / interruption ---------------------------------------------
    def test_keyboard_interrupt_removes_exact_stage_only(self):
        (self.destination / "other").write_text("unrelated")
        with patch.object(kfinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.object(kfinstaller, "bounded", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.run_install(archive=None)
        self.assertEqual(self.names(), ["other"])

    def test_destination_change_during_install_refused(self):
        real = kfinstaller.extract_member

        def appear(archive, target, pin):
            out = real(archive, target, pin)
            self.target.write_bytes(b"racing writer")
            return out
        with patch.object(kfinstaller, "extract_member", appear), \
                self.assertRaisesRegex(release.Refusal, "destination changed"):
            self.run_install()
        self.assertEqual(self.target.read_bytes(), b"racing writer")
        self.assertEqual(self.names(), ["kubectl-fabric"])
        self.target.write_bytes(PAYLOAD)
        self.target.chmod(0o644)

        def replace(archive, target, pin):
            out = real(archive, target, pin)
            replacement = self.root / "replacement"
            replacement.write_bytes(PAYLOAD)
            os.replace(replacement, self.target)
            return out
        with patch.object(kfinstaller, "extract_member", replace), \
                self.assertRaisesRegex(release.Refusal, "destination changed"):
            self.run_install()
        self.assertEqual(self.names(), ["kubectl-fabric"])

    def test_cleanup_failure_handling(self):
        with patch.object(kfinstaller.shutil, "rmtree", side_effect=OSError("cleanup")), \
                patch.object(kfinstaller, "copy_archive", side_effect=release.Refusal("primary")), \
                self.assertRaisesRegex(release.Refusal, "primary"):
            self.run_install()
        for stale in self.destination.glob(".kubectl-fabric-stage-*"):
            import shutil
            shutil.rmtree(stale)
        with patch.object(kfinstaller.shutil, "rmtree", side_effect=OSError("cleanup")), \
                self.assertRaisesRegex(release.Refusal, "cleanup failed"):
            self.run_install()
        self.assertEqual(self.target.read_bytes(), PAYLOAD)

    def test_total_deadline_alarm_cancels_and_cleans(self):
        (self.destination / "other").write_text("unrelated")
        with patch.object(kfinstaller, "TOTAL", 1), patch.object(kfinstaller, "curl", return_value="/usr/bin/curl"), \
                patch.object(kfinstaller, "bounded", lambda *a, **k: __import__("time").sleep(5)), \
                patch.object(sys, "argv", ["x", "--version", "0.96.2", "--platform", "linux/amd64",
                                           "--install-dir", str(self.destination)]):
            with self.assertRaisesRegex(release.Refusal, "deadline exceeded"):
                kfinstaller.main()
        self.assertEqual(signal.alarm(0), 0)
        self.assertEqual(self.names(), ["other"])

    # --- no execution, result budget, CLI -----------------------------------------------
    def test_no_installed_byte_execution_or_kubeconfig_use(self):
        guards = {name: AssertionError("must not execute") for name in ("system", "execv", "execve", "spawnv")}
        with patch.object(kfinstaller.os, "system", side_effect=guards["system"]), \
                patch.object(kfinstaller.os, "execv", side_effect=guards["execv"]), \
                patch.object(kfinstaller, "bounded", side_effect=AssertionError("no child in local mode")), \
                patch.dict(os.environ, {"KUBECONFIG": str(self.root / "must-not-be-read")}):
            self.run_install()
            self.run_install()
        self.assertFalse((self.root / "must-not-be-read").exists())

    def test_result_refuses_observed_change_and_oversized_report(self):
        outcome = self.run_install()
        derived = {"size": outcome["member_size"], "sha256": outcome["member_sha256"]}
        self.target.chmod(0o644)
        with self.assertRaisesRegex(release.Refusal, "fails verification"):
            kfinstaller.result("0.96.2", self.pin, derived, self.target, "unchanged")
        self.target.chmod(0o755)
        with patch.object(kfinstaller, "RESULT_LIMIT", 1), \
                self.assertRaisesRegex(release.Refusal, "output budget"):
            kfinstaller.result("0.96.2", self.pin, derived, self.target, "unchanged")

    def test_cli_prints_one_json_line_and_requires_explicit_pin(self):
        argv = ["x", "--version", "0.96.2", "--platform", "linux/amd64", "--install-dir", str(self.destination),
                "--archive", str(self.archive)]
        out = io.StringIO()
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(out):
            kfinstaller.main()
        self.assertEqual(json.loads(out.getvalue())["status"], "installed")
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        for bad in (["x"], ["x", "--version", "0.96.2"], ["x", "--version", "latest", "--platform", "linux/amd64"],
                    ["x", "--version", "0.96.2", "--platform", "linux/arm64"],
                    ["x", "--version=0.96.2", "--platform", "linux/amd64", "--force"],
                    ["x", "--vers", "0.96.2", "--platform", "linux/amd64"]):
            with patch.object(sys, "argv", bad), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                kfinstaller.main()


if __name__ == "__main__":
    unittest.main()
