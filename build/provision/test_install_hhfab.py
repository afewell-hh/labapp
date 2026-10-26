"""Installer behavior with synthetic public archives, plus actual isolated CLI lane."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import hhfab_release as release
spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install-hhfab.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "bin"
        self.destination.mkdir(mode=0o700)
        self.target = self.destination / "hhfab"
        self.target.write_bytes(b"old binary, never execute")
        self.archive = self.root / "release.tar.gz"
        self.archive_for()

    def archive_for(self, name="hhfab-linux-amd64/hhfab", kind=tarfile.REGTYPE):
        with tarfile.open(self.archive, "w:gz") as tar:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 4 if kind == tarfile.REGTYPE else 0
            tar.addfile(member, io.BytesIO(b"test") if member.size else None)
        self.pin = (self.archive.stat().st_size, release.digest(self.archive), 4, hashlib.sha256(b"test").hexdigest())

    def run_install(self):
        with patch.dict(installer.PINS, {"fixture": self.pin}):
            return installer.install("fixture", self.destination, self.archive)

    def test_atomic_install_idempotence_and_mode_repair(self):
        self.assertEqual(self.run_install(), "installed")
        inode = self.target.stat().st_ino
        self.assertEqual(self.run_install(), "unchanged")
        self.assertEqual(self.target.stat().st_ino, inode)
        self.target.chmod(0o644)
        self.assertEqual(self.run_install(), "installed")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(self.target.read_bytes(), b"test")
        self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_integrity_failures_preserve_prior_state(self):
        for index in (0, 1, 2, 3):
            with self.subTest(index=index):
                pin = list(self.pin)
                pin[index] = pin[index] + 1 if index in (0, 2) else "0" * 64
                with patch.dict(installer.PINS, {"fixture": tuple(pin)}), self.assertRaises(release.Refusal):
                    installer.install("fixture", self.destination, self.archive)
                self.assertEqual(self.target.read_bytes(), b"old binary, never execute")
                self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_matching_target_returns_unchanged_before_reading_the_archive(self):
        # Why a corrupt-archive negative needs isolated, nonmatching prior bytes (#274):
        # an already pinned 0755 target is answered "unchanged" before the archive is opened.
        self.assertEqual(self.run_install(), "installed")
        self.archive.write_bytes(b"corrupt, wrong size and digest")
        self.assertEqual(self.run_install(), "unchanged")
        self.assertEqual(self.target.read_bytes(), b"test")
        self.archive.unlink()                              # not even present
        self.assertEqual(self.run_install(), "unchanged")
        self.archive_for()
        self.target.write_bytes(b"old binary, never execute")      # nonmatching prior bytes
        self.archive.write_bytes(b"corrupt, wrong size and digest")
        with self.assertRaisesRegex(release.Refusal, "archive checksum/size mismatch"):
            self.run_install()
        self.assertEqual(self.target.read_bytes(), b"old binary, never execute")
        self.assertEqual(list(self.destination.iterdir()), [self.target])
        self.target.unlink()                               # absent target: the same refusal, nothing left
        with self.assertRaisesRegex(release.Refusal, "archive checksum/size mismatch"):
            self.run_install()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_archive_member_safety_preserves_existing(self):
        for name, kind in [("../escape", tarfile.REGTYPE), ("hhfab-linux-amd64/hhfab", tarfile.SYMTYPE),
                           ("hhfab-linux-amd64/hhfab", tarfile.LNKTYPE)]:
            self.archive_for(name, kind)
            with self.assertRaises(release.Refusal):
                self.run_install()
            self.assertEqual(self.target.read_bytes(), b"old binary, never execute")

    def test_unsafe_destinations_refused_without_mutation(self):
        for shape in ("symlink", "directory", "hardlink"):
            self.target.unlink() if self.target.is_file() or self.target.is_symlink() else self.target.rmdir()
            if shape == "symlink":
                self.target.symlink_to(self.archive)
            elif shape == "directory":
                self.target.mkdir()
            else:
                os.link(self.archive, self.target)
            with self.assertRaises(release.Refusal):
                self.run_install()
            self.assertEqual(list(self.destination.iterdir()), [self.target])
        link = self.root / "linked-bin"
        link.symlink_to(self.destination)
        with self.assertRaises(release.Refusal):
            installer.install("0.43.1", link, self.archive)
        self.destination.chmod(0o777)
        with self.assertRaises(release.Refusal):
            self.run_install()

    def test_bad_platform_version_and_archive_link_before_mutation(self):
        for changes in ({"platform.system": "Darwin"}, {"platform.machine": "aarch64"}):
            key, value = next(iter(changes.items()))
            with patch.object(getattr(installer, key.split('.')[0]), key.split('.')[1], return_value=value):
                with self.assertRaises(release.Refusal):
                    self.run_install()
        with self.assertRaises(release.Refusal):
            installer.install("unapproved", self.destination)
        alias = self.root / "alias"
        alias.symlink_to(self.archive)
        with self.assertRaises(release.Refusal):
            installer.install("0.43.1", self.destination, alias)
        self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_download_failure_preserves_existing_and_removes_stage(self):
        with patch.dict(installer.PINS, {"fixture": self.pin}), patch.object(installer, "download", side_effect=release.Refusal("official release download failed")):
            with self.assertRaises(release.Refusal):
                installer.install("fixture", self.destination)
        self.assertEqual(self.target.read_bytes(), b"old binary, never execute")
        self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_installer_alarm_and_interruption_preserve_existing(self):
        fake = self.root / "curl"
        script = Path(__file__).with_name("install-hhfab.py")
        for kind in ("alarm", "termination"):
            fake.write_text("#!/bin/sh\n" + ("kill -TERM \"$PPID\"\n" if kind == "termination" else "") + "sleep 10\n")
            fake.chmod(0o755)
            program = ("import runpy,signal,sys; "
                       "original=signal.alarm; signal.alarm=lambda seconds:original(min(seconds,1)); "
                       "sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; "
                       "runpy.run_path(sys.argv[0],run_name='__main__')")
            result = subprocess.run([sys.executable, "-c", program, str(script.parent), str(script),
                                     "--version", "0.43.1", "--install-dir", str(self.destination)],
                                    env=dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"]),
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"deadline exceeded" if kind == "alarm" else b"interrupted", result.stderr)
            self.assertEqual(self.target.read_bytes(), b"old binary, never execute")
            self.assertEqual(list(self.destination.iterdir()), [self.target])

    def test_real_download_child_failure_and_bounds(self):
        fake = self.root / "curl"
        for script in ("exit 22", "sleep 10"):
            fake.write_text("#!/bin/sh\n" + script + "\n")
            fake.chmod(0o755)
            original = release.bounded
            def quick(args, _seconds):
                # Keep exact downloader argv, shorten only external test deadline.
                self.assertIn("--max-filesize", args)
                self.assertIn("--max-time", args)
                self.assertIn("--proto-redir", args)
                return original(args, .1)
            with patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}), patch.object(release, "bounded", side_effect=quick):
                with self.assertRaises(release.Refusal):
                    installer.install("0.43.1", self.destination)
            self.assertEqual(self.target.read_bytes(), b"old binary, never execute")
            self.assertEqual(list(self.destination.iterdir()), [self.target])


def lane(version):
    if os.environ.get("LABAPP_HHFAB_TEST") != "1" or os.getuid() != 1000:
        raise release.Refusal("requires isolated nonroot test runner")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if int(status["CapEff"].strip(), 16) or status["NoNewPrivs"].strip() != "1":
        raise release.Refusal("privilege isolation mismatch")
    if {p.name for p in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise release.Refusal("network isolation mismatch")
    destination = Path("/work/bin")
    destination.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/work", "LANG": "C.UTF-8", "GOMAXPROCS": "2"}
    args = ["python3", "/suite/install-hhfab.py", "--version", version, "--install-dir", str(destination),
            "--archive", "/suite/" + version + ".tar.gz"]
    checks = []
    for check in ("clean-install", "idempotent-rerun", "matching-mode-repair"):
        if check == "matching-mode-repair":
            (destination / "hhfab").chmod(0o644)
        code, output = release.bounded(args, 45, env=env)
        if code or release.digest(destination / "hhfab") != release.PINS[version][3]:
            raise release.Refusal("same-code installation failed")
        if stat.S_IMODE((destination / "hhfab").stat().st_mode) != 0o755:
            raise release.Refusal("installed mode mismatch")
        checks.append(check)
    code, output = release.bounded([str(destination / "hhfab"), "--version"], 15, env=env)
    if code or version.encode() not in output:
        raise release.Refusal("installed CLI smoke failed")
    print(json.dumps({"version": version, "status": "passed", "checks": checks + ["installed-cli-version"],
                      "binary_sha256": release.PINS[version][3]}))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "lane":
        lane(sys.argv[2])
    else:
        unittest.main()
