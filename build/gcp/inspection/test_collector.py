"""Synthetic filesystems only; never needs mounts, cloud or credentials."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from inspection.collector import (DPKG_LIMIT, FILE_LIMIT, ENTRY_LIMIT, Gap, Guest,
                                  collect, helper_refs, main, write_private)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "guest"
        self.root.mkdir()
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.marker = "NOSECRET_HOST_ESCAPE"
        self.host = self.base / "host"
        self.host.write_text(self.marker)

    def put(self, path, text):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def record(self, path):
        return next(r for r in collect(self.root)["records"] if r["path"] == path)

    def assert_no_host(self, report):
        self.assertNotIn(self.marker, json.dumps(report))

    def test_private_unit_helper_and_installed_packages(self):
        unit = "/etc/systemd/system/kubeconfig-merge.service"
        self.put(unit, "[Service]\nExecStart=/usr/local/bin/kubeconfig-merge.sh\n")
        self.put("/usr/local/bin/kubeconfig-merge.sh", "#!/bin/sh\necho PRIVATE_VALUE\n")
        self.put("/etc/os-release", 'ID=ubuntu\n')
        self.put("/var/lib/dpkg/status", "Package: qemu-system-x86\nVersion: 1:8.2+dfsg-1\n"
                 "Status: install ok installed\nDescription: NOT_COPIED\n\n"
                 "Package: removed\nVersion: 1\nStatus: deinstall ok config-files\n")
        report = collect(self.root)
        self.assertTrue(report["private_review_required"])
        helpers = [r for r in report["records"] if r["kind"] == "helper"]
        self.assertEqual(len(helpers), 1)
        self.assertIn("PRIVATE_VALUE", helpers[0]["private_content"])
        packages = next(r for r in report["records"] if r["kind"] == "packages")
        self.assertEqual(packages["packages"], [{"name": "qemu-system-x86", "version": "1:8.2+dfsg-1"}])
        self.assertNotIn("NOT_COPIED", json.dumps(report))
        self.assertNotIn("private_content", packages)

    def test_missing(self):
        self.assertEqual(self.record("/etc/os-release")["status"], "missing")

    def test_historical_helper_names(self):
        for name in ("hhbr-ip-setup.sh", "fix-argocd-port.sh"):
            self.assertEqual(list(helper_refs("ExecStart=/usr/local/bin/" + name)),
                             ["/usr/local/bin/" + name])

    def test_absolute_symlink_never_reads_host(self):
        target = self.put("/etc/os-release", "")
        target.unlink()
        target.symlink_to(self.host)
        report = collect(self.root)
        self.assert_no_host(report)
        self.assertEqual(self.record("/etc/os-release")["status"], "symlink_skipped")

    def test_intermediate_symlink_never_reads_host(self):
        (self.root / "etc").symlink_to(self.base, target_is_directory=True)
        self.assert_no_host(collect(self.root))
        self.assertEqual(self.record("/etc/os-release")["status"], "symlink_skipped")

    def test_relative_escape_link(self):
        link = self.put("/etc/os-release", "")
        link.unlink()
        link.symlink_to("../../host")
        self.assert_no_host(collect(self.root))
        self.assertEqual(self.record("/etc/os-release")["status"], "symlink_skipped")

    def test_absolute_guest_link_reported_as_gap(self):
        self.put("/usr/lib/os-release", "ID=guest\n")
        link = self.put("/etc/os-release", "")
        link.unlink()
        link.symlink_to("/usr/lib/os-release")
        self.assertEqual(self.record("/etc/os-release")["status"], "symlink_skipped")

    def test_link_cycle(self):
        link = self.put("/etc/os-release", "")
        link.unlink()
        link.symlink_to("os-release")
        self.assertEqual(self.record("/etc/os-release")["status"], "symlink_skipped")

    def test_symlinked_dropin_directory(self):
        path = self.root / "etc/systemd/system/hhbr-ip.service.d"
        path.parent.mkdir(parents=True)
        path.symlink_to(self.base, target_is_directory=True)
        self.assertEqual(self.record("/etc/systemd/system/hhbr-ip.service.d")["status"], "symlink_skipped")

    def test_symlinked_dropin_file(self):
        path = self.put("/etc/systemd/system/hhbr-ip.service.d/override.conf", "")
        path.unlink()
        path.symlink_to(self.host)
        self.assertEqual(self.record("/etc/systemd/system/hhbr-ip.service.d/override.conf")["status"], "symlink_skipped")
        self.assert_no_host(collect(self.root))

    def test_oversize(self):
        self.put("/etc/os-release", "x" * (FILE_LIMIT + 1))
        self.assertEqual(self.record("/etc/os-release")["status"], "oversize")

    def test_nontext(self):
        for data in (b"\xff", b"hello\x00secret"):
            path = self.put("/etc/os-release", "")
            path.write_bytes(data)
            self.assertEqual(self.record("/etc/os-release")["status"], "nontext")

    def test_fifo_never_blocks(self):
        path = self.root / "etc/os-release"
        path.parent.mkdir()
        os.mkfifo(path)
        self.assertEqual(self.record("/etc/os-release")["status"], "not_regular")

    def test_malicious_references_never_followed(self):
        unit = "\n".join("ExecStart=" + command for command in (
            str(self.host), "/etc/shadow", "/usr/local/bin/../../etc/shadow",
            "/usr/local/bin/token", "/usr/local/bin/kubeconfig",
            "/bin/sh -c 'cat /etc/shadow'", "$(cat /etc/shadow)",
            "/usr/local/bin/hhbr-ip;cat /etc/shadow", "\"unterminated"))
        self.put("/etc/systemd/system/hhbr-ip.service", unit)
        report = collect(self.root)
        self.assertFalse([r for r in report["records"] if r["kind"] == "helper"])
        self.assert_no_host(report)

    def test_helper_intermediate_escape(self):
        self.put("/etc/systemd/system/hhbr-ip.service", "ExecStart=/usr/local/bin/hhbr-ip\n")
        (self.root / "usr/local").mkdir(parents=True)
        (self.root / "usr/local/bin").symlink_to(self.base)
        self.assertEqual(self.record("/usr/local/bin/hhbr-ip")["status"], "symlink_skipped")

    def test_no_recursive_helper_parsing(self):
        self.put("/etc/systemd/system/hhbr-ip.service", "ExecStart=/usr/local/bin/hhbr-ip\n")
        self.put("/usr/local/bin/hhbr-ip", "ExecStart=/usr/local/bin/kubeconfig-merge\n")
        self.put("/usr/local/bin/kubeconfig-merge", self.marker)
        self.assert_no_host(collect(self.root))

    def test_bounded_directory(self):
        for i in range(ENTRY_LIMIT + 1):
            self.put(f"/etc/systemd/system/hhbr-ip.service.d/{i}.conf", "")
        self.assertEqual(self.record("/etc/systemd/system/hhbr-ip.service.d")["status"], "too_many_entries")

    def test_private_file_mode_no_overwrite_or_stdout(self):
        self.put("/etc/os-release", "PRIVATE_OS_VALUE")
        output = self.private / "inventory.json"
        stdout = io.StringIO()
        with patch("sys.argv", ["collector", "--root", str(self.root), "--private-output", str(output)]), contextlib.redirect_stdout(stdout):
            main()
        self.assertNotIn("PRIVATE_OS_VALUE", stdout.getvalue())
        self.assertNotIn(str(output), stdout.getvalue())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            write_private(self.root, output)
        self.assertIn("PRIVATE_OS_VALUE", output.read_text())

    def test_private_parent_required(self):
        self.private.chmod(0o755)
        with self.assertRaisesRegex(Gap, "private_parent_required"):
            write_private(self.root, self.private / "inventory.json")

    def test_output_inside_guest_rejected(self):
        self.root.chmod(0o700)
        with self.assertRaisesRegex(Gap, "output_inside_guest"):
            write_private(self.root, self.root / "inventory.json")

    def test_output_symlink_not_followed(self):
        output = self.private / "inventory.json"
        output.symlink_to(self.host)
        with self.assertRaises(FileExistsError):
            write_private(self.root, output)
        self.assertEqual(self.host.read_text(), self.marker)

    def test_invalid_guest_paths_rejected(self):
        guest = Guest(self.root)
        self.addCleanup(guest.close)
        for path in ("etc/shadow", "/etc/../shadow", "/etc//shadow"):
            with self.assertRaisesRegex(Gap, "invalid_path"):
                guest.open(path)

    def test_report_bound_produces_no_output(self):
        output = self.private / "inventory.json"
        with patch("inspection.collector.REPORT_LIMIT", 1), self.assertRaisesRegex(Gap, "report_oversize"):
            write_private(self.root, output)
        self.assertFalse(output.exists())

    def test_malformed_dpkg_not_copied(self):
        self.put("/var/lib/dpkg/status", "Package: BAD_NAME\nVersion: 1\nStatus: install ok installed\n")
        self.assertEqual(self.record("/var/lib/dpkg/status")["status"], "invalid_dpkg")


if __name__ == "__main__":
    unittest.main()
