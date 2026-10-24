"""Mocked inspector commands only: no mounts, devices, privileges or cloud."""
import contextlib
import copy
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from inspection import mounted_collect as wrapper


class MountWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.mountpoint = self.private / "guest-root"
        self.calls = []
        self.collected = []
        self.layout = {"blockdevices": [{"name": "/dev/sdb", "maj:min": "8:16",
            "type": "disk", "fstype": None, "ro": True, "mountpoints": [None],
            "children": [{"name": "/dev/sdb1", "maj:min": "8:17", "type": "part",
                          "fstype": "ext4", "ro": True, "mountpoints": [None]}]}]}
        self.clean = "Filesystem state:         clean\nFilesystem features:      has_journal extent\n"
        self.mount = {"target": str(self.mountpoint), "source": "/dev/sdb1",
                      "maj:min": "8:17", "fstype": "ext4", "propagation": "private",
                      "options": "ro,nosuid,nodev,noexec,relatime,norecovery"}
        self.device_patch = patch.object(wrapper, "device_number")
        self.device_patch.start()
        self.addCleanup(self.device_patch.stop)
        self.ns_patch = patch.object(wrapper.os, "readlink", side_effect=["mnt:[2]", "mnt:[1]"] * 100)
        self.ns_patch.start()
        self.addCleanup(self.ns_patch.stop)

    def fake_run(self, argv):
        self.calls.append(argv)
        name = Path(argv[0]).name
        if name == "findmnt":
            if "--target" in argv:
                return json.dumps({"filesystems": [{"maj:min": "8:1", "propagation": "private"}]})
            return json.dumps({"filesystems": [self.mount]})
        if name == "lsblk":
            return json.dumps(self.layout)
        if name == "dumpe2fs":
            return self.clean
        return ""

    def fake_collect(self, root, output):
        self.collected.append((root, output))
        output.write_text("PRIVATE_MARKER")
        output.chmod(0o600)
        return {"records": 1}

    def execute(self, run=None, collector=None):
        return wrapper.collect_mounted("/dev/sdb", "/dev/sdb1", "8:16", "8:17",
            self.private, run=run or self.fake_run, collector=collector or self.fake_collect)

    def test_success_exact_commands_and_private_result(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.execute(), {"records": 1})
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(self.calls[-3], ["/usr/bin/mount", "--internal-only", "-t", "ext4",
                         "-o", "ro,noload,nodev,nosuid,noexec", "--", "/dev/sdb1", str(self.mountpoint)])
        self.assertEqual(self.calls[-1], ["/usr/bin/umount", "--internal-only", "--", str(self.mountpoint)])
        self.assertFalse(self.mountpoint.exists())
        self.assertEqual((self.private / "inventory.json").read_text(), "PRIVATE_MARKER")
        self.assertEqual(stat.S_IMODE((self.private / "inventory.json").stat().st_mode), 0o600)

    def test_real_unchanged_collector_on_synthetic_mount(self):
        def run(argv):
            if Path(argv[0]).name == "mount":
                etc = self.mountpoint / "etc"
                etc.mkdir()
                (etc / "os-release").write_text("ID=synthetic\n")
            if Path(argv[0]).name == "umount":
                (self.mountpoint / "etc/os-release").unlink()
                (self.mountpoint / "etc").rmdir()
            return self.fake_run(argv)
        result = self.execute(run=run, collector=wrapper.write_private)
        self.assertGreater(result["records"], 0)
        self.assertNotIn("ID=synthetic", json.dumps(result))
        data = json.loads((self.private / "inventory.json").read_text())
        self.assertEqual(data["records"][0]["private_content"], "ID=synthetic\n")

    def test_root_namespace_refused_before_commands(self):
        self.ns_patch.stop()
        with patch.object(wrapper.os, "readlink", return_value="mnt:[1]"), self.assertRaisesRegex(wrapper.Refused, "private_namespace_required"):
            self.execute()
        self.assertFalse(self.calls)

    def test_nonprivate_propagation(self):
        def run(argv):
            return json.dumps({"filesystems": [{"maj:min": "8:1", "propagation": "shared"}]})
        with self.assertRaisesRegex(wrapper.Refused, "private_namespace_required"):
            self.execute(run=run)
        self.assertFalse(self.collected)

    def test_identity_mismatch_never_mounts(self):
        with patch.object(wrapper, "device_number", side_effect=wrapper.Refused("device_identity_mismatch")), self.assertRaises(wrapper.Refused):
            self.execute()
        self.assertFalse(any(Path(c[0]).name == "mount" for c in self.calls))

    def test_refuses_unsafe_layouts_before_mount(self):
        original = copy.deepcopy(self.layout)
        for mutation in ("writable_disk", "writable_part", "mounted", "lvm", "encrypted", "extra_ext4", "wrong_number", "boot_disk"):
            self.layout = copy.deepcopy(original)
            parent = self.layout["blockdevices"][0]
            child = parent["children"][0]
            if mutation == "writable_disk": parent["ro"] = False
            if mutation == "writable_part": child["ro"] = False
            if mutation == "mounted": child["mountpoints"] = ["/other"]
            if mutation == "lvm": child["type"] = "lvm"
            if mutation == "encrypted": child["fstype"] = "crypto_LUKS"
            if mutation == "extra_ext4": parent["children"].append(copy.deepcopy(child))
            if mutation == "wrong_number": child["maj:min"] = "8:18"
            if mutation == "boot_disk": child["maj:min"] = "8:1"
            self.calls.clear()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(wrapper.Refused, "unsupported_disk_layout"):
                self.execute()
            self.assertFalse(any(Path(c[0]).name == "mount" for c in self.calls))
        self.assertFalse(self.collected)

    def test_dirty_or_recovery_needed_refused(self):
        for value in ("Filesystem state: not clean\nFilesystem features: extent\n",
                      "Filesystem state: clean\nFilesystem features: needs_recovery extent\n",
                      "Filesystem state: clean with errors\nFilesystem features: extent\n", "bad"):
            self.clean = value
            with self.subTest(value=value), self.assertRaisesRegex(wrapper.Refused, "unclean_filesystem"):
                self.execute()
        self.assertFalse(any(Path(c[0]).name == "mount" for c in self.calls))

    def test_postmount_verification_failure_always_unmounts(self):
        for key, value in (("source", "/dev/sda1"), ("maj:min", "8:1"), ("fstype", "xfs"),
                           ("options", "rw,nodev,nosuid,noexec,norecovery"),
                           ("options", "ro,nodev,nosuid,noexec"), ("propagation", "shared")):
            old = self.mount[key]
            self.mount[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(wrapper.Refused, "mount_contract_failed"):
                self.execute()
            self.mount[key] = old
            self.assertEqual(Path(self.calls[-1][0]).name, "umount")
            self.assertFalse(self.mountpoint.exists())
        self.assertFalse(self.collected)

    def test_mount_failure_still_attempts_unmount(self):
        def run(argv):
            if Path(argv[0]).name == "mount":
                raise wrapper.Refused("command_failed")
            return self.fake_run(argv)
        with self.assertRaisesRegex(wrapper.Refused, "command_failed"):
            self.execute(run=run)
        self.assertEqual(Path(self.calls[-1][0]).name, "umount")
        self.assertFalse(self.collected)

    def test_cancel_removes_partial_raw_and_unmounts(self):
        def collect(root, output):
            output.write_text("PRIVATE_PARTIAL")
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.execute(collector=collect)
        self.assertEqual(Path(self.calls[-1][0]).name, "umount")
        self.assertFalse((self.private / "inventory.json").exists())
        self.assertFalse(self.mountpoint.exists())

    def test_unmount_failure_refuses_success_and_preserves_mountpoint(self):
        def run(argv):
            if Path(argv[0]).name == "umount":
                raise wrapper.Refused("command_failed")
            return self.fake_run(argv)
        with self.assertRaisesRegex(wrapper.Refused, "unmount_failed"):
            self.execute(run=run)
        self.assertTrue(self.mountpoint.exists())

    def test_private_directory_symlink_or_nonempty_refused(self):
        self.private.rmdir()
        self.private.symlink_to(Path(self.temp.name))
        with self.assertRaisesRegex(wrapper.Refused, "invalid_private_directory"):
            self.execute()
        self.private.unlink()
        self.private.mkdir(mode=0o700)
        (self.private / "existing").write_text("KEEP")
        with self.assertRaisesRegex(wrapper.Refused, "private_directory_not_empty"):
            self.execute()
        self.assertEqual((self.private / "existing").read_text(), "KEEP")

    def test_device_validation_never_opens_special_files(self):
        self.device_patch.stop()
        for mode, number, path in ((stat.S_IFLNK, 0, "/dev/sdb"),
                                   (stat.S_IFREG, 0, "/dev/sdb"),
                                   (stat.S_IFBLK, 0, "/dev/sdb"),
                                   (stat.S_IFBLK, 0, "/dev/../sdb")):
            with patch.object(wrapper.os, "lstat", return_value=SimpleNamespace(st_mode=mode, st_rdev=number)), patch("builtins.open") as opened:
                with self.assertRaises(wrapper.Refused):
                    wrapper.device_number(path, "8:16")
                opened.assert_not_called()

    def test_exact_direct_block_node_identity(self):
        self.device_patch.stop()
        def info(path):
            if path == "/dev":
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=wrapper.os.makedev(8, 16))
        with patch.object(wrapper.os, "lstat", side_effect=info):
            wrapper.device_number("/dev/sdb", "8:16")
            with self.assertRaisesRegex(wrapper.Refused, "device_identity_mismatch"):
                wrapper.device_number("/dev/sdb", "8:17")

    def test_command_failures_never_relay_private_output(self):
        for result in (SimpleNamespace(returncode=1, stdout=b"PRIVATE", stderr=b"PRIVATE"),
                       subprocess.TimeoutExpired("PRIVATE", 15, output=b"PRIVATE")):
            with patch.object(wrapper.subprocess, "run", side_effect=result if isinstance(result, Exception) else None,
                              return_value=result), self.assertRaises(wrapper.Refused) as caught:
                wrapper.command(["/usr/bin/mount"])
            self.assertNotIn("PRIVATE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
