"""Synthetic remaining-host checks: no native command, root or device operation."""
import contextlib
import copy
import importlib.util
import os
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("native_assert_qemu", HERE / "guest/assert-qemu.py")
aq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aq)

VERSIONS = {"sudo": "1.9.15p5-3ubuntu5.24.04.4", "openssh-client": "1:9.6p1-3ubuntu13.20",
            "less": "590-2ubuntu2.1"}


def meta(mode, uid=0, gid=0, ino=2, rdev=0, nlink=1):
    return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_ino=ino, st_dev=1,
                                 st_rdev=rdev, st_nlink=nlink, st_size=20, st_mtime_ns=3, st_ctime_ns=4)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.rows = "".join(f"{p}\tamd64\t{v}\tinstalled\n" for p, v in VERSIONS.items()).encode()
        self.calls = []
        self.files = {p: meta(stat.S_IFDIR | 0o755) for p in ("/", "/usr", "/usr/bin")}
        for name in ("sudo", "ssh", "less"):
            self.files["/usr/bin/" + name] = meta(stat.S_IFREG | (0o4755 if name == "sudo" else 0o755))
        self.cfg = types.SimpleNamespace(run=self.command)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(aq.os, "lstat", side_effect=lambda p: self.files[p]))
        self.stack.enter_context(mock.patch.object(aq.os, "statvfs", return_value=types.SimpleNamespace(f_flag=0)))
        self.which = self.stack.enter_context(mock.patch.object(aq.shutil, "which", side_effect=lambda n, path: "/usr/bin/" + n))
        self.hash = self.stack.enter_context(mock.patch.object(aq, "sha256", return_value="a" * 64))

    def command(self, argv, seconds):
        self.calls.append((argv, seconds))
        if argv[1] == "-W":
            return 0, self.rows
        name = os.path.basename(argv[-1])
        package = {"ssh": "openssh-client"}.get(name, name)
        return 0, f"{package}: {argv[-1]}\n".encode()

    def test_real_package_queries_and_setuid_sudo_have_closed_inventory(self):
        found = aq.remaining_inventory(self.cfg)
        self.assertEqual(set(found), set(VERSIONS))
        for package, version in VERSIONS.items():
            self.assertEqual(found[package]["version"], version)
            self.assertEqual(found[package]["sha256"], "a" * 64)
        self.assertEqual(self.calls[0], (["/usr/bin/dpkg-query", "-W",
                         "-f=${Package}\t${Architecture}\t${Version}\t${db:Status-Status}\\n",
                         "sudo", "openssh-client", "less"], 20))
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(c[0][0] == "/usr/bin/dpkg-query" for c in self.calls))

    def test_legitimate_hardlinks_and_merged_usr_alias_are_supported(self):
        self.files["/usr/bin/sudo"].st_nlink = 2
        aq.remaining_inventory(self.cfg)
        self.which.side_effect = lambda n, path: "/bin/" + n
        self.files["/bin"] = meta(stat.S_IFLNK | 0o777)
        with mock.patch.object(aq.os, "readlink", return_value="usr/bin"):
            aq.remaining_inventory(self.cfg)
        with mock.patch.object(aq.os, "readlink", return_value="elsewhere"):
            self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)

    def test_missing_duplicate_malformed_arch_status_and_oversize_rows_refuse(self):
        good = self.rows
        for bad in (b"", good + good, good.replace(b"amd64", b"arm64", 1),
                    good.replace(b"installed", b"unpacked", 1), good.replace(b"\tamd64", b"", 1),
                    good.replace(b"1.9.15p5", b"SECRET/path"), b"x" * 4097, good + b"unknown\tamd64\t1\tinstalled\n"):
            with self.subTest(bad=bad[:40]):
                self.rows = bad
                self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)

    def test_untrusted_files_parents_and_shadowed_resolution_refuse_before_hash(self):
        good = copy.deepcopy(self.files)
        for path, field, value in (("/usr/bin/sudo", "st_mode", stat.S_IFREG | 0o755),
                                  ("/usr/bin/ssh", "st_mode", stat.S_IFLNK | 0o777),
                                  ("/usr/bin/less", "st_mode", stat.S_IFREG | 0o777),
                                  ("/usr", "st_uid", 1000), ("/usr/bin", "st_mode", stat.S_IFDIR | 0o777)):
            with self.subTest(path=path, field=field):
                self.files = copy.deepcopy(good)
                setattr(self.files[path], field, value)
                self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)
        self.files = good
        for resolved in (None, "/usr/local/bin/ssh", "/tmp/ssh"):
            self.which.side_effect = lambda n, path: resolved
            self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)

    def test_owner_query_failure_or_foreign_owner_and_noexec_refuse(self):
        for value in ((1, b"SECRET"), (0, b"foreign: /usr/bin/sudo\n"), (0, b"sudo: /usr/bin/sudo\n" * 2)):
            self.cfg.run = lambda argv, seconds: (0, self.rows) if argv[1] == "-W" else value
            self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)
        self.cfg.run = self.command
        with mock.patch.object(aq.os, "statvfs", return_value=types.SimpleNamespace(f_flag=os.ST_NOEXEC)):
            self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)

    def test_timeout_overflow_missing_file_and_midquery_replacement_refuse(self):
        for kind in ("timeout", "output"):
            self.cfg.run = mock.Mock(side_effect=aq.Timeout(kind))
            with self.assertRaisesRegex(aq.Check, "^host-" + kind + "$"):
                aq.remaining_inventory(self.cfg)
        self.cfg.run = self.command
        with mock.patch.object(aq.os, "lstat", side_effect=FileNotFoundError):
            self.assertRaises(aq.Check, aq.remaining_inventory, self.cfg)
        def replace(_):
            self.files["/usr/bin/sudo"].st_ino += 1
            return "a" * 64
        # The native observation captures metadata values before the hash, not a mutable mock object.
        with mock.patch.object(aq.os, "lstat", side_effect=lambda p: copy.copy(self.files[p])):
            self.hash.side_effect = replace
            with self.assertRaisesRegex(aq.Check, "^host-drift$"):
                aq.remaining_inventory(self.cfg)


class SudoTests(unittest.TestCase):
    def cfg(self, result=(0, b"0\n"), uid=1000, gid=1000):
        return types.SimpleNamespace(lookup=lambda _: types.SimpleNamespace(pw_uid=uid, pw_gid=gid),
                                     run=mock.Mock(return_value=result))

    def test_only_fixed_ubuntu_noninteractive_identity_command_is_run(self):
        cfg = self.cfg()
        aq.sudo_identity(cfg)
        cfg.run.assert_called_once_with(["/usr/sbin/runuser", "-u", "ubuntu", "--", "/usr/bin/env", "-i",
                                        "PATH=" + aq.SAFE_PATH, "HOME=/home/ubuntu", "LC_ALL=C.UTF-8",
                                        "/usr/bin/sudo", "-n", "-k", "--", "/usr/bin/id", "-u"], 10)

    def test_root_fallback_foreign_user_denial_bad_identity_and_timeout_refuse(self):
        for cfg in (self.cfg(uid=0), self.cfg(uid=1001), self.cfg(gid=0), self.cfg((1, b"SECRET")),
                    self.cfg((0, b"1000\n")), self.cfg((0, b"0")), self.cfg((0, b"0\nSECRET"))):
            self.assertRaises(aq.Check, aq.sudo_identity, cfg)
        for kind in ("timeout", "output"):
            cfg = self.cfg()
            cfg.run.side_effect = aq.Timeout(kind)
            with self.assertRaisesRegex(aq.Check, "^sudo-" + kind + "$"):
                aq.sudo_identity(cfg)


class TunTests(unittest.TestCase):
    def setUp(self):
        self.device = meta(stat.S_IFCHR | 0o666, rdev=os.makedev(10, 200))
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.lstat = self.stack.enter_context(mock.patch.object(aq.os, "lstat", side_effect=lambda p:
            self.device if p == "/dev/net/tun" else meta(stat.S_IFDIR | 0o755)))
        self.open = self.stack.enter_context(mock.patch.object(aq.os, "open", return_value=17))
        self.fstat = self.stack.enter_context(mock.patch.object(aq.os, "fstat", side_effect=lambda _: copy.copy(self.device)))
        self.close = self.stack.enter_context(mock.patch.object(aq.os, "close"))
        self.ioctl = self.stack.enter_context(mock.patch.object(aq.fcntl, "ioctl", side_effect=self.features))

    @staticmethod
    def features(fd, operation, buffer, mutate):
        buffer[:] = (0x1003).to_bytes(4, "little")
        return 0

    def test_unattached_device_query_uses_only_getfeatures_and_always_closes(self):
        self.assertIsNone(aq.tun_query())
        self.open.assert_called_once_with("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.assertEqual(self.ioctl.call_args.args[:2], (17, 0x800454cf))
        self.assertEqual(len(self.ioctl.call_args.args[2]), 4)
        self.close.assert_called_once_with(17)

    def test_wrong_device_symlink_untrusted_parent_and_absence_never_open(self):
        for mode, rdev in ((stat.S_IFREG | 0o666, 0), (stat.S_IFLNK | 0o777, 0),
                           (stat.S_IFCHR | 0o666, os.makedev(10, 232))):
            self.device.st_mode, self.device.st_rdev = mode, rdev
            self.assertRaises(aq.Check, aq.tun_query)
        self.open.assert_not_called()
        self.lstat.side_effect = lambda p: self.device if p == "/dev/net/tun" else meta(stat.S_IFDIR | 0o777)
        self.assertRaises(aq.Check, aq.tun_query)
        self.open.assert_not_called()
        self.lstat.side_effect = FileNotFoundError
        self.assertRaises(aq.Check, aq.tun_query)
        self.open.assert_not_called()

    def test_open_ioctl_descriptor_substitution_and_missing_tap_fail_with_exact_cleanup(self):
        self.open.side_effect = PermissionError
        self.assertRaises(aq.Check, aq.tun_query)
        self.close.assert_not_called()
        self.open.side_effect = None
        for fail in ("ioctl", "features", "identity"):
            self.close.reset_mock()
            self.fstat.side_effect = lambda _: copy.copy(self.device)
            self.ioctl.side_effect = self.features
            if fail == "ioctl":
                self.ioctl.side_effect = OSError
            elif fail == "features":
                self.ioctl.side_effect = lambda *args: 0
            else:
                self.fstat.return_value = meta(stat.S_IFCHR | 0o666, ino=99, rdev=os.makedev(10, 200))
                self.fstat.side_effect = None
            self.assertRaises(aq.Check, aq.tun_query)
            self.close.assert_called_once_with(17)


if __name__ == "__main__":
    unittest.main()
