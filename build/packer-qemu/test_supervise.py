"""Offline tests for supervise.py using real fake owned processes.

The "packer" under test is a throwaway Python script, so process groups,
sessions, signals, grandchildren and work-directory cleanup are real. These
tests do not prove real Packer, QEMU or guest behavior.
"""
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest

import supervise

PRELUDE = '''#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
W = os.environ["PKR_VAR_work_dir"]
def marker(nonce=None):
    os.makedirs(W + "/out")
    open(W + "/out/labapp.qcow2", "w").write("x")
    with open(W + "/verified.json", "w") as h:
        json.dump({"nonce": nonce or os.environ["PKR_VAR_nonce"],
                   "inputs": os.environ["PKR_VAR_inputs"],
                   "shutdown": "guest-shutdown", "receipt": "ok"}, h)
def grandchild():
    p = subprocess.Popen(["sleep", "600"])
    open(PIDFILE, "w").write(str(p.pid))
'''


def alive(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except OSError:
        return False


class SuperviseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sup-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pidfile = os.path.join(self.tmp, "child.pid")
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root)
        del supervise._cancel[:]
        self.addCleanup(supervise._cancel.clear)

    def fake_packer(self, body):
        path = os.path.join(self.tmp, "packer")
        with open(path, "w") as handle:
            handle.write(PRELUDE.replace("PIDFILE", repr(self.pidfile)) + body)
        os.chmod(path, 0o755)
        return path

    def cfg(self, body):
        return {"packer": self.fake_packer(body), "base_image": "/x/base.img",
                "base_sha256": "0" * 64, "stage": [], "plan": None, "work_root": self.root}

    def run_fake(self, body, work=5, cleanup=8, grace=0.5):
        started = time.monotonic()
        result = supervise.run(self.cfg(body), work, cleanup, term_grace=grace)
        self.elapsed = time.monotonic() - started
        return result

    def assertNoResidue(self):
        self.assertEqual(os.listdir(self.root), [], "work directory must be removed")
        if os.path.exists(self.pidfile):
            with open(self.pidfile) as handle:
                self.assertFalse(alive(int(handle.read())), "owned grandchild survived")

    def test_marker_and_clean_exit_succeed_and_keep_only_output(self):
        result, work = self.run_fake("marker()\n")
        self.assertEqual(result, "ok")
        self.assertEqual(sorted(os.listdir(work)), ["cd", "out", "verified.json"])

    def test_exit_zero_without_verifier_marker_fails(self):
        self.assertEqual(self.run_fake("sys.exit(0)\n"), ("failed", None))
        self.assertNoResidue()

    def test_stale_marker_from_another_run_fails(self):
        self.assertEqual(self.run_fake("marker('f' * 64)\n"), ("failed", None))
        self.assertNoResidue()

    def test_marker_present_but_packer_nonzero_fails_and_removes_output(self):
        self.assertEqual(self.run_fake("marker()\nsys.exit(1)\n"), ("failed", None))
        self.assertNoResidue()

    def test_abrupt_exit_kills_orphaned_grandchild(self):
        # Packer dies while its child (QEMU stand-in) keeps running.
        self.assertEqual(self.run_fake("grandchild()\nos._exit(9)\n"), ("failed", None))
        self.assertNoResidue()

    def test_timeout_terminates_owned_tree_within_budget(self):
        result = self.run_fake("grandchild()\ntime.sleep(600)\n", work=1, cleanup=6)
        self.assertEqual(result, ("timeout", None))
        self.assertLess(self.elapsed, 7)
        self.assertNoResidue()

    def test_sigterm_ignoring_tree_is_killed(self):
        body = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\ngrandchild()\ntime.sleep(600)\n"
        self.assertEqual(self.run_fake(body, work=1, cleanup=6), ("timeout", None))
        self.assertNoResidue()

    def test_cancellation_cleans_up_and_is_reported(self):
        threading.Timer(1.0, supervise._cancel.append, [signal.SIGTERM]).start()
        result = self.run_fake("grandchild()\ntime.sleep(600)\n", work=30, cleanup=6)
        self.assertEqual(result, ("cancelled", None))
        self.assertLess(self.elapsed, 10)
        self.assertNoResidue()

    def test_missing_packer_fails_and_removes_work_dir(self):
        cfg = self.cfg("sys.exit(0)\n")
        cfg["packer"] = os.path.join(self.tmp, "absent")
        self.assertEqual(supervise.run(cfg, 5, 5), ("failed", None))
        self.assertNoResidue()

    def test_unkillable_session_is_reported_as_cleanup_failure(self):
        proc = os.path.join(self.tmp, "proc")
        os.makedirs(os.path.join(proc, "999999999"))
        with open(os.path.join(proc, "999999999", "stat"), "w") as handle:
            handle.write("999999999 (x) S 1 777 777 0 0")
        self.assertFalse(supervise.drain_session(777, 0.1, time.monotonic() + 0.5, proc))

    def test_only_session_members_are_signaled(self):
        own = subprocess.Popen(["sleep", "600"], start_new_session=True)
        foreign = subprocess.Popen(["sleep", "600"], start_new_session=True)
        self.addCleanup(foreign.kill)
        self.addCleanup(own.kill)
        proc = os.path.join(self.tmp, "proc2")
        for pid, sid in ((own.pid, 777), (foreign.pid, 888)):
            os.makedirs(os.path.join(proc, str(pid)))
            with open(os.path.join(proc, str(pid), "stat"), "w") as handle:
                handle.write("%d (a) b (c)) S 1 %d %d 0" % (pid, sid, sid))
        self.assertEqual(supervise.session_members(777, proc), [own.pid])
        supervise.signal_session(777, signal.SIGKILL, proc)
        own.wait(5)
        time.sleep(0.2)
        self.assertIsNone(foreign.poll())

    def test_zombies_do_not_count_as_session_members(self):
        proc = os.path.join(self.tmp, "proc3")
        os.makedirs(os.path.join(proc, "5"))
        with open(os.path.join(proc, "5", "stat"), "w") as handle:
            handle.write("5 (z) Z 1 777 777 0")
        self.assertEqual(supervise.session_members(777, proc), [])


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sup-in-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.module = os.path.join(self.tmp, "install-x.sh")
        with open(self.module, "w") as handle:
            handle.write("echo one\n")
        self.n = 0

    def stage(self, **kw):
        self.n += 1
        cd = os.path.join(self.tmp, "cd%d" % self.n)
        digest = supervise.stage_inputs(cd, kw.get("stage", [self.module]), kw.get("plan"),
                                        kw.get("nonce", "a" * 64))
        return cd, digest

    def test_digest_is_manifest_digest_and_excludes_nonce(self):
        cd, digest = self.stage()
        with open(os.path.join(cd, "MANIFEST"), "rb") as handle:
            manifest = handle.read()
        self.assertEqual(digest, hashlib.sha256(manifest).hexdigest())
        names = [line.split("  ")[1] for line in manifest.decode().splitlines()]
        self.assertEqual(names, ["guest-build.sh", "install-x.sh", "meta-data",
                                 "plan.txt", "user-data"])
        self.assertEqual(self.stage(nonce="b" * 64)[1], digest)

    def test_changed_module_bytes_change_digest(self):
        first = self.stage()[1]
        with open(self.module, "w") as handle:
            handle.write("echo two\n")
        self.assertNotEqual(self.stage()[1], first)

    def test_plan_bytes_are_covered(self):
        plan = os.path.join(self.tmp, "plan")
        with open(plan, "w") as handle:
            handle.write("root bash @IN@/install-x.sh\n")
        self.assertNotEqual(self.stage(plan=plan)[1], self.stage()[1])

    def test_duplicate_symlink_and_bad_names_are_rejected(self):
        link = os.path.join(self.tmp, "link.sh")
        os.symlink(self.module, link)
        other = os.path.join(self.tmp, "sub")
        os.mkdir(other)
        dup = os.path.join(other, "install-x.sh")
        shutil.copy(self.module, dup)
        odd = os.path.join(self.tmp, "bad name.sh")
        shutil.copy(self.module, odd)
        builtin = os.path.join(supervise.HERE, "guest", "user-data")
        for stage in ([link], [self.module, dup], [odd], [builtin]):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.stage(stage=stage)

    def test_marker_must_match_exactly_and_be_a_small_regular_file(self):
        good = '{"inputs": "%s", "nonce": "%s", "receipt": "ok", "shutdown": "guest-shutdown"}'
        path = os.path.join(self.tmp, "m.json")
        with open(path, "w") as handle:
            handle.write(good % ("b" * 64, "a" * 64))
        self.assertTrue(supervise.read_marker(path, "a" * 64, "b" * 64))
        self.assertFalse(supervise.read_marker(path, "c" * 64, "b" * 64))
        self.assertFalse(supervise.read_marker(path, "a" * 64, "c" * 64))
        link = os.path.join(self.tmp, "l.json")
        os.symlink(path, link)
        self.assertFalse(supervise.read_marker(link, "a" * 64, "b" * 64))
        with open(path, "w") as handle:
            handle.write(" " * 5000)
        self.assertFalse(supervise.read_marker(path, "a" * 64, "b" * 64))
        self.assertFalse(supervise.read_marker(os.path.join(self.tmp, "none"), "a", "b"))


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sup-pf-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make(self, flags, nested, kvm=True):
        cpuinfo = os.path.join(self.tmp, "cpuinfo")
        with open(cpuinfo, "w") as handle:
            handle.write("processor\t: 0\nflags\t\t: fpu %s\n" % flags)
        sysmod = os.path.join(self.tmp, "mod")
        for vendor in ("kvm_intel", "kvm_amd"):
            os.makedirs(os.path.join(sysmod, vendor, "parameters"), exist_ok=True)
            with open(os.path.join(sysmod, vendor, "parameters", "nested"), "w") as handle:
                handle.write(nested + "\n")
        dev = os.path.join(self.tmp, "kvm")
        if kvm:
            open(dev, "w").close()
        return supervise.preflight(cpuinfo, sysmod, dev)

    def joined(self, *a, **kw):
        return " | ".join(self.make(*a, **kw))

    def test_missing_kvm_is_reported(self):
        self.assertIn("missing or not readable/writable", self.joined("vmx", "Y", kvm=False))

    def test_cpu_without_vmx_or_svm_is_reported(self):
        self.assertIn("vmx/svm", self.joined("sse2", "Y"))

    def test_nested_disabled_is_reported_for_each_vendor(self):
        self.assertIn("kvm_intel nested parameter is not enabled", self.joined("vmx", "N"))
        self.assertIn("kvm_amd nested parameter is not enabled", self.joined("svm", "0"))

    def test_usable_kvm_and_nested_report_no_cpu_failures(self):
        text = self.joined("vmx", "Y")
        for needle in ("vmx/svm", "nested", "missing or not"):
            self.assertNotIn(needle, text)


class ArgumentTests(unittest.TestCase):
    base = ["--profile", "sentinel", "--packer", "/p/packer", "--base-image", "/b/i.img",
            "--base-sha256", "a" * 64]

    def test_accepts_valid_and_rejects_unsafe_values(self):
        supervise.parse(self.base)
        for extra in (["--packer", "relative"], ["--base-sha256", "XYZ"], ["--stage", "/a b"],
                      ["--profile", "forever"], ["--work-root", "/tmp/$(x)"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                supervise.parse(self.base + extra)

    def test_profile_allocations_are_absolute_and_fixed(self):
        self.assertEqual(supervise.PROFILES, {"sentinel": (900, 300), "fixture": (1800, 900)})


if __name__ == "__main__":
    unittest.main()
