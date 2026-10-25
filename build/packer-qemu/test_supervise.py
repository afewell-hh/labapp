"""Offline preparation and fail-closed execution tests; no child launches."""
import contextlib
import hashlib
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

import supervise


class ExecutionGateTests(unittest.TestCase):
    args = ["--profile", "sentinel", "--packer", "/abs/packer",
            "--base-image", "/abs/base.img", "--base-sha256", "a" * 64]

    def test_direct_call_rejects_before_any_input_or_process_operation(self):
        with mock.patch.object(supervise, "stage_inputs", side_effect=AssertionError), \
                mock.patch.object(supervise.tempfile, "mkdtemp", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                mock.patch("os.kill", side_effect=AssertionError):
            for cfg, work, cleanup in ((None, 0, 0), ({}, 900, 300),
                                       ({"work_root": "/unowned"}, 1800, 900)):
                self.assertEqual(supervise.run(cfg, work, cleanup), ("disabled", None))

    def test_cli_cannot_launch_even_when_hardware_would_pass(self):
        with mock.patch.object(supervise, "preflight", side_effect=AssertionError), \
                mock.patch.object(supervise, "stage_inputs", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(supervise.main(self.args), 6)
        self.assertIn("execution disabled", output.getvalue())

    def test_preflight_success_does_not_claim_execution_admission(self):
        with mock.patch.object(supervise, "preflight", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(supervise.main(["--preflight-only"]), 0)
        self.assertIn("execution remains disabled", output.getvalue())

    def test_preflight_failure_stays_nonzero(self):
        with mock.patch.object(supervise, "preflight", return_value=["missing KVM"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(supervise.main(["--preflight-only"]), 2)
        self.assertIn("missing KVM", output.getvalue())
        self.assertIn("execution disabled", output.getvalue())


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
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                supervise.parse(self.base + extra)

    def test_proposed_profile_allocations_remain_fixed(self):
        self.assertEqual(supervise.PROFILES, {"sentinel": (900, 300), "fixture": (1800, 900)})


if __name__ == "__main__":
    unittest.main()
