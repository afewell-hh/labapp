"""Offline synthetic tests for kubectl_native_proof.py. No network, no real kubectl, no execution of installed bytes."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import kubectl_native_proof as proof

HERE = Path(__file__).resolve().parent
PAYLOAD = b"synthetic kubectl bytes, never executed"
PIN = {"url": "https://example.invalid/kubectl", "size": len(PAYLOAD),
       "sha256": hashlib.sha256(PAYLOAD).hexdigest()}
COMMIT, TREE = "a" * 40, "b" * 40

# Stand-in installer CLI with the same arguments and result shape; behavior is chosen by `mode`.
FAKE = '''
import json, os, signal, subprocess, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
mode = (here / "mode").read_text().strip()
count = here / "count"
n = int(count.read_text()) + 1 if count.exists() else 1
count.write_text(str(n))
args = sys.argv[1:]
dest = Path(args[args.index("--install-dir") + 1])
target = dest / "kubectl"
payload = (here / "payload").read_bytes()
if mode == "overflow":
    print("x" * 10000, flush=True)
    time.sleep(600)
if mode == "fail":
    print("kubectl install: official kubectl download failed", file=sys.stderr)
    sys.exit(1)
if mode == "nested":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"],
                             start_new_session=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (here / "child_pid").write_text(str(child.pid))
    def cancel(*args):
        child.kill()
        child.wait(timeout=2)
        (here / "nested_reaped").write_text("yes")
        sys.exit(1)
    signal.signal(signal.SIGTERM, cancel)
    time.sleep(600)
if mode == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (here / "child_pid").write_text(str(os.getpid()))
    time.sleep(600)
if mode == "hang":
    (here / "child_pid").write_text(str(os.getpid()))
    time.sleep(600)
if mode == "stray" and n == 1:
    child = subprocess.Popen([sys.executable, "-c", "import os, time; os.setpgid(0, 0); time.sleep(600)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (here / "child_pid").write_text(str(child.pid))
if not target.exists():
    target.write_bytes(payload)
    os.chmod(target, 0o755)
    status = "installed"
else:
    status = "unchanged"
    if mode == "replace":
        swap = dest / ".swap"
        swap.write_bytes(payload)
        os.chmod(swap, 0o755)
        os.replace(swap, target)
if mode == "extra" and n == 1:
    (dest / "foreign.txt").write_text("x")
out = json.loads((here / "expect.json").read_text())
out.update(target=str(target), target_mode="0755", status=status)
if (here / "override.json").exists():
    out.update(json.loads((here / "override.json").read_text()))
if mode == "drift":
    (here / "hhfab_release.py").write_text("changed public source")
if mode == "garbage":
    print("not json")
else:
    print(json.dumps(out, sort_keys=True))
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:  # an unreaped zombie still counts as dead
        return Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return True


class ProofTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.root = base / "private"
        self.tools = base / "tools"
        for path in (self.root, self.root / "home", self.root / "tmp", self.tools):
            path.mkdir()
            path.chmod(0o700)
        shutil.copy(HERE / "hhfab_release.py", self.tools / "hhfab_release.py")
        (self.tools / "payload").write_bytes(PAYLOAD)
        self.installer = self.tools / "install-kubectl.py"
        for name, value in (("PIN", PIN), ("PYTHON", sys.executable)):
            patcher = patch.object(proof, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(proof, "observe_host", lambda: {"synthetic": True})
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake(self, mode, override=None):
        self.installer.write_text(FAKE)
        (self.tools / "mode").write_text(mode)
        (self.tools / "expect.json").write_text(json.dumps({
            "tool": "kubectl", "version": "1.35.0", "platform": "linux/amd64",
            "source_url": PIN["url"], "pinned_size": PIN["size"], "pinned_sha256": PIN["sha256"],
            "module_sha256": sha(self.installer), "helper_sha256": sha(self.tools / "hhfab_release.py"),
            "target_sha256": PIN["sha256"], "executed": False}))
        if override:
            (self.tools / "override.json").write_text(json.dumps(override))

    def invocations(self):
        count = self.tools / "count"
        return int(count.read_text()) if count.exists() else 0

    def run_proof(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return proof.prove(self.root, self.installer, COMMIT, TREE, "synthetic image", environ={})

    def assert_clean(self, report):
        self.assertFalse((self.root / "install").exists())
        self.assertEqual(list((self.root / "home").iterdir()) + list((self.root / "tmp").iterdir()), [])
        self.assertTrue(report["cleanup"]["install_dir_absent"])
        self.assertTrue(report["cleanup"]["processes_absent"])

    def test_first_install_then_identical_rerun(self):
        self.fake("good")
        report = self.run_proof()
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(self.invocations(), 2)
        self.assertEqual(report["first"]["outcome"]["status"], "installed")
        self.assertEqual(report["rerun"]["outcome"]["status"], "unchanged")
        self.assertEqual(report["first"]["target"], report["rerun"]["target"])
        self.assertEqual(report["source"]["installer_sha256"], sha(self.installer))
        self.assertEqual((report["commit"], report["tree"]), (COMMIT, TREE))
        self.assertTrue(report["target_absent_before_first"])
        self.assertEqual(report["cleanup"]["removed"], ["kubectl"])
        self.assertTrue(all(0 <= report[k]["seconds"] < 60 for k in ("first", "rerun")))
        self.assert_clean(report)

    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "needs Linux x86_64")
    def test_real_installer_with_local_binary_input(self):
        text = (HERE / "install-kubectl.py").read_text()
        for old, new in (("https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl", PIN["url"]),
                         ("58597560", str(PIN["size"])),
                         ("a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989", PIN["sha256"])):
            self.assertEqual(text.count(old), 1)
            text = text.replace(old, new)
        self.installer.write_text(text)

        def local(installer, destination):
            return [sys.executable, "-B", str(installer), "--version", "1.35.0", "--platform", "linux/amd64",
                    "--install-dir", str(destination), "--binary", str(self.tools / "payload")]
        with patch.object(proof, "command", local):
            report = self.run_proof()
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(report["first"]["outcome"]["status"], "installed")
        self.assertEqual(report["rerun"]["outcome"]["status"], "unchanged")
        self.assertEqual(report["first"]["target"], report["rerun"]["target"])
        self.assertIs(report["rerun"]["outcome"]["executed"], False)
        self.assert_clean(report)

    def test_result_binding_mismatches_fail_and_clean(self):
        bad = {"module_sha256": "0" * 64, "helper_sha256": "1" * 64, "target": "/elsewhere/kubectl",
               "target_sha256": "2" * 64, "target_mode": "0644", "status": "unchanged",
               "source_url": "https://example.invalid/other", "executed": True, "pinned_size": 1}
        for key, value in bad.items():
            with self.subTest(key=key):
                (self.tools / "count").unlink(missing_ok=True)
                self.fake("good", {key: value})
                report = self.run_proof()
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["error"], "installer result mismatch: " + key)
                self.assertEqual(self.invocations(), 1, "no rerun or retry after failure")
                self.assert_clean(report)
                self.assertNotIn("cleanup_error", report)

    def test_installer_failure_preserves_primary_error_without_retry(self):
        self.fake("fail")
        report = self.run_proof()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error"], "installer failed: kubectl install: official kubectl download failed")
        self.assertEqual(self.invocations(), 1)
        self.assert_clean(report)

    def test_non_json_output_refused(self):
        self.fake("garbage")
        report = self.run_proof()
        self.assertEqual(report["error"], "installer output is not JSON")
        self.assert_clean(report)

    def test_rerun_identity_change_refused(self):
        self.fake("replace")
        report = self.run_proof()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error"], "rerun changed the target identity or metadata")
        self.assertIn("unknown child", report["cleanup_error"])
        self.assertTrue((self.root / "install" / "kubectl").exists())

    def test_timeout_kills_child_and_cleans(self):
        self.fake("hang")
        with patch.object(proof, "RUN_CAP", 1):
            report = self.run_proof()
        self.assertEqual(report["error"], "command timeout")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assertEqual(self.invocations(), 1)
        self.assert_clean(report)

    def test_cancellation_is_reported_and_cleaned(self):
        self.fake("hang")
        timer = threading.Timer(1.5, os.kill, (os.getpid(), signal.SIGTERM))
        self.addCleanup(timer.cancel)
        before = signal.getsignal(signal.SIGTERM)
        timer.start()
        report = self.run_proof()
        self.assertEqual(report["error"], "interrupted")
        self.assertEqual(report["status"], "failed")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assertIs(signal.getsignal(signal.SIGTERM), before)
        self.assert_clean(report)

    def test_nested_separate_session_child_reaped_on_timeout(self):
        self.fake("nested")
        with patch.object(proof, "RUN_CAP", 1):
            report = self.run_proof()
        self.assertEqual(report["error"], "command timeout")
        self.assertEqual((self.tools / "nested_reaped").read_text(), "yes")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assert_clean(report)

    def test_nested_separate_session_child_reaped_on_cancellation(self):
        self.fake("nested")
        timer = threading.Timer(1.5, os.kill, (os.getpid(), signal.SIGTERM))
        self.addCleanup(timer.cancel)
        timer.start()
        report = self.run_proof()
        self.assertEqual(report["error"], "interrupted")
        self.assertEqual((self.tools / "nested_reaped").read_text(), "yes")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assert_clean(report)

    def test_forced_escalation_keeps_nested_cleanup_unverified(self):
        self.fake("stubborn")
        with patch.object(proof, "RUN_CAP", 1), patch.object(proof, "TERM_GRACE", 0.1):
            report = self.run_proof()
        self.assertEqual(report["error"], "command timeout")
        self.assertIn("nested process cleanup unverified", report["cleanup_error"])
        self.assertFalse(report["cleanup"]["processes_absent"])
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assertEqual(self.invocations(), 1)

    def test_source_mutation_refused_without_rerun(self):
        self.fake("drift")
        report = self.run_proof()
        self.assertEqual(report["error"], "installer sources changed during the proof")
        self.assertEqual(self.invocations(), 1)
        self.assert_clean(report)

    def test_actual_child_output_overflow_is_bounded(self):
        self.fake("overflow")
        report = self.run_proof()
        self.assertEqual(report["error"], "command output overflow")
        self.assertEqual(self.invocations(), 1)
        self.assert_clean(report)

    def test_target_metadata_change_during_hash_refused(self):
        target = self.root / "kubectl"
        target.write_bytes(PAYLOAD)
        target.chmod(0o755)
        def changing(path):
            target.chmod(0o700)
            return PIN["sha256"]
        with patch.object(proof, "digest", changing), self.assertRaisesRegex(
                proof.Refusal, "installed target changed while observed"):
            proof.observe(target)

    def test_work_deadline_bounds_non_child_steps(self):
        self.fake("good")
        with patch.object(proof, "WORK", 1), patch.object(proof, "observe_host", lambda: time.sleep(30)):
            begun = time.monotonic()
            report = self.run_proof()
        self.assertLess(time.monotonic() - begun, 10)
        self.assertEqual(report["error"], "work deadline exceeded")
        self.assertEqual(self.invocations(), 0)
        self.assert_clean(report)

    def test_cleanup_has_its_own_deadline(self):
        self.fake("good")
        with patch.object(proof, "CLEANUP", 1), patch.object(proof, "remove_destination",
                                                              lambda *args: time.sleep(30)):
            report = self.run_proof()
        self.assertEqual(report["status"], "failed")
        self.assertNotIn("error", report)
        self.assertEqual(report["cleanup_error"], "cleanup deadline exceeded")

    def test_stray_session_process_is_refused_and_killed(self):
        self.fake("stray")
        report = self.run_proof()
        self.assertEqual(report["error"], "unexpected process outlived the installer")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assertEqual(self.invocations(), 1)
        self.assertIn("unknown child", report["cleanup_error"])
        self.assertTrue((self.root / "install" / "kubectl").exists())

    def test_unknown_child_is_preserved_not_deleted(self):
        self.fake("extra")
        report = self.run_proof()
        self.assertEqual(report["error"], "install directory contains unexpected entries")
        self.assertIn("1 unknown child entries retained", report["cleanup_error"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual([p.name for p in (self.root / "install").iterdir()], ["foreign.txt"])
        self.assertFalse(report["cleanup"]["install_dir_absent"])

    def test_cleanup_refuses_replaced_install_directory(self):
        state = {"dir": self.root / "install", "dir_id": (0, 0), "target_id": None}
        state["dir"].mkdir()
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(state["dir"], state, [])
        self.assertTrue(state["dir"].exists())

    def test_cleanup_refuses_even_plausibly_named_stage(self):
        destination = self.root / "install"
        destination.mkdir()
        info = destination.stat()
        state = {"dir": destination, "dir_id": (info.st_dev, info.st_ino), "target_id": None}
        stage = destination / ".kubectl-stage-abc"
        stage.mkdir()
        (stage / "kubectl").write_bytes(b"x")
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((stage / "kubectl").exists())

    def test_cleanup_refuses_unobserved_target(self):
        destination = self.root / "install"
        destination.mkdir()
        info = destination.stat()
        (destination / "kubectl").write_bytes(PAYLOAD)
        state = {"dir": destination, "dir_id": (info.st_dev, info.st_ino), "target_id": None}
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((destination / "kubectl").exists())

    def test_cleanup_refuses_target_with_unrecorded_inode(self):
        destination = self.root / "install"
        destination.mkdir()
        info = destination.stat()
        (destination / "kubectl").write_bytes(PAYLOAD)
        state = {"dir": destination, "dir_id": (info.st_dev, info.st_ino), "target_id": (0, 0)}
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((destination / "kubectl").exists())

    def test_non_private_root_refused_before_any_mutation(self):
        self.fake("good")
        self.root.chmod(0o755)
        report = self.run_proof()
        self.assertEqual(report["error"], "private directory must be a caller-owned 0700 real directory")
        self.assertEqual(self.invocations(), 0)
        self.assertFalse((self.root / "install").exists())

    def test_nonempty_home_refused(self):
        self.fake("good")
        (self.root / "home" / "kept").write_text("x")
        report = self.run_proof()
        self.assertEqual(report["error"], "private home and tmp must start empty")
        self.assertEqual(self.invocations(), 0)
        self.assertEqual(report["cleanup_error"], "unknown child entries in private home")

    def test_ambient_environment_refused(self):
        self.fake("good")
        with contextlib.redirect_stdout(io.StringIO()):
            report = proof.prove(self.root, self.installer, COMMIT, TREE,
                                 environ={"PATH": "/usr/bin", "KUBECONFIG": "x", "https_proxy": "y"})
        self.assertEqual(report["error"], "ambient environment not cleared: KUBECONFIG, https_proxy")
        self.assertEqual(self.invocations(), 0)

    def test_main_rejects_malformed_source_identity(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            proof.main(["--root", str(self.root), "--commit", "not-a-sha", "--tree", TREE])


class HostTests(unittest.TestCase):
    def test_pin_and_limits_match_the_accepted_installer(self):
        self.assertEqual(proof.PIN, {
            "url": "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl", "size": 58597560,
            "sha256": "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989"})
        self.assertEqual((proof.VERSION, proof.PLATFORM), ("1.35.0", "linux/amd64"))
        self.assertEqual((proof.WORK, proof.CLEANUP, proof.RUN_CAP), (600, 60, 185))
        installer = (HERE / "install-kubectl.py").read_text()
        self.assertIn('"size": %d' % proof.PIN["size"], installer)
        self.assertIn(proof.PIN["sha256"], installer)
        self.assertIn(proof.PIN["url"], installer)

    def test_release_must_be_ubuntu_2404(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "os-release"
            release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            with patch.object(proof, "OS_RELEASE", release), self.assertRaises(proof.Refusal):
                proof.observe_host()


if __name__ == "__main__":
    unittest.main()
