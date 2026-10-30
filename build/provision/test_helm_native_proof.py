"""Offline synthetic tests for helm_native_proof.py. No network, no real helm, no execution of installed bytes."""
import subprocess
import gzip
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import helm_native_proof as proof

HERE = Path(__file__).resolve().parent
PAYLOAD = b"synthetic helm bytes, never executed"
PIN = {"url": "https://example.invalid/helm", "size": len(PAYLOAD),
       "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
       "archive_size": 123, "archive_sha256": "f" * 64}
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
target = dest / "helm"
payload = (here / "payload").read_bytes()
if mode == "overflow":
    print("x" * 10000, flush=True)
    time.sleep(600)
if mode == "fail" or (mode == "second-fail" and n == 2):
    print("helm install: official helm download failed", file=sys.stderr)
    sys.exit(17)
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
if mode == "mtime" and n == 2:
    st = target.stat()
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns + 1000000))
if mode == "mode" and n == 2:
    target.chmod(0o700)
if mode == "bytes" and n == 1:
    target.write_bytes(b"x" * len(payload))
if mode == "stage":
    (dest / ".helm-stage-unknown").mkdir(exist_ok=True)
if mode == "extra" and n == 1:
    (dest / "foreign.txt").write_text("x")
out = json.loads((here / "expect.json").read_text())
st = target.lstat()
out.update(target=str(target), target_mode="0755", status=status,
           target_size=st.st_size,target_uid=st.st_uid,target_dev=st.st_dev,target_inode=st.st_ino)
if (here / "override.json").exists():
    out.update(json.loads((here / "override.json").read_text()))
if mode == "drift":
    (here / "hhfab_release.py").write_text("changed public source")
if mode == "missing":
    del out["tool"]
if mode == "array":
    out = []
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
        self.installer = self.tools / "install-helm.py"
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
            "tool": "helm", "version": "3.19.4", "platform": "linux/amd64",
            "source_url": PIN["url"], "pinned_size": PIN["size"], "pinned_sha256": PIN["sha256"],
            "module_sha256": sha(self.installer), "helper_sha256": sha(self.tools / "hhfab_release.py"),
            "target_sha256": PIN["sha256"], "executed": False,
            "archive_size": PIN["archive_size"], "archive_sha256": PIN["archive_sha256"],
            "verified": "synthetic", "not_verified": "synthetic", "atomicity": "synthetic"}))
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
        self.assertTrue(report["cleanup"]["direct_children_reaped"])

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
        self.assertEqual(report["cleanup"]["removed"], ["helm"])
        self.assertTrue(all(0 <= report[k]["seconds"] < 60 for k in ("first", "rerun")))
        self.assert_clean(report)

    def test_actual_installer_with_synthetic_local_archive(self):
        # Synthetic archive and recomputed pins reach the actual accepted parser.
        # Only this test command adds --archive; this is not native evidence.
        from test_install_helm import fixture, CONTRACT, PAYLOAD as payload
        archive = self.tools / "fixture.gz"
        archive.write_bytes(gzip.compress(fixture(), mtime=0))
        pin = dict(PIN, size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                   archive_size=archive.stat().st_size, archive_sha256=sha(archive))
        text = (HERE / "install-helm.py").read_text()
        marker = "EXPANDED_LIMIT = 70 * 1024 * 1024"
        self.assertEqual(text.count(marker), 1)
        text = text.replace(marker, "PINS = {VERSION: " + repr(pin) + "}\nMEMBERS = " + repr(CONTRACT) + "\n" + marker)
        self.installer.write_text(text)
        def local(installer, destination):
            return [sys.executable, "-B", str(installer), "--version", "3.19.4", "--platform", "linux/amd64",
                    "--install-dir", str(destination), "--archive", str(archive)]
        with patch.object(proof, "PIN", pin), patch.object(proof, "command", local):
            report = self.run_proof()
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(report["first"]["target"], report["rerun"]["target"])
        self.assertIs(report["rerun"]["outcome"]["executed"], False)
        self.assert_clean(report)

    def test_actual_installer_nested_download_cleanup_on_wrapper_term(self):
        # Inspected fake download command substitutes only the network boundary.
        # Original installer bounded()/SIGTERM/stage cleanup code runs in its child.
        text = (HERE / "install-helm.py").read_text()
        marker = '    try:\n        main()'
        self.assertEqual(text.count(marker),1)
        child_program = ("import os,time;from pathlib import Path;"
                         "Path(" + repr(str(self.tools / "nested_pid")) + ").write_text(str(os.getpid()));"
                         "time.sleep(30)")
        injection = ("    def fake_download(pin,target):\n"
                     "        bounded([sys.executable,'-I','-B','-c'," + repr(child_program) + "],30,env=dict(CHILD_ENV))\n"
                     "    download=fake_download\n")
        self.installer.write_text(text.replace(marker,injection+marker))
        marker_path = self.tools / "nested_pid"
        def cancel_when_ready():
            deadline = time.monotonic()+3
            while not marker_path.exists() and time.monotonic()<deadline: time.sleep(.01)
            if marker_path.exists(): os.kill(os.getpid(),signal.SIGTERM)
        timer = threading.Thread(target=cancel_when_ready)
        timer.start()
        try: report = self.run_proof()
        finally: timer.join(timeout=4)
        self.assertEqual(report["exit_code"],143,report)
        self.assertTrue(marker_path.exists())
        self.assertTrue(gone(int(marker_path.read_text())))
        self.assert_clean(report)
        self.assertNotIn("cleanup_error",report)

    def test_result_binding_mismatches_fail_and_clean(self):
        bad = {"module_sha256": "0" * 64, "helper_sha256": "1" * 64, "target": "/elsewhere/helm",
               "target_sha256": "2" * 64, "target_mode": "0644", "status": "unchanged",
               "source_url": "https://example.invalid/other", "executed": True, "pinned_size": 1,
               "target_size": 1, "target_uid": -1, "target_dev": -1, "target_inode": -1,
               "archive_size": True, "archive_sha256": "0"*64, "verified": False}
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
        self.assertEqual(report["error"], "installer failed: helm install: official helm download failed")
        self.assertEqual(report["exit_code"], 17)
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
        self.assertTrue((self.root / "install" / "helm").exists())

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
        self.assertEqual(report["error"], "interrupted by SIGTERM")
        self.assertEqual(report["exit_code"], 143)
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
        self.assertEqual(report["error"], "interrupted by SIGTERM")
        self.assertEqual(report["exit_code"], 143)
        self.assertEqual((self.tools / "nested_reaped").read_text(), "yes")
        self.assertTrue(gone(int((self.tools / "child_pid").read_text())))
        self.assert_clean(report)

    def test_forced_escalation_keeps_nested_cleanup_unverified(self):
        self.fake("stubborn")
        with patch.object(proof, "RUN_CAP", 1), patch.object(proof, "TERM_GRACE", 0.1):
            report = self.run_proof()
        self.assertEqual(report["error"], "command timeout")
        self.assertIn("nested process cleanup unverified", report["cleanup_error"])
        self.assertEqual(report["cleanup"]["nested_cleanup"], "unverified")
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
        target = self.root / "helm"
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
        destination.mkdir(mode=0o700)
        state = {"dir": destination, "dir_id": proof.directory_identity(destination), "target_id": None}
        stage = destination / ".helm-stage-abc"
        stage.mkdir()
        (stage / "helm").write_bytes(b"x")
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((stage / "helm").exists())

    def test_cleanup_refuses_unobserved_target(self):
        destination = self.root / "install"
        destination.mkdir(mode=0o700)
        (destination / "helm").write_bytes(PAYLOAD)
        state = {"dir": destination, "dir_id": proof.directory_identity(destination), "target_id": None}
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((destination / "helm").exists())

    def test_cleanup_refuses_target_with_unrecorded_inode(self):
        destination = self.root / "install"
        destination.mkdir(mode=0o700)
        (destination / "helm").write_bytes(PAYLOAD)
        state = {"dir": destination, "dir_id": proof.directory_identity(destination), "target_id": (0, 0)}
        with self.assertRaises(proof.Refusal):
            proof.remove_destination(destination, state, [])
        self.assertTrue((destination / "helm").exists())

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

    def test_second_failure_preserves_nonzero(self):
        self.fake("second-fail")
        report = self.run_proof()
        self.assertEqual(report["exit_code"], 17)
        self.assertEqual(self.invocations(), 2)
        self.assert_clean(report)

    def test_result_extra_missing_shape_and_strict_bool(self):
        for mode, override, error in (("good", {"extra":1}, "keys mismatch"),
                                      ("missing", None, "mismatch: tool"),
                                      ("array", None, "not an object"),
                                      ("good", {"executed":0}, "mismatch: executed")):
            self.fake(mode, override)
            report = self.run_proof()
            self.assertIn(error, report["error"], report)
            self.assert_clean(report)
            (self.tools / "override.json").unlink(missing_ok=True)

    def test_actual_bytes_mode_and_timestamp_refused(self):
        for mode in ("bytes", "mode", "mtime"):
            self.fake(mode)
            report = self.run_proof()
            self.assertEqual(report["status"], "failed", report)
            self.assertIn("target", report["error"])
            # Unobserved bytes stay; the recorded first inode may be removed.
            dest = self.root / "install"
            if dest.exists():
                self.assertIn("cleanup_error", report)
                (dest / "helm").unlink()
                dest.rmdir()
            (self.tools / "count").unlink()

    def test_sigint_and_primary_codes_survive_cleanup_failure(self):
        for sig, code in ((signal.SIGINT,130),(signal.SIGTERM,143),(None,124)):
            self.fake("hang")
            (self.root / "tmp" / "unknown").write_text("keep")
            # Create the unknown only after preflight so cancellation is reached.
            (self.root / "tmp" / "unknown").unlink()
            def cancel():
                (self.root / "tmp" / "unknown").write_text("keep")
                if sig: os.kill(os.getpid(),sig)
            timer = threading.Timer(.3,cancel)
            timer.start()
            try:
                with patch.object(proof,"RUN_CAP",.6): report = self.run_proof()
            finally:
                timer.cancel()
                timer.join()
            self.assertEqual(report["exit_code"],code,report)
            self.assertIn("cleanup_error",report)
            self.assertEqual((self.root / "tmp" / "unknown").read_text(),"keep")
            (self.root / "tmp" / "unknown").unlink()

    def test_private_directory_replacement_preserved(self):
        self.fake("good")
        actual = proof.run_installer
        def replacing(*args):
            result = actual(*args)
            old = self.root / "old-home"
            (self.root / "home").rename(old)
            (self.root / "home").mkdir(mode=0o700)
            return result
        with patch.object(proof,"run_installer",replacing): report = self.run_proof()
        self.assertIn("identity changed",report["error"])
        self.assertIn("retained",report["cleanup_error"])
        self.assertTrue((self.root / "install" / "helm").exists())

    def test_cli_denies_overrides_and_relative_root(self):
        good = ["--root",str(self.root),"--commit",COMMIT,"--tree",TREE]
        for argv in (good+["--archive","/x"],good+["--install-dir","/x"],
                     ["--root","relative","--commit",COMMIT,"--tree",TREE],
                     good+["--runner-image","bad\ntext"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): proof.main(argv)

    def test_duplicate_json_and_invalid_output_shapes(self):
        self.fake("good")
        actual = proof.run_installer
        for change in (lambda o:o.replace(b'"tool": "helm"',b'"tool": "helm", "tool": "helm"'),
                       lambda o:o+b'\n',lambda o:o.rstrip(b'\n'),
                       lambda o:o.replace(b'"executed": false',b'"executed": NaN')):
            def changed(*args):
                code,out = actual(*args)
                return code,change(out)
            with patch.object(proof,"run_installer",changed): report = self.run_proof()
            self.assertEqual(report["status"],"failed",report)
            self.assert_clean(report)

    def test_maintained_workflow_cleanup_body(self):
        workflow = HERE.parents[1] / ".github/workflows/helm-native-proof.yml"
        text = workflow.read_text().split("      - name: One bounded native install and rerun trial",1)[1]
        body = "\n".join(line[10:] for line in text.splitlines() if line.startswith("          "))
        self.exercise_host_trap(body[body.index("root_identity="):].split("env -i ",1)[0])

    def test_maintained_ci_cleanup_body(self):
        workflow = HERE.parents[1] / ".github/workflows/ci.yml"
        text = workflow.read_text().split("      - name: Required Helm native-proof offline regressions",1)[1]
        text = text.split("      - name: Required kubectl",1)[0]
        body = "\n".join(line[10:] for line in text.splitlines() if line.startswith("          "))
        prelude = body[body.index("root_identity="):].split("env -i ",1)[0]
        self.exercise_host_trap(prelude)

    def exercise_host_trap(self, prelude):
        for mutation in ("none","unknown","replace-home","replace-root"):
            for primary in (0,124,130,143,17):
                root = self.tools / (mutation+str(primary))
                root.mkdir(mode=0o700)
                script = 'set -euo pipefail\nprivate=$1\ntest_root=$1\n'+prelude
                if mutation == "unknown": script += 'touch "$private/tmp/unknown"\n'
                if mutation == "replace-home": script += 'mv "$private/home" "$private/original-home"; mkdir -m700 "$private/home"\n'
                if mutation == "replace-root": script += 'mv "$private" "$private-original"; mkdir -m700 "$private"; mkdir -m700 "$private/home" "$private/tmp"\n'
                script += 'exit %d\n' % primary
                result = subprocess.run(["/bin/bash","-c",script,"fixture",str(root)],
                                        env=dict(proof.CHILD_ENV),stdin=subprocess.DEVNULL,
                                        capture_output=True,timeout=5)
                self.assertEqual(result.returncode,primary or int(mutation!="none"),result.stderr)
                if mutation == "none":
                    self.assertFalse(root.exists())
                    self.assertEqual(result.stdout.count(b'host cleanup absent:'),3)
                else:
                    self.assertTrue(root.exists())
                    if mutation == "replace-root":
                        self.assertTrue((root/"home").exists())
                        self.assertTrue((root/"tmp").exists())

    def test_observe_refuses_owner_and_file_shapes(self):
        target = self.root / "helm"
        target.write_bytes(PAYLOAD)
        target.chmod(0o755)
        with patch.object(proof.os,"geteuid",return_value=os.geteuid()+1), self.assertRaises(proof.Refusal):
            proof.observe(target)
        target.unlink()
        for shape in ("symlink","directory","fifo","hardlink"):
            if shape == "symlink": target.symlink_to(self.tools/"payload")
            elif shape == "directory": target.mkdir()
            elif shape == "fifo": os.mkfifo(target)
            else: os.link(self.tools/"payload",target)
            with self.assertRaises(proof.Refusal): proof.observe(target)
            target.rmdir() if shape == "directory" else target.unlink()

    def test_nonzero_precedes_secondary_identity_failure(self):
        self.fake("fail")
        actual = proof.run_installer
        def replacing(*args):
            result = actual(*args)
            (self.root/"home").rename(self.root/"original-home")
            (self.root/"home").mkdir(mode=0o700)
            return result
        with patch.object(proof,"run_installer",replacing): report = self.run_proof()
        self.assertEqual(report["exit_code"],17,report)
        self.assertIn("identity changed",report["cleanup_error"])

    def test_failed_termination_wait_preserves_primary(self):
        self.fake("stubborn")
        original = subprocess.Popen.wait
        failed = [False]
        def wait(proc,*args,**kwargs):
            if proc.poll() is None and not failed[0]:
                failed[0] = True
                raise OSError("synthetic wait failure")
            return original(proc,*args,**kwargs)
        with patch.object(proof,"RUN_CAP",.3), patch.object(subprocess.Popen,"wait",wait):
            report = self.run_proof()
        self.assertEqual(report["exit_code"],124,report)
        self.assertTrue(report["cleanup"]["direct_children_reaped"])
        self.assertIn("unverified",report["cleanup_error"])
        self.assertTrue(gone(int((self.tools/"child_pid").read_text())))




class HostTests(unittest.TestCase):
    def test_pin_limits_command_and_unchanged_sources(self):
        from test_install_helm import h
        self.assertEqual(proof.PIN, h.PINS["3.19.4"])
        self.assertEqual((proof.WORK, proof.CLEANUP, proof.RUN_CAP), (600,60,185))
        self.assertEqual(proof.command(Path("/source/install-helm.py"), Path("/private/install")),
                         [proof.PYTHON,"-B","/source/install-helm.py","--version","3.19.4",
                          "--platform","linux/amd64","--install-dir","/private/install"])

    def test_workflow_structure_and_fixed_guards(self):
        text = (HERE.parents[1] / ".github/workflows/helm-native-proof.yml").read_text()
        # Exact structural prefix: no extra trigger, input, permission or job can
        # hide in an unexamined mapping. Actual shell cleanup is exercised above.
        prefix = text.split("      - uses: actions/checkout@v4",1)[0]
        self.assertEqual(prefix, """---
name: helm native install and rerun proof

'on':
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: helm-native-proof
  cancel-in-progress: false

jobs:
  helm-proof:
    if: >-
      github.repository_id == '1089062808' &&
      github.repository_owner_id == '193945001' &&
      github.ref == 'refs/heads/main' &&
      github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-24.04
    timeout-minutes: 13
    steps:
""")
        self.assertIn("          ref: ${{ github.sha }}\n          persist-credentials: false\n",text)
        self.assertEqual(text.count("      - "),3)
        self.assertIn("/usr/bin/timeout --kill-after=30s 700s",text)
        self.assertNotIn("--archive",text)

    def test_release_must_be_ubuntu_2404(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "os-release"
            release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            with patch.object(proof, "OS_RELEASE", release), self.assertRaises(proof.Refusal):
                proof.observe_host()


if __name__ == "__main__":
    unittest.main()
