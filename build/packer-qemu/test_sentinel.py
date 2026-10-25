"""Offline tests for the fixed `sentinel` task contracts. Synthetic daemon, tiny synthetic
archives and a stand-in KVM check: no Docker, QEMU, KVM, VM, download or package operation.
They prove fail-closed gating, identity/digest binding, the original-budget rule, fixed
argv and cleanup decisions, not that any real runtime or guest works (UNRUN gates in
README.md)."""
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import types
import unittest
from unittest import mock

import container_runner as cr
import stage_tools as st
import supervise
import test_container_runner as tc
import test_stage_tools as ts

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = {"image_id": "sha256:" + "d" * 64, "diffids": ["sha256:" + "e" * 64, "sha256:" + "f" * 64]}
KVM_GID = 994


class SentinelDaemon(tc.FakeDaemon):
    """Synthetic daemon whose 'container' writes the fixed sentinel result files."""

    def __init__(self, clock, steps="build 0\n", receipt="good", artifact=True, tamper=False,
                 runtime_fault=None, exit_code=0, **kw):
        super().__init__(clock, kw.pop("mode", "ok"), exit_code=exit_code, **kw)
        self.steps, self.receipt, self.artifact = steps, receipt, artifact
        self.tamper, self.runtime_fault = tamper, runtime_fault

    def image_info(self):
        info = {"Id": RUNTIME["image_id"], "RootFS": {"Layers": list(RUNTIME["diffids"])}, "Config": {}}
        if self.runtime_fault == "wrong_id":
            info["Id"] = "sha256:" + "0" * 64
        if self.runtime_fault == "wrong_layers":
            info["RootFS"]["Layers"] = RUNTIME["diffids"][:1]
        if self.runtime_fault == "onbuild":
            info["Config"]["OnBuild"] = ["RUN x"]
        return json.dumps(info)

    def start(self, c):
        out = next(a for a in c["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
        ws = os.path.dirname(out)
        with open(os.path.join(ws, "cd", "nonce")) as handle:
            nonce = handle.read().strip()
        with open(os.path.join(ws, "cd", "MANIFEST"), "rb") as handle:
            guest = hashlib.sha256(handle.read()).hexdigest()
        good = {"nonce": nonce, "inputs": guest, "shutdown": "guest-shutdown", "receipt": "ok"}
        receipts = {
            "good": json.dumps(good),
            "stale": json.dumps({**good, "inputs": "0" * 64}),
            "wrong_nonce": json.dumps({**good, "nonce": "1" * 64}),
            "no_shutdown": json.dumps({**good, "shutdown": "none"}),
            "extra_key": json.dumps({**good, "extra": 1}),
            "malformed": "{not json",
            "duplicate": '{"nonce": "%s", "nonce": "%s", "inputs": "%s", "shutdown": "guest-shutdown", '
                         '"receipt": "ok"}' % (nonce, nonce, guest),
            "missing": None,
        }
        files = {"steps": self.steps, "build.out": "build ok\n", "build.err": ""}
        for name, text in files.items():
            if text is not None:
                with open(os.path.join(out, name), "w") as handle:
                    handle.write(text)
        if receipts[self.receipt] is not None:
            with open(os.path.join(out, "work", "verified.json"), "w") as handle:
                handle.write(receipts[self.receipt])
        if self.artifact:
            os.mkdir(os.path.join(out, "work", "out"))
            with open(os.path.join(out, "work", "out", "labapp.qcow2"), "wb") as handle:
                handle.write(b"synthetic disposable artifact")
        if self.tamper:
            packer = os.path.join(ws, "in", "tools", "packer")
            os.chmod(packer, 0o600)
            with open(packer, "ab") as handle:
                handle.write(b"x")
        c["state"], c["exit_at"], c["code"] = "running", self.clock.now + 1.0, self.exit_code


class SentinelCase(tc.RunnerCase):
    def setUp(self):
        super().setUp()
        src = os.path.join(os.path.dirname(self.root), "src")
        os.mkdir(src, 0o700)
        self.sources, pins = ts.make_inputs(src)
        for patcher in (mock.patch.object(cr.stage_tools, "PINS", pins),
                        mock.patch.object(cr, "SENTINEL_RUNTIME", RUNTIME),
                        mock.patch.object(cr, "kvm_preflight", return_value=KVM_GID)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_sentinel(self, daemon=None, delay=0.0, **kw):
        daemon = daemon or SentinelDaemon(self.clock)
        result = cr.run_probe(tc.IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              admitted_at=self.clock() - delay, uid=os.getuid() or 1000, mode="sentinel",
                              sources=self.sources, **kw)
        return result, daemon

    def create_call(self, daemon):
        return next(c[0] for c in daemon.calls if c[0][0] == "create")


class FailClosedTests(SentinelCase):
    def test_no_accepted_runtime_refuses_before_ledger_workspace_staging_or_docker(self):
        daemon = SentinelDaemon(self.clock)
        with mock.patch.object(cr, "SENTINEL_RUNTIME", None), \
                mock.patch.object(cr.stage_tools, "stage", side_effect=AssertionError), \
                mock.patch.object(cr, "kvm_preflight", side_effect=AssertionError):
            with self.assertRaises(ValueError):
                cr.run_probe(tc.IMAGE, self.root, self.ledger, daemon, clock=self.clock,
                             uid=os.getuid() or 1000, mode="sentinel", sources=self.sources)
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(os.listdir(self.ledger), [])

    def test_malformed_runtime_identities_are_rejected(self):
        good = RUNTIME["image_id"]
        bad = [{}, [], "sha256:" + "d" * 64, {"image_id": good},
               {"image_id": "sha256:xyz", "diffids": RUNTIME["diffids"]},
               {"image_id": good, "diffids": []}, {"image_id": good, "diffids": ["bad"]},
               {"image_id": good, "diffids": "sha256:" + "e" * 64},
               {"image_id": good, "diffids": RUNTIME["diffids"], "extra": 1}]
        for runtime in bad:
            with self.subTest(runtime=runtime), mock.patch.object(cr, "SENTINEL_RUNTIME", runtime):
                with self.assertRaises(ValueError):
                    cr.require_runtime()

    def test_cli_execute_is_refused_without_runtime_and_contacts_nothing(self):
        argv = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "sentinel", "--execute",
                "--core-file", "/a", "--plugin-file", "/b", "--base-file", "/c"]
        with mock.patch.object(cr, "SENTINEL_RUNTIME", None), \
                mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch.object(cr, "run_probe", side_effect=AssertionError), \
                mock.patch("os.makedirs", side_effect=AssertionError), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cr.main(argv), 2)
        self.assertIn("not accepted", err.getvalue())

    def test_cli_plan_shows_fixed_device_and_unaccepted_runtime_without_contact(self):
        argv = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "sentinel",
                "--core-file", "/a", "--plugin-file", "/b", "--base-file", "/c"]
        with mock.patch.object(cr, "SENTINEL_RUNTIME", None), \
                mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cr.main(argv), 0)
        plan = json.loads(out.getvalue())
        self.assertEqual((plan["mode"], plan["executed"], plan["runtime_accepted"]), ("sentinel", False, False))
        self.assertIn("--device=/dev/kvm", plan["create"])

    def test_cli_has_no_image_or_command_option_and_requires_all_input_files(self):
        base = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "sentinel"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(base), 2)
            self.assertEqual(cr.main(base + ["--core-file", "/a"]), 2)
            for option in ("--image", "--command", "--runtime-image"):
                with self.assertRaises(SystemExit):
                    cr.main(base + [option, "x"])

    def test_missing_kvm_fails_before_workspace_and_never_substitutes_emulation(self):
        with mock.patch.object(cr, "kvm_preflight", side_effect=cr.HardwareMissing("absent")):
            result, daemon = self.run_sentinel()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "kvm_unavailable"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])
        self.assertNotIn("tcg", json.dumps(cr.SENTINEL_SCRIPT + cr.ENTRY).lower())

    def test_kvm_preflight_is_metadata_only_and_requires_a_nonroot_group_device(self):
        def info(mode, gid):
            return types.SimpleNamespace(st_mode=mode, st_gid=gid)
        with mock.patch("os.lstat", return_value=info(stat.S_IFCHR | 0o660, KVM_GID)), \
                mock.patch("os.open", side_effect=AssertionError), mock.patch("builtins.open", side_effect=AssertionError):
            self.assertEqual(cr.kvm_preflight(), KVM_GID)
        for bad in (info(stat.S_IFREG | 0o660, KVM_GID), info(stat.S_IFCHR | 0o660, 0),
                    info(stat.S_IFCHR | 0o600, KVM_GID), info(stat.S_IFCHR | 0o640, KVM_GID)):
            with self.subTest(mode=oct(bad.st_mode), gid=bad.st_gid), \
                    mock.patch("os.lstat", return_value=bad), self.assertRaises(cr.HardwareMissing):
                cr.kvm_preflight()
        with mock.patch("os.lstat", side_effect=FileNotFoundError), self.assertRaises(cr.HardwareMissing):
            cr.kvm_preflight()

    def test_runtime_image_must_be_exactly_the_accepted_id_and_layers(self):
        for fault in ("wrong_id", "wrong_layers", "onbuild"):
            with self.subTest(fault=fault):
                self.setUp()
                result, daemon = self.run_sentinel(SentinelDaemon(self.clock, runtime_fault=fault))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "daemon_error"))
                self.assertEqual(self.mutations(daemon), [])


class ArgvTests(SentinelCase):
    def test_profile_limits_and_the_only_added_access_is_kvm(self):
        self.assertEqual(cr.PROFILES["sentinel"], (900, 300))
        self.assertEqual((cr.PROFILES["probe"], cr.PROFILES["hcl-check"]), ((30, 20), (120, 30)))
        result, daemon = self.run_sentinel()
        args = self.create_call(daemon)
        self.assertIn(RUNTIME["image_id"], args)
        for expected in ("--pull=never", "--network=none", "--cap-drop=ALL", "--read-only",
                         "--security-opt=no-new-privileges", "--memory=10g", "--memory-swap=10g",
                         "--cpus=5", "--pids-limit=512", "--log-driver=none", "--no-healthcheck",
                         "--device=/dev/kvm", f"--group-add={KVM_GID}"):
            self.assertIn(expected, args)
        for forbidden in ("--privileged", "--init", "--pid", "--ipc", "--uts", "--userns", "--volume", "-v",
                          "--env", "-e", "--cap-add", "--tmpfs", "--add-host", "--network=host", "--net"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertEqual([a for a in args if a.startswith("--device")], ["--device=/dev/kvm"])
        self.assertEqual([a for a in args if a.startswith("--group-add")], [f"--group-add={KVM_GID}"])
        mounts = [a for a in args if a.startswith("--mount=")]
        self.assertEqual(len(mounts), 3)
        self.assertEqual(len([m for m in mounts if not m.endswith(",readonly")]), 1)
        self.assertTrue(any(m.endswith(",dst=/in,readonly") for m in mounts))
        self.assertTrue(any(m.endswith("/cd,dst=/out/work/cd,readonly") for m in mounts))
        self.assertEqual(args[-1], cr.SENTINEL_SCRIPT)

    def test_other_modes_never_get_a_device_or_group(self):
        for mode in ("probe", "hcl-check"):
            args = cr.create_args("n", "l", tc.IMAGE_ID, "1:1", "/w", 5, "b", mode)
            self.assertFalse(any(a.startswith(("--device", "--group-add")) for a in args), mode)

    def test_fixed_script_is_one_build_with_empty_environment_and_no_install(self):
        script = cr.SENTINEL_SCRIPT
        self.assertEqual(script.count("/in/tools/packer "), 1)
        self.assertIn("packer build -color=false -var-file=/in/sentinel.pkrvars.hcl /in/labapp.pkr.hcl", script)
        self.assertIn("env -i HOME=/out/home TMPDIR=/out/tmp", script)
        self.assertIn("PACKER_PLUGIN_PATH=/in/plugins", script)
        for word in ("init", "install", "plugins", "curl", "wget", "-on-error", "PACKER_LOG"):
            self.assertNotIn(word, script.replace("/in/plugins", ""))

    def test_socket_paths_stay_short_under_the_owned_output_tree(self):
        text = open(os.path.join(HERE, "labapp.pkr.hcl")).read()
        for sock in re.findall(r'unix:\$\{var\.work_dir\}/(\w+\.sock)', text):
            self.assertLess(len("/out/work/" + sock), 100)    # AF_UNIX sun_path limit is 108


class AcceptanceTests(SentinelCase):
    def test_accepted_run_binds_both_identities_and_deletes_the_artifact(self):
        result, daemon = self.run_sentinel()
        self.assertEqual((result["outcome"], result["reason"]), ("accepted", None))
        self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))
        evidence = result["evidence"]
        self.assertEqual(evidence["image_id"], RUNTIME["image_id"])
        self.assertEqual(evidence["runtime_diffids"], RUNTIME["diffids"])
        self.assertNotEqual(evidence["inputs"], evidence["guest_receipt"])
        for key in ("inputs", "guest_receipt", "vars_sha256", "hcl_sha256", "base_sha256", "nonce_sha256"):
            self.assertRegex(evidence[key], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["artifact"]["sha256"], hashlib.sha256(b"synthetic disposable artifact").hexdigest())
        self.assertTrue(evidence["artifact"]["deleted"])
        self.assertEqual(self.record()["state"], "released")
        self.assertEqual(self.record()["mode"], "sentinel")

    def test_verify_time_uses_the_original_budget_without_the_shutdown_timeout(self):
        result, _ = self.run_sentinel()
        self.assertEqual(result["evidence"]["verify_seconds"], 900 - cr.SENTINEL_RESERVE)
        self.setUp()
        result, _ = self.run_sentinel(delay=100.0)
        self.assertEqual(result["evidence"]["verify_seconds"], 800 - cr.SENTINEL_RESERVE)
        self.assertGreater(900 - cr.SENTINEL_RESERVE, 900 - 300)    # 5 min is not reserved

    def test_exhausted_original_budget_never_reaches_the_daemon(self):
        for delay in (800.0, 880.0, 899.0):
            with self.subTest(delay=delay):
                self.setUp()
                result, daemon = self.run_sentinel(delay=delay)
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
                self.assertEqual(daemon.calls, [])

    def test_stale_or_malformed_receipts_are_failed(self):
        for receipt in ("stale", "wrong_nonce", "no_shutdown", "extra_key", "malformed", "duplicate"):
            with self.subTest(receipt=receipt):
                self.setUp()
                result, _ = self.run_sentinel(SentinelDaemon(self.clock, receipt=receipt))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "stale_or_malformed_receipt"))
                self.assertEqual(result["cleanup"], "verified")

    def test_missing_receipt_steps_or_artifact_are_failed(self):
        result, _ = self.run_sentinel(SentinelDaemon(self.clock, receipt="missing"))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_step_evidence"))
        self.setUp()
        result, _ = self.run_sentinel(SentinelDaemon(self.clock, steps=None))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_step_evidence"))
        self.setUp()
        result, _ = self.run_sentinel(SentinelDaemon(self.clock, artifact=False))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "artifact_invalid_or_not_deleted"))

    def test_packer_failure_or_unexpected_exit_is_never_success(self):
        for steps in ("build 1\n", "build 0\nextra 0\n", ""):
            with self.subTest(steps=steps):
                self.setUp()
                result, _ = self.run_sentinel(SentinelDaemon(self.clock, steps=steps))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "build_failed"))
        for code in (1, 124, 137):
            with self.subTest(code=code):
                self.setUp()
                result, _ = self.run_sentinel(SentinelDaemon(self.clock, exit_code=code))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))

    def test_input_mutation_during_the_run_is_failed(self):
        result, _ = self.run_sentinel(SentinelDaemon(self.clock, tamper=True))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "staged_inputs_changed"))

    def test_uncertain_cleanup_holds_and_retains_the_record(self):
        for mode in ("rm_lost", "stop_fail", "query_down"):
            with self.subTest(mode=mode):
                self.setUp()
                result, _ = self.run_sentinel(SentinelDaemon(self.clock, mode=mode))
                self.assertEqual(result["outcome"], "hold")
                self.assertEqual(result["cleanup"], "uncertain")
                self.assertEqual(self.record()["state"], "hold")
                self.assertEqual(result["workspace"], "retained")


class StagingTests(ts.StageCase):
    def sentinel(self, seconds=600, **kw):
        return self.stage(task="sentinel", verify_seconds=seconds, **kw)

    def test_guest_receipt_digest_is_the_cd_manifest_hash_and_differs_from_the_overall_identity(self):
        staged = self.sentinel()
        manifest_hash = hashlib.sha256(self.read("cd", "MANIFEST")).hexdigest()
        self.assertEqual(staged["guest_receipt"], manifest_hash)
        self.assertNotEqual(staged["inputs"], staged["guest_receipt"])
        text = self.read("in", st.SENTINEL_VARS_NAME).decode()
        self.assertIn(f'inputs = "{manifest_hash}"', text)
        self.assertNotIn(staged["inputs"], text)
        self.assertIn("verify_seconds = 600\n", text)
        self.assertEqual(staged["vars_name"], st.SENTINEL_VARS_NAME)
        self.assertEqual(staged["vars_sha256"], hashlib.sha256(text.encode()).hexdigest())
        overall = st.manifest(self.ws, staged["base_sha256"])
        self.assertEqual(hashlib.sha256(overall).hexdigest(), staged["inputs"])
        self.assertNotIn(st.SENTINEL_VARS_NAME, overall.decode())
        self.assertIn("cd/MANIFEST", overall.decode())       # the overall identity covers the guest identity
        self.assertTrue(st.verify_staged(self.ws, staged))

    def test_assertion_script_and_plan_are_in_the_manifest_and_guest_readable(self):
        self.sentinel()
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "cd"))),
                         ["MANIFEST", "assert-sentinel.sh", "guest-build.sh", "meta-data", "nonce", "plan.txt",
                          "user-data"])
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.ws, "cd", st.ASSERT_NAME)).st_mode), 0o444)
        manifest = self.read("cd", "MANIFEST").decode()
        for name in (st.ASSERT_NAME, "plan.txt"):
            self.assertRegex(manifest, r"(?m)^[0-9a-f]{64}  " + re.escape(name) + "$")
        plan = self.read("cd", "plan.txt").decode().splitlines()
        self.assertEqual(plan, ["root /bin/bash @IN@/assert-sentinel.sh root",
                                "ubuntu /bin/bash @IN@/assert-sentinel.sh ubuntu"])
        with open(os.path.join(HERE, "guest", st.ASSERT_NAME), "rb") as handle:
            self.assertEqual(self.read("cd", st.ASSERT_NAME), handle.read())

    def test_hcl_check_staging_is_unchanged(self):
        staged = self.stage()
        self.assertEqual(staged["vars_name"], st.VARS_NAME)
        self.assertNotIn("guest_receipt", staged)
        self.assertIn(f'inputs = "{staged["inputs"]}"', self.read("in", st.VARS_NAME).decode())
        self.assertIn("verify_seconds = 30\n", self.read("in", st.VARS_NAME).decode())
        self.assertEqual(self.read("cd", "plan.txt"), b"")
        self.assertNotIn(st.ASSERT_NAME, os.listdir(os.path.join(self.ws, "cd")))

    def test_verify_seconds_callable_runs_after_the_manifest_exists(self):
        seen = []
        def seconds():
            seen.append(os.path.exists(os.path.join(self.ws, "cd", "MANIFEST")))
            return 123
        self.stage(task="sentinel", verify_seconds=seconds)
        self.assertEqual(seen, [True])

    def test_invalid_verify_seconds_and_task_are_rejected(self):
        for value in (None, 0, -1, True, 86401, 1.5, "30"):
            with self.subTest(value=value):
                self.setUp()
                with self.assertRaises(st.StageError):
                    self.sentinel(value)
        self.setUp()
        with self.assertRaises(st.StageError):
            self.stage(task="build")

    def test_changed_sentinel_var_file_or_cd_is_detected(self):
        staged = self.sentinel()
        path = os.path.join(self.ws, "in", st.SENTINEL_VARS_NAME)
        os.chmod(path, 0o600)
        with open(path, "ab") as handle:
            handle.write(b" ")
        self.assertFalse(st.verify_staged(self.ws, staged))
        self.setUp()
        staged = self.sentinel()
        path = os.path.join(self.ws, "cd", "plan.txt")
        os.chmod(path, 0o600)
        with open(path, "ab") as handle:
            handle.write(b"root /bin/true\n")
        self.assertFalse(st.verify_staged(self.ws, staged))


class RuntimeSourceTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "runtime", "Dockerfile")) as handle:
            self.text = handle.read()
        self.code = "\n".join(line for line in self.text.splitlines() if not line.lstrip().startswith("#"))

    def test_shipped_runtime_identity_is_unset(self):
        # Setting it needs a separately accepted concrete prepared image (README gate).
        with open(os.path.join(HERE, "container_runner.py")) as handle:
            self.assertEqual(re.findall(r"(?m)^SENTINEL_RUNTIME = (.*)$", handle.read()), ["None"])

    def test_context_is_the_dockerfile_alone(self):
        self.assertEqual(os.listdir(os.path.join(HERE, "runtime")), ["Dockerfile"])

    def test_base_is_the_full_accepted_digest_and_nothing_else_is_copied_in(self):
        froms = re.findall(r"(?m)^FROM (\S+)$", self.code)
        self.assertEqual(froms, [cr.PINNED_IMAGE])
        self.assertRegex(froms[0], r"@sha256:[0-9a-f]{64}$")
        for word in ("COPY ", "ADD ", "curl", "wget", "apt-key", "trusted=yes", "allow-insecure",
                     "allow-unauthenticated", "AllowUnauthenticated", "Check-Valid-Until", "--force-yes"):
            self.assertNotIn(word, self.code)

    def test_one_isolated_dated_signed_source_with_matching_snapshot_stanzas(self):
        self.assertIn("rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*", self.code)
        self.assertEqual(self.code.count("Snapshot: 20261024T000000Z"), 2)
        self.assertEqual(self.code.count("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"), 2)
        for suite in ("noble noble-updates", "noble-security"):
            self.assertIn(f"Suites: {suite}", self.code)
        self.assertEqual(len(re.findall(r"'URIs: http://(archive|security)\.ubuntu\.com/ubuntu'", self.code)), 2)

    def test_explicit_exact_roots_without_recommends_and_qemu_matches_the_guest_pins(self):
        self.assertIn("--no-install-recommends", self.code)
        roots = dict(re.findall(r"^\s+([a-z0-9.+-]+)=(\S+?)(?: \\)?$", self.code, re.M))
        self.assertEqual(sorted(roots), ["python3", "python3.12", "qemu-system-x86", "qemu-utils", "seabios",
                                         "xorriso"])
        with open(os.path.join(HERE, "..", "provision", "install-qemu.py")) as handle:
            pins = dict(re.findall(r'"([a-z0-9-]+)": "([^"]+)"', handle.read().split("PINS = ")[1].split("}")[0]))
        for name in ("qemu-system-x86", "qemu-utils", "seabios"):
            self.assertEqual(roots[name], pins[name])
        self.assertNotIn("socat", self.code)
        self.assertNotIn("genisoimage", self.code)

    def test_resolved_set_and_signed_index_hashes_are_recorded_in_the_image(self):
        self.assertIn("dpkg-query -W", self.code)
        self.assertIn("InRelease", self.code)
        self.assertIn("/usr/share/labapp-runtime/packages.txt", self.code)


class IsoToolDiagnosticTests(unittest.TestCase):
    def failures(self, tools):
        with mock.patch.object(supervise.shutil, "which", side_effect=lambda t: "/x" if t in tools else None), \
                mock.patch.object(supervise.os, "access", return_value=True), \
                mock.patch.object(supervise.platform, "system", return_value="Linux"), \
                mock.patch.object(supervise.platform, "machine", return_value="x86_64"):
            return [f for f in supervise.preflight() if "CD builder" in f]

    def test_only_tools_the_pinned_plugin_searches_satisfy_the_diagnostic(self):
        self.assertTrue(self.failures({"genisoimage", "qemu-img"}))
        self.assertFalse(self.failures({"xorriso"}))
        self.assertFalse(self.failures({"mkisofs"}))

    def test_execution_stays_disabled(self):
        self.assertEqual(supervise.run({}, 900, 300), ("disabled", None))


if __name__ == "__main__":
    unittest.main()
