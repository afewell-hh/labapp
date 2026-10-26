"""Offline tests for the fixed failure-only `sentinel-expiry` proof. Synthetic daemon, socket
pairs standing in for QMP/serial and tiny synthetic archives: no Docker, QEMU, KVM, VM,
download or package operation. They prove gating, the observer's state order, witness
identity/strictness, budget/dwell rules and cleanup decisions, not that a paused real guest
survives to the timer (UNRUN gate in README.md)."""
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import container_runner as cr
import host_verify as hv
import stage_tools as st
import test_container_runner as tc
import test_host_verify as thv
import test_sentinel as tsn
import test_stage_tools as ts

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = tsn.RUNTIME
KVM_GID = tsn.KVM_GID


class ExpiryDaemon(tc.FakeDaemon):
    """Synthetic container: writes the files the real expiry run would leave behind."""

    image_info = tsn.SentinelDaemon.image_info

    def __init__(self, clock, armed="good", armed_offset=10, steps=None, verified=False, artifact=True,
                 witness="good", build_logs=True, tamper=False, exit_code=124, early=False, **kw):
        super().__init__(clock, kw.pop("mode", "ok"), exit_code=exit_code, **kw)
        self.runtime_fault = None
        self.armed, self.armed_offset, self.steps, self.verified = armed, armed_offset, steps, verified
        self.artifact, self.witness, self.build_logs = artifact, witness, build_logs
        self.tamper, self.early = tamper, early

    def start(self, c):
        args = c["args"]
        deadline = int(args[args.index("bash") + 1])
        n = int(self.clock.now)
        timer = deadline - n - 1 - cr.KILL_AFTER
        out = next(a for a in args if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
        ws = os.path.dirname(out)
        with open(os.path.join(ws, "cd", "nonce")) as handle:
            nonce = handle.read().strip()
        with open(os.path.join(ws, "cd", "MANIFEST"), "rb") as handle:
            guest = hashlib.sha256(handle.read()).hexdigest()
        good = {"kind": hv.ARMED_KIND, "armed": "paused", "armed_at": n + self.armed_offset,
                "nonce": nonce, "inputs": guest, "boot_id": cr.host_boot_id()}
        armed = {
            "good": json.dumps(good),
            "stale_nonce": json.dumps({**good, "nonce": "1" * 64}),
            "wrong_inputs": json.dumps({**good, "inputs": "0" * 64}),
            "extra_key": json.dumps({**good, "extra": 1}),
            "missing_key": json.dumps({k: v for k, v in good.items() if k != "armed_at"}),
            "malformed": "{not json",
            "duplicate": '{"kind": "%s", "kind": "%s", "armed": "paused", "armed_at": %d, "nonce": "%s", '
                         '"inputs": "%s"}' % (hv.ARMED_KIND, hv.ARMED_KIND, n + 10, nonce, guest),
            "boolean_time": json.dumps({**good, "armed_at": True}),
            "float_time": json.dumps({**good, "armed_at": n + 10.5}),
            "running": json.dumps({**good, "armed": "running"}),
            "wrong_kind": json.dumps({**good, "kind": "other"}),
            "before_start": json.dumps({**good, "armed_at": n - 5}),
            "nan": '{"kind": "%s", "armed": "paused", "armed_at": NaN, "nonce": "%s", "inputs": "%s"}'
                   % (hv.ARMED_KIND, nonce, guest),
            "missing": None,
        }[self.armed]
        witness = {"good": f"start {n} {timer}\n", "bad": f"start {n} {timer + 9}\n",
                   "garbage": "start x\n", "missing": None}[self.witness]
        files = {"witness": witness, "steps": self.steps,
                 "build.out": "packer started\n" if self.build_logs else None,
                 "build.err": "" if self.build_logs else None}
        for name, text in files.items():
            if text is not None:
                with open(os.path.join(out, name), "w") as handle:
                    handle.write(text)
        if armed is not None:
            with open(os.path.join(out, "work", "armed.json"), "w") as handle:
                handle.write(armed)
        if self.verified:
            with open(os.path.join(out, "work", "verified.json"), "w") as handle:
                handle.write("{}")
        if self.artifact:
            os.mkdir(os.path.join(out, "work", "out"))
            with open(os.path.join(out, "work", "out", "labapp.qcow2"), "wb") as handle:
                handle.write(b"partial disposable artifact")
        if self.tamper:
            packer = os.path.join(ws, "in", "tools", "packer")
            os.chmod(packer, 0o600)
            with open(packer, "ab") as handle:
                handle.write(b"x")
        c["state"] = "running"
        c["exit_at"] = self.clock.now + 1.0 if self.early else n + timer + 0.5
        c["code"] = self.exit_code


class ExpiryCase(tc.RunnerCase):
    def setUp(self):
        super().setUp()
        src = os.path.join(os.path.dirname(self.root), "src")
        os.mkdir(src, 0o700)
        self.sources, pins = ts.make_inputs(src)
        # Only EXPIRY_RUNTIME is set: the success runtime gate stays closed throughout.
        for patcher in (mock.patch.object(cr.stage_tools, "PINS", pins),
                        mock.patch.object(cr, "EXPIRY_RUNTIME", RUNTIME),
                        mock.patch.object(cr, "kvm_preflight", return_value=KVM_GID)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_expiry(self, daemon=None, delay=0.0, **kw):
        daemon = daemon or ExpiryDaemon(self.clock)
        result = cr.run_probe(RUNTIME["image_id"], self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              admitted_at=self.clock() - delay, uid=os.getuid() or 1000,
                              mode="sentinel-expiry", sources=self.sources, **kw)
        return result, daemon


class GateAndArgvTests(ExpiryCase):
    def test_unset_expiry_runtime_refuses_before_ledger_workspace_staging_or_docker(self):
        daemon = ExpiryDaemon(self.clock)
        with mock.patch.object(cr, "EXPIRY_RUNTIME", None), \
                mock.patch.object(cr.stage_tools, "stage", side_effect=AssertionError), \
                mock.patch.object(cr, "kvm_preflight", side_effect=AssertionError):
            with self.assertRaises(ValueError):
                cr.run_probe(RUNTIME["image_id"], self.root, self.ledger, daemon, clock=self.clock,
                             uid=os.getuid() or 1000, mode="sentinel-expiry", sources=self.sources)
        self.assertEqual((daemon.calls, os.listdir(self.root), os.listdir(self.ledger)), ([], [], []))

    def test_gates_are_independent(self):
        self.assertIsNone(cr.SENTINEL_RUNTIME)
        with self.assertRaises(ValueError):          # success runtime unset: sentinel still refuses
            cr.require_runtime("sentinel")
        self.assertEqual(cr.require_runtime("sentinel-expiry"), RUNTIME)
        with mock.patch.object(cr, "SENTINEL_RUNTIME", RUNTIME), mock.patch.object(cr, "EXPIRY_RUNTIME", None):
            with self.assertRaises(ValueError):      # success runtime does not enable the expiry proof
                cr.require_runtime("sentinel-expiry")

    def test_shipped_expiry_identity_is_concrete_and_success_unset(self):
        with open(os.path.join(HERE, "container_runner.py")) as handle:
            text = handle.read()
        self.assertEqual(re.findall(r"(?m)^EXPIRY_RUNTIME = (.*)$", text), ["PREPARED_RUNTIME"])
        self.assertEqual(re.findall(r"(?m)^SENTINEL_RUNTIME = (.*)$", text), ["None"])

    def test_cli_execute_refused_and_plan_contacts_nothing(self):
        argv = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "sentinel-expiry",
                "--core-file", "/a", "--plugin-file", "/b", "--base-file", "/c"]
        with mock.patch.object(cr, "EXPIRY_RUNTIME", None), \
                mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(cr.main(argv), 0)
            plan = json.loads(out.getvalue())
            self.assertEqual((plan["mode"], plan["executed"], plan["runtime_accepted"]),
                             ("sentinel-expiry", False, False))
            self.assertIn("--device=/dev/kvm", plan["create"])
            with mock.patch("os.makedirs", side_effect=AssertionError), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cr.main(argv + ["--execute"]), 2)
            self.assertIn("not accepted", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            for option in ("--image", "--command", "--duration", "--qmp"):
                with self.assertRaises(SystemExit):
                    cr.main(argv + [option, "x"])

    def test_fixed_profile_and_argv_equal_the_sentinel_boundary(self):
        self.assertEqual(cr.PROFILES["sentinel-expiry"], (300, 120))
        self.assertEqual(cr.PROFILES["sentinel"], (900, 300))
        self.assertEqual(cr.LIMITS["sentinel-expiry"], cr.LIMITS["sentinel"])
        self.assertEqual(cr.create_args("n", "l", tc.IMAGE_ID, "1:1", "/w", 5, "b", "sentinel-expiry", KVM_GID),
                         cr.create_args("n", "l", tc.IMAGE_ID, "1:1", "/w", 5, "b", "sentinel", KVM_GID))
        result, daemon = self.run_expiry()
        args = next(c[0] for c in daemon.calls if c[0][0] == "create")
        self.assertIn(RUNTIME["image_id"], args)
        self.assertEqual([a for a in args if a.startswith("--device")], ["--device=/dev/kvm"])
        self.assertEqual([a for a in args if a.startswith("--group-add")], [f"--group-add={KVM_GID}"])
        for expected in ("--network=none", "--cap-drop=ALL", "--read-only", "--security-opt=no-new-privileges",
                         "--pull=never", "--memory=10g", "--cpus=5", "--pids-limit=512"):
            self.assertIn(expected, args)
        for forbidden in ("--privileged", "--env", "-e", "--cap-add", "--tmpfs", "--volume", "--network=host"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertEqual(len([a for a in args if a.startswith("--mount=")]), 3)
        self.assertEqual(args[-1], cr.SENTINEL_SCRIPT)

    def test_missing_kvm_fails_before_workspace_without_emulation(self):
        with mock.patch.object(cr, "kvm_preflight", side_effect=cr.HardwareMissing("absent")):
            result, daemon = self.run_expiry()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "kvm_unavailable"))
        self.assertEqual((daemon.calls, os.listdir(self.root)), ([], []))

    def test_runtime_image_must_match_the_expiry_identity(self):
        for fault in ("wrong_id", "wrong_layers", "onbuild"):
            with self.subTest(fault=fault):
                self.setUp()
                daemon = ExpiryDaemon(self.clock)
                daemon.runtime_fault = fault
                result, daemon = self.run_expiry(daemon)
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "daemon_error"))
                self.assertEqual(self.mutations(daemon), [])


class AcceptanceTests(ExpiryCase):
    def test_expected_expiry_is_accepted_only_as_a_failure_proof_never_a_build(self):
        result, daemon = self.run_expiry()
        self.assertEqual((result["outcome"], result["reason"]), ("accepted", None))
        self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))
        self.assertEqual(result["proof"], "expected_expiry")
        evidence = result["evidence"]
        self.assertIs(evidence["build_success"], False)
        self.assertEqual(evidence["exit_code"], 124)
        self.assertEqual(evidence["verify_seconds"], cr.EXPIRY_VERIFY_SECONDS)
        self.assertNotEqual(evidence["inputs"], evidence["guest_receipt"])
        for key in ("build.out", "build.err", "witness", "armed.json"):
            self.assertRegex(evidence[key]["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("verified.json", evidence)
        self.assertEqual(evidence["artifact"]["disposal"], "owned_workspace_cleanup")
        self.assertEqual(daemon.containers, {})
        self.assertEqual((self.record()["state"], self.record()["mode"]), ("released", "sentinel-expiry"))

    def test_released_expiry_record_allows_reuse_only_for_accepted_mode_identity(self):
        result, _ = self.run_expiry()
        self.assertEqual(result["outcome"], "accepted")
        record = self.record()
        self.assertEqual(record["image"], RUNTIME["image_id"])
        self.assertTrue(cr.released_record(record))
        self.assertEqual(cr.unresolved_records(self.ledger), [])
        self.assertFalse(cr.released_record({**record, "image": cr.PINNED_IMAGE}))
        self.assertFalse(cr.released_record({**record, "mode": "unknown"}))
        self.assertFalse(cr.released_record({**record, "mode": "sentinel"}))  # success gate closed
        for runtime in (None, {}, {"image_id": RUNTIME["image_id"], "diffids": []}):
            with self.subTest(runtime=runtime), mock.patch.object(cr, "EXPIRY_RUNTIME", runtime):
                self.assertFalse(cr.released_record(record))
        with mock.patch.object(cr, "EXPIRY_RUNTIME", {**RUNTIME, "image_id": "sha256:" + "9" * 64}):
            self.assertFalse(cr.released_record(record))
        with mock.patch.object(cr, "SENTINEL_RUNTIME", RUNTIME):
            self.assertTrue(cr.released_record({**record, "mode": "sentinel"}))
            self.assertFalse(cr.released_record({**record, "mode": "sentinel", "image": cr.PINNED_IMAGE}))

    def test_post_expiry_rehash_uses_original_total_deadline_with_cleanup_reserve(self):
        real = st.verify_staged
        def slow(workspace, staged, check):
            self.clock.now += 12
            check()
            return real(workspace, staged, check)
        with mock.patch.object(st, "verify_staged", slow):
            result, _ = self.run_expiry()
        self.assertEqual((result["outcome"], result["cleanup"]), ("accepted", "verified"))
        record = self.record()
        self.assertGreater(self.clock.now, record["work_deadline"])
        self.assertLess(self.clock.now, record["deadline"])
        self.assertEqual(record["deadline"] - record["admitted_at"], 420)
        self.setUp()
        def exhausted(workspace, staged, check):
            self.clock.now += 65
            check()
            return True
        with mock.patch.object(st, "verify_staged", exhausted):
            result, _ = self.run_expiry()
        self.assertEqual((result["outcome"], result["reason"], result["cleanup"]),
                         ("failed", "budget_exhausted", "verified"))

    def test_secondary_timeout_is_fixed_and_later_than_original_deadline(self):
        self.assertEqual(cr.EXPIRY_VERIFY_SECONDS, 300)

    def test_artifact_parent_alias_cannot_delete_host_canary(self):
        host = os.path.join(os.path.dirname(self.root), "host-output")
        os.mkdir(host)
        canary = os.path.join(host, "labapp.qcow2")
        with open(canary, "wb") as handle:
            handle.write(b"host-canary")
        class Aliased(ExpiryDaemon):
            def start(inner, container):
                super().start(container)
                out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                artifact_dir = os.path.join(out, "work", "out")
                os.rename(artifact_dir, artifact_dir + "-owned")
                os.symlink(host, artifact_dir)
        result, _ = self.run_expiry(Aliased(self.clock))
        self.assertEqual(result["cleanup"], "verified")
        with open(canary, "rb") as handle:
            self.assertEqual(handle.read(), b"host-canary")
        self.assertNotIn("artifact", result["evidence"])

    def test_invalid_marker_types_cannot_look_absent(self):
        for marker in ("steps", "verified.json", "armed.json.failed"):
            for kind in ("oversized", "symlink", "fifo"):
                with self.subTest(marker=marker, kind=kind):
                    self.setUp()
                    class Marked(ExpiryDaemon):
                        def start(inner, container):
                            super().start(container)
                            out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                            path = os.path.join(out, marker) if marker == "steps" else os.path.join(out, "work", marker)
                            if kind == "oversized":
                                with open(path, "wb") as handle:
                                    handle.truncate(cr.STEP_CAP + 1)
                            elif kind == "symlink":
                                os.symlink("missing", path)
                            else:
                                os.mkfifo(path)
                    result, _ = self.run_expiry(Marked(self.clock))
                    self.assertEqual(result["outcome"], "failed")
                    self.assertEqual(result["reason"], {"steps": "build_completed_before_expiry",
                                     "verified.json": "unexpected_success_marker",
                                     "armed.json.failed": "observer_failed"}[marker])

    def test_host_expiry_retains_logs_without_accepting_or_mutating_live_output(self):
        class Hung(ExpiryDaemon):
            def start(inner, container):
                super().start(container)
                container["exit_at"] += 1000
        result, _ = self.run_expiry(Hung(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "host_expiry"))
        self.assertIn("packer started", result["evidence"]["build.out"]["excerpt"])
        self.assertIn("armed.json", result["evidence"])
        self.assertEqual(result["cleanup"], "verified")

    def test_wrong_boot_identity_is_not_a_fresh_witness(self):
        class WrongBoot(ExpiryDaemon):
            def start(inner, container):
                super().start(container)
                out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                path = os.path.join(out, "work", "armed.json")
                with open(path) as handle:
                    body = json.load(handle)
                body["boot_id"] = "00000000-0000-0000-0000-000000000000"
                with open(path, "w") as handle:
                    json.dump(body, handle)
        result, _ = self.run_expiry(WrongBoot(self.clock))
        self.assertEqual(result["reason"], "invalid_or_short_armed_witness")

    def test_later_observer_failure_revokes_arming_even_if_packer_hangs_until_timer(self):
        class FailedObserver(ExpiryDaemon):
            def start(inner, container):
                super().start(container)
                out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                witness = os.path.join(out, "work", "armed.json")
                args = hv.parse(["--qmp", "/q", "--serial", "/s", "--result", "/r", "--timeout", "300",
                                 "--nonce", thv.NONCE, "--inputs", thv.INPUTS, "--expiry-witness", witness])
                with mock.patch.object(hv, "connect", return_value=mock.Mock()), \
                     mock.patch.object(hv, "observe", side_effect=hv.Failure("guest-reset")):
                    with self.assertRaises(hv.Failure):
                        hv.verify(args)
                self.assertFalse(os.path.lexists(witness))
        result, _ = self.run_expiry(FailedObserver(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "observer_failed"))
        self.assertEqual(result["cleanup"], "verified")

    def test_exit_137_after_timer_escalation_is_also_expiry(self):
        result, _ = self.run_expiry(ExpiryDaemon(self.clock, exit_code=137))
        self.assertEqual(result["outcome"], "accepted")

    def test_work_budget_includes_staging_and_is_never_renewed(self):
        result, _ = self.run_expiry(delay=100.0)
        self.assertEqual(result["outcome"], "accepted")
        for delay in (150.5, 160.0, 290.0):
            with self.subTest(delay=delay):
                self.setUp()
                result, daemon = self.run_expiry(delay=delay)
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
                self.assertEqual(daemon.calls, [])

    def test_witness_leaving_under_sixty_seconds_of_dwell_is_not_proof(self):
        # t is about 293; an armed_at 40 s before the timer ends is under the 60 s minimum.
        result, _ = self.run_expiry(ExpiryDaemon(self.clock, armed_offset=260))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_or_short_armed_witness"))
        self.setUp()
        result, _ = self.run_expiry(ExpiryDaemon(self.clock, armed_offset=200))   # ~93 s dwell
        self.assertEqual(result["outcome"], "accepted")

    def test_invalid_armed_witnesses_are_failed_with_diagnostics_retained(self):
        for armed in ("stale_nonce", "wrong_inputs", "extra_key", "missing_key", "malformed", "duplicate",
                      "boolean_time", "float_time", "running", "wrong_kind", "before_start", "nan"):
            with self.subTest(armed=armed):
                self.setUp()
                result, _ = self.run_expiry(ExpiryDaemon(self.clock, armed=armed))
                self.assertEqual((result["outcome"], result["reason"]),
                                 ("failed", "invalid_or_short_armed_witness"))
                self.assertEqual(result["cleanup"], "verified")
                self.assertRegex(result["evidence"]["build.out"]["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn("packer started", result["evidence"]["build.out"]["excerpt"])

    def test_missing_witness_or_a_completed_build_or_success_marker_is_failed(self):
        cases = (({"armed": "missing"}, "missing_armed_witness"),
                 ({"steps": "build 0\n"}, "build_completed_before_expiry"),
                 ({"steps": "build 1\n"}, "build_completed_before_expiry"),
                 ({"verified": True}, "unexpected_success_marker"),
                 ({"witness": "missing"}, "invalid_step_evidence"),
                 ({"witness": "bad"}, "no_timer_witness"),
                 ({"witness": "garbage"}, "no_timer_witness"),
                 ({"build_logs": False}, "invalid_step_evidence"),
                 ({"early": True}, "exited_before_timer"),
                 ({"tamper": True}, "staged_inputs_changed"))
        for kw, reason in cases:
            with self.subTest(kw=kw):
                self.setUp()
                result, _ = self.run_expiry(ExpiryDaemon(self.clock, **kw))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", reason))
                self.assertNotEqual(result.get("proof"), "expected_expiry")
                self.assertEqual(result["cleanup"], "verified")

    def test_early_failure_or_oom_is_never_the_proof(self):
        for code in (0, 1, 2, 125):
            with self.subTest(code=code):
                self.setUp()
                result, _ = self.run_expiry(ExpiryDaemon(self.clock, exit_code=code))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))
        self.setUp()
        result, _ = self.run_expiry(ExpiryDaemon(self.clock, mode="oom", exit_code=137))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))
        self.assertTrue(result["evidence"]["oom_killed"])

    def test_aliased_work_directory_never_enters_evidence(self):
        host = os.path.join(os.path.dirname(self.root), "hostonly")
        os.mkdir(host)
        with open(os.path.join(host, "armed.json"), "w") as handle:
            handle.write("HOST_ONLY_CANARY")

        class Aliased(ExpiryDaemon):
            def start(inner, container):
                super().start(container)
                out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                work = os.path.join(out, "work")
                os.rename(work, work + "-owned")
                os.symlink(host, work)
        result, _ = self.run_expiry(Aliased(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "observer_failed"))
        self.assertNotIn("armed.json", result["evidence"])
        self.assertNotIn("HOST_ONLY_CANARY", json.dumps(result))

    def test_uncertain_cleanup_holds_and_retains_the_record(self):
        for mode in ("rm_lost", "stop_fail", "query_down"):
            with self.subTest(mode=mode):
                self.setUp()
                result, _ = self.run_expiry(ExpiryDaemon(self.clock, mode=mode))
                self.assertEqual((result["outcome"], result["cleanup"]), ("hold", "uncertain"))
                self.assertEqual((self.record()["state"], result["workspace"]), ("hold", "retained"))

    def test_cancellation_never_accepts_and_cleans_the_owned_container(self):
        real = cr.shutil.rmtree

        def remove(path):
            os.kill(os.getpid(), signal.SIGTERM)
            return real(path)
        with mock.patch.object(cr.shutil, "rmtree", remove):
            result, daemon = self.run_expiry(handle_signals=True)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "cancelled"))
        self.assertEqual(daemon.containers, {})


class StagingTests(ts.StageCase):
    def test_expiry_staging_reuses_guest_inputs_and_asks_for_the_armed_witness(self):
        staged = self.stage(task="sentinel-expiry", verify_seconds=300)
        text = self.read("in", st.SENTINEL_VARS_NAME).decode()
        manifest_hash = hashlib.sha256(self.read("cd", "MANIFEST")).hexdigest()
        self.assertEqual(staged["guest_receipt"], manifest_hash)
        self.assertNotEqual(staged["inputs"], staged["guest_receipt"])
        self.assertIn(f'inputs = "{manifest_hash}"', text)
        self.assertIn("verify_seconds = 300\n", text)
        self.assertIn("expiry_proof = true\n", text)
        self.assertNotIn("require_sentinel_evidence", text)
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "cd"))),
                         ["MANIFEST", "assert-sentinel.sh", "guest-build.sh", "meta-data", "nonce", "plan.txt",
                          "sentinel-evidence.py", "user-data"])
        self.assertTrue(st.verify_staged(self.ws, staged))

    def test_success_and_hcl_check_staging_do_not_request_the_witness(self):
        self.stage(task="sentinel", verify_seconds=600)
        self.assertNotIn("expiry_proof", self.read("in", st.SENTINEL_VARS_NAME).decode())
        self.setUp()
        self.stage()
        self.assertNotIn("expiry_proof", self.read("in", st.VARS_NAME).decode())


class HclSourceTests(unittest.TestCase):
    def test_hcl_selects_the_witness_flag_only_through_the_expiry_variable(self):
        with open(os.path.join(HERE, "labapp.pkr.hcl")) as handle:
            text = handle.read()
        self.assertRegex(text, r'variable "expiry_proof" \{\s*type\s*=\s*bool\s*default\s*=\s*false\s*\}')
        self.assertIn('var.expiry_proof ? "--expiry-witness ${var.work_dir}/armed.json" : ""', text)
        self.assertLess(len("/out/work/armed.json"), 100)


class Pair:
    """Nonblocking socket pairs: this end is the observer's, the thread plays QEMU/guest."""

    def __init__(self, test):
        self.qmp, self.qemu_qmp = socket.socketpair()
        self.serial, self.guest_serial = socket.socketpair()
        for sock in (self.qmp, self.serial):
            sock.setblocking(False)
        for sock in (self.qmp, self.serial, self.qemu_qmp, self.guest_serial):
            test.addCleanup(sock.close)


class ObserverExpiryTests(unittest.TestCase):
    RETURNS = [{}, {"status": "prelaunch", "running": False}, {"enabled": True, "present": True}, {},
               {"status": "running", "running": True}, {}, {"status": "paused", "running": False}]
    COMMANDS = ["qmp_capabilities", "query-status", "query-kvm", "cont", "query-status", "stop", "query-status"]

    def observe(self, returns=None, after=None, close_qmp=False, serial_after=b"", timeout=1.0, errors=()):
        pair = Pair(self)
        returns = list(returns or self.RETURNS)
        seen, armed = [], []
        finished = threading.Event()

        def qemu():
            try:
                pair.qemu_qmp.sendall(thv.GREETING)
                buf = b""
                for index, ret in enumerate(returns):
                    while b"\n" not in buf:
                        chunk = pair.qemu_qmp.recv(4096)
                        if not chunk:
                            return
                        buf += chunk
                    line, buf = buf.split(b"\n", 1)
                    message = json.loads(line)
                    seen.append(message["execute"])
                    if index in errors:
                        pair.qemu_qmp.sendall(json.dumps({"error": {"class": "GenericError", "desc": "x"},
                                                          "id": message["id"]}).encode() + b"\n")
                    else:
                        pair.qemu_qmp.sendall(thv.ok(message["id"], ret))
                if after:
                    pair.qemu_qmp.sendall(after)
                if serial_after:
                    pair.guest_serial.sendall(serial_after)
                if close_qmp:
                    pair.qemu_qmp.close()
                finished.wait(5)
            except OSError:
                pass
        thread = threading.Thread(target=qemu, daemon=True)
        thread.start()
        try:
            with self.assertRaises(hv.Failure) as caught:
                hv.observe(pair.qmp, pair.serial, thv.NONCE, thv.INPUTS, time.monotonic() + timeout,
                           on_armed=lambda: armed.append(1))
        finally:
            finished.set()
            with contextlib.suppress(OSError):
                pair.qemu_qmp.shutdown(socket.SHUT_RDWR)      # wake a blocked recv
            thread.join(5)
        return str(caught.exception), seen, armed

    def test_full_state_order_arms_once_then_only_the_outer_timer_ends_it(self):
        reason, seen, armed = self.observe()
        self.assertEqual(seen, self.COMMANDS)
        self.assertEqual(armed, [1])
        self.assertEqual(reason, "timeout")        # never a success return

    def test_wrong_responses_fail_before_the_witness_is_written(self):
        cases = {4: ("qmp-not-running", {"status": "paused", "running": False}),
                 5: ("qmp-stop", {"unexpected": 1}),
                 6: ("qmp-not-paused", {"status": "running", "running": True})}
        for index, (reason, bad) in cases.items():
            with self.subTest(index=index):
                returns = list(self.RETURNS)
                returns[index] = bad
                got, _, armed = self.observe(returns)
                self.assertEqual((got, armed), (reason, []))
        got, _, armed = self.observe(errors=(5,))
        self.assertEqual((got, armed), ("qmp-stop", []))
        got, _, armed = self.observe(errors=(6,))
        self.assertEqual((got, armed), ("qmp-not-paused", []))

    def test_earlier_startup_gates_are_unchanged(self):
        returns = list(self.RETURNS)
        returns[1] = {"status": "running", "running": True}
        self.assertEqual(self.observe(returns)[0], "qmp-not-prelaunch")
        returns = list(self.RETURNS)
        returns[2] = {"enabled": False, "present": True}
        got, seen, armed = self.observe(returns)
        self.assertEqual((got, armed, seen[-1]), ("qmp-kvm-unavailable", [], "query-kvm"))

    def test_events_receipts_and_eof_after_arming_fail_the_proof(self):
        got, _, armed = self.observe(after=thv.SHUTDOWN_OK)
        self.assertEqual((got, armed), ("shutdown-during-expiry-proof", [1]))
        got, _, _ = self.observe(serial_after=thv.receipt())
        self.assertEqual(got, "guest-receipt-during-expiry-proof")
        got, _, _ = self.observe(close_qmp=True)
        self.assertEqual(got, "qmp-eof-before-shutdown")
        got, _, _ = self.observe(after=thv.event("STOP"))       # interleaved STOP is not evidence
        self.assertEqual(got, "timeout")

    def test_success_mode_is_unchanged(self):
        proto = hv.Qmp()
        self.assertEqual(proto.steps, hv.STARTUP)
        self.assertEqual(hv.Qmp(expiry=True).steps, hv.STARTUP + hv.EXPIRY_STEPS)
        self.assertEqual([s[0] for s in hv.EXPIRY_STEPS], ["query-status", "stop", "query-status"])


class WitnessFileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_witness_is_one_strict_exclusive_private_file(self):
        path = os.path.join(self.tmp.name, "armed.json")
        hv.write_armed(path, thv.NONCE, thv.INPUTS, 1234.9, cr.host_boot_id())
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertEqual(json.loads(raw), {"kind": hv.ARMED_KIND, "armed": "paused", "armed_at": 1235, "boot_id": cr.host_boot_id(),
                                           "nonce": thv.NONCE, "inputs": thv.INPUTS})
        with self.assertRaises(FileExistsError):
            hv.write_armed(path, thv.NONCE, thv.INPUTS, 1, cr.host_boot_id())
        link = os.path.join(self.tmp.name, "link.json")
        os.symlink(os.path.join(self.tmp.name, "elsewhere"), link)
        with self.assertRaises(OSError):
            hv.write_armed(link, thv.NONCE, thv.INPUTS, 1, cr.host_boot_id())

    def test_runner_and_observer_agree_on_the_witness_contract(self):
        self.assertEqual(cr.ARMED_KIND, hv.ARMED_KIND)
        path = os.path.join(self.tmp.name, "armed.json")
        hv.write_armed(path, thv.NONCE, thv.INPUTS, 1100, cr.host_boot_id())
        with open(path, "rb") as handle:
            raw = handle.read()
        staged = {"nonce": thv.NONCE, "guest_receipt": thv.INPUTS}
        self.assertTrue(cr._armed_valid(raw, staged, 1000, 200, cr.host_boot_id()))        # 100 s dwell
        self.assertFalse(cr._armed_valid(raw, staged, 1000, 150, cr.host_boot_id()))       # 50 s dwell
        self.assertFalse(cr._armed_valid(raw, staged, 1101, 500, cr.host_boot_id()))       # armed before the timer began

    def test_prearm_rejects_under_sixty_seconds_before_creating_witness(self):
        timer_path = os.path.join(self.tmp.name, "timer")
        target = os.path.join(self.tmp.name, "armed.json")
        real_open = os.open
        def opened(path, *args, **kwargs):
            return real_open(timer_path if path == "/out/witness" else path, *args, **kwargs)
        with open(timer_path, "wb") as handle:
            handle.write(b"start 900 160\n")
        with mock.patch.object(hv.os, "open", opened), \
             mock.patch.object(hv.time, "clock_gettime", return_value=1000.1):
            with self.assertRaisesRegex(hv.Failure, "insufficient-expiry-dwell"):
                hv.arm_expiry(target, thv.NONCE, thv.INPUTS)
        self.assertFalse(os.path.lexists(target))
        with open(timer_path, "wb") as handle:
            handle.write(b"start 900 161\n")
        with mock.patch.object(hv.os, "open", opened), \
             mock.patch.object(hv.time, "clock_gettime", return_value=1000.1):
            hv.arm_expiry(target, thv.NONCE, thv.INPUTS)
        with open(target) as handle:
            body = json.load(handle)
        self.assertEqual(body["armed_at"], 1001)
        self.assertEqual(body["boot_id"], cr.host_boot_id())

    def test_cli_flag_rules(self):
        base = ["--qmp", "/q", "--serial", "/s", "--result", "/r", "--timeout", "10",
                "--nonce", thv.NONCE, "--inputs", thv.INPUTS]
        self.assertEqual(hv.parse(base + ["--expiry-witness", "/w"]).expiry_witness, "/w")
        self.assertIsNone(hv.parse(base).expiry_witness)
        with contextlib.redirect_stderr(io.StringIO()):
            for extra in (["--expiry-witness", "/w", "--require-sentinel-evidence"],
                          ["--expiry-witness", "relative"]):
                with self.subTest(extra=extra), self.assertRaises(SystemExit):
                    hv.parse(base + extra)


if __name__ == "__main__":
    unittest.main()
