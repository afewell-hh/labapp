"""Offline tests for the fixed networked `qemu-fixture` task. Synthetic daemon, synthetic serial peers and a
scripted stand-in for the guest commands: no Docker, network, QEMU, KVM, VM, package or download operation.
They prove the source contracts (mode gating, the only network widening, staged bytes and plan, the strict
witness line and its revalidation, guest adapter failure mapping, cleanup and deadline reuse), not that a
real guest, bridge network, mirror or KVM works (UNRUN gates in README.md)."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import tempfile
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
PROVISION = os.path.join(os.path.dirname(HERE), "provision")
RUNTIME = tsn.RUNTIME
NATIVE = {"sudo": {"version": "1.9.15p5-3ubuntu5.24.04.4", "architecture": "amd64", "sha256": "a" * 64},
          "openssh-client": {"version": "1:9.6p1-3ubuntu13.20", "architecture": "amd64", "sha256": "b" * 64},
          "less": {"version": "590-2ubuntu2.1", "architecture": "amd64", "sha256": "c" * 64}}
HOST = {"native": NATIVE, "caller_uid": 1000, "sudo_uid": 0,
        "tun_open": True, "tun_api": True, "tap_flag": True, "tap_create": "unrun"}

spec = importlib.util.spec_from_file_location("assert_qemu", os.path.join(HERE, "guest", "assert-qemu.py"))
aq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aq)

GOOD_WITNESS = {"accelerator": "kvm", "exit": 33, "uid": 0, "nonce_equal": True, "backing_unchanged": True,
                "workspace_removed": True, "install1": {"changed": True, "seconds": 41},
                "install2": {"changed": False, "seconds": 12}, "witness_seconds": 3,
                "network": {"default_route": True, "ca_bundle": True, "resolver": True}, "host_contract": HOST}


def qemu_line(nonce=thv.NONCE, inputs=thv.INPUTS, **more):
    fields = {"accel": "kvm", "exit": "33", "uid": "0", "equal": "1", "backing": "1", "removed": "1",
              "i1": "1:41", "i2": "0:12", "w": "3", "net": "111",
              **{name: NATIVE[p]["version"] + ":" + NATIVE[p]["sha256"]
                 for name, p in (("sudo", "sudo"), ("ssh", "openssh-client"), ("less", "less"))},
              "caller": "1000", "sudo_uid": "0", "arch": "amd64", "tun_open": "1", "tun_api": "1",
              "tap_flag": "1", "tap_create": "unrun", **more}
    return (f"LABAPP-QEMU v2 nonce={nonce} inputs={inputs} " + " ".join(f"{k}={v}" for k, v in fields.items())
            + "\n").encode()


# ---------------------------------------------------------------- staging


class StagingTests(ts.StageCase):
    def setUp(self):
        super().setUp()
        self.sources, self.pins = tsn.with_archive(self.sources, self.pins, self.inputs)

    def stage_qemu(self, **kw):
        return self.stage(task="qemu-fixture", verify_seconds=kw.pop("seconds", 600), **kw)

    def test_cd_has_the_unchanged_modules_the_adapter_and_the_fixed_plan_with_archive(self):
        staged = self.stage_qemu()
        names = sorted(os.listdir(os.path.join(self.ws, "cd")))
        self.assertEqual(names, sorted(["MANIFEST", "assert-sentinel.sh", "assert-qemu.py", "guest-build.sh",
                                        "hhfab_release.py", "install-qemu.py", "qemu_offline.py", "qemu_witness.py",
                                        "meta-data", "nonce", "plan.txt", "sentinel-evidence.py", "user-data",
                                        "install-hhfab.py", "assert-fixture.py", "component_prerequisites.py", st.ARCHIVE_NAME]))
        for name in set(st.QEMU_PROVISION_FILES + st.PROVISION_FILES + (st.PROBE_FILE,)):  # unchanged modules
            with open(os.path.join(PROVISION, name), "rb") as handle:
                self.assertEqual(self.read("cd", name), handle.read(), name)
        with open(os.path.join(HERE, "guest", st.QEMU_ASSERT), "rb") as handle:
            self.assertEqual(self.read("cd", st.QEMU_ASSERT), handle.read())
        manifest = self.read("cd", "MANIFEST").decode()
        for name in (*st.QEMU_PROVISION_FILES, st.QEMU_ASSERT, "plan.txt"):
            self.assertRegex(manifest, r"(?m)^[0-9a-f]{64}  " + re.escape(name) + "$")
        self.assertEqual(staged["guest_receipt"], hashlib.sha256(self.read("cd", "MANIFEST")).hexdigest())
        self.assertEqual(staged["hhfab_archive_sha256"], self.pins["hhfab"]["sha256"])
        self.assertTrue(st.verify_staged(self.ws, staged))

    def test_qemu_files_are_root_only_and_exact_under_a_restrictive_umask(self):
        previous = os.umask(0o077)
        try:
            self.stage_qemu()
        finally:
            os.umask(previous)
        modes = {n: stat.S_IMODE(os.lstat(os.path.join(self.ws, "cd", n)).st_mode)
                 for n in os.listdir(os.path.join(self.ws, "cd"))}
        for name in (*st.QEMU_PROVISION_FILES, st.QEMU_ASSERT, "plan.txt", "MANIFEST", "nonce"):
            self.assertEqual(modes[name], 0o444 if name == "hhfab_release.py" else 0o400, name)     # shared helper remains public for the old prefix
        self.assertEqual(modes["assert-sentinel.sh"], 0o444)
        for name in (*st.PROVISION_FILES, st.ARCHIVE_NAME):
            self.assertEqual(modes[name], 0o444, name)
        self.assertEqual(modes[st.PROBE_FILE], 0o400)

    def test_plan_retains_all_ten_fixture_steps_then_appends_qemu(self):
        self.stage_qemu()
        check = "root /usr/bin/python3 -I -B @IN@/assert-qemu.py "
        self.assertEqual(self.read("cd", "plan.txt").decode().splitlines(), st.FIXTURE_PLAN.decode().splitlines() + [
            check + "baseline", check + "install 1", check + "install 2", check + "witness"])
        plan = st.QEMU_PLAN.decode()
        for word in ("curl", "wget", "--offline", "--capture-state", "--receipt-sha256", "--base-id", "-S"):
            self.assertNotIn(word, plan)

    def test_vars_reuse_the_sentinel_evidence_flag_and_add_no_hcl_input(self):
        self.stage_qemu()
        text = self.read("in", st.SENTINEL_VARS_NAME).decode()
        self.assertIn("require_sentinel_evidence = true\n", text)
        self.assertNotIn("qemu", text)
        self.assertNotIn("expiry_proof", text)
        with open(os.path.join(HERE, "labapp.pkr.hcl")) as handle:
            hcl = handle.read()
        self.assertNotIn("qemu_witness", hcl)             # HCL is unchanged by this task
        self.assertRegex(hcl, r'net_bridge\s*=\s*""')
        self.assertRegex(hcl, r'communicator\s*=\s*"none"')

    def test_other_tasks_stage_no_qemu_files_and_changed_bytes_are_detected(self):
        staged = self.stage_qemu()
        path = os.path.join(self.ws, "cd", "install-qemu.py")
        os.chmod(path, 0o600)
        with open(path, "ab") as handle:
            handle.write(b"#")
        self.assertFalse(st.verify_staged(self.ws, staged))
        self.setUp()
        self.stage(task="sentinel", verify_seconds=600, sources={k: v for k, v in self.sources.items() if k != "archive"})
        listed = os.listdir(os.path.join(self.ws, "cd"))
        for name in (*st.QEMU_PROVISION_FILES, st.QEMU_ASSERT):
            self.assertNotIn(name, listed)

    def test_a_missing_source_is_rejected(self):
        del self.sources["base"]
        with self.assertRaises(KeyError):
            self.stage_qemu()


# ---------------------------------------------------------------- runner


class QemuDaemon(tsn.SentinelDaemon):
    """Sentinel daemon whose observer result also carries a (possibly bad) qemu_witness."""

    def __init__(self, clock, variant="good", **kw):
        super().__init__(clock, **kw)
        self.variant = variant

    def start(self, container):
        super().start(container)
        out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
        path = os.path.join(out, "work", "verified.json")
        if not os.path.exists(path):
            return
        with open(path) as handle:
            try:
                body = json.load(handle)
            except ValueError:
                return
        witness = copy.deepcopy(GOOD_WITNESS)
        VARIANTS[self.variant](body, witness)
        with open(path, "w") as handle:
            json.dump(body, handle)


def _set(key, value):
    def apply(body, witness):
        witness[key] = value
        body["qemu_witness"] = witness
    return apply


def _nested(outer, key, value):
    def apply(body, witness):
        witness[outer][key] = value
        body["qemu_witness"] = witness
    return apply


def _drop(body, witness):
    pass


def _good(body, witness):
    body["qemu_witness"] = witness


def _missing_field(body, witness):
    del witness["uid"]
    body["qemu_witness"] = witness


def _not_a_dict(body, witness):
    body["qemu_witness"] = "ok"


VARIANTS = {
    "good": _good, "missing": _drop, "missing_field": _missing_field, "not_a_dict": _not_a_dict,
    "extra_key": _set("extra", 1), "tcg": _set("accelerator", "tcg"), "upper_kvm": _set("accelerator", "KVM"),
    "exit_34": _set("exit", 34), "exit_float": _set("exit", 33.0), "exit_bool": _set("exit", True),
    "student_uid": _set("uid", 1000), "nonce_not_equal": _set("nonce_equal", False),
    "backing_int": _set("backing_unchanged", 1), "workspace_kept": _set("workspace_removed", False),
    "witness_seconds_big": _set("witness_seconds", 1000), "witness_seconds_str": _set("witness_seconds", "3"),
    "install1_unchanged": _nested("install1", "changed", False),
    "install2_changed": _nested("install2", "changed", True),
    "install1_seconds_negative": _nested("install1", "seconds", -1),
    "install2_extra": _nested("install2", "stderr", "x"),
    "network_int": _nested("network", "default_route", 1),
    "network_extra": _nested("network", "proxy", True),
}


class QemuRunnerCase(tsn.SentinelCase):
    def setUp(self):
        super().setUp()
        self.sources, pins = tsn.with_archive(self.sources, cr.stage_tools.PINS,
                                              os.path.join(os.path.dirname(self.root), "src"))
        patcher = mock.patch.object(cr.stage_tools, "PINS", pins)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_qemu(self, daemon=None, delay=0.0, mode="qemu-fixture", **kw):
        daemon = daemon or QemuDaemon(self.clock)
        result = cr.run_probe(RUNTIME["image_id"], self.root, self.ledger, daemon, clock=self.clock,
                              sleep=self.clock.sleep, admitted_at=self.clock() - delay, uid=os.getuid() or 1000,
                              mode=mode, sources=(self.sources if mode == "qemu-fixture" else {k: v for k, v in self.sources.items() if k != "archive"}), **kw)
        return result, daemon


class NetworkScopeTests(QemuRunnerCase):
    def test_only_the_new_mode_is_networked_and_every_other_mode_stays_none(self):
        self.assertEqual(cr.NETWORKED_MODES, ("qemu-fixture",))
        for mode in cr.MODES:
            args = cr.create_args("n", "l", tc.IMAGE_ID, "1:1", "/w", 5, "b", mode)
            networks = [a for a in args if a.startswith("--network")]
            expected = ["--network=bridge"] if mode == "qemu-fixture" else ["--network=none"]
            self.assertEqual(networks, expected, mode)

    def test_the_networked_container_gains_no_other_access(self):
        result, daemon = self.run_qemu()
        args = self.create_call(daemon)
        for expected in ("--pull=never", "--restart=no", "--cap-drop=ALL", "--read-only",
                         "--security-opt=no-new-privileges", "--memory=10g", "--memory-swap=10g", "--cpus=5",
                         "--pids-limit=512", "--log-driver=none", "--no-healthcheck", "--device=/dev/kvm",
                         f"--group-add={tsn.KVM_GID}", "--network=bridge", "--entrypoint=/bin/bash"):
            self.assertIn(expected, args)
        for forbidden in ("--privileged", "--init", "--pid", "--ipc", "--uts", "--userns", "--volume", "-v",
                          "--env", "-e", "--cap-add", "--tmpfs", "--add-host", "--network=host", "--net",
                          "--publish", "-p", "-P", "--publish-all", "--dns", "--link", "--expose", "--sysctl",
                          "--security-opt=seccomp=unconfined", "--security-opt=apparmor=unconfined"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertEqual(len([a for a in args if a.startswith("--network")]), 1)
        self.assertEqual([a for a in args if a.startswith("--device")], ["--device=/dev/kvm"])
        self.assertEqual([a for a in args if a.startswith("--group-add")], [f"--group-add={tsn.KVM_GID}"])
        mounts = [a for a in args if a.startswith("--mount=")]
        self.assertEqual(len(mounts), 3)
        self.assertEqual(len([m for m in mounts if not m.endswith(",readonly")]), 1)
        self.assertTrue(any(m.endswith("/cd,dst=/out/work/cd,readonly") for m in mounts))
        self.assertEqual(args[-1], cr.SENTINEL_SCRIPT)
        self.assertEqual(cr.LIMITS["qemu-fixture"], cr.LIMITS["sentinel"])
        self.assertEqual(result["outcome"], "accepted", result)

    def test_the_fixed_script_and_entry_stay_free_of_network_and_tcg_options(self):
        text = (cr.SENTINEL_SCRIPT + cr.ENTRY).lower()
        for word in ("tcg", "curl", "wget", "proxy", "--network", "install"):
            self.assertNotIn(word, text)

    def test_supervise_stays_disabled_for_the_new_mode(self):
        import supervise
        self.assertNotIn("qemu-fixture", supervise.PROFILES)


class DeadlineAndAdmissionTests(QemuRunnerCase):
    def test_profile_and_every_other_profile_are_unchanged(self):
        self.assertEqual(cr.PROFILES, {"probe": (30, 20), "hcl-check": (120, 30), "sentinel": (900, 300),
                                       "runtime-check": (90, 30), "sentinel-expiry": (300, 120),
                                       "fixture": (1800, 900), "qemu-fixture": (1800, 900)})
        result, _ = self.run_qemu()
        record = self.record()
        self.assertEqual(record["work_deadline"] - record["admitted_at"], 1800)
        self.assertEqual(record["deadline"] - record["work_deadline"], 900)
        self.assertEqual(result["evidence"]["verify_seconds"], 1800 - cr.SENTINEL_RESERVE)
        self.assertEqual(record["mode"], "qemu-fixture")

    def test_exhausted_original_budget_never_reaches_the_daemon(self):
        result, daemon = self.run_qemu(delay=1700.0)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertEqual(daemon.calls, [])

    def test_no_accepted_runtime_refuses_before_ledger_workspace_staging_or_docker(self):
        daemon = QemuDaemon(self.clock)
        with mock.patch.object(cr, "SENTINEL_RUNTIME", None), \
                mock.patch.object(cr.stage_tools, "stage", side_effect=AssertionError), \
                mock.patch.object(cr, "kvm_preflight", side_effect=AssertionError):
            with self.assertRaises(ValueError):
                self.run_qemu(daemon)
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(os.listdir(self.ledger), [])

    def test_missing_kvm_fails_before_workspace_and_never_substitutes_emulation(self):
        with mock.patch.object(cr, "kvm_preflight", side_effect=cr.HardwareMissing("absent")):
            result, daemon = self.run_qemu()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "kvm_unavailable"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])

    def test_exactly_the_four_pinned_sources_are_required(self):
        daemon = QemuDaemon(self.clock)
        for sources in ({k: v for k, v in self.sources.items() if k != "base"}, {k: v for k, v in self.sources.items() if k != "archive"}):
            with self.subTest(keys=sorted(sources)), self.assertRaises(ValueError):
                cr.run_probe(RUNTIME["image_id"], self.root, self.ledger, daemon, clock=self.clock,
                             uid=os.getuid() or 1000, mode="qemu-fixture", sources=sources)
        self.assertEqual(daemon.calls, [])


class AcceptanceTests(QemuRunnerCase):
    def test_accepted_run_retains_the_closed_witness_claims_network_and_verified_cleanup(self):
        result, _ = self.run_qemu()
        self.assertEqual((result["outcome"], result["reason"]), ("accepted", None), result)
        self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))
        evidence = result["evidence"]
        self.assertEqual(evidence["task"], "qemu-fixture")
        self.assertEqual(evidence["qemu_witness"], GOOD_WITNESS)
        self.assertEqual(evidence["network"], "docker-bridge-outbound")
        self.assertEqual(evidence["claims"], cr.QEMU_CLAIMS)
        self.assertEqual(evidence["claims"]["caller_uid"], 0)
        for claim in ("student_readiness", "full_vlab", "reboot", "other_platforms"):
            self.assertIs(evidence["claims"][claim], False)
        self.assertEqual(evidence["cloud_init"], {"status": "done", "errors": 0, "recoverable_errors": 0})
        self.assertTrue(evidence["artifact"]["deleted"])
        self.assertTrue(cr.released_record(self.record()))
        self.assertEqual(cr.unresolved_records(self.ledger), [])

    def test_every_missing_forged_or_out_of_contract_witness_is_a_failure(self):
        for variant in VARIANTS:
            if variant == "good":
                continue
            with self.subTest(variant=variant):
                self.setUp()
                result, _ = self.run_qemu(QemuDaemon(self.clock, variant))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "stale_or_malformed_receipt"))
                self.assertNotIn("qemu_witness", result["evidence"])
                self.assertEqual(result["cleanup"], "verified")

    def test_no_witness_cannot_pass_even_with_a_perfect_sentinel_receipt(self):
        result, _ = self.run_qemu(tsn.SentinelDaemon(self.clock))      # plain five-key sentinel receipt
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "stale_or_malformed_receipt"))

    def test_stale_wrong_nonce_missing_and_malformed_receipts_still_fail(self):
        for receipt in ("stale", "wrong_nonce", "no_shutdown", "extra_key", "malformed", "missing",
                        "missing_evidence", "bad_evidence", "boolean_evidence"):
            with self.subTest(receipt=receipt):
                self.setUp()
                result, _ = self.run_qemu(QemuDaemon(self.clock, receipt=receipt))
                self.assertEqual(result["outcome"], "failed")
                self.assertIn(result["reason"], ("stale_or_malformed_receipt", "invalid_step_evidence"))

    def test_the_witness_is_not_accepted_by_the_other_success_modes(self):
        result, _ = self.run_qemu(QemuDaemon(self.clock), mode="sentinel")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "stale_or_malformed_receipt"))

    def test_build_failure_install_timing_reason_and_nonzero_exit_are_never_success(self):
        class Failing(QemuDaemon):
            def start(inner, container):
                super().start(container)
                out = next(a for a in container["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                with open(os.path.join(out, "build.out"), "w") as handle:
                    handle.write("noise\n" * 1000 + "    qemu.labapp (shell-local): host-verify: failed reason="
                                 "guest-reported-failure step=4 exit=1 reason=inst1-refused-s217\n")
        result, _ = self.run_qemu(Failing(self.clock, steps="build 1\n"))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "build_failed"))
        self.assertEqual(result["evidence"]["observer_failure"],
                         "guest-reported-failure step=4 exit=1 reason=inst1-refused-s217")
        self.assertNotIn("qemu_witness", result["evidence"])
        self.setUp()
        result, _ = self.run_qemu(QemuDaemon(self.clock, exit_code=1))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))

    def test_changed_inputs_uncertain_cleanup_and_client_loss_keep_their_decisions(self):
        result, _ = self.run_qemu(QemuDaemon(self.clock, tamper=True))
        self.assertEqual(result["reason"], "staged_inputs_changed")
        self.setUp()
        result, _ = self.run_qemu(QemuDaemon(self.clock, mode="rm_lost"))
        self.assertEqual((result["outcome"], result["cleanup"]), ("hold", "uncertain"))
        self.setUp()
        result, _ = self.run_qemu(QemuDaemon(self.clock, mode="start_lost"))
        self.assertEqual(result["outcome"], "hold")


class CliTests(QemuRunnerCase):
    BASE = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "qemu-fixture",
            "--core-file", "/a", "--plugin-file", "/b", "--base-file", "/c", "--archive-file", "/d"]

    def test_plan_shows_the_bridge_and_never_contacts_docker(self):
        with mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cr.main(self.BASE), 0)
        plan = json.loads(out.getvalue())
        self.assertEqual((plan["mode"], plan["executed"], plan["network"]), ("qemu-fixture", False, "bridge"))
        self.assertIn("--network=bridge", plan["create"])
        self.assertIn("--device=/dev/kvm", plan["create"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cr.main(self.BASE[:5] + ["sentinel"] + self.BASE[6:-2]), 0)
        self.assertEqual(json.loads(out.getvalue())["network"], "none")

    def test_inputs_and_the_archive_are_required(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(self.BASE[:8]), 2)
            self.assertEqual(cr.main(self.BASE[:-2]), 2)
            self.assertEqual(cr.main(self.BASE[:8] + ["--core-file", "relative", "--plugin-file", "/b",
                                                      "--base-file", "/c"]), 2)
            for option in ("--image", "--command", "--network", "--proxy"):
                with self.assertRaises(SystemExit):
                    cr.main(self.BASE + [option, "x"])

    def test_execute_is_refused_without_the_accepted_runtime_and_contacts_nothing(self):
        with mock.patch.object(cr, "SENTINEL_RUNTIME", None), \
                mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch.object(cr, "run_probe", side_effect=AssertionError), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cr.main(self.BASE + ["--execute"]), 2)
        self.assertIn("not accepted", err.getvalue())

    def test_execute_passes_the_fixed_mode_and_the_four_sources_only(self):
        argv = ["--workspace-root", self.root, "--ledger-dir", self.ledger, "--mode", "qemu-fixture",
                "--core-file", "/a", "--plugin-file", "/b", "--base-file", "/c", "--archive-file", "/d", "--execute"]
        with mock.patch.object(cr, "Backend", return_value=object()), \
                mock.patch.object(cr, "run_probe", return_value={"outcome": "accepted"}) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cr.main(argv), 0)
        self.assertEqual(run.call_args.args[0], RUNTIME["image_id"])
        self.assertEqual(run.call_args.kwargs["mode"], "qemu-fixture")
        self.assertEqual(run.call_args.kwargs["sources"], {"core": "/a", "plugin": "/b", "base": "/c", "archive": "/d"})


# ---------------------------------------------------------------- observer


class ObserverTests(unittest.TestCase):
    run_case = thv.SentinelEvidenceTests.run_case

    def test_a_valid_line_becomes_exactly_the_closed_object_alongside_the_existing_binding(self):
        result = self.run_case(thv.evidence() + qemu_line() + thv.receipt())
        self.assertEqual(result["qemu_witness"], GOOD_WITNESS)
        self.assertEqual({k: v for k, v in result.items() if k != "qemu_witness"},
                         {"nonce": thv.NONCE, "inputs": thv.INPUTS, "receipt": "ok",
                          "shutdown": "guest-shutdown", "cloud_init": hv.CLOUD_INIT})

    def test_observer_and_runner_agree_on_the_contract(self):
        found = hv.QEMU_RE.fullmatch(qemu_line().rstrip(b"\n"))
        self.assertEqual(hv.qemu_summary(found.groups()), GOOD_WITNESS)
        self.assertTrue(cr.qemu_witness_valid(GOOD_WITNESS))
        flags = hv.qemu_summary(hv.QEMU_RE.fullmatch(qemu_line(net="010").rstrip(b"\n")).groups())
        self.assertEqual(flags["network"], {"default_route": False, "ca_bundle": True, "resolver": False})
        self.assertTrue(cr.qemu_witness_valid(flags))

    def test_native_and_feasibility_objects_reject_missing_extra_wrong_type_and_false_claims(self):
        bad = [None, [], {}, {**HOST, "extra": True}, {**HOST, "caller_uid": 0},
               {**HOST, "sudo_uid": False}, {**HOST, "tun_api": 1}, {**HOST, "tun_open": False},
               {**HOST, "tap_flag": False}, {**HOST, "tap_create": "passed"},
               {**HOST, "native": []}, {**HOST, "native": {}}]
        for package in NATIVE:
            for change in ({"version": "x"}, {"version": "1" * 65}, {"version": "1\n"},
                           {"version": 1}, {"sha256": "G" * 64}, {"sha256": 1},
                           {"architecture": "arm64"}, {"extra": "SECRET"}):
                native = copy.deepcopy(NATIVE)
                native[package].update(change)
                bad.append({**HOST, "native": native})
            for key in NATIVE[package]:
                native = copy.deepcopy(NATIVE)
                del native[package][key]
                bad.append({**HOST, "native": native})
        for host in bad:
            with self.subTest(host=host):
                self.assertFalse(cr.qemu_witness_valid({**GOOD_WITNESS, "host_contract": host}))

    def test_maximum_native_version_fields_fit_unchanged_transport_bounds(self):
        line = qemu_line(**{name: "1" * 64 + ":" + "a" * 64 for name in ("sudo", "ssh", "less")})
        self.assertLess(len(line), hv.SERIAL_LINE_MAX)
        witness = hv.qemu_summary(hv.QEMU_RE.fullmatch(line.rstrip(b"\n")).groups())
        body = {"nonce": thv.NONCE, "inputs": thv.INPUTS, "receipt": "ok", "shutdown": "guest-shutdown",
                "cloud_init": hv.CLOUD_INIT, "qemu_witness": witness}
        self.assertLess(len(json.dumps(body).encode()), cr.RESULT_CAP)
        self.assertTrue(cr.qemu_witness_valid(witness))

    def test_absent_line_keeps_the_existing_result_for_other_modes(self):
        result = self.run_case(thv.evidence() + thv.receipt())
        self.assertNotIn("qemu_witness", result)

    def test_the_line_is_ignored_when_evidence_is_not_required(self):
        result = self.run_case(qemu_line() + thv.receipt(), required=False)
        self.assertNotIn("qemu_witness", result)

    def test_malformed_wrong_value_and_extra_field_lines_fail_without_echo(self):
        bad = [qemu_line(accel="tcg"), qemu_line(accel="KVM"), qemu_line(exit="34"), qemu_line(uid="1000"),
               qemu_line(equal="0"), qemu_line(backing="0"), qemu_line(removed="0"), qemu_line(i1="0:41"),
               qemu_line(i2="1:12"), qemu_line(i1="1:1000"), qemu_line(w="-1"), qemu_line(net="112"),
               qemu_line(net="11"), qemu_line(secret="1"), qemu_line().replace(b" v2 ", b" v1 "),
               qemu_line(caller="0"), qemu_line(sudo_uid="1000"), qemu_line(tun_open="0"),
               qemu_line(tun_api="0"), qemu_line(tap_flag="0"), qemu_line(tap_create="passed"),
               qemu_line(arch="arm64"), qemu_line(sudo="1:" + "G" * 64),
               qemu_line(ssh="1" * 65 + ":" + "a" * 64), qemu_line(less="/path:" + "a" * 64),
               qemu_line().replace(b"LABAPP-QEMU", b"LABAPP-QEMU x"), qemu_line().rstrip(b"\n") + b" tail\n",
               qemu_line(nonce="G" * 64)]
        for line in bad:
            with self.subTest(line=line[:80]):
                self.run_case(thv.evidence() + line + thv.receipt(), "^malformed-qemu-witness$")

    def test_duplicate_stale_and_oversize_lines_fail(self):
        self.run_case(thv.evidence() + qemu_line() * 2 + thv.receipt(), "^duplicate-qemu-witness$")
        self.run_case(thv.evidence() + qemu_line(nonce="0" * 64) + thv.receipt(),
                      "^stale-or-wrong-qemu-witness$")
        self.run_case(thv.evidence() + qemu_line(inputs="0" * 64) + thv.receipt(),
                      "^stale-or-wrong-qemu-witness$")
        self.run_case(thv.evidence() + qemu_line().rstrip() + b"x" * hv.SERIAL_LINE_MAX + b"\n" + thv.receipt(),
                      "^line-limit$")

    def test_a_failing_receipt_is_still_a_failure_with_only_the_fixed_diagnostic(self):
        self.run_case(thv.evidence() + qemu_line() + thv.diag(step=4, exit=1, reason="inst1-refused-s217")
                      + thv.receipt(status="fail"),
                      r"^guest-reported-failure step=4 exit=1 reason=inst1-refused-s217$")


# ---------------------------------------------------------------- guest adapter

PINS = {"qemu-system-x86": "1:8.2.2+ds-0ubuntu1.18", "qemu-utils": "1:8.2.2+ds-0ubuntu1.18",
        "socat": "1.8.0.0-4ubuntu0.1", "seabios": "1.16.3-2"}
NONCE_VALUE = "c3" * 32
WITNESS_JSON = {"accelerator": "KVM", "exit": 33, "nonce_equal": True, "fixture_sha256": "d" * 64,
                "backing_unchanged": True, "owned_workspace_removed": True,
                "artifacts": aq.EXPECTED_ARTIFACTS, "pins": PINS, "uid": 0, "gid": 0,
                "groups": [0], "device": {"character": True, "uid": 0, "gid": 994, "mode": "0o660",
                                          "major": 10, "minor": 232}, "seconds": 1.2}


def install_json(changed, **more):
    body = {"snapshot": "20261024T000000Z", "pins": PINS, "resolved_installed": {**PINS, "libfoo": "1"},
            "downloaded_archives": [], "changed": changed, "seconds": 1.5, **more}
    return (json.dumps(body, sort_keys=True) + "\n").encode()


class Tick:
    def __init__(self, step=7.0):
        self.now, self.step = 100.0, step

    def __call__(self):
        self.now += self.step
        return self.now


class GuestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = os.path.realpath(self.tmp.name)
        self.here = os.path.join(base, "in")
        os.mkdir(self.here, 0o755)
        for name in aq.MODULES:
            with open(os.path.join(self.here, name), "wb") as handle:
                handle.write(b"# synthetic, never executed\n")
            os.chmod(os.path.join(self.here, name), 0o444 if name == "hhfab_release.py" else 0o400)
        with open(os.path.join(self.here, "nonce"), "w") as handle:
            handle.write(NONCE_VALUE + "\n")
        with open(os.path.join(self.here, "MANIFEST"), "wb") as handle:
            handle.write(b"synthetic manifest\n")
        self.inputs = hashlib.sha256(b"synthetic manifest\n").hexdigest()
        self.files = {}
        for key, content in (("route", b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                                       b"eth0\t00000000\t0202000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"),
                             ("resolver", b"nameserver 10.0.2.3\n"), ("ca", b"-----BEGIN CERTIFICATE-----\n"),
                             ("tty", b""), ("a1", b"1"), ("a2", b"2")):
            path = os.path.join(base, key)
            with open(path, "wb") as handle:
                handle.write(content)
            self.files[key] = path
        self.reason = os.path.join(base, "reason")
        self.state = os.path.join(base, "state")
        self.packages = dict(PINS)
        self.audit = b""
        self.installs = [(0, install_json(True)), (0, install_json(False))]
        self.witness_result = (0, (json.dumps(WITNESS_JSON) + "\n").encode())
        self.commands = []
        self.mutate = None
        self.remaining = copy.deepcopy(NATIVE)
        self.tun_result = None
        self.sudo_result = (0, b"0\n")

    def cfg(self, euid=0):
        return aq.Config(self.here, state=self.state, reason=self.reason, tty=self.files["tty"],
                         route=self.files["route"], resolver=self.files["resolver"], ca=self.files["ca"],
                         euid=lambda: euid, run=self.fake, clock=Tick(), owner=os.getuid(),
                         artifacts=(self.files["a1"], self.files["a2"]),
                         inventory=lambda: copy.deepcopy(self.remaining), tun=self.fake_tun,
                         lookup=lambda _: type("Owner", (), {"pw_uid": 1000, "pw_gid": 1000})())

    def fake_tun(self):
        if self.tun_result:
            raise self.tun_result

    def fake(self, argv, seconds):
        self.commands.append((list(argv), seconds))
        if argv[0] == "/usr/sbin/runuser":
            if isinstance(self.sudo_result, Exception):
                raise self.sudo_result
            return self.sudo_result
        if argv[0] == "/usr/bin/dpkg-query":
            rows = "".join(f"{n}\t{v}\tinstalled\n" for n, v in self.packages.items())
            return 0, (rows + "unrelated\t9\tinstalled\n").encode()
        if argv[0] == "/usr/bin/dpkg":
            return 0, self.audit
        script = os.path.basename(argv[-1])
        if script == "install-qemu.py":
            result = self.installs.pop(0)
            if isinstance(result, Exception):
                raise result
            if self.mutate:
                self.mutate()
            return result
        if script == "qemu_witness.py":
            if isinstance(self.witness_result, Exception):
                raise self.witness_result
            return self.witness_result
        raise AssertionError(argv)

    def go(self, *argv):
        return aq.run(list(argv), self.cfg())

    def token(self):
        try:
            with open(self.reason) as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def sequence(self):
        return [self.go(*step) for step in (("baseline",), ("install", "1"), ("install", "2"), ("witness",))]

    def tty(self):
        with open(self.files["tty"], "rb") as handle:
            return handle.read()


class GuestSuccessTests(GuestCase):
    def test_real_socat_filetree_preserves_link_and_payload_and_refuses_retarget(self):
        cfg = self.cfg()
        directory = os.path.dirname(self.files["a1"])
        payload = os.path.join(directory, "socat1")
        link = os.path.join(directory, "socat")
        with open(payload, "wb") as handle:
            handle.write(b"synthetic package payload")
        os.symlink("socat1", link)
        cfg.artifacts = (payload,)
        before = aq.native_state(cfg, set(PINS))
        self.assertEqual(before, aq.native_state(cfg, set(PINS)))
        self.assertEqual(before["artifacts"][payload][-1], hashlib.sha256(b"synthetic package payload").hexdigest())
        os.unlink(link)
        os.symlink("a1", link)
        with self.assertRaisesRegex(aq.Check, "native-artifact"):
            aq.native_state(cfg, set(PINS))

    def test_known_resolver_symlink_observes_target_without_repair(self):
        target = "/run/systemd/resolve/stub-resolv.conf"
        os.unlink(self.files["resolver"])
        os.symlink(target, self.files["resolver"])
        original = aq.read_small
        with mock.patch.object(aq, "read_small", side_effect=lambda path: b"nameserver 127.0.0.53\n" if path == target else original(path)):
            self.assertTrue(aq.network_facts(self.cfg())["resolver"])
        self.assertEqual(os.readlink(self.files["resolver"]), target)

    def test_expected_contract_tracks_unchanged_modules(self):
        import ast
        for filename, constants in (("install-qemu.py", {"SNAPSHOT": aq.EXPECTED_SNAPSHOT, "PINS": aq.EXPECTED_PINS}),
                                    ("qemu_witness.py", {"ARTIFACTS": aq.EXPECTED_ARTIFACTS})):
            with open(os.path.join(PROVISION, filename)) as handle:
                tree = ast.parse(handle.read())
            actual = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                      if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                      and node.targets[0].id in constants}
            self.assertEqual(actual, constants)

    def test_full_sequence_emits_exactly_one_run_bound_line_the_observer_and_runner_accept(self):
        self.assertEqual(self.sequence(), [0, 0, 0, 0])
        self.assertIsNone(self.token())
        line = self.tty()
        self.assertEqual(line.count(b"\n"), 2)       # one blank-framed record
        record = line.strip(b"\n")
        found = hv.QEMU_RE.fullmatch(record)
        self.assertIsNotNone(found, record)
        self.assertEqual(found.groups()[:2], (NONCE_VALUE.encode(), self.inputs.encode()))
        witness = hv.qemu_summary(found.groups())
        self.assertEqual(witness["install1"], {"changed": True, "seconds": 7})
        self.assertEqual(witness["install2"], {"changed": False, "seconds": 7})
        self.assertEqual(witness["network"], {"default_route": True, "ca_bundle": True, "resolver": True})
        self.assertTrue(cr.qemu_witness_valid(witness))

    def test_the_modules_run_unchanged_with_no_options_in_the_fixed_environment(self):
        self.sequence()
        runs = [c for c in self.commands if c[0][0] == "/usr/bin/python3"]
        self.assertEqual([c[0][1:2] + [os.path.basename(c[0][2])] for c in runs],
                         [["-B", "install-qemu.py"], ["-B", "install-qemu.py"], ["-B", "qemu_witness.py"]])
        self.assertTrue(all(len(c[0]) == 3 for c in runs))        # no argument reaches any module
        self.assertEqual([c[1] for c in runs], [aq.INSTALL_SECONDS, aq.INSTALL_SECONDS, aq.WITNESS_SECONDS])
        self.assertEqual(aq.ENV, {"PATH": aq.SAFE_PATH, "HOME": "/root", "LC_ALL": "C.UTF-8",
                                  "DEBIAN_FRONTEND": "noninteractive"})

    def test_network_facts_report_missing_route_ca_and_resolver_without_failing_or_repairing(self):
        for key in ("route", "ca", "resolver"):
            open(self.files[key], "wb").close()
        self.assertEqual(self.sequence(), [0, 0, 0, 0])
        self.assertIn(b"net=000", self.tty())

    def test_unrelated_package_changes_do_not_fail_the_rerun(self):
        self.go("baseline")
        self.go("install", "1")
        self.packages["unrelated"] = "9"          # fake lists an extra row regardless; only pins compare
        self.assertEqual(self.go("install", "2"), 0)


class GuestFailureTests(GuestCase):
    def fails(self, steps_before, step, pattern):
        for name in steps_before:
            self.assertEqual(self.go(*name), 0, name)
        self.assertEqual(self.go(*step), 1)
        got = self.token()
        self.assertRegex(got, pattern)
        self.assertRegex(got, aq.REASON_RE)
        self.assertEqual(self.tty(), b"")           # never a success line after a failure

    def test_bad_arguments_do_nothing(self):
        for argv in ([], ["bogus"], ["install"], ["install", "3"], ["install", "1", "x"], ["witness", "x"],
                     ["baseline", "x"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.go(*argv), 2)
        self.assertEqual(self.commands, [])
        self.assertFalse(os.path.exists(self.state))

    def test_not_root_and_unexpected_staging_modes_fail_at_baseline(self):
        self.assertEqual(aq.run(["baseline"], self.cfg(euid=1000)), 1)
        self.assertEqual(self.token(), "not-root")
        os.unlink(self.reason)
        os.chmod(os.path.join(self.here, "install-qemu.py"), 0o444)
        self.assertEqual(self.go("baseline"), 1)
        self.assertEqual(self.token(), "staging-input")

    def test_first_failure_token_is_never_overwritten(self):
        aq.report(self.cfg(), "inst1-timeout")
        aq.report(self.cfg(), "witness-failed")
        self.assertEqual(self.token(), "inst1-timeout")
        os.unlink(self.reason)
        aq.report(self.cfg(), "Bad Token\n")
        self.assertEqual(self.token(), "internal")

    def test_installer_refusal_exit_timeout_and_overflow_keep_the_phase_and_bounded_time(self):
        cases = [((1, b"anything SECRET"), r"^inst1-refused-s007$"), ((2, b"x"), r"^inst1-exit-s007$"),
                 ((130, b"x"), r"^inst1-exit-s007$"), (aq.Timeout("timeout"), r"^inst1-timeout$"),
                 (aq.Timeout("output"), r"^inst1-output$")]
        for result, pattern in cases:
            with self.subTest(pattern=pattern):
                self.setUp()
                self.installs = [result]
                self.fails([("baseline",)], ("install", "1"), pattern)
                self.assertNotIn("SECRET", self.token())

    def test_the_second_run_failures_are_attributed_to_run_two(self):
        self.installs = [(0, install_json(True)), (1, b"x")]
        self.fails([("baseline",), ("install", "1")], ("install", "2"), r"^inst2-refused-s007$")

    def test_remaining_host_version_hash_and_identity_drift_fail_at_each_boundary(self):
        for phase in (1, 2, 3):
            for field, value in (("version", "9"), ("sha256", "f" * 64), ("identity", [999])):
                with self.subTest(phase=phase, field=field):
                    self.setUp()
                    self.assertEqual(self.go("baseline"), 0)
                    if phase >= 2:
                        self.assertEqual(self.go("install", "1"), 0)
                    if phase == 3:
                        self.assertEqual(self.go("install", "2"), 0)
                    self.remaining["sudo"][field] = value
                    step = ("install", str(phase)) if phase < 3 else ("witness",)
                    self.assertEqual(self.go(*step), 1)
                    self.assertEqual(self.token(), "host-drift")
                    self.assertEqual(self.tty(), b"")

    def test_sudo_and_tun_failures_never_emit_a_success_summary(self):
        for result in ((1, b"SECRET"), (0, b"1000\n"), aq.Timeout("timeout"), aq.Timeout("output")):
            self.setUp()
            self.sudo_result = result
            self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), r"^sudo-")
        self.setUp()
        self.tun_result = aq.Check("tun-api")
        self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), r"^tun-api$")

    def test_malformed_or_out_of_contract_installer_output_is_rejected(self):
        good = json.loads(install_json(True))
        bad = [b"", b"not json", b"[]", b'{"a": 1, "a": 2}', b"NaN",
               json.dumps({**good, "extra": 1}).encode(),
               json.dumps({k: v for k, v in good.items() if k != "pins"}).encode(),
               json.dumps({**good, "changed": 1}).encode(),
               json.dumps({**good, "pins": {}}).encode(),
               json.dumps({**good, "pins": {**PINS, "socat": 1}}).encode(),
               json.dumps({**good, "resolved_installed": {}}).encode(),
               json.dumps({**good, "downloaded_archives": "x"}).encode(),
               b"\xff", b" " * (aq.INSTALL_OUTPUT_CAP + 1),
               install_json(True, snapshot="wrong"), install_json(True, seconds=True),
               install_json(True, seconds=float("nan")), install_json(True, downloaded_archives=[{}])]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                self.setUp()
                self.installs = [(0, raw)]
                self.fails([("baseline",)], ("install", "1"), "^inst1-output$")

    def test_run_one_must_change_the_guest_and_run_two_must_not(self):
        self.installs = [(0, install_json(False))]
        self.fails([("baseline",)], ("install", "1"), "^inst1-unchanged$")
        self.setUp()
        self.installs = [(0, install_json(True)), (0, install_json(True))]
        self.fails([("baseline",), ("install", "1")], ("install", "2"), "^inst2-changed$")

    def test_native_checks_reject_wrong_versions_missing_packages_and_a_dirty_dpkg(self):
        for label, change in (("version", lambda s: s.packages.update(socat="0")),
                              ("missing", lambda s: s.packages.pop("seabios")),
                              ("audit", lambda s: setattr(s, "audit", b"partially installed"))):
            with self.subTest(label=label):
                self.setUp()
                change(self)
                token = "^native-audit$" if label == "audit" else "^native-pins$"
                self.fails([("baseline",)], ("install", "1"), token)

    def test_a_rewritten_artifact_or_changed_version_on_the_rerun_is_not_idempotent(self):
        def rewrite():
            os.utime(self.files["a1"], ns=(1, 1))
            with open(self.files["a1"], "ab") as handle:
                handle.write(b"x")
        self.go("baseline")
        self.go("install", "1")
        self.mutate = rewrite
        self.assertEqual(self.go("install", "2"), 1)
        self.assertEqual(self.token(), "rerun-state")

    def test_witness_refusals_map_only_to_fixed_tokens(self):
        for message, token in aq.WITNESS_REFUSALS.items():
            with self.subTest(message=message):
                self.setUp()
                self.witness_result = (1, f"qemu witness: {message}\n".encode())
                self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), "^" + token + "$")
        for result in ((1, b"qemu witness: SECRET new text\n"), (1, b"Traceback SECRET"), (3, b"x")):
            with self.subTest(result=result):
                self.setUp()
                self.witness_result = result
                self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), "^witness-failed$")
                self.assertNotIn("SECRET", self.token())

    def test_witness_timeout_and_overflow(self):
        for exc, token in ((aq.Timeout("timeout"), "witness-timeout"), (aq.Timeout("output"), "witness-output")):
            self.setUp()
            self.witness_result = exc
            self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), "^" + token + "$")

    def test_witness_reports_that_are_not_real_kvm_exit33_root_nonce_backing_cleanup_or_same_pins_fail(self):
        variants = [{"accelerator": "TCG-test-only"}, {"exit": 34}, {"exit": 33.0}, {"exit": True},
                    {"uid": 1000}, {"nonce_equal": False}, {"backing_unchanged": False},
                    {"owned_workspace_removed": False}, {"pins": {**PINS, "socat": "9"}},
                    {"device": {"character": False}}, {"device": None}, {"fixture_sha256": "zz"},
                    {"extra": 1}, {"seconds": True}, {"gid": False}, {"groups": [True]},
                    {"artifacts": {}}]
        for change in variants:
            with self.subTest(change=change):
                self.setUp()
                self.witness_result = (0, json.dumps({**WITNESS_JSON, **change}).encode())
                self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), "^witness-invalid$")
        for raw in (b"", b'{"a":1,"a":2}', b"Infinity", b" " * (aq.WITNESS_OUTPUT_CAP + 1)):
            self.setUp()
            self.witness_result = (0, raw)
            self.fails([("baseline",), ("install", "1"), ("install", "2")], ("witness",), "^witness-output$")

    def test_witness_cannot_run_without_both_installer_runs_and_an_unwritable_console_fails(self):
        self.assertEqual(self.go("baseline"), 0)
        self.assertEqual(self.go("witness"), 1)
        self.assertEqual(self.token(), "state-missing")
        self.assertEqual([c for c in self.commands if "qemu_witness.py" in c[0][-1]], [])
        self.setUp()
        self.assertEqual([self.go("baseline"), self.go("install", "1"), self.go("install", "2")], [0, 0, 0])
        os.unlink(self.files["tty"])
        self.assertEqual(self.go("witness"), 1)
        self.assertEqual(self.token(), "emit-failed")

    def test_missing_identity_inputs_fail_before_any_line(self):
        for name in ("nonce", "MANIFEST"):
            with self.subTest(name=name):
                self.setUp()
                self.assertEqual([self.go("baseline"), self.go("install", "1"), self.go("install", "2")], [0, 0, 0])
                os.unlink(os.path.join(self.here, name))
                self.assertEqual(self.go("witness"), 1)
                self.assertEqual(self.token(), "identity")
                self.assertEqual(self.tty(), b"")


class SourceContractTests(unittest.TestCase):
    def test_adapter_has_no_network_repair_retry_or_shell_surface(self):
        with open(os.path.join(HERE, "guest", "assert-qemu.py")) as handle:
            source = handle.read()
        for word in ("shell=True", "os.system", "apt-get", "curl", "wget", "tcg", "--offline", "--capture-state",
                     "chmod", "chown", "modprobe", "usermod", "adduser", "ip link", "dhclient", "resolvectl"):
            self.assertNotIn(word, source, word)

    def test_plan_pins_only_the_adapter_and_witness_never_arguments_to_the_modules(self):
        plan = st.QEMU_PLAN.decode()
        self.assertEqual(plan.count("install-qemu.py"), 0)     # run by the adapter with no argument
        self.assertEqual(plan.count("assert-qemu.py"), 4)

    def test_guest_runner_adds_no_nonroot_reader_for_the_qemu_files(self):
        with open(os.path.join(HERE, "guest", "guest-build.sh")) as handle:
            text = handle.read()
        self.assertNotIn("install-qemu.py", text)       # no nonroot reader is added
        self.assertNotIn("qemu_witness.py", text)

    def test_witness_module_remains_kvm_only_and_unmodified_in_the_staged_set(self):
        with open(os.path.join(PROVISION, "qemu_witness.py")) as handle:
            text = handle.read()
        self.assertIn('"tcg,thread=single" if test_tcg else "kvm"', text)
        self.assertIn("probe()", text)
        self.assertNotIn("test_tcg=True", text)


if __name__ == "__main__":
    unittest.main()
