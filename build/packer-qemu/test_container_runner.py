"""Offline tests with a synthetic Docker daemon and fake docker executables.

No Docker, container, systemd or VM is used (the entry script is run only under the
local /bin/bash with stand-in paths). They prove the supervisor's call sequence,
bounds, ledger ordering and fail-closed decisions, not Docker or kernel behavior.
"""
import contextlib
import fcntl
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import container_runner as cr
import test_stage_tools as ts

IMAGE = cr.PINNED_IMAGE
IMAGE_ID = "sha256:" + "b" * 64


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeDaemon:
    """Argv-level fake. `mode` injects faults; every call advances the clock.
    It models the entry script's arithmetic: timer recomputed at actual start."""

    def __init__(self, clock, mode="ok", exit_code=137, call_cost=0.1, start_delay=0.0, on_call=None):
        self.clock, self.mode, self.exit_code, self.cost = clock, mode, exit_code, call_cost
        self.start_delay, self.on_call = start_delay, on_call
        self.containers, self.calls = {}, []

    def option(self, args, prefix):
        return next(a[len(prefix):] for a in args if a.startswith(prefix))

    def matches(self, args):
        filters = [args[i + 1] for i, a in enumerate(args) if a == "--filter"]
        out = []
        for c in self.containers.values():
            ok = True
            for f in filters:
                key, val = f.split("=", 1)
                ok &= {"name": val == f"^/{c['name']}$", "label": val == c["label"],
                       "id": c["id"].startswith(val)}[key]
            if ok:
                out.append(c["id"])
        return "\n".join(out)

    def image_info(self):
        info = {"Id": IMAGE_ID, "RepoDigests": [IMAGE], "Config": {}}
        if self.mode == "image_volume":
            info["Config"]["Volumes"] = {"/data": {}}
        if self.mode == "image_onbuild":
            info["Config"]["OnBuild"] = ["RUN x"]
        if self.mode == "image_other_digest":
            info["RepoDigests"] = ["ubuntu@sha256:" + "c" * 64]
        return json.dumps(info)

    def start(self, c):
        self.clock.now += self.start_delay
        args = c["args"]
        deadline = int(args[args.index("bash") + 1])
        n = int(self.clock.now)
        timer = deadline - n - 1 - cr.KILL_AFTER
        ws = self.option(args, "--mount=").split("src=")[1].split(",")[0]
        c["state"] = "running"
        if self.mode == "no_witness":                 # immediate 137, no probe/timer witness
            c["exit_at"] = self.clock.now + 0.9
        elif timer < cr.MIN_TIMER:                     # late actual start: probe never runs
            c["exit_at"], c["code"] = self.clock.now, 125
        else:
            text = f"start {n} {timer}\nprobe 77\nterm_ignored\n"
            if self.mode == "bad_witness":
                text = f"start {n} {timer + 9}\nprobe 77\nterm_ignored\n"
            with open(os.path.join(ws, "witness"), "w") as handle:
                handle.write(text)
            c["exit_at"] = n + timer + cr.KILL_AFTER
            if self.mode == "early_exit":
                c["exit_at"] = self.clock.now + 1.0
        if self.mode == "never_exits":
            c["exit_at"] = float("inf")
        c.setdefault("code", self.exit_code)

    def call(self, args, seconds):
        self.calls.append((list(args), seconds))
        self.clock.now += self.cost
        assert seconds > 0
        if self.on_call:
            self.on_call(args)
        verb = args[0]
        if self.mode == "down" and verb in ("container", "inspect", "stop", "rm"):
            raise cr.DockerError()
        if verb == "version":
            return "29.6.1"
        if verb == "image":
            return self.image_info()
        if verb == "create":
            name, label = self.option(args, "--name="), self.option(args, "--label=")
            ident = hashlib.sha256(name.encode()).hexdigest()
            self.containers[ident] = {"id": ident, "name": name, "label": label,
                                      "state": "created", "args": args}
            if self.mode == "create_lost":
                raise cr.DockerTimeout()
            if self.mode == "create_garbage":
                return "not-an-id"
            return ident
        if verb == "start":
            self.start(self.containers[args[-1]])
            if self.mode == "start_lost":
                raise cr.DockerTimeout()
            if self.mode == "start_interrupt":
                raise KeyboardInterrupt()
            return ""
        if verb == "inspect":
            c = self.containers[args[-1]]
            if "{{.Name}}" in args[3]:
                label = c["label"].split("=", 1)[1]
                return f"{c['id']} /{c['name']}{'x' if self.mode == 'name_mismatch' else ''} {label}"
            if self.mode == "poll_down":
                raise cr.DockerError()
            if self.clock.now < c["exit_at"]:
                return "running 0 false"
            c["state"] = "exited"
            return f"exited {c['code']} {'true' if self.mode == 'oom' else 'false'}"
        if verb == "container":
            if self.mode == "query_down":
                raise cr.DockerError()
            if self.mode == "stale" and "--filter" in args and args[args.index("--filter") + 1].startswith("name="):
                return self.matches(args) + "\n" + "c" * 64
            if self.mode == "rm_ignored" and self.containers and "id=" in " ".join(args):
                return next(iter(self.containers))
            if self.mode == "vanished" and not self.containers_removed_by_us():
                return ""
            return self.matches(args)
        if verb == "stop":
            if self.mode == "deprecated_stop_warning":
                if any(a.startswith("--time=") for a in args):
                    return "Flag --time has been deprecated, use --timeout instead\n" + args[-1]
                return args[-1]
            if self.mode == "stop_fail":
                raise cr.DockerError()
            return ""
        if verb == "rm":
            if self.mode != "rm_ignored":
                self.containers.pop(args[-1], None)
            if self.mode == "rm_lost":
                raise cr.DockerTimeout()
            return args[-1]
        raise AssertionError(args)

    def containers_removed_by_us(self):
        return any(c[0][0] == "rm" for c in self.calls)


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = os.path.realpath(self.tmp.name)
        self.root, self.ledger = os.path.join(base, "ws"), os.path.join(base, "ledger")
        for d in (self.root, self.ledger):
            os.mkdir(d, 0o700)
        self.clock = Clock()

    def run_probe(self, mode="ok", delay=0.0, **kw):
        daemon = FakeDaemon(self.clock, mode, **kw.pop("daemon", {}))
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              admitted_at=self.clock() - delay, uid=os.getuid() or 1000, **kw)
        return result, daemon

    def mutations(self, daemon):
        return [c[0][0] for c in daemon.calls if c[0][0] in ("create", "start", "rm", "stop")]

    def record(self):
        names = [n for n in os.listdir(self.ledger) if n.endswith(".json")]
        self.assertEqual(len(names), 1)
        with open(os.path.join(self.ledger, names[0])) as handle:
            return json.load(handle)


def workspace_of(args):
    return next(a for a in args if a.startswith("--mount")).split("src=")[1].split(",")[0]


class ReleasedModeIdentityTests(RunnerCase):
    def test_prior_probe_hcl_and_runtime_records_preserve_their_fixed_identity(self):
        result, _ = self.run_probe()
        self.assertEqual(result["outcome"], "accepted")
        record = self.record()
        for mode, image in (("probe", cr.PINNED_IMAGE), ("hcl-check", cr.PINNED_IMAGE),
                            ("runtime-check", cr.PREPARED_RUNTIME["image_id"])):
            with self.subTest(mode=mode):
                self.assertTrue(cr.released_record({**record, "mode": mode, "image": image}))
                self.assertFalse(cr.released_record({**record, "mode": mode, "image": "sha256:" + "0" * 64}))
        legacy = {k: v for k, v in record.items() if k != "mode"}
        self.assertTrue(cr.released_record(legacy))
        for mode in ("unknown", "", None, 7, []):
            with self.subTest(mode=mode):
                self.assertFalse(cr.released_record({**record, "mode": mode}))


class CreateArgumentTests(RunnerCase):
    def test_fixed_restrictive_command_and_no_forbidden_options(self):
        result, daemon = self.run_probe()
        self.assertEqual(result["outcome"], "accepted", result)
        args = next(c[0] for c in daemon.calls if c[0][0] == "create")
        for required in ("--pull=never", "--restart=no", "--network=none", "--cap-drop=ALL", "--no-healthcheck",
                         "--security-opt=no-new-privileges", "--read-only", "--pids-limit=64",
                         "--memory=256m", "--cpus=1", "--entrypoint=/bin/bash"):
            self.assertIn(required, args)
        for forbidden in ("--privileged", "--init", "--pid", "--ipc", "--uts", "--userns",
                          "--device", "--volume", "-v", "--env", "-e", "--cap-add", "--group-add"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertNotIn("docker.sock", " ".join(args))
        self.assertEqual([a for a in args if a.startswith("--mount")],
                         [f"--mount=type=bind,src={workspace_of(args)},dst=/out"])
        tail = args[args.index(IMAGE_ID) + 1:]
        self.assertEqual(tail, ["-c", cr.ENTRY, "bash", "1030", cr.host_boot_id(), cr.PROBE_SCRIPT])   # fixed; deadline = admission + 30
        self.assertTrue(any(a.startswith("--user=") and not a.startswith("--user=0") for a in args))

    def test_only_the_pinned_digest_and_non_root_are_accepted(self):
        for bad in ("ubuntu:24.04", "ubuntu@sha256:abc", "ubuntu@sha256:" + "a" * 64, "debian@sha256:" + "a" * 64):
            with self.assertRaises(ValueError):
                cr.run_probe(bad, self.root, self.ledger, FakeDaemon(self.clock))
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, self.ledger, FakeDaemon(self.clock), uid=0)

    def test_image_config_is_inspected_and_unsupported_images_rejected_before_create(self):
        for mode in ("image_volume", "image_onbuild", "image_other_digest"):
            self.setUp()
            result, daemon = self.run_probe(mode)
            self.assertEqual(result["outcome"], "failed", mode)
            self.assertEqual(self.mutations(daemon), [], mode)
            self.assertNotIn("pull", [c[0][0] for c in daemon.calls])

    def test_entry_script_recomputes_timer_and_execs_same_pid1(self):
        """Run ENTRY under local sh with stand-in paths: no container involved."""
        with tempfile.TemporaryDirectory() as d:
            boot = "12345678-1234-1234-1234-123456789abc"
            for name, content in (("boot", boot), ("offsets", "monotonic 0 0\nboottime 0 0\n"),
                                  ("uptime", "1000.99 10.00")):
                with open(os.path.join(d, name), "w") as handle:
                    handle.write(content.rstrip("\n") + "\n")
            timeout = os.path.join(d, "timeout")
            with open(timeout, "w") as handle:
                handle.write('#!/bin/bash\nprintf "%s\\n" "$$" "$@" > ' + d + '/argv\n')
            os.chmod(timeout, 0o755)
            script = cr.ENTRY.replace("/proc/sys/kernel/random/boot_id", d + "/boot") \
                .replace("/proc/self/timens_offsets", d + "/offsets").replace("/proc/uptime", d + "/uptime") \
                .replace("/usr/bin/timeout", timeout).replace("/out/", d + "/")
            proc = subprocess.Popen(["/bin/bash", "-c", script, "bash", "1030", boot, "PROBE"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _, err = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0, err)
            with open(os.path.join(d, "argv")) as handle:
                argv = handle.read().splitlines()
            self.assertEqual(argv, [str(proc.pid), "--kill-after=5s", "24s", "/bin/bash", "-c", "PROBE"])
            for deadline, bootarg in (("1010", boot), ("1030", "different")):
                late = subprocess.run(["/bin/bash", "-c", script, "bash", deadline, bootarg], capture_output=True, timeout=3)
                self.assertEqual(late.returncode, 125)
            with open(os.path.join(d, "offsets"), "w") as handle:
                handle.write("monotonic 0 0\nboottime 1 0\n")
            shifted = subprocess.run(["/bin/bash", "-c", script, "bash", "1030", boot], capture_output=True, timeout=3)
            self.assertEqual(shifted.returncode, 125)


class BudgetTests(RunnerCase):
    def test_preparation_delay_rejects_before_any_mutation(self):
        result, daemon = self.run_probe(delay=25.0)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertEqual(self.mutations(daemon), [])
        self.assertEqual(result["workspace"], "removed")

    def test_admission_after_total_deadline_makes_no_calls(self):
        result, daemon = self.run_probe(delay=60.0)
        self.assertEqual(daemon.calls, [])
        self.assertEqual(result["outcome"], "failed")

    def test_late_actual_start_runs_no_probe_and_is_not_accepted(self):
        result, daemon = self.run_probe(daemon={"start_delay": 20.0})
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["reason"], "unexpected_exit")       # exit 125, no witness
        self.assertEqual(daemon.containers, {})

    def test_timer_shrinks_with_actual_start_and_ends_inside_the_deadline(self):
        seen = []

        def grab(args):
            if args[0] == "inspect" and "{{.State.Status}}" in args[3]:
                ws = [os.path.join(self.root, n) for n in os.listdir(self.root)][0]
                with open(os.path.join(ws, "witness")) as handle:
                    seen.append(handle.readline().split())
        self.run_probe(daemon={"on_call": grab})
        self.setUp()
        self.run_probe(daemon={"on_call": grab, "start_delay": 8.0})
        first, second = seen[0], seen[-1]
        self.assertEqual((first[0], int(first[2])), ("start", 24))      # 1030 - 1000 - 1 - 5
        self.assertEqual((second[0], int(second[2])), ("start", 16))    # started 8 s later: 1030 - 1008 - 6
        self.assertLessEqual(int(second[1]) + int(second[2]) + cr.KILL_AFTER, 1030 - 1)

    def test_every_call_is_bounded_by_remaining_budget(self):
        _, daemon = self.run_probe(daemon={"call_cost": 4.0})
        for args, seconds in daemon.calls:
            self.assertLessEqual(seconds, cr.CALL_CAP)

    def test_slow_daemon_cannot_extend_beyond_total_deadline(self):
        result, _ = self.run_probe("never_exits", daemon={"call_cost": 3.0})
        self.assertLess(self.clock() - 1000.0, 50.0 + 3.0 + cr.CALL_CAP)
        self.assertNotEqual(result["outcome"], "accepted")

    def test_host_expiry_is_never_acceptance_and_container_is_removed(self):
        result, daemon = self.run_probe("never_exits")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "host_expiry"))
        self.assertEqual(daemon.containers, {})
        self.assertEqual(result["cleanup"], "verified")


class EvidenceTests(RunnerCase):
    def test_immediate_137_without_witness_is_not_accepted(self):
        result, _ = self.run_probe("no_witness")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "no_probe_witness"))

    def test_inconsistent_witness_is_rejected(self):
        result, _ = self.run_probe("bad_witness")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "no_probe_witness"))

    def test_exit_long_before_timer_is_rejected(self):
        result, _ = self.run_probe("early_exit")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "exited_before_timer"))

    def test_any_extra_output_is_rejected_as_untrusted(self):
        def plant(args):
            if args[0] == "start":
                os.symlink("/etc/passwd", os.path.join(workspace_of(self.created(daemon)), "evil"))
        daemon = FakeDaemon(self.clock, on_call=plant)
        daemon.calls = []
        self.created = lambda d: next(c[0] for c in d.calls if c[0][0] == "create")
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              uid=os.getuid() or 1000)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "no_probe_witness"))
        self.assertEqual(result["workspace"], "removed")
        self.assertTrue(os.path.exists("/etc/passwd"))

    def test_symlinked_witness_is_rejected(self):
        def swap(args):
            if args[0] == "inspect" and "{{.State.Status}}" in args[3]:
                ws = workspace_of(next(c[0] for c in daemon.calls if c[0][0] == "create"))
                path = os.path.join(ws, "witness")
                if os.path.isfile(path) and not os.path.islink(path):
                    os.unlink(path)
                    os.symlink("/etc/hostname", path)
        daemon = FakeDaemon(self.clock, on_call=swap)
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              uid=os.getuid() or 1000)
        self.assertNotEqual(result["outcome"], "accepted")

    def test_accepted_run_removes_workspace_and_releases_ledger(self):
        result, _ = self.run_probe()
        self.assertEqual((result["outcome"], result["workspace"], result["exit_code"]), ("accepted", "removed", 137))
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(self.record()["state"], "released")

    def test_unexpected_exit_code_and_oom_not_accepted(self):
        self.assertEqual(self.run_probe(daemon={"exit_code": 0})[0]["reason"], "unexpected_exit")
        self.setUp()
        self.assertEqual(self.run_probe("oom")[0]["outcome"], "failed")

    def test_workspace_root_must_be_private_and_symlink_free(self):
        os.chmod(self.root, 0o777)
        with self.assertRaises(ValueError):
            cr.make_workspace(self.root, "x", os.getuid())
        os.chmod(self.root, 0o700)
        link = self.root + "-link"
        os.symlink(self.root, link)
        self.addCleanup(os.unlink, link)
        with self.assertRaises(ValueError):
            cr.make_workspace(link, "x", os.getuid())


class LedgerTests(RunnerCase):
    def test_intent_is_durable_before_each_daemon_mutation(self):
        seen = []

        def spy(args):
            if args[0] in ("create", "start", "stop", "rm"):
                seen.append((args[0], self.record()["state"]))
        self.run_probe(daemon={"on_call": spy})
        self.assertEqual(seen, [("create", "create_intent"), ("start", "start_intent"),
                                ("stop", "stop_rm_intent"), ("rm", "stop_rm_intent")])

    def test_ledger_is_outside_workspace_and_records_recovery_information(self):
        result, _ = self.run_probe("start_lost")
        record = self.record()
        self.assertFalse(result["ledger"].startswith(self.root))
        for key in ("name", "label", "id", "workspace", "image", "deadline", "state", "outcome"):
            self.assertIn(key, record)
        self.assertEqual((record["state"], record["id"]), ("hold", result["container_id"]))
        self.assertRegex(record["id"], r"^[0-9a-f]{64}$")

    def test_ledger_dir_must_be_separate_from_workspace_root(self):
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, self.root, FakeDaemon(self.clock), uid=os.getuid() or 1000)
        os.mkdir(os.path.join(self.root, "inner"), 0o700)
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, os.path.join(self.root, "inner"), FakeDaemon(self.clock),
                         uid=os.getuid() or 1000)

    def test_unresolved_prior_record_blocks_new_work_without_any_call(self):
        first, _ = self.run_probe("start_lost")
        self.assertEqual(first["outcome"], "hold")
        second, daemon = self.run_probe()
        self.assertEqual((second["outcome"], second["reason"]), ("hold", "unresolved_prior_request"))
        self.assertEqual(daemon.calls, [])
        with open(os.path.join(self.ledger, "labapp-probe-corrupt.json"), "w") as handle:
            handle.write("{")
        self.assertEqual(len(cr.unresolved_records(self.ledger)), 2)

    def test_ledger_write_failure_before_create_prevents_mutation(self):
        with mock.patch.object(cr.Ledger, "write", side_effect=OSError()):
            result, daemon = self.run_probe()
        self.assertEqual(daemon.calls, [])
        self.assertNotEqual(result["outcome"], "accepted")

    def test_ledger_failure_after_create_is_hold(self):
        real = cr.Ledger.write

        def flaky(self_, state, **more):
            if state == "created":
                self_.failed = True
                raise OSError()
            return real(self_, state, **more)
        with mock.patch.object(cr.Ledger, "write", flaky):
            result, daemon = self.run_probe()
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(result["workspace"], "retained")


class AmbiguityAndHoldTests(RunnerCase):
    def test_lost_create_response_recovers_exact_container_then_holds(self):
        result, daemon = self.run_probe("create_lost")
        self.assertEqual((result["outcome"], result["reason"]), ("hold", "ambiguous_create"))
        self.assertEqual(daemon.containers, {})            # removed via name+label
        self.assertNotIn("start", self.mutations(daemon))
        self.assertEqual(result["workspace"], "retained")

    def test_unparseable_create_id_is_ambiguous(self):
        result, daemon = self.run_probe("create_garbage")
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(daemon.containers, {})

    def test_lost_start_response_holds_after_cleanup(self):
        result, daemon = self.run_probe("start_lost")
        self.assertEqual((result["outcome"], result["reason"]), ("hold", "ambiguous_start"))
        self.assertEqual(daemon.containers, {})

    def test_cancellation_during_start_cleans_up_and_holds(self):
        result, daemon = self.run_probe("start_interrupt")
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(daemon.containers, {})

    def test_daemon_unreachable_is_hold_not_absence(self):
        result, daemon = self.run_probe("query_down")
        self.assertEqual((result["outcome"], result["cleanup"], result["workspace"]), ("hold", "uncertain", "retained"))
        self.assertEqual(len(daemon.containers), 1)

    def test_stale_identity_under_reservation_is_hold_and_nothing_foreign_removed(self):
        result, daemon = self.run_probe("stale")
        self.assertEqual(result["outcome"], "hold")
        self.assertNotIn("c" * 64, [c[0][-1] for c in daemon.calls if c[0][0] == "rm"])

    def test_name_or_label_mismatch_blocks_stop_and_remove(self):
        result, daemon = self.run_probe("name_mismatch")
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual([m for m in self.mutations(daemon) if m in ("stop", "rm")], [])

    def test_remove_ignored_by_daemon_is_hold(self):
        result, _ = self.run_probe("rm_ignored")
        self.assertEqual((result["outcome"], result["cleanup"]), ("hold", "uncertain"))

    def test_lost_remove_or_failed_stop_stays_hold_even_if_queries_find_nothing(self):
        for mode in ("rm_lost", "stop_fail"):
            self.setUp()
            result, daemon = self.run_probe(mode)
            self.assertEqual((result["outcome"], result["cleanup"]), ("hold", "uncertain"), mode)
            self.assertEqual(self.record()["state"], "hold")

    def test_container_vanishing_without_our_remove_is_hold(self):
        result, _ = self.run_probe("vanished")
        self.assertEqual(result["outcome"], "hold")

    def test_daemon_loss_mid_run_never_accepts(self):
        self.assertNotEqual(self.run_probe("poll_down")[0]["outcome"], "accepted")

    def test_current_stop_timeout_flag_avoids_deprecation_stdout(self):
        result, daemon = self.run_probe("deprecated_stop_warning")
        self.assertEqual((result["outcome"], result["cleanup"]), ("accepted", "verified"))
        stop = next(c[0] for c in daemon.calls if c[0][0] == "stop")
        self.assertEqual(stop, ["stop", f"--timeout={cr.STOP_GRACE}", result["container_id"]])
        self.assertEqual(self.record()["state"], "released")

    def test_cleanup_queries_use_full_id_and_name_plus_label(self):
        result, daemon = self.run_probe()
        final = daemon.calls[-2:]
        self.assertTrue(any(f"id={result['container_id']}" in c[0] for c in final))
        self.assertTrue(any("label=" + result["label"] in c[0] and f"name=^/{result['name']}$" in c[0]
                            for c in daemon.calls if c[0][0] == "container"))
        ids = [c[0][-1] for c in daemon.calls if c[0][0] in ("stop", "rm")]
        self.assertTrue(all(i == result["container_id"] for i in ids))


class CancellationTests(RunnerCase):
    def test_sigterm_during_work_cleans_up_and_never_accepts(self):
        def term(args):
            if args[0] == "start":
                os.kill(os.getpid(), signal.SIGTERM)
        daemon = FakeDaemon(self.clock, on_call=term)
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              uid=os.getuid() or 1000, handle_signals=True)
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(result["reason"], "ambiguous_start")
        self.assertEqual(daemon.containers, {})
        self.assertEqual(self.record()["state"], "hold")
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_sigterm_during_cleanup_does_not_abort_cleanup(self):
        def term(args):
            if args[0] == "stop":
                os.kill(os.getpid(), signal.SIGTERM)
        daemon = FakeDaemon(self.clock, on_call=term)
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              uid=os.getuid() or 1000, handle_signals=True)
        self.assertEqual(daemon.containers, {})
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "cancelled"))

    def test_deadline_passing_during_last_slow_call_blocks_acceptance(self):
        def slow(args):
            if args[0] == "rm":
                self.clock.now += 100
        result, _ = self.run_probe(daemon={"on_call": slow})
        self.assertNotEqual(result["outcome"], "accepted")

    def test_finalization_exception_becomes_hold_not_crash_or_acceptance(self):
        real = cr.Ledger.write

        def boom(self_, state, **more):
            if state == "released":
                raise RuntimeError()
            return real(self_, state, **more)
        with mock.patch.object(cr.Ledger, "write", boom):
            result, _ = self.run_probe()
        self.assertEqual((result["outcome"], result["reason"]), ("hold", "finalization_error"))
        self.assertNotEqual(self.record()["state"], "released")      # ownership record survives
        self.setUp()
        with mock.patch.object(cr.shutil, "rmtree", side_effect=RuntimeError()):
            result, _ = self.run_probe()
        self.assertEqual((result["outcome"], result["workspace"]), ("hold", "retained"))


class BoundaryRegressionTests(RunnerCase):
    def test_concurrent_invocation_cannot_pass_admission(self):
        blocked = []
        def nested(args):
            if args[0] == "version":
                blocked.append(self.run_probe()[0])
        result, _ = self.run_probe(daemon={"on_call": nested})
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(blocked[0]["reason"], "admission_lock_unavailable")
        self.assertEqual(len([n for n in os.listdir(self.ledger) if n.endswith(".json")]), 1)

    def test_release_is_after_confirmed_workspace_absence(self):
        real = cr.Ledger.write
        def observe(ledger, state, **more):
            if state == "released":
                self.assertEqual(os.listdir(self.root), [])
                self.assertFalse(os.path.lexists(ledger.data["workspace"]))
            return real(ledger, state, **more)
        with mock.patch.object(cr.Ledger, "write", observe):
            self.assertEqual(self.run_probe()[0]["outcome"], "accepted")
        # A valid complete released record permits the next serial request.
        self.assertEqual(self.run_probe()[0]["outcome"], "accepted")

    def test_failed_or_ineffective_workspace_removal_blocks_reuse(self):
        for effect in (OSError(), None):
            self.setUp()
            with mock.patch.object(cr.shutil, "rmtree", side_effect=effect):
                result, _ = self.run_probe()
            self.assertEqual(result["outcome"], "hold")
            self.assertEqual(self.record()["state"], "hold")
            second, daemon = self.run_probe()
            self.assertEqual(second["outcome"], "hold")
            self.assertEqual(daemon.calls, [])

    def test_cancellation_during_workspace_cleanup_prevents_acceptance(self):
        real = cr.shutil.rmtree
        def remove(path):
            os.kill(os.getpid(), signal.SIGTERM)
            return real(path)
        with mock.patch.object(cr.shutil, "rmtree", remove):
            result, _ = self.run_probe(handle_signals=True)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "cancelled"))

    def test_deadline_crossing_during_publication_revokes_release(self):
        real = cr.Ledger.write
        def publish(ledger, state, **more):
            real(ledger, state, **more)
            if state == "released":
                self.clock.now += 100
        with mock.patch.object(cr.Ledger, "write", publish):
            result, _ = self.run_probe()
        self.assertEqual((result["outcome"], self.record()["state"]), ("hold", "hold"))

    def test_failed_release_publication_is_replaced_with_hold(self):
        real = cr.Ledger.write
        def publish(ledger, state, **more):
            real(ledger, state, **more)
            if state == "released":
                raise OSError("directory fsync failure after rename")
        with mock.patch.object(cr.Ledger, "write", publish):
            result, _ = self.run_probe()
        self.assertEqual((result["outcome"], self.record()["state"]), ("hold", "hold"))

    def test_symlinked_lock_is_hold_without_daemon_contact(self):
        os.symlink("/dev/null", os.path.join(self.ledger, "admission.lock"))
        result, daemon = self.run_probe()
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(daemon.calls, [])

    def test_corrupt_oversized_symlink_and_fifo_records_hold(self):
        for kind in ("corrupt", "oversized", "symlink", "fifo", "incomplete"):
            self.setUp()
            path = os.path.join(self.ledger, "labapp-probe-bad.json")
            if kind == "symlink":
                os.symlink("/dev/zero", path)
            elif kind == "fifo":
                os.mkfifo(path)
            else:
                with open(path, "w") as handle:
                    handle.write({"corrupt": "{", "oversized": "x" * 5000,
                                  "incomplete": '{"state":"released"}'}.get(kind, ""))
            result, daemon = self.run_probe()
            self.assertEqual(result["outcome"], "hold", kind)
            self.assertEqual(daemon.calls, [], kind)

    def test_ledger_entry_count_is_bounded(self):
        for n in range(129):
            with open(os.path.join(self.ledger, f"labapp-probe-{n}.json"), "w") as handle:
                json.dump({"state": "hold"}, handle)
        self.assertEqual(cr.unresolved_records(self.ledger), ["ledger_entry_limit"])
        self.assertEqual(self.run_probe()[0]["outcome"], "hold")

    def test_host_clock_uses_boottime_and_rejects_shifted_namespace(self):
        with mock.patch.object(cr.time, "clock_gettime", return_value=123.5) as clock:
            self.assertEqual(cr.boot_clock(), 123.5)
            clock.assert_called_once_with(time.CLOCK_BOOTTIME)
        boot = "12345678-1234-1234-1234-123456789abc"
        with mock.patch.object(cr, "read_proc", side_effect=[boot, "monotonic 0 0\nboottime 1 0"]):
            with self.assertRaises(ValueError):
                cr.host_boot_id()

    def test_probe_child_installs_handler_and_witnesses_own_pid(self):
        self.assertNotIn("$!", cr.PROBE_SCRIPT)
        self.assertIn('setsid /bin/bash -c', cr.PROBE_SCRIPT)
        self.assertIn('trap "" TERM; echo "probe $$"', cr.PROBE_SCRIPT)
        syntax = subprocess.run(["/bin/bash", "-n"], input=cr.PROBE_SCRIPT, text=True,
                                capture_output=True, timeout=3)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)


class RealBackendTests(unittest.TestCase):
    """The real client against owned fake executables standing in for docker."""

    def fake(self, directory, body):
        path = os.path.join(directory, "docker")
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\n" + body + "\n")
        os.chmod(path, 0o755 | stat.S_IXUSR)
        return cr.Backend(path, "unix:///tmp/none.sock", directory)

    def test_success_failure_and_timeout_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.fake(directory, "echo ok").call(["x"], 5), "ok")
            with self.assertRaises(cr.DockerError):
                self.fake(directory, "exit 3").call(["x"], 5)
            with self.assertRaises(cr.DockerTimeout):
                self.fake(directory, "exec sleep 30").call(["x"], 0.3)
            with self.assertRaises(cr.DockerError):
                cr.Backend(os.path.join(directory, "missing")).call(["x"], 1)

    def test_explicit_endpoint_config_and_minimal_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.fake(directory, 'echo "$@"; env | sort | tr "\\n" " "')
            os.environ["DOCKER_HOST"] = "tcp://elsewhere:1"
            os.environ["DOCKER_CONFIG"] = "/home/someone/.docker"
            self.addCleanup(os.environ.pop, "DOCKER_HOST")
            self.addCleanup(os.environ.pop, "DOCKER_CONFIG")
            out = backend.call(["ps"], 5)
            self.assertIn(f"--host unix:///tmp/none.sock --config {directory} ps", out)
            self.assertNotIn("tcp://elsewhere", out)
            self.assertNotIn("/home/someone", out)

    def test_output_flood_is_rejected_quickly_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.fake(directory, "yes aaaaaaaaaaaaaaaa")      # endless stdout
            start = time.monotonic()
            with self.assertRaises(cr.DockerError):
                backend.call(["x"], 10)
            self.assertLess(time.monotonic() - start, 5)
            backend = self.fake(directory, "head -c 70000 /dev/zero | tr '\\0' a")   # just over the cap
            with self.assertRaises(cr.DockerError):
                backend.call(["x"], 10)
            backend = self.fake(directory, "head -c 60000 /dev/zero | tr '\\0' a")   # under the cap
            self.assertEqual(len(backend.call(["x"], 10)), 60000)

    def test_slow_trickle_and_stuck_children_hit_the_deadline_and_are_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.fake(directory, "while :; do echo a; sleep 0.1; done")
            start = time.monotonic()
            with self.assertRaises(cr.DockerTimeout):
                backend.call(["x"], 0.5)
            self.assertLess(time.monotonic() - start, 3)
            marker = os.path.join(directory, "child")
            backend = self.fake(directory, f"(sleep 30; touch {marker}) & echo started; wait")
            with self.assertRaises(cr.DockerTimeout):
                backend.call(["x"], 0.4)
            time.sleep(0.2)
            self.assertFalse(os.path.exists(marker))

    def test_group_cleanup_precedes_leader_reap(self):
        real_waitid, real_killpg = os.waitid, os.killpg
        real_wait = subprocess.Popen.wait
        events = []
        def observe(kind, pid, options):
            self.assertEqual(options, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            events.append("observe")
            return real_waitid(kind, pid, options)
        def kill_group(pid, sig):
            # Even after the leader exited, it must still be our waitable child.
            status = real_waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNotNone(status)
            self.assertEqual(status.si_status, 0)
            events.append("kill_group")
            return real_killpg(pid, sig)
        def reap(proc, timeout=None):
            self.assertIn("kill_group", events)
            events.append("reap")
            return real_wait(proc, timeout=timeout)
        with tempfile.TemporaryDirectory() as directory:
            # stdout closes while the leader is still alive: EOF is not exit.
            backend = self.fake(directory, "exec 1>&-; sleep 0.1; exit 0")
            with mock.patch.object(cr.os, "waitid", observe), \
                    mock.patch.object(cr.os, "killpg", kill_group), \
                    mock.patch.object(cr.subprocess.Popen, "wait", reap), \
                    mock.patch.object(cr.subprocess.Popen, "poll", side_effect=AssertionError("early reap")):
                self.assertEqual(backend.call(["x"], 3), "")
        self.assertGreater(events.count("observe"), 1)
        self.assertLess(events.index("kill_group"), events.index("reap"))

    def test_exited_parent_pipe_holder_is_killed_on_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "escaped")
            backend = self.fake(directory, f"(sleep 0.8; touch {marker}) & exit 0")
            start = time.monotonic()
            with self.assertRaises(cr.DockerTimeout):
                backend.call(["x"], 0.15)
            self.assertLess(time.monotonic() - start, 1)
            time.sleep(1)
            self.assertFalse(os.path.exists(marker))

    def test_invalid_utf8_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(cr.DockerError):
                self.fake(directory, "printf '\\377\\376'").call(["x"], 5)


class CliTests(unittest.TestCase):
    def test_default_prints_plan_without_contacting_docker(self):
        with mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.run", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cr.main(["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y"])
        self.assertEqual(code, 0)
        plan = json.loads(out.getvalue())
        self.assertFalse(plan["executed"])
        self.assertEqual(plan["image"], cr.PINNED_IMAGE)

    def test_there_is_no_image_option_and_bad_endpoint_is_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cr.main(["--image", "ubuntu:latest", "--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y",
                                      "--docker-host", "tcp://evil:1"]), 2)


class HclDaemon(FakeDaemon):
    """Synthetic daemon for hcl-check: the 'container' writes the fixed result files."""

    GOOD_STEPS = "version 0\nsyntax 0\nfull 0\n"

    def __init__(self, clock, steps=GOOD_STEPS, version="Packer v1.16.2\n", exit_code=0, tamper=False, **kw):
        super().__init__(clock, "ok", exit_code=exit_code, **kw)
        self.steps, self.version, self.tamper = steps, version, tamper

    def start(self, c):
        out = next(a for a in c["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
        files = {"steps": self.steps, "version.out": self.version, "version.err": "",
                 "syntax.out": "", "syntax.err": "", "full.out": "The configuration is valid.\n",
                 "full.err": ""}
        for name, text in files.items():
            if text is not None:
                with open(os.path.join(out, name), "w") as handle:
                    handle.write(text)
        if self.tamper:
            packer = os.path.join(os.path.dirname(out), "in", "tools", "packer")
            os.chmod(packer, 0o600)
            with open(packer, "ab") as handle:
                handle.write(b"x")
        c["state"], c["exit_at"], c["code"] = "running", self.clock.now + 1.0, self.exit_code


class HclCheckTests(RunnerCase):
    def setUp(self):
        super().setUp()
        src = os.path.join(os.path.dirname(self.root), "src")
        os.mkdir(src, 0o700)
        self.sources, pins = ts.make_inputs(src)
        patcher = mock.patch.object(cr.stage_tools, "PINS", pins)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_hcl(self, daemon=None, sources=None, **kw):
        daemon = daemon or HclDaemon(self.clock)
        result = cr.run_probe(IMAGE, self.root, self.ledger, daemon, clock=self.clock, sleep=self.clock.sleep,
                              admitted_at=self.clock(), uid=os.getuid() or 1000, mode="hcl-check",
                              sources=self.sources if sources is None else sources, **kw)
        return result, daemon

    def create_call(self, daemon):
        return next(c[0] for c in daemon.calls if c[0][0] == "create")

    def test_profile_and_fixed_task_arguments(self):
        self.assertEqual(cr.PROFILES["hcl-check"], (120, 30))
        self.assertEqual(cr.PROFILES["probe"], (30, 20))
        result, daemon = self.run_hcl()
        args = self.create_call(daemon)
        for expected in ("--pull=never", "--network=none", "--cap-drop=ALL", "--read-only",
                         "--security-opt=no-new-privileges", "--memory=1g", "--memory-swap=1g",
                         "--cpus=1", "--pids-limit=128", "--log-driver=none", "--no-healthcheck"):
            self.assertIn(expected, args)
        for forbidden in ("--privileged", "--init", "--pid", "--ipc", "--uts", "--userns", "--device", "--volume",
                          "-v", "--env", "-e", "--cap-add", "--group-add", "--tmpfs", "--add-host"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertNotIn("docker.sock", " ".join(args))
        mounts = [a for a in args if a.startswith("--mount=")]
        self.assertEqual(len(mounts), 3)
        writable = [m for m in mounts if not m.endswith(",readonly")]
        self.assertEqual(len(writable), 1)
        self.assertTrue(writable[0].endswith("/out,dst=/out"))
        self.assertTrue(any(m.endswith(",dst=/in,readonly") for m in mounts))
        self.assertFalse(any(self.sources[key] in m for key in self.sources for m in mounts))
        self.assertFalse(any("dst=/in/base.img" in m for m in mounts))
        self.assertTrue(any(m.endswith("/cd,dst=/out/work/cd,readonly") for m in mounts))
        self.assertEqual(args[-1], cr.HCL_SCRIPT)

    def test_fixed_script_runs_only_the_three_reviewed_commands(self):
        script = cr.HCL_SCRIPT
        self.assertEqual(script.count("/in/tools/packer "), 3)
        for word in ("init", "build", "install", "plugins", "get", "fix", "console", "curl", "wget",
                     "evaluate-datasources", "inspect"):
            self.assertNotIn(f"packer {word}", script)
        self.assertIn("validate -syntax-only /in/labapp.pkr.hcl", script)
        self.assertIn("validate -var-file=/in/validate.pkrvars.hcl /in/labapp.pkr.hcl", script)
        self.assertIn("env -i HOME=/out/home TMPDIR=/out/tmp", script)
        self.assertIn("PACKER_PLUGIN_PATH=/in/plugins", script)
        self.assertIn("CHECKPOINT_DISABLE=1", script)
        self.assertIn("ulimit -f", script)

    def test_probe_arguments_are_unchanged_by_the_new_mode(self):
        args = cr.create_args("n", "l", IMAGE_ID, "1:1", "/w", 5, "b")
        self.assertEqual(args[-1], cr.PROBE_SCRIPT)
        self.assertIn("--memory=256m", args)
        self.assertIn("--pids-limit=64", args)
        self.assertEqual([a for a in args if a.startswith("--mount=")], ["--mount=type=bind,src=/w,dst=/out"])

    def test_accepted_run_records_identities_and_cleans_up(self):
        result, daemon = self.run_hcl()
        self.assertEqual((result["outcome"], result["reason"]), ("accepted", None))
        self.assertEqual(result["cleanup"], "verified")
        self.assertEqual(result["workspace"], "removed")
        evidence = result["evidence"]
        self.assertEqual(evidence["image_id"], IMAGE_ID)
        for key in ("inputs", "vars_sha256", "hcl_sha256", "base_sha256", "core_member_sha256",
                    "plugin_member_sha256", "core_archive_sha256", "plugin_archive_sha256"):
            self.assertRegex(evidence[key], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["steps"]["bytes"], len(HclDaemon.GOOD_STEPS))
        self.assertEqual(len(evidence["commands"]), 3)
        self.assertEqual(self.record()["state"], "released")
        self.assertEqual(self.record()["mode"], "hcl-check")
        self.assertFalse(os.path.lexists(result.get("workspace_path", "/nonexistent")))

    def test_any_nonzero_step_is_failed_never_tool_success(self):
        for steps in ("version 0\nsyntax 0\nfull 1\n", "version 0\nsyntax 1\nfull 0\n",
                      "version 1\nsyntax 0\nfull 0\n", "version 0\nsyntax 0\n", None, "version 0\nsyntax 0\nfull 0\nextra 0\n"):
            with self.subTest(steps=steps):
                self.setUp()
                result, daemon = self.run_hcl(HclDaemon(self.clock, steps=steps))
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["reason"], "invalid_step_evidence" if steps is None else "tool_check_failed")
                self.assertEqual(result["cleanup"], "verified")

    def test_wrong_core_version_is_failed(self):
        for version in ("Packer v1.15.4\n", "Packer v1.16.2-dev\n", "Packer v1.16.2\nmore\n", None):
            with self.subTest(version=version):
                self.setUp()
                result, _ = self.run_hcl(HclDaemon(self.clock, version=version))
                reason = "invalid_step_evidence" if version is None else "wrong_core_version"
                self.assertEqual((result["outcome"], result["reason"]), ("failed", reason))

    def test_nonzero_container_exit_and_timer_codes_are_failed(self):
        for code in (1, 124, 137):
            with self.subTest(code=code):
                self.setUp()
                result, _ = self.run_hcl(HclDaemon(self.clock, exit_code=code))
                self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))

    def test_oversized_output_is_not_trusted(self):
        class Flood(HclDaemon):
            def start(self, c):
                super().start(c)
                out = next(a for a in c["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                with open(os.path.join(out, "steps"), "w") as handle:
                    handle.write("x" * (cr.STEP_CAP + 1))
        result, _ = self.run_hcl(Flood(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_step_evidence"))

    def test_symlinked_result_file_is_not_followed(self):
        class Link(HclDaemon):
            def start(self, c):
                super().start(c)
                out = next(a for a in c["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                os.unlink(os.path.join(out, "steps"))
                os.symlink("/etc/hostname", os.path.join(out, "steps"))
        result, _ = self.run_hcl(Link(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_step_evidence"))

    def test_every_step_evidence_file_is_required_bounded_regular_and_no_follow(self):
        for name in ("steps", "version.out", "version.err", "syntax.out", "syntax.err", "full.out", "full.err"):
            for fault in ("missing", "directory", "fifo", "oversize", "symlink"):
                with self.subTest(name=name, fault=fault):
                    self.setUp()
                    class BadEvidence(HclDaemon):
                        def start(inner, c):
                            super().start(c)
                            out = next(a for a in c["args"] if a.endswith(",dst=/out")).split("src=")[1].split(",")[0]
                            path = os.path.join(out, name)
                            os.unlink(path)
                            if fault == "directory":
                                os.mkdir(path)
                            elif fault == "fifo":
                                os.mkfifo(path)
                            elif fault == "oversize":
                                with open(path, "wb") as handle:
                                    handle.truncate(cr.STEP_CAP + 1)
                            elif fault == "symlink":
                                target = os.path.join(out, "synthetic-target")
                                with open(target, "w") as handle:
                                    handle.write("synthetic output")
                                os.symlink(target, path)
                    result, _ = self.run_hcl(BadEvidence(self.clock))
                    self.assertEqual((result["outcome"], result["reason"]), ("failed", "invalid_step_evidence"))
                    self.assertEqual(result["evidence"]["invalid_files"], [name])
                    self.assertEqual(result["cleanup"], "verified")

    def test_source_edit_before_create_does_not_change_bound_snapshot(self):
        source = self.sources["base"]
        class SourceEdit(HclDaemon):
            def start(inner, c):
                inp = next(a for a in c["args"] if a.endswith(",dst=/in,readonly")).split("src=")[1].split(",")[0]
                with open(os.path.join(inp, "base.img"), "rb") as handle:
                    self.assertEqual(handle.read(), ts.BASE_BYTES)
                super().start(c)
        def edit(args):
            if args[0] == "create":
                with open(source, "wb") as handle:
                    handle.write(b"external path substituted")
        result, _ = self.run_hcl(SourceEdit(self.clock, on_call=edit))
        self.assertEqual(result["outcome"], "accepted")

    def test_snapshot_mutated_during_run_is_rejected(self):
        class Mutation(HclDaemon):
            def start(inner, c):
                super().start(c)
                inp = next(a for a in c["args"] if a.endswith(",dst=/in,readonly")).split("src=")[1].split(",")[0]
                path = os.path.join(inp, "base.img")
                os.chmod(path, 0o600)
                with open(path, "r+b") as handle:
                    handle.write(b"X")
        result, _ = self.run_hcl(Mutation(self.clock))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "staged_inputs_changed"))
        self.assertEqual(result["cleanup"], "verified")

    def test_snapshot_rehash_expiry_uses_original_admission_deadline(self):
        original = cr.stage_tools.hash_file
        calls = []
        def slow_hash(path, size=None, check=cr.stage_tools._noop):
            if path.endswith("/base.img"):
                def spend():
                    calls.append(1)
                    if len(calls) == 2:
                        self.clock.now += 121
                    check()
                return original(path, size, spend)
            return original(path, size, check)
        with mock.patch.object(cr.stage_tools, "CHUNK", 32), mock.patch.object(cr.stage_tools, "hash_file", slow_hash):
            result, daemon = self.run_hcl()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertEqual(result["cleanup"], "verified")
        self.assertEqual(result["workspace"], "removed")
        self.assertEqual(self.record()["state"], "released")
        self.assertEqual(len(calls), 2)

    def test_mid_copy_expiry_uses_original_admission_deadline(self):
        original = cr.stage_tools.copy_hash
        calls = []
        def slow_copy(path, dest, size, check):
            def spend():
                calls.append(1)
                if len(calls) == 2:
                    self.clock.now += 121
                check()
            return original(path, dest, size, spend)
        with mock.patch.object(cr.stage_tools, "CHUNK", 32), mock.patch.object(cr.stage_tools, "copy_hash", slow_copy):
            result, daemon = self.run_hcl()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(result["workspace"], "removed")
        self.assertEqual(len(calls), 2)

    def test_staged_bytes_changed_during_run_are_not_accepted(self):
        result, _ = self.run_hcl(HclDaemon(self.clock, tamper=True))
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "staged_inputs_changed"))
        self.assertEqual(result["cleanup"], "verified")

    def test_rejected_input_fails_before_any_daemon_call(self):
        with open(self.sources["core"], "ab") as handle:
            handle.write(b"x")
        result, daemon = self.run_hcl()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "staging_rejected"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(result["workspace"], "removed")

    def test_staging_spends_the_admission_budget(self):
        real = cr.stage_tools.stage

        def slow(ws, sources, nonce, check, pins):
            staged = real(ws, sources, nonce, check, pins=pins)
            self.clock.now += 200
            check()
            return staged
        with mock.patch.object(cr.stage_tools, "stage", slow):
            result, daemon = self.run_hcl()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertEqual(self.mutations(daemon), [])

    def test_sources_are_required_and_exact(self):
        for sources in (None, {}, {"core": "/a", "plugin": "/b"}, dict(self.sources, extra="/x")):
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                cr.run_probe(IMAGE, self.root, self.ledger, HclDaemon(self.clock), clock=self.clock,
                             uid=os.getuid() or 1000, mode="hcl-check", sources=sources)

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, self.ledger, HclDaemon(self.clock), clock=self.clock,
                         uid=os.getuid() or 1000, mode="build")

    def test_cli_plan_for_hcl_check_does_not_touch_docker_or_files(self):
        argv = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "hcl-check",
                "--core-file", "/nonexistent/c.zip", "--plugin-file", "/nonexistent/p.zip",
                "--base-file", "/nonexistent/b.img"]
        with mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.Popen", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cr.main(argv), 0)
        plan = json.loads(out.getvalue())
        self.assertEqual((plan["mode"], plan["executed"]), ("hcl-check", False))
        self.assertIn("--memory=1g", plan["create"])

    def test_cli_requires_all_input_files_only_for_hcl_check(self):
        base = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(base + ["--mode", "hcl-check"]), 2)
            self.assertEqual(cr.main(base + ["--mode", "hcl-check", "--core-file", "/a"]), 2)
            self.assertEqual(cr.main(base + ["--core-file", "/a"]), 2)
            with self.assertRaises(SystemExit):
                cr.main(base + ["--mode", "build"])


class RuntimeDaemon(FakeDaemon):
    """Data-only stand-in for the fixed tools, not an image execution."""
    def __init__(self, clock, fault=None, **kwargs):
        super().__init__(clock, exit_code=0, **kwargs)
        self.fault = fault

    def image_info(self):
        info = {"Id": cr.PREPARED_RUNTIME["image_id"],
                "RootFS": {"Layers": list(cr.PREPARED_RUNTIME["diffids"])}, "Config": {}}
        if self.fault == "image_id":
            info["Id"] = IMAGE_ID
        if self.fault == "layers":
            info["RootFS"]["Layers"].reverse()
        if self.fault in ("Volumes", "OnBuild"):
            info["Config"][self.fault] = ["unexpected"]
        return json.dumps(info)

    def start(self, c):
        ws = workspace_of(c["args"])
        source = os.path.join(ws, "source", cr.RUNTIME_PATH)
        os.makedirs(os.path.dirname(source))
        with open(source, "wb") as handle:
            handle.write(cr.RUNTIME_BYTES)
        iso = bytearray(40 * 2048)
        iso[32768:32775] = b'\x01CD001\x01'
        iso[32808:32840] = b'cidata'.ljust(32)
        report = {"schema": 1, "versions": cr.RUNTIME_VERSIONS, "firmware": list(cr.RUNTIME_FIRMWARE),
                  "input_sha256": hashlib.sha256(cr.RUNTIME_BYTES).hexdigest(),
                  "iso_sha256": hashlib.sha256(iso).hexdigest(), "iso_bytes": len(iso),
                  "readback_sha256": hashlib.sha256(cr.RUNTIME_BYTES).hexdigest(), "volume": "cidata"}
        if self.fault == "version":
            report["versions"] = dict(report["versions"], qemu="QEMU emulator version 9.0.0")
        if self.fault == "boolean":
            report["schema"] = True
        if self.fault == "firmware":
            report["firmware"] = []
        if self.fault == "extra":
            report["extra"] = "ignored?"
        if self.fault == "volume":
            iso[32808] = 0
            report["iso_sha256"] = hashlib.sha256(iso).hexdigest()
        files = {"runtime.json": json.dumps(report).encode(), "check.iso": iso,
                 "readback": cr.RUNTIME_BYTES}
        files.update({name + ".log": b"synthetic tool log\n" for name in
                      ("qemu", "qemu_img", "python", "xorriso", "create", "extract", "runtime")})
        if self.fault == "duplicate":
            files["runtime.json"] = files["runtime.json"][:-1] + b', "schema": 1}'
        if self.fault == "oversize":
            files["runtime.json"] = b" " * (cr.RESULT_CAP + 1)
        if self.fault == "log_cap":
            files["create.log"] = b"x" * 16385
        if self.fault == "readback":
            files["readback"] = b"bad"
        if self.fault == "iso_hash":
            files["check.iso"][-1] = 1
        if self.fault == "missing":
            del files["runtime.json"]
        for name, raw in files.items():
            with open(os.path.join(ws, name), "wb") as handle:
                handle.write(raw)
        if self.fault == "symlink":
            os.unlink(os.path.join(ws, "runtime.json"))
            os.symlink("readback", os.path.join(ws, "runtime.json"))
        c["state"], c["exit_at"], c["code"] = "running", self.clock.now + 1, self.exit_code
        if self.mode == "never_exits":
            c["exit_at"] = float("inf")
        if self.fault == "exit":
            c["code"] = 1


class RuntimeCheckTests(RunnerCase):
    def run_runtime(self, fault=None, **kwargs):
        daemon = RuntimeDaemon(self.clock, fault, **kwargs.pop("daemon", {}))
        result = cr.run_probe(cr.PREPARED_RUNTIME["image_id"], self.root, self.ledger, daemon,
                              clock=self.clock, sleep=self.clock.sleep, uid=os.getuid() or 1000,
                              mode="runtime-check", **kwargs)
        return result, daemon

    def test_fixed_non_vm_args_identity_and_no_staging(self):
        with mock.patch.object(cr.stage_tools, "stage", side_effect=AssertionError), \
                mock.patch.object(cr, "kvm_preflight", side_effect=AssertionError):
            result, daemon = self.run_runtime()
        self.assertEqual(result["outcome"], "accepted", result)
        self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))
        self.assertIsNone(cr.SENTINEL_RUNTIME)
        args = next(a for a, _ in daemon.calls if a[0] == "create")
        for flag in ("--pull=never", "--network=none", "--cap-drop=ALL", "--read-only",
                     "--security-opt=no-new-privileges", "--memory=256m", "--cpus=1", "--pids-limit=64"):
            self.assertIn(flag, args)
        self.assertEqual(len([a for a in args if a.startswith("--mount=")]), 1)
        self.assertIn(cr.PREPARED_RUNTIME["image_id"], args)
        self.assertEqual(args[-1], cr.RUNTIME_SCRIPT)
        self.assertTrue(cr.RUNTIME_SCRIPT.endswith(" > /out/runtime.log 2>&1 < /dev/null"))
        self.assertFalse(any(a.startswith(("--device", "--group-add", "--env", "--privileged")) for a in args))
        self.assertEqual(self.record()["image"], cr.PREPARED_RUNTIME["image_id"])
        self.assertTrue(cr.released_record(self.record()))
        self.assertEqual(cr.PROFILES["runtime-check"], (90, 30))
        self.assertEqual(result["evidence"]["runtime_diffids"], cr.PREPARED_RUNTIME["diffids"])

    def test_preflight_rejects_image_and_config_mismatch_before_create(self):
        for fault in ("image_id", "layers", "Volumes", "OnBuild"):
            with self.subTest(fault=fault):
                result, daemon = self.run_runtime(fault)
                self.assertEqual(result["outcome"], "failed", result)
                self.assertFalse(self.mutations(daemon))

    def test_untrusted_report_or_iso_never_accepts_and_still_cleans(self):
        for fault in ("version", "boolean", "firmware", "extra", "duplicate", "oversize", "log_cap",
                      "readback", "iso_hash", "missing", "symlink", "volume", "exit"):
            with self.subTest(fault=fault):
                result, daemon = self.run_runtime(fault)
                self.assertEqual(result["outcome"], "failed", result)
                self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))

    def test_cleanup_ambiguity_cancellation_and_expiry_override_success(self):
        for mode in ("rm_lost", "name_mismatch", "never_exits", "start_interrupt"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as ledger:
                os.chmod(ledger, 0o700)
                old = self.ledger
                self.ledger = ledger
                try:
                    result, daemon = self.run_runtime(daemon={"mode": mode})
                finally:
                    self.ledger = old
                self.assertNotEqual(result["outcome"], "accepted", result)
                if mode in ("rm_lost", "name_mismatch"):
                    self.assertEqual(result["outcome"], "hold")
        result, daemon = self.run_runtime(admitted_at=self.clock() - 90)
        self.assertNotEqual(result["outcome"], "accepted")
        self.assertFalse(self.mutations(daemon))

    def test_failed_tool_diagnostics_survive_verified_cleanup(self):
        class FailedXorriso(RuntimeDaemon):
            def start(inner, c):
                super().start(c)
                ws = workspace_of(c["args"])
                os.unlink(os.path.join(ws, "runtime.json"))
                os.unlink(os.path.join(ws, "extract.log"))
                for name, raw in (("create.log", b'xorriso: FAILURE: invalid input\n\x1b[31m' + b'x' * 4096),
                                  ("runtime.log", b'Traceback: CalledProcessError: xorriso exited 1\n')):
                    with open(os.path.join(ws, name), "wb") as handle:
                        handle.write(raw)
                c["code"] = 1
        daemon = FailedXorriso(self.clock)
        result = cr.run_probe(cr.PREPARED_RUNTIME["image_id"], self.root, self.ledger, daemon,
                              clock=self.clock, sleep=self.clock.sleep, uid=os.getuid() or 1000,
                              mode="runtime-check")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))
        self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))
        self.assertFalse(os.path.exists(workspace_of(next(args for args, _ in daemon.calls if args[0] == "create"))))
        evidence = result["evidence"]
        self.assertEqual(evidence["exit_code"], 1)
        self.assertEqual(evidence["image_id"], cr.PREPARED_RUNTIME["image_id"])
        self.assertEqual(evidence["runtime_diffids"], cr.PREPARED_RUNTIME["diffids"])
        self.assertIn("elapsed", evidence)
        self.assertEqual(evidence["invalid_files"], ["extract.log"])
        self.assertIn("CalledProcessError", evidence["logs"]["runtime"]["excerpt"])
        self.assertIn("xorriso: FAILURE", evidence["logs"]["create"]["excerpt"])
        self.assertEqual(len(evidence["logs"]["create"]["excerpt"]), cr.EXCERPT)
        self.assertGreater(evidence["logs"]["create"]["bytes"], cr.EXCERPT)
        self.assertNotIn('\x1b', json.dumps(result))
        self.assertIn('\\u001b', json.dumps(result))

    def test_failure_evidence_survives_oom_and_uncertain_cleanup(self):
        for mode, outcome in (("oom", "failed"), ("rm_lost", "hold")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as ledger:
                os.chmod(ledger, 0o700)
                daemon = RuntimeDaemon(self.clock, fault="exit", mode=mode)
                result = cr.run_probe(cr.PREPARED_RUNTIME["image_id"], self.root, ledger, daemon,
                                      clock=self.clock, sleep=self.clock.sleep, uid=os.getuid() or 1000,
                                      mode="runtime-check")
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(result["evidence"]["exit_code"], 1)
                self.assertEqual(result["evidence"]["oom_killed"], mode == "oom")
                self.assertIn("runtime", result["evidence"]["logs"])

    def test_failed_diagnostic_files_are_bounded_regular_and_no_follow(self):
        for name in ("qemu", "qemu_img", "python", "xorriso", "create", "extract", "runtime"):
            for fault in ("missing", "symlink", "oversize", "directory", "fifo"):
                with self.subTest(name=name, fault=fault):
                    class BadDiagnostic(RuntimeDaemon):
                        def start(inner, c):
                            super().start(c)
                            path = os.path.join(workspace_of(c["args"]), name + ".log")
                            os.unlink(path)
                            if fault == "symlink":
                                os.symlink("/etc/hostname", path)
                            elif fault == "oversize":
                                with open(path, "wb") as handle:
                                    handle.truncate(16385)
                            elif fault == "directory":
                                os.mkdir(path)
                            elif fault == "fifo":
                                os.mkfifo(path)
                            c["code"] = 1
                    daemon = BadDiagnostic(self.clock)
                    result = cr.run_probe(cr.PREPARED_RUNTIME["image_id"], self.root, self.ledger, daemon,
                                          clock=self.clock, sleep=self.clock.sleep, uid=os.getuid() or 1000,
                                          mode="runtime-check")
                    self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))
                    self.assertEqual(result["evidence"]["invalid_files"], [name + ".log"])
                    self.assertNotIn(name, result["evidence"]["logs"])
                    self.assertEqual((result["cleanup"], result["workspace"]), ("verified", "removed"))

    def test_cli_no_input_or_image_override_and_plan_is_offline(self):
        base = ["--workspace-root", "/tmp/x", "--ledger-dir", "/tmp/y", "--mode", "runtime-check"]
        with mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cr.main(base), 0)
        self.assertEqual(json.loads(out.getvalue())["image"], cr.PREPARED_RUNTIME["image_id"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(base + ["--core-file", "/anything"]), 2)
            with self.assertRaises(SystemExit):
                cr.main(base + ["--image", IMAGE_ID])
        with self.assertRaises(ValueError):
            self.run_runtime(sources={"core": "/anything"})
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, self.ledger, RuntimeDaemon(self.clock),
                         mode="runtime-check", uid=os.getuid() or 1000)


class RuntimeProgramTests(unittest.TestCase):
    """Execute only the Python assertion logic with fake tools/firmware and inert files.
    This catches command/argument, failed tool and readback errors without any image."""
    def test_plugin_recipe_and_each_assertion_failure(self):
        from pathlib import Path
        for fault in (None, "version", "create", "readback", "firmware", "volume"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                calls = []
                old_cwd = os.getcwd()
                old_umask = os.umask(0o077)
                os.umask(old_umask)
                self.addCleanup(os.chdir, old_cwd)
                real_is_file, real_access, real_stat = Path.is_file, os.access, os.stat
                def is_file(path):
                    if str(path) in cr.RUNTIME_FIRMWARE:
                        return fault != "firmware"
                    return real_is_file(path)
                def access(path, mode):
                    return True if path in cr.RUNTIME_FIRMWARE else real_access(path, mode)
                def info(path, *args, **kwargs):
                    if path in cr.RUNTIME_FIRMWARE:
                        return type('Info', (), {'st_size': 1024})()
                    return real_stat(path, *args, **kwargs)
                def tool(argv, **kwargs):
                    calls.append(argv)
                    self.assertEqual(kwargs["env"], {'PATH': '/usr/bin:/bin', 'HOME': '/out',
                                                     'TMPDIR': '/out', 'LC_ALL': 'C'})
                    if argv[1] in ("--version", "-version"):
                        key = {"qemu-system-x86_64": "qemu", "qemu-img": "qemu_img",
                               "python3": "python", "xorriso": "xorriso"}[os.path.basename(argv[0])]
                        kwargs["stdout"].write((('wrong' if fault == 'version' else cr.RUNTIME_VERSIONS[key]) + '\n').encode())
                    elif argv[1] == "-as":
                        self.assertEqual(argv, ['/usr/bin/xorriso', '-as', 'genisoimage', '-rock', '-joliet',
                                                '-volid', 'cidata', '-output', '/out/check.iso', '/out/source'])
                        if fault == "create":
                            kwargs["stdout"].write(b'xorriso: FAILURE: synthetic tool error\n')
                            raise subprocess.CalledProcessError(1, argv)
                        iso = bytearray(40 * 2048)
                        iso[32768:32775] = b'\x01CD001\x01'
                        iso[32808:32840] = (b'bad' if fault == 'volume' else b'cidata').ljust(32)
                        Path('check.iso').write_bytes(iso)
                    else:
                        self.assertEqual(argv, ['/usr/bin/xorriso', '-abort_on', 'FAILURE', '-osirrox', 'on',
                                                '-indev', '/out/check.iso', '-extract', '/' + cr.RUNTIME_PATH,
                                                '/out/readback'])
                        Path('readback').write_bytes(b'bad' if fault == 'readback' else cr.RUNTIME_BYTES)
                # The embedded program is fixed; only its private /out cwd and immutable
                # firmware metadata are substituted. No subprocess ever starts.
                real_chdir = os.chdir
                os.chdir(tmp)
                try:
                    with mock.patch('os.chdir', side_effect=lambda path: None if path == '/out' else real_chdir(path)), \
                            mock.patch('subprocess.run', side_effect=tool), mock.patch.object(Path, 'is_file', is_file), \
                            mock.patch('os.access', side_effect=access), mock.patch('os.stat', side_effect=info):
                        if fault:
                            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                                exec(compile(cr.RUNTIME_PROGRAM, '<fixed runtime assertions>', 'exec'), {})
                            self.assertFalse(Path('runtime.json').exists())
                            if fault == 'create':
                                self.assertIn(b'xorriso: FAILURE', Path('create.log').read_bytes())
                        else:
                            exec(compile(cr.RUNTIME_PROGRAM, '<fixed runtime assertions>', 'exec'), {})
                            self.assertEqual(json.loads(Path('runtime.json').read_text())['volume'], 'cidata')
                            self.assertEqual(len(calls), 6)
                finally:
                    os.chdir(old_cwd)
                    os.umask(old_umask)


if __name__ == "__main__":
    unittest.main()
