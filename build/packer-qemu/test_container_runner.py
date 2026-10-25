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


if __name__ == "__main__":
    unittest.main()
