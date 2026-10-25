"""Offline tests with a synthetic Docker daemon and a fake docker executable.

No Docker, container, systemd or VM is used. They prove the supervisor's call
sequence, bounds and fail-closed decisions, not Docker or kernel behavior.
"""
import hashlib
import os
import stat
import tempfile
import unittest

import container_runner as cr

IMAGE = "ubuntu@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeDaemon:
    """Argv-level fake. `mode` injects faults; every call advances the clock."""

    def __init__(self, clock, mode="ok", exit_code=137, call_cost=0.1):
        self.clock, self.mode, self.exit_code, self.cost = clock, mode, exit_code, call_cost
        self.containers, self.calls, self.polls = {}, [], 0

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

    def call(self, args, seconds):
        self.calls.append((list(args), seconds))
        self.clock.now += self.cost
        assert seconds > 0
        verb = args[0]
        if self.mode == "down" and verb in ("container", "inspect", "stop", "rm"):
            raise cr.DockerError()
        if verb == "version":
            return "29.6.1"
        if verb == "image":
            return IMAGE_ID
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
            self.containers[args[-1]]["state"] = "running"
            if self.mode == "start_lost":
                raise cr.DockerTimeout()
            if self.mode == "start_interrupt":
                raise KeyboardInterrupt()
            return ""
        if verb == "inspect":
            self.polls += 1
            if self.mode == "never_exits":
                return "running 0 false"
            if self.mode == "poll_down":
                raise cr.DockerError()
            if self.polls < 3:
                return "running 0 false"
            self.containers[args[-1]]["state"] = "exited"
            return f"exited {self.exit_code} {'true' if self.mode == 'oom' else 'false'}"
        if verb == "container":
            if self.mode == "query_down":
                raise cr.DockerError()
            if self.mode == "stale" and "--filter" in args and args[args.index("--filter") + 1].startswith("name="):
                return self.matches(args) + "\n" + "c" * 64
            if self.mode == "rm_ignored" and self.containers and "id=" in " ".join(args):
                return next(iter(self.containers))
            return self.matches(args)
        if verb == "stop":
            return ""
        if verb == "rm":
            if self.mode != "rm_ignored":
                self.containers.pop(args[-1], None)
            if self.mode == "rm_lost":
                raise cr.DockerTimeout()
            return ""
        raise AssertionError(args)


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.clock = Clock()

    def run_probe(self, mode="ok", delay=0.0, **kw):
        daemon = FakeDaemon(self.clock, mode, **kw.pop("daemon", {}))
        result = cr.run_probe(IMAGE, self.root, daemon, clock=self.clock, sleep=self.clock.sleep,
                              admitted_at=self.clock() - delay, uid=os.getuid() or 1000, **kw)
        return result, daemon

    def mutations(self, daemon):
        return [c[0][0] for c in daemon.calls if c[0][0] in ("create", "start", "rm", "stop")]


class CreateArgumentTests(RunnerCase):
    def test_fixed_restrictive_command_and_no_forbidden_options(self):
        result, daemon = self.run_probe()
        self.assertEqual(result["outcome"], "accepted", result)
        args = next(c[0] for c in daemon.calls if c[0][0] == "create")
        for required in ("--pull=never", "--restart=no", "--network=none", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--read-only", "--pids-limit=64",
                         "--memory=256m", "--cpus=1", "--entrypoint=/usr/bin/timeout"):
            self.assertIn(required, args)
        for forbidden in ("--privileged", "--init", "--pid", "--ipc", "--uts", "--userns",
                          "--device", "--volume", "-v", "--env", "-e", "--cap-add", "--group-add"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertNotIn("docker.sock", " ".join(args))
        self.assertNotIn("--network=host", args)
        self.assertEqual([a for a in args if a.startswith("--mount")],
                         [f"--mount=type=bind,src={result_workspace(args)},dst=/out"])
        self.assertNotIn("rw", args)
        self.assertEqual(args[args.index(IMAGE_ID) + 1], "--kill-after=5s")   # timeout is PID 1, exec form
        self.assertTrue(args[args.index(IMAGE_ID) + 2].endswith("s"))
        self.assertTrue(any(a.startswith("--user=") and not a.startswith("--user=0") for a in args))

    def test_timer_is_remaining_allowance_not_full_allocation(self):
        _, fresh = self.run_probe()
        _, late = self.run_probe(delay=5.0)
        timer = lambda d: int(next(c[0] for c in d.calls if c[0][0] == "create")[-4][:-1])
        self.assertLess(timer(late), timer(fresh))
        self.assertLessEqual(timer(fresh) + cr.KILL_AFTER + cr.START_RESERVE, 30)
        self.assertLessEqual(timer(late) + cr.KILL_AFTER + cr.START_RESERVE, 30 - 5)

    def test_image_must_be_pinned_and_root_refused(self):
        for bad in ("ubuntu:24.04", "ubuntu@sha256:abc", "UBUNTU@sha256:" + "a" * 64):
            with self.assertRaises(ValueError):
                cr.run_probe(bad, self.root, FakeDaemon(self.clock))
        with self.assertRaises(ValueError):
            cr.run_probe(IMAGE, self.root, FakeDaemon(self.clock), uid=0)


def result_workspace(args):
    return next(a for a in args if a.startswith("--mount")).split("src=")[1].split(",")[0]


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

    def test_every_call_is_bounded_by_remaining_budget(self):
        _, daemon = self.run_probe(daemon={"call_cost": 4.0})
        for args, seconds in daemon.calls:
            self.assertLessEqual(seconds, cr.CALL_CAP)

    def test_slow_daemon_cannot_extend_beyond_total_deadline(self):
        result, daemon = self.run_probe("never_exits", daemon={"call_cost": 3.0})
        self.assertLess(self.clock() - 1000.0, 50.0 + 3.0 + cr.CALL_CAP)
        self.assertNotEqual(result["outcome"], "accepted")

    def test_host_expiry_is_never_acceptance_and_container_is_removed(self):
        result, daemon = self.run_probe("never_exits")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "host_expiry"))
        self.assertEqual(daemon.containers, {})
        self.assertEqual(result["cleanup"], "verified")


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
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(result["cleanup"], "uncertain")
        self.assertEqual(len(daemon.containers), 1)
        self.assertEqual(result["workspace"], "retained")

    def test_stale_identity_under_reservation_is_hold_and_nothing_foreign_removed(self):
        result, daemon = self.run_probe("stale")
        self.assertEqual(result["outcome"], "hold")
        self.assertNotIn("c" * 64, [c[0][-1] for c in daemon.calls if c[0][0] == "rm"])

    def test_remove_ignored_by_daemon_is_hold(self):
        result, _ = self.run_probe("rm_ignored")
        self.assertEqual((result["outcome"], result["cleanup"]), ("hold", "uncertain"))

    def test_lost_remove_response_still_verified_by_queries(self):
        result, daemon = self.run_probe("rm_lost")
        self.assertEqual((result["outcome"], result["cleanup"]), ("accepted", "verified"))
        self.assertEqual(daemon.containers, {})

    def test_daemon_loss_mid_run_never_accepts(self):
        result, _ = self.run_probe("poll_down")
        self.assertNotEqual(result["outcome"], "accepted")

    def test_cleanup_queries_use_full_id_and_name_plus_label(self):
        result, daemon = self.run_probe()
        queries = [c[0] for c in daemon.calls if c[0][0] == "container"]
        self.assertGreaterEqual(len(queries), 3)
        final = daemon.calls[-2:]
        self.assertTrue(any(f"id={result['container_id']}" in c[0] for c in final))
        self.assertTrue(any("label=" + result["label"] in c[0] and f"name=^/{result['name']}$" in c[0]
                            for c in daemon.calls if c[0][0] == "container"))


class OutputAndExitTests(RunnerCase):
    def test_unexpected_exit_code_not_accepted(self):
        result, _ = self.run_probe(daemon={"exit_code": 0})
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))

    def test_oom_not_accepted(self):
        result, _ = self.run_probe("oom")
        self.assertEqual(result["outcome"], "failed")

    def test_any_output_is_rejected_as_untrusted(self):
        class Writer(FakeDaemon):
            def call(inner, args, seconds):
                if args[0] == "start":
                    ws = result_workspace(next(c for c in inner.calls if c[0][0] == "create")[0])
                    os.symlink("/etc/passwd", os.path.join(ws, "evil"))
                return super().call(args, seconds)
        daemon = Writer(self.clock)
        result = cr.run_probe(IMAGE, self.root, daemon, clock=self.clock, sleep=self.clock.sleep,
                              uid=os.getuid() or 1000)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_output"))
        self.assertEqual(result["workspace"], "removed")
        self.assertTrue(os.path.exists("/etc/passwd"))

    def test_accepted_run_removes_workspace(self):
        result, _ = self.run_probe()
        self.assertEqual((result["outcome"], result["workspace"]), ("accepted", "removed"))
        self.assertEqual(os.listdir(self.root), [])

    def test_workspace_root_must_be_private_and_symlink_free(self):
        os.chmod(self.root, 0o777)
        result, daemon = self.run_probe()
        self.assertEqual((result["reason"], daemon.calls), ("invalid_input", []))
        os.chmod(self.root, 0o700)
        link = self.root + "-link"
        os.symlink(self.root, link)
        self.addCleanup(os.unlink, link)
        with self.assertRaises(ValueError):
            cr.make_workspace(link, "x", os.getuid())


class RealBackendTests(unittest.TestCase):
    """The real client against owned fake executables standing in for docker."""

    def fake(self, directory, body):
        path = os.path.join(directory, "docker")
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\n" + body + "\n")
        os.chmod(path, 0o755 | stat.S_IXUSR)
        return cr.Backend(path)

    def test_success_failure_and_timeout_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.fake(directory, "echo ok").call(["x"], 5), "ok")
            with self.assertRaises(cr.DockerError):
                self.fake(directory, "exit 3").call(["x"], 5)
            with self.assertRaises(cr.DockerTimeout):
                self.fake(directory, "exec sleep 30").call(["x"], 0.3)
            with self.assertRaises(cr.DockerError):
                cr.Backend(os.path.join(directory, "missing")).call(["x"], 1)

    def test_environment_is_minimal(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.fake(directory, "env | sort | tr '\\n' ' '")
            os.environ["DOCKER_HOST"] = "tcp://elsewhere:1"
            self.addCleanup(os.environ.pop, "DOCKER_HOST")
            self.assertNotIn("DOCKER_HOST", backend.call([], 5))


class CliTests(unittest.TestCase):
    def test_default_prints_plan_without_contacting_docker(self):
        import contextlib
        import io
        import json
        from unittest import mock
        with mock.patch.object(cr, "Backend", side_effect=AssertionError), \
                mock.patch("subprocess.run", side_effect=AssertionError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cr.main(["--image", IMAGE, "--workspace-root", "/tmp/x"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out.getvalue())["executed"])

    def test_unpinned_image_is_usage_error(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cr.main(["--image", "ubuntu:latest", "--workspace-root", "/tmp/x"]), 2)


if __name__ == "__main__":
    unittest.main()
