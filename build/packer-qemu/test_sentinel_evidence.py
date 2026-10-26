"""Synthetic status JSON only; never invoke cloud-init or guest operations.

The second half tests guest/assert-fixture.py on temporary directories with synthetic bytes;
only its negatives run the unchanged installer, and those refuse before reading real release
bytes. Nothing here installs, executes hhfab or touches a VM."""
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import sys
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "sentinel_evidence", HERE / "guest" / "sentinel-evidence.py")
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)


class SummaryTests(unittest.TestCase):
    def test_normalizes_known_24x_nested_records_without_retaining_peer_text(self):
        body = {"status": "done", "errors": [], "recoverable_errors": {},
                "detail": {"modules-final": {"errors": [], "recoverable_errors": {"WARNING": []}}},
                "boot_status_code": "enabled-by-generator", "arbitrary": "PEER_TEXT"}
        raw = json.dumps(body).encode()
        self.assertEqual(se.summary(raw), {"status": "done", "errors": 0, "recoverable_errors": 0})
        line = se.record(raw, "a" * 64, "b" * 64)
        self.assertNotIn("PEER_TEXT", line)
        self.assertIn("nonce=" + "a" * 64 + " inputs=" + "b" * 64, line)
        self.assertLess(len(line), 4096)

    def test_rejects_size_shape_errors_non_done_and_duplicate_fields(self):
        bad = [b'{"status":"done"}' + b" " * se.STATUS_CAP,
               b'{"status":"done","status":"done"}', b'{"status":"running"}',
               b'{"status":"done","errors":false}', b'{"status":"done","errors":0}',
               b'{"status":"done","errors":["SECRET"]}',
               b'{"status":"done","recoverable_errors":{"WARNING":["SECRET"]}}',
               b'{"status":"done","detail":{"init":{"errors":["SECRET"]}}}',
               b'{"status":"done","exit_code":1}', b'{"status":"done","x":NaN}',
               b'[]', b'not json']
        for raw in bad:
            with self.subTest(raw=raw[:100]), self.assertRaises(ValueError):
                se.summary(raw)

    def test_malformed_identity_never_emits_a_record(self):
        for nonce, inputs in (("invalid", "b" * 64), ("a" * 64, "b" * 65)):
            with self.assertRaises(ValueError):
                se.record(b'{"status":"done"}', nonce, inputs)


class RendererProcessTests(unittest.TestCase):
    """Real subprocesses/pipes: the renderer's fixed statuses and the pipeline wrapper."""
    GOOD = b'{"status":"done","errors":[],"recoverable_errors":{}}'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(os.path.realpath(tmp.name))
        shutil.copy(HERE / "guest" / "sentinel-evidence.py", self.dir)
        shutil.copy(HERE / "guest" / "assert-sentinel.sh", self.dir)
        (self.dir / "nonce").write_text("a" * 64 + "\n")
        (self.dir / "MANIFEST").write_bytes(b"m\n")
        self.inputs = hashlib.sha256(b"m\n").hexdigest()
        self.expected = ("\nLABAPP-EVIDENCE v1 nonce=" + "a" * 64 + " inputs=" + self.inputs
                         + " cloud-init=done errors=0 recoverable=0\n").encode()

    def render(self, data, stdout=subprocess.PIPE):
        proc = subprocess.run([sys.executable, "-I", str(self.dir / "sentinel-evidence.py")],
                              input=data, stdout=stdout, stderr=subprocess.PIPE, timeout=20)
        return proc

    def test_valid_record_is_byte_exact_and_status_zero(self):
        proc = self.render(self.GOOD)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, self.expected, b""))

    def test_invalid_and_oversized_input_is_status_1_with_no_output(self):
        for data in (b"not json", b'{"status":"running"}', b'{"status":"done"}' + b" " * se.STATUS_CAP):
            proc = self.render(data)
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (1, b"", b""))

    def test_output_write_failures_are_fixed_handled_statuses_not_interpreter_120(self):
        with open("/dev/full", "wb", buffering=0) as full:
            proc = self.render(self.GOOD, stdout=full)
        self.assertEqual((proc.returncode, proc.stderr), (se.WRITE_ENOSPC, b""))
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            proc = self.render(self.GOOD, stdout=write_end)
        finally:
            os.close(write_end)
        self.assertEqual((proc.returncode, proc.stderr), (se.WRITE_EPIPE, b""))

    def test_emit_handles_partial_writes_interrupts_and_stalls(self):
        calls = []

        def fake(fd, view):
            calls.append(bytes(view))
            if len(calls) == 1:
                raise InterruptedError()
            return 3
        with mock.patch.object(se.os, "write", fake):
            self.assertEqual(se.emit(b"abcdefg"), 0)
        self.assertEqual(calls, [b"abcdefg", b"abcdefg", b"defg", b"g"])
        with mock.patch.object(se.os, "write", lambda fd, view: 0):
            self.assertEqual(se.emit(b"abc"), se.WRITE_STALLED)

    def test_emit_maps_errno_to_fixed_statuses_without_peer_text(self):
        import errno
        for code, status in ((errno.EPIPE, se.WRITE_EPIPE), (errno.ENOSPC, se.WRITE_ENOSPC),
                             (errno.EIO, se.WRITE_EIO), (errno.EBADF, se.WRITE_OTHER)):
            with mock.patch.object(se.os, "write", side_effect=OSError(code, "SECRET")):
                self.assertEqual(se.emit(b"x"), status)

    def pipeline(self, producer, out="/dev/null"):
        """Run assert-sentinel.sh's root pipeline with a fake cloud-init and ttyS0 stand-in."""
        bindir = self.dir / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "cloud-init"
        fake.write_text("#!/bin/bash\n" + producer + "\n")
        fake.chmod(0o755)
        script = (self.dir / "assert-sentinel.sh").read_text()
        # Only the fixed root-identity and device/reason paths are redirected for the test.
        script = (script.split("[[ $(id -u)")[0]
                  + "uid=$(id -u); want=root\n"
                  + "set -Eeuo pipefail\n" + "if [[ $want == root ]]; then"
                  + script.split("if [[ $want == root ]]; then", 1)[1])
        script = script.replace("/dev/ttyS0", out).replace("/run/labapp-reason", str(self.dir / "reason"))
        path = self.dir / "run.sh"
        path.write_text(script)
        env = {"PATH": "%s:%s" % (bindir, os.environ["PATH"])}
        proc = subprocess.run(["bash", str(path), "root"], env=env, cwd=str(self.dir),
                              capture_output=True, timeout=20)
        reason = self.dir / "reason"
        return proc, reason.read_text() if reason.exists() else None

    def test_wrapper_classifies_actual_oversize_and_broken_pipe_producers(self):
        # The first producer really writes 1 MiB through the pipe (not subprocess input=).
        # The second keeps writing until the bounded renderer closes its input. A separate
        # distribution timeout bounds the synthetic producer even if this test regresses.
        producers = [
            "exec /usr/bin/python3 -I -B -c 'import os; "
            "view=memoryview(b\"PEER_TEXT\" * 131072);\n"
            "while view: view=view[os.write(1, view):]'",
            "exec /usr/bin/timeout --kill-after=1s 2s /usr/bin/yes PEER_TEXT",
        ]
        for producer in producers:
            with self.subTest(producer=producer):
                start = time.monotonic()
                proc, reason = self.pipeline(producer)
                self.assertLess(time.monotonic() - start, 5)
                self.assertEqual(proc.returncode, 1)
                found = re.fullmatch(r"pipe-p([0-9]{1,3})-r1", reason)
                self.assertIsNotNone(found)
                self.assertGreater(int(found.group(1)), 0)
                self.assertLessEqual(int(found.group(1)), 255)
                self.assertLessEqual(len(reason), 32)
                self.assertLess(len(proc.stdout) + len(proc.stderr), 4096)
                self.assertNotIn(b"PEER_TEXT", proc.stdout + proc.stderr)
                (self.dir / "reason").unlink()

    def test_wrapper_classifies_serial_redirection_open_failure(self):
        good = "printf '%s' '%s'" % (self.GOOD.decode(), "")
        start = time.monotonic()
        proc, reason = self.pipeline(good, out=str(self.dir / "missing-parent" / "tty"))
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(proc.returncode, 1)
        found = re.fullmatch(r"pipe-p([0-9]{1,3})-r1", reason)
        self.assertIsNotNone(found)
        # The producer can finish its small write before the renderer's shell refuses
        # the output redirection, or see SIGPIPE. Neither ordering permits acceptance.
        self.assertLessEqual(int(found.group(1)), 255)
        self.assertLessEqual(len(reason), 32)
        self.assertLess(len(proc.stdout) + len(proc.stderr), 4096)
        self.assertNotIn(self.GOOD, proc.stdout + proc.stderr)
        self.assertFalse((self.dir / "missing-parent").exists())

    def test_wrapper_accepts_valid_and_records_separate_statuses_for_failures(self):
        good = "printf '%s' '%s'" % (self.GOOD.decode(), "")
        proc, reason = self.pipeline(good, out=str(self.dir / "tty"))
        self.assertEqual((proc.returncode, reason), (0, None))
        self.assertEqual((self.dir / "tty").read_bytes(), self.expected)
        for name in ("tty", "reason"):
            if (self.dir / name).exists():
                (self.dir / name).unlink()
        cases = [("exit 3", "/dev/null", "pipe-p3-r1"),                       # producer fails, no input
                 (good + "; exit 3", "/dev/null", "pipe-p3-r0"),               # valid output, producer nonzero
                 ("echo SECRET", "/dev/null", "pipe-p0-r1"),                   # invalid input
                 (good, "/dev/full", "pipe-p0-r%d" % se.WRITE_ENOSPC)]         # serial write failure
        for producer, out, token in cases:
            with self.subTest(token=token):
                proc, reason = self.pipeline(producer, out=out)
                self.assertEqual((proc.returncode, reason), (1, token))
                self.assertRegex(token, r"^[a-z][a-z0-9-]{0,31}$")
                self.assertNotIn(b"SECRET", proc.stdout + proc.stderr)
                (self.dir / "reason").unlink()
        # An earlier reason is never overwritten.
        (self.dir / "reason").write_text("earlier")
        proc, reason = self.pipeline("exit 3")
        self.assertEqual((proc.returncode, reason), (1, "earlier"))


spec = importlib.util.spec_from_file_location("assert_fixture", HERE / "guest" / "assert-fixture.py")
af = importlib.util.module_from_spec(spec)
spec.loader.exec_module(af)
PROVISION = HERE.parent / "provision"
spec = importlib.util.spec_from_file_location("hhfab_release_pins", PROVISION / "hhfab_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
BINARY = b"synthetic installed hhfab, never executed\n"
CAN_RUN_INSTALLER = (platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64")
                     and os.path.exists("/usr/bin/python3"))


class FixtureAssertionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        self.bin = os.path.join(self.root, "bin")
        os.mkdir(self.bin, 0o755)
        os.chmod(self.bin, 0o755)
        self.other = os.path.join(self.bin, "other-tool")
        self.write(self.other, b"unrelated\n", 0o755)
        here = os.path.join(self.root, "in")
        os.mkdir(here)
        self.cfg = af.Config(here, install_dir=self.bin, state=os.path.join(self.root, "state"),
                             reason=os.path.join(self.root, "reason"), ubuntu_prefix=(), top=self.root,
                             lookup=lambda name: types.SimpleNamespace(pw_uid=1000, pw_gid=1000))
        staging = mock.patch.object(af, "staging_access")
        staging.start()  # legacy phase tests isolate staging; dedicated tests below exercise it
        self.addCleanup(staging.stop)
        self.cfg.installer = str(PROVISION / "install-hhfab.py")
        self.cfg.archive = os.path.join(here, "archive.tar.gz")
        self.write(self.cfg.archive, bytes(range(256)) * 16, 0o400)
        for name, value in (("MEMBER_SIZE", len(BINARY)), ("MEMBER_SHA256", hashlib.sha256(BINARY).hexdigest())):
            patcher = mock.patch.object(af, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, path, data, mode):
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)

    def install(self, data=BINARY, mode=0o755):
        self.write(os.path.join(self.bin, "hhfab"), data, mode)

    def reason(self):
        try:
            with open(self.cfg.reason) as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def run_phase(self, phase, expect=0, reason=None):
        self.assertEqual(af.run([phase], self.cfg), expect, phase)
        self.assertEqual(self.reason(), reason)
        if reason is not None:
            self.assertRegex(reason, af.REASON_RE)
            os.unlink(self.cfg.reason)

    def through_snapshot(self):
        self.run_phase("baseline")
        self.install()
        self.run_phase("snapshot")

    def probe_output(self, code, payload):
        """Run the prereq phase with the bounded helper replaced by a canned probe result."""
        data = payload if isinstance(payload, bytes) else json.dumps(payload, sort_keys=True).encode()
        with mock.patch.object(af, "command", return_value=subprocess.CompletedProcess([], code, data)) as run:
            result = af.run(["prereq", "1000", "/in/archive.tar.gz"], self.cfg)
        return result, run

    def failure(self, phase="kvm", **extra):
        value = {"schema": af.PROBE_SCHEMA, "outcome": "failed", "reason": "prerequisite command failed",
                 "phase": phase}
        value.update(extra)
        return value

    def test_prereq_maps_every_allowed_phase_to_a_short_fixed_token(self):
        for phase in ("preflight", "installer", "systemd", "kvm", "cleanup", "unknown"):
            result, run = self.probe_output(1, self.failure(phase))
            self.assertEqual(result, 1)
            token = self.reason()
            self.assertEqual(token, "prereq-" + phase)
            self.assertLessEqual(len(token), 32)
            self.assertRegex(token, af.REASON_RE)
            os.unlink(self.cfg.reason)
        argv = run.call_args.args[1]
        self.assertEqual(argv, ["/usr/bin/python3", "-B", self.cfg.probe, "--owner-uid", "1000",
                                "--archive", "/in/archive.tar.gz"])

    def test_prereq_success_requires_the_exact_schema_and_checks(self):
        good = {"schema": af.PROBE_SCHEMA, "caller_uid": 0, "python": "3.12.3",
                "checks": {"installer": {}, "systemd": {}, "kvm": {}}}
        result, _ = self.probe_output(0, good)
        self.assertEqual((result, self.reason()), (0, None))
        for bad in (dict(good, checks={"installer": {}}), dict(good, outcome="failed"),
                    dict(good, schema="other"), b"not json", b"[]"):
            result, _ = self.probe_output(0, bad)
            self.assertEqual((result, self.reason()), (1, "prereq-invalid"))
            os.unlink(self.cfg.reason)

    def test_prereq_rejects_malformed_inconsistent_or_unexpected_output(self):
        cases = [(1, b"{"), (1, b"\xff"), (1, b"[]"), (1, self.failure("network")),
                 (1, self.failure(phase=["kvm"])), (1, self.failure(outcome="passed")),
                 (1, self.failure(schema="x")), (1, self.failure(extra="SECRET")),
                 (1, self.failure(reason=7)), (2, self.failure()), (0, self.failure()),
                 (-9, self.failure()), (1, {"schema": af.PROBE_SCHEMA, "outcome": "failed"})]
        for code, payload in cases:
            with self.subTest(code=code, payload=payload):
                result, _ = self.probe_output(code, payload)
                self.assertEqual((result, self.reason()), (1, "prereq-invalid"))
                os.unlink(self.cfg.reason)

    def test_prereq_overflow_and_deadline_use_fixed_classifications_without_peer_text(self):
        # `command` maps the helper's Refusal to these Check tokens (existing behavior).
        for token, expected in (("output-bound", "prereq-invalid"), ("prereq-timeout", "prereq-timeout")):
            with mock.patch.object(af, "command", side_effect=af.Check(token)):
                self.assertEqual(af.run(["prereq", "1000", "/in/a"], self.cfg), 1)
            self.assertEqual(self.reason(), expected)
            os.unlink(self.cfg.reason)

    def test_real_output_cap_applies_to_the_probe_capture(self):
        script = os.path.join(self.root, "loud.py")
        self.write(script, b"print('X' * 10000)\n", 0o600)
        self.cfg.probe = script
        self.cfg.installer = str(PROVISION / "install-hhfab.py")
        if not os.path.exists("/usr/bin/python3"):
            self.skipTest("no /usr/bin/python3")
        self.assertEqual(af.run(["prereq", "1000", "/in/a"], self.cfg), 1)
        self.assertEqual(self.reason(), "prereq-invalid")

    def test_prereq_arguments_are_strict(self):
        for argv in (["prereq"], ["prereq", "0", "/a"], ["prereq", "1000", "relative"],
                     ["prereq", "1000", "/a", "extra"], ["prereq", "1; id", "/a"]):
            with mock.patch.object(af, "command") as run:
                self.assertEqual(af.run(argv, self.cfg), 2, argv)
            run.assert_not_called()

    def test_pins_and_version_match_the_unchanged_installer_and_stager(self):
        import stage_tools
        archive_size, archive_sha, member_size, member_sha = release.PINS["0.50.4"]
        spec = importlib.util.spec_from_file_location("real_af", HERE / "guest" / "assert-fixture.py")
        real = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real)
        self.assertEqual((real.VERSION, stage_tools.HHFAB_VERSION), ("0.50.4", "0.50.4"))
        self.assertEqual((real.MEMBER_SIZE, real.MEMBER_SHA256), (member_size, member_sha))
        self.assertEqual((stage_tools.PINS["hhfab"]["size"], stage_tools.PINS["hhfab"]["sha256"]),
                         (archive_size, archive_sha))
        self.assertEqual(real.Config("/in").archive, "/in/" + stage_tools.ARCHIVE_NAME)

    def test_clean_first_install_and_unchanged_rerun_pass_and_preserve_unrelated_tools(self):
        self.through_snapshot()
        self.run_phase("verify")
        with open(self.other, "rb") as handle:
            self.assertEqual(handle.read(), b"unrelated\n")

    def test_baseline_requires_ubuntu_to_be_the_explicit_dedicated_nonroot_owner(self):
        import stage_tools
        self.assertEqual(af.Config("/in").owner_uid, stage_tools.OWNER_UID)     # plan and guest agree
        for entry in (types.SimpleNamespace(pw_uid=0, pw_gid=0),       # root
                      types.SimpleNamespace(pw_uid=1001, pw_gid=1001),  # a different user
                      types.SimpleNamespace(pw_uid=1000, pw_gid=0)):    # root primary group
            self.cfg.lookup = lambda name, entry=entry: entry
            self.run_phase("baseline", 1, "owner-map")
        def missing(name):
            raise KeyError(name)
        self.cfg.lookup = missing
        self.run_phase("baseline", 1, "owner-map")
        self.assertFalse(os.path.exists(self.cfg.state))        # nothing recorded before the refusal

    def test_baseline_staging_refusal_uses_existing_reason_before_state_creation(self):
        with mock.patch.object(af, "staging_access", side_effect=af.Check("staging-input")):
            self.run_phase("baseline", 1, "staging-input")
        self.assertFalse(os.path.exists(self.cfg.state))

    def test_baseline_refuses_unsafe_directory_or_existing_target_without_deleting_anything(self):
        self.install()
        self.run_phase("baseline", 1, "target-present")
        os.unlink(os.path.join(self.bin, "hhfab"))
        os.chmod(self.bin, 0o775)
        self.run_phase("baseline", 1, "dir-state")
        os.chmod(self.bin, 0o755)
        link = os.path.join(self.root, "link")
        os.symlink(self.bin, link)
        self.cfg.install_dir = link
        self.run_phase("baseline", 1, "dir-state")
        self.cfg.install_dir = self.bin
        os.mkdir(os.path.join(self.bin, ".hhfab-stage-old"))
        self.run_phase("baseline", 1, "stage-leftover")
        self.assertTrue(os.path.exists(self.other))

    def test_first_install_state_directory_changes_and_leftovers_are_reasoned(self):
        self.run_phase("baseline")
        for data, mode in ((BINARY + b"x", 0o755), (BINARY, 0o775), (BINARY, 0o644)):
            with self.subTest(mode=mode, size=len(data)):
                self.install(data, mode)
                self.run_phase("snapshot", 1, "install-state")
        self.install()
        os.mkdir(os.path.join(self.bin, ".hhfab-stage-left"))
        self.run_phase("snapshot", 1, "stage-leftover")
        os.rmdir(os.path.join(self.bin, ".hhfab-stage-left"))
        os.unlink(self.other)
        self.run_phase("snapshot", 1, "dir-preserved")
        self.write(self.other, b"changed\n", 0o755)
        self.run_phase("snapshot", 1, "dir-preserved")

    def test_rerun_must_leave_the_same_inode_and_times_and_no_new_entries(self):
        self.through_snapshot()
        staged = os.path.join(self.bin, "hhfab.new")
        self.write(staged, BINARY, 0o755)
        os.replace(staged, os.path.join(self.bin, "hhfab"))      # same bytes, new inode
        self.run_phase("verify", 1, "rerun-state")
        self.write(os.path.join(self.bin, "added"), b"x", 0o644)
        self.run_phase("verify", 1, "dir-preserved")
        os.unlink(os.path.join(self.bin, "added"))
        os.chmod(os.path.join(self.bin, "hhfab"), 0o644)
        self.run_phase("verify", 1, "install-state")

    def test_unknown_phase_and_missing_prior_state(self):
        self.assertEqual(af.run(["bogus"], self.cfg), 2)
        self.assertEqual(af.run([], self.cfg), 2)
        self.install()
        self.run_phase("snapshot", 1, "internal")      # no baseline state

    @unittest.skipUnless(CAN_RUN_INSTALLER, "installer needs Linux amd64 python3")
    def test_negatives_refuse_corrupt_archive_and_bad_version_on_isolated_state(self):
        self.through_snapshot()
        self.run_phase("negatives")
        neg = os.path.join(self.cfg.state, "neg")
        with open(os.path.join(neg, "prior", "hhfab"), "rb") as handle:
            self.assertEqual(handle.read(), af.PRIOR_BYTES)         # nonmatching, never executed
        self.assertEqual(os.listdir(os.path.join(neg, "absent")), [])
        with open(os.path.join(self.bin, "hhfab"), "rb") as handle:
            self.assertEqual(handle.read(), BINARY)                  # the good install is never an argument

    @unittest.skipUnless(CAN_RUN_INSTALLER, "installer needs Linux amd64 python3")
    def test_negatives_fail_with_a_specific_reason_when_the_refusal_is_not_the_expected_one(self):
        self.through_snapshot()
        with mock.patch.object(af, "REFUSAL", b"hhfab install: something else\n"):
            self.run_phase("negatives", 1, "archive-integrity")

    def smoke_with(self, script, reason=None, expect=0):
        self.write(os.path.join(self.bin, "hhfab"), script, 0o755)
        self.run_phase("smoke", expect, reason)

    @unittest.skipUnless(os.path.exists("/usr/bin/env"), "needs env")
    def test_smoke_accepts_only_the_established_anchored_version_format(self):
        for out in ("hhfab version v0.50.4", "hhfab version 0.50.4"):
            with self.subTest(out=out):
                self.smoke_with(("#!/bin/sh\necho '%s'\n" % out).encode())
        self.smoke_with(b"#!/bin/sh\nprintf 'hhfab version v0.50.4'\n")       # newline is optional
        for out in ("hhfab version v0.50.40", "hhfab version v0.50.4 extra", "xhhfab version v0.50.4",
                    "hhfab version v0.50.4\\nmore", "version 0.50.4", "", "v0.50.4"):
            with self.subTest(out=out):
                self.smoke_with(("#!/bin/sh\nprintf '%s'\n" % out).encode(), "cli-version", 1)

    @unittest.skipUnless(os.path.exists("/usr/bin/env"), "needs env")
    def test_smoke_failure_exit_and_output_bound_are_specific(self):
        self.smoke_with(b"#!/bin/sh\necho 'hhfab version v0.50.4'\nexit 3\n", "cli-run", 1)
        self.smoke_with(b"#!/bin/sh\nhead -c 8192 /dev/zero\n", "output-bound", 1)

    @unittest.skipUnless(os.path.exists("/usr/bin/env"), "needs env")
    def test_smoke_runs_under_a_sanitized_environment_and_cwd(self):
        script = (b"#!/bin/sh\n[ \"$PWD\" = / ] && [ \"$HOME\" = /home/ubuntu ] && [ -z \"$SECRET\" ] "
                  b"&& echo 'hhfab version v0.50.4'\n")
        with mock.patch.dict(os.environ, {"SECRET": "x"}):
            self.smoke_with(script)

    def test_streaming_command_bounds_combined_output_before_capture(self):
        start = time.monotonic()
        with self.assertRaisesRegex(af.Check, "^output-bound$"):
            af.command(self.cfg, [sys.executable, "-I", "-B", "-c",
                                  "import os; os.write(2, b'x' * 10000000)"],
                       2, "negative-timeout", {"PATH": af.SAFE_PATH})
        self.assertLess(time.monotonic() - start, 2.5)

    def test_command_deadline_kills_child_and_pipe_holding_descendant(self):
        for fork in (False, True):
            with self.subTest(pipe_holder=fork):
                pidfile = os.path.join(self.root, "owned-child-pid")
                script = ("import os,time; " + ("pid=os.fork(); " if fork else "")
                          + "open(%r, 'w').write(str(os.getpid())); " % pidfile
                          + ("time.sleep(30) if pid == 0 else None" if fork else "time.sleep(30)"))
                start = time.monotonic()
                try:
                    with self.assertRaisesRegex(af.Check, "^cli-timeout$"):
                        af.command(self.cfg, [sys.executable, "-I", "-B", "-c", script],
                                   .3, "cli-timeout", {"PATH": af.SAFE_PATH})
                    self.assertLess(time.monotonic() - start, 2.5)
                    pid = int(Path(pidfile).read_text())
                    status = Path("/proc/%d/stat" % pid)
                    until = time.monotonic() + 1
                    while status.exists() and status.read_text().split()[2] != "Z" and time.monotonic() < until:
                        time.sleep(.01)
                    self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z")
                finally:
                    # Exact test-owned process only; also clean up if the assertion regresses.
                    if os.path.exists(pidfile):
                        pid = int(Path(pidfile).read_text())
                        try:
                            os.kill(pid, 9)
                        except ProcessLookupError:
                            pass
                        os.unlink(pidfile)

    def test_reason_tokens_are_fixed_and_valid_for_the_guest_runner(self):
        source = (HERE / "guest" / "assert-fixture.py").read_text()
        tokens = set(re.findall(r'"([a-z]+(?:-[a-z]+)+)"\)', source))
        self.assertIn("archive-integrity", tokens)
        for token in tokens:
            self.assertRegex(token, af.REASON_RE)




class GuestModeNormalizationTests(unittest.TestCase):
    """Run the shipped shell function on owned temporary files, without guest/privileged work."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.public = ("assert-sentinel.sh", "sentinel-evidence.py", "install-hhfab.py",
                       "hhfab_release.py", "hhfab-linux-amd64-v0.50.4.tar.gz")

    def normalize(self):
        return subprocess.run(["/bin/bash", "-c", 'umask 077; source "$1"; IN=$2; normalize_input_modes',
                               "mode-test", str(HERE / "guest" / "guest-build.sh"), str(self.root)],
                              env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=5)

    def sdk_copy(self, name):
        # SDK0.6.11 AddFile: os.Create (0666 before umask) + io.Copy, no copied mode.
        previous = os.umask(0o077)
        try:
            fd = os.open(str(self.root / name), os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o666)
            with os.fdopen(fd, "wb") as output:
                output.write(("inert " + name).encode())
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)

    def test_sdk_mode_loss_is_normalized_for_minimal_and_fixture_without_changing_bytes(self):
        for fixture in (False, True):
            with self.subTest(fixture=fixture):
                for old in self.root.iterdir():
                    old.unlink()
                names = (self.public if fixture else self.public[:2]) + ("nonce", "MANIFEST", "plan.txt", "guest-build.sh")
                for name in names:
                    self.sdk_copy(name)
                before = {p.name: p.read_bytes() for p in self.root.iterdir()}
                result = self.normalize()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
                self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)
                for name in names:
                    expected = 0o444 if name in self.public else 0o600 if name == "nonce" else 0o400
                    self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), expected, name)

    def test_symlink_refusal_does_not_chmod_the_outside_target(self):
        with tempfile.TemporaryDirectory() as other:
            target = Path(other) / "outside"
            target.write_bytes(b"outside")
            target.chmod(0o600)
            (self.root / "alias").symlink_to(target)
            result = self.normalize()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_unreadable_bash_script_exit126_matches_failure_class_and_normalization_fixes_it(self):
        path = self.root / "assert-sentinel.sh"
        path.write_text("#!/bin/bash\nexit 0\n")
        path.chmod(0)
        first = subprocess.run(["/bin/bash", str(path)], capture_output=True, timeout=5)
        self.assertEqual(first.returncode, 126)
        (self.root / "nonce").write_bytes(b"nonce")
        self.assertEqual(self.normalize().returncode, 0)
        second = subprocess.run(["/bin/bash", str(path)], capture_output=True, timeout=5)
        self.assertEqual(second.returncode, 0)

    def test_normalization_and_optional_staging_guard_precede_first_ubuntu_step(self):
        runner = (HERE / "guest" / "guest-build.sh").read_text().split("main() {", 1)[1]
        self.assertLess(runner.index("check_inputs"), runner.index("normalize_input_modes"))
        self.assertLess(runner.index("normalize_input_modes"), runner.index("run_plan"))
        sentinel = (HERE / "guest" / "assert-sentinel.sh").read_text()
        self.assertIn('if [[ -f ${BASH_SOURCE[0]%/*}/assert-fixture.py ]]; then', sentinel)
        self.assertIn('/usr/bin/python3 -I -B "${BASH_SOURCE[0]%/*}/assert-fixture.py" staging', sentinel)
        self.assertIn("staging", af.PHASES)
        self.assertIs(af.PHASES["staging"], af.staging_access)

class GuestStagingTests(unittest.TestCase):
    """Unprivileged synthetic metadata/access checks, not proof of a root-owned guest copy."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        os.chmod(self.root, 0o755)
        self.here = os.path.join(self.root, "in")
        os.mkdir(self.here, 0o755)
        self.cfg = af.Config(self.here, top=self.root, staging_uid=os.geteuid(), ubuntu_prefix=(),
                             owner_uid=os.geteuid())
        for name in ("install-hhfab.py", "hhfab_release.py"):
            shutil.copyfile(PROVISION / name, os.path.join(self.here, name))
            os.chmod(os.path.join(self.here, name), 0o444)
        Path(self.cfg.archive).write_bytes(b"synthetic archive, never installed")
        os.chmod(self.cfg.archive, 0o444)
        self.nonce = os.path.join(self.here, "nonce")
        Path(self.nonce).write_bytes(b"private")
        os.chmod(self.nonce, 0o600)

    def test_trusted_metadata_accepts_exact_modes_and_owner(self):
        af.staging_metadata(self.cfg)
        self.assertEqual(af.Config("/in").staging_uid, 0)

    def test_parent_modes_owner_and_symlink_are_refused(self):
        for mode in (0o700, 0o775, 0o777):
            os.chmod(self.here, mode)
            with self.assertRaisesRegex(af.Check, "^staging-parent$"):
                af.staging_metadata(self.cfg)
        os.chmod(self.here, 0o755)
        self.cfg.staging_uid = os.geteuid() + 1
        with self.assertRaisesRegex(af.Check, "^staging-parent$"):
            af.staging_metadata(self.cfg)
        self.cfg.staging_uid = os.geteuid()
        alias = os.path.join(self.root, "alias")
        os.symlink(self.here, alias)
        self.cfg.here = alias
        with self.assertRaisesRegex(af.Check, "^staging-parent$"):
            af.staging_metadata(self.cfg)

    def test_each_input_and_nonce_refuse_wrong_modes_symlinks_and_hardlinks(self):
        for name, good in (("install-hhfab.py", 0o444), ("hhfab_release.py", 0o444),
                           (os.path.basename(self.cfg.archive), 0o444), ("nonce", 0o600)):
            path = os.path.join(self.here, name)
            for mode in (0o400 if good == 0o444 else 0o644, 0o666):
                os.chmod(path, mode)
                with self.assertRaisesRegex(af.Check, "^staging-input$"):
                    af.staging_metadata(self.cfg)
            os.chmod(path, good)
            extra = os.path.join(self.root, "extra")
            os.link(path, extra)
            with self.assertRaisesRegex(af.Check, "^staging-input$"):
                af.staging_metadata(self.cfg)
            os.unlink(extra)
            os.rename(path, extra)
            os.symlink(extra, path)
            with self.assertRaisesRegex(af.Check, "^staging-input$"):
                af.staging_metadata(self.cfg)
            os.unlink(path)
            os.rename(extra, path)

    def test_input_owner_mismatch_is_refused_independently_of_parent_owner(self):
        original = os.lstat
        def metadata(path):
            info = original(path)
            if path == self.cfg.archive:
                values = list(info)
                values[4] = info.st_uid + 1
                return os.stat_result(values)
            return info
        with mock.patch.object(af.os, "lstat", side_effect=metadata):
            with self.assertRaisesRegex(af.Check, "^staging-input$"):
                af.staging_metadata(self.cfg)

    @unittest.skipUnless(os.geteuid() > 0 and os.path.exists("/proc/1/mem"), "nonroot Linux access check")
    def test_same_uid_private_nonce_is_rejected_by_the_actual_data_only_child(self):
        # A host same-UID read is intentionally NOT a successful guest privacy proof.
        with self.assertRaisesRegex(af.Check, "^staging-access$"):
            af.staging_access(self.cfg)

    @unittest.skipUnless(os.geteuid() > 0 and os.path.exists("/proc/1/mem"), "nonroot Linux access check")
    def test_actual_readonly_sibling_import_and_read_under_sanitized_child_environment(self):
        # /proc/1/mem is an independently inaccessible lower-layer stand-in, not a guest nonce.
        with self.assertRaises(PermissionError):
            open("/proc/1/mem", "rb")
        argv = ["/usr/bin/env", "-i", "PATH=" + af.SAFE_PATH, "HOME=/home/ubuntu", "LC_ALL=C.UTF-8",
                "/usr/bin/python3", "-I", "-B", "-c", af.ACCESS_CHILD, self.here,
                "/proc/1/mem", str(os.geteuid())]
        done = af.command(self.cfg, argv, 20, "staging-timeout", {"PATH": af.SAFE_PATH})
        self.assertEqual((done.returncode, done.stdout), (0, b""))
        self.assertEqual(sorted(os.listdir(self.here)),
                         ["hhfab-linux-amd64-v0.50.4.tar.gz", "hhfab_release.py", "install-hhfab.py", "nonce"])

    def test_access_failure_and_unexpected_output_are_bounded_fixed_refusals(self):
        for code, output in ((1, b"private peer output"), (0, b"unexpected")):
            with mock.patch.object(af, "command", return_value=subprocess.CompletedProcess([], code, output)):
                with self.assertRaisesRegex(af.Check, "^staging-access$"):
                    af.staging_access(self.cfg)

if __name__ == "__main__":
    unittest.main()
