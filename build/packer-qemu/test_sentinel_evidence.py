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
import tempfile
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
                             reason=os.path.join(self.root, "reason"), ubuntu_prefix=(), top=self.root)
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

    def test_reason_tokens_are_fixed_and_valid_for_the_guest_runner(self):
        source = (HERE / "guest" / "assert-fixture.py").read_text()
        tokens = set(re.findall(r'"([a-z]+(?:-[a-z]+)+)"\)', source))
        self.assertIn("archive-integrity", tokens)
        for token in tokens:
            self.assertRegex(token, af.REASON_RE)


if __name__ == "__main__":
    unittest.main()
