"""Public synthetic integrity/bounds and Docker-ownership regression tests."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import hhfab_test as subject
import test_bridge_ipv4_harness as ownership


class IntegrityTests(unittest.TestCase):
    def archive(self, root, name="hhfab-linux-amd64/hhfab", kind=tarfile.REGTYPE, extra=False):
        path = root / "release.tgz"
        with tarfile.open(path, "w:gz") as tar:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 4 if kind == tarfile.REGTYPE else 0
            tar.addfile(member, io.BytesIO(b"test") if member.size else None)
            if extra:
                tar.addfile(tarfile.TarInfo("unexpected"))
        return path, (path.stat().st_size, subject.digest(path), 4, hashlib.sha256(b"test").hexdigest())

    def test_distribution_csafe_loader_accepts_yaml_separation_tab(self):
        import yaml
        self.assertEqual(yaml.load("ip:\tdhcp # public upstream template\n", Loader=yaml.CSafeLoader), {"ip": "dhcp"})

    def test_extract_exact_member(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            subject.extract(archive, root / "binary", pin)
            self.assertEqual((root / "binary").read_bytes(), b"test")
            self.assertEqual((root / "binary").stat().st_mode & 0o777, 0o755)

    def test_bad_archive_digest_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            pin = (pin[0], "0" * 64, *pin[2:])
            with self.assertRaisesRegex(subject.Refusal, "archive checksum"):
                subject.extract(archive, root / "binary", pin)
            self.assertFalse((root / "binary").exists())

    def test_bad_member_digest_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, pin = self.archive(root)
            with self.assertRaisesRegex(subject.Refusal, "member checksum"):
                subject.extract(archive, root / "binary", (*pin[:3], "0" * 64))

    def test_unsafe_or_multiple_members_refused(self):
        for member, kind, extra in [("../escape", tarfile.REGTYPE, False),
                                    ("hhfab-linux-amd64/hhfab", tarfile.SYMTYPE, False),
                                    ("hhfab-linux-amd64/hhfab", tarfile.REGTYPE, True)]:
            with self.subTest(member=member, kind=kind, extra=extra), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                archive, pin = self.archive(root, member, kind, extra)
                with self.assertRaisesRegex(subject.Refusal, "archive member"):
                    subject.extract(archive, root / "binary", pin)
                self.assertFalse((root / "binary").exists())

    def test_timeout_and_overflow_actual_children(self):
        for code, seconds, limit, reason in [("import time; time.sleep(10)", .1, 1024, "timeout"),
                                             ("print('x'*10000)", 2, 1024, "overflow")]:
            with self.subTest(reason=reason), self.assertRaisesRegex(subject.Refusal, reason):
                subject.bounded([sys.executable, "-c", code], seconds, limit)

    def test_interruption_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "pid"
            child = ("import os,signal,time; from pathlib import Path; "
                     "Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); "
                     "os.kill(os.getppid(),signal.SIGINT); time.sleep(10)")
            program = ("import sys; sys.path.insert(0,sys.argv[1]); import hhfab_test as h; "
                       "h.bounded([sys.executable,'-c',sys.argv[2]],2)")
            proc = subprocess.run([sys.executable, "-c", program, str(Path(__file__).parent), child],
                                  capture_output=True, timeout=4)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b"KeyboardInterrupt", proc.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)


class NoSwitchSmokeTests(unittest.TestCase):
    """Exercise real command bindings; the bounded spy never executes a CLI."""
    FABRIC = b"kind: Fabricator\nmetadata: {name: default}\n---\nkind: ControlNode\nmetadata: {name: control-1}\n"
    NAMESPACES = (b"kind: VLANNamespace\nmetadata: {name: default}\nspec: {ranges: [{from: 1000, to: 2999}]}\n---\n"
                  b"kind: IPv4Namespace\nmetadata: {name: default}\nspec: {subnets: [10.0.0.0/16]}\n---\n"
                  b"kind: SwitchGroup\nmetadata: {name: empty}\nspec: {}\n")

    def run_smoke(self, generated=None, fabric=None, codes=None, extra=None, mutate=False):
        from unittest.mock import patch
        codes = codes or {}
        calls = []
        with tempfile.TemporaryDirectory() as name:
            case = Path(name) / "case"
            case.mkdir()
            env = {"PATH": "/usr/bin:/bin", "HOME": str(Path(name) / "home"),
                   "XDG_CACHE_HOME": str(Path(name) / "cache"), "LANG": "C.UTF-8", "GOMAXPROCS": "2"}
            binary, cache = Path(name) / "verified-binary", Path(env["XDG_CACHE_HOME"])
            validations = 0

            def bounded(argv, seconds, env=None):
                nonlocal validations
                calls.append((argv, seconds, env))
                self.assertEqual(argv[0], str(binary))
                self.assertEqual(argv[argv.index("--workdir") + 1], str(case))
                self.assertEqual(argv[argv.index("--cache-dir") + 1], str(cache))
                command = "generate" if argv[1:3] == ["vlab", "generate"] else argv[1]
                if command == "validate":
                    validations += 1
                code = codes.get("rerun" if validations == 2 else command, 0)
                if code:
                    return code, b"private diagnostic must not escape"
                if command == "init":
                    for directory in ("include", "result"):
                        (case / directory).mkdir()
                    (case / "fab.yaml").write_bytes(self.FABRIC if fabric is None else fabric)
                    (case / ".registry.yaml").write_bytes(b"x: 1\n")
                elif command == "generate":
                    target = case / "include/vlab.generated.yaml"
                    target.write_bytes(self.NAMESPACES if generated is None else generated)
                    if extra == "include":
                        (case / "include/wiringd.yaml").write_bytes(b"")
                    elif extra == "top":
                        (case / "unexpected").write_bytes(b"")
                    elif extra == "result":
                        (case / "result/unexpected").write_bytes(b"")
                    elif extra == "symlink":
                        target.unlink()
                        target.symlink_to(case / "fab.yaml")
                elif command == "validate" and validations == 2 and mutate:
                    (case / ".registry.yaml").write_bytes(b"changed: true\n")
                return 0, b""

            with patch.object(subject, "bounded", side_effect=bounded), patch.object(subject.time, "monotonic", return_value=10):
                cli, init, validate = subject.fixture_cli(binary, cache, env, 25)
                try:
                    result = subject.no_switch_smoke(cli, init, validate, case)
                except subject.Refusal as error:
                    result = error
            return result, calls, case, cache, binary, env

    def test_exact_bounded_argv_order_bindings_and_environment(self):
        result, calls, case, cache, binary, env = self.run_smoke()
        self.assertIsInstance(result, dict)
        tail = ["--workdir", str(case), "--cache-dir", str(cache)]
        self.assertEqual([call[0] for call in calls], [
            [str(binary), "init", *tail, "--fabric-mode", "spine-leaf", "--dev", "--gateway=false",
             "--registry-repo", "ghcr.io", "--registry-prefix", "githedgehog"],
            [str(binary), "vlab", "generate", *tail, "--no-switches"],
            [str(binary), "validate", *tail, "--hydrate-mode", "if-not-present"],
            [str(binary), "validate", *tail, "--hydrate-mode", "if-not-present"]])
        self.assertTrue(all(seconds == 15 and child_env is env for _, seconds, child_env in calls))
        self.assertEqual(result["node_kinds"], ["ControlNode", "Fabricator"])
        self.assertEqual(result["wiring_kinds"], ["IPv4Namespace", "SwitchGroup", "VLANNamespace"])
        self.assertEqual(set(result), {"node_kinds", "wiring_kinds", "tree_sha256"})

    def test_canonical_init_retains_exact_wiring_argv_and_byte_identity(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as name, patch.object(subject, "bounded", return_value=(0, b"")) as run:
            case = Path(name)
            cli, init, validate = subject.fixture_cli("/verified", "/cache", {}, subject.time.monotonic() + 120)
            init(case)
            self.assertEqual(run.call_args.args[0], ["/verified", "init", "--workdir", str(case), "--cache-dir", "/cache",
                "--fabric-mode", "spine-leaf", "--dev", "--gateway=false", "--registry-repo", "ghcr.io",
                "--registry-prefix", "githedgehog", "--wiring", "/suite/wiringd.yaml"])
            self.assertLessEqual(run.call_args.args[1], 30)
            (case / "occupied").touch()
            with self.assertRaises(subject.Refusal):
                init(case)
            self.assertEqual(run.call_count, 1)
        subject.check_wiring(Path(__file__).resolve().parents[2] / "wiringd.yaml")

    def test_deadline_and_forbidden_commands_refuse_before_child(self):
        from unittest.mock import patch
        with patch.object(subject, "bounded") as run, patch.object(subject.time, "monotonic", return_value=10):
            cli, _, _ = subject.fixture_cli("/verified", "/cache", {}, 10)
            for command in ("init", "build", "vlab up", "_helpers"):
                with self.subTest(command=command), self.assertRaises(subject.Refusal):
                    cli(command, Path("/case"))
            run.assert_not_called()

    def test_unexpected_topology_refused(self):
        for kind in ("Switch", "Server", "Connection", "Gateway", "External", "SwitchGroup", "Surprise"):
            with self.subTest(kind=kind):
                extra = ("---\nkind: %s\nmetadata: {name: x}\n" % kind).encode()
                self.assertIsInstance(self.run_smoke(generated=self.NAMESPACES + extra)[0], subject.Refusal)

    def test_missing_duplicate_and_malformed_identity_refused(self):
        for value in (b"", b"null\n", b"[]\n", b"kind: [\n", b"kind: IPv4Namespace\n",
                      self.NAMESPACES + self.NAMESPACES, self.NAMESPACES.replace(b"name: default", b"name: other", 1),
                      self.NAMESPACES.replace(b"1000", b"999"), self.NAMESPACES.replace(b"10.0.0.0/16", b"10.1.0.0/16")):
            with self.subTest(generated=value):
                self.assertIsInstance(self.run_smoke(generated=value)[0], subject.Refusal)
        for value in (b"", b"kind: [\n", self.FABRIC + b"---\nkind: FabNode\nmetadata: {name: gw}\n",
                      self.FABRIC + b"---\nkind: ControlNode\nmetadata: {name: control-2}\n",
                      self.FABRIC.replace(b"control-1", b"control-2"), self.FABRIC.replace(b"name: default", b"name: other"),
                      b"kind: Fabricator\nmetadata: {name: default}\n"):
            with self.subTest(fabric=value):
                self.assertIsInstance(self.run_smoke(fabric=value)[0], subject.Refusal)

    def test_empty_switch_group_marker_requires_exact_identity_and_spec(self):
        marker = b"---\nkind: SwitchGroup\nmetadata: {name: empty}\nspec: {}\n"
        for value in (self.NAMESPACES.replace(marker, b""), self.NAMESPACES + marker,
                      self.NAMESPACES.replace(b"name: empty", b"name: other"),
                      self.NAMESPACES.replace(b"spec: {}", b"spec: {unexpected: true}"),
                      self.NAMESPACES.replace(b"spec: {}", b"spec: null"),
                      self.NAMESPACES.replace(b"spec: {}\n", b"")):
            with self.subTest(generated=value):
                self.assertIsInstance(self.run_smoke(generated=value)[0], subject.Refusal)

    def test_extra_outputs_symlink_and_mutating_rerun_refused(self):
        for extra in ("include", "top", "result", "symlink"):
            with self.subTest(extra=extra):
                self.assertIsInstance(self.run_smoke(extra=extra)[0], subject.Refusal)
        self.assertIsInstance(self.run_smoke(mutate=True)[0], subject.Refusal)
        self.assertIsInstance(self.run_smoke(generated=b"x" * (1024 * 1024 + 1))[0], subject.Refusal)

    def test_nonzero_cli_stops_and_retains_safe_failure(self):
        for command, expected_calls in (("init", 1), ("generate", 2), ("validate", 3), ("rerun", 4)):
            with self.subTest(command=command):
                result, calls, *_ = self.run_smoke(codes={command: 1})
                self.assertIsInstance(result, subject.Refusal)
                self.assertEqual(len(calls), expected_calls)
                self.assertNotIn("private diagnostic", str(result))


class ConfigImportTests(unittest.TestCase):
    """Run the maintained import helper and CLI binding with a nonexecuting spy."""
    def run_import(self, failure=None, mutation=None, occupied=False, renderer=False):
        from unittest.mock import patch
        calls = []
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, case = root / "source", root / "import"
            source.mkdir()
            case.mkdir()
            (source / "include").mkdir()
            (source / "result").mkdir()
            (source / "fab.yaml").write_bytes(NoSwitchSmokeTests.FABRIC)
            (source / ".registry.yaml").write_bytes(b"prefix: githedgehog\nrepo: ghcr.io\n")
            wiring = Path(__file__).resolve().parents[2] / "wiringd.yaml"
            (source / "include/wiringd.yaml").write_bytes(wiring.read_bytes())
            binary = root / "verified-binary"
            binary.write_bytes(b"synthetic binary, never executed")
            pin = (0, "unused", binary.stat().st_size, subject.digest(binary))
            if occupied:
                (case / "foreign").write_bytes(b"preserve")
            env = {"PATH": "/usr/bin:/bin", "HOME": str(root / "home")}
            cache = root / "cache"
            reference = source
            if renderer:
                source = root / 'rendered-public'
                source.mkdir()

            def bounded(argv, seconds, env=None):
                calls.append((argv, seconds, env))
                stage = ("init", "validate", "rerun")[len(calls) - 1]
                if failure == stage:
                    return 1, b"private diagnostic must not escape"
                if stage == "init":
                    for path in ("include", "result"):
                        (case / path).mkdir()
                    for path in ("fab.yaml", ".registry.yaml", "include/wiringd.yaml"):
                        (case / path).write_bytes((source / path).read_bytes())
                if mutation and mutation[0] == stage:
                    target, action = mutation[1:]
                    if target == "binary":
                        binary.write_bytes(b"replaced")
                    elif target.startswith("source/"):
                        (source / target.removeprefix("source/")).write_bytes(b"changed")
                    elif action == "extra-dir":
                        (case / target).mkdir()
                    elif action == "remove":
                        (case / target).unlink()
                    elif action == "symlink":
                        (case / target).unlink()
                        (case / target).symlink_to(source / "fab.yaml")
                    else:
                        (case / target).write_bytes(b"changed")
                return 0, b""

            with patch.dict(subject.PINS, {"0.43.1": pin}), patch.object(subject, "bounded", side_effect=bounded), \
                    patch.object(subject.time, "monotonic", return_value=10):
                cli, _, validate = subject.fixture_cli(binary, cache, env, 25)
                try:
                    result = (subject.rendered_config_smoke(cli, validate, reference, source, case, wiring, binary)
                              if renderer else subject.config_import_smoke(cli, validate, source, case, wiring, binary))
                except subject.Refusal as error:
                    result = error
            foreign = (case / "foreign").read_bytes() if occupied else None
            return result, calls, source, case, wiring, binary, cache, env, foreign

    def test_exact_import_and_two_validate_bindings_and_safe_report(self):
        result, calls, source, case, wiring, binary, cache, env, _ = self.run_import()
        tail = ["--workdir", str(case), "--cache-dir", str(cache)]
        self.assertEqual([c[0] for c in calls], [
            [str(binary), "init", *tail, "--config", str(source / "fab.yaml"),
             "--registry-repo", "ghcr.io", "--registry-prefix", "githedgehog", "--wiring", str(wiring)],
            [str(binary), "validate", *tail, "--hydrate-mode", "if-not-present"],
            [str(binary), "validate", *tail, "--hydrate-mode", "if-not-present"]])
        self.assertTrue(all(seconds == 15 and child_env is env for _, seconds, child_env in calls))
        self.assertEqual(set(result), {"scope", "tree_sha256"})
        self.assertEqual(result["scope"], "generated-public-candidate-only")
        self.assertEqual(set(result["tree_sha256"]), {"fab.yaml", ".registry.yaml", "include/wiringd.yaml"})
        self.assertEqual(result["tree_sha256"]["include/wiringd.yaml"], subject.WIRING_SHA)

    def test_each_native_refusal_stops_before_later_command(self):
        for stage, count in (("init", 1), ("validate", 2), ("rerun", 3)):
            with self.subTest(stage=stage):
                result, calls, *_ = self.run_import(failure=stage)
                self.assertIsInstance(result, subject.Refusal)
                self.assertEqual(len(calls), count)
                self.assertTrue(str(result).startswith('generated-reference: '))
                self.assertNotIn("private diagnostic", str(result))

    def test_shared_trial_renderer_reuses_exact_import_and_two_validations(self):
        result, calls, source, case, wiring, binary, cache, env, _ = self.run_import(renderer=True)
        self.assertEqual([c[0][1] for c in calls], ['init','validate','validate'])
        self.assertEqual(calls[0][0][-8:], ['--config',str(source/'fab.yaml'),'--registry-repo','ghcr.io',
                                         '--registry-prefix','githedgehog','--wiring',str(wiring)])
        self.assertTrue(result['public_fixture'])
        self.assertEqual(result['renderer_sha256'], result['tree_sha256']['fab.yaml'])
        for stage, count in (('init',1),('validate',2),('rerun',3)):
            failed, events, *_ = self.run_import(renderer=True, failure=stage)
            self.assertIsInstance(failed, subject.Refusal)
            self.assertEqual(len(events), count)
            self.assertTrue(str(failed).startswith('rendered-candidate: '))
            self.assertNotIn('private diagnostic', str(failed))

    def test_trial_renderer_leaves_canonical_topology_for_official_hydration(self):
        import vlab_core as core
        import yaml
        raw = subject.candidate_fab('ssh-ed25519 AAAA', '$5$publicfixture$' + 'a'*43, 'f'*64)
        docs = core.validate_fab(raw)
        node = docs[1]['spec']
        self.assertEqual(node['management'], {'interface': 'enp2s1'})
        self.assertNotIn('dummy', node)
        wiring = subject.check_wiring(Path(__file__).resolve().parents[2] / 'wiringd.yaml')
        for doc in wiring:
            if doc['kind'] == 'Switch':
                self.assertTrue({'ip', 'protocolIP', 'vtepIP', 'asn'}.isdisjoint(doc['spec']))
            elif doc['kind'] == 'Connection':
                for link in doc['spec'].get('fabric', {}).get('links', []):
                    self.assertEqual(set(link['spine']), {'port'})
                    self.assertEqual(set(link['leaf']), {'port'})
        # Retain the accepted effective control address policy; this test does
        # not implement or simulate the official allocator.
        node['management']['ip'] = '172.30.0.5/21'
        core.validate_fab(yaml.safe_dump_all(docs).encode())
        node['management']['ip'] = '172.30.0.6/21'
        with self.assertRaisesRegex(core.Failure, 'control candidate policy'):
            core.validate_fab(yaml.safe_dump_all(docs).encode())

    def test_import_byte_object_and_shape_changes_stop_before_validation(self):
        for target, action in (("fab.yaml", "write"), ("include/wiringd.yaml", "write"),
                               (".registry.yaml", "write"), ("fab.yaml", "remove"),
                               ("include/extra.yaml", "write"), ("result/extra", "write"),
                               ("unexpected", "extra-dir"), ("include/unexpected", "extra-dir"),
                               ("fab.yaml", "symlink")):
            with self.subTest(target=target, action=action):
                result, calls, *_ = self.run_import(mutation=("init", target, action))
                self.assertIsInstance(result, subject.Refusal)
                self.assertEqual(len(calls), 1)

    def test_validation_and_rerun_mutations_are_failures(self):
        for stage, count in (("validate", 2), ("rerun", 3)):
            for target in ("fab.yaml", "include/wiringd.yaml", "source/fab.yaml", "binary"):
                with self.subTest(stage=stage, target=target):
                    result, calls, *_ = self.run_import(mutation=(stage, target, "write"))
                    self.assertIsInstance(result, subject.Refusal)
                    self.assertEqual(len(calls), count)

    def test_import_must_not_mutate_first_fixture_or_verified_tool(self):
        for target in ("source/fab.yaml", "source/include/wiringd.yaml", "binary"):
            with self.subTest(target=target):
                result, calls, *_ = self.run_import(mutation=("init", target, "write"))
                self.assertIsInstance(result, subject.Refusal)
                self.assertEqual(len(calls), 1)

    def test_occupied_destination_preserved_without_any_child(self):
        result, calls, *_, foreign = self.run_import(occupied=True)
        self.assertIsInstance(result, subject.Refusal)
        self.assertEqual(calls, [])
        self.assertEqual(foreign, b"preserve")


class OwnershipTests(ownership.CleanupTests):
    """Reuse established daemon model; synthetic runs prove ownership, not CLI."""
    def run_harness(self, mode):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "docker"
            source = ownership.FAKE_DOCKER.replace("elif a[0] == 'start':", "elif a[0] == 'cp':\n    pass\nelif a[0] == 'start':")
            source = source.replace("elif a[0] == 'inspect':\n    print('0')",
                                    "elif a[0] == 'inspect':\n    print('1' if mode == 'lane_failed' and 'runtime' in s['containers'][a[-1]]['name'] else '0')")
            # Inject explicit deletion refusal, retained object must cause failure.
            source = source.replace("obj = s['containers'].pop(a[-1])", "\n    if mode == 'remove_denied':\n        save(); sys.exit(1)\n    obj = s['containers'].pop(a[-1])")
            fake.write_text(source)
            fake.chmod(0o755)
            # No downloads/CLI in ownership-only model; integrity tested separately.
            python = root / "python3"
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            state_path = root / "state.json"
            state_path.write_text(json.dumps({"containers": {}, "images": {}, "calls": []}))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       FAKE_DOCKER_STATE=str(state_path), FAKE_DOCKER_MODE=mode)
            result = subprocess.run(["bash", str(Path(__file__).with_name("test-hhfab-offline.sh"))],
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, json.loads(state_path.read_text())

    def assert_owned_removed(self, state):
        # Parent asserts exact nonce name/tag + conjunction label on all queries.
        import json
        adjusted = json.loads(json.dumps(state).replace("labapp.hhfab-test.run=", "labapp.bridge-test.run=")
                              .replace("labapp-hhfab-test:", "labapp-bridge-test:"))
        super().assert_owned_removed(adjusted)

    def test_daemon_query_failure_is_cleanup_failure_not_absence(self):
        result, state = self.run_harness("daemon_down")
        self.assertEqual(result.returncode, 1)
        self.assertIn("owned cleanup failed", result.stderr)
        self.assertTrue(any(not obj["name"].endswith("-foreign") for obj in state["containers"].values()))
        first_query = next(i for i, args in enumerate(state["calls"]) if args[:2] == ["container", "ls"])
        self.assertFalse(any(a[0] == "rm" or a[:2] == ["image", "rm"] for a in state["calls"][first_query:]))

    def test_failed_lane_is_aggregate_failure_and_second_lane_runs(self):
        result, state = self.run_harness("lane_failed")
        self.assertEqual(result.returncode, 1)
        runtimes = [args for args in state["calls"] if args[0] == "create" and any("runtime" in arg for arg in args)]
        self.assertEqual(len(runtimes), 2)
        self.assert_owned_removed(state)

    def test_remove_denied_is_failure(self):
        result, state = self.run_harness("remove_denied")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owned cleanup failed", result.stderr)
        self.assertTrue(any(not obj["name"].endswith("-foreign") for obj in state["containers"].values()))


if __name__ == "__main__":
    unittest.main()
