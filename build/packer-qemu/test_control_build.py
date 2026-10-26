"""Offline tests for the fixed non-VM `control-build` task. Synthetic daemon, tiny synthetic hhfab archive and a
synthetic container that writes the fixed result files: no Docker, container, build, download, registry, network,
root, device or VM operation. They prove the source contracts (argv and staged bindings, absent KVM/host-network/
credential widening, cold versus no-op versus warm labelling, fail-closed acceptance, immutable budgets, bounded
disk observations that are explicitly NOT a quota, exact owned cleanup), not that the real official CLI, registry
or runtime works (UNRUN gates in README.md)."""
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import container_runner as cr
import stage_tools as st
import test_container_runner as tc
import test_sentinel as tsn

HERE = os.path.dirname(os.path.abspath(__file__))
MEMBER = b"synthetic hhfab binary\n"
ISO1, ISO2 = b"synthetic control iso one\n" * 40, b"synthetic control iso two\n" * 40
ISO_NAME = "control--control-1--install-usb.iso"


def make_archive(directory):
    """A tiny tar.gz with the sole official member plus matching synthetic pins (the real pins are 59 MB)."""
    path = os.path.join(directory, "hhfab.tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("hhfab-linux-amd64/hhfab")
        info.size, info.mode = len(MEMBER), 0o755
        tar.addfile(info, io.BytesIO(MEMBER))
    return path, pins_for(path)


def pins_for(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    pins = {"hhfab": {"file": st.ARCHIVE_NAME, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
    release = (len(raw), pins["hhfab"]["sha256"], len(MEMBER), hashlib.sha256(MEMBER).hexdigest())
    return pins, release


def fake_release(release):
    module = st._release_module(st.PROVISION_DIR)
    module.PINS = {st.HHFAB_VERSION: release}
    return module


def synthetic_cache_references():
    return tuple((root, manifest, tuple((name, len(MEMBER), hashlib.sha256(MEMBER).hexdigest(), unpacked)
                                       for name, _, _, unpacked in entries))
                 for root, manifest, entries in st.CONTROL_CACHE_REFERENCES)


def write_cache(cache, references):
    cache = os.path.join(cache, 'v1')
    os.mkdir(cache)
    for root, _, entries in references:
        base = os.path.join(cache, root)
        os.mkdir(base)
        for name, _, _, unpacked in entries:
            target = os.path.join(base, name)
            if unpacked:
                os.mkdir(target)
                target = os.path.join(target, 'synthetic-file')
            with open(target, 'wb') as handle:
                handle.write(MEMBER)


class CacheIdentityTests(unittest.TestCase):
    def test_fixed_build_only_references_are_exact_accepted_subset(self):
        rows = st.CONTROL_CACHE_REFERENCES
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(len(entries) for _, _, entries in rows), 19)
        self.assertEqual(sum(size for _, _, entries in rows for _, size, _, _ in entries), 2273598059)
        self.assertEqual(sum(unpacked for _, _, entries in rows for _, _, _, unpacked in entries), 4)
        self.assertNotIn('flatcar-vlab', repr(rows))
        self.assertEqual(st.CONTROL_CACHE_FINGERPRINT, hashlib.sha256(json.dumps(
            rows, separators=(',', ':')).encode('ascii')).hexdigest())

    def test_all_regular_payloads_hash_and_directory_contents_have_safe_fingerprints(self):
        references = synthetic_cache_references()
        with tempfile.TemporaryDirectory() as cache, mock.patch.object(st, 'CONTROL_CACHE_REFERENCES', references):
            write_cache(cache, references)
            receipt = st.verify_control_cache(cache)
            self.assertEqual((receipt['roots'], receipt['regular_payloads_verified'], receipt['unpacked_directories']),
                             (10, 15, 4))
            self.assertFalse(receipt['root_manifest_selection_verified'])
            self.assertFalse(receipt['packed_directory_descriptors_verified'])
            first = next(iter(receipt['unpacked_content']))
            with open(os.path.join(cache, 'v1', first, 'synthetic-file'), 'wb') as handle:
                handle.write(b'changed content')
            self.assertNotEqual(st.verify_control_cache(cache)['unpacked_content'][first]['sha256'],
                                receipt['unpacked_content'][first]['sha256'])
            self.assertNotIn('synthetic-file', json.dumps(receipt))
            self.assertNotIn(MEMBER.decode().strip(), json.dumps(receipt))

    def test_missing_extra_drift_and_aliases_refuse_without_following(self):
        references = synthetic_cache_references()
        root, _, entries = references[0]
        for scenario in ('missing_root', 'extra_root', 'missing_file', 'extra_file', 'drift', 'root_alias', 'file_alias'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as cache, mock.patch.object(
                    st, 'CONTROL_CACHE_REFERENCES', references):
                write_cache(cache, references)
                target = os.path.join(cache, 'v1', root, entries[0][0])
                if scenario == 'missing_root':
                    import shutil
                    shutil.rmtree(os.path.join(cache, 'v1', root))
                elif scenario == 'extra_root':
                    os.mkdir(os.path.join(cache, 'v1', 'unexpected'))
                elif scenario == 'extra_file':
                    open(os.path.join(cache, 'v1', root, 'unexpected'), 'wb').close()
                elif scenario == 'root_alias':
                    os.rename(os.path.join(cache, 'v1', root), os.path.join(cache, 'v1', root + '-moved'))
                    os.symlink(root + '-moved', os.path.join(cache, 'v1', root))
                else:
                    os.unlink(target)
                    if scenario == 'drift':
                        with open(target, 'wb') as handle:
                            handle.write(b'x' * len(MEMBER))
                    elif scenario == 'file_alias':
                        os.symlink('/etc/passwd', target)
                with self.assertRaises((st.StageError, OSError)):
                    st.verify_control_cache(cache)

    def test_cache_version_is_exact_and_cannot_be_a_directory_alias(self):
        references = synthetic_cache_references()
        for scenario in ('missing', 'extra', 'alias'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as cache, mock.patch.object(
                    st, 'CONTROL_CACHE_REFERENCES', references):
                write_cache(cache, references)
                if scenario == 'extra':
                    os.mkdir(os.path.join(cache, 'v2'))
                elif scenario == 'alias':
                    import shutil
                    shutil.rmtree(os.path.join(cache, 'v1'))
                    os.symlink('/etc', os.path.join(cache, 'v1'))
                else:
                    os.rename(os.path.join(cache, 'v1'), os.path.join(cache, 'v2'))
                with self.assertRaises((st.StageError, OSError)):
                    st.verify_control_cache(cache)

    def test_cache_entry_and_byte_caps_refuse(self):
        references = synthetic_cache_references()
        for key in ('CONTROL_CACHE_ENTRY_CAP', 'CONTROL_CACHE_BYTE_CAP'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as cache, mock.patch.object(
                    st, 'CONTROL_CACHE_REFERENCES', references), mock.patch.object(st, key, 1):
                write_cache(cache, references)
                with self.assertRaises(st.StageError):
                    st.verify_control_cache(cache)

    def test_cache_scan_preserves_original_deadline(self):
        references = synthetic_cache_references()
        with tempfile.TemporaryDirectory() as cache, mock.patch.object(st, 'CONTROL_CACHE_REFERENCES', references):
            write_cache(cache, references)
            with self.assertRaises(cr.Expired):
                st.verify_control_cache(cache, check=lambda: (_ for _ in ()).throw(cr.Expired()))


class StageControlCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = os.path.realpath(self.tmp.name)
        self.src, self.ws = os.path.join(base, "src"), os.path.join(base, "ws")
        os.mkdir(self.src, 0o700)
        os.mkdir(self.ws, 0o700)
        self.archive, (self.pins, release) = make_archive(self.src)
        patcher = mock.patch.object(st, "_release_module", return_value=fake_release(release))
        patcher.start()
        self.addCleanup(patcher.stop)

    def stage(self, sources=None, **kw):
        return st.stage_control(self.ws, sources if sources is not None else {"archive": self.archive}, pins=self.pins, **kw)

    def mode(self, *parts):
        return os.stat(os.path.join(self.ws, *parts)).st_mode & 0o777


class StageControlTests(StageControlCase):
    def test_layout_modes_and_empty_docker_config(self):
        staged = self.stage()
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "in"))), ["docker", "hhfab", "wiringd.yaml"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "out"))), ["cache", "home", "tmp", "w1", "w2"])
        for name in os.listdir(os.path.join(self.ws, "out")):
            self.assertEqual(os.listdir(os.path.join(self.ws, "out", name)), [])
        self.assertEqual((self.mode("in", "hhfab"), self.mode("in", "wiringd.yaml"),
                          self.mode("in", "docker", "config.json")), (0o500, 0o400, 0o400))
        with open(os.path.join(self.ws, "in", "docker", "config.json"), "rb") as handle:
            self.assertEqual(handle.read(), b'{"auths":{}}')
        with open(os.path.join(self.ws, "in", "hhfab"), "rb") as handle:
            self.assertEqual(handle.read(), MEMBER)
        self.assertEqual(staged["hhfab_member_sha256"], hashlib.sha256(MEMBER).hexdigest())
        self.assertEqual(staged["wiring_sha256"], st.WIRING_SHA256)
        self.assertEqual(staged["docker_config_sha256"], hashlib.sha256(b'{"auths":{}}').hexdigest())
        self.assertTrue(st.verify_control(self.ws, staged))

    def test_wiring_is_the_in_repo_file_and_pins_match_the_accepted_identities(self):
        with open(st.WIRING_PATH, "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), st.WIRING_SHA256)
        self.assertEqual(st.WIRING_SHA256, "c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a")
        self.assertEqual(st.PINS["hhfab"]["size"], 59692810)
        self.assertEqual(st.PINS["hhfab"]["sha256"], "a8e6d1b8d0f752d7586c29201add3ff174d330c87fa25a3bdadec43f6c1376b6")

    def test_real_release_module_pin_equals_staging_pin_and_binary_identity(self):
        spec = importlib.util.spec_from_file_location(
            "check_release", os.path.join(st.PROVISION_DIR, "hhfab_release.py"))
        release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release)
        size, sha, member_size, member_sha = release.PINS[st.HHFAB_VERSION]
        self.assertEqual((size, sha), (st.PINS["hhfab"]["size"], st.PINS["hhfab"]["sha256"]))
        self.assertEqual((member_size, member_sha),
                         (104890530, "b7a5c7744e3b617d7e76d9ccc9015588a8c32da62623c8ecc114cae24e1a5fcd"))

    def test_staging_refuses_wrong_source_sets_and_workspace_aliases(self):
        for sources in ({}, {"archive": self.archive, "core": self.archive}, {"core": self.archive}):
            with self.subTest(sources=sorted(sources)):
                with self.assertRaises(st.StageError):
                    self.stage(sources)
                self.assertEqual(os.listdir(self.ws), [])
        inside = os.path.join(self.ws, "inside.tgz")
        with open(self.archive, "rb") as handle, open(inside, "wb") as out:
            out.write(handle.read())
        with self.assertRaises(st.StageError):
            self.stage({"archive": inside})

    def test_archive_differing_from_its_pin_is_refused(self):
        for field, value in (("sha256", "0" * 64), ("size", self.pins["hhfab"]["size"] + 1)):
            with self.subTest(field=field):
                ws = tempfile.mkdtemp(dir=os.path.dirname(self.ws))
                pins = {"hhfab": {**self.pins["hhfab"], field: value}}
                with self.assertRaises(st.StageError):
                    st.stage_control(ws, {"archive": self.archive}, pins=pins)

    def test_extra_or_renamed_archive_member_and_changed_binary_are_refused(self):
        for variant in ("extra", "renamed", "changed"):
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as work:
                    work = os.path.realpath(work)
                    ws = os.path.join(work, "ws")
                    os.mkdir(ws, 0o700)
                    path = os.path.join(work, "a.tgz")
                    with tarfile.open(path, "w:gz") as tar:
                        name = "hhfab-linux-amd64/other" if variant == "renamed" else "hhfab-linux-amd64/hhfab"
                        body = b"different\n" if variant == "changed" else MEMBER
                        info = tarfile.TarInfo(name)
                        info.size = len(body)
                        tar.addfile(info, io.BytesIO(body))
                        if variant == "extra":
                            extra = tarfile.TarInfo("hhfab-linux-amd64/README")
                            extra.size = 1
                            tar.addfile(extra, io.BytesIO(b"x"))
                    pins, release = pins_for(path)
                    with mock.patch.object(st, "_release_module", return_value=fake_release(
                            (release[0], release[1], len(MEMBER), release[3]))):
                        with self.assertRaises(st.StageError):
                            st.stage_control(ws, {"archive": path}, pins=pins)

    def test_wiring_not_matching_the_pin_is_refused(self):
        wiring = os.path.join(self.src, "wiringd.yaml")
        with open(wiring, "w") as handle:
            handle.write("kind: Other\n")
        with self.assertRaises(st.StageError):
            self.stage(wiring_path=wiring)

    def test_post_run_tampering_or_extra_input_is_detected(self):
        staged = self.stage()
        path = os.path.join(self.ws, "in", "wiringd.yaml")
        os.chmod(path, 0o600)
        with open(path, "ab") as handle:
            handle.write(b"#")
        self.assertFalse(st.verify_control(self.ws, staged))
        os.chmod(path, 0o600)
        with open(path, "wb") as handle, open(st.WIRING_PATH, "rb") as real:
            handle.write(real.read())
        self.assertTrue(st.verify_control(self.ws, staged))
        with open(os.path.join(self.ws, "in", "extra"), "w") as handle:
            handle.write("x")
        with self.assertRaises(st.StageError):
            st.verify_control(self.ws, staged)

    def test_restrictive_umask_does_not_change_the_fixed_modes(self):
        previous = os.umask(0o077)
        try:
            self.stage()
        finally:
            os.umask(previous)
        self.assertEqual(self.mode("in", "hhfab"), 0o500)


class FixedPlanTests(unittest.TestCase):
    def args(self, mode="control-build"):
        return cr.create_args("n", "l", tc.IMAGE_ID, "1000:1000", "/w", 5, "b", mode)

    def test_fixed_non_vm_profile_has_no_kvm_host_network_ports_credentials_or_privilege(self):
        args = self.args()
        for expected in ("--pull=never", "--restart=no", "--network=bridge", "--cap-drop=ALL", "--no-healthcheck",
                         "--security-opt=no-new-privileges", "--read-only", "--memory=10g", "--memory-swap=10g",
                         "--cpus=5", "--pids-limit=512", "--log-driver=none", "--entrypoint=/bin/bash"):
            self.assertIn(expected, args)
        self.assertEqual(cr.LIMITS["control-build"], cr.LIMITS["sentinel"])
        self.assertNotIn("control-build", cr.VM_MODES)
        for forbidden in ("--device", "--group-add", "--privileged", "--init", "--pid", "--ipc", "--uts", "--userns",
                          "--volume", "-v", "--env", "-e", "--env-file", "--cap-add", "--tmpfs", "--add-host",
                          "--network=host", "--net", "--publish", "-p", "-P", "--publish-all", "--dns", "--link",
                          "--expose", "--sysctl", "--security-opt=seccomp=unconfined", "--gpus"):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "=") for a in args), forbidden)
        self.assertEqual(len([a for a in args if a.startswith("--network")]), 1)
        self.assertEqual(args[-1], cr.CONTROL_SCRIPT)
        mounts = [a for a in args if a.startswith("--mount=")]
        self.assertEqual(mounts, ["--mount=type=bind,src=/w/in,dst=/in,readonly", "--mount=type=bind,src=/w/out,dst=/out"])
        self.assertFalse(any("docker.sock" in a or ".docker" in a for a in args))

    def test_per_file_limit_exceeds_exact_recipe_raw_disk_with_fixed_headroom(self):
        self.assertEqual(cr.CONTROL_RECIPE_DISK_BYTES, 10189046784)
        self.assertEqual(cr.CONTROL_FILE_KIB * 1024, 12 << 30)
        self.assertGreater(cr.CONTROL_FILE_KIB * 1024, cr.CONTROL_RECIPE_DISK_BYTES)
        self.assertEqual((cr.CONTROL_OWNED_CAP, cr.CONTROL_MIN_FREE), (32 << 30, 40 << 30))

    def test_other_modes_keep_their_argv_and_networking(self):
        for mode in cr.MODES:
            if mode == "control-build":
                continue
            args = self.args(mode)
            self.assertEqual("--network=bridge" in args, mode == "qemu-fixture", mode)
            self.assertNotIn(cr.CONTROL_SCRIPT, args)
        self.assertEqual(cr.PROFILES["control-build"], (1800, 900))

    def test_script_is_exactly_the_declared_official_plan(self):
        script = cr.CONTROL_SCRIPT
        self.assertEqual(script.count("/in/hhfab init"), 2)
        self.assertEqual(script.count("/in/hhfab validate"), 2)
        self.assertEqual(script.count("/in/hhfab build"), 3)
        build = ("build --hydrate-mode if-not-present --build-controls=true --build-gateways=false --build-mode=iso "
                 "--workdir /out/w")
        self.assertEqual(script.count(build), 3)
        self.assertEqual(script.count("--import-host-upstream"), 2)
        self.assertEqual(script.count("--registry-repo ghcr.io --registry-prefix githedgehog --wiring /in/wiringd.yaml"), 2)
        order = [script.index((f"asserted {n} " if n.startswith("assert") else f"step {n} ")) for n in cr.CONTROL_STEPS]
        self.assertEqual(order, sorted(order))
        self.assertEqual(script.count(cr.CONTROL_ENV), 7)
        self.assertEqual(script.count("env -i"), 8)           # seven hhfab calls plus the assertion
        for word in ("PrepareVLAB", "prepare", "vlab", "qemu", "ssh", "kubeconfig", "systemctl", "sudo", "curl", "wget",
                     "docker ", "--force", "--clean", "--config", "--extra-cache-dir", "--gateway=true", "mount",
                     "ip link", "HHFAB_WORK_DIR", "HHFAB_CACHE_DIR", "XDG"):
            self.assertNotIn(word, script.replace("DOCKER_CONFIG=/in/docker", ""), word)
        self.assertIn("DOCKER_CONFIG=/in/docker", cr.CONTROL_ENV)
        self.assertIn("HHFAB_PREVIEW=true", cr.CONTROL_ENV)
        self.assertIn("HOME=/out/home", cr.CONTROL_ENV)
        self.assertEqual(script.count("--cache-dir /out/cache"), 7)
        self.assertTrue(script.startswith(f"ulimit -f {cr.CONTROL_FILE_KIB} || exit 125; umask 077; "))
        self.assertTrue(script.endswith("; exit 0"))

    def test_script_parses_under_bash(self):
        done = subprocess.run(["/bin/bash", "-n", "-c", cr.CONTROL_SCRIPT], capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        done = subprocess.run(["/bin/bash", "-n", "-c", cr.ENTRY], capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_default_entry_is_unchanged_and_not_widened(self):
        self.assertIn("exec /usr/bin/timeout --kill-after=5s", cr.ENTRY)


class UpstreamAssertionTests(unittest.TestCase):
    GOOD = ("spec:\n  config:\n    registry:\n      mode: upstream\n      upstream:\n        repo: ghcr.io\n"
            "        prefix: githedgehog\n        noTLSVerify: false\n        username:\n        password:\n")

    def check(self, text):
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, "fab.yaml")
            with open(path, "w") as handle:
                handle.write(text)
            return subprocess.run([sys.executable, "-I", "-B", "-c", cr.ASSERT_PROGRAM, path],
                                  capture_output=True).returncode

    def test_anonymous_upstream_with_exact_repo_and_prefix_passes(self):
        self.assertEqual(self.check(self.GOOD), 0)
        self.assertEqual(self.check(self.GOOD.replace("username:\n", 'username: ""\n')), 0)

    def test_other_generated_passwords_and_tokens_do_not_affect_registry_assertion(self):
        full = self.GOOD + ('    control:\n      joinToken: secret-token\n'
                            '      defaultUser:\n        password: secret-hash\n'
                            '    fabric:\n      defaultSwitchUsers:\n'
                            '        admin:\n          password: secret-hash\n'
                            '---\nkind: ControlNode\nmetadata:\n  name: control-1\n')
        self.assertEqual(self.check(full), 0)
        self.assertNotEqual(self.check(self.GOOD.replace('    registry:', '    unrelated:')), 0)
        self.assertNotEqual(self.check(self.GOOD.replace('  config:', '  unrelated:')), 0)

    def test_every_deviation_is_refused(self):
        variants = {
            "airgap": self.GOOD.replace("mode: upstream", "mode: airgap"),
            "no_upstream_mode": self.GOOD.replace("      mode: upstream\n", ""),
            "other_repo": self.GOOD.replace("ghcr.io", "example.com"),
            "other_prefix": self.GOOD.replace("githedgehog", "someone"),
            "no_tls_verify": self.GOOD.replace("noTLSVerify: false", "noTLSVerify: true"),
            "username": self.GOOD.replace("username:\n", "username: bob\n"),
            "password": self.GOOD.replace("password:\n", "password: hunter2\n"),
            "missing_username": self.GOOD.replace("        username:\n", ""),
            "duplicate_repo": self.GOOD + "        repo: ghcr.io\n",
        }
        for name, text in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(self.check(text), 0)
        self.assertNotEqual(self.check("x" * 1048577), 0)


class MeasureTests(unittest.TestCase):
    def test_counts_names_and_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as work:
            work = os.path.realpath(work)
            outside = os.path.join(work, "outside")
            with open(outside, "wb") as handle:
                handle.write(b"x" * 100000)
            tree = os.path.join(work, "tree")
            os.makedirs(os.path.join(tree, "d"))
            with open(os.path.join(tree, "d", "f"), "wb") as handle:
                handle.write(b"y" * 5000)
            os.symlink(outside, os.path.join(tree, "link"))
            logical, allocated, entries = cr.measure_tree(tree)
            self.assertEqual(entries, 3)
            self.assertGreaterEqual(logical, 5000)
            self.assertLess(logical, 100000)
            self.assertGreaterEqual(allocated, 0)
            with self.assertRaises(cr.OutputBound):
                cr.measure_tree(tree, limit=2)


class ControlDaemon(tsn.SentinelDaemon):
    """Synthetic daemon whose 'container' writes the fixed control-build result files for a named scenario."""

    def __init__(self, clock, scenario="ok", run_seconds=120.0, **kw):
        super().__init__(clock, **kw)
        self.scenario, self.run_seconds = scenario, run_seconds

    def start(self, c):
        mount = next(a for a in c["args"] if a.endswith(",dst=/out"))
        out = mount.split("src=")[1].split(",")[0]
        scenario = self.scenario
        write_cache(os.path.join(out, 'cache'), st.CONTROL_CACHE_REFERENCES)
        if scenario == 'cache_mismatch':
            first = st.CONTROL_CACHE_REFERENCES[0]
            with open(os.path.join(out, 'cache', 'v1', first[0], first[2][0][0]), 'ab') as handle:
                handle.write(b'drift')
        steps = [(n, 0, 1500 + 100 * i) for i, n in enumerate(cr.CONTROL_STEPS)]
        if scenario == "step_fail":
            steps = steps[:3] + [("cold", 1, 900)]
        if scenario == "bad_order":
            steps[3], steps[4] = steps[4], steps[3]
        if scenario == "slow":
            steps[3] = ("cold", 0, cr.CONTROL_MS_CAP + 1)
        if scenario == "no_steps":
            steps = []
        if scenario == "unknown_step":
            steps[0] = ("secrettoken", 1, 900)
        self.write(out, "steps", "".join(f"{n} {code} {ms}\n" for n, code, ms in steps))
        for n, _, _ in steps:
            self.write(out, n + ".out", "ok\n")
            self.write(out, n + ".err", "failure detail\n" if scenario == "step_fail" else "")
        self.write(out, "sizes", "cache_cold 2000000 2100000\nw1_cold 3000000 3100000\n"
                                 "cache_warm 2000100 2100100\nw2_warm 3000000 3100000\n")
        cold = f"cold {len(ISO1)} 4242 1700000000\n"
        noop = cold.replace("cold", "noop", 1)
        if scenario == "noop_rebuilt":
            noop = f"noop {len(ISO1)} 4243 1700000500\n"
        self.write(out, "isostat", cold + noop)
        if scenario == "missing_log":
            os.unlink(os.path.join(out, "cold.out"))
        if scenario == "oversize_log":
            with open(os.path.join(out, "cold.err"), "wb") as handle:
                handle.truncate(cr.STEP_CAP + 1)
        if scenario == "bad_sizes":
            self.write(out, "sizes", "cache_cold two 1\n")
        if scenario == "bad_isostat":
            self.write(out, "isostat", cold)
        for name, body in (("w1", ISO1), ("w2", ISO2)):
            result = os.path.join(out, name, "result")
            os.makedirs(result)
            if scenario == "missing_iso" and name == "w2":
                continue
            if scenario == "symlink_iso" and name == "w1":
                os.symlink("/etc/passwd", os.path.join(result, ISO_NAME))
                continue
            with open(os.path.join(result, ISO_NAME), "wb") as handle:
                handle.write(body)
            if scenario == "two_isos" and name == "w1":
                with open(os.path.join(result, "control--control-2--install-usb.iso"), "wb") as handle:
                    handle.write(body)
            if scenario == "wrong_size" and name == "w1":
                with open(os.path.join(result, ISO_NAME), "ab") as handle:
                    handle.write(b"x")
            if scenario == "empty_iso" and name == "w2":
                open(os.path.join(result, ISO_NAME), "wb").close()
        if scenario == "tamper":
            path = os.path.join(os.path.dirname(out), "in", "wiringd.yaml")
            os.chmod(path, 0o600)
            with open(path, "ab") as handle:
                handle.write(b"#")
        code = {"bad_exit": 1}.get(scenario, 0)
        c["state"], c["code"] = "running", code
        c["exit_at"] = float("inf") if scenario == "never_exits" else self.clock.now + self.run_seconds

    @staticmethod
    def write(out, name, text):
        with open(os.path.join(out, name), "w") as handle:
            handle.write(text)


class ControlCase(tc.RunnerCase):
    def setUp(self):
        super().setUp()
        src = os.path.join(os.path.dirname(self.root), "src")
        os.mkdir(src, 0o700)
        archive, (pins, release) = make_archive(src)
        self.sources = {"archive": archive}
        real = st.stage_control
        for patcher in (mock.patch.object(cr, "PREPARED_RUNTIME", tsn.RUNTIME),
                        mock.patch.object(cr, "free_bytes", return_value=1 << 50),
                        mock.patch.object(st, "CONTROL_CACHE_REFERENCES", synthetic_cache_references()),
                        mock.patch.object(st, "_release_module", return_value=fake_release(release)),
                        mock.patch.object(cr.stage_tools, "stage_control",
                                          side_effect=lambda ws, sources, check=st._noop: real(
                                              ws, sources, check, pins=pins))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_control(self, scenario="ok", delay=0.0, daemon_kw=None, **kw):
        daemon = ControlDaemon(self.clock, scenario, **(daemon_kw or {}))
        result = cr.run_probe(tsn.RUNTIME["image_id"], self.root, self.ledger, daemon, clock=self.clock,
                              sleep=self.clock.sleep, admitted_at=self.clock() - delay, uid=os.getuid() or 1000,
                              mode="control-build", sources=self.sources, **kw)
        return result, daemon

    def assert_fully_cleaned(self, result, daemon):
        self.assertEqual(result["cleanup"], "verified")
        self.assertEqual(result["workspace"], "removed")
        self.assertEqual(daemon.containers, {})
        self.assertEqual(os.listdir(self.root), [])
        with open(result["ledger"]) as handle:
            self.assertEqual(json.load(handle)["state"], "released")


class AcceptanceTests(ControlCase):
    def test_complete_cold_noop_and_fresh_workspace_warm_run_is_accepted_and_disposed(self):
        result, daemon = self.run_control()
        self.assertEqual((result["outcome"], result["reason"]), ("accepted", None), result)
        self.assert_fully_cleaned(result, daemon)
        evidence = result["evidence"]
        self.assertEqual(evidence["noop"], "unchanged_metadata_noop_candidate")
        self.assertEqual([s[0] for s in evidence["steps"]], list(cr.CONTROL_STEPS))
        self.assertEqual(evidence["iso"]["w1"], {"sha256": hashlib.sha256(ISO1).hexdigest(), "bytes": len(ISO1),
                                                 "name": ISO_NAME})
        self.assertEqual(evidence["iso"]["w2"]["sha256"], hashlib.sha256(ISO2).hexdigest())
        self.assertFalse(evidence["iso_equal"])
        self.assertEqual(evidence["warm_cache_growth_apparent_kib"], 100)
        self.assertEqual(evidence["timing_seconds"]["cold"], 1.8)
        self.assertEqual(evidence["claims"], cr.CONTROL_CLAIMS)
        self.assertFalse(evidence["claims"]["disk_quota"])
        self.assertFalse(evidence["limits"]["quota"])
        self.assertEqual(evidence["claims"]["peak"], "sampled-lower-bound")
        for key in ("at_exit", "peak_sampled"):
            self.assertGreater(evidence["owned_bytes"][key]["logical"], 0)
        self.assertGreater(evidence["owned_bytes"]["peak_sampled"]["samples"], 0)
        self.assertEqual(evidence["network"], "docker-bridge-outbound")
        self.assertEqual(evidence["image_id"], tsn.RUNTIME["image_id"])
        self.assertEqual(evidence["inputs"]["wiring_sha256"], st.WIRING_SHA256)
        text = json.dumps(result)
        for secret in ("auths", "password", "username", "fab.yaml"):
            self.assertNotIn(secret, text)

    def test_in_place_second_build_that_replaced_the_iso_is_labelled_rebuilt_not_noop(self):
        result, _ = self.run_control("noop_rebuilt")
        self.assertEqual(result["outcome"], "accepted", result)
        self.assertEqual(result["evidence"]["noop"], "rebuilt_in_place")

    def test_ledger_binds_the_fixed_mode_and_runtime_identity(self):
        self.run_control()
        record = self.record()
        self.assertEqual((record["mode"], record["image"]), ("control-build", tsn.RUNTIME["image_id"]))
        self.assertTrue(cr.released_record(record))
        self.assertFalse(cr.released_record({**record, "image": cr.PINNED_IMAGE}))

    def test_single_create_with_fixed_argv_and_one_start_per_run(self):
        _, daemon = self.run_control()
        creates = [c[0] for c in daemon.calls if c[0][0] == "create"]
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0][-1], cr.CONTROL_SCRIPT)
        self.assertNotIn("--device", " ".join(creates[0]))
        self.assertEqual([c[0][0] for c in daemon.calls].count("start"), 1)


class FailClosedTests(ControlCase):
    def test_every_incomplete_or_inconsistent_run_fails_and_is_still_fully_cleaned(self):
        reasons = {"step_fail": "build_failed", "bad_order": "build_failed", "slow": "build_failed",
                   "no_steps": "build_failed", "bad_sizes": "invalid_step_evidence",
                   "bad_isostat": "invalid_step_evidence", "missing_iso": "iso_missing_or_invalid",
                   "symlink_iso": "iso_missing_or_invalid", "two_isos": "iso_missing_or_invalid",
                   "wrong_size": "iso_missing_or_invalid", "empty_iso": "iso_missing_or_invalid",
                   "bad_exit": "unexpected_exit", "tamper": "staged_inputs_changed",
                   "missing_log": "invalid_step_evidence", "oversize_log": "invalid_step_evidence",
                   "unknown_step": "build_failed", "cache_mismatch": "cache_identity_mismatch"}
        for scenario, reason in reasons.items():
            with self.subTest(scenario=scenario):
                result, daemon = self.run_control(scenario)
                self.assertEqual(result["outcome"], "failed", result)
                self.assertEqual(result["reason"], reason)
                self.assert_fully_cleaned(result, daemon)

    def test_failing_step_keeps_only_closed_summary_and_log_hashes(self):
        result, _ = self.run_control("step_fail")
        failed = result["evidence"]["failed_step"]
        self.assertEqual((failed["name"], failed["exit"]), ("cold", 1))
        self.assertEqual(failed, {"name": "cold", "exit": 1})
        self.assertNotIn("failure detail", json.dumps(result))
        self.assertEqual(set(result["evidence"]["logs"]["cold.out"]), {"bytes", "sha256"})

    def test_unknown_peer_step_names_are_never_retained(self):
        result, _ = self.run_control("unknown_step")
        self.assertEqual(result["outcome"], "failed")
        self.assertNotIn("secrettoken", json.dumps(result))

    def test_oom_kill_cannot_pass(self):
        result, daemon = self.run_control(daemon_kw={"mode": "oom"})
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "unexpected_exit"))
        self.assert_fully_cleaned(result, daemon)

    def test_overflow_of_the_sampled_owned_allocation_bound_fails_and_cleans(self):
        with mock.patch.object(cr, "CONTROL_OWNED_CAP", 1):
            result, daemon = self.run_control()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "output_bound_exceeded"))
        self.assert_fully_cleaned(result, daemon)

    def test_entry_count_overflow_fails_closed(self):
        with mock.patch.object(cr, "CONTROL_ENTRY_CAP", 3), mock.patch.object(
                cr, "measure_tree", side_effect=cr.OutputBound("x")):
            result, daemon = self.run_control()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "output_bound_exceeded"))
        self.assert_fully_cleaned(result, daemon)

    def test_container_that_never_exits_is_stopped_at_the_original_deadline_and_cleaned(self):
        result, daemon = self.run_control("never_exits")
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "host_expiry"))
        self.assert_fully_cleaned(result, daemon)
        self.assertLessEqual(self.clock.now, 1000 + 1800 + 900)

    def test_client_loss_by_sigterm_while_polling_cleans_the_owned_container_and_workspace(self):
        def term(args):
            if args[0] == "inspect" and "{{.State.Status}}" in args[3]:
                os.kill(os.getpid(), signal.SIGTERM)
        result, daemon = self.run_control(daemon_kw={"on_call": term}, handle_signals=True)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "cancelled"))
        self.assert_fully_cleaned(result, daemon)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_cancellation_during_start_holds_like_every_other_mode(self):
        result, daemon = self.run_control(daemon_kw={"mode": "start_interrupt"})
        self.assertEqual((result["outcome"], result["reason"]), ("hold", "ambiguous_start"))
        self.assertEqual(daemon.containers, {})

    def test_unremovable_container_holds_instead_of_passing(self):
        result, _ = self.run_control(daemon_kw={"mode": "rm_lost"})
        self.assertEqual(result["outcome"], "hold")
        self.assertEqual(self.record()["state"], "hold")


class BudgetAndAdmissionTests(ControlCase):
    def test_budget_is_immutable_work_1800_plus_cleanup_900_from_admission(self):
        self.run_control()
        record = self.record()
        self.assertEqual(record["work_deadline"] - record["admitted_at"], 1800)
        self.assertEqual(record["deadline"] - record["work_deadline"], 900)

    def test_nearly_exhausted_budget_never_reaches_create(self):
        result, daemon = self.run_control(delay=1790.0)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "budget_exhausted"))
        self.assertNotIn("create", [c[0][0] for c in daemon.calls])
        self.assertEqual(os.listdir(self.root), [])

    def test_missing_free_space_refuses_before_workspace_or_docker(self):
        with mock.patch.object(cr, "free_bytes", return_value=cr.CONTROL_MIN_FREE - 1):
            result, daemon = self.run_control()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "insufficient_disk_headroom"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(self.record()["state"], "released")

    def test_staging_failure_leaves_no_container_and_removes_the_workspace(self):
        bad = os.path.join(os.path.dirname(self.root), "src", "bad.tgz")
        with open(bad, "wb") as handle:
            handle.write(b"not an archive")
        self.sources = {"archive": bad}
        result, daemon = self.run_control()
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "staging_rejected"))
        self.assertEqual(daemon.calls, [])
        self.assertEqual(os.listdir(self.root), [])

    def test_wrong_source_keys_or_image_are_refused(self):
        for sources in ({}, {"archive": "/x", "core": "/y"}, None):
            with self.subTest(sources=sources):
                with self.assertRaises(ValueError):
                    cr.run_probe(tsn.RUNTIME["image_id"], self.root, self.ledger, ControlDaemon(self.clock),
                                 clock=self.clock, sleep=self.clock.sleep, uid=os.getuid() or 1000,
                                 mode="control-build", sources=sources)
        with self.assertRaises(ValueError):
            cr.run_probe(cr.PINNED_IMAGE, self.root, self.ledger, ControlDaemon(self.clock), clock=self.clock,
                         sleep=self.clock.sleep, uid=os.getuid() or 1000, mode="control-build",
                         sources=self.sources)


class CliTests(unittest.TestCase):
    def run_main(self, *argv):
        with tempfile.TemporaryDirectory() as work:
            work = os.path.realpath(work)
            root, ledger = os.path.join(work, "ws"), os.path.join(work, "ledger")
            os.mkdir(root, 0o700)
            os.mkdir(ledger, 0o700)
            out = io.StringIO()
            err = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                code = cr.main(["--workspace-root", root, "--ledger-dir", ledger, *argv])
            return code, out.getvalue(), err.getvalue()

    def test_plan_only_default_prints_the_fixed_non_vm_networked_plan_without_docker(self):
        code, out, _ = self.run_main("--mode", "control-build", "--archive-file", "/tmp/hhfab.tgz")
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual((plan["executed"], plan["network"], plan["image"]),
                         (False, "bridge", cr.PREPARED_RUNTIME["image_id"]))
        self.assertFalse(any(a.startswith("--device") for a in plan["create"]))

    def test_inputs_other_than_the_archive_are_usage_errors(self):
        for argv in (("--mode", "control-build"), ("--mode", "control-build", "--archive-file", "relative"),
                     ("--mode", "control-build", "--archive-file", "/tmp/a", "--core-file", "/tmp/b"),
                     ("--mode", "probe", "--archive-file", "/tmp/a")):
            with self.subTest(argv=argv):
                code, _, _ = self.run_main(*argv)
                self.assertEqual(code, cr.EXIT["usage"])

    def test_supervise_profiles_do_not_include_the_new_mode(self):
        import supervise
        self.assertNotIn("control-build", supervise.PROFILES)


if __name__ == "__main__":
    unittest.main()
