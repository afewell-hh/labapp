"""Offline synthetic tests for configure-student-kubeconfig.py.

Public invented data only. The native kubectl boundary is a MOCK: `bounded` is replaced by a fake that
loads the staged file as JSON (optionally behind comment lines) and renders JSON or a YAML-shaped
text. That is not native YAML parsing and proves nothing about real kubectl 1.35.0 interoperability.
No network, no credential files, no real kubectl execution, no cluster.
"""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import unittest
from unittest.mock import patch

import hhfab_release as release

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("csk", HERE / "configure-student-kubeconfig.py")
csk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csk)

FAKE_KUBECTL = b"synthetic kubectl bytes, never executed"
YAML_HEADER = "# synthetic native yaml\n"


def b64(text):
    return base64.b64encode(text.encode()).decode()


def fake_load(data):
    lines = [line for line in data.decode().splitlines() if not line.startswith("#")]
    return json.loads("\n".join(lines))


def render(document, output_format):
    document = copy.deepcopy(document)
    document.setdefault("preferences", {})
    if output_format == "json":
        return json.dumps(document).encode()
    for key in ("clusters", "users", "contexts"):  # native ordering may differ from input
        document[key] = list(reversed(document[key]))
    return (YAML_HEADER + json.dumps(document, indent=2)).encode()


def kube(context, cluster, user, item, namespace="", current=""):
    body = {"cluster": cluster, "user": user}
    if namespace:
        body["namespace"] = namespace
    return {"apiVersion": "v1", "kind": "Config", "current-context": current,
            "clusters": [{"name": cluster, "cluster": {
                "server": item["server"], "certificate-authority-data": item["ca"]}}],
            "users": [{"name": user, "user": {
                "client-certificate-data": item["cert"], "client-key-data": item["key"]}}],
            "contexts": [{"name": context, "context": body}]}


def binding(prefix, number=1):
    return {"server": "https://%s.invalid:6443" % prefix, "ca": b64(prefix + "-ca"),
            "cert": b64("%s-cert-%d" % (prefix, number)), "key": b64("%s-key-%d" % (prefix, number))}


def private_write(path, data):
    Path(path).write_bytes(data)
    Path(path).chmod(0o600)


class PinTests(unittest.TestCase):
    def test_pin_matches_installer_and_bounds(self):
        installer_spec = importlib.util.spec_from_file_location(
            "kinstaller", HERE / "install-kubectl.py")
        installer = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer)
        pin = installer.PINS["1.35.0"]
        self.assertEqual(csk.KUBECTL_PIN["size"], pin["size"])
        self.assertEqual(csk.KUBECTL_PIN["sha256"], pin["sha256"])
        self.assertEqual((csk.KUBECTL_PIN["version"], csk.KUBECTL_PIN["platform"]),
                         ("1.35.0", "linux/amd64"))
        self.assertEqual((csk.KUBECTL_PIN["size"], csk.KUBECTL_PIN["sha256"]), (
            58597560, "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989"))
        self.assertEqual((csk.TOTAL, csk.CHILD, csk.INPUT_LIMIT, csk.OUTPUT_LIMIT),
                         (30, 10, 65536, 262144))
        self.assertEqual(csk.BINDINGS, (("vlab", "labapp-vlab"),
                                        ("k3d-k3d-observability", "labapp-management")))


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.out = self.state / "config"
        self.kubectl = self.root / "kubectl"
        self.kubectl.write_bytes(FAKE_KUBECTL)
        self.kubectl.chmod(0o755)
        pin = patch.dict(csk.KUBECTL_PIN, {"size": len(FAKE_KUBECTL),
                                           "sha256": hashlib.sha256(FAKE_KUBECTL).hexdigest()})
        pin.start()
        self.addCleanup(pin.stop)
        self.vlab, self.mgmt = self.root / "vlab.src", self.root / "mgmt.src"
        self.vl, self.mg = binding("vlab"), binding("mgmt")
        self.write_sources()
        self.calls, self.hook = [], None
        fake = patch.object(csk, "bounded", self.fake_bounded)
        fake.start()
        self.addCleanup(fake.stop)

    # --- fake native boundary (MOCK) ---
    def fake_bounded(self, args, seconds, limit=None, env=None, **kwargs):
        self.calls.append({"args": list(args), "seconds": seconds, "limit": limit, "env": env})
        if self.hook is not None:
            replaced = self.hook(len(self.calls), args)
            if replaced is not None:
                return replaced
        try:
            document = fake_load(Path(args[2]).read_bytes())
        except (ValueError, OSError):
            return 1, b""
        return 0, render(document, args[-1])

    def write_sources(self, vlab_extra=None):
        document = kube("default", "vlab-cluster", "vlab-user", self.vl, current="default")
        if vlab_extra:
            vlab_extra(document)
        private_write(self.vlab, json.dumps(document).encode())
        private_write(self.mgmt, render(kube("admin@k3d", "k3d-cluster", "k3d-admin", self.mg), "yaml"))

    def argv(self, **override):
        values = {"kubectl": self.kubectl, "vlab-config": self.vlab,
                  "management-config": self.mgmt, "output": self.out}
        values.update(override)
        return [item for key, value in values.items() for item in ("--" + key, str(value))]

    def run_main(self, **override):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = csk.main(self.argv(**override))
        for secret in (self.vl, self.mg):
            for field in secret.values():
                self.assertNotIn(field, out.getvalue() + err.getvalue())
        return code, out.getvalue(), err.getvalue()

    def names(self):
        return sorted(path.name for path in self.state.iterdir())

    def published(self):
        return csk.target_state(csk.parse_config(fake_load(self.out.read_bytes())))

    def snapshot(self):
        info = self.out.stat()
        return (self.out.read_bytes(), info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)

    def edit_output(self, change):
        document = fake_load(self.out.read_bytes())
        change(document)
        self.out.write_bytes(render(document, "yaml"))

    def install(self):
        code, out, _ = self.run_main()
        self.assertEqual((code, json.loads(out)), (0, {"status": "installed"}))
        self.calls.clear()  # later hooks count only the native calls of the run under test


class InstallTests(Base):
    def test_fresh_install_yaml_args_env_and_reconstruction(self):
        captured = {}

        def hook(number, args):
            if Path(args[2]).name == "candidate-input.json":
                captured["input"] = Path(args[2]).read_bytes()
        self.hook = hook
        code, out, err = self.run_main()
        self.assertEqual((code, json.loads(out), err), (0, {"status": "installed"}, ""))
        self.assertEqual(self.names(), ["config"])
        info = self.out.stat()
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid),
                         (0o600, 1, os.geteuid()))
        text = self.out.read_text()
        self.assertTrue(text.startswith(YAML_HEADER))
        with self.assertRaises(ValueError):
            json.loads(text)  # student output is the native YAML rendering, not JSON
        state, current = self.published()
        self.assertEqual(current, "vlab")
        self.assertEqual(state["vlab"], {**self.vl, "namespace": ""})
        self.assertEqual(state["k3d-k3d-observability"], {**self.mg, "namespace": ""})
        self.assertEqual([c["args"][-1] for c in self.calls], ["json", "json", "yaml", "json"])
        stages = set()
        for call in self.calls:
            args = call["args"]
            self.assertEqual(args[:2], [str(self.kubectl), "--kubeconfig"])
            self.assertEqual(args[3:7], ["config", "view", "--raw=true", "-o"])
            self.assertEqual(len(args), 8)
            for forbidden in ("--flatten", "--flatten=true", "--minify", "--raw=false"):
                self.assertNotIn(forbidden, args)
            staged = Path(args[2])
            self.assertTrue(staged.parent.name.startswith(csk.STAGE_PREFIX))
            self.assertEqual(staged.parent.parent, self.state)
            stages.add(staged.parent)
            self.assertNotIn(args[2], (str(self.vlab), str(self.mgmt), str(self.out)))
            home = staged.parent / "home"
            self.assertEqual(call["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(home)})
            self.assertEqual(call["limit"], 262144)
            self.assertTrue(0 < call["seconds"] <= 10)
        self.assertEqual(len(stages), 1)
        # Native input is rebuilt from validated state (normalized names), never raw source bytes.
        rebuilt = json.loads(captured["input"])
        self.assertEqual(captured["input"], csk.build_config(
            {"vlab": {**self.vl, "namespace": ""}, "k3d-k3d-observability": {**self.mg, "namespace": ""}},
            "vlab"))
        self.assertEqual([c["name"] for c in rebuilt["contexts"]], ["vlab", "k3d-k3d-observability"])
        self.assertEqual({c["name"] for c in rebuilt["clusters"]}, {"labapp-vlab", "labapp-management"})
        self.assertNotIn(b"default", captured["input"])

    def test_namespace_preserved_and_status_line(self):
        self.write_sources(lambda d: d["contexts"][0]["context"].update(namespace="lab-one"))
        code, out, err = self.run_main()
        self.assertEqual((code, out, err), (0, '{"status": "installed"}\n', ""))
        self.assertEqual(self.published()[0]["vlab"]["namespace"], "lab-one")

    def test_unchanged_rerun_keeps_inode_mode_and_times_without_candidate_work(self):
        self.install()
        before = self.snapshot()
        self.calls.clear()
        code, out, _ = self.run_main()
        self.assertEqual((code, json.loads(out)), (0, {"status": "unchanged"}))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual([c["args"][-1] for c in self.calls], ["json", "json", "json"])
        self.assertEqual(self.names(), ["config"])

    def test_native_use_context_reordering_accepted_selection_preserved_and_refresh(self):
        self.install()

        def switch(document):  # what native use-context + serialization may do: selection, order
            document["current-context"] = "k3d-k3d-observability"
            document["extensions"] = None
            document["preferences"] = {}
            document["contexts"].reverse()
            for entry in document["users"]:
                entry["user"].update({"exec": None, "auth-provider": None, "token": ""})
        self.edit_output(switch)
        before = self.snapshot()
        code, out, _ = self.run_main()
        self.assertEqual((code, json.loads(out)), (0, {"status": "unchanged"}))
        self.assertEqual(self.snapshot(), before)
        self.mg = binding("mgmt", 2)  # same-binding fake credential refresh
        self.write_sources()
        code, out, _ = self.run_main()
        self.assertEqual((code, json.loads(out)), (0, {"status": "updated"}))
        state, current = self.published()
        self.assertEqual(current, "k3d-k3d-observability")
        self.assertEqual(state["k3d-k3d-observability"]["cert"], self.mg["cert"])
        self.assertEqual(state["vlab"]["cert"], self.vl["cert"])
        self.assertEqual(self.names(), ["config"])
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)

    def test_refresh_with_vlab_selected_preserves_vlab(self):
        self.install()
        self.vl = binding("vlab", 2)
        self.write_sources()
        self.assertEqual(self.run_main()[1], '{"status": "updated"}\n')
        self.assertEqual(self.published()[1], "vlab")

    def test_combined_output_uses_output_bound_on_rerun_and_refresh(self):
        self.vl["cert"] = b64("PUBLIC INVENTED VLAB CERTIFICATE " + "V" * 26000)
        self.mg["cert"] = b64("PUBLIC INVENTED MANAGEMENT CERTIFICATE " + "M" * 26000)
        self.write_sources()
        self.assertLess(self.vlab.stat().st_size, csk.INPUT_LIMIT)
        self.assertLess(self.mgmt.stat().st_size, csk.INPUT_LIMIT)
        self.install()
        self.assertGreater(self.out.stat().st_size, csk.INPUT_LIMIT)
        self.assertLess(self.out.stat().st_size, csk.OUTPUT_LIMIT)
        before = self.snapshot()
        self.assertEqual(self.run_main()[1], '{"status": "unchanged"}\n')
        self.assertEqual(self.snapshot(), before)
        self.mg["key"] = b64("PUBLIC INVENTED RENEWED MANAGEMENT KEY")
        self.write_sources()
        self.assertEqual(self.run_main()[1], '{"status": "updated"}\n')
        self.assertEqual(self.published()[0]["k3d-k3d-observability"]["key"], self.mg["key"])
        self.assertEqual(self.names(), ["config"])


class RefusalTests(Base):
    def assert_refused(self, expect_calls=None):
        code, out, err = self.run_main()
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("configure-student-kubeconfig: "))
        self.assertEqual(len(err.splitlines()), 1)
        self.assertEqual(self.names(), [])
        self.assertNotIn("yaml", [c["args"][-1] for c in self.calls])  # no candidate work happened
        if expect_calls is not None:
            self.assertEqual(len(self.calls), expect_calls)

    def test_pin_mismatch_before_any_invocation(self):
        for name, damage in {
            "size": lambda: self.kubectl.write_bytes(FAKE_KUBECTL + b"x"),
            "hash": lambda: self.kubectl.write_bytes(FAKE_KUBECTL[:-1] + b"X"),
            "missing": lambda: self.kubectl.unlink(),
            "symlink": lambda: (self.kubectl.unlink(), self.kubectl.symlink_to(self.vlab)),
            "writable": lambda: self.kubectl.chmod(0o775),
            "nonexec": lambda: self.kubectl.chmod(0o644),
        }.items():
            with self.subTest(name):
                self.kubectl.write_bytes(FAKE_KUBECTL)
                self.kubectl.chmod(0o755)
                damage()
                self.assert_refused(expect_calls=0)
                if self.kubectl.is_symlink():
                    self.kubectl.unlink()

    def test_pin_rechecked_before_every_invocation(self):
        def tamper(number, args):
            if number == 1:
                self.kubectl.write_bytes(FAKE_KUBECTL[:-1] + b"X")
        self.hook = tamper
        self.assert_refused(expect_calls=1)

    def test_forbidden_or_unknown_mechanisms_refused_after_only_the_safe_view(self):
        def user(change):
            return lambda d: change(d["users"][0]["user"])

        def cluster(change):
            return lambda d: change(d["clusters"][0]["cluster"])
        cases = {
            "exec": user(lambda u: u.update({"exec": {"command": "x"}})),
            "auth-provider": user(lambda u: u.update({"auth-provider": {"name": "x"}})),
            "token": user(lambda u: u.update({"token": "t"})),
            "tokenFile": user(lambda u: u.update({"tokenFile": "/x"})),
            "password": user(lambda u: u.update({"password": "p"})),
            "username": user(lambda u: u.update({"username": "u"})),
            "as": user(lambda u: u.update({"as": "root"})),
            "as-uid": user(lambda u: u.update({"as-uid": "1"})),
            "as-groups": user(lambda u: u.update({"as-groups": ["g"]})),
            "as-user-extra": user(lambda u: u.update({"as-user-extra": {"a": ["b"]}})),
            "client-certificate": user(lambda u: u.update({"client-certificate": "/c"})),
            "client-key": user(lambda u: u.update({"client-key": "/k"})),
            "user-extension": user(lambda u: u.update({"extensions": [{"name": "e"}]})),
            "user-unknown": user(lambda u: u.update({"surprise": 1})),
            "missing-cert": user(lambda u: u.pop("client-certificate-data")),
            "empty-key": user(lambda u: u.update({"client-key-data": ""})),
            "bad-base64": user(lambda u: u.update({"client-key-data": "!!!!"})),
            "unnormalized-base64": user(lambda u: u.update({"client-key-data": u["client-key-data"].rstrip("=") + "\n"})),
            "ca-file": cluster(lambda c: c.update({"certificate-authority": "/ca"})),
            "proxy": cluster(lambda c: c.update({"proxy-url": "http://p:1"})),
            "insecure": cluster(lambda c: c.update({"insecure-skip-tls-verify": True})),
            "insecure-int": cluster(lambda c: c.update({"insecure-skip-tls-verify": 0})),
            "tls-server-name": cluster(lambda c: c.update({"tls-server-name": "x"})),
            "compression": cluster(lambda c: c.update({"disable-compression": True})),
            "cluster-extension": cluster(lambda c: c.update({"extensions": [{"name": "e"}]})),
            "cluster-unknown": cluster(lambda c: c.update({"surprise": 1})),
            "http": cluster(lambda c: c.update({"server": "http://vlab.invalid:6443"})),
            "userinfo": cluster(lambda c: c.update({"server": "https://u:p@vlab.invalid"})),
            "schemeless": cluster(lambda c: c.update({"server": "vlab.invalid:6443"})),
            "no-ca": cluster(lambda c: c.pop("certificate-authority-data")),
            "ctx-extension": lambda d: d["contexts"][0]["context"].update({"extensions": [{"name": "e"}]}),
            "ctx-unknown": lambda d: d["contexts"][0]["context"].update({"surprise": 1}),
            "ctx-bad-namespace": lambda d: d["contexts"][0]["context"].update({"namespace": "Bad NS"}),
            "root-unknown": lambda d: d.update({"surprise": 1}),
            "root-extension": lambda d: d.update({"extensions": [{"name": "e"}]}),
            "colors": lambda d: d.update({"preferences": {"colors": True}}),
            "api-version": lambda d: d.update({"apiVersion": "v2"}),
            "kind": lambda d: d.update({"kind": "Other"}),
            "no-current": lambda d: d.pop("current-context"),
            "two-contexts": lambda d: d["contexts"].append(copy.deepcopy(d["contexts"][0])),
            "second-cluster": lambda d: d["clusters"].append({"name": "x", "cluster": d["clusters"][0]["cluster"]}),
            "unlinked": lambda d: d["contexts"][0]["context"].update({"user": "other"}),
            "null-collection": lambda d: d.update({"users": None}),
            "entry-extra-key": lambda d: d["users"][0].update({"extra": 1}),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.calls.clear()
                self.write_sources(change)
                self.assert_refused(expect_calls=1)  # only the first source's no-flatten JSON view ran
                self.assertEqual(self.calls[0]["args"][-1], "json")

    def test_collisions(self):
        same = binding("vlab")
        self.mg = {**same}
        self.write_sources()
        self.assert_refused()
        self.mg = binding("mgmt")
        self.write_sources()
        self.assertEqual(self.run_main(**{"management-config": self.vlab})[0], 1)
        self.assertEqual(self.run_main(output=self.vlab)[0], 1)
        os.link(self.vlab, self.root / "alias")
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.names(), [])

    def test_path_and_permission_boundary(self):
        link = self.root / "linked-state"
        link.symlink_to(self.state)
        symlink_source = self.root / "link.src"
        symlink_source.symlink_to(self.vlab)
        wide = self.root / "wide.src"
        private_write(wide, self.vlab.read_bytes())
        wide.chmod(0o644)
        cases = [
            {"kubectl": "kubectl"}, {"output": "state/config"}, {"vlab-config": "relative.src"},
            {"output": self.state / ".." / "state" / "config"}, {"output": link / "config"},
            {"vlab-config": symlink_source}, {"vlab-config": wide}, {"vlab-config": self.root},
            {"management-config": self.root / "missing.src"},
            {"output": self.root / "missing-dir" / "config"},
            {"output": self.state / (csk.STAGE_PREFIX + "x")},
        ]
        for case in cases:
            with self.subTest(case):
                self.assertEqual(self.run_main(**case)[0], 1)
                self.assertEqual(self.names(), [])
        self.calls.clear()
        self.state.chmod(0o755)
        self.assertEqual(self.run_main()[0], 1)
        self.state.chmod(0o700)
        with patch.object(csk.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(self.run_main()[0], 1)
        self.root.chmod(0o770)
        self.assertEqual(self.run_main()[0], 1)
        self.root.chmod(0o700)
        self.assertEqual(self.calls, [])

    def test_unsafe_existing_output_refused_and_preserved(self):
        for name, prepare in {
            "mode": lambda: self.out.chmod(0o644),
            "hardlink": lambda: os.link(self.out, self.root / "second-name"),
            "symlink": lambda: (self.out.unlink(), self.out.symlink_to(self.vlab)),
            "oversize": lambda: private_write(self.out, b"#" * (csk.OUTPUT_LIMIT + 1)),
            "garbage": lambda: private_write(self.out, b"\x00 not a config"),
        }.items():
            with self.subTest(name):
                for stale in (self.root / "second-name",):
                    stale.unlink(missing_ok=True)
                self.out.unlink(missing_ok=True)
                self.install()
                prepare()
                before = self.out.read_bytes() if not self.out.is_symlink() else None
                code, _, _ = self.run_main()
                self.assertEqual(code, 1)
                self.assertEqual(self.names(), ["config"])
                if before is not None:
                    self.assertEqual(self.out.read_bytes(), before)

    def test_existing_output_conflicts_refuse_with_original_bytes(self):
        def add_context(d):
            d["contexts"].append({"name": "extra", "context": {"cluster": "labapp-vlab", "user": "labapp-vlab"}})

        def add_user(d):
            d["users"].append({"name": "extra", "user": d["users"][0]["user"]})

        def add_cluster(d):
            d["clusters"].append({"name": "extra", "cluster": d["clusters"][0]["cluster"]})

        def find(d, kind, name):
            return next(e for e in d[kind] if e["name"] == name)
        cases = {
            "server": lambda d: find(d, "clusters", "labapp-vlab")["cluster"].update(server="https://other.invalid"),
            "ca": lambda d: find(d, "clusters", "labapp-management")["cluster"].update(
                {"certificate-authority-data": b64("other")}),
            "namespace": lambda d: find(d, "contexts", "vlab")["context"].update(namespace="other"),
            "extra-context": add_context, "extra-user": add_user, "extra-cluster": add_cluster,
            "selection": lambda d: d.update({"current-context": "extra"}),
            "empty-selection": lambda d: d.update({"current-context": ""}),
            "alias": lambda d: find(d, "contexts", "vlab")["context"].update(user="labapp-management"),
            "renamed": lambda d: find(d, "contexts", "vlab").update(name="renamed"),
            "token": lambda d: find(d, "users", "labapp-vlab")["user"].update(token="t"),
            "exec": lambda d: find(d, "users", "labapp-vlab")["user"].update(exec={"command": "x"}),
            "api": lambda d: d.update(apiVersion="v2"),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.out.unlink(missing_ok=True)
                self.install()
                self.edit_output(change)
                self.mg = binding("mgmt", 2)  # a refresh is wanted, but the conflict must win
                self.write_sources()
                before = self.snapshot()
                code, out, err = self.run_main()
                self.assertEqual((code, out), (1, ""))
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.names(), ["config"])
                self.mg = binding("mgmt")
                self.write_sources()


class BoundTests(Base):
    def assert_precommit_refusal(self):
        code, out, err = self.run_main()
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(len(err.splitlines()), 1)
        self.assertEqual(self.names(), [])

    def test_input_bound(self):
        private_write(self.vlab, b" " * (csk.INPUT_LIMIT + 1))
        self.assert_precommit_refusal()
        self.assertEqual(self.calls, [])
        document = json.dumps(kube("default", "c", "u", self.vl)).encode()
        private_write(self.vlab, document + b" " * (csk.INPUT_LIMIT - len(document)))
        self.assertEqual(self.run_main()[0], 0)  # exactly at the bound is accepted

    def test_native_failures_are_fixed_and_sanitized(self):
        good = render(kube("default", "c", "u", self.vl), "json")
        outcomes = {
            "nonzero": (3, b"SECRET stderr text"), "empty": (0, b""), "garbage": (0, b"{not json"),
            "merged-stderr": (0, b"warning: x\n" + good), "duplicate": (0, b'{"kind": "Config", "kind": "Config"}'),
            "nan": (0, b'{"kind": NaN}'), "list": (0, b"[]"), "nesting": (0, b"[" * 100000),
            "binary": (0, b"\xff\xfe"), "overflow": release.Refusal("command output overflow"),
            "timeout": release.Refusal("command timeout"),
        }
        for name, outcome in outcomes.items():
            with self.subTest(name):
                def hook(number, args, outcome=outcome):
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                self.hook = hook
                self.calls.clear()
                self.assert_precommit_refusal()
                self.assertEqual(len(self.calls), 1)

    def test_total_deadline_alarm_and_child_budget(self):
        seen = {}
        original = signal.getsignal(signal.SIGALRM)

        def hook(number, args):
            if number == 1:
                seen["alarm"] = signal.alarm(0)
            handler = signal.getsignal(signal.SIGALRM)
            with self.assertRaisesRegex(release.Refusal, "deadline"):
                handler(signal.SIGALRM, None)
        self.hook = hook
        self.assertEqual(self.run_main()[0], 0)
        self.assertTrue(0 < seen["alarm"] <= csk.TOTAL)
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        with patch.object(csk.time, "monotonic", side_effect=[0.0, csk.TOTAL + 1.0]):
            budget = csk.Budget()
            with self.assertRaises(release.Refusal):
                budget.child()
        with patch.object(csk.time, "monotonic", side_effect=[0.0, csk.TOTAL - 3.0]):
            budget = csk.Budget()
            self.assertEqual(budget.child(), 3.0)

    def test_deadline_expiry_precommit_preserves_original(self):
        self.install()
        before = self.snapshot()
        self.mg = binding("mgmt", 2)
        self.write_sources()

        def expire(number, args):
            if number == 4:
                signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
        self.hook = expire
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.names(), ["config"])

    def test_interrupt_before_commit(self):
        def interrupt(number, args):
            raise KeyboardInterrupt
        self.hook = interrupt
        code, out, err = self.run_main()
        self.assertEqual((code, out, err), (130, "", "configure-student-kubeconfig: interrupted\n"))
        self.assertEqual(self.names(), [])


class PublicationTests(Base):
    def test_candidate_not_equivalent_to_intended_state(self):
        def corrupt(number, args):
            if args[-1] == "json" and Path(args[2]).name == "candidate.yaml":
                document = fake_load(Path(args[2]).read_bytes())
                document["clusters"][0]["cluster"]["server"] = "https://swapped.invalid"
                return 0, render(document, "json")
        self.hook = corrupt
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.names(), [])

    def test_source_changed_before_publication(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.out.unlink(missing_ok=True)
                self.hook = None
                if existing:
                    self.install()
                    self.mg = binding("mgmt", 2)
                    self.write_sources()
                    before = self.snapshot()
                last = 5 if existing else 4

                def change(number, args):
                    if number == last:
                        self.mgmt.write_bytes(self.mgmt.read_bytes() + b"\n# touched")
                self.hook = change
                self.assertEqual(self.run_main()[0], 1)
                self.assertEqual(self.names(), ["config"] if existing else [])
                if existing:
                    self.assertEqual(self.snapshot(), before)
                self.mg = binding("mgmt")
                self.write_sources()

    def test_absent_target_created_concurrently_is_not_clobbered(self):
        def create(number, args):
            if number == 4:
                private_write(self.out, b"someone else")
        self.hook = create
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.out.read_bytes(), b"someone else")
        self.assertEqual(self.names(), ["config"])

    def test_link_and_replace_failures_preserve_prior_state(self):
        with patch.object(csk.os, "link", side_effect=OSError("denied")):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.names(), [])
        with patch.object(csk.os, "link", side_effect=FileExistsError):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.names(), [])
        self.install()
        before = self.snapshot()
        self.mg = binding("mgmt", 2)
        self.write_sources()
        with patch.object(csk.os, "replace", side_effect=OSError("denied")):
            code, _, err = self.run_main()
        self.assertEqual((code, err), (1, "configure-student-kubeconfig: publication failed\n"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.names(), ["config"])

    def test_target_changed_before_replace_is_not_overwritten(self):
        self.install()
        self.mg = binding("mgmt", 2)
        self.write_sources()

        def change(number, args):
            if number == 5:
                self.out.write_bytes(self.out.read_bytes() + b"\n# user edit")
        self.hook = change
        self.assertEqual(self.run_main()[0], 1)
        self.assertTrue(self.out.read_bytes().endswith(b"# user edit"))
        self.assertEqual(self.names(), ["config"])

    def test_staging_failures_clean_owned_state_and_preserve_output(self):
        with patch.object(csk.tempfile, "mkdtemp", side_effect=OSError("full")):
            code, _, err = self.run_main()
        self.assertEqual((code, err), (1, "configure-student-kubeconfig: operational failure\n"))
        self.assertEqual((self.names(), self.calls), ([], []))
        real, count = csk.write_private, []

        def flaky(path, data):
            count.append(path)
            if len(count) == 2:
                raise OSError("disk")
            return real(path, data)
        with patch.object(csk, "write_private", flaky):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.names(), [])

    def test_incomplete_cleanup_never_removes_unknown_children(self):
        def stray(number, args):
            if number == 1:
                (Path(args[2]).parent / "stray").write_bytes(b"not ours")
        self.hook = stray
        code, out, err = self.run_main()  # fresh install commits, then cleanup cannot finish
        self.assertEqual((code, out), (3, ""))
        self.assertEqual(err, "configure-student-kubeconfig: committed-but-incomplete; do not retry blindly\n")
        self.assertEqual(self.published()[1], "vlab")
        left = [p for p in self.state.iterdir() if p.name != "config"]
        self.assertEqual(len(left), 1)
        self.assertEqual([p.name for p in left[0].iterdir()], ["stray"])

    def test_incomplete_cleanup_before_commit_is_a_refusal(self):
        self.install()
        before = self.snapshot()

        def stray(number, args):
            if number == 1:
                (Path(args[2]).parent / "stray").write_bytes(b"not ours")
        self.hook = stray
        code, _, err = self.run_main()  # unchanged: nothing committed
        self.assertEqual((code, err), (1, "configure-student-kubeconfig: owned stage cleanup failed\n"))
        self.assertEqual(self.snapshot(), before)


class PostCommitTests(Base):
    COMMITTED = "configure-student-kubeconfig: committed-but-incomplete; do not retry blindly\n"

    def test_durability_failure_is_committed_but_incomplete_without_retry(self):
        with patch.object(csk, "sync_directory", side_effect=OSError("io")) as sync:
            code, out, err = self.run_main()
        self.assertEqual((code, out, err), (3, "", self.COMMITTED))
        self.assertEqual(sync.call_count, 1)
        self.assertEqual(len(self.calls), 4)  # no native work or retry after the commit point
        self.assertEqual(self.names(), ["config"])  # owned stage still cleaned
        self.assertEqual(self.published()[1], "vlab")  # committed bytes are not rolled back

    def test_replace_commit_then_failure_keeps_new_bytes(self):
        self.install()
        self.mg = binding("mgmt", 2)
        self.write_sources()
        with patch.object(csk, "sync_directory", side_effect=OSError("io")):
            code, _, err = self.run_main()
        self.assertEqual((code, err), (3, self.COMMITTED))
        self.assertEqual(self.published()[0]["k3d-k3d-observability"]["cert"], self.mg["cert"])
        self.assertEqual(self.names(), ["config"])

    def test_interrupt_and_reporting_failure_after_commit(self):
        with patch.object(csk, "sync_directory", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_main()[0], 3)
        self.out.unlink()

        class Broken(io.StringIO):
            def write(self, text):
                raise OSError("closed")
        err = io.StringIO()
        with contextlib.redirect_stdout(Broken()), contextlib.redirect_stderr(err):
            code = csk.main(self.argv())
        self.assertEqual((code, err.getvalue()), (3, self.COMMITTED))
        self.assertEqual(self.names(), ["config"])

    def commit_with_signal(self, name, sig):
        """Wrap the real commit syscall; the signal is raised inside it and must be deferred."""
        real, seen = getattr(csk.os, name), {}

        def wrapped(*args, **kwargs):
            seen["masked"] = csk.HANDLED_SIGNALS <= signal.pthread_sigmask(signal.SIG_BLOCK, [])
            result = real(*args, **kwargs)
            signal.raise_signal(sig)
            return result
        with patch.object(csk.os, name, wrapped):
            outcome = self.run_main()
        self.assertTrue(seen["masked"])
        self.assertFalse(csk.HANDLED_SIGNALS & signal.pthread_sigmask(signal.SIG_BLOCK, []))
        return outcome

    def test_handled_signal_during_link_commit_is_committed_but_incomplete(self):
        for sig in (signal.SIGTERM, signal.SIGALRM, signal.SIGINT):
            with self.subTest(sig=sig):
                self.out.unlink(missing_ok=True)
                code, out, err = self.commit_with_signal("link", sig)
                self.assertEqual((code, out, err), (3, "", self.COMMITTED))
                self.assertEqual(self.published()[1], "vlab")
                self.assertEqual(self.names(), ["config"])

    def test_handled_signal_during_replace_commit_is_committed_but_incomplete(self):
        self.install()
        self.mg = binding("mgmt", 2)
        self.write_sources()
        code, out, err = self.commit_with_signal("replace", signal.SIGTERM)
        self.assertEqual((code, out, err), (3, "", self.COMMITTED))
        self.assertEqual(self.published()[0]["k3d-k3d-observability"]["cert"], self.mg["cert"])
        self.assertEqual(self.names(), ["config"])

    def test_failed_commit_restores_mask_and_stays_a_refusal(self):
        with patch.object(csk.os, "link", side_effect=OSError("denied")):
            code, _, err = self.run_main()
        self.assertEqual((code, err), (1, "configure-student-kubeconfig: publication failed\n"))
        self.assertFalse(csk.HANDLED_SIGNALS & signal.pthread_sigmask(signal.SIG_BLOCK, []))

    def test_cleanup_incomplete_accompanies_primary_failure_without_replacing_it(self):
        def stray_then_fail(number, args):
            if number == 1:
                (Path(args[2]).parent / "stray").write_bytes(b"not ours")
            if number == 2:
                return 1, b""  # primary native failure
        self.hook = stray_then_fail
        code, out, err = self.run_main()
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, "configure-student-kubeconfig: native kubectl view failed\n"
                              "configure-student-kubeconfig: owned stage cleanup incomplete\n")
        left = [p for p in self.state.iterdir()]
        self.assertEqual([[c.name for c in p.iterdir()] for p in left], [["stray"]])

    def test_cleanup_incomplete_after_interrupt_keeps_interrupt_report(self):
        def stray_then_interrupt(number, args):
            (Path(args[2]).parent / "stray").write_bytes(b"not ours")
            raise KeyboardInterrupt
        self.hook = stray_then_interrupt
        code, _, err = self.run_main()
        self.assertEqual(code, 130)
        self.assertEqual(err, "configure-student-kubeconfig: interrupted\n"
                              "configure-student-kubeconfig: owned stage cleanup incomplete\n")

    def test_failed_owned_unlink_keeps_primary_error_and_previous_output(self):
        self.install()
        before = self.snapshot()
        real_unlink = csk.os.unlink

        def fail_owned_unlink(path, *args, **kwargs):
            if Path(path).name == "vlab-source":
                raise OSError("synthetic unlink failure")
            return real_unlink(path, *args, **kwargs)

        self.hook = lambda number, args: (1, b"")
        with patch.object(csk.os, "unlink", fail_owned_unlink):
            code, out, err = self.run_main()
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, "configure-student-kubeconfig: native kubectl view failed\n"
                              "configure-student-kubeconfig: owned stage cleanup incomplete\n")
        self.assertEqual(self.snapshot(), before)
        stages = [path for path in self.state.iterdir() if path.name != "config"]
        self.assertEqual(len(stages), 1)
        self.assertEqual([path.name for path in stages[0].iterdir()], ["vlab-source"])

    def test_sigterm_handler_restored_and_maps_to_interrupt(self):
        before = signal.getsignal(signal.SIGTERM)

        def term(number, args):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.hook = term
        self.assertEqual(self.run_main()[0], 130)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        self.assertEqual(self.names(), [])


if __name__ == "__main__":
    unittest.main()
