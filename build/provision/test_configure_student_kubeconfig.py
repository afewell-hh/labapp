"""Offline synthetic tests for configure-student-kubeconfig.py.

All certificate-like values are PUBLIC INVENTED TEST DATA, never real credentials. No network,
no kubectl, no subprocess, no real cluster or configuration is read.
"""
import base64
import contextlib
import copy
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

SOURCE = Path(__file__).with_name("configure-student-kubeconfig.py")
spec = importlib.util.spec_from_file_location("kubeconfig_tool", SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def b64(text):
    return base64.b64encode(text.encode()).decode()


def config(server, ca, cert="cert-one", key="key-one", namespace=None, names=("c", "u", "x")):
    context = {"cluster": names[0], "user": names[1]}
    if namespace is not None:
        context["namespace"] = namespace
    return {
        "apiVersion": "v1", "kind": "Config", "preferences": {}, "current-context": names[2],
        "clusters": [{"name": names[0], "cluster": {
            "server": server, "certificate-authority-data": b64(ca)}}],
        "users": [{"name": names[1], "user": {
            "client-certificate-data": b64(cert), "client-key-data": b64(key)}}],
        "contexts": [{"name": names[2], "context": context}],
    }


def vlab(**kw):
    return config("https://vlab.invalid:6443", "invented-ca-vlab", names=("a", "b", "c"), **kw)


def management(**kw):
    return config("https://management.invalid:6443", "invented-ca-management", names=("a", "b", "c"), **kw)


class Base(unittest.TestCase):
    def setUp(self):
        handler = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, handler)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out_dir = self.root / "out"
        self.out_dir.mkdir(mode=0o700)
        self.out = self.out_dir / "config"
        self.vlab_path = self.root / "vlab.json"
        self.management_path = self.root / "management.json"
        self.put(self.vlab_path, vlab())
        self.put(self.management_path, management())

    def put(self, path, value, mode=0o600):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_bytes(data)
        path.chmod(mode)

    def run_tool(self):
        return tool.configure(self.vlab_path, self.management_path, self.out)

    def refused(self, pattern=None):
        before = self.out.read_bytes() if self.out.exists() else None
        with self.assertRaises(tool.Refusal) as caught:
            self.run_tool()
        if pattern:
            self.assertRegex(str(caught.exception), pattern)
        self.assertEqual(self.out.read_bytes() if self.out.exists() else None, before)
        self.assertEqual(sorted(p.name for p in self.out_dir.iterdir()), ["config"] if before is not None else [])

    def loaded(self):
        return json.loads(self.out.read_text())

    def install(self):
        self.assertEqual(self.run_tool(), "installed")
        return self.out.stat()


class ContractTests(unittest.TestCase):
    def test_bounds_and_source_discipline(self):
        self.assertEqual((tool.INPUT_LIMIT, tool.OUTPUT_LIMIT, tool.TOTAL), (65536, 262144, 30))
        self.assertEqual(tool.ROLES, (("vlab", "labapp-vlab"), ("k3d-k3d-observability", "labapp-management")))
        source = SOURCE.read_text()
        for forbidden in ("subprocess", "socket", "urllib.request", "yaml", "environ", "getenv", "kubectl("):
            self.assertNotIn(forbidden, source)


class InstallTests(Base):
    def test_fresh_install_links_both_contexts(self):
        info = self.install()
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o600, 1))
        self.assertEqual(sorted(p.name for p in self.out_dir.iterdir()), ["config"])
        got = self.loaded()
        self.assertEqual(got["current-context"], "vlab")
        self.assertEqual([c["name"] for c in got["contexts"]], ["vlab", "k3d-k3d-observability"])
        self.assertEqual([c["name"] for c in got["clusters"]], ["labapp-vlab", "labapp-management"])
        self.assertEqual([u["name"] for u in got["users"]], ["labapp-vlab", "labapp-management"])
        for context, alias in (("vlab", "labapp-vlab"), ("k3d-k3d-observability", "labapp-management")):
            entry = next(c for c in got["contexts"] if c["name"] == context)["context"]
            self.assertEqual(entry, {"cluster": alias, "user": alias})
        self.assertEqual(got["clusters"][0]["cluster"]["server"], "https://vlab.invalid:6443")
        self.assertEqual(got["users"][1]["user"]["client-key-data"], b64("key-one"))
        self.assertEqual(self.out.read_bytes(), tool.serialize(got))

    def test_namespace_is_preserved(self):
        self.put(self.vlab_path, vlab(namespace="lab"))
        self.install()
        contexts = {c["name"]: c["context"] for c in self.loaded()["contexts"]}
        self.assertEqual(contexts["vlab"]["namespace"], "lab")
        self.assertNotIn("namespace", contexts["k3d-k3d-observability"])

    def test_unchanged_rerun_keeps_inode_mode_and_timestamps(self):
        before = self.install()
        data = self.out.read_bytes()
        with patch.object(tool.tempfile, "mkstemp", side_effect=AssertionError("no staging")):
            self.assertEqual(self.run_tool(), "unchanged")
        after = self.out.stat()
        self.assertEqual(self.out.read_bytes(), data)
        self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns))

    def test_management_selection_survives_credential_refresh(self):
        self.install()
        state = self.loaded()
        state["current-context"] = "k3d-k3d-observability"
        self.out.write_bytes(tool.serialize(state))
        self.out.chmod(0o600)
        before = self.out.stat()
        self.put(self.management_path, management(cert="cert-two", key="key-two"))
        self.assertEqual(self.run_tool(), "updated")
        got = self.loaded()
        self.assertEqual(got["current-context"], "k3d-k3d-observability")
        self.assertEqual(got["users"][1]["user"]["client-certificate-data"], b64("cert-two"))
        self.assertEqual(got["users"][0]["user"]["client-certificate-data"], b64("cert-one"))
        info = self.out.stat()
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o600, 1))
        self.assertNotEqual(info.st_ino, before.st_ino)
        self.assertEqual(sorted(p.name for p in self.out_dir.iterdir()), ["config"])

    def test_same_server_with_different_ca_is_not_conflated_but_identical_binding_is_refused(self):
        other = config("https://vlab.invalid:6443", "invented-ca-other", names=("a", "b", "c"))
        self.put(self.management_path, other)
        self.install()
        self.out.unlink()
        self.put(self.management_path, config("https://VLAB.invalid:6443/", "invented-ca-vlab", names=("a", "b", "c")))
        self.refused("same endpoint and CA")

    def test_cli_status_is_fixed_and_leaks_nothing(self):
        argv = ["--vlab-json", str(self.vlab_path), "--management-json", str(self.management_path),
                "--output", str(self.out)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(tool.cli(argv), 0)
            self.assertEqual(tool.cli(argv), 0)
            self.out.chmod(0o644)
            self.assertEqual(tool.cli(argv), 1)
        lines = stdout.getvalue().splitlines()
        self.assertEqual([json.loads(line) for line in lines], [
            {"component": "configure-student-kubeconfig", "status": "installed"},
            {"component": "configure-student-kubeconfig", "status": "unchanged"}])
        self.assertEqual(stderr.getvalue(),
                         "configure-student-kubeconfig: file must be a caller-owned 0600 single-link "
                         "regular file within the size bound\n")
        for secret in (b64("cert-one"), b64("key-one"), b64("invented-ca-vlab"), "vlab.invalid"):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_operational_failure_message_is_fixed(self):
        stderr = io.StringIO()
        with patch.object(tool, "configure", side_effect=OSError("secret path detail")), \
                contextlib.redirect_stderr(stderr):
            code = tool.cli(["--vlab-json", "/x", "--management-json", "/y", "--output", "/z"])
        self.assertEqual((code, stderr.getvalue()), (1, "configure-student-kubeconfig: operational failure\n"))


class InputRefusalTests(Base):
    def mutate(self, change, base=None):
        value = copy.deepcopy(base or vlab())
        change(value)
        self.put(self.vlab_path, value)
        self.refused()

    def test_invalid_shapes_are_refused_without_output(self):
        cases = {
            "extra top key": lambda v: v.update(extensions=[]),
            "bad kind": lambda v: v.update(kind="Other"),
            "non-empty preferences": lambda v: v.update(preferences={"colors": True}),
            "missing current": lambda v: v.pop("current-context"),
            "current mismatch": lambda v: v.update({"current-context": "other"}),
            "dangling cluster": lambda v: v["contexts"][0]["context"].update(cluster="nope"),
            "dangling user": lambda v: v["contexts"][0]["context"].update(user="nope"),
            "two clusters": lambda v: v["clusters"].append(copy.deepcopy(v["clusters"][0])),
            "no users": lambda v: v.update(users=[]),
            "insecure tls": lambda v: v["clusters"][0]["cluster"].update({"insecure-skip-tls-verify": True}),
            "proxy": lambda v: v["clusters"][0]["cluster"].update({"proxy-url": "http://p.invalid"}),
            "ca file ref": lambda v: v["clusters"][0]["cluster"].update({"certificate-authority": "/etc/ca"}),
            "cert file ref": lambda v: v["users"][0]["user"].update({"client-certificate": "/etc/c"}),
            "key file ref": lambda v: v["users"][0]["user"].update({"client-key": "/etc/k"}),
            "token": lambda v: v["users"][0]["user"].update({"token": "t"}),
            "password": lambda v: v["users"][0]["user"].update({"username": "u", "password": "p"}),
            "exec": lambda v: v["users"][0]["user"].update({"exec": {"command": "x"}}),
            "auth provider": lambda v: v["users"][0]["user"].update({"auth-provider": {"name": "x"}}),
            "cluster extension": lambda v: v["clusters"][0].update(extensions=[]),
            "http server": lambda v: v["clusters"][0]["cluster"].update(server="http://vlab.invalid"),
            "userinfo server": lambda v: v["clusters"][0]["cluster"].update(server="https://u:p@vlab.invalid"),
            "query server": lambda v: v["clusters"][0]["cluster"].update(server="https://vlab.invalid/?x=1"),
            "no host": lambda v: v["clusters"][0]["cluster"].update(server="https:///x"),
            "bad base64": lambda v: v["users"][0]["user"].update({"client-key-data": "!!!"}),
            "non canonical base64": lambda v: v["users"][0]["user"].update({"client-key-data": "Zm9v\n"}),
            "unpadded base64": lambda v: v["users"][0]["user"].update({"client-key-data": "Zm9vYg"}),
            "empty ca": lambda v: v["clusters"][0]["cluster"].update({"certificate-authority-data": ""}),
            "bad namespace": lambda v: v["contexts"][0]["context"].update(namespace="Bad_NS"),
            "non string namespace": lambda v: v["contexts"][0]["context"].update(namespace=1),
            "context extension": lambda v: v["contexts"][0]["context"].update(extensions=[]),
            "blank name": lambda v: v["clusters"][0].update(name="has space"),
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.mutate(change)

    def test_malformed_json_is_refused(self):
        valid = json.dumps(vlab())
        cases = {
            "duplicate key": '{"kind":"Config","kind":"Config"}',
            "nested duplicate": valid.replace('"preferences": {}', '"preferences": {"a": {}, "a": {}}'),
            "NaN": valid.replace('"preferences": {}', '"preferences": NaN'),
            "Infinity": valid.replace('"preferences": {}', '"preferences": Infinity'),
            "number": valid.replace('"preferences": {}', '"preferences": 1.5'),
            "integer": valid.replace('"preferences": {}', '"preferences": 7'),
            "not object": "[]",
            "garbage": "{",
            "deep nesting": "[" * 50000,
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.put(self.vlab_path, content.encode())
                self.refused()
        self.put(self.vlab_path, b"\xff\xfe")
        self.refused()

    def test_oversize_input_refused(self):
        padded = json.dumps(vlab()).encode() + b" " * tool.INPUT_LIMIT
        self.put(self.vlab_path, padded)
        self.refused()

    def test_unsafe_input_files_refused(self):
        real = self.root / "real.json"
        self.put(real, vlab())
        self.vlab_path.unlink()
        self.vlab_path.symlink_to(real)
        self.refused()
        self.vlab_path.unlink()
        os.link(real, self.vlab_path)
        self.refused()
        self.vlab_path.unlink()
        real.unlink()
        self.put(self.vlab_path, vlab(), mode=0o644)
        self.refused()
        self.vlab_path.unlink()
        self.vlab_path.mkdir()
        self.refused()
        self.vlab_path.rmdir()
        self.refused()  # missing

    def test_input_directory_symlink_refused(self):
        link = self.root / "link"
        link.symlink_to(self.root)
        self.vlab_path = link / "vlab.json"
        self.refused()

    def test_relative_and_colliding_paths_refused(self):
        for args in ((Path("vlab.json"), self.management_path, self.out),
                     (self.vlab_path, self.vlab_path, self.out),
                     (self.vlab_path, self.management_path, self.vlab_path),
                     (self.vlab_path, self.management_path, self.management_path),
                     (self.vlab_path, self.management_path, Path("config"))):
            with self.subTest(args=args), self.assertRaises(tool.Refusal):
                tool.configure(*args)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["management.json", "out", "vlab.json"])

    def test_existing_output_hardlinked_to_input_refused(self):
        os.link(self.vlab_path, self.out)
        self.out.chmod(0o600)
        self.refused()

    def test_output_directory_must_be_private_and_present(self):
        self.out_dir.chmod(0o755)
        with self.assertRaises(tool.Refusal):
            self.run_tool()
        self.out_dir.chmod(0o700)
        missing = self.root / "missing" / "config"
        with self.assertRaises(tool.Refusal):
            tool.configure(self.vlab_path, self.management_path, missing)
        self.assertFalse((self.root / "missing").exists())
        with patch.object(tool.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(tool.Refusal):
            self.run_tool()
        self.assertEqual(list(self.out_dir.iterdir()), [])


class ExistingOutputTests(Base):
    def seed(self, **kw):
        self.put(self.vlab_path, vlab(**kw))
        self.install()
        return self.out.read_bytes()

    def test_foreign_or_malformed_existing_targets_refused_and_preserved(self):
        good = self.seed()
        state = json.loads(good)

        def edited(change):
            value = copy.deepcopy(state)
            change(value)
            return json.dumps(value).encode()
        cases = {
            "unrelated bytes": b"not a kubeconfig\n",
            "empty": b"",
            "empty object": b"{}",
            "unknown top key": edited(lambda v: v.update(extra=1)),
            "unknown user key": edited(lambda v: v["users"][0]["user"].update(token="t")),
            "missing preferences": edited(lambda v: v.pop("preferences")),
            "alias collision": edited(lambda v: (v["clusters"][0].update(name="labapp-management"))),
            "renamed context": edited(lambda v: v["contexts"][0].update(name="other")),
            "swapped order": edited(lambda v: v["contexts"].reverse()),
            "bad current": edited(lambda v: v.update({"current-context": "other"})),
            "third entry": edited(lambda v: v["clusters"].append(copy.deepcopy(v["clusters"][0]))),
            "duplicate keys": good.replace(b'"kind"', b'"kind": "Config", "kind"', 1),
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.out.write_bytes(content)
                self.out.chmod(0o600)
                self.refused()
                self.assertEqual(self.out.read_bytes(), content)
        self.out.write_bytes(b"x" * (tool.OUTPUT_LIMIT + 1))
        self.out.chmod(0o600)
        self.refused()

    def test_wrong_type_mode_and_links_refused(self):
        good = self.seed()
        self.out.chmod(0o644)
        self.refused()
        self.assertEqual(self.out.read_bytes(), good)
        self.out.chmod(0o600)
        twin = self.root / "twin"
        os.link(self.out, twin)
        self.refused()
        twin.unlink()
        self.out.unlink()
        target = self.root / "target"
        target.write_bytes(good)
        target.chmod(0o600)
        self.out.symlink_to(target)
        with self.assertRaises(tool.Refusal):
            self.run_tool()
        self.assertEqual(target.read_bytes(), good)
        self.out.unlink()
        self.out.mkdir()
        with self.assertRaises(tool.Refusal):
            self.run_tool()

    def test_identity_and_namespace_drift_refused(self):
        good = self.seed(namespace="lab")

        def ca(v):
            v["clusters"][0]["cluster"]["certificate-authority-data"] = b64("changed-ca")

        def server(v):
            v["clusters"][0]["cluster"]["server"] = "https://other.invalid:6443"

        def other_ns(v):
            v["contexts"][0]["context"]["namespace"] = "other"

        def no_ns(v):
            del v["contexts"][0]["context"]["namespace"]
        for label, change in (("ca", ca), ("server", server), ("namespace", other_ns),
                              ("namespace removed", no_ns)):
            with self.subTest(label):
                value = vlab(namespace="lab")
                change(value)
                self.put(self.vlab_path, value)
                self.refused()
                self.assertEqual(self.out.read_bytes(), good)
        self.put(self.vlab_path, vlab(namespace="lab"))
        value = management()
        server(value)
        self.put(self.management_path, value)
        self.refused()
        self.assertEqual(self.out.read_bytes(), good)

    def test_equivalent_endpoint_spelling_is_same_binding(self):
        self.seed()
        value = vlab()
        value["clusters"][0]["cluster"]["server"] = "https://VLAB.invalid:6443/"
        self.put(self.vlab_path, value)
        self.assertEqual(self.run_tool(), "updated")  # spelling is preserved from the new input
        self.assertEqual(self.loaded()["clusters"][0]["cluster"]["server"], "https://VLAB.invalid:6443/")


class PublicationFailureTests(Base):
    def test_fresh_link_failure_leaves_nothing(self):
        with patch.object(tool.os, "link", side_effect=OSError("boom")), self.assertRaises(OSError):
            self.run_tool()
        self.assertEqual(list(self.out_dir.iterdir()), [])

    def test_fresh_staging_failure_leaves_nothing(self):
        with patch.object(tool.os, "fsync", side_effect=OSError("boom")), self.assertRaises(OSError):
            self.run_tool()
        self.assertEqual(list(self.out_dir.iterdir()), [])

    def test_replace_failure_preserves_valid_config_and_cleans_stage(self):
        self.install()
        good = self.out.read_bytes()
        self.put(self.management_path, management(cert="cert-two"))
        with patch.object(tool.os, "replace", side_effect=OSError("boom")), self.assertRaises(OSError):
            self.run_tool()
        self.assertEqual(self.out.read_bytes(), good)
        self.assertEqual([p.name for p in self.out_dir.iterdir()], ["config"])

    def test_no_clobber_when_target_appears_during_publication(self):
        real = tool.tempfile.mkstemp

        def racing(*args, **kwargs):
            made = real(*args, **kwargs)
            self.out.write_bytes(b"intruder")
            return made
        with patch.object(tool.tempfile, "mkstemp", side_effect=racing):
            with self.assertRaisesRegex(tool.Refusal, "appeared"):
                self.run_tool()
        self.assertEqual(self.out.read_bytes(), b"intruder")
        self.assertEqual([p.name for p in self.out_dir.iterdir()], ["config"])

    def test_target_changed_during_update_is_not_replaced(self):
        self.install()
        self.put(self.management_path, management(cert="cert-two"))
        real = tool.tempfile.mkstemp

        def racing(*args, **kwargs):
            made = real(*args, **kwargs)
            self.out.unlink()
            self.out.write_bytes(b"intruder")
            return made
        with patch.object(tool.tempfile, "mkstemp", side_effect=racing):
            with self.assertRaisesRegex(tool.Refusal, "changed"):
                self.run_tool()
        self.assertEqual(self.out.read_bytes(), b"intruder")
        self.assertEqual([p.name for p in self.out_dir.iterdir()], ["config"])

    def test_cleanup_failure_after_publication_is_not_reported_as_success(self):
        with patch.object(tool.os, "unlink", side_effect=OSError("boom")), \
                self.assertRaisesRegex(tool.Refusal, "cleanup failed"):
            self.run_tool()
        for leftover in self.out_dir.iterdir():
            if leftover.name != "config":
                leftover.unlink()


if __name__ == "__main__":
    unittest.main()
