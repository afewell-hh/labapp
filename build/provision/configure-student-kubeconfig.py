"""Stage the student kubeconfig (YAML) from two invented/caller-supplied sources; Ubuntu 24.04 Python 3.12.

Invoke python3 /absolute/path/configure-student-kubeconfig.py --kubectl /abs/kubectl
--vlab-config /abs/vlab.src --management-config /abs/mgmt.src --output /abs/private-dir/config
Run as the owning non-root or root user; no sudo, TTY, prompts, cwd or environment dependence
(the child gets a fresh private HOME). Keep sibling hhfab_release.py (Refusal, bounded, digest)
alongside this file. Standard library only; it never downloads, flattens, minifies or contacts a
cluster. The only native operation is the pinned kubectl 1.35.0 linux/amd64
`--kubeconfig <private snapshot> config view --raw=true -o json|yaml`.

The caller owns a 0700 directory holding --output. Sources and an existing output must be owned
0600 single-link regular files, bounded at 64 KiB per source and 256 KiB for output. Native JSON is
internal validation only. One writer is assumed; this is not defense against a hostile writer.
Status (stdout, one JSON line): installed, unchanged or updated. Any refusal before publication
preserves the prior output. Publication (no-clobber link or atomic replace) is the commit point; a
later failure exits 3 as committed-but-incomplete: no rollback, no blind retry.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit

from hhfab_release import Refusal, bounded, digest

KUBECTL_PIN = {
    "version": "1.35.0", "platform": "linux/amd64", "size": 58597560,
    "sha256": "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989",
}
# Finite assumptions, not measured fit: whole run, one native child, input and native output caps.
TOTAL, CHILD = 30, 10
INPUT_LIMIT, OUTPUT_LIMIT = 64 * 1024, 256 * 1024
BASE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
VLAB = ("vlab", "labapp-vlab")
MANAGEMENT = ("k3d-k3d-observability", "labapp-management")
BINDINGS = (VLAB, MANAGEMENT)
DEFAULT_SELECTION = VLAB[0]  # fresh output only; an existing selection is always preserved
STAGE_PREFIX = ".student-kubeconfig-stage-"
STAGE_FILES = ("vlab-source", "management-source", "target-snapshot", "candidate-input.json",
               "candidate.yaml")
EXIT_COMMITTED_INCOMPLETE = 3
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,252}$")
NAMESPACE = re.compile(r"^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)?$")
# Closed effective native key sets (Kubernetes v1.35.0 clientcmd api/v1 types.go; lead policy).
ROOT_KEYS = {"apiVersion", "kind", "preferences", "clusters", "users", "contexts",
             "current-context", "extensions"}
CLUSTER_KEYS = {"server", "tls-server-name", "insecure-skip-tls-verify", "certificate-authority",
                "certificate-authority-data", "proxy-url", "disable-compression", "extensions"}
USER_KEYS = {"client-certificate", "client-certificate-data", "client-key", "client-key-data",
             "token", "tokenFile", "as", "as-uid", "as-groups", "as-user-extra", "username",
             "password", "auth-provider", "exec", "extensions"}
CONTEXT_KEYS = {"cluster", "user", "namespace", "extensions"}


class Run:
    """Mutable outcome state read by the reporter; committed is set only by publication."""
    committed = False
    cleanup_incomplete = False  # set only when cleanup fails while a primary failure is propagating


HANDLED_SIGNALS = {signal.SIGALRM, signal.SIGTERM, signal.SIGINT}


class Budget:
    def __init__(self):
        self.start = time.monotonic()

    def child(self):
        left = TOTAL - (time.monotonic() - self.start)
        if left <= 0:
            raise Refusal("deadline exceeded")
        return min(CHILD, left)


# ---- filesystem boundary -------------------------------------------------------------------
def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_nlink)


def normalized_absolute(path):
    text = str(path)
    if not path.is_absolute() or text == "/" or os.path.normpath(text) != text:
        raise Refusal("paths must be normalized and absolute")


def real_directory(path, private):
    try:
        for component in [*reversed(path.parents), path]:
            if not stat.S_ISDIR(component.lstat().st_mode):
                raise Refusal("path components must be real directories")
        info = path.lstat()
    except OSError:
        raise Refusal("directory unavailable") from None
    if info.st_uid != os.geteuid():
        raise Refusal("directory must be caller-owned")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise Refusal("output directory must be mode 0700")
    if not private and info.st_mode & 0o022:
        raise Refusal("source directory must not be group/world writable")


def verify_kubectl(path):
    """Size and SHA256 are verified before every invocation. Exec by path remains a TOCTOU window."""
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                or not info.st_mode & 0o100 or info.st_size != KUBECTL_PIN["size"]
                or digest(path) != KUBECTL_PIN["sha256"]):
            raise Refusal("kubectl does not match the pin")
    except OSError:
        raise Refusal("kubectl unavailable") from None


def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refusal("input unavailable") from None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600):
            raise Refusal("input must be an owned 0600 single-link regular file")
        if before.st_size > limit:
            raise Refusal("input exceeds size bound")
        chunks, total = [], 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise Refusal("input exceeds size bound")
            chunks.append(block)
        after = os.fstat(descriptor)
    except OSError:
        raise Refusal("input unreadable") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise Refusal("input changed while reading")
    return data, identity(after)


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def cleanup(stage):
    """Remove only the exact known stage entries; unknown children keep the stage (returns False)."""
    clean = True
    for name in STAGE_FILES:
        try:
            os.unlink(stage / name)
        except FileNotFoundError:
            pass
        except OSError:
            clean = False
    for directory in (stage / "home", stage):
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            pass
        except OSError:
            clean = False
    return clean


# ---- native boundary -----------------------------------------------------------------------
class Native:
    def __init__(self, kubectl, home, budget):
        self.kubectl, self.home, self.budget = kubectl, home, budget

    def view(self, config, output_format):
        assert output_format in ("json", "yaml")
        verify_kubectl(self.kubectl)
        # No --flatten/--minify, no auth/cluster verbs, only an explicit private snapshot.
        argv = [str(self.kubectl), "--kubeconfig", str(config), "config", "view", "--raw=true",
                "-o", output_format]
        env = {**BASE_ENV, "HOME": str(self.home)}
        code, output = bounded(argv, self.budget.child(), limit=OUTPUT_LIMIT, env=env)
        if code or not output:
            raise Refusal("native kubectl view failed")
        return output


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _no_constant(_name):
    raise ValueError("constant")


def load_native_json(output):
    try:
        return json.loads(output.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refusal("native output malformed") from None


# ---- closed effective-field policy ----------------------------------------------------------
def _only(mapping, allowed):
    if not isinstance(mapping, dict) or set(mapping) - allowed:
        raise Refusal("kubeconfig contains an unsupported field or type")


def _same(value, accepted):
    if accepted is None:
        return value is None
    return type(value) is type(accepted) and value == accepted


def _absent_or(mapping, key, accepted):
    """Omitted, or exactly one of the inert accepted values (strict type; False is not 0)."""
    if key in mapping and not any(_same(mapping[key], inert) for inert in accepted):
        raise Refusal("kubeconfig uses a forbidden auth, transport or extension field")


def _strict_base64(value):
    try:
        if not isinstance(value, str) or not value:
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        if not raw or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError
    except ValueError:
        raise Refusal("embedded credential data must be nonempty normalized base64") from None
    return value


def _https_server(value):
    try:
        if not isinstance(value, str) or not value.isascii() or not value.isprintable() or " " in value:
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment):
            raise ValueError
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        raise Refusal("cluster server must be a plain https endpoint") from None
    return value


def _cluster(body):
    _only(body, CLUSTER_KEYS)
    for key in ("tls-server-name", "certificate-authority", "proxy-url"):
        _absent_or(body, key, ("",))
    for key in ("insecure-skip-tls-verify", "disable-compression"):
        _absent_or(body, key, (False,))
    _absent_or(body, "extensions", (None, []))
    return {"server": _https_server(body.get("server")),
            "ca": _strict_base64(body.get("certificate-authority-data"))}


def _user(body):
    _only(body, USER_KEYS)
    for key in ("client-certificate", "client-key", "token", "tokenFile", "as", "as-uid",
                "username", "password"):
        _absent_or(body, key, ("",))
    _absent_or(body, "as-groups", (None, []))
    _absent_or(body, "as-user-extra", (None, {}))
    _absent_or(body, "auth-provider", (None,))
    _absent_or(body, "exec", (None,))
    _absent_or(body, "extensions", (None, []))
    return {"cert": _strict_base64(body.get("client-certificate-data")),
            "key": _strict_base64(body.get("client-key-data"))}


def _context(body):
    _only(body, CONTEXT_KEYS)
    _absent_or(body, "extensions", (None, []))
    namespace = body.get("namespace", "")
    cluster, user = body.get("cluster"), body.get("user")
    if (not isinstance(namespace, str) or not NAMESPACE.match(namespace)
            or not all(isinstance(v, str) and NAME.match(v) for v in (cluster, user))):
        raise Refusal("context fields are invalid")
    return {"cluster": cluster, "user": user, "namespace": namespace}


def _named(entries, key, clean):
    if not isinstance(entries, list):
        raise Refusal("kubeconfig collections must be lists")
    result = []
    for entry in entries:
        _only(entry, {"name", key})
        name = entry.get("name")
        if set(entry) != {"name", key} or not isinstance(name, str) or not NAME.match(name):
            raise Refusal("named entry is invalid")
        result.append((name, clean(entry[key])))
    if len({name for name, _ in result}) != len(result):
        raise Refusal("duplicate names in kubeconfig")
    return dict(result)


def parse_config(document):
    """Validate the CLOSED effective native Config; returns normalized data only (raw is dropped)."""
    _only(document, ROOT_KEYS)
    if document.get("apiVersion") != "v1" or document.get("kind") != "Config":
        raise Refusal("kubeconfig apiVersion/kind unsupported")
    _absent_or(document, "extensions", (None, []))
    if "preferences" in document:
        preferences = document["preferences"]
        _only(preferences, {"colors", "extensions"})
        _absent_or(preferences, "colors", (False,))
        _absent_or(preferences, "extensions", (None, []))
    current = document.get("current-context")
    if not isinstance(current, str):
        raise Refusal("current-context must be a string")
    return {
        "clusters": _named(document.get("clusters"), "cluster", _cluster),
        "users": _named(document.get("users"), "user", _user),
        "contexts": _named(document.get("contexts"), "context", _context),
        "current": current,
    }


def source_binding(config):
    if not all(len(config[key]) == 1 for key in ("clusters", "users", "contexts")):
        raise Refusal("a source needs exactly one cluster, user and context")
    (context,) = config["contexts"].values()
    cluster, user = config["clusters"].get(context["cluster"]), config["users"].get(context["user"])
    if cluster is None or user is None:
        raise Refusal("source context is not linked to its cluster and user")
    return {**cluster, **user, "namespace": context["namespace"]}


def target_state(config):
    names = {context for context, _ in BINDINGS}
    if (set(config["contexts"]) != names or set(config["clusters"]) != {a for _, a in BINDINGS}
            or set(config["users"]) != {a for _, a in BINDINGS}):
        raise Refusal("output must hold exactly the two prescribed bindings")
    state = {}
    for context, alias in BINDINGS:
        body = config["contexts"][context]
        if body["cluster"] != alias or body["user"] != alias:
            raise Refusal("output bindings are not the prescribed links")
        state[context] = {**config["clusters"][alias], **config["users"][alias],
                          "namespace": body["namespace"]}
    if config["current"] not in names:
        raise Refusal("output selection is not a prescribed context")
    return state, config["current"]


def build_config(state, current):
    """Native input reconstructed solely from validated state; no raw field is ever re-passed."""
    document = {"apiVersion": "v1", "kind": "Config", "preferences": {}, "current-context": current,
                "clusters": [], "users": [], "contexts": []}
    for context, alias in BINDINGS:
        item = state[context]
        document["clusters"].append({"name": alias, "cluster": {
            "server": item["server"], "certificate-authority-data": item["ca"]}})
        document["users"].append({"name": alias, "user": {
            "client-certificate-data": item["cert"], "client-key-data": item["key"]}})
        body = {"cluster": alias, "user": alias}
        if item["namespace"]:
            body["namespace"] = item["namespace"]
        document["contexts"].append({"name": context, "context": body})
    return json.dumps(document, sort_keys=True).encode("utf-8")


# ---- publication ---------------------------------------------------------------------------
def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def publish(run, candidate, target, sources, existing):
    """Recheck every source and the target, then the single commit syscall."""
    for path, (checksum, ident) in sources.items():
        data, now = read_regular(path, INPUT_LIMIT)
        if digest_of(data) != checksum or now != ident:
            raise Refusal("a source changed during the run")
    if existing is None:
        if os.path.lexists(target):
            raise Refusal("output appeared during the run")
    else:
        data, now = read_regular(target, OUTPUT_LIMIT)
        if digest_of(data) != existing[0] or now != existing[1]:
            raise Refusal("output changed during the run")
    # Handled signals are deferred (kernel-pending, not lost) only around the single commit syscall
    # and the outcome flag, so a handler cannot run between them. The mask is restored right after
    # the flag; no deadline is renewed and nothing is rolled back or retried.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    try:
        try:
            if existing is None:
                os.link(candidate, target)  # no-clobber commit
            else:
                os.replace(candidate, target)  # atomic commit
        except FileExistsError:
            raise Refusal("output appeared during the run") from None
        except OSError:
            raise Refusal("publication failed") from None
        run.committed = True
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    sync_directory(target.parent)


def check_arguments(args):
    paths = [args.kubectl, args.vlab_config, args.management_config, args.output]
    for path in paths:
        normalized_absolute(path)
    if len({str(path) for path in paths}) != len(paths):
        raise Refusal("paths must be distinct")
    if (platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64")):
        raise Refusal("unsupported platform")
    if args.output.name.startswith(STAGE_PREFIX):
        raise Refusal("output name is reserved")
    verify_kubectl(args.kubectl)
    real_directory(args.output.parent, private=True)
    for source in (args.vlab_config, args.management_config):
        real_directory(source.parent, private=False)


def stage_and_validate(args, run, stage, budget):
    home = stage / "home"
    os.mkdir(home, 0o700)
    native = Native(args.kubectl, home, budget)
    sources, bindings, identities = {}, {}, []
    for (context, _), label, path in ((VLAB, "vlab-source", args.vlab_config),
                                      (MANAGEMENT, "management-source", args.management_config)):
        data, ident = read_regular(path, INPUT_LIMIT)
        sources[path] = (digest_of(data), ident)
        identities.append(ident[:2])
        write_private(stage / label, data)
        bindings[context] = source_binding(parse_config(load_native_json(native.view(stage / label, "json"))))
    existing = None
    if os.path.lexists(args.output):
        data, ident = read_regular(args.output, OUTPUT_LIMIT)
        existing = (digest_of(data), ident)
        identities.append(ident[:2])
        write_private(stage / "target-snapshot", data)
    if len(set(identities)) != len(identities):
        raise Refusal("input paths alias the same file")
    first, second = bindings[VLAB[0]], bindings[MANAGEMENT[0]]
    if (first["server"], first["ca"]) == (second["server"], second["ca"]):
        raise Refusal("the two prescribed clusters must be distinct")
    current, status = DEFAULT_SELECTION, "installed"
    if existing is not None:
        old, current = target_state(parse_config(load_native_json(
            native.view(stage / "target-snapshot", "json"))))
        for context, _ in BINDINGS:
            for field in ("server", "ca", "namespace"):
                if old[context][field] != bindings[context][field]:
                    raise Refusal("output binding identity or namespace differs from the sources")
        if all(old[c]["cert"] == bindings[c]["cert"] and old[c]["key"] == bindings[c]["key"]
               for c, _ in BINDINGS):
            return "unchanged"
        status = "updated"
    intended = {context: bindings[context] for context, _ in BINDINGS}
    write_private(stage / "candidate-input.json", build_config(intended, current))
    rendered = native.view(stage / "candidate-input.json", "yaml")
    try:
        rendered.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("native output malformed") from None
    write_private(stage / "candidate.yaml", rendered)
    checked = target_state(parse_config(load_native_json(native.view(stage / "candidate.yaml", "json"))))
    if checked != (intended, current):
        raise Refusal("candidate is not equivalent to the intended state")
    publish(run, stage / "candidate.yaml", args.output, sources, existing)
    return status


def configure(args, run):
    budget = Budget()
    check_arguments(args)
    stage = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=args.output.parent))
    try:
        status = stage_and_validate(args, run, stage, budget)
    except BaseException:
        # The primary failure stays the reported outcome; incomplete cleanup is recorded separately.
        if not cleanup(stage):
            run.cleanup_incomplete = True
        raise
    if not cleanup(stage):
        raise Refusal("owned stage cleanup failed")
    return status


# ---- command line --------------------------------------------------------------------------
def report(error, run):
    signal.alarm(0)
    if run.committed:
        print("configure-student-kubeconfig: committed-but-incomplete; do not retry blindly",
              file=sys.stderr)
        code = EXIT_COMMITTED_INCOMPLETE
    elif isinstance(error, KeyboardInterrupt):
        print("configure-student-kubeconfig: interrupted", file=sys.stderr)
        code = 130
    else:
        text = str(error) if isinstance(error, Refusal) else "operational failure"
        print("configure-student-kubeconfig: " + text, file=sys.stderr)
        code = 1
    if run.cleanup_incomplete:
        print("configure-student-kubeconfig: owned stage cleanup incomplete", file=sys.stderr)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for flag in ("--kubectl", "--vlab-config", "--management-config", "--output"):
        parser.add_argument(flag, required=True, type=Path)
    args = parser.parse_args(argv)
    run = Run()

    def expired(_signum, _frame):
        raise Refusal("deadline exceeded")

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    old_alarm = signal.signal(signal.SIGALRM, expired)
    old_term = signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(TOTAL)
    try:
        status = configure(args, run)
        print(json.dumps({"status": status}))
        sys.stdout.flush()
        return 0
    except BaseException as error:
        return report(error, run)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_alarm)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
