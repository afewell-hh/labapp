"""Assemble one private student kubeconfig (JSON) from two synthetic-shaped single-context JSON configs.

Python 3.12 stdlib only: no child processes, network, YAML parser, kubectl, plugin or ambient config.
Invoke python3 /absolute/path/configure-student-kubeconfig.py --vlab-json /abs/vlab.json
--management-json /abs/management.json --output /abs/dir/config

Inputs are caller-owned 0600 single-link regular JSON files (<= 64 KiB), each exactly one
v1 Config with one cluster (HTTPS server + embedded base64 CA), one user (embedded base64
client certificate/key) and one context linked by current-context; an optional empty
preferences object and optional context namespace are allowed. Anything else (tokens, exec,
auth providers, file references, proxy, insecure TLS, extensions, unknown keys, duplicate
JSON keys, nonfinite numbers) is refused. Native YAML-to-JSON export is a separate, explicit
step outside this component. The output is ordinary Kubernetes Config JSON with contexts
vlab (clusters/users labapp-vlab) and k3d-k3d-observability (labapp-management), initial
current-context vlab, mode 0600, in a caller-owned 0700 directory that must already exist.

Rerun: an existing output must be an owned 0600 single-link file that is exactly the canonical
two-context shape with the same per-context HTTPS endpoint, CA bytes and namespace; then
identical content is left untouched ("unchanged") and changed credentials replace it
atomically ("updated"), preserving its current-context. Anything else is refused and the
previous bytes are kept. These are configuration binding checks only: no certificate is
parsed, no principal, authorization or real cluster identity is verified, and no DNS or
network inference is done (endpoint equality lowercases the host, defaults port 443 and
ignores a trailing slash only). The public result is a fixed JSON status with no config or
credential content; errors are fixed messages. Absent output is published no-clobber; updates
use an owned staging file and os.replace; there is no rollback after publication. Callers must
exclude concurrent mutation of the output directory and its ancestors.
"""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
from urllib.parse import urlsplit

COMPONENT = "configure-student-kubeconfig"
INPUT_LIMIT = 64 * 1024
OUTPUT_LIMIT = 256 * 1024
NAME_LIMIT = 253
SERVER_LIMIT = 2048
TOTAL = 30  # finite whole-run assumption in seconds, not measured fit
VLAB = "vlab"
MANAGEMENT = "k3d-k3d-observability"
ROLES = ((VLAB, "labapp-vlab"), (MANAGEMENT, "labapp-management"))
STAGE_PREFIX = ".student-kubeconfig-stage-"
NAMESPACE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


class Refusal(Exception):
    """Fixed-message refusal; messages never contain input or output content."""


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def real_parents(path):
    if not path.is_absolute() or ".." in path.parts or path != Path(os.path.normpath(path)):
        raise Refusal("paths must be absolute and normalized")
    for component in reversed(path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            raise Refusal("path directory missing") from None
        if not stat.S_ISDIR(info.st_mode):
            raise Refusal("path components must be real directories")


def private_directory(path):
    real_parents(path / "x")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refusal("output directory must be caller-owned mode 0700")


def private_file(info, limit):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
        raise Refusal("file must be a caller-owned 0600 single-link regular file within the size bound")


def read_private(path, limit):
    real_parents(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise Refusal("input file missing") from None
    private_file(before, limit)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        private_file(info, limit)
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise Refusal("file changed while opening")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise Refusal("file exceeds the size bound")
    return data, info


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal("duplicate JSON key")
            result[key] = value
        return result

    def number(_text):
        raise Refusal("numbers are not allowed")

    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=number,
                            parse_float=number, parse_int=number)
    except (ValueError, RecursionError):
        raise Refusal("input is not valid strict JSON") from None
    if type(parsed) is not dict:
        raise Refusal("config must be a JSON object")
    return parsed


def text(value, limit=NAME_LIMIT):
    if type(value) is not str or not re.fullmatch(r"[!-~]{1,%d}" % limit, value):
        raise Refusal("invalid string value")
    return value


def keys(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) <= set(required) | set(optional):
        raise Refusal("unexpected or missing keys")
    return value


def blob(value):
    text(value, INPUT_LIMIT)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Refusal("embedded data must be strict base64") from None
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise Refusal("embedded data must be nonempty canonical base64")
    return decoded


def endpoint(server):
    text(server, SERVER_LIMIT)
    if not server.startswith("https://") or any(mark in server for mark in "@?#\\"):
        raise Refusal("server must be a plain https URL")
    try:
        parts = urlsplit(server)
        port = parts.port
    except ValueError:
        raise Refusal("server URL is invalid") from None
    if not parts.hostname or port == 0:
        raise Refusal("server URL is invalid")
    return (parts.hostname, 443 if port is None else port, parts.path.rstrip("/"))


def named(items, label, count, required, optional=()):
    if type(items) is not list or len(items) != count:
        raise Refusal("unexpected number of config entries")
    found = {}
    for item in items:
        keys(item, ("name", label))
        name = text(item["name"])
        if name in found:
            raise Refusal("duplicate entry name")
        found[name] = keys(item[label], required, optional)
    return found


def records(config, count):
    keys(config, ("apiVersion", "kind", "clusters", "users", "contexts", "current-context"), ("preferences",))
    if config["apiVersion"] != "v1" or config["kind"] != "Config":
        raise Refusal("config must be apiVersion v1 kind Config")
    if "preferences" in config and (type(config["preferences"]) is not dict or config["preferences"]):
        raise Refusal("preferences must be empty")
    clusters = named(config["clusters"], "cluster", count, ("server", "certificate-authority-data"))
    users = named(config["users"], "user", count, ("client-certificate-data", "client-key-data"))
    contexts = named(config["contexts"], "context", count, ("cluster", "user"), ("namespace",))
    current = text(config["current-context"])
    if current not in contexts:
        raise Refusal("current-context must name a context")
    found = []
    for name, context in contexts.items():
        cluster = clusters.get(text(context["cluster"]))
        user = users.get(text(context["user"]))
        if cluster is None or user is None:
            raise Refusal("context links a missing cluster or user")
        namespace = context.get("namespace")
        if namespace is not None and (type(namespace) is not str or not NAMESPACE.fullmatch(namespace)):
            raise Refusal("invalid namespace")
        found.append({
            "context": name, "cluster": context["cluster"], "user": context["user"],
            "server": cluster["server"], "endpoint": endpoint(cluster["server"]),
            "ca_text": cluster["certificate-authority-data"], "ca": blob(cluster["certificate-authority-data"]),
            "cert": user["client-certificate-data"], "key": user["client-key-data"],
            "namespace": namespace,
        })
        blob(user["client-certificate-data"])
        blob(user["client-key-data"])
    if len({r["cluster"] for r in found}) != count or len({r["user"] for r in found}) != count:
        raise Refusal("contexts must not share a cluster or user")
    return found, current


def build(by_role, current):
    config = {"apiVersion": "v1", "kind": "Config", "preferences": {}, "current-context": current,
              "clusters": [], "users": [], "contexts": []}
    for context, alias in ROLES:
        rec = by_role[context]
        config["clusters"].append({"name": alias, "cluster": {
            "server": rec["server"], "certificate-authority-data": rec["ca_text"]}})
        config["users"].append({"name": alias, "user": {
            "client-certificate-data": rec["cert"], "client-key-data": rec["key"]}})
        entry = {"cluster": alias, "user": alias}
        if rec["namespace"] is not None:
            entry["namespace"] = rec["namespace"]
        config["contexts"].append({"name": context, "context": entry})
    return config


def serialize(config):
    data = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > OUTPUT_LIMIT:
        raise Refusal("output exceeds the size bound")
    return data


def existing_state(path):
    data, info = read_private(path, OUTPUT_LIMIT)
    found, current = records(strict_json(data), 2)
    by_role = {rec["context"]: rec for rec in found}
    if set(by_role) != {VLAB, MANAGEMENT} or current not in by_role:
        raise Refusal("existing output is not the canonical two-context config")
    if build(by_role, current) != strict_json(data):
        raise Refusal("existing output is not the canonical two-context config")
    return data, info, by_role, current


def publish(output, data, existing):
    stage_descriptor, stage_name = tempfile.mkstemp(prefix=STAGE_PREFIX, dir=output.parent)
    stage = Path(stage_name)
    try:
        with os.fdopen(stage_descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if existing is None:
            try:
                os.link(stage, output)  # no-clobber publication of an absent target
            except FileExistsError:
                raise Refusal("output appeared during installation") from None
        else:
            try:
                changed = identity(output.lstat()) != identity(existing)
            except OSError:
                changed = True
            if changed:
                raise Refusal("output changed during update")
            os.replace(stage, output)
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        # Preserve a primary failure, but never report success after failed cleanup.
        primary = sys.exc_info()[0] is not None
        try:
            os.unlink(stage)
        except FileNotFoundError:
            pass
        except OSError:
            if not primary:
                raise Refusal("owned stage cleanup failed after publication") from None


def configure(vlab_path, management_path, output):
    paths = (vlab_path, management_path, output)
    if len({str(p) for p in paths}) != 3:
        raise Refusal("input and output paths must be distinct")
    private_directory(output.parent)
    inputs = []
    for path in paths[:2]:
        data, info = read_private(path, INPUT_LIMIT)
        found, _ = records(strict_json(data), 1)
        inputs.append((found[0], (info.st_dev, info.st_ino)))
    (vlab, vlab_id), (management, management_id) = inputs
    if vlab_id == management_id:
        raise Refusal("input and output paths must be distinct")
    if (vlab["endpoint"], vlab["ca"]) == (management["endpoint"], management["ca"]):
        raise Refusal("both inputs bind the same endpoint and CA")
    by_role = {VLAB: vlab, MANAGEMENT: management}
    if not os.path.lexists(output):
        publish(output, serialize(build(by_role, VLAB)), None)
        return "installed"
    data, info, kept, current = existing_state(output)
    if (info.st_dev, info.st_ino) in {vlab_id, management_id}:
        raise Refusal("input and output paths must be distinct")
    for role in kept:
        old, new = kept[role], by_role[role]
        if (old["endpoint"], old["ca"], old["namespace"]) != (new["endpoint"], new["ca"], new["namespace"]):
            raise Refusal("existing output binding differs from the inputs")
    updated = serialize(build(by_role, current))
    if updated == data:
        return "unchanged"
    publish(output, updated, info)
    return "updated"


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--vlab-json", required=True, type=Path)
    parser.add_argument("--management-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    def expired(_signum, _frame):
        raise Refusal("deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(TOTAL)
    try:
        status = configure(args.vlab_json, args.management_json, args.output)
        print(json.dumps({"component": COMPONENT, "status": status}, sort_keys=True))
        return 0
    except Refusal as error:
        print(COMPONENT + ": " + str(error), file=sys.stderr)
    except Exception:
        print(COMPONENT + ": operational failure", file=sys.stderr)
    finally:
        signal.alarm(0)
    return 1


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(cli())
    except KeyboardInterrupt:
        print(COMPONENT + ": interrupted", file=sys.stderr)
        sys.exit(130)
