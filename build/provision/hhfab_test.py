"""Test-only public-input preparation and isolated official CLI proof.

Host prepare: Python 3.10+ stdlib, curl; network bounded, no hhfab execution.
Guest lane: Ubuntu24.04 Python3.12 + distribution PyYAML, uid1000, no caps/network.
Invoked explicitly by test-hhfab-offline.sh, independent of caller cwd. No sudo,
installation fallback, ambient HHFAB_* settings, production output or VLAB launch.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from hhfab_release import PINS, Refusal, digest, bounded, extract, download

WIRING_SHA = "c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a"
SIZES = {"control": {"cpu": 6, "ram": 6144, "disk": 100},
         "switch": {"cpu": 4, "ram": 5120, "disk": 50},
         "server": {"cpu": 2, "ram": 768, "disk": 10},
         "gateway": {"cpu": 8, "ram": 6144, "disk": 50},
         "external": {"cpu": 4, "ram": 5120, "disk": 50}}



def prepare(destination, source, installer=False):
    if list(destination.iterdir()):
        raise Refusal("preparation destination must be empty")
    if digest(source / "wiringd.yaml") != WIRING_SHA:
        raise Refusal("public wiring checksum mismatch")
    shutil.copyfile(source / "wiringd.yaml", destination / "wiringd.yaml")
    shutil.copyfile(Path(__file__), destination / "hhfab_test.py")
    for name in ("hhfab_release.py", "install-hhfab.py", "test_install_hhfab.py"):
        shutil.copyfile(Path(__file__).with_name(name), destination / name)
    for version, pin in PINS.items():
        archive = destination / (version + ".tar.gz")
        download(version, archive)
        extract(archive, destination / ("hhfab-" + version), pin)
        if not installer:
            archive.unlink()
        print(json.dumps({"version": version, "archive_bytes": pin[0], "archive_sha256": pin[1],
                          "member_bytes": pin[2], "member_sha256": pin[3]}), flush=True)


def require(condition, message):
    if not condition:
        raise Refusal(message)


def tree_hashes(case):
    result = {}
    for path in sorted(case.rglob("*")):
        require(not path.is_symlink(), "unexpected generated symlink")
        if path.is_file():
            require(path.stat().st_size <= 1024 * 1024, "generated file overflow")
            result[str(path.relative_to(case))] = digest(path)
    return result


def check_wiring(path):
    import yaml
    require(digest(path) == WIRING_SHA, "wiring byte identity changed")
    docs = list(yaml.load_all(path.read_bytes(), Loader=yaml.CSafeLoader))
    kinds = {}
    for doc in docs:
        kinds.setdefault(doc["kind"], []).append(doc)
    require({kind: len(items) for kind, items in kinds.items()} == {
        "VLANNamespace": 1, "IPv4Namespace": 1, "SwitchGroup": 3,
        "Switch": 7, "Server": 10, "Connection": 21}, "wiring counts mismatch")
    require(sorted(d["spec"]["role"] for d in kinds["Switch"]) == ["server-leaf"] * 5 + ["spine"] * 2,
            "wiring switch roles mismatch")
    require(kinds["VLANNamespace"][0]["spec"]["ranges"] == [{"from": 1000, "to": 2999}], "VLAN range mismatch")
    require(kinds["IPv4Namespace"][0]["spec"]["subnets"] == ["10.0.0.0/16"], "IPv4 namespace mismatch")
    return docs


def check_zero_topology(generated, fabric):
    """Inspect only the bounded public no-switch fixture with distribution libyaml."""
    import yaml
    for path in (generated, fabric):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
                "zero-topology file invalid or oversized")
    try:
        wiring = list(yaml.load_all(generated.read_bytes(), Loader=yaml.CSafeLoader))
        nodes = list(yaml.load_all(fabric.read_bytes(), Loader=yaml.CSafeLoader))
    except yaml.YAMLError:
        raise Refusal("zero-topology config malformed") from None
    for doc in wiring + nodes:
        require(isinstance(doc, dict) and isinstance(doc.get("kind"), str)
                and isinstance(doc.get("metadata"), dict)
                and isinstance(doc["metadata"].get("name"), str), "zero-topology object malformed")
    identities = lambda docs: sorted((d["kind"], d["metadata"]["name"]) for d in docs)
    require(identities(wiring) == [("IPv4Namespace", "default"), ("SwitchGroup", "empty"), ("VLANNamespace", "default")],
            "generated wiring identities mismatch")
    require(identities(nodes) == [("ControlNode", "control-1"), ("Fabricator", "default")],
            "generated nodes are not exactly the expected control")
    kinds = {d["kind"]: d for d in wiring}
    require(kinds["SwitchGroup"].get("spec") == {}, "generated empty switch group mismatch")
    require(kinds["VLANNamespace"].get("spec") == {"ranges": [{"from": 1000, "to": 2999}]},
            "generated VLAN namespace mismatch")
    require(kinds["IPv4Namespace"].get("spec") == {"subnets": ["10.0.0.0/16"]},
            "generated IPv4 namespace mismatch")
    return {"wiring_kinds": sorted(kinds), "node_kinds": sorted(d["kind"] for d in nodes)}


def fixture_cli(binary, cache, env, deadline):
    """Bind the existing fixed public commands to one lane's isolation and deadline."""
    def cli(command, case, extra=()):
        require(command in ("init", "validate", "versions", "vlab generate"), "unexpected fixture command")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "lane deadline exceeded")
        return bounded([str(binary), *command.split(), "--workdir", str(case), "--cache-dir", str(cache), *extra],
                       min(30, remaining), env=env)

    def init(case, wiring="/suite/wiringd.yaml", mode="spine-leaf"):
        require(case.is_dir() and not case.is_symlink() and not list(case.iterdir()),
                "init requires fresh owned empty case")
        return cli("init", case, ["--fabric-mode", mode, "--dev", "--gateway=false",
                                 "--registry-repo", "ghcr.io", "--registry-prefix", "githedgehog",
                                 *(["--wiring", str(wiring)] if wiring is not None else [])])

    def validate(case):
        return cli("validate", case, ["--hydrate-mode", "if-not-present"])

    return cli, init, validate


def no_switch_smoke(cli, init, validate, case):
    """Fresh init (no wiring) -> official vlab generate --no-switches -> validate."""
    require(init(case, None)[0] == 0, "official init refused no-switch fixture")
    require(not list((case / "include").iterdir()), "init left unexpected include files")
    require(cli("vlab generate", case, ["--no-switches"])[0] == 0, "official generate --no-switches refused")
    generated = case / "include/vlab.generated.yaml"
    require([p.name for p in (case / "include").iterdir()] == ["vlab.generated.yaml"] and generated.is_file(),
            "unexpected generated include outputs")
    tree_hashes(case)
    require(validate(case)[0] == 0, "official validate refused no-switch fixture")
    require([p.name for p in (case / "include").iterdir()] == ["vlab.generated.yaml"],
            "validation left unexpected include outputs")
    require({p.name for p in case.iterdir()} == {"fab.yaml", ".registry.yaml", "include", "result"},
            "unexpected no-switch outputs")
    require(not list((case / "result").iterdir()), "unexpected persisted no-switch result")
    summary = check_zero_topology(generated, case / "fab.yaml")
    before = tree_hashes(case)
    require(validate(case)[0] == 0 and tree_hashes(case) == before, "no-switch validation rerun changed fixture")
    summary["tree_sha256"] = before
    return summary


def config_import_smoke(cli, validate, source, case, wiring, binary):
    """Import only the generated public 0.43.1 candidate, never original inputs."""
    require(case.is_dir() and not case.is_symlink() and not list(case.iterdir())
            and case != source, "config import requires fresh owned empty case")
    pin = PINS["0.43.1"]

    def tool_identity():
        require(binary.is_file() and not binary.is_symlink()
                and binary.stat().st_size == pin[2] and digest(binary) == pin[3],
                "config import binary identity mismatch")

    def fixture_identity(directory):
        require({p.name for p in directory.iterdir()} == {"fab.yaml", ".registry.yaml", "include", "result"}
                and (directory / "include").is_dir() and (directory / "result").is_dir(),
                "config import fixture outputs mismatch")
        require({p.name for p in (directory / "include").iterdir()} == {"wiringd.yaml"}
                and not list((directory / "result").iterdir()), "config import fixture contents mismatch")
        return tree_hashes(directory)

    tool_identity()
    check_wiring(wiring)
    before = fixture_identity(source)
    require(before["include/wiringd.yaml"] == WIRING_SHA, "config import source wiring mismatch")
    require(cli("init", case, ["--config", str(source / "fab.yaml"),
                              "--registry-repo", "ghcr.io", "--registry-prefix", "githedgehog",
                              "--wiring", str(wiring)])[0] == 0, "official config import refused")

    def preserved():
        require(fixture_identity(source) == before, "config import changed source fixture")
        require(fixture_identity(case) == before, "config import changed candidate bytes or objects")
        check_wiring(wiring)
        tool_identity()

    preserved()
    require(validate(case)[0] == 0, "official validate refused imported config")
    preserved()
    require(validate(case)[0] == 0, "official imported config validation rerun refused")
    preserved()
    return {"scope": "generated-public-candidate-only", "tree_sha256": before}


def lane(version):
    import yaml
    require(hasattr(yaml, "CSafeLoader"), "distribution CSafeLoader unavailable")
    require(os.environ.get("LABAPP_HHFAB_TEST") == "1" and os.getuid() == 1000,
            "requires isolated nonroot test runner")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(int(status["CapEff"].strip(), 16) == 0 and status["NoNewPrivs"].strip() == "1",
            "runtime privilege isolation mismatch")
    require({p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}, "runtime network isolation mismatch")
    require(version in PINS, "unapproved version")
    binary = Path("/suite/hhfab-" + version)
    require(binary.stat().st_size == PINS[version][2] and digest(binary) == PINS[version][3],
            "baked binary identity mismatch")
    docs = check_wiring(Path("/suite/wiringd.yaml"))
    deadline = time.monotonic() + 120
    env = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "XDG_CACHE_HOME": "/work/cache",
           "LANG": "C.UTF-8", "GOMAXPROCS": "2"}
    Path(env["HOME"]).mkdir(mode=0o700)
    cache = Path("/work/cache")
    cache.mkdir(mode=0o700)
    checks = []
    summaries = []

    cli, init, validate = fixture_cli(binary, cache, env, deadline)

    def versions(case):
        # CLI versions can succeed with defaults even without config: guard FIRST.
        require((case / "fab.yaml").is_file() and (case / "include/wiringd.yaml").is_file(),
                "versions requires existing fixture")
        require(validate(case)[0] == 0, "versions requires validated fixture")
        return cli("versions", case, ["--hydrate-mode", "if-not-present"])

    for run in range(2):
        case = Path(tempfile.mkdtemp(prefix="fresh-", dir="/work"))
        require(init(case)[0] == 0, "official init refused approved fixture")
        require(validate(case)[0] == 0, "official validate refused approved fixture")
        check_wiring(case / "include/wiringd.yaml")
        require({p.name for p in case.iterdir()} == {"fab.yaml", ".registry.yaml", "include", "result"},
                "unexpected init outputs")
        require(not list((case / "result").iterdir()), "unexpected persisted result")
        fabric = list(yaml.load_all((case / "fab.yaml").read_bytes(), Loader=yaml.CSafeLoader))
        require([(d["kind"], d["metadata"]["name"]) for d in fabric] ==
                [("Fabricator", "default"), ("ControlNode", "control-1")], "generated object identity mismatch")
        require(fabric[0]["spec"]["config"]["fabric"]["mode"] == "spine-leaf", "generated mode mismatch")
        before = tree_hashes(case)
        require(validate(case)[0] == 0 and tree_hashes(case) == before, "validation rerun changed fixture")
        code, output = versions(case)
        require(code == 0 and tree_hashes(case) == before, "versions failed or changed fixture")
        # Version output kept local and hashed, never export config/log text.
        summaries.append({"text_sha256": before, "versions_stdout_sha256": hashlib.sha256(output).hexdigest()})
        checks.extend(["fresh-init", "official-validate", "exact-wiring", "rerun-preservation", "versions-after-validation"])
    require(summaries[0]["text_sha256"] == summaries[1]["text_sha256"], "fresh text nondeterministic")
    checks.append("deterministic-fresh-text")
    good = case
    good_hashes = tree_hashes(good)
    imported = None
    if version == "0.43.1":
        imported = config_import_smoke(cli, validate, good,
                                      Path(tempfile.mkdtemp(prefix="import-", dir="/work")),
                                      Path("/suite/wiringd.yaml"), binary)
        checks.append("public-config-import-preserved-and-revalidated")
    negatives = {
        "malformed-yaml": b"kind: [\n",
        "unsupported-gvk": b"apiVersion: unsupported.example/v1\nkind: Surprise\nmetadata: {name: bad}\n",
        "duplicate-object": Path("/suite/wiringd.yaml").read_bytes() + b"\n---\n" + yaml.safe_dump(docs[0]).encode(),
    }
    for name, port in [("nonexistent-endpoint", "missing/E1/8"), ("invalid-port", "leaf-01/E999/999")]:
        changed = json.loads(json.dumps(docs))
        next(d for d in changed if d["kind"] == "Connection" and "fabric" in d["spec"])["spec"]["fabric"]["links"][0]["leaf"]["port"] = port
        negatives[name] = yaml.safe_dump_all(changed).encode()
    # One switch with a persisted hydration field mixed into otherwise unhydrated graph.
    changed = json.loads(json.dumps(docs))
    next(d for d in changed if d["kind"] == "Switch")["spec"]["ip"] = "172.30.0.10/21"
    negatives["partial-hydration"] = yaml.safe_dump_all(changed).encode()
    for name, body in negatives.items():
        input_path = Path("/work") / (name + ".yaml")
        input_path.write_bytes(body)
        bad = Path(tempfile.mkdtemp(prefix="bad-", dir="/work"))
        code, output = init(bad, input_path)
        if code == 0:
            code, output = validate(bad)
        require(code == 1, "negative fixture did not return semantic refusal: " + name)
        if name == "partial-hydration":
            require(b"already partially hydrated" in output,
                    "partial fixture missed hydration refusal")
        require(tree_hashes(good) == good_hashes, "negative fixture changed good case")
        checks.append("reject-" + name)
    bad = Path(tempfile.mkdtemp(prefix="bad-mode-", dir="/work"))
    require(init(bad, mode="invalid-mode")[0] != 0, "invalid fabric mode accepted")
    checks.append("reject-invalid-mode")
    empty = Path(tempfile.mkdtemp(prefix="missing-", dir="/work"))
    try:
        versions(empty)
    except Refusal as error:
        require(str(error) == "versions requires existing fixture", "wrong missing-fixture refusal")
    else:
        raise Refusal("missing fixture allowed versions")
    checks.append("reject-missing-config-before-versions")
    no_switch = no_switch_smoke(cli, init, validate, Path(tempfile.mkdtemp(prefix="noswitch-", dir="/work")))
    checks.append("no-switch-smoke")
    # Test unchanged bounded executor against real isolated children (not simulated exit0).
    for name, program, seconds, limit in [
        ("timeout", "import time; time.sleep(10)", 0.1, 1024),
        ("output overflow", "import os; os.write(1,b'x'*65536)", 2, 1024),
    ]:
        try:
            bounded([sys.executable, "-c", program], seconds, limit)
        except Refusal as error:
            require(str(error) == "command " + name, "wrong child bound refusal")
        else:
            raise Refusal("child bound failed")
        checks.append("child-" + name.replace(" ", "-"))
    require(all(set(v) == {"cpu", "ram", "disk"} and all(type(n) is int and 0 < n < 65536 for n in v.values())
                for v in SIZES.values()), "invalid separate sizing fixture")
    checks.append("sizing-fixture-only")
    report = {"schema": 1, "version": version, "status": "passed", "checks": checks,
              "fresh_runs": summaries, "no_switch": no_switch,
              "sizing_scope": "fixture-only; not upstream VLAB validation"}
    if imported is not None:
        report["config_import"] = imported
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if len(sys.argv) == 4 and sys.argv[1] in ("prepare", "prepare-install"):
            prepare(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[1] == "prepare-install")
        elif len(sys.argv) == 4 and sys.argv[1] == "attach":
            code, output = bounded(["docker", "start", "-a", sys.argv[2]], 135)
            report = Path(sys.argv[3])
            previous = report.stat().st_size if report.exists() else 0
            require(previous + len(output) <= 1024 * 1024, "combined report overflow")
            with report.open("ab") as stream:
                stream.write(output)
            sys.stdout.buffer.write(output)
            sys.exit(code)
        elif len(sys.argv) == 3 and sys.argv[1] == "lane":
            lane(sys.argv[2])
        else:
            raise Refusal("invalid test invocation")
    except KeyboardInterrupt:
        print("hhfab test: interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        # Only Refusal messages are safe controlled diagnostics.
        print("hhfab test: " + (str(error) if isinstance(error, Refusal) else "operational failure"), file=sys.stderr)
        sys.exit(1)
