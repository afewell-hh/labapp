#!/usr/bin/env python3
"""Root-only Ubuntu24.04 noble amd64 Python3.12 fixed Docker package component.

Installs exactly docker-ce and docker-ce-cli 5:29.1.3-1~ubuntu.24.04~noble and
containerd.io 2.2.1-1~ubuntu.24.04~noble with --no-install-recommends, plus
whatever dependencies the reviewed simulation shows. Needs apt/dpkg, curl, HTTPS
CA certificates, the Ubuntu archive keyring and sibling hhfab_release.py. Any
cwd; no shell/login environment. Uses a private APT config/key/sources/
preferences/lists/cache and never edits /etc/apt. Run on disposable guests: APT
cannot roll back a partial dpkg failure and this module does not repair one.
Source-only: does not configure users, daemon, k3d, VLAB or recommendations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import sys
import tempfile
import time

from hhfab_release import Refusal, bounded, digest

SNAPSHOT = "20260114T000000Z"
DOCKER_VERSION = "5:29.1.3-1~ubuntu.24.04~noble"
PINS = {"docker-ce": DOCKER_VERSION, "docker-ce-cli": DOCKER_VERSION,
        "containerd.io": "2.2.1-1~ubuntu.24.04~noble"}
# Declared SHA256 of the original .deb archives (#315 independent review).
ARCHIVES = {"docker-ce": "010dee76e0c1833e1e538b4897e914a2d2d23972acb8798baf056565202a06ab",
            "docker-ce-cli": "06e43beef08b66d39c24d38bcbe2e64889a59f6228ff715e1a27f967a3aa37cb",
            "containerd.io": "95e5464da24724dafc576075401c1e781f50f713f62237ee2ae93e220e3e1273"}
KEY_SHA256 = "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
KEY_URL = "https://download.docker.com/linux/ubuntu/gpg"
KEY_MAX = 16 * 1024
UBUNTU_KEY = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
# Packages that collide with the reviewed trio (Docker's documented removal list).
CONFLICTS = ("docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
             "podman-docker", "containerd", "runc")
# Payloads: package -> package-relative path verified against dpkg md5sums.
PAYLOADS = {"docker-ce": "usr/bin/dockerd", "docker-ce-cli": "usr/bin/docker",
            "containerd.io": "usr/bin/containerd"}
EXTRA_PAYLOADS = ("usr/bin/runc", "usr/bin/ctr")  # shipped by containerd.io
# Paths that must be absent (no unowned collision) before the first install.
COLLISION_PATHS = ("/usr/bin/dockerd", "/usr/bin/docker", "/usr/bin/containerd", "/usr/bin/runc",
                   "/usr/bin/ctr", "/usr/lib/systemd/system/docker.service",
                   "/usr/lib/systemd/system/containerd.service")
MAX_PLAN = 32
BUDGET, CHILD_CAP, ALARM = 210, 180, 235
BASE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
            "DEBIAN_FRONTEND": "noninteractive", "HOME": "/root"}


def call(args, seconds=10, env=None):
    code, out = bounded(args, seconds, env=dict(BASE_ENV if env is None else env))
    if code:
        raise Refusal(f"command failed: {Path(args[0]).name} code={code!r} output_tail={out[-4096:]!r}")
    return out


def installed():
    rows = call(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n"]).decode().splitlines()
    parts = [row.split("\t") for row in rows]
    return {p[0]: p[1] for p in parts if len(p) == 3 and p[2] == "installed"}


def safe_tree(path, uids=(0,)):
    """Refuse links, foreign owners and writable-by-others in an existing private tree."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise Refusal("unsafe link path")
    if info.st_uid not in uids or info.st_mode & 0o022:
        raise Refusal("unowned or writable path")
    if stat.S_ISDIR(info.st_mode):
        for child in sorted(Path(path).iterdir()):
            safe_tree(child, uids)
    elif stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            raise Refusal("unsafe link path")
    else:
        raise Refusal("unexpected special file")


def system_paths():
    for path in ("/var/lib/dpkg", "/var/lib/dpkg/status", "/usr", "/usr/bin", "/var/tmp"):
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise Refusal("unsafe or unowned system path: " + path)
    for path in COLLISION_PATHS:
        parent = os.path.dirname(path)
        if os.path.lexists(parent) and os.path.islink(parent):
            raise Refusal("unsafe link parent: " + parent)


def verify_payloads():
    """Compare mandatory payloads with the installed packages' own md5sums."""
    shas = {}
    wanted = {name: [rel] for name, rel in PAYLOADS.items()}
    wanted["containerd.io"] += list(EXTRA_PAYLOADS)
    for package, relatives in wanted.items():
        metadata = call(["/usr/bin/dpkg-query", "--control-show", package, "md5sums"]).decode()
        expected = dict(line.split(None, 1)[::-1] for line in metadata.splitlines() if line.strip())
        for relative in relatives:
            artifact = Path("/") / relative
            if artifact.is_symlink() or not artifact.is_file() or relative not in expected:
                raise Refusal("installed pinned artifact missing: " + package)
            data = artifact.read_bytes()
            if hashlib.md5(data).hexdigest() != expected[relative]:  # dpkg md5sums format
                raise Refusal("installed pinned artifact drift: " + package)
            shas[relative] = hashlib.sha256(data).hexdigest()
    return shas


def health():
    if call(["/usr/bin/dpkg", "--audit"]).strip():
        raise Refusal("broken dpkg state")
    if call(["/usr/bin/apt-mark", "showhold"]).strip():
        raise Refusal("held packages require explicit resolution")


def preflight():
    if os.geteuid() != 0:
        raise Refusal("root required")
    if sys.version_info[:2] != (3, 12):
        raise Refusal("Python 3.12 required")
    release = Path("/etc/os-release").read_text().splitlines()
    if ("ID=ubuntu" not in release or 'VERSION_ID="24.04"' not in release
            or "VERSION_CODENAME=noble" not in release):
        raise Refusal("Ubuntu 24.04 noble required")
    if call(["/usr/bin/dpkg", "--print-architecture"]).strip() != b"amd64":
        raise Refusal("amd64 required")
    if call(["/usr/bin/dpkg", "--print-foreign-architectures"]).strip():
        raise Refusal("foreign architectures unsupported")
    health()
    for path in (UBUNTU_KEY, "/etc/ssl/certs/ca-certificates.crt"):
        if not Path(path).is_file():
            raise Refusal("archive keyring/CA dependency missing")
    before = installed()
    for name in CONFLICTS:
        if name in before:
            raise Refusal("conflicting package installed: " + name)
    for name, version in PINS.items():
        if name in before and before[name] != version:
            raise Refusal("installed pinned package drift: " + name)
    system_paths()
    if not all(before.get(n) == v for n, v in PINS.items()):
        if any(n in before for n in PINS):
            raise Refusal("partially installed trio unsupported")
        for path in COLLISION_PATHS:
            if os.path.lexists(path):
                raise Refusal("unowned payload path collision: " + path)
    return before


def setup(root):
    """Private APT contract; nothing here touches /etc/apt or the global config."""
    root.chmod(0o755)
    for name in ("lists/partial", "archives/partial", "parts", "preferences", "keys"):
        (root / name).mkdir(parents=True, exist_ok=True)
    key = root / "keys" / "docker.asc"
    (root / "sources.list").write_text(
        f"deb [arch=amd64 signed-by={key}] https://download.docker.com/linux/ubuntu noble stable\n"
        + "".join(f"deb [arch=amd64 signed-by={UBUNTU_KEY}] "
                  f"https://snapshot.ubuntu.com/ubuntu/{SNAPSHOT}/ {suite} main universe\n"
                  for suite in ("noble", "noble-updates", "noble-security")))
    # Exact trio versions from the Docker source; other Docker packages unselectable.
    (root / "preferences" / "docker.pref").write_text(
        "".join(f"Package: {n}\nPin: version {v}\nPin-Priority: 990\n\n" for n, v in PINS.items())
        + "Package: *\nPin: origin download.docker.com\nPin-Priority: -1\n")
    # APT_CONFIG is parsed before ambient files; main/parts point at empty owned paths.
    config = root / "fixed.conf"
    config.write_text(f'Dir::Etc::main "{root}/none";\nDir::Etc::parts "{root}/parts";\n')
    settings = {
        "Dir::Etc::sourcelist": str(root / "sources.list"), "Dir::Etc::sourceparts": str(root / "parts"),
        "Dir::Etc::preferences": str(root / "preferences/none"),
        "Dir::Etc::preferencesparts": str(root / "preferences"),
        "Dir::Etc::netrc": str(root / "none"), "Dir::Etc::netrcparts": str(root / "parts"),
        "Dir::State::lists": str(root / "lists"), "Dir::Cache::archives": str(root / "archives"),
        "Dir::Cache::pkgcache": "", "Dir::Cache::srcpkgcache": "",
        "APT::Architecture": "amd64", "APT::Architectures::": "amd64",
        "APT::Install-Recommends": "false", "APT::Install-Suggests": "false",
        "Acquire::Retries": "1", "Acquire::https::Timeout": "15", "Acquire::GzipIndexes": "true",
        "DPkg::Lock::Timeout": "10", "APT::Get::AllowUnauthenticated": "false",
        "Acquire::AllowInsecureRepositories": "false", "Acquire::AllowWeakRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false", "Acquire::Check-Valid-Until": "true",
        "APT::Get::allow-Downgrades": "false", "APT::Get::allow-Change-Held-Packages": "false",
        "APT::Get::Remove": "false"}
    options = [item for k, v in settings.items() for item in ("-o", k + "=" + v)]
    return ["/usr/bin/apt-get", *options], str(config), key


def fetch_key(run, key):
    run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
         "--max-time", "30", "--max-filesize", str(KEY_MAX), "--output", str(key), KEY_URL], plain=True)
    if key.is_symlink() or not key.is_file() or key.stat().st_size > KEY_MAX or digest(key) != KEY_SHA256:
        raise Refusal("Docker key SHA256 mismatch")
    key.chmod(0o644)


def check_plan(text):
    """Refuse simulations that remove/purge/upgrade anything or miss the exact trio."""
    seen, count = {}, 0
    for line in text.splitlines():
        if line.startswith(("Remv ", "Purg ")):
            raise Refusal("simulation removes packages")
        if not line.startswith("Inst "):
            continue
        count += 1
        match = re.match(r"Inst (\S+)( \[[^\]]+\])? \((\S+) ", line)
        if not match:
            raise Refusal("unparseable simulation line")
        name, old, version = match.group(1), match.group(2), match.group(3)
        if old and name not in PINS:
            raise Refusal("simulation upgrades unrelated package: " + name)
        if name in CONFLICTS:
            raise Refusal("simulation selects conflicting package: " + name)
        seen[name] = version
    if count > MAX_PLAN:
        raise Refusal("simulation plan too large")
    if any(seen.get(n) != v for n, v in PINS.items()):
        raise Refusal("simulation does not select exact reviewed versions")


def receipt_for(after, shas):
    here = Path(__file__).parent
    return {"format": "labapp-docker-receipt-v1", "snapshot": SNAPSHOT, "pins": PINS,
            "archives": ARCHIVES, "key_sha256": KEY_SHA256,
            "module": {n: digest(here / n) for n in ("install-docker.py", "hhfab_release.py")},
            "installed": {n: after[n] for n in PINS}, "payload_sha256": shas}


def install(receipt_path=None):
    started = time.monotonic()
    before = preflight()
    complete = all(before.get(n) == v for n, v in PINS.items())
    with tempfile.TemporaryDirectory(prefix="labapp-docker-", dir="/var/tmp") as temporary:
        root = Path(temporary)
        apt, config, key = setup(root)
        safe_tree(root)

        def run(args, plain=False):
            remaining = BUDGET - (time.monotonic() - started)
            if remaining <= 0:
                raise Refusal("installation deadline exceeded")
            env = dict(BASE_ENV) if plain else {**BASE_ENV, "APT_CONFIG": config}
            return call(args, min(CHILD_CAP, remaining), env=env)
        if not complete:
            fetch_key(run, key)
            run([*apt, "-o", "APT::Update::Error-Mode=any", "update"])
            safe_tree(root, uids=(0, apt_uid()))
            # Configured-but-unsatisfied relations are not a dpkg audit failure.
            run([*apt, "check"])
            selected = [n + "=" + v for n, v in PINS.items()]
            plan = run([*apt, "--simulate", "--no-remove", "--no-install-recommends", "install", *selected])
            check_plan(plan.decode(errors="replace"))
            run([*apt, "--yes", "--no-remove", "--no-install-recommends", "--download-only", "install", *selected])
            for name, version in PINS.items():
                files = sorted((root / "archives").glob(f"{name}_{version.split(':')[-1]}_amd64.deb"))
                if len(files) != 1 or digest(files[0]) != ARCHIVES[name]:
                    raise Refusal("trio archive digest mismatch: " + name)
            run([*apt, "--yes", "--no-remove", "--no-install-recommends", "--no-download", "install", *selected])
        run([*apt, "check"])
        after = installed()
        if any(after.get(n) != v for n, v in PINS.items()):
            raise Refusal("installed version mismatch")
        health()
        shas = verify_payloads()
        receipt = receipt_for(after, shas)
    persist(receipt_path, receipt)
    print(json.dumps({**receipt, "changed": before != after,
                      "seconds": round(time.monotonic() - started, 3)}, sort_keys=True))


def apt_uid():
    try:
        return pwd.getpwnam("_apt").pw_uid
    except KeyError:
        return 0


def persist(path, receipt):
    """Rerun compares an existing receipt; first run exclusively creates it."""
    if path is None:
        return
    path = Path(path)
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    if os.path.lexists(path):
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise Refusal("unsafe receipt path")
        if path.read_bytes() != encoded:
            raise Refusal("receipt does not match source/hash identity")
        return
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".docker-receipt-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def main():
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    def expired(_signum, _frame):
        raise Refusal("overall deadline exceeded")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(ALARM)
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--receipt", type=Path)
        install(parser.parse_args().receipt)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("docker install: interrupted", file=sys.stderr)
        sys.exit(130)
    except (Refusal, OSError) as exc:
        print("docker install: " + str(exc), file=sys.stderr)
        sys.exit(1)
