"""Fixed hhfab fixture assertions (see ../README.md "Fixed hhfab fixture task").

Staged on the CD by stage_tools.py and run by guest-build.sh's plan as
`root /usr/bin/python3 -I -B @IN@/assert-fixture.py <phase>` under `env -i`, cwd `/`,
stdin /dev/null, between runs of the UNCHANGED build/provision/install-hhfab.py.
Python 3.10+ stdlib only. It installs nothing into /usr/local/bin and never executes
hhfab as root; the only execution of the installed binary is the nonroot `smoke`.

Phases: baseline (before the first install), snapshot (after run 1), verify (after run 2),
negatives (isolated refusals), smoke (nonroot CLI). A failed check writes ONE fixed
reason token to /run/labapp-reason (read and validated by guest-build.sh, which adds the
plan step and exit code to its bounded diagnostic line) and exits 1. No peer or tool
output is ever echoed. UNRUN in a guest.
"""
import hashlib
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
import sys

VERSION = "0.50.4"
# Duplicated from build/provision/hhfab_release.py PINS; a host test keeps them identical.
MEMBER_SIZE = 104890530
MEMBER_SHA256 = "b7a5c7744e3b617d7e76d9ccc9015588a8c32da62623c8ecc114cae24e1a5fcd"
PRIOR_BYTES = b"nonmatching prior bytes, never executed\n"
REFUSAL = b"hhfab install: archive checksum/size mismatch\n"
VERSION_RE = re.compile(rb"hhfab version v?0\.50\.4\n?")      # as component_prerequisites.py
OUTPUT_CAP = 4096
INSTALL_SECONDS = 150
SMOKE_SECONDS = 20
REASON_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class Check(Exception):
    """A failed assertion; its text is a fixed reason token, never peer output."""


class Config:
    def __init__(self, here, install_dir="/usr/local/bin", state="/run/labapp-fixture",
                 reason="/run/labapp-reason", ubuntu_prefix=("runuser", "-u", "ubuntu", "--"), top="/",
                 owner_uid=1000, lookup=pwd.getpwnam, staging_uid=0):
        self.here = here
        self.top = top
        self.owner_uid = owner_uid      # must equal stage_tools.OWNER_UID (a host test checks)
        self.lookup = lookup
        self.staging_uid = staging_uid  # production root; synthetic metadata tests use their caller
        self.install_dir = install_dir
        self.state = state
        self.reason = reason
        self.ubuntu_prefix = tuple(ubuntu_prefix)
        self.archive = os.path.join(here, "hhfab-linux-amd64-v%s.tar.gz" % VERSION)
        self.installer = os.path.join(here, "install-hhfab.py")


def need(condition, reason):
    if not condition:
        raise Check(reason)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def real_directories(path, top, reason):
    """Every component from `top` (the root directory in the guest) down is a real directory,
    caller-owned and not group/world writable."""
    parts = [path]
    while parts[-1] not in (top, "/"):
        parts.append(os.path.dirname(parts[-1]))
    for part in parts:
        info = os.lstat(part)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o022, reason)


def listing(directory):
    """name -> identity of every direct entry, without following symlinks."""
    with os.scandir(directory) as entries:
        return {entry.name: identity(entry.stat(follow_symlinks=False)) for entry in entries}


def read_state(cfg, name):
    path = os.path.join(cfg.state, name)
    info = os.lstat(path)
    need(stat.S_ISREG(info.st_mode) and info.st_size <= 1 << 20, "state-missing")
    with open(path, "rb") as handle:
        return json.loads(handle.read(1 << 20).decode("ascii"))


def write_state(cfg, name, value):
    fd = os.open(os.path.join(cfg.state, name),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(json.dumps(value, sort_keys=True).encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())


def installed_state(cfg, others):
    """The good install: single-link regular 0755 file of the pinned member; every other entry
    is exactly `others` (unrelated tools preserved, no stage leftover)."""
    target = os.path.join(cfg.install_dir, "hhfab")
    info = os.lstat(target)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o755
         and info.st_uid == os.geteuid() and info.st_size == MEMBER_SIZE
         and sha256(target) == MEMBER_SHA256, "install-state")
    now = listing(cfg.install_dir)
    need(not any(name.startswith(".hhfab-stage-") for name in now), "stage-leftover")
    need({name: item for name, item in now.items() if name != "hhfab"} == others, "dir-preserved")
    return identity(info)



# Data-only nonroot child: read the required files, import the exact sibling, and prove the
# private nonce is inaccessible. No installer/probe entrypoint or hhfab binary is executed.
ACCESS_CHILD = r"""
import importlib.util, os, sys
here, nonce, uid = sys.argv[1:]
assert os.geteuid() == int(uid) > 0
for name in ("install-hhfab.py", "hhfab_release.py", "hhfab-linux-amd64-v0.50.4.tar.gz"):
    path = os.path.join(here, name)
    with open(path, "rb") as handle:
        assert handle.read(1)
    assert not os.access(path, os.W_OK)
try:
    with open(nonce, "rb"):
        pass
except PermissionError:
    pass
else:
    raise AssertionError("private nonce readable")
spec = importlib.util.spec_from_file_location("fixture_access_release", os.path.join(here, "hhfab_release.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert "0.50.4" in module.PINS
"""


def staging_metadata(cfg):
    """Validate the actual post-cloud-init guest copy, not host/ISO source metadata."""
    part = cfg.here
    while True:
        info = os.lstat(part)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == cfg.staging_uid
             and not info.st_mode & 0o022 and info.st_mode & 0o001, "staging-parent")
        if part in (cfg.top, "/"):
            break
        part = os.path.dirname(part)
    for name, mode in (("install-hhfab.py", 0o444), ("hhfab_release.py", 0o444),
                       ("hhfab-linux-amd64-v0.50.4.tar.gz", 0o444), ("nonce", 0o600)):
        info = os.lstat(os.path.join(cfg.here, name))
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == cfg.staging_uid
             and stat.S_IMODE(info.st_mode) == mode, "staging-input")


def staging_access(cfg):
    staging_metadata(cfg)
    argv = [*cfg.ubuntu_prefix, "/usr/bin/env", "-i", "PATH=" + SAFE_PATH,
            "HOME=/home/ubuntu", "LC_ALL=C.UTF-8", "/usr/bin/python3", "-I", "-B", "-c",
            ACCESS_CHILD, cfg.here, os.path.join(cfg.here, "nonce"), str(cfg.owner_uid)]
    done = command(cfg, argv, SMOKE_SECONDS, "staging-timeout", {"PATH": SAFE_PATH})
    need(done.returncode == 0 and done.stdout == b"", "staging-access")


def baseline(cfg):
    # The prerequisite probe is given --owner-uid explicitly: `ubuntu` must be that dedicated
    # nonroot user (nonroot primary group); never silently fall back to root.
    try:
        owner = cfg.lookup("ubuntu")
    except KeyError:
        raise Check("owner-map") from None
    need(owner.pw_uid == cfg.owner_uid > 0 and owner.pw_gid > 0, "owner-map")
    staging_access(cfg)
    real_directories(cfg.install_dir, cfg.top, "dir-state")
    now = listing(cfg.install_dir)
    need("hhfab" not in now, "target-present")
    need(not any(name.startswith(".hhfab-stage-") for name in now), "stage-leftover")
    os.makedirs(cfg.state, mode=0o700)
    write_state(cfg, "baseline.json", now)


def snapshot(cfg):
    base = read_state(cfg, "baseline.json")
    found = installed_state(cfg, base)
    write_state(cfg, "snapshot.json", {"hhfab": found, "dir": listing(cfg.install_dir)})


def verify(cfg):
    """Run 2 returned "unchanged": the same inode and times, no replacement, no new entries."""
    shot = read_state(cfg, "snapshot.json")
    found = installed_state(cfg, {n: i for n, i in shot["dir"].items() if n != "hhfab"})
    need(found == shot["hhfab"], "rerun-state")


def command(cfg, argv, seconds, timeout_reason, env):
    """Use the unchanged sibling helper's streaming cap and group deadline/cleanup.

    Load only the exact staged sibling; -I deliberately excludes cwd from imports.
    GNU env fixes cwd without changing this assertion process's working directory.
    stdout/stderr are combined and never exported as diagnostic text.
    """
    path = os.path.join(os.path.dirname(cfg.installer), "hhfab_release.py")
    spec = importlib.util.spec_from_file_location("fixture_hhfab_release", path)
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    try:
        code, output = release.bounded(["/usr/bin/env", "-C", "/", *argv], seconds,
                                       limit=OUTPUT_CAP, env=env)
    except release.Refusal as exc:
        raise Check("output-bound" if str(exc) == "command output overflow" else timeout_reason) from None
    return subprocess.CompletedProcess(argv, code, output)


def run_installer(cfg, directory, version, archive):
    argv = ["/usr/bin/python3", "-B", cfg.installer, "--version", version,
            "--install-dir", directory, "--archive", archive]
    env = {"PATH": SAFE_PATH, "HOME": "/root", "LC_ALL": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive"}
    return command(cfg, argv, INSTALL_SECONDS, "negative-timeout", env)


def negatives(cfg):
    """Refusals against ISOLATED destinations: a good installed binary returns `unchanged`
    before its archive is ever read, so a corrupt archive must meet other prior state."""
    shot = read_state(cfg, "snapshot.json")
    root = os.path.join(cfg.state, "neg")
    os.mkdir(root, 0o700)
    with open(cfg.archive, "rb") as handle:
        data = bytearray(handle.read(1 << 28))
    need(len(data) > 1024, "archive-integrity")
    data[len(data) // 2] ^= 0xFF                 # same size, different bytes
    corrupt = os.path.join(root, "corrupt.tar.gz")
    fd = os.open(corrupt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    del data
    prior = os.path.join(root, "prior")
    absent = os.path.join(root, "absent")
    for directory in (prior, absent):
        os.mkdir(directory, 0o755)
        os.chmod(directory, 0o755)
    target = os.path.join(prior, "hhfab")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(PRIOR_BYTES)
    before = identity(os.lstat(target))
    for directory in (prior, absent):
        done = run_installer(cfg, directory, VERSION, corrupt)
        need(done.returncode == 1 and done.stdout == REFUSAL, "archive-integrity")
    need(identity(os.lstat(target)) == before, "neg-state")
    with open(target, "rb") as handle:
        need(handle.read(OUTPUT_CAP) == PRIOR_BYTES, "neg-state")
    need(sorted(os.listdir(prior)) == ["hhfab"] and os.listdir(absent) == [], "neg-state")
    done = run_installer(cfg, prior, "9.9.9", cfg.archive)       # argparse refusal, exit 2
    need(done.returncode == 2 and b"invalid choice: '9.9.9'" in done.stdout,
         "bad-version")
    need(identity(os.lstat(target)) == before and sorted(os.listdir(prior)) == ["hhfab"], "neg-state")
    # The good installation and its directory were never an argument to any negative.
    need(identity(os.lstat(os.path.join(cfg.install_dir, "hhfab"))) == shot["hhfab"], "rerun-state")
    need(listing(cfg.install_dir) == shot["dir"], "dir-preserved")


def smoke(cfg):
    argv = [*cfg.ubuntu_prefix, "env", "-i", "PATH=" + SAFE_PATH, "HOME=/home/ubuntu",
            "LC_ALL=C.UTF-8", "DEBIAN_FRONTEND=noninteractive",
            os.path.join(cfg.install_dir, "hhfab"), "--version"]
    done = command(cfg, argv, SMOKE_SECONDS, "cli-timeout", {"PATH": SAFE_PATH})
    need(done.returncode == 0, "cli-run")
    need(VERSION_RE.fullmatch(done.stdout) is not None, "cli-version")


PHASES = {"baseline": baseline, "snapshot": snapshot, "verify": verify,
          "negatives": negatives, "smoke": smoke}


def report(cfg, token):
    """One fixed token, never overwriting an earlier reason. Best effort."""
    if not REASON_RE.fullmatch(token):
        token = "internal"
    try:
        fd = os.open(cfg.reason, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(token.encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass


def run(argv, cfg=None):
    if len(argv) != 1 or argv[0] not in PHASES:
        return 2
    cfg = cfg or Config(os.path.dirname(os.path.abspath(__file__)))
    try:
        PHASES[argv[0]](cfg)
    except Check as exc:
        report(cfg, str(exc))
        return 1
    except Exception:       # peer-controlled text must not reach the diagnostic
        report(cfg, "internal")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
