"""Bounded, pin-verified staging for the fixed `hcl-check` task (container_runner.py).

Selects only the reviewed archive members, rejects anything that differs from the
committed pins, and writes into fresh owned directories. It never executes staged
bytes and never extracts with `extractall`. Trusted host-side Python 3.10+ stdlib.
The pins come from the authenticated, unexecuted receipts in #261/#262/#263 and
the controlling review 6402679535; member SHA256 values are NOT pinned because
nothing measured them: they are computed here from CRC-checked, size-bounded bytes.
Same-user concurrent writers are outside this module's trust model.
"""
import hashlib
import json
import io
import os
import re
import stat
import tarfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
CHUNK = 1 << 20
TEXT_LIMIT = 1 << 20          # repository text inputs
FILE_LIMIT = 1 << 28          # re-hash bound for any staged file
PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PLUGIN_DIR = ("plugins", "github.com", "hashicorp", "qemu")
PLUGIN_FILE = "packer-plugin-qemu_v1.1.7_x5.0_linux_amd64"
VARS_NAME = "validate.pkrvars.hcl"
SENTINEL_VARS_NAME = "sentinel.pkrvars.hcl"
VARS_NAMES = (VARS_NAME, SENTINEL_VARS_NAME)     # generated, excluded from the overall identity
VERIFY_SECONDS = 30
GUEST_FILES = ("user-data", "guest-build.sh")
TASKS = ("hcl-check", "sentinel", "sentinel-expiry", "fixture", "qemu-fixture")
VM_TASKS = ("sentinel", "sentinel-expiry", "fixture", "qemu-fixture")      # same guest-receipt identity
ARTIFACT_LIMIT = 1 << 32      # bound for hashing the disposable sentinel output
# Sentinel guest assertions. Staged 0444 so `ubuntu` can read the copy made by user-data
# (cp -a keeps modes; ISO Rock Ridge modes are UNVERIFIED until the tiny ISO check).
ASSERT_NAME = "assert-sentinel.sh"
SENTINEL_PLAN = (f"root /bin/bash @IN@/{ASSERT_NAME} root\n"
                 f"ubuntu /bin/bash @IN@/{ASSERT_NAME} ubuntu\n").encode()
# Fixed hhfab fixture: the UNCHANGED build/provision installer pair is staged byte-for-byte and
# run twice with the pinned --archive; assert-fixture.py only observes (see its docstring).
# The sentinel root+ubuntu/cloud-init steps come first and supply the pre-seal evidence line.
PROVISION_DIR = os.path.normpath(os.path.join(HERE, "..", "provision"))
PROVISION_FILES = ("install-hhfab.py", "hhfab_release.py")
# Shared prerequisite probe, staged 0400 (run by root only). Its nonroot child reads the
# installer pair and the archive, so exactly those are staged 0444.
PROBE_FILE = "component_prerequisites.py"
OWNER_UID = 1000          # the cloud image's dedicated `ubuntu` user; baseline asserts the mapping
FIXTURE_ASSERT = "assert-fixture.py"
# Fixed networked QEMU fixture: the UNCHANGED build/provision network installer (install-qemu.py with its
# siblings) runs twice and the UNCHANGED KVM witness once; guest/assert-qemu.py only observes. The original fixture prefix and
# its public installer pair/archive remain intact; additional QEMU files are root-only.
QEMU_PROVISION_FILES = ("install-qemu.py", "qemu_offline.py", "hhfab_release.py", "qemu_witness.py")
QEMU_ASSERT = "assert-qemu.py"
_QEMU_STEP = f"root /usr/bin/python3 -I -B @IN@/{QEMU_ASSERT} "
HHFAB_VERSION = "0.50.4"
ARCHIVE_NAME = f"hhfab-linux-amd64-v{HHFAB_VERSION}.tar.gz"
_INSTALL = (f"root /usr/bin/python3 -B @IN@/install-hhfab.py --version {HHFAB_VERSION} "
            f"--archive @IN@/{ARCHIVE_NAME}\n")
_ASSERT = f"root /usr/bin/python3 -I -B @IN@/{FIXTURE_ASSERT} "
FIXTURE_PLAN = (SENTINEL_PLAN.decode() + _ASSERT + "baseline\n" + _INSTALL + _ASSERT + "snapshot\n"
                + _INSTALL + _ASSERT + "verify\n" + _ASSERT + "negatives\n" + _ASSERT + "smoke\n"
                + _ASSERT + f"prereq {OWNER_UID} @IN@/{ARCHIVE_NAME}\n").encode()

QEMU_PLAN = (FIXTURE_PLAN.decode() + _QEMU_STEP + "baseline\n" + _QEMU_STEP + "install 1\n"
             + _QEMU_STEP + "install 2\n" + _QEMU_STEP + "witness\n").encode()

# members: name -> (unix permission bits, uncompressed size, CRC32) from the #262 listing
PINS = {
    "core": {
        "file": "packer_1.16.2_linux_amd64.zip", "size": 34038571,
        "sha256": "abbfe0cf74985084112659b53e3565f264f70a20914c3b7c4f789f54f61c2414",
        "extract": "packer",
        "members": {"LICENSE.txt": (0o644, 4943, 2875435567),
                    "packer": (0o755, 103727266, 3924419061)},
    },
    "plugin": {
        "file": "packer-plugin-qemu_1.1.7_linux_amd64.zip", "size": 15249228,
        "sha256": "2da856928d658afadc210747337027492a9a7856c9914b8888c32a96034794f2",
        "extract": PLUGIN_FILE,
        "members": {"LICENSE.txt": (0o644, 16757, 1201051225),
                    PLUGIN_FILE: (0o755, 49807522, 3434352986)},
    },
    # Full release archive of the 0.50.4 compatibility candidate (not an image pin); identical to
    # build/provision/hhfab_release.py PINS, whose unchanged guest module validates the member too.
    "hhfab": {"file": ARCHIVE_NAME, "size": 59692810,
              "sha256": "a8e6d1b8d0f752d7586c29201add3ff174d330c87fa25a3bdadec43f6c1376b6"},
    "base": {
        "file": "ubuntu-24.04-server-cloudimg-amd64.img", "size": 621284352,
        "sha256": "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94",
    },
}


class StageError(ValueError):
    """Input differs from its pin, is unsafe, or the staging budget ran out."""


def _noop():
    pass


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_regular(path, limit, path_re=PATH_RE):
    """Open without following symlinks; return (handle, fstat) for a bounded regular file."""
    if not path_re.fullmatch(path) or os.path.normpath(path) != path:
        raise StageError("unsafe input path")
    # Resolve each parent through an anchored directory descriptor. O_NOFOLLOW
    # on the leaf alone would still follow a symlinked or retargeted parent.
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.split("/")[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(os.path.basename(path),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    except OSError as exc:
        raise StageError("input cannot be opened without following symlinks") from exc
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise StageError("input is not a bounded regular file")
        return os.fdopen(fd, "rb"), info
    except BaseException:
        os.close(fd)
        raise


def read_file(path, limit, check=_noop):
    """Whole file in memory, size-bounded; reject if it changes while being read."""
    handle, info = open_regular(path, limit)
    with handle:
        chunks, total = [], 0
        while True:
            check()
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise StageError("input exceeds its bound")
            chunks.append(chunk)
        if total != info.st_size or identity(os.fstat(handle.fileno())) != identity(info):
            raise StageError("input changed while being read")
    return b"".join(chunks)


def hash_file(path, size=None, check=_noop, limit=FILE_LIMIT, path_re=PATH_RE):
    """Return (sha256 hex, identity) of a regular file read once through one descriptor."""
    handle, info = open_regular(path, limit if size is None else size, path_re)
    with handle:
        if size is not None and info.st_size != size:
            raise StageError("input size differs from its pin")
        digest, total = hashlib.sha256(), 0
        while True:
            check()
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > info.st_size:
                raise StageError("input grew while being read")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    if total != info.st_size or identity(after) != identity(info):
        raise StageError("input changed while being read")
    return digest.hexdigest(), identity(info)


def copy_hash(path, dest, size, check=_noop, mode=0o400):
    """Copy/hash a pinned-size source through one stable FD into a new read-only file."""
    handle, info = open_regular(path, size)
    with handle:
        if info.st_size != size:
            raise StageError("input size differs from its pin")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)  # exact fresh-file contract, independent of caller umask
            digest, total = hashlib.sha256(), 0
            while True:
                check()
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise StageError("input grew while being copied")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
            check()
        if total != size or identity(os.fstat(handle.fileno())) != identity(info):
            raise StageError("input changed while being copied")
    return digest.hexdigest()


def check_listing(zf, pin):
    infos = zf.infolist()
    if sorted(i.filename for i in infos) != sorted(pin["members"]):
        raise StageError("unexpected archive members")
    for info in infos:
        mode, size, crc = pin["members"][info.filename]
        attr = info.external_attr >> 16
        if (info.is_dir() or stat.S_IFMT(attr) != stat.S_IFREG or stat.S_IMODE(attr) != mode
                or info.file_size != size or info.CRC != crc or info.flag_bits & 0x1
                or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            raise StageError("archive member differs from its pin")


def write_new(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def extract_member(zf, name, size, crc, dest, check):
    """Stream one named member to a new file, bounded by ACTUAL bytes; return its SHA256."""
    digest, total, running = hashlib.sha256(), 0, 0
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o500)
    with os.fdopen(fd, "wb") as out, zf.open(name) as src:
        while True:
            check()
            chunk = src.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > size:
                raise StageError("member exceeds its pinned size")
            running = zlib.crc32(chunk, running)
            digest.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if total != size or running != crc:
        raise StageError("member size or CRC differs from its pin")
    return digest.hexdigest()


def make_dirs(base, *parts):
    path = base
    for part in parts:
        path = os.path.join(path, part)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:      # fresh only: an existing path is an error
            raise StageError("staging path already exists") from exc
    return path


def walk(base, rel=""):
    """Sorted relative regular-file paths; any symlink or special entry is rejected."""
    with os.scandir(os.path.join(base, rel) if rel else base) as entries:
        found = sorted(entries, key=lambda e: e.name)
    for entry in found:
        path = f"{rel}/{entry.name}" if rel else entry.name
        mode = entry.stat(follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            yield from walk(base, path)
        elif stat.S_ISREG(mode):
            yield path
        else:
            raise StageError("non-regular staged entry")


def manifest(ws, base_sha, check=_noop):
    """Canonical `sha256  relpath` lines for staged read-only inputs (in/ and cd/),
    excluding the generated var-file; base.img is listed with its verified hash."""
    rows = [(base_sha, "in/base.img")]
    for top in ("in", "cd"):
        for rel in walk(os.path.join(ws, top)):
            if top == "in" and (rel in VARS_NAMES or rel == "base.img"):
                continue
            rows.append((hash_file(os.path.join(ws, top, rel), check=check)[0], f"{top}/{rel}"))
    return "".join(f"{h}  {n}\n" for h, n in sorted(rows, key=lambda r: r[1])).encode()


def vars_text(nonce, inputs, base_sha, verify_seconds=VERIFY_SECONDS):
    return "".join(f'{k} = {v}\n' for k, v in (
        ("work_dir", '"/out/work"'), ("nonce", f'"{nonce}"'), ("inputs", f'"{inputs}"'),
        ("base_image", '"/in/base.img"'), ("base_sha256", f'"{base_sha}"'),
        ("verifier", '"/in/host_verify.py"'), ("verify_seconds", str(verify_seconds)))).encode()


def stage(ws, sources, nonce, check=_noop, pins=PINS, repo_dir=HERE, task="hcl-check",
          verify_seconds=None, provision_dir=PROVISION_DIR):
    """Create ws/in (read-only inputs), ws/cd (read-only CD files) and ws/out (the only
    writable tree, with its fixed empty subdirectories). `sources` maps core, plugin
    and base to caller-supplied files that must match the pins. Return the evidence.

    hcl-check keeps its original contract (empty plan, overall digest as `inputs`, 30 s).
    sentinel stages the assertion script and plan BEFORE the CD MANIFEST, passes
    SHA256(cd/MANIFEST) (exactly what guest-build.sh puts in its receipt) as the
    observer `inputs`, keeps the overall in/+cd/ digest as `inputs` EVIDENCE, and
    takes `verify_seconds` (sentinel-expiry stages the identical guest inputs but asks the
    observer for the armed witness; its verify_seconds must exceed the work window) (an int or a callable evaluated when the var-file is
    written, so it reflects the original budget actually left).
    fixture stages the sentinel inputs plus the fixed hhfab plan, assert-fixture.py, the
    byte-identical install-hhfab.py/hhfab_release.py and the pinned archive (`sources["archive"]`)
    on the CD, so all of them are covered by the MANIFEST/receipt identity.
    qemu-fixture retains all fixture inputs/archive and its ten-step prefix, then stages the byte-identical install-qemu.py, qemu_offline.py,
    hhfab_release.py and qemu_witness.py, `guest/assert-qemu.py` and the fixed appended QEMU plan."""
    if task not in TASKS:
        raise StageError("unknown staging task")
    if task in ("fixture", "qemu-fixture") and "archive" not in sources:
        raise StageError("fixture needs the pinned hhfab archive")
    if not HEX64_RE.match(nonce):
        raise StageError("nonce must be 64 lowercase hex characters")
    for path in sources.values():
        if os.path.commonpath((os.path.realpath(ws), os.path.realpath(path))) == os.path.realpath(ws):
            raise StageError("source is inside the staging workspace")
    inp, out, cd = (make_dirs(ws, name) for name in ("in", "out", "cd"))
    for name in ("home", "tmp", "cache"):
        make_dirs(out, name)
    make_dirs(out, "work", "cd")      # mountpoint for the read-only CD bind, caller-owned
    tools = make_dirs(inp, "tools")
    plugin_dir = make_dirs(inp, *PLUGIN_DIR)
    member_sha = {}
    for key, dest_dir in (("core", tools), ("plugin", plugin_dir)):
        pin = pins[key]
        data = read_file(sources[key], pin["size"], check)
        if len(data) != pin["size"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise StageError(f"{key} archive differs from its pin")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                check_listing(zf, pin)
                _, size, crc = pin["members"][pin["extract"]]
                member_sha[key] = extract_member(zf, pin["extract"], size, crc,
                                                 os.path.join(dest_dir, pin["extract"]), check)
        except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
            raise StageError(f"{key} archive unreadable") from exc
        del data
    # The sidecar is exactly the plugin binary's 64 hex ASCII bytes, no newline.
    write_new(os.path.join(plugin_dir, pins["plugin"]["extract"] + "_SHA256SUM"),
              member_sha["plugin"].encode("ascii"), 0o400)
    for name in ("labapp.pkr.hcl", "host_verify.py"):
        write_new(os.path.join(inp, name), read_file(os.path.join(repo_dir, name), TEXT_LIMIT, check), 0o400)
    for name in GUEST_FILES:
        write_new(os.path.join(cd, name),
                  read_file(os.path.join(repo_dir, "guest", name), TEXT_LIMIT, check), 0o400)
    write_new(os.path.join(cd, "meta-data"), b"instance-id: labapp-build\n", 0o400)
    if task in VM_TASKS:
        for name in (ASSERT_NAME, "sentinel-evidence.py"):
            write_new(os.path.join(cd, name),
                      read_file(os.path.join(repo_dir, "guest", name), TEXT_LIMIT, check), 0o444)
    if task in ("fixture", "qemu-fixture"):
        # Root-only inputs (every fixture step beyond the sentinel pair runs as root). The two
        # provisioning modules are copied byte-for-byte; the archive is pinned and bounded.
        write_new(os.path.join(cd, FIXTURE_ASSERT),
                  read_file(os.path.join(repo_dir, "guest", FIXTURE_ASSERT), TEXT_LIMIT, check), 0o400)
        # Installer pair and archive are 0444 for the nonroot probe child (user-data makes the
        # root-owned staging parents 0755); the root-run probe stays 0400 and the nonce private.
        for name in PROVISION_FILES:
            write_new(os.path.join(cd, name),
                      read_file(os.path.join(provision_dir, name), TEXT_LIMIT, check), 0o444)
        write_new(os.path.join(cd, PROBE_FILE),
                  read_file(os.path.join(provision_dir, PROBE_FILE), TEXT_LIMIT, check), 0o400)
        archive_pin = pins["hhfab"]
        if copy_hash(sources["archive"], os.path.join(cd, archive_pin["file"]), archive_pin["size"],
                     check, 0o444) != archive_pin["sha256"]:
            raise StageError("hhfab archive differs from its pin")
    if task == "qemu-fixture":
        # Additional byte-identical QEMU modules and observer adapter. The guest QEMU installer
        # reaches the pinned snapshot itself; the hhfab archive remains in the fixture prefix.
        for name in QEMU_PROVISION_FILES:
            if name in PROVISION_FILES:  # shared public helper already staged for the nonroot probe
                continue
            write_new(os.path.join(cd, name),
                      read_file(os.path.join(provision_dir, name), TEXT_LIMIT, check), 0o400)
        write_new(os.path.join(cd, QEMU_ASSERT),
                  read_file(os.path.join(repo_dir, "guest", QEMU_ASSERT), TEXT_LIMIT, check), 0o400)
    plans = {"fixture": FIXTURE_PLAN, "qemu-fixture": QEMU_PLAN}
    write_new(os.path.join(cd, "plan.txt"),
              plans.get(task, SENTINEL_PLAN if task in VM_TASKS else b""), 0o400)
    write_new(os.path.join(cd, "nonce"), nonce.encode("ascii") + b"\n", 0o400)
    lines = "".join(f"{hash_file(os.path.join(cd, n), check=check)[0]}  {n}\n" for n in sorted(os.listdir(cd))
                    if n != "nonce")
    write_new(os.path.join(cd, "MANIFEST"), lines.encode(), 0o400)
    base_pin = pins["base"]
    base_sha = copy_hash(sources["base"], os.path.join(inp, "base.img"), base_pin["size"], check)
    if base_sha != base_pin["sha256"]:
        raise StageError("base image differs from its pin")
    inputs = hashlib.sha256(manifest(ws, base_sha, check)).hexdigest()
    extra = {}
    if task in VM_TASKS:
        # Guest receipt identity, distinct from the overall `inputs` above.
        guest_receipt = hash_file(os.path.join(cd, "MANIFEST"), check=check)[0]
        seconds = verify_seconds() if callable(verify_seconds) else verify_seconds
        if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= 86400:
            raise StageError("sentinel needs a verification time within the remaining budget")
        # The expiry proof never succeeds, so it asks for the armed witness instead of evidence.
        flag = b"expiry_proof = true\n" if task == "sentinel-expiry" else b"require_sentinel_evidence = true\n"
        var_bytes = vars_text(nonce, guest_receipt, base_sha, seconds) + flag
        vars_name = SENTINEL_VARS_NAME
        extra = {"guest_receipt": guest_receipt, "verify_seconds": seconds}
        if task in ("fixture", "qemu-fixture"):
            extra["hhfab_archive_sha256"] = pins["hhfab"]["sha256"]
    else:
        var_bytes, vars_name = vars_text(nonce, inputs, base_sha), VARS_NAME
    write_new(os.path.join(inp, vars_name), var_bytes, 0o400)
    return {"inputs": inputs, "vars_sha256": hashlib.sha256(var_bytes).hexdigest(),
            "vars_name": vars_name, **extra,
            "nonce": nonce, "base_sha256": base_sha, "base_size": base_pin["size"],
            "core_archive_sha256": pins["core"]["sha256"], "core_member_sha256": member_sha["core"],
            "plugin_archive_sha256": pins["plugin"]["sha256"],
            "plugin_member_sha256": member_sha["plugin"],
            "hcl_sha256": hash_file(os.path.join(inp, "labapp.pkr.hcl"), check=check)[0]}


# Fixed `control-build` inputs: the pinned hhfab release archive (caller path, pinned size/SHA256), its sole pinned
# binary member, the in-repo public curriculum wiring (never caller-supplied) and a freshly written EMPTY Docker
# credential store. Nothing is downloaded or executed here.
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
WIRING_PATH = os.path.join(REPO_ROOT, "wiringd.yaml")
WIRING_SHA256 = "c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a"
EMPTY_DOCKER_CONFIG = b'{"auths":{}}'
CONTROL_FILES = ("hhfab", "wiringd.yaml", "docker/config.json")


def _release_module(provision_dir):
    """Load the UNCHANGED build/provision/hhfab_release.py (exact-member tar extraction) without touching sys.path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("labapp_hhfab_release", os.path.join(provision_dir, "hhfab_release.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage_control(ws, sources, check=_noop, pins=PINS, provision_dir=PROVISION_DIR, wiring_path=WIRING_PATH):
    """Create ws/in (read-only: hhfab, wiringd.yaml, docker/config.json) and ws/out (the only writable tree, with
    empty home, tmp, cache, w1 and w2). `sources` is exactly {"archive": path}. Return the evidence."""
    if set(sources) != {"archive"}:
        raise StageError("control-build needs exactly the hhfab archive")
    if os.path.commonpath((os.path.realpath(ws), os.path.realpath(sources["archive"]))) == os.path.realpath(ws):
        raise StageError("source is inside the staging workspace")
    inp, out = (make_dirs(ws, name) for name in ("in", "out"))
    for name in ("home", "tmp", "cache", "w1", "w2"):
        make_dirs(out, name)
    docker = make_dirs(inp, "docker")
    pin = pins["hhfab"]
    release = _release_module(provision_dir)
    version_pin = release.PINS[HHFAB_VERSION]
    if (version_pin[0], version_pin[1]) != (pin["size"], pin["sha256"]):
        raise StageError("hhfab pins disagree")
    copy = os.path.join(inp, "archive.tgz")
    if copy_hash(sources["archive"], copy, pin["size"], check, 0o400) != pin["sha256"]:
        raise StageError("hhfab archive differs from its pin")
    target = os.path.join(inp, "hhfab")
    try:
        from pathlib import Path
        release.extract(Path(copy), Path(target), version_pin)     # exact sole member; size and SHA256 re-verified
    except (release.Refusal, OSError, EOFError, zlib.error, tarfile.TarError) as exc:
        raise StageError("hhfab member differs from its pin") from exc
    os.chmod(target, 0o500)
    os.unlink(copy)
    check()
    wiring = read_file(wiring_path, TEXT_LIMIT, check)
    if hashlib.sha256(wiring).hexdigest() != WIRING_SHA256:
        raise StageError("wiring differs from its pin")
    write_new(os.path.join(inp, "wiringd.yaml"), wiring, 0o400)
    write_new(os.path.join(docker, "config.json"), EMPTY_DOCKER_CONFIG, 0o400)
    return control_identity(ws, check)


def control_identity(ws, check=_noop):
    """SHA256 of every staged input plus the exact file list (no extra or missing entry in in/)."""
    base = os.path.join(ws, "in")
    if sorted(walk(base)) != sorted(CONTROL_FILES):
        raise StageError("unexpected staged control inputs")
    hashes = {name: hash_file(os.path.join(base, name), check=check)[0] for name in CONTROL_FILES}
    return {"hhfab_archive_sha256": PINS["hhfab"]["sha256"], "hhfab_member_sha256": hashes["hhfab"],
            "wiring_sha256": hashes["wiringd.yaml"], "docker_config_sha256": hashes["docker/config.json"]}


def verify_control(ws, staged, check=_noop):
    """After the run: the read-only inputs are exactly what was recorded."""
    return control_identity(ws, check) == staged


# Accepted #298 build-only v0.50.4 public observations (2026-10-26): test
# references, not release pins/signatures. ORAS file.Store metadata is MEMORY ONLY;
# these expected manifest digests do not prove the CLI selected those manifests.
CONTROL_CACHE_REFERENCES = (('fabricator_k3s-airgap@v1.36.3-k3s1.oras',
  'd6598184bf5ac9dd67210c98f8426e0b9a01412172be1e83fdaabeb6c129063c',
  (('k3s', 82010274, '2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5', False),
   ('k3s-airgap-images-amd64.tar.gz',
    263181910,
    'e09e718f931ef094294781d3c35e58b84e2170acd5cc2edae075a20f58d1f89d',
    False),
   ('k3s-install.sh', 37118, '46177d4c99440b4c0311b67233823a8e8a2fc09693f6c89af1a7161e152fbfad', False))),
 ('fabricator_toolbox@v0.15.0.oras',
  'f0e50971cdfa3b9d069ae40b54df30d31f03eb6ebd89aeb67648a67fc91bd8da',
  (('toolbox.tar', 184470016, '74a940d218fac144a8c019bb0aee1ddbf627f4f24c0c336104b7358712556a59', False),)),
 ('fabricator_k9s@v0.50.18.oras',
  '46599bfa7998e445d09914763c42687027f45d8bc11d344b1aff537f99ab5f4d',
  (('k9s', 129171640, '239d5996131ab272ea8fa021294f0d464b8ce3c395d3a91b3dbf896d2f0760be', False),)),
 ('fabricator_zot-airgap@v2.1.16.oras',
  '60cc5ff528880fee28c57901247fdba71dcbd4ff14056709f4bffcf8fa01cd2f',
  (('zot-airgap-images-amd64.tar.gz',
    67755049,
    'bb90030257e5de228e5b8f15fe17afa612375ac4b93f1ce1b36c46bf26d5b249',
    False),
   ('zot-chart.tgz', 12779, '629a56ba77e94ff9076f029160cd59cc3385f91687d7eccdb758ed0cc8dd5ad1', False))),
 ('fabricator_flatcar-update@v4593.2.5.oras',
  '029c3081893d1826b7ebc9d3fa80052a539b973d0a5dc5b05bde2bf8c867ee30',
  (('flatcar_production_update.gz',
    452011487,
    '6f74286203549e5090b81e622d627202ed8dfc0c2f3e9e780ea9ac04da4eb0f6',
    False),)),
 ('fabricator_cert-manager-airgap@v1.20.2.oras',
  'aeb635be56d37bbe8535cd44bfcbbc9af8a96dffd48e3688667d3795f7e12b8d',
  (('cert-manager-airgap-images-amd64.tar.gz',
    77570354,
    '8534a85d3763d7330ec00c79a24faf4ee77874fe581eccc2e6bc83a1433239c4',
    False),
   ('cert-manager-chart.tgz', 147139, 'd2a50bd44a09d838c2576a8f3dfca1524597c7393cf8d82ab3ec8a465b9eeb79', False))),
 ('fabricator_bash-completion@v2.16.0.oras',
  '7c691e3dcb061ed163f24f2b68787dce1dc10d6824ce64379c86b0693c5a6330',
  (('bash-completion', 618791, '1b924bc8e181b507bf8399a7501e35716dbf1d4d5805b2d0c750eea38ad9c717', True),)),
 ('fabric_hhfctl@v0.133.0.oras',
  'f973233a0da10c59cd6ae290a977f31aec5f52600e3a72b9fe439860c18e40b3',
  (('hhfctl', 41918626, 'ef4b3753fff6104a355c5eecbae7b9d0bc64cdee6febf98fe7c95238852f0193', False),)),
 ('fabricator_hhfabctl@v0.50.4.oras',
  '2333edf8cf25902e76cc6fbdec41dad30ee4f963a7d291520af84c5b8fc4d44c',
  (('hhfabctl', 44400802, '4c3314dfb44ba96496a00cc5419b467940908fb9803fbe41edd4ff41838059ec', False),)),
 ('fabricator_control-usb-root@v4593.2.5-hh1.oras',
  'ebf7ee191e0f1479932606627df9163661048ae5916c56b57fd39bbe7e2ee2d5',
  (('boot', 2163295, 'f88027d50554606608e4d0c30598b979a96c4d39ce8b55b237ee00e93fde60d4', True),
   ('EFI', 2122870, 'bcee95fb7a2570a83dd4f69d212d89f9efac3b626ec39906603bd19f570d4f3a', True),
   ('images', 4384885, '8d2ba1a78bf26d9e66e44c071794e732656bb1faddcb9f393fdccfa51708c448', True),
   ('flatcar_production_image.bin.bz2',
    495630664,
    'cefd3d62efdc15074327fa8171ea9b03d0649725fe37ee8d6e7c812c6ea02738',
    False),
   ('flatcar_production_pxe.vmlinuz',
    34245760,
    'fe0b7ef1f9f98acc00e1db22937cdc57456df860a372fdc8eb806298f767b676',
    False),
   ('flatcar_production_pxe_image.cpio.gz',
    391744600,
    '50b390c0bad46bf33cbce5e9afd1a557f96d56a8e1298e7920730e53e7c49efb',
    False))))
CONTROL_CACHE_PATH_RE = re.compile(r"^/[A-Za-z0-9_@./-]+$")
CONTROL_CACHE_ENTRY_CAP = 200000
CONTROL_CACHE_BYTE_CAP = 32 << 30
CONTROL_CACHE_FINGERPRINT = hashlib.sha256(json.dumps(
    CONTROL_CACHE_REFERENCES, separators=(',', ':')).encode('ascii')).hexdigest()


class CacheAuditRefusal(StageError):
    """Closed cache-only diagnostic; never retain exception messages or observed names."""
    STAGES = {'version', 'roots', 'payloads', 'regular', 'unpacked'}
    REASONS = {'entry_set', 'path_policy', 'entry_type', 'file_size', 'file_hash', 'file_changed',
               'file_refused', 'empty_tree', 'entry_bound', 'byte_bound', 'filesystem'}
    COUNTS = {'entries_scanned', 'payload_bytes_hashed', 'regular_payloads_verified',
              'unpacked_directories_fingerprinted', 'observed_count', 'expected_count',
              'missing_count', 'extra_count', 'observed_bytes', 'expected_bytes'}

    def __init__(self, stage, reason, **fields):
        if stage not in self.STAGES or reason not in self.REASONS or set(fields) - self.COUNTS - {'root_index', 'payload_index'}:
            raise ValueError('invalid cache refusal fields')
        receipt = {'status': 'refused', 'stage': stage, 'reason': reason}
        for key, value in fields.items():
            if type(value) is not int or value < 0:
                raise ValueError('invalid cache refusal count')
            if key in ('root_index', 'payload_index'):
                if value > (9 if key == 'root_index' else 5):
                    raise ValueError('invalid cache refusal index')
                receipt[key] = value
            else:
                receipt[key] = min(value, 1 << 40)
        self.receipt = receipt
        super().__init__('cache audit refused')


def verify_control_cache(cache, check=_noop):
    """Audit named official ORAS payloads only; errors carry closed partial counters.
    Root selection and original packed-directory descriptors remain unverified.
    """
    count = total = files = directories = 0
    stage, indices = 'version', {}

    def refuse(reason, **counts):
        raise CacheAuditRefusal(stage, reason, **indices, entries_scanned=count,
                                payload_bytes_hashed=total, regular_payloads_verified=files,
                                unpacked_directories_fingerprinted=directories, **counts)

    def children(directory):
        nonlocal count
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in directory.split('/')[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            result = []
            with os.scandir(fd) as items:
                for item in items:
                    check()
                    count += 1
                    if count > CONTROL_CACHE_ENTRY_CAP:
                        refuse('entry_bound')
                    result.append((item.name, item.stat(follow_symlinks=False)))
            return dict(sorted(result))
        finally:
            os.close(fd)

    def exact_entries(observed, expected):
        if set(observed) != set(expected):
            refuse('entry_set', observed_count=len(observed), expected_count=len(expected),
                   missing_count=len(set(expected) - set(observed)), extra_count=len(set(observed) - set(expected)))

    def checked_hash(path, info, size=None):
        if not CONTROL_CACHE_PATH_RE.fullmatch(path) or os.path.normpath(path) != path:
            refuse('path_policy')
        if not stat.S_ISREG(info.st_mode):
            refuse('entry_type')
        if (size is not None and info.st_size != size) or info.st_size > 12 << 30:
            refuse('file_size', observed_bytes=info.st_size, expected_bytes=size if size is not None else 12 << 30)
        sha, identity_now = hash_file(path, size=size, check=check, limit=12 << 30, path_re=CONTROL_CACHE_PATH_RE)
        if identity_now != identity(info):
            refuse('file_changed')
        return sha

    try:
        top = children(cache)
        exact_entries(top, {'v1'})
        if not stat.S_ISDIR(top['v1'].st_mode):
            refuse('entry_type')
        cache = os.path.join(cache, 'v1')
        stage = 'roots'
        roots = children(cache)
        exact_entries(roots, {row[0] for row in CONTROL_CACHE_REFERENCES})
        fingerprints = {}
        for root_index, (root, _, entries) in enumerate(CONTROL_CACHE_REFERENCES):
            indices = {'root_index': root_index}
            stage = 'roots'
            check()
            if not stat.S_ISDIR(roots[root].st_mode):
                refuse('entry_type')
            stage = 'payloads'
            base = os.path.join(cache, root)
            payloads = children(base)
            exact_entries(payloads, {e[0] for e in entries})
            for payload_index, (name, size, digest, unpacked) in enumerate(entries):
                indices = {'root_index': root_index, 'payload_index': payload_index}
                path = os.path.join(base, name)
                stage = 'unpacked' if unpacked else 'regular'
                if not unpacked:
                    sha = checked_hash(path, payloads[name], size)
                    total += size
                    if sha != digest:
                        refuse('file_hash')
                    files += 1
                    if total > CONTROL_CACHE_BYTE_CAP:
                        refuse('byte_bound')
                    continue
                if not stat.S_ISDIR(payloads[name].st_mode):
                    refuse('entry_type')
                tree = hashlib.sha256()
                stack = [(path, '')]
                tree_count = tree_bytes = 0
                while stack:
                    check()
                    parent, relative = stack.pop()
                    for child_name, info in children(parent).items():
                        check()
                        tree_count += 1
                        rel = relative + '/' + child_name
                        child_path = os.path.join(parent, child_name)
                        if stat.S_ISDIR(info.st_mode):
                            kind, sha = 'dir', ''
                            stack.append((child_path, rel))
                        elif stat.S_ISREG(info.st_mode):
                            kind = 'file'
                            sha = checked_hash(child_path, info)
                            tree_bytes += info.st_size
                            total += info.st_size
                        else:
                            refuse('entry_type')
                        if total > CONTROL_CACHE_BYTE_CAP:
                            refuse('byte_bound')
                        tree.update(json.dumps([rel, kind, info.st_size if kind == 'file' else 0, sha],
                                               ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n')
                if tree_count == 0:
                    refuse('empty_tree')
                directories += 1
                fingerprints[root + '/' + name] = {'sha256': tree.hexdigest(), 'entries': tree_count,
                                                  'bytes': tree_bytes}
    except CacheAuditRefusal:
        raise
    except OSError:
        refuse('filesystem')
    except StageError as exc:
        # These are fixed local helper messages, never serialized. Unknown messages
        # receive one closed fallback, including arbitrary peer-bearing exceptions.
        reason = {'unsafe input path': 'path_policy',
                  'input grew while being read': 'file_changed',
                  'input changed while being read': 'file_changed',
                  'input size differs from its pin': 'file_size'}.get(str(exc), 'file_refused')
        refuse('filesystem' if isinstance(exc.__cause__, OSError) else reason)
    return {'expected_reference_sha256': CONTROL_CACHE_FINGERPRINT, 'roots': len(roots),
            'regular_payloads_verified': files, 'unpacked_directories': directories,
            'unpacked_content': fingerprints, 'payload_bytes_hashed': total,
            'root_manifest_selection_verified': False, 'packed_directory_descriptors_verified': False,
            'signatures_verified': False}


def verify_staged(ws, staged, check=_noop):
    """After the run: staged bytes, var-file and base file are exactly what was recorded."""
    same = hashlib.sha256(manifest(ws, staged["base_sha256"], check)).hexdigest() == staged["inputs"]
    same = same and hash_file(os.path.join(ws, "in", staged["vars_name"]), check=check)[0] == staged["vars_sha256"]
    return same and hash_file(os.path.join(ws, "in", "base.img"),
                              staged["base_size"], check)[0] == staged["base_sha256"]
