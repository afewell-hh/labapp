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
import io
import os
import re
import stat
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
TASKS = ("hcl-check", "sentinel", "sentinel-expiry")
VM_TASKS = ("sentinel", "sentinel-expiry")      # same guest inputs and guest-receipt identity
ARTIFACT_LIMIT = 1 << 32      # bound for hashing the disposable sentinel output
# Sentinel guest assertions. Staged 0444 so `ubuntu` can read the copy made by user-data
# (cp -a keeps modes; ISO Rock Ridge modes are UNVERIFIED until the tiny ISO check).
ASSERT_NAME = "assert-sentinel.sh"
SENTINEL_PLAN = (f"root /bin/bash @IN@/{ASSERT_NAME} root\n"
                 f"ubuntu /bin/bash @IN@/{ASSERT_NAME} ubuntu\n").encode()

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


def open_regular(path, limit):
    """Open without following symlinks; return (handle, fstat) for a bounded regular file."""
    if not PATH_RE.fullmatch(path) or os.path.normpath(path) != path:
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


def hash_file(path, size=None, check=_noop, limit=FILE_LIMIT):
    """Return (sha256 hex, identity) of a regular file read once through one descriptor."""
    handle, info = open_regular(path, limit if size is None else size)
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


def copy_hash(path, dest, size, check=_noop):
    """Copy/hash a pinned-size source through one stable FD into a new read-only file."""
    handle, info = open_regular(path, size)
    with handle:
        if info.st_size != size:
            raise StageError("input size differs from its pin")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        with os.fdopen(fd, "wb") as out:
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
          verify_seconds=None):
    """Create ws/in (read-only inputs), ws/cd (read-only CD files) and ws/out (the only
    writable tree, with its fixed empty subdirectories). `sources` maps core, plugin
    and base to caller-supplied files that must match the pins. Return the evidence.

    hcl-check keeps its original contract (empty plan, overall digest as `inputs`, 30 s).
    sentinel stages the assertion script and plan BEFORE the CD MANIFEST, passes
    SHA256(cd/MANIFEST) (exactly what guest-build.sh puts in its receipt) as the
    observer `inputs`, keeps the overall in/+cd/ digest as `inputs` EVIDENCE, and
    takes `verify_seconds` (sentinel-expiry stages the identical guest inputs but asks the
    observer for the armed witness; its verify_seconds must exceed the work window) (an int or a callable evaluated when the var-file is
    written, so it reflects the original budget actually left)."""
    if task not in TASKS:
        raise StageError("unknown staging task")
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
    write_new(os.path.join(cd, "plan.txt"), SENTINEL_PLAN if task in VM_TASKS else b"", 0o400)
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


def verify_staged(ws, staged, check=_noop):
    """After the run: staged bytes, var-file and base file are exactly what was recorded."""
    same = hashlib.sha256(manifest(ws, staged["base_sha256"], check)).hexdigest() == staged["inputs"]
    same = same and hash_file(os.path.join(ws, "in", staged["vars_name"]), check=check)[0] == staged["vars_sha256"]
    return same and hash_file(os.path.join(ws, "in", "base.img"),
                              staged["base_size"], check)[0] == staged["base_sha256"]
