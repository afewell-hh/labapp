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
VERIFY_SECONDS = 30
GUEST_FILES = ("user-data", "guest-build.sh")

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
    if not PATH_RE.match(path):
        raise StageError("unsafe input path")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise StageError("input cannot be opened") from exc
    handle = os.fdopen(fd, "rb")
    try:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise StageError("input is not a bounded regular file")
        return handle, info
    except BaseException:
        handle.close()
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


def hash_file(path, size=None, check=_noop):
    """Return (sha256 hex, identity) of a regular file read once through one descriptor."""
    handle, info = open_regular(path, FILE_LIMIT if size is None else size)
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


def file_identity(path):
    """Cheap re-check of an already hashed file: lstat identity of a regular file."""
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise StageError("input is no longer a regular file")
    return identity(info)


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
            if top == "in" and rel in (VARS_NAME, "base.img"):
                continue
            rows.append((hash_file(os.path.join(ws, top, rel), check=check)[0], f"{top}/{rel}"))
    return "".join(f"{h}  {n}\n" for h, n in sorted(rows, key=lambda r: r[1])).encode()


def vars_text(nonce, inputs, base_sha):
    return "".join(f'{k} = {v}\n' for k, v in (
        ("work_dir", '"/out/work"'), ("nonce", f'"{nonce}"'), ("inputs", f'"{inputs}"'),
        ("base_image", '"/in/base.img"'), ("base_sha256", f'"{base_sha}"'),
        ("verifier", '"/in/host_verify.py"'), ("verify_seconds", str(VERIFY_SECONDS)))).encode()


def stage(ws, sources, nonce, check=_noop, pins=PINS, repo_dir=HERE):
    """Create ws/in (read-only inputs), ws/cd (read-only CD files) and ws/out (the only
    writable tree, with its fixed empty subdirectories). `sources` maps core, plugin
    and base to caller-supplied files that must match the pins. Return the evidence."""
    if not HEX64_RE.match(nonce):
        raise StageError("nonce must be 64 lowercase hex characters")
    inp, out, cd = (make_dirs(ws, name) for name in ("in", "out", "cd"))
    for name in ("home", "tmp", "cache", "work"):
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
    write_new(os.path.join(cd, "plan.txt"), b"", 0o400)
    write_new(os.path.join(cd, "nonce"), nonce.encode("ascii") + b"\n", 0o400)
    lines = "".join(f"{hash_file(os.path.join(cd, n))[0]}  {n}\n" for n in sorted(os.listdir(cd))
                    if n != "nonce")
    write_new(os.path.join(cd, "MANIFEST"), lines.encode(), 0o400)
    base_pin = pins["base"]
    base_sha, base_id = hash_file(sources["base"], base_pin["size"], check)
    if base_sha != base_pin["sha256"]:
        raise StageError("base image differs from its pin")
    write_new(os.path.join(inp, "base.img"), b"", 0o400)       # mountpoint for the file bind
    inputs = hashlib.sha256(manifest(ws, base_sha, check)).hexdigest()
    var_bytes = vars_text(nonce, inputs, base_sha)
    write_new(os.path.join(inp, VARS_NAME), var_bytes, 0o400)
    return {"inputs": inputs, "vars_sha256": hashlib.sha256(var_bytes).hexdigest(),
            "nonce": nonce, "base_sha256": base_sha, "base_identity": base_id,
            "base_source": sources["base"],
            "core_archive_sha256": pins["core"]["sha256"], "core_member_sha256": member_sha["core"],
            "plugin_archive_sha256": pins["plugin"]["sha256"],
            "plugin_member_sha256": member_sha["plugin"],
            "hcl_sha256": hash_file(os.path.join(inp, "labapp.pkr.hcl"))[0]}


def verify_staged(ws, staged, check=_noop):
    """After the run: staged bytes, var-file and base file are exactly what was recorded."""
    same = hashlib.sha256(manifest(ws, staged["base_sha256"], check)).hexdigest() == staged["inputs"]
    same = same and hash_file(os.path.join(ws, "in", VARS_NAME))[0] == staged["vars_sha256"]
    return same and file_identity(staged["base_source"]) == staged["base_identity"]
