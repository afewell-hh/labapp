"""Linux/Python 3.12 stdlib collector for an already read-only guest root.

Never mounts, executes guest content, or accesses cloud services. Every guest
component is opened relative to a pinned directory fd with O_NOFOLLOW. Symlinks
are deliberately reported as gaps, including legitimate absolute guest links.
The operator must supply a stable, read-only mount; concurrent hostile mount
replacement and a malicious inspector host are outside this contract.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

UNIT_NAMES = (
    "hhfab-vlab-resume", "vlab-netfilter", "hhbr-ip", "kubeconfig-merge",
    "argocd-port-fix", "hhfab-vlab",
)
UNIT_DIRS = ("/etc/systemd/system", "/usr/local/lib/systemd/system",
             "/usr/lib/systemd/system", "/lib/systemd/system")
HELPER_DIRS = ("/usr/local/bin", "/usr/local/sbin",
               "/opt/hedgehog/bin", "/home/ubuntu/bin", "/home/hhlab/bin")
HELPER_NAMES = {name + suffix for name in UNIT_NAMES for suffix in ("", ".sh")}
HELPER_NAMES.add("hhfab-vlab-runner")
HELPER_NAMES.update(("hhbr-ip-setup.sh", "fix-argocd-port.sh"))
FILE_LIMIT = 256 * 1024
DPKG_LIMIT = 16 * 1024 * 1024
REPORT_LIMIT = 8 * 1024 * 1024
ENTRY_LIMIT = 128
RECORD_LIMIT = 256


class Gap(Exception):
    """A fixed, non-content-bearing failure code."""


class Guest:
    def __init__(self, root):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        os.close(self.fd)

    def open(self, path, directory=False):
        parts = path.split("/")[1:]
        if not path.startswith("/") or not parts or any(
                p in ("", ".", "..") for p in parts):
            raise Gap("invalid_path")
        current = os.dup(self.fd)
        try:
            for i, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if i < len(parts) - 1 or directory:
                    flags |= os.O_DIRECTORY
                try:
                    # lstat is diagnostic only; open's NOFOLLOW enforces safety.
                    info = os.stat(part, dir_fd=current, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        raise Gap("symlink_skipped")
                    if i == len(parts) - 1 and not directory and not stat.S_ISREG(info.st_mode):
                        # Avoid even opening guest device nodes or FIFOs. The
                        # post-open fstat remains necessary for replacement races.
                        raise Gap("not_regular")
                    next_fd = os.open(part, flags, dir_fd=current)
                except FileNotFoundError:
                    raise Gap("missing") from None
                except OSError:
                    raise Gap("unreadable_or_changed") from None
                os.close(current)
                current = next_fd
            result = current
            current = None
            return result
        finally:
            if current is not None:
                os.close(current)

    def text(self, path, limit=FILE_LIMIT):
        fd = self.open(path)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Gap("not_regular")
            if info.st_size > limit:
                raise Gap("oversize")
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise Gap("oversize")
            try:
                value = data.decode("utf-8")
            except UnicodeDecodeError:
                raise Gap("nontext") from None
            if any(ord(c) < 32 and c not in "\t\r\n" for c in value):
                raise Gap("nontext")
            return value, hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)

    def entries(self, path):
        fd = self.open(path, directory=True)
        try:
            # Iteration is bounded even on enormous or hostile directories.
            with os.scandir(fd) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > ENTRY_LIMIT:
                        raise Gap("too_many_entries")
                return sorted(names)
        finally:
            os.close(fd)


def packages(text):
    """Parse installed name/version only; never return arbitrary dpkg fields."""
    result = []
    for paragraph in text.split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in ("Package", "Version", "Status"):
                if key in fields:
                    raise Gap("invalid_dpkg")
                fields[key] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        name, version = fields.get("Package", ""), fields.get("Version", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or not re.fullmatch(
                r"[0-9][A-Za-z0-9.+:~\-]*", version):
            raise Gap("invalid_dpkg")
        result.append({"name": name, "version": version})
    return sorted(result, key=lambda p: (p["name"], p["version"]))


def helper_refs(text):
    """Conservative first executable only; never interpret shell or specifiers.

    This is evidence discovery, not a systemd parser or effective-unit resolver.
    Unsupported commands remain visible in the private raw unit for review.
    """
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("ExecStart", "ExecStartPre", "ExecStartPost"):
            try:
                words = shlex.split(value)
            except ValueError:
                continue
            if words:
                candidate = words[0]
                parent, _, name = candidate.rpartition("/")
                if parent in HELPER_DIRS and name in HELPER_NAMES:
                    yield candidate


def collect(root):
    guest = Guest(root)
    records, helpers = [], set()

    def capture(path, kind, limit=FILE_LIMIT):
        if len(records) >= RECORD_LIMIT:
            raise Gap("record_limit")
        record = {"path": path, "kind": kind}
        try:
            text, digest = guest.text(path, limit)
            record.update(status="captured", sha256=digest)
            if kind == "packages":
                record["packages"] = packages(text)
            else:
                record["private_content"] = text
            if kind == "unit":
                helpers.update(helper_refs(text))
        except Gap as error:
            record.update(status=str(error))
        records.append(record)

    try:
        capture("/etc/os-release", "os_release")
        capture("/var/lib/dpkg/status", "packages", DPKG_LIMIT)
        # Fixed canonical alternative only: never resolve the guest's symlink.
        capture("/usr/lib/os-release", "os_release")
        for directory in UNIT_DIRS:
            for name in UNIT_NAMES:
                path = f"{directory}/{name}.service"
                capture(path, "unit")
                dropdir = path + ".d"
                try:
                    names = guest.entries(dropdir)
                    for entry in names:
                        if re.fullmatch(r"[A-Za-z0-9_.-]+\.conf", entry):
                            capture(f"{dropdir}/{entry}", "unit")
                except Gap as error:
                    records.append({"path": dropdir, "kind": "dropin_directory",
                                    "status": str(error)})
        for path in sorted(helpers):
            capture(path, "helper")
    finally:
        guest.close()
    return {"schema_version": 1, "private_review_required": True,
            "unimplemented": ["effective_systemd_configuration", "recursive_helpers",
                              "environment_files", "fabric_wiring", "network_settings",
                              "shell_profiles", "binary_versions", "charts", "runtime"],
            "records": records}


def write_private(root, output):
    root = Path(root).absolute()
    output = Path(output).absolute()
    parent = output.parent.resolve(strict=True)
    # Explicit operator-owned private storage only; no overwriting or symlinks.
    info = parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Gap("private_parent_required")
    if parent == root.resolve() or root.resolve() in parent.parents:
        raise Gap("output_inside_guest")
    report = collect(root)
    data = (json.dumps(report, ensure_ascii=True, sort_keys=True) + "\n").encode()
    if len(data) > REPORT_LIMIT:
        raise Gap("report_oversize")
    fd = os.open(parent / output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        os.unlink(parent / output.name)
        raise
    counts = Counter(record["status"] for record in report["records"])
    # Nothing derived from file bodies, filenames or unit values is printed.
    return {"records": len(report["records"]), "statuses": dict(counts),
            "private_report_sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--private-output", required=True)
    args = parser.parse_args()
    try:
        summary = write_private(args.root, args.private_output)
    except (Gap, OSError, ValueError):
        parser.exit(1, "Collection failed; no guest content is printed.\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
