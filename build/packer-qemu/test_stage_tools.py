"""Offline tests for the bounded stager. Synthetic tiny archives and pins only: no
downloaded bytes, no extraction of real inputs, nothing is executed."""
import hashlib
import io
import os
import stat
import tempfile
import unittest
import zipfile
import zlib

import stage_tools as st

CORE_BYTES = b"#!/bin/sh\necho synthetic packer\n"
PLUGIN_BYTES = b"#!/bin/sh\necho synthetic plugin\n"
BASE_BYTES = b"synthetic base image\n" * 10


def make_zip(path, members):
    """members: name -> (data, unix mode); returns the file's bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, (data, mode) in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    raw = buffer.getvalue()
    with open(path, "wb") as handle:
        handle.write(raw)
    return raw


def pin_for(raw, extract, members):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "extract": extract,
            "members": {n: (m, len(d), zlib.crc32(d)) for n, (d, m) in members.items()}}


def make_inputs(directory):
    """Write synthetic core/plugin/base files; return (sources, pins)."""
    core = {"LICENSE.txt": (b"license\n", 0o644), "packer": (CORE_BYTES, 0o755)}
    plugin = {"LICENSE.txt": (b"mpl\n", 0o644), st.PLUGIN_FILE: (PLUGIN_BYTES, 0o755)}
    sources = {k: os.path.join(directory, k) for k in ("core", "plugin", "base")}
    core_raw = make_zip(sources["core"], core)
    plugin_raw = make_zip(sources["plugin"], plugin)
    with open(sources["base"], "wb") as handle:
        handle.write(BASE_BYTES)
    pins = {"core": pin_for(core_raw, "packer", core),
            "plugin": pin_for(plugin_raw, st.PLUGIN_FILE, plugin),
            "base": {"size": len(BASE_BYTES), "sha256": hashlib.sha256(BASE_BYTES).hexdigest()}}
    return sources, pins


class StageCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = os.path.realpath(self.tmp.name)
        self.inputs = os.path.join(base, "src")
        os.mkdir(self.inputs, 0o700)
        self.ws = os.path.join(base, "ws")
        os.mkdir(self.ws, 0o700)
        self.sources, self.pins = make_inputs(self.inputs)
        self.nonce = "ab" * 32

    def stage(self, **kw):
        return st.stage(self.ws, kw.pop("sources", self.sources), self.nonce, pins=kw.pop("pins", self.pins), **kw)

    def read(self, *parts):
        with open(os.path.join(self.ws, *parts), "rb") as handle:
            return handle.read()


class RealPinTests(unittest.TestCase):
    def test_pins_are_full_length_and_match_issue_receipts(self):
        for key in ("core", "plugin", "base"):
            self.assertRegex(st.PINS[key]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(st.PINS["core"]["size"], 34038571)
        self.assertEqual(st.PINS["plugin"]["size"], 15249228)
        self.assertEqual(st.PINS["base"]["size"], 621284352)
        self.assertEqual(sorted(st.PINS["core"]["members"]), ["LICENSE.txt", "packer"])
        self.assertEqual(sorted(st.PINS["plugin"]["members"]), ["LICENSE.txt", st.PLUGIN_FILE])
        self.assertEqual(st.PINS["core"]["members"]["packer"], (0o755, 103727266, 3924419061))
        self.assertEqual(st.PINS["plugin"]["members"][st.PLUGIN_FILE], (0o755, 49807522, 3434352986))


class StageTests(StageCase):
    def test_stages_only_selected_members_and_exact_layout(self):
        staged = self.stage()
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "in"))),
                         ["base.img", "host_verify.py", "labapp.pkr.hcl", "plugins", "tools", "validate.pkrvars.hcl"])
        self.assertEqual(os.listdir(os.path.join(self.ws, "in", "tools")), ["packer"])
        plugin_dir = os.path.join(self.ws, "in", *st.PLUGIN_DIR)
        self.assertEqual(sorted(os.listdir(plugin_dir)), [st.PLUGIN_FILE, st.PLUGIN_FILE + "_SHA256SUM"])
        self.assertEqual(self.read("in", "tools", "packer"), CORE_BYTES)
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.ws, "in", "tools", "packer")).st_mode), 0o500)
        sidecar = self.read("in", *st.PLUGIN_DIR, st.PLUGIN_FILE + "_SHA256SUM")
        self.assertEqual(sidecar, hashlib.sha256(PLUGIN_BYTES).hexdigest().encode())
        self.assertEqual(len(sidecar), 64)
        self.assertEqual(staged["core_member_sha256"], hashlib.sha256(CORE_BYTES).hexdigest())
        self.assertEqual(staged["plugin_member_sha256"], hashlib.sha256(PLUGIN_BYTES).hexdigest())
        self.assertFalse(any("LICENSE" in n for _, _, names in os.walk(self.ws) for n in names))

    def test_output_tree_has_only_fixed_empty_directories_and_no_work_out(self):
        self.stage()
        out = os.path.join(self.ws, "out")
        self.assertEqual(sorted(os.listdir(out)), ["cache", "home", "tmp", "work"])
        self.assertEqual(os.listdir(os.path.join(out, "work")), ["cd"])
        self.assertEqual(os.listdir(os.path.join(out, "work", "cd")), [])
        self.assertEqual(os.listdir(os.path.join(out, "home")), [])
        for path in (self.ws, out, os.path.join(out, "work", "cd")):
            self.assertEqual(os.lstat(path).st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o700)

    def test_var_file_has_the_seven_variables_and_inputs_excludes_it(self):
        staged = self.stage()
        text = self.read("in", st.VARS_NAME).decode()
        self.assertEqual([line.split(" = ")[0] for line in text.splitlines()],
                         ["work_dir", "nonce", "inputs", "base_image", "base_sha256", "verifier", "verify_seconds"])
        self.assertIn('work_dir = "/out/work"', text)
        self.assertIn(f'nonce = "{self.nonce}"', text)
        self.assertIn(f'inputs = "{staged["inputs"]}"', text)
        self.assertIn('base_image = "/in/base.img"', text)
        self.assertIn('verifier = "/in/host_verify.py"', text)
        self.assertIn("verify_seconds = 30\n", text)
        self.assertEqual(staged["vars_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertNotIn(st.VARS_NAME, st.manifest(self.ws, staged["base_sha256"]).decode())
        self.assertEqual(hashlib.sha256(st.manifest(self.ws, staged["base_sha256"])).hexdigest(), staged["inputs"])
        self.assertTrue(st.verify_staged(self.ws, staged))

    def test_cd_directory_has_guest_files_and_generated_inputs(self):
        self.stage()
        self.assertEqual(sorted(os.listdir(os.path.join(self.ws, "cd"))),
                         ["MANIFEST", "guest-build.sh", "meta-data", "nonce", "plan.txt", "user-data"])
        self.assertEqual(self.read("cd", "nonce"), self.nonce.encode() + b"\n")
        self.assertNotIn("nonce", self.read("cd", "MANIFEST").decode())

    def test_changed_input_after_staging_is_detected(self):
        staged = self.stage()
        os.chmod(os.path.join(self.ws, "in", "tools"), 0o700)
        path = os.path.join(self.ws, "in", "tools", "packer")
        os.chmod(path, 0o600)
        with open(path, "ab") as handle:
            handle.write(b"x")
        self.assertFalse(st.verify_staged(self.ws, staged))

    def test_changed_var_file_or_base_is_detected(self):
        staged = self.stage()
        os.chmod(os.path.join(self.ws, "in", st.VARS_NAME), 0o600)
        with open(os.path.join(self.ws, "in", st.VARS_NAME), "ab") as handle:
            handle.write(b"#")
        self.assertFalse(st.verify_staged(self.ws, staged))
        # a fresh run for the base image
        other = os.path.join(self.ws, "again")
        os.mkdir(other, 0o700)
        staged = st.stage(other, self.sources, self.nonce, pins=self.pins)
        os.utime(self.sources["base"], ns=(1, 1))
        self.assertFalse(st.verify_staged(other, staged))


class RejectionTests(StageCase):
    def rejects(self, **kw):
        with self.assertRaises(st.StageError):
            self.stage(**kw)

    def test_wrong_archive_hash_or_size(self):
        pins = {k: dict(v) for k, v in self.pins.items()}
        pins["core"]["sha256"] = "0" * 64
        self.rejects(pins=pins)

    def test_wrong_size_pin_rejects_before_extraction(self):
        pins = {k: dict(v) for k, v in self.pins.items()}
        pins["plugin"]["size"] += 1
        self.rejects(pins=pins)
        self.assertEqual(os.listdir(os.path.join(self.ws, "in", *st.PLUGIN_DIR)), [])

    def test_extra_or_missing_member(self):
        members = {"LICENSE.txt": (b"l", 0o644), "packer": (CORE_BYTES, 0o755), "extra": (b"e", 0o644)}
        raw = make_zip(self.sources["core"], members)
        pins = {k: dict(v) for k, v in self.pins.items()}
        pins["core"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.rejects(pins=pins)

    def test_member_mode_size_and_crc_must_match_pin(self):
        for field, value in ((0, 0o644), (1, 1), (2, 1)):
            members = dict(self.pins["core"]["members"])
            entry = list(members["packer"])
            entry[field] = value
            members["packer"] = tuple(entry)
            pins = {k: dict(v) for k, v in self.pins.items()}
            pins["core"]["members"] = members
            fresh = os.path.join(self.inputs, f"ws{field}")
            os.mkdir(fresh, 0o700)
            with self.subTest(field=field):
                with self.assertRaises(st.StageError):
                    st.stage(fresh, self.sources, self.nonce, pins=pins)

    def test_symlink_member_type_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            info = zipfile.ZipInfo("packer")
            info.external_attr = (stat.S_IFLNK | 0o755) << 16
            zf.writestr(info, CORE_BYTES)
            zf.writestr(zipfile.ZipInfo("LICENSE.txt"), b"l")
        with open(self.sources["core"], "wb") as handle:
            handle.write(buffer.getvalue())
        pins = {k: dict(v) for k, v in self.pins.items()}
        pins["core"].update(size=len(buffer.getvalue()), sha256=hashlib.sha256(buffer.getvalue()).hexdigest())
        self.rejects(pins=pins)

    def test_actual_bytes_are_bounded_not_declared_size(self):
        # Declared size/CRC in the listing match the pin, but the pin is smaller than
        # the real stream: extraction must stop at the bound instead of trusting headers.
        pins = {k: dict(v) for k, v in self.pins.items()}
        members = dict(pins["core"]["members"])
        mode, size, crc = members["packer"]
        pin_zf = zipfile.ZipFile(self.sources["core"])
        with self.assertRaises(st.StageError):
            os.mkdir(os.path.join(self.ws, "x"), 0o700)
            st.extract_member(pin_zf, "packer", size - 1, crc, os.path.join(self.ws, "x", "packer"), st._noop)

    def test_corrupt_member_data_is_rejected(self):
        raw = bytearray(open(self.sources["core"], "rb").read())
        with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
            offset = zf.getinfo("packer").header_offset
        raw[offset + 30 + len("packer") + 3] ^= 0xFF      # inside the stored/deflated data
        with open(self.sources["core"], "wb") as handle:
            handle.write(raw)
        pins = {k: dict(v) for k, v in self.pins.items()}
        pins["core"].update(size=len(raw), sha256=hashlib.sha256(bytes(raw)).hexdigest())
        self.rejects(pins=pins)

    def test_symlinked_or_non_regular_sources_are_rejected(self):
        real = self.sources["base"] + ".real"
        os.rename(self.sources["base"], real)
        os.symlink(real, self.sources["base"])
        self.rejects()

    def test_fifo_source_is_rejected_without_blocking(self):
        os.unlink(self.sources["base"])
        os.mkfifo(self.sources["base"])
        self.rejects()

    def test_changed_base_image_is_rejected(self):
        with open(self.sources["base"], "ab") as handle:
            handle.write(b"x")
        self.rejects()

    def test_unsafe_path_and_bad_nonce(self):
        sources = dict(self.sources, base=self.sources["base"] + ",x")
        self.rejects(sources=sources)

    def test_bad_nonce(self):
        self.nonce = "ABC"
        self.rejects()

    def test_existing_output_paths_are_refused(self):
        os.mkdir(os.path.join(self.ws, "in"), 0o700)
        self.rejects()


class WalkTests(unittest.TestCase):
    def test_walk_rejects_symlinks_and_special_files(self):
        with tempfile.TemporaryDirectory() as raw:
            base = os.path.realpath(raw)
            open(os.path.join(base, "a"), "w").close()
            self.assertEqual(list(st.walk(base)), ["a"])
            os.symlink("a", os.path.join(base, "link"))
            with self.assertRaises(st.StageError):
                list(st.walk(base))


class BudgetHookTests(StageCase):
    def test_check_callback_runs_and_can_abort(self):
        class Stop(Exception):
            pass
        calls = []

        def check():
            calls.append(1)
            if len(calls) > 3:
                raise Stop()
        with self.assertRaises(Stop):
            self.stage(check=check)
        self.assertGreater(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
