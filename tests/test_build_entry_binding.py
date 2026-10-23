"""Self-contained fail-closed tests for the private entry-binding schema."""
from __future__ import annotations

import copy
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
import build_entry_binding as b


def sample_doc() -> dict:
    modules = []
    for index, name in enumerate(b.ORDER):
        modules.append({
            "module": name,
            "image_size": 0x8000,
            "writable_begin": 0x4000,
            "writable_size": 0x2000,
            "dt_init": 0x100 + index * 4,
            "init_array": {"offset": 0x5000, "size": 16},
            "ctor_flag": 0x4100 + index * 4,
            "carrier_size": 0x7000,
            "carrier_sha256": f"{index + 1:064x}",
        })
    document = {
        "schema": b.SCHEMA,
        "version": b.VERSION,
        "module_count": 3,
        "module_order": list(b.ORDER),
        "trusted_manifest_sha256": "a" * 64,
        "relocation_stream_sha256": "b" * 64,
        "modules": modules,
        "entries": {
            "nn_init_start": {"provider_id": 2, "offset": 0x300, "identity_source": "verified-elf-linkage"},
            "nn_main": {"provider_id": 0, "offset": 0x400, "identity_source": "verified-elf-linkage"},
        },
    }
    document["self_digest"] = b.sha(b.canonical(document))
    return document


def resign(document: dict) -> None:
    document.pop("self_digest", None)
    document["self_digest"] = b.sha(b.canonical(document))


def synthetic_build_fixture(directory: str):
    root = Path(directory) / "elf"
    root.mkdir()
    modules = []
    manifest_rows = []
    for index, name in enumerate(b.ORDER):
        carrier = root / f"{name}.elf"
        carrier.write_bytes(bytes([index + 1]) * 32)
        manifest_rows.append(f"{name}\t32\t{b.sha(carrier.read_bytes())}")
        exports = []
        if name == "main":
            exports.append({"name": b.MAIN, "binding": 2, "defined": True, "value": 0x100})
        if name == "sdk":
            exports.append({"name": b.START, "binding": 2, "defined": True, "value": 0x200})
        modules.append({
            "module": name,
            "elf_private": carrier,
            "exports_private": exports,
            "dynamic_private": [[b.INIT, 0x80]],
            "segments_private": [
                {"address": 0, "size": 0x1000, "extra": 0},
                {"address": 0x1000, "size": 0x1000, "extra": 0},
                {"address": 0x2000, "size": 0x1000, "extra": 0x1000},
            ],
        })
    relocations = Path(directory) / "relocations.bin"
    relocations.write_bytes(b"synthetic-stream")
    manifest_rows.append(
        f"relocations\t{relocations.stat().st_size}\t{b.sha(relocations.read_bytes())}"
    )
    manifest = Path(directory) / "manifest.tsv"
    manifest.write_text("\n".join(manifest_rows) + "\n", encoding="utf-8")
    descriptors = [
        (index, 0, b.linkage.MODULE_LAYOUT_START + index * b.linkage.MODULE_SLOT_SIZE,
         0x4000, 0x2000, 0x4000, 0)
        for index in range(3)
    ]
    stream = {"modules": 3, "descriptors": descriptors}
    return manifest, relocations, root, modules, stream


class EntryBindingTests(unittest.TestCase):
    def assert_rejected(self, mutate) -> None:
        document = sample_doc()
        mutate(document)
        resign(document)
        with self.assertRaises(ValueError):
            b.validate(document)

    def test_valid_deterministic_canonical_document(self):
        first = sample_doc()
        second = sample_doc()
        self.assertTrue(b.validate(first))
        self.assertEqual(b.canonical(first), b.canonical(second))
        self.assertEqual(first["self_digest"], second["self_digest"])

    def test_self_digest_rejected(self):
        document = sample_doc()
        document["self_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "self digest"):
            b.validate(document)

    def test_exact_top_level_and_module_keys(self):
        self.assert_rejected(lambda d: d.update(extra=1))
        self.assert_rejected(lambda d: d["modules"][0].update(extra=1))

    def test_bool_is_not_an_integer(self):
        self.assert_rejected(lambda d: d["modules"][0].update(image_size=True))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(provider_id=True))

    def test_digest_shape_and_case(self):
        self.assert_rejected(lambda d: d["modules"][0].update(carrier_sha256="A" * 64))
        self.assert_rejected(lambda d: d.update(trusted_manifest_sha256="0" * 63))

    def test_module_order_and_nonempty_geometry(self):
        self.assert_rejected(lambda d: d.update(module_order=["sdk", "subsdk0", "main"]))
        self.assert_rejected(lambda d: d["modules"][0].update(writable_size=0))
        self.assert_rejected(lambda d: d["modules"][0].update(image_size=0))

    def test_writable_range_overflow_and_containment(self):
        self.assert_rejected(lambda d: d["modules"][0].update(writable_begin=b.U64 - 7, writable_size=16))
        self.assert_rejected(lambda d: d["modules"][0].update(writable_begin=0x7000, writable_size=0x2000))

    def test_dt_init_and_ctor_bounds(self):
        self.assert_rejected(lambda d: d["modules"][0].update(dt_init=0))
        self.assert_rejected(lambda d: d["modules"][0].update(dt_init=3))
        self.assert_rejected(lambda d: d["modules"][0].update(ctor_flag=0x3000))

    def test_init_array_absent_is_canonical(self):
        document = sample_doc()
        document["modules"][0]["init_array"] = None
        resign(document)
        self.assertTrue(b.validate(document))

    def test_init_array_keys_alignment_size_overflow_and_bounds(self):
        self.assert_rejected(lambda d: d["modules"][0].update(init_array={"offset": 0x5000, "size": 16, "x": 0}))
        self.assert_rejected(lambda d: d["modules"][0].update(init_array={"offset": 3, "size": 16}))
        self.assert_rejected(lambda d: d["modules"][0].update(init_array={"offset": 0x5000, "size": 0}))
        self.assert_rejected(lambda d: d["modules"][0].update(init_array={"offset": b.U64 - 7, "size": 16}))
        self.assert_rejected(lambda d: d["modules"][0].update(init_array={"offset": 0x7ff8, "size": 16}))

    def test_entry_structure_provider_alignment_and_range(self):
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(provider_id=1))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(offset=3))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(offset=0x8000))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(identity_source="guess"))

    def test_entry_metadata_aliases(self):
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(offset=d["modules"][0]["dt_init"]))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(offset=d["modules"][0]["ctor_flag"]))
        self.assert_rejected(lambda d: d["entries"]["nn_main"].update(offset=d["modules"][0]["init_array"]["offset"]))

    def test_singleton_dynamic_tags(self):
        self.assertEqual(b.singleton([[12, 4]], 12, True), 4)
        with self.assertRaises(ValueError):
            b.singleton([], 12, True)
        with self.assertRaises(ValueError):
            b.singleton([[12, 4], [12, 8]], 12, True)

    def test_symbol_resolution(self):
        module = {"exports_private": [{"name": "target", "defined": True, "value": 0x100}],
                  "segments_private": [{"address": 0, "size": 0x1000, "extra": 0}]}
        self.assertEqual(b.symbol(module, "target"), 0x100)
        with self.assertRaises(ValueError):
            b.symbol({**module, "exports_private": []}, "target")
        with self.assertRaises(ValueError):
            b.symbol({**module, "exports_private": module["exports_private"] * 2}, "target")

    def test_planner_ordered_entry_resolution_and_fail_closed_identity(self):
        def module(name, exports):
            return {"module": name, "exports_private": exports,
                    "segments_private": [{"address": 0, "size": 0x1000, "extra": 0}]}
        good = {"name": "target", "binding": 2, "defined": True, "value": 0x100}
        mods = [module("main", []), module("subsdk0", []), module("sdk", [good])]
        self.assertEqual(b.resolve_entry(mods, "target", "sdk"), 0x100)
        shadow = copy.deepcopy(mods); shadow[0]["exports_private"] = [copy.deepcopy(good)]
        with self.assertRaisesRegex(ValueError, "provider mismatch"):
            b.resolve_entry(shadow, "target", "sdk")
        for bad in ({**good, "defined": False}, {**good, "value": 0x1000}, {**good, "value": 3}):
            with self.assertRaises(ValueError):
                b.resolve_entry([module("main", []), module("subsdk0", []), module("sdk", [bad])], "target", "sdk")
        ambiguous = [module("main", []), module("subsdk0", []), module("sdk", [good, copy.deepcopy(good)])]
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            b.resolve_entry(ambiguous, "target", "sdk")

    def test_constructor_zero_fill_is_not_initialized_writable(self):
        document = sample_doc()
        document["modules"][0]["ctor_flag"] = 0x6000
        resign(document)
        with self.assertRaises(ValueError):
            b.validate(document)

    def test_build_cross_checks_live_stream_and_carrier_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, relocations, root, modules, stream = synthetic_build_fixture(directory)
            with mock.patch.object(b, "validate_stream", return_value=stream), \
                    mock.patch.object(b.linkage, "load_module", side_effect=modules), \
                    mock.patch.object(b, "decode_ctor", return_value=0x2100):
                document = b.build(manifest, relocations, root)
            self.assertTrue(b.validate(document))

        with tempfile.TemporaryDirectory() as directory:
            manifest, relocations, root, modules, stream = synthetic_build_fixture(directory)
            bad_stream = copy.deepcopy(stream)
            descriptor = list(bad_stream["descriptors"][0])
            descriptor[3] += 1
            bad_stream["descriptors"][0] = tuple(descriptor)
            with mock.patch.object(b, "validate_stream", return_value=bad_stream), \
                    mock.patch.object(b.linkage, "load_module", side_effect=modules), \
                    mock.patch.object(b, "decode_ctor", return_value=0x2100), \
                    self.assertRaisesRegex(ValueError, "stream geometry mismatch"):
                b.build(manifest, relocations, root)

        with tempfile.TemporaryDirectory() as directory:
            manifest, relocations, root, modules, stream = synthetic_build_fixture(directory)
            (root / "main.elf").write_bytes(b"changed")
            with mock.patch.object(b, "validate_stream", return_value=stream), \
                    mock.patch.object(b.linkage, "load_module", side_effect=modules), \
                    mock.patch.object(b, "decode_ctor", return_value=0x2100), \
                    self.assertRaisesRegex(ValueError, "carrier mismatch main"):
                b.build(manifest, relocations, root)

        with tempfile.TemporaryDirectory() as directory:
            manifest, relocations, root, modules, stream = synthetic_build_fixture(directory)
            relocations.write_bytes(b"changed")
            with mock.patch.object(b, "validate_stream", return_value=stream), \
                    mock.patch.object(b.linkage, "load_module", side_effect=modules), \
                    mock.patch.object(b, "decode_ctor", return_value=0x2100), \
                    self.assertRaisesRegex(ValueError, "relocation carrier mismatch"):
                b.build(manifest, relocations, root)

    def test_ctor_decoder_masks_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "module.elf"
            elf.write_bytes(struct.pack("<II", 0x90000013, 0xB9400268))
            module = {"segments_private": [], "elf_private": elf}
            with mock.patch.object(b.linkage, "virtual_to_file", return_value=0):
                self.assertIsInstance(b.decode_ctor(module, 0x1000), int)
                elf.write_bytes(struct.pack("<II", 0, 0xB9400268))
                with self.assertRaisesRegex(ValueError, "ADRP"):
                    b.decode_ctor(module, 0x1000)
                elf.write_bytes(b"\0" * 4)
                with self.assertRaisesRegex(ValueError, "truncated"):
                    b.decode_ctor(module, 0x1000)

    def test_manifest_exact_shape_order_and_digest(self):
        rows = [f"{name}\t1\t{'0' * 64}" for name in (*b.ORDER, "relocations")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.tsv"
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            _, parsed = b.read_manifest(path)
            self.assertEqual([row[0] for row in parsed], [*b.ORDER, "relocations"])
            path.write_text(rows[0] + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                b.read_manifest(path)
            for size in ("01", "０", "١"):
                path.write_text("\n".join(f"{name}\t{size}\t{'0' * 64}" for name in (*b.ORDER, "relocations")) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    b.read_manifest(path)

    def test_read_rejects_trailing_truncated_and_noncanonical_json(self):
        document = sample_doc()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.json"
            path.write_bytes(b.canonical(document))
            self.assertEqual(b.read(path), document)
            path.write_bytes(b.canonical(document) + b"\n")
            with self.assertRaises(ValueError):
                b.read(path)
            path.write_bytes(json.dumps(document).encode() + b"\n")
            with self.assertRaises(ValueError):
                b.read(path)
            path.write_bytes(b"{")
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                b.read(path)

    def test_atomic_write_rereads_and_leaves_no_temporary_file(self):
        document = sample_doc()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.json"
            b.atomic(path, document)
            self.assertEqual(b.read(path), document)
            self.assertEqual(list(Path(directory).glob("binding.json.*")), [])


if __name__ == "__main__":
    unittest.main()
