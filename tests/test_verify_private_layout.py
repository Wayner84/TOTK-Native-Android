import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools" / "verify_private_layout.py"
SPEC = importlib.util.spec_from_file_location("verify_private_layout", MODULE_PATH)
layout = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(layout)


class PrivateLayoutTests(unittest.TestCase):
    def write_fixture(self, root: Path, *, mismatch=False, bad_bounds=False):
        segments = [
            {"name": "text", "address": 0x0000, "size": 0x1000, "extra": 0x0100,
             "elf_file_offset": 0x1000},
            {"name": "rodata", "address": 0x2000, "size": 0x1000, "extra": 0,
             "elf_file_offset": 0x2000},
            {"name": "data", "address": 0x4000, "size": 0x0800, "extra": 0x0800,
             "elf_file_offset": 0x3000},
        ]
        inventory = root / "main-inventory.json"
        inventory.write_text(json.dumps({
            "module": "main",
            "segment_hashes_verified": True,
            "segments": segments,
            "private_symbol_name": "must-not-leak",
        }), encoding="utf-8")

        payload = bytearray(0x3800)
        ident = b"\x7fELF\x02\x01\x01" + bytes(9)
        header = layout.ELF_HEADER.pack(
            ident, 3, 183, 1, 0, layout.ELF_HEADER.size, 0, 0,
            layout.ELF_HEADER.size, layout.PROGRAM_HEADER.size, 3, 0, 0, 0)
        payload[:len(header)] = header
        observed = [dict(segment) for segment in segments]
        if mismatch:
            observed[1]["size"] += 8
        if bad_bounds:
            observed[2]["elf_file_offset"] = len(payload)
        flags = (5, 4, 6)
        for index, segment in enumerate(observed):
            program = layout.PROGRAM_HEADER.pack(
                1, flags[index], segment["elf_file_offset"], segment["address"], 0,
                segment["size"], segment["size"] + (segment["extra"] if index == 2 else 0),
                4096)
            offset = layout.ELF_HEADER.size + index * layout.PROGRAM_HEADER.size
            payload[offset:offset + len(program)] = program
        elf = root / "main.elf"
        elf.write_bytes(payload)
        return inventory, elf

    def test_verified_layout_emits_sanitized_geometry(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory, elf = self.write_fixture(Path(temporary))
            report = layout.verify_layout(inventory, elf, "test")
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["segment_count"], 3)
            self.assertEqual(report["image_bytes"], 0x5000)
            self.assertEqual(report["initialized_bytes"], 0x2800)
            self.assertEqual(report["zero_fill_bytes"], 0x800)
            serialized = json.dumps(report)
            self.assertNotIn(str(inventory), serialized)
            self.assertNotIn(str(elf), serialized)
            self.assertNotIn("must-not-leak", serialized)

    def test_rejects_inventory_and_elf_geometry_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory, elf = self.write_fixture(Path(temporary), mismatch=True)
            with self.assertRaisesRegex(ValueError, "differs"):
                layout.verify_layout(inventory, elf, "test")

    def test_rejects_pt_load_outside_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory, elf = self.write_fixture(Path(temporary), bad_bounds=True)
            with self.assertRaisesRegex(ValueError, "exceeds ELF"):
                layout.verify_layout(inventory, elf, "test")

    def test_requires_verified_segment_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory, elf = self.write_fixture(root)
            document = json.loads(inventory.read_text(encoding="utf-8"))
            document["segment_hashes_verified"] = False
            inventory.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not confirm"):
                layout.verify_layout(inventory, elf, "test")


if __name__ == "__main__":
    unittest.main()
