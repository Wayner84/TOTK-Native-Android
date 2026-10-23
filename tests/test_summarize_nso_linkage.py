import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import summarize_nso_linkage as linkage


class NsoLinkageSummaryTests(unittest.TestCase):
    def make_module(self, root: Path, name: str, *, imports=None, exports=None,
                    target=0x2000, symbol_index=1, duplicate_rela=False):
        imports = imports or []
        exports = exports or []
        segments = [
            {"name": "text", "address": 0, "size": 0x100, "extra": 0,
             "elf_file_offset": 0x100},
            {"name": "rodata", "address": 0x1000, "size": 0x100, "extra": 0,
             "elf_file_offset": 0x200},
            {"name": "data", "address": 0x2000, "size": 0x100, "extra": 0x100,
             "elf_file_offset": 0x300},
        ]
        dynamic = [[7, 0x1000], [8, 24], [9, 24], [0, 0]]
        if duplicate_rela:
            dynamic.insert(1, [7, 0x1018])
        document = {
            "module": name,
            "segment_hashes_verified": True,
            "segments": segments,
            "dynamic_tags": dynamic,
            "needed": [],
            "imports": imports,
            "exports": exports,
        }
        (root / f"{name}-inventory.json").write_text(json.dumps(document), encoding="utf-8")
        elf = bytearray(0x400)
        elf[:4] = b"\x7fELF"
        struct.pack_into("<QQq", elf, 0x200, target, (symbol_index << 32) | 257, 0)
        (root / f"{name}.elf").write_bytes(elf)
        return document

    @staticmethod
    def symbol(index: int, name: str, defined: bool, binding: int = 1):
        return {"index": index, "name": name, "defined": defined, "binding": binding,
                "value": 0}

    def test_valid_cross_module_summary_hides_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "provider", exports=[self.symbol(1, "shared", True)])
            self.make_module(root, "consumer", imports=[self.symbol(1, "shared", False)])
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            result = linkage.summarize_version(root, "test", ("provider", "consumer"))
            consumer = result["modules"][1]
            self.assertEqual(consumer["imports_resolved_by_name"], 1)
            self.assertEqual(consumer["relocation_types"], {"257": 1})
            self.assertNotIn("shared", json.dumps(result))
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})

    def test_planner_uses_first_module_for_duplicate_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "first", exports=[self.symbol(1, "shared", True)])
            self.make_module(root, "second", exports=[self.symbol(1, "shared", True)])
            self.make_module(root, "consumer", imports=[self.symbol(1, "shared", False)])
            result = linkage.summarize_version(
                root, "test", ("first", "second", "consumer"),
                ("first", "second", "consumer"))
            plan = result["relocation_plan"]
            self.assertEqual(plan["shadowed_exports"]["second"], 1)
            consumer = next(row for row in plan["modules"] if row["module"] == "consumer")
            self.assertEqual(consumer["providers"], {"first": 1})

    def test_rejects_relocation_target_outside_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "bad", exports=[self.symbol(1, "x", True)], target=0x9000)
            with self.assertRaisesRegex(ValueError, "target is outside"):
                linkage.load_module(root, "bad")

    def test_rejects_relocation_symbol_out_of_range(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "bad", exports=[self.symbol(1, "x", True)], symbol_index=2)
            with self.assertRaisesRegex(ValueError, "symbol index is out of range"):
                linkage.load_module(root, "bad")

    def test_rejects_duplicate_singleton_dynamic_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "bad", exports=[self.symbol(1, "x", True)], duplicate_rela=True)
            with self.assertRaisesRegex(ValueError, "duplicated"):
                linkage.load_module(root, "bad")

    def test_rejects_noncontiguous_symbol_indices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "bad", exports=[self.symbol(2, "x", True)], symbol_index=0)
            with self.assertRaisesRegex(ValueError, "not contiguous"):
                linkage.load_module(root, "bad")

    def test_rejects_oversized_symbol_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "bad", exports=[self.symbol(1, "x" * 4097, True)])
            with self.assertRaisesRegex(ValueError, "oversized"):
                linkage.load_module(root, "bad")

    def test_relr_expands_base_and_bitmap_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = root / "relr.elf"
            payload = bytearray(0x300)
            struct.pack_into("<QQ", payload, 0x200, 0x2000, 0b1011)
            elf.write_bytes(payload)
            segments = [{"address": 0x1000, "size": 0x100, "extra": 0,
                         "elf_file_offset": 0x200},
                        {"address": 0x2000, "size": 0x100, "extra": 0,
                         "elf_file_offset": 0x100}]
            entries, relocations = linkage.parse_relr_table(elf, segments, 0x1000, 16)
            self.assertEqual((entries, relocations), (2, 3))

    def test_relr_rejects_bitmap_before_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = root / "relr.elf"
            payload = bytearray(0x300)
            struct.pack_into("<Q", payload, 0x200, 3)
            elf.write_bytes(payload)
            segments = [{"address": 0x1000, "size": 0x100, "extra": 0,
                         "elf_file_offset": 0x200}]
            with self.assertRaisesRegex(ValueError, "before a base"):
                linkage.parse_relr_table(elf, segments, 0x1000, 8)

    def test_planner_rejects_unresolved_strong(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "consumer", imports=[
                self.symbol(1, "strong", False),
                self.symbol(2, "weak", False, binding=2),
            ], symbol_index=1)
            with self.assertRaisesRegex(ValueError, "unresolved strong"):
                linkage.summarize_version(root, "test", ("consumer",))

    def test_planner_accepts_unresolved_weak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_module(root, "consumer", imports=[
                self.symbol(1, "weak", False, binding=2),
            ], symbol_index=1)
            result = linkage.summarize_version(root, "test", ("consumer",))
            self.assertEqual(result["unresolved_strong_imports"], 0)
            self.assertEqual(result["unresolved_weak_imports"], 1)
            self.assertEqual(result["relocation_plan"]["modules"][0]["weak_zero"], 1)


if __name__ == "__main__":
    unittest.main()
