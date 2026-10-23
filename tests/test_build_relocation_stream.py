import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_relocation_stream as relocation_stream
import summarize_nso_linkage as linkage


class RelocationStreamTests(unittest.TestCase):
    def write_valid_stream(self, path: Path) -> bytearray:
        descriptors = [
            (0, 0, 0x10000000, 0x3000, 0x2000, 0x2100, 1),
            (1, 0, 0x20000000, 0x3000, 0x2000, 0x2100, 2),
        ]
        records = [
            (0x2000, 1027, relocation_stream.SOURCE_RELA, 0, 0, 0, 0x10),
            (0x2000, 257, relocation_stream.SOURCE_RELA, 0, 0, 0x20, 4),
            (0x2008, 1026, relocation_stream.SOURCE_RELA,
             relocation_stream.NO_PROVIDER, 0, 0, 0),
        ]
        payload = bytearray(relocation_stream.HEADER.pack(
            relocation_stream.MAGIC, relocation_stream.FORMAT_VERSION,
            relocation_stream.HEADER.size, relocation_stream.MODULE.size,
            relocation_stream.RECORD.size, len(descriptors), len(records),
            linkage.GUEST_WINDOW_SIZE, linkage.MODULE_SLOT_SIZE,
            linkage.MODULE_LAYOUT_START))
        for descriptor in descriptors:
            payload.extend(relocation_stream.MODULE.pack(*descriptor))
        for record in records:
            payload.extend(relocation_stream.RECORD.pack(*record))
        path.write_bytes(payload)
        return payload

    def record_offset(self, module_count: int, record_index: int) -> int:
        return (relocation_stream.HEADER.size + module_count * relocation_stream.MODULE.size +
                record_index * relocation_stream.RECORD.size)

    def test_valid_stream_is_name_free_and_counted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "valid.bin"
            self.write_valid_stream(path)
            summary = relocation_stream.validate_stream(path)
            self.assertEqual(summary["records"], 3)
            self.assertEqual(summary["kind_counts"], {"257": 1, "1026": 1, "1027": 1})
            self.assertFalse(summary["private_names_recorded"])
            self.assertFalse(summary["mapped_bytes_modified"])

    def test_builder_externally_sorts_with_one_record_chunks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            segments = [
                {"address": 0, "size": 0x100, "extra": 0, "elf_file_offset": 0x100},
                {"address": 0x1000, "size": 0x100, "extra": 0, "elf_file_offset": 0x200},
                {"address": 0x2000, "size": 0x100, "extra": 0x100, "elf_file_offset": 0x300},
            ]
            provider_elf = root / "provider.elf"
            provider_elf.write_bytes(bytearray(0x400))
            consumer_bytes = bytearray(0x400)
            # Deliberately emit higher target first; output must be sorted.
            struct.pack_into("<QQq", consumer_bytes, 0x200,
                             0x2008, (1 << 32) | 257, 3)
            struct.pack_into("<QQq", consumer_bytes, 0x218,
                             0x2000, (1 << 32) | 1026, 99)
            consumer_elf = root / "consumer.elf"
            consumer_elf.write_bytes(consumer_bytes)
            provider_symbol = {"index": 1, "name": "shared", "defined": True,
                               "binding": 1, "value": 0x20}
            import_symbol = {"index": 1, "name": "shared", "defined": False,
                             "binding": 1, "value": 0}
            provider = {
                "module": "provider", "segments_private": segments,
                "dynamic_private": [], "elf_private": provider_elf,
                "symbols_by_index_private": {1: provider_symbol},
                "imports_private": [], "exports_private": [provider_symbol],
            }
            consumer = {
                "module": "consumer", "segments_private": segments,
                "dynamic_private": [[7, 0x1000], [8, 48], [9, 24]],
                "elf_private": consumer_elf,
                "symbols_by_index_private": {1: import_symbol},
                "imports_private": [import_symbol], "exports_private": [],
            }
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            output = root / "private-relocations.bin"
            summary = relocation_stream.build_stream(
                [provider, consumer], ("provider", "consumer"), output, chunk_records=1)
            self.assertEqual(summary["records"], 2)
            self.assertEqual(summary["chunk_records"], 1)
            self.assertEqual(before, {path.name: path.read_bytes()
                                      for path in root.iterdir() if path != output})
            raw = output.read_bytes()
            start = self.record_offset(2, 0)
            first = relocation_stream.RECORD.unpack_from(raw, start)
            second = relocation_stream.RECORD.unpack_from(raw, start + relocation_stream.RECORD.size)
            self.assertEqual((first[0], second[0]), (0x2000, 0x2008))
            self.assertEqual(first[1], 1026)
            self.assertEqual(first[6], 0)  # JUMP_SLOT addend is canonicalized.

    def test_chunk_merge_fan_in_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = []
            for index in range(relocation_stream.MAX_MERGE_FAN_IN + 1):
                path = root / f"input-{index}.bin"
                relocation_stream.write_chunk(
                    path, [(index * 8, 1027, relocation_stream.SOURCE_RELA, 0, 0, index)])
                paths.append(path)
            reduced = relocation_stream.reduce_chunk_fan_in(paths, root, "bounded")
            self.assertLessEqual(len(reduced), relocation_stream.MAX_MERGE_FAN_IN)
            self.assertEqual([row[0] for row in relocation_stream.merge_chunks(reduced)],
                             [index * 8 for index in range(relocation_stream.MAX_MERGE_FAN_IN + 1)])
            self.assertTrue(all(not path.exists() for path in paths))

    def mutate_record(self, payload: bytearray, index: int, field_offset: int,
                      fmt: str, value: int) -> bytearray:
        struct.pack_into(fmt, payload, self.record_offset(2, index) + field_offset, value)
        return payload

    def assert_invalid(self, mutation, message: str):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.bin"
            payload = self.write_valid_stream(path)
            mutation(payload)
            path.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, message):
                relocation_stream.validate_stream(path)

    def test_rejects_unsupported_kind(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 0, 8, "<I", 999),
                            "unsupported kind")

    def test_rejects_target_outside_writable_segment(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 0, 0, "<Q", 0x1000),
                            "target is invalid")

    def test_rejects_provider_out_of_range(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 1, 13, "<B", 3),
                            "provider is invalid")

    def test_rejects_symbol_outside_provider(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 1, 16, "<Q", 0x3000),
                            "outside provider image")

    def test_rejects_relative_addend_out_of_range(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 0, 24, "<q", -1),
                            "relative addend is invalid")

    def test_rejects_duplicate_targets(self):
        self.assert_invalid(lambda data: self.mutate_record(data, 2, 0, "<Q", 0x2000),
                            "duplicated or unsorted")

    def test_rejects_truncated_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "truncated.bin"
            payload = self.write_valid_stream(path)
            path.write_bytes(payload[:-1])
            with self.assertRaisesRegex(ValueError, "truncated or has trailing data"):
                relocation_stream.validate_stream(path)


if __name__ == "__main__":
    unittest.main()
