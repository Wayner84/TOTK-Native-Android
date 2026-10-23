#!/usr/bin/env python3
"""Cross-check a private analysis carrier's PT_LOAD layout against its inventory.

The committed report contains numeric geometry only. It never records private
paths, hashes, symbol names, or proprietary bytes.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path

MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_INVENTORY_BYTES = 128 * 1024 * 1024
MAX_SLOT_BYTES = 256 * 1024 * 1024
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
EXPECTED_FLAGS = (5, 4, 6)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def checked_int(value: object, label: str, maximum: int = (1 << 63) - 1) -> int:
    check(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    check(0 <= value <= maximum, f"{label} is out of range")
    return value


def read_inventory(path: Path) -> tuple[str, list[dict[str, int]]]:
    size = path.stat().st_size
    check(0 < size <= MAX_INVENTORY_BYTES, "invalid inventory size")
    document = json.loads(path.read_text(encoding="utf-8"))
    check(isinstance(document, dict), "inventory must be an object")
    module = document.get("module")
    check(isinstance(module, str) and module in ("rtld", "main", "sdk", "subsdk0"),
          "unsupported module identity")
    check(document.get("segment_hashes_verified") is True,
          "inventory does not confirm segment hashes")
    raw_segments = document.get("segments")
    check(isinstance(raw_segments, list) and len(raw_segments) == 3,
          "expected exactly three inventory segments")
    segments: list[dict[str, int]] = []
    previous_end = 0
    for index, raw in enumerate(raw_segments):
        check(isinstance(raw, dict), f"inventory segment {index} must be an object")
        address = checked_int(raw.get("address"), f"segment {index} address", MAX_SLOT_BYTES)
        file_bytes = checked_int(raw.get("size"), f"segment {index} size", MAX_SLOT_BYTES)
        zero_fill = checked_int(raw.get("extra", 0), f"segment {index} extra", MAX_SLOT_BYTES)
        file_offset = checked_int(raw.get("elf_file_offset"),
                                  f"segment {index} file offset", MAX_ELF_BYTES)
        check(file_bytes > 0, f"segment {index} is empty")
        check(file_bytes <= MAX_SLOT_BYTES - zero_fill, f"segment {index} size overflows")
        # The private inventory's `extra` includes NSO decompression/hash-tail
        # bytes for all segments. The analysis carrier exposes only the data
        # segment's `extra` as ELF zero-fill (p_memsz - p_filesz); text and
        # rodata PT_LOAD memory sizes remain equal to their initialized sizes.
        inventory_extent = file_bytes + zero_fill
        memory_bytes = inventory_extent if index == 2 else file_bytes
        check(address >= previous_end and address <= MAX_SLOT_BYTES - inventory_extent,
              "inventory segments overlap or exceed the module slot")
        previous_end = address + inventory_extent
        segments.append({
            "virtual_address": address,
            "file_offset": file_offset,
            "file_bytes": file_bytes,
            "memory_bytes": memory_bytes,
            "flags": EXPECTED_FLAGS[index],
        })
    return module, segments


def read_elf_load_segments(path: Path) -> tuple[int, list[dict[str, int]]]:
    file_size = path.stat().st_size
    check(ELF_HEADER.size <= file_size <= MAX_ELF_BYTES, "invalid analysis ELF size")
    with path.open("rb") as source:
        raw_header = source.read(ELF_HEADER.size)
        check(len(raw_header) == ELF_HEADER.size, "truncated ELF header")
        (ident, elf_type, machine, version, entry, program_offset, _section_offset,
         _flags, header_size, program_entry_size, program_count,
         _section_entry_size, _section_count, _section_names) = ELF_HEADER.unpack(raw_header)
        check(ident[:7] == b"\x7fELF\x02\x01\x01", "unsupported ELF identity")
        check(elf_type == 3 and machine == 183 and version == 1 and entry == 0,
              "unsupported ELF header")
        check(header_size == ELF_HEADER.size and program_entry_size == PROGRAM_HEADER.size,
              "unsupported ELF header sizes")
        check(0 < program_count <= 16, "program-header count is out of range")
        table_bytes = program_count * PROGRAM_HEADER.size
        check(program_offset <= file_size and table_bytes <= file_size - program_offset,
              "program-header table exceeds the ELF")
        source.seek(program_offset)
        loads: list[dict[str, int]] = []
        for index in range(program_count):
            row = source.read(PROGRAM_HEADER.size)
            check(len(row) == PROGRAM_HEADER.size, f"truncated program header {index}")
            (kind, flags, offset, virtual_address, _physical_address,
             segment_file_bytes, memory_bytes, alignment) = PROGRAM_HEADER.unpack(row)
            if kind != 1:
                continue
            check(segment_file_bytes > 0 and segment_file_bytes <= memory_bytes,
                  f"invalid PT_LOAD size at index {index}")
            check(offset <= file_size and segment_file_bytes <= file_size - offset,
                  f"PT_LOAD exceeds ELF at index {index}")
            check(alignment == 4096 and offset % alignment == virtual_address % alignment,
                  f"unsupported PT_LOAD alignment at index {index}")
            check(virtual_address <= MAX_SLOT_BYTES and
                  memory_bytes <= MAX_SLOT_BYTES - virtual_address,
                  f"PT_LOAD exceeds module slot at index {index}")
            loads.append({
                "virtual_address": virtual_address,
                "file_offset": offset,
                "file_bytes": segment_file_bytes,
                "memory_bytes": memory_bytes,
                "flags": flags,
            })
    loads.sort(key=lambda segment: segment["virtual_address"])
    check(len(loads) == 3, "expected exactly three PT_LOAD segments")
    return file_size, loads


def verify_layout(inventory_path: Path, elf_path: Path, version: str) -> dict:
    check(version and "\0" not in version and len(version) <= 64, "invalid version label")
    module, expected = read_inventory(inventory_path)
    carrier_bytes, observed = read_elf_load_segments(elf_path)
    for index, (inventory, elf) in enumerate(zip(expected, observed, strict=True)):
        check(elf == inventory, f"PT_LOAD {index} differs from verified inventory geometry")
    image_bytes = max(segment["virtual_address"] + segment["memory_bytes"]
                      for segment in observed)
    initialized_bytes = sum(segment["file_bytes"] for segment in observed)
    zero_fill_bytes = sum(segment["memory_bytes"] - segment["file_bytes"]
                          for segment in observed)
    return {
        "format": 1,
        "status": "pass",
        "scope": "private analysis-carrier PT_LOAD geometry cross-check",
        "private_paths_recorded": False,
        "private_hashes_recorded": False,
        "private_names_recorded": False,
        "version": version,
        "module": module,
        "carrier_bytes": carrier_bytes,
        "segment_count": len(observed),
        "image_bytes": image_bytes,
        "initialized_bytes": initialized_bytes,
        "zero_fill_bytes": zero_fill_bytes,
        "segments": [
            {
                "virtual_address": hex(segment["virtual_address"]),
                "file_bytes": segment["file_bytes"],
                "memory_bytes": segment["memory_bytes"],
                "flags": segment["flags"],
            }
            for segment in observed
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_layout(args.inventory, args.elf, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, args.output)
    print(f"PASS: {report['module']} layout matches verified inventory; sanitized report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
