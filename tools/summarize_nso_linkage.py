#!/usr/bin/env python3
"""Validate private NSO analysis metadata and emit a name-free linkage summary.

Inputs are the private analysis carriers produced by the pinned
MacNativeGames prepare_modules.py tool. The committed output contains counts
and numeric relocation kinds only: no symbols, module hashes, or proprietary
bytes.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import struct
from pathlib import Path

MODULES = ("rtld", "main", "sdk", "subsdk0")
# Matches the proven Mac runtime's generated Module[] order. rtld performs the
# original bootstrap and is not one of the three persistent relocated images.
RESOLUTION_ORDER = ("main", "subsdk0", "sdk")
GUEST_WINDOW_SIZE = 0x320000000
MODULE_SLOT_SIZE = 0x10000000
MODULE_LAYOUT_START = 0x10000000
MAX_INVENTORY_BYTES = 128 * 1024 * 1024
MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_SYMBOLS = 1_000_000
MAX_RELOCATIONS = 4_000_000
MAX_NAME_CHARS = 4096
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_PLTREL = 20
DT_JMPREL = 23
DT_RELRSZ = 35
DT_RELR = 36
DT_RELRENT = 37
DT_RELA_VALUE = 7


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json_bounded(path: Path) -> dict:
    size = path.stat().st_size
    check(0 < size <= MAX_INVENTORY_BYTES, f"invalid inventory size: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    check(isinstance(value, dict), f"inventory must be an object: {path.name}")
    return value


def checked_int(value: object, label: str, maximum: int = (1 << 63) - 1) -> int:
    check(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    check(0 <= value <= maximum, f"{label} is out of range")
    return value


def checked_name(value: object, label: str) -> str:
    check(isinstance(value, str), f"{label} must be text")
    check(0 < len(value) <= MAX_NAME_CHARS and "\0" not in value,
          f"{label} is empty, oversized, or contains NUL")
    return value


def singleton_tag(dynamic: list[object], tag: int, required: bool = False) -> int | None:
    values = []
    for index, row in enumerate(dynamic):
        check(isinstance(row, list) and len(row) == 2, f"dynamic row {index} is malformed")
        row_tag = checked_int(row[0], f"dynamic tag {index}")
        row_value = checked_int(row[1], f"dynamic value {index}")
        if row_tag == tag:
            values.append(row_value)
    check(len(values) <= 1, f"dynamic tag {tag} is duplicated")
    if required:
        check(len(values) == 1, f"dynamic tag {tag} is missing")
    return values[0] if values else None


def validate_segments(raw_segments: object) -> list[dict[str, int]]:
    check(isinstance(raw_segments, list) and len(raw_segments) == 3,
          "expected exactly text, rodata, and data segments")
    segments: list[dict[str, int]] = []
    previous_end = 0
    for index, raw in enumerate(raw_segments):
        check(isinstance(raw, dict), f"segment {index} must be an object")
        address = checked_int(raw.get("address"), f"segment {index} address", (1 << 48) - 1)
        size = checked_int(raw.get("size"), f"segment {index} size", 256 * 1024 * 1024)
        extra = checked_int(raw.get("extra", 0), f"segment {index} extra", 256 * 1024 * 1024)
        file_offset = checked_int(raw.get("elf_file_offset"), f"segment {index} file offset", MAX_ELF_BYTES)
        check(size > 0 and address >= previous_end, "segments overlap or are unsorted")
        check(address + size + extra < (1 << 48), "segment address overflow")
        previous_end = address + size + extra
        segments.append({"address": address, "size": size, "extra": extra,
                         "elf_file_offset": file_offset})
    return segments


def virtual_to_file(segments: list[dict[str, int]], address: int, size: int) -> int:
    check(size >= 0 and address + size < (1 << 64), "metadata address overflow")
    for segment in segments:
        begin = segment["address"]
        end = begin + segment["size"]
        if begin <= address and address + size <= end:
            return segment["elf_file_offset"] + address - begin
    raise ValueError("dynamic metadata lies outside initialized segments")


def relocation_target_is_mapped(segments: list[dict[str, int]], address: int) -> bool:
    for segment in segments:
        begin = segment["address"]
        end = begin + segment["size"] + segment["extra"]
        if begin <= address and address + 8 <= end:
            return True
    return False


def validate_symbols(document: dict) -> tuple[list[dict], list[dict], int]:
    imports = document.get("imports")
    exports = document.get("exports")
    check(isinstance(imports, list) and isinstance(exports, list), "imports/exports must be arrays")
    symbols = imports + exports
    check(len(symbols) <= MAX_SYMBOLS, "symbol count exceeds bound")
    indices: set[int] = set()
    for kind, rows, expected_defined in (("import", imports, False), ("export", exports, True)):
        for position, symbol in enumerate(rows):
            check(isinstance(symbol, dict), f"{kind} {position} must be an object")
            checked_name(symbol.get("name"), f"{kind} {position} name")
            index = checked_int(symbol.get("index"), f"{kind} {position} index", MAX_SYMBOLS)
            binding = checked_int(symbol.get("binding"), f"{kind} {position} binding", 15)
            checked_int(symbol.get("value"), f"{kind} {position} value", (1 << 48) - 1)
            check(index != 0 and index not in indices, "symbol indices are zero or duplicated")
            check(symbol.get("defined") is expected_defined, f"{kind} defined flag is inconsistent")
            check(binding in (0, 1, 2, 10), f"unsupported symbol binding {binding}")
            indices.add(index)
    count = max(indices, default=0) + 1
    check(indices == set(range(1, count)), "named symbol indices are not contiguous")
    return imports, exports, count


def parse_relocation_table(
    elf: Path,
    segments: list[dict[str, int]],
    address: int,
    size: int,
    symbol_count: int,
) -> collections.Counter[int]:
    check(size % 24 == 0, "relocation table size is not ELF64 Rela aligned")
    count = size // 24
    check(count <= MAX_RELOCATIONS, "relocation count exceeds bound")
    offset = virtual_to_file(segments, address, size)
    elf_size = elf.stat().st_size
    check(0 < elf_size <= MAX_ELF_BYTES, "invalid analysis ELF size")
    check(offset + size <= elf_size, "relocation table exceeds analysis ELF")
    kinds: collections.Counter[int] = collections.Counter()
    with elf.open("rb") as source:
        source.seek(offset)
        for index in range(count):
            row = source.read(24)
            check(len(row) == 24, f"truncated relocation {index}")
            target, info, _addend = struct.unpack("<QQq", row)
            symbol = info >> 32
            kind = info & 0xFFFFFFFF
            check(symbol < symbol_count, f"relocation {index} symbol index is out of range")
            check(relocation_target_is_mapped(segments, target),
                  f"relocation {index} target is outside the module image")
            kinds[kind] += 1
    return kinds


def parse_relr_table(
    elf: Path,
    segments: list[dict[str, int]],
    address: int,
    size: int,
) -> tuple[int, int]:
    check(size % 8 == 0, "RELR table size is not 64-bit aligned")
    entries = size // 8
    check(entries <= MAX_RELOCATIONS, "RELR entry count exceeds bound")
    offset = virtual_to_file(segments, address, size)
    elf_size = elf.stat().st_size
    check(0 < elf_size <= MAX_ELF_BYTES and offset + size <= elf_size,
          "RELR table exceeds analysis ELF")
    cursor: int | None = None
    relocations = 0
    with elf.open("rb") as source:
        source.seek(offset)
        for index in range(entries):
            row = source.read(8)
            check(len(row) == 8, f"truncated RELR entry {index}")
            entry = struct.unpack("<Q", row)[0]
            if entry & 1 == 0:
                check(entry % 8 == 0, f"unaligned RELR address at entry {index}")
                check(cursor is None or entry >= cursor, f"backward RELR address at entry {index}")
                check(relocation_target_is_mapped(segments, entry),
                      f"RELR target {index} is outside the module image")
                cursor = entry + 8
                relocations += 1
            else:
                check(cursor is not None, "RELR bitmap appears before a base address")
                for bit in range(1, 64):
                    if entry & (1 << bit):
                        target = cursor + (bit - 1) * 8
                        check(relocation_target_is_mapped(segments, target),
                              f"RELR bitmap target {index} is outside the module image")
                        relocations += 1
                        check(relocations <= MAX_RELOCATIONS,
                              "expanded RELR count exceeds bound")
                cursor += 63 * 8
    return entries, relocations


def iter_relocations(
    elf: Path,
    segments: list[dict[str, int]],
    address: int,
    size: int,
):
    check(size % 24 == 0 and size // 24 <= MAX_RELOCATIONS,
          "invalid relocation table bound")
    offset = virtual_to_file(segments, address, size)
    check(offset + size <= elf.stat().st_size, "relocation table exceeds analysis ELF")
    with elf.open("rb") as source:
        source.seek(offset)
        for index in range(size // 24):
            row = source.read(24)
            check(len(row) == 24, f"truncated relocation {index}")
            target, info, addend = struct.unpack("<QQq", row)
            yield target, info >> 32, info & 0xFFFFFFFF, addend


def iter_relr_targets(
    elf: Path,
    segments: list[dict[str, int]],
    address: int,
    size: int,
):
    check(size % 8 == 0 and size // 8 <= MAX_RELOCATIONS,
          "invalid RELR table bound")
    offset = virtual_to_file(segments, address, size)
    check(offset + size <= elf.stat().st_size, "RELR table exceeds analysis ELF")
    cursor: int | None = None
    expanded = 0
    with elf.open("rb") as source:
        source.seek(offset)
        for index in range(size // 8):
            row = source.read(8)
            check(len(row) == 8, f"truncated RELR entry {index}")
            entry = struct.unpack("<Q", row)[0]
            if entry & 1 == 0:
                check(entry % 8 == 0 and (cursor is None or entry >= cursor),
                      f"malformed RELR base at entry {index}")
                cursor = entry + 8
                expanded += 1
                yield entry
            else:
                check(cursor is not None, "RELR bitmap appears before a base address")
                for bit in range(1, 64):
                    if entry & (1 << bit):
                        expanded += 1
                        check(expanded <= MAX_RELOCATIONS, "expanded RELR count exceeds bound")
                        yield cursor + (bit - 1) * 8
                cursor += 63 * 8


def load_module(root: Path, module: str) -> dict:
    inventory_path = root / f"{module}-inventory.json"
    elf_path = root / f"{module}.elf"
    document = read_json_bounded(inventory_path)
    check(document.get("module") == module, f"module identity mismatch for {module}")
    check(document.get("segment_hashes_verified") is True,
          f"segment hashes were not verified for {module}")
    segments = validate_segments(document.get("segments"))
    imports, exports, symbol_count = validate_symbols(document)
    dynamic = document.get("dynamic_tags")
    check(isinstance(dynamic, list) and len(dynamic) <= 4096, "dynamic table exceeds bound")
    rela_ent = singleton_tag(dynamic, DT_RELAENT)
    if rela_ent is not None:
        check(rela_ent == 24, "unsupported DT_RELAENT")

    kinds: collections.Counter[int] = collections.Counter()
    tables = 0
    relr_entries = 0
    relr_relocations = 0
    for address_tag, size_tag, label in (
        (DT_RELA, DT_RELASZ, "rela"),
        (DT_JMPREL, DT_PLTRELSZ, "jmprel"),
    ):
        address = singleton_tag(dynamic, address_tag)
        size = singleton_tag(dynamic, size_tag)
        check((address is None) == (size is None), f"incomplete {label} metadata")
        if address is None or size == 0:
            continue
        if label == "jmprel":
            check(singleton_tag(dynamic, DT_PLTREL, required=True) == DT_RELA_VALUE,
                  "unsupported PLT relocation encoding")
        kinds.update(parse_relocation_table(elf_path, segments, address, size, symbol_count))
        tables += 1

    relr_address = singleton_tag(dynamic, DT_RELR)
    relr_size = singleton_tag(dynamic, DT_RELRSZ)
    relr_ent = singleton_tag(dynamic, DT_RELRENT)
    check((relr_address is None) == (relr_size is None) == (relr_ent is None),
          "incomplete RELR metadata")
    if relr_address is not None and relr_size:
        check(relr_ent == 8, "unsupported DT_RELRENT")
        relr_entries, relr_relocations = parse_relr_table(
            elf_path, segments, relr_address, relr_size)
        kinds[1027] += relr_relocations
        tables += 1

    needed = document.get("needed")
    check(isinstance(needed, list), "needed must be an array")
    for index, name in enumerate(needed):
        checked_name(name, f"needed {index}")
    expected_needed = sum(1 for row in dynamic if isinstance(row, list) and len(row) == 2 and row[0] == DT_NEEDED)
    check(len(needed) == expected_needed, "DT_NEEDED count differs from inventory")
    return {
        "module": module,
        "imports_private": imports,
        "exports_private": exports,
        "symbols_by_index_private": {symbol["index"]: symbol for symbol in imports + exports},
        "segments_private": segments,
        "dynamic_private": dynamic,
        "elf_private": elf_path,
        "summary": {
            "module": module,
            "segment_hashes_verified": True,
            "symbols": symbol_count,
            "imports": len(imports),
            "exports": len(exports),
            "needed": len(needed),
            "relocation_tables": tables,
            "relocations": sum(kinds.values()),
            "relocation_types": {str(kind): kinds[kind] for kind in sorted(kinds)},
            "relr_entries": relr_entries,
            "relr_relocations": relr_relocations,
        },
    }


def read_virtual_u64(module: dict, address: int) -> int:
    offset = virtual_to_file(module["segments_private"], address, 8)
    elf = module["elf_private"]
    with elf.open("rb") as source:
        source.seek(offset)
        data = source.read(8)
    check(len(data) == 8, "truncated relocation addend")
    return struct.unpack("<Q", data)[0]


def plan_version_relocations(loaded: list[dict], order: tuple[str, ...] = RESOLUTION_ORDER) -> dict:
    by_name = {module["module"]: module for module in loaded}
    check(len(by_name) == len(loaded) and len(set(order)) == len(order),
          "module names/order must be unique")
    check(all(name in by_name for name in order), "resolution order references a missing module")

    bases: dict[str, int] = {}
    image_ends: dict[str, int] = {}
    for index, name in enumerate(order):
        module = by_name[name]
        image_end = max(segment["address"] + segment["size"] + segment["extra"]
                        for segment in module["segments_private"])
        check(image_end <= MODULE_SLOT_SIZE, f"{name} exceeds its guest slot")
        base = MODULE_LAYOUT_START + index * MODULE_SLOT_SIZE
        check(base + image_end <= GUEST_WINDOW_SIZE, f"{name} exceeds the guest window")
        bases[name] = base
        image_ends[name] = image_end

    selected: dict[str, tuple[str, dict]] = {}
    selected_counts: collections.Counter[str] = collections.Counter()
    shadowed_counts: collections.Counter[str] = collections.Counter()
    non_addressable_counts: collections.Counter[str] = collections.Counter()
    for name in order:
        for symbol in by_name[name]["exports_private"]:
            if symbol["binding"] not in (1, 2, 10):
                continue
            if symbol["value"] >= image_ends[name]:
                non_addressable_counts[name] += 1
                continue
            if symbol["name"] in selected:
                shadowed_counts[name] += 1
            else:
                selected[symbol["name"]] = (name, symbol)
                selected_counts[name] += 1

    module_results = []
    for name in order:
        module = by_name[name]
        segments = module["segments_private"]
        dynamic = module["dynamic_private"]
        elf = module["elf_private"]
        symbols = module["symbols_by_index_private"]
        writable_begin = segments[2]["address"]
        writable_end = writable_begin + segments[2]["size"] + segments[2]["extra"]
        slots: set[int] = set()
        counts: collections.Counter[str] = collections.Counter()
        providers: collections.Counter[str] = collections.Counter()

        relr_address = singleton_tag(dynamic, DT_RELR)
        relr_size = singleton_tag(dynamic, DT_RELRSZ)
        if relr_address is not None and relr_size:
            for target in iter_relr_targets(elf, segments, relr_address, relr_size):
                check(writable_begin <= target <= writable_end - 8,
                      f"{name} RELR target is outside writable data")
                check(target not in slots, f"{name} has duplicate relocation targets")
                slots.add(target)
                addend = read_virtual_u64(module, target)
                check(addend < image_ends[name], f"{name} RELR addend is outside its image")
                check(bases[name] + addend < GUEST_WINDOW_SIZE,
                      f"{name} RELR result exceeds the guest window")
                counts["relative"] += 1
                counts["relr"] += 1

        for address_tag, size_tag in ((DT_RELA, DT_RELASZ), (DT_JMPREL, DT_PLTRELSZ)):
            address = singleton_tag(dynamic, address_tag)
            size = singleton_tag(dynamic, size_tag)
            if address is None or not size:
                continue
            for target, symbol_index, kind, addend in iter_relocations(elf, segments, address, size):
                check(kind in (257, 1025, 1026, 1027), f"{name} has unsupported relocation kind")
                check(writable_begin <= target <= writable_end - 8,
                      f"{name} relocation target is outside writable data")
                check(target not in slots, f"{name} has duplicate relocation targets")
                slots.add(target)
                if kind == 1027:
                    check(symbol_index == 0, f"{name} RELATIVE relocation has a symbol")
                    check(0 <= addend < image_ends[name],
                          f"{name} relative addend is outside its image")
                    check(bases[name] + addend < GUEST_WINDOW_SIZE,
                          f"{name} relative result exceeds the guest window")
                    counts["relative"] += 1
                    continue

                symbol = symbols.get(symbol_index)
                check(symbol is not None, f"{name} relocation symbol metadata is missing")
                provider_name: str | None
                provider_symbol: dict | None
                if symbol["defined"]:
                    provider_name, provider_symbol = name, symbol
                    counts["local_symbol"] += 1
                else:
                    resolved = selected.get(symbol["name"])
                    if resolved is None:
                        check(symbol["binding"] == 2,
                              f"{name} has an unresolved strong relocation")
                        provider_name = provider_symbol = None
                        counts["weak_zero"] += 1
                    else:
                        provider_name, provider_symbol = resolved
                        counts["cross_module"] += 1
                if provider_symbol is not None and provider_name is not None:
                    check(provider_symbol["value"] < image_ends[provider_name],
                          "resolved symbol lies outside provider image")
                    value = bases[provider_name] + provider_symbol["value"]
                    if kind != 1026:
                        value += addend
                    check(0 <= value < GUEST_WINDOW_SIZE,
                          f"{name} resolved relocation exceeds the guest window")
                    providers[provider_name] += 1
                counts["symbolic"] += 1

        planned = sum(counts[key] for key in ("relative", "symbolic"))
        check(planned == len(slots), f"{name} planner count mismatch")
        module_results.append({
            "module": name,
            "guest_offset": hex(bases[name]),
            "image_bytes": image_ends[name],
            "relocations_planned": planned,
            "relative": counts["relative"],
            "packed_relr": counts["relr"],
            "symbolic": counts["symbolic"],
            "local_symbol": counts["local_symbol"],
            "cross_module": counts["cross_module"],
            "weak_zero": counts["weak_zero"],
            "providers": {provider: providers[provider] for provider in order if providers[provider]},
        })

    return {
        "mode": "dry-run; no image writes",
        "module_order": list(order),
        "precedence": "first defined global/weak/unique export in module_order wins",
        "guest_window_bytes": GUEST_WINDOW_SIZE,
        "module_slot_bytes": MODULE_SLOT_SIZE,
        "selected_exports": {name: selected_counts[name] for name in order},
        "shadowed_exports": {name: shadowed_counts[name] for name in order},
        "non_addressable_exports": {name: non_addressable_counts[name] for name in order},
        "modules": module_results,
        "relocations_planned": sum(module["relocations_planned"] for module in module_results),
    }


def summarize_version(
    root: Path,
    label: str,
    modules: tuple[str, ...] = MODULES,
    resolution_order: tuple[str, ...] | None = None,
) -> dict:
    loaded = [load_module(root, module) for module in modules]
    if resolution_order is None:
        resolution_order = RESOLUTION_ORDER if modules == MODULES else modules
    export_counts: collections.Counter[str] = collections.Counter()
    for module in loaded:
        for symbol in module["exports_private"]:
            if symbol["binding"] in (1, 2, 10):
                export_counts[symbol["name"]] += 1

    result_modules = []
    total_strong_unresolved = 0
    total_weak_unresolved = 0
    for module in loaded:
        resolved = strong_unresolved = weak_unresolved = 0
        for symbol in module["imports_private"]:
            if export_counts[symbol["name"]]:
                resolved += 1
            elif symbol["binding"] == 2:
                weak_unresolved += 1
            else:
                strong_unresolved += 1
        summary = dict(module["summary"])
        summary.update({
            "imports_resolved_by_name": resolved,
            "imports_unresolved_strong": strong_unresolved,
            "imports_unresolved_weak": weak_unresolved,
        })
        result_modules.append(summary)
        total_strong_unresolved += strong_unresolved
        total_weak_unresolved += weak_unresolved

    return {
        "version": label,
        "modules": result_modules,
        "duplicate_export_names": sum(1 for count in export_counts.values() if count > 1),
        "unresolved_strong_imports": total_strong_unresolved,
        "unresolved_weak_imports": total_weak_unresolved,
        "relocation_plan": plan_version_relocations(loaded, resolution_order),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", required=True, metavar="LABEL=PRIVATE_ELF_DIR")
    parser.add_argument("--output", type=Path, default=Path("logs/nso-linkage-summary.json"))
    args = parser.parse_args()
    versions = []
    for item in args.version:
        check("=" in item, "--version must be LABEL=PATH")
        label, raw_path = item.split("=", 1)
        checked_name(label, "version label")
        root = Path(raw_path)
        check(root.is_dir(), f"missing private ELF directory for {label}")
        versions.append(summarize_version(root, label))
    report = {
        "format": 2,
        "status": "pass",
        "scope": "bounded NSO linkage inventory and no-write relocation plan",
        "private_names_recorded": False,
        "private_hashes_recorded": False,
        "versions": versions,
    }
    destination = args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    os.replace(temporary, destination)
    print(f"PASS: validated {len(versions)} version(s); sanitized report: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
