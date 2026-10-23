#!/usr/bin/env python3
"""Build and validate a bounded, name-free real-relocation stream.

The input is a private directory of hash-verified NSO analysis carriers. The
output is also private: it contains proprietary-derived relocation geometry and
must never be committed. Records are normalized, externally sorted in bounded
chunks, validated without modifying any mapped image, and atomically written.
"""
from __future__ import annotations

import argparse
import heapq
import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

import summarize_nso_linkage as linkage

MAGIC = b"TOTKRLP1"
FORMAT_VERSION = 1
HEADER = struct.Struct("<8sIIIIQQQQQ")
MODULE = struct.Struct("<IIQQQQQ")
RECORD = struct.Struct("<QIBBHQq")
SOURCE_RELA = 1
SOURCE_RELR = 2
NO_PROVIDER = 0xFF
SUPPORTED_KINDS = frozenset((257, 1025, 1026, 1027))
DEFAULT_CHUNK_RECORDS = 8192
MAX_MODULES = 16
MAX_MERGE_FAN_IN = 64


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def add_signed(base: int, addend: int) -> int:
    value = base + addend
    check(0 <= value < linkage.GUEST_WINDOW_SIZE, "resolved relocation result exceeds guest window")
    return value


def prepare_context(loaded: list[dict], order: tuple[str, ...]) -> dict:
    check(0 < len(order) <= MAX_MODULES, "module count is out of range")
    check(len(set(order)) == len(order), "module order contains duplicates")
    by_name = {module["module"]: module for module in loaded}
    check(len(by_name) == len(loaded), "loaded module names are duplicated")
    check(all(name in by_name for name in order), "module order references a missing module")

    bases: dict[str, int] = {}
    image_ends: dict[str, int] = {}
    module_ids = {name: index for index, name in enumerate(order)}
    for index, name in enumerate(order):
        image_end = max(segment["address"] + segment["size"] + segment["extra"]
                        for segment in by_name[name]["segments_private"])
        check(0 < image_end <= linkage.MODULE_SLOT_SIZE, f"{name} exceeds its guest slot")
        base = linkage.MODULE_LAYOUT_START + index * linkage.MODULE_SLOT_SIZE
        check(base + image_end <= linkage.GUEST_WINDOW_SIZE, f"{name} exceeds guest window")
        bases[name] = base
        image_ends[name] = image_end

    selected: dict[str, tuple[str, dict]] = {}
    for name in order:
        for symbol in by_name[name]["exports_private"]:
            if symbol["binding"] not in (1, 2, 10) or symbol["value"] >= image_ends[name]:
                continue
            selected.setdefault(symbol["name"], (name, symbol))

    return {
        "by_name": by_name,
        "bases": bases,
        "image_ends": image_ends,
        "module_ids": module_ids,
        "selected": selected,
    }


def iter_module_records(name: str, context: dict) -> Iterator[tuple[int, int, int, int, int, int]]:
    module = context["by_name"][name]
    module_id = context["module_ids"][name]
    segments = module["segments_private"]
    dynamic = module["dynamic_private"]
    elf = module["elf_private"]
    symbols = module["symbols_by_index_private"]
    image_end = context["image_ends"][name]
    writable_begin = segments[2]["address"]
    writable_end = writable_begin + segments[2]["size"] + segments[2]["extra"]

    def validate_target(target: int) -> None:
        check(target % 8 == 0, f"{name} relocation target is unaligned")
        check(writable_begin <= target <= writable_end - 8,
              f"{name} relocation target is outside writable data")

    relr_address = linkage.singleton_tag(dynamic, linkage.DT_RELR)
    relr_size = linkage.singleton_tag(dynamic, linkage.DT_RELRSZ)
    if relr_address is not None and relr_size:
        for target in linkage.iter_relr_targets(elf, segments, relr_address, relr_size):
            validate_target(target)
            addend = linkage.read_virtual_u64(module, target)
            check(addend < image_end, f"{name} RELR addend is outside its image")
            add_signed(context["bases"][name], addend)
            yield target, 1027, SOURCE_RELR, module_id, 0, addend

    for address_tag, size_tag in ((linkage.DT_RELA, linkage.DT_RELASZ),
                                  (linkage.DT_JMPREL, linkage.DT_PLTRELSZ)):
        address = linkage.singleton_tag(dynamic, address_tag)
        size = linkage.singleton_tag(dynamic, size_tag)
        if address is None or not size:
            continue
        for target, symbol_index, kind, addend in linkage.iter_relocations(
                elf, segments, address, size):
            check(kind in SUPPORTED_KINDS, f"{name} has unsupported relocation kind")
            validate_target(target)
            if kind == 1027:
                check(symbol_index == 0, f"{name} RELATIVE relocation has a symbol")
                check(0 <= addend < image_end, f"{name} relative addend is outside its image")
                add_signed(context["bases"][name], addend)
                yield target, kind, SOURCE_RELA, module_id, 0, addend
                continue

            symbol = symbols.get(symbol_index)
            check(symbol is not None, f"{name} relocation symbol metadata is missing")
            if symbol["defined"]:
                provider_name, provider_symbol = name, symbol
            else:
                resolved = context["selected"].get(symbol["name"])
                if resolved is None:
                    check(symbol["binding"] == 2,
                          f"{name} has an unresolved strong relocation")
                    provider_name = None
                    provider_symbol = None
                else:
                    provider_name, provider_symbol = resolved

            if provider_symbol is None or provider_name is None:
                provider_id = NO_PROVIDER
                symbol_value = 0
                base_value = 0
            else:
                provider_id = context["module_ids"][provider_name]
                symbol_value = provider_symbol["value"]
                check(symbol_value < context["image_ends"][provider_name],
                      "resolved symbol lies outside provider image")
                base_value = context["bases"][provider_name] + symbol_value

            # AArch64 JUMP_SLOT resolves to S; its ELF addend is not applied.
            canonical_addend = 0 if kind == 1026 else addend
            add_signed(base_value, canonical_addend)
            yield target, kind, SOURCE_RELA, provider_id, symbol_value, canonical_addend


def write_chunk(path: Path, records: list[tuple[int, int, int, int, int, int]]) -> None:
    records.sort(key=lambda row: row[0])
    with path.open("wb") as output:
        for target, kind, source, provider, symbol_value, addend in records:
            output.write(RECORD.pack(target, kind, source, provider, 0, symbol_value, addend))


def iter_chunk(path: Path) -> Iterator[tuple[int, int, int, int, int, int]]:
    with path.open("rb") as source:
        while True:
            raw = source.read(RECORD.size)
            if not raw:
                return
            check(len(raw) == RECORD.size, "temporary relocation chunk is truncated")
            target, kind, origin, provider, reserved, symbol_value, addend = RECORD.unpack(raw)
            check(reserved == 0, "temporary relocation chunk has nonzero reserved field")
            yield target, kind, origin, provider, symbol_value, addend


def stage_sorted_chunks(records: Iterable[tuple[int, int, int, int, int, int]],
                        directory: Path, prefix: str, chunk_records: int) -> tuple[list[Path], int]:
    check(0 < chunk_records <= linkage.MAX_RELOCATIONS, "chunk record bound is invalid")
    paths: list[Path] = []
    batch: list[tuple[int, int, int, int, int, int]] = []
    count = 0
    for record in records:
        check(count < linkage.MAX_RELOCATIONS, "relocation count exceeds bound")
        batch.append(record)
        count += 1
        if len(batch) == chunk_records:
            path = directory / f"{prefix}-{len(paths):06d}.bin"
            write_chunk(path, batch)
            paths.append(path)
            batch = []
    if batch:
        path = directory / f"{prefix}-{len(paths):06d}.bin"
        write_chunk(path, batch)
        paths.append(path)
    return paths, count


def merge_chunks(paths: list[Path]) -> Iterator[tuple[int, int, int, int, int, int]]:
    if not paths:
        return
    yield from heapq.merge(*(iter_chunk(path) for path in paths), key=lambda row: row[0])


def reduce_chunk_fan_in(paths: list[Path], directory: Path, prefix: str) -> list[Path]:
    """Merge in bounded passes so hostile chunk sizes cannot exhaust descriptors."""
    generation = 0
    current = paths
    while len(current) > MAX_MERGE_FAN_IN:
        reduced: list[Path] = []
        for begin in range(0, len(current), MAX_MERGE_FAN_IN):
            group = current[begin:begin + MAX_MERGE_FAN_IN]
            destination = directory / f"{prefix}-merge-{generation:03d}-{len(reduced):06d}.bin"
            with destination.open("wb") as output:
                for target, kind, origin, provider, symbol_value, addend in merge_chunks(group):
                    output.write(RECORD.pack(
                        target, kind, origin, provider, 0, symbol_value, addend))
            reduced.append(destination)
        for path in current:
            path.unlink()
        current = reduced
        generation += 1
    return current


def module_descriptor(module_id: int, name: str, context: dict, count: int) -> tuple[int, ...]:
    segments = context["by_name"][name]["segments_private"]
    writable_begin = segments[2]["address"]
    writable_end = writable_begin + segments[2]["size"] + segments[2]["extra"]
    return (module_id, 0, context["bases"][name], context["image_ends"][name],
            writable_begin, writable_end, count)


def build_stream(loaded: list[dict], order: tuple[str, ...], output: Path,
                 chunk_records: int = DEFAULT_CHUNK_RECORDS) -> dict:
    context = prepare_context(loaded, order)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptors: list[tuple[int, ...]] = []
    staged: list[tuple[list[Path], int]] = []
    with tempfile.TemporaryDirectory(prefix="relocation-stream-", dir=output.parent) as temporary:
        temp_dir = Path(temporary)
        for module_id, name in enumerate(order):
            chunks, count = stage_sorted_chunks(
                iter_module_records(name, context), temp_dir, f"module-{module_id}", chunk_records)
            chunks = reduce_chunk_fan_in(chunks, temp_dir, f"module-{module_id}")
            staged.append((chunks, count))
            descriptors.append(module_descriptor(module_id, name, context, count))

        total = sum(count for _chunks, count in staged)
        check(total <= linkage.MAX_RELOCATIONS * len(order), "total relocation count exceeds bound")
        temporary_output = temp_dir / "relocation-stream.bin"
        with temporary_output.open("wb") as destination:
            destination.write(HEADER.pack(
                MAGIC, FORMAT_VERSION, HEADER.size, MODULE.size, RECORD.size,
                len(order), total, linkage.GUEST_WINDOW_SIZE,
                linkage.MODULE_SLOT_SIZE, linkage.MODULE_LAYOUT_START))
            for descriptor in descriptors:
                destination.write(MODULE.pack(*descriptor))
            for module_id, (chunks, expected_count) in enumerate(staged):
                previous_target: int | None = None
                emitted = 0
                for record in merge_chunks(chunks):
                    target = record[0]
                    check(previous_target is None or target > previous_target,
                          f"module {module_id} has duplicate relocation targets")
                    previous_target = target
                    destination.write(RECORD.pack(
                        record[0], record[1], record[2], record[3], 0,
                        record[4], record[5]))
                    emitted += 1
                check(emitted == expected_count, "merged relocation count mismatch")
            destination.flush()
            os.fsync(destination.fileno())
        # Validate before replacement so a producer defect cannot destroy the
        # last known-good private stream. The second pass verifies the rename.
        validate_stream(temporary_output)
        os.replace(temporary_output, output)

    summary = validate_stream(output)
    summary["chunk_records"] = chunk_records
    return summary


def read_exact(source: BinaryIO, size: int, label: str) -> bytes:
    value = source.read(size)
    check(len(value) == size, f"truncated {label}")
    return value


def validate_stream(path: Path) -> dict:
    size = path.stat().st_size
    check(HEADER.size + MODULE.size <= size <= 512 * 1024 * 1024,
          "relocation stream size is out of range")
    with path.open("rb") as source:
        fields = HEADER.unpack(read_exact(source, HEADER.size, "relocation stream header"))
        (magic, version, header_size, module_size, record_size, module_count,
         record_count, guest_window, slot_size, layout_start) = fields
        check(magic == MAGIC and version == FORMAT_VERSION, "unsupported relocation stream format")
        check(header_size == HEADER.size and module_size == MODULE.size and record_size == RECORD.size,
              "relocation stream structure sizes are invalid")
        check(0 < module_count <= MAX_MODULES, "relocation stream module count is invalid")
        check(record_count <= linkage.MAX_RELOCATIONS * module_count,
              "relocation stream record count exceeds bound")
        check(guest_window == linkage.GUEST_WINDOW_SIZE and slot_size == linkage.MODULE_SLOT_SIZE and
              layout_start == linkage.MODULE_LAYOUT_START,
              "relocation stream layout constants are incompatible")
        expected_size = HEADER.size + module_count * MODULE.size + record_count * RECORD.size
        check(size == expected_size, "relocation stream is truncated or has trailing data")

        descriptors = []
        descriptor_total = 0
        for expected_id in range(module_count):
            descriptor = MODULE.unpack(read_exact(source, MODULE.size, f"module {expected_id} descriptor"))
            module_id, reserved, guest_offset, image_size, writable_begin, writable_end, count = descriptor
            check(module_id == expected_id and reserved == 0, "module descriptor identity is invalid")
            check(guest_offset == layout_start + module_id * slot_size,
                  "module guest offset is invalid")
            check(0 < image_size <= slot_size and guest_offset + image_size <= guest_window,
                  "module image geometry is invalid")
            check(writable_begin <= writable_end <= image_size and writable_end - writable_begin >= 8,
                  "module writable geometry is invalid")
            check(count <= linkage.MAX_RELOCATIONS, "module relocation count exceeds bound")
            descriptor_total += count
            descriptors.append(descriptor)
        check(descriptor_total == record_count, "module counts do not match header")

        kind_counts: dict[int, int] = {}
        source_counts: dict[int, int] = {}
        for module_id, descriptor in enumerate(descriptors):
            _id, _reserved, _base, image_size, writable_begin, writable_end, count = descriptor
            previous_target: int | None = None
            for index in range(count):
                raw = read_exact(source, RECORD.size, f"module {module_id} record {index}")
                target, kind, origin, provider, reserved, symbol_value, addend = RECORD.unpack(raw)
                check(reserved == 0, f"module {module_id} record has nonzero reserved field")
                check(kind in SUPPORTED_KINDS, f"module {module_id} record has unsupported kind")
                check(origin in (SOURCE_RELA, SOURCE_RELR),
                      f"module {module_id} record has unsupported source")
                check(target % 8 == 0 and writable_begin <= target <= writable_end - 8,
                      f"module {module_id} record target is invalid")
                check(previous_target is None or target > previous_target,
                      f"module {module_id} records are duplicated or unsorted")
                previous_target = target

                if kind == 1027:
                    check(provider == module_id and symbol_value == 0,
                          f"module {module_id} relative record operands are invalid")
                    check(0 <= addend < image_size,
                          f"module {module_id} relative addend is invalid")
                    add_signed(descriptors[module_id][2], addend)
                else:
                    check(origin == SOURCE_RELA, f"module {module_id} symbolic record source is invalid")
                    check(provider == NO_PROVIDER or provider < module_count,
                          f"module {module_id} provider is invalid")
                    if provider == NO_PROVIDER:
                        check(symbol_value == 0, f"module {module_id} weak-zero symbol value is invalid")
                        provider_base = 0
                    else:
                        check(symbol_value < descriptors[provider][3],
                              f"module {module_id} symbol value is outside provider image")
                        provider_base = descriptors[provider][2] + symbol_value
                    check(kind != 1026 or addend == 0,
                          f"module {module_id} JUMP_SLOT addend is noncanonical")
                    add_signed(provider_base, addend)
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
                source_counts[origin] = source_counts.get(origin, 0) + 1
        check(source.read(1) == b"", "relocation stream has trailing data")

    return {
        "format": FORMAT_VERSION,
        "modules": module_count,
        "descriptors": descriptors,
        "records": record_count,
        "bytes": size,
        "kind_counts": {str(kind): kind_counts[kind] for kind in sorted(kind_counts)},
        "source_counts": {
            "rela": source_counts.get(SOURCE_RELA, 0),
            "relr": source_counts.get(SOURCE_RELR, 0),
        },
        "private_names_recorded": False,
        "mapped_bytes_modified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="private analysis-carrier directory")
    parser.add_argument("--output", type=Path, required=True, help="private output stream path")
    parser.add_argument("--chunk-records", type=int, default=DEFAULT_CHUNK_RECORDS)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    if args.validate_only:
        summary = validate_stream(args.output)
    else:
        check(args.input.is_dir(), "private analysis-carrier directory is missing")
        check(any(part.lower() == "private" for part in args.output.parts),
              "derived relocation stream output must remain under a private path")
        loaded = [linkage.load_module(args.input, module) for module in linkage.MODULES]
        summary = build_stream(loaded, linkage.RESOLUTION_ORDER, args.output, args.chunk_records)
    print("PASS: relocation stream " + ", ".join(f"{key}={value}" for key, value in summary.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
