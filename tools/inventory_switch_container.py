#!/usr/bin/env python
"""Bounded, read-only inventory of Switch PFS0 NSP and XCI/HFS0 containers.

This intentionally does not decrypt NCA content. It validates container bounds and
lists stored names/sizes without extracting or modifying the source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MAX_ENTRIES = 100_000
MAX_STRING_TABLE = 16 * 1024 * 1024
MAX_HEADER = 64 * 1024 * 1024
CHUNK = 1024 * 1024


class FormatError(ValueError):
    pass


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def read_exact(f: BinaryIO, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise FormatError("negative read range")
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise FormatError(f"short read at 0x{offset:x}: wanted {size}, got {len(data)}")
    return data


def checked_region(offset: int, size: int, limit: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise FormatError(f"{label} range 0x{offset:x}+0x{size:x} exceeds 0x{limit:x}")


def parse_name(table: bytes, offset: int) -> str:
    if offset >= len(table):
        raise FormatError(f"string offset {offset} outside table")
    end = table.find(b"\0", offset)
    if end < 0:
        raise FormatError("unterminated file name")
    raw = table[offset:end]
    if not raw or b"/" in raw or b"\\" in raw or raw in (b".", b".."):
        raise FormatError(f"unsafe/empty file name at string offset {offset}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError(f"invalid UTF-8 name at string offset {offset}") from exc


@dataclass(frozen=True)
class Region:
    offset: int
    size: int


def parse_partition(
    f: BinaryIO,
    region: Region,
    expected_magic: bytes | None = None,
    data_alignment: int = 1,
) -> dict:
    checked_region(region.offset, region.size, os.fstat(f.fileno()).st_size, "container")
    fixed = read_exact(f, region.offset, 16)
    magic = fixed[:4]
    if expected_magic is not None and magic != expected_magic:
        raise FormatError(f"expected {expected_magic!r} at 0x{region.offset:x}, got {magic!r}")
    if magic not in (b"PFS0", b"HFS0"):
        raise FormatError(f"unsupported magic {magic!r} at 0x{region.offset:x}")
    count, string_size, reserved = struct.unpack_from("<III", fixed, 4)
    if reserved != 0:
        raise FormatError(f"non-zero reserved header word: 0x{reserved:x}")
    if count > MAX_ENTRIES:
        raise FormatError(f"entry count {count} exceeds bound {MAX_ENTRIES}")
    if string_size > MAX_STRING_TABLE:
        raise FormatError(f"string table {string_size} exceeds bound {MAX_STRING_TABLE}")
    entry_size = 24 if magic == b"PFS0" else 64
    raw_header_size = 16 + count * entry_size + string_size
    if raw_header_size > MAX_HEADER or raw_header_size > region.size:
        raise FormatError(f"header size {raw_header_size} is invalid")
    header = read_exact(f, region.offset, raw_header_size)
    table_offset = 16 + count * entry_size
    strings = header[table_offset:table_offset + string_size]
    data_offset = align_up(raw_header_size, data_alignment)
    if data_offset > region.size:
        raise FormatError("aligned data offset exceeds container")

    files = []
    for index in range(count):
        pos = 16 + index * entry_size
        stored_offset, stored_size, name_offset = struct.unpack_from("<QQI", header, pos)
        checked_region(data_offset + stored_offset, stored_size, region.size, f"entry {index}")
        item = {
            "index": index,
            "name": parse_name(strings, name_offset),
            "size": stored_size,
            "absolute_offset": region.offset + data_offset + stored_offset,
        }
        if magic == b"HFS0":
            hashed_size = struct.unpack_from("<I", header, pos + 20)[0]
            reserved_entry = struct.unpack_from("<Q", header, pos + 24)[0]
            if hashed_size > stored_size or reserved_entry != 0:
                raise FormatError(f"invalid HFS0 metadata for entry {index}")
            item["hashed_size"] = hashed_size
            item["hash_sha256"] = header[pos + 32:pos + 64].hex()
        files.append(item)
    return {
        "format": magic.decode("ascii"),
        "offset": region.offset,
        "size": region.size,
        "header_size": raw_header_size,
        "data_offset": data_offset,
        "entry_count": count,
        "files": files,
    }


def quick_fingerprint(path: Path) -> str:
    size = path.stat().st_size
    h = hashlib.sha256()
    h.update(struct.pack("<Q", size))
    with path.open("rb") as f:
        h.update(f.read(CHUNK))
        if size > CHUNK:
            f.seek(max(CHUNK, size - CHUNK))
            h.update(f.read(CHUNK))
    return h.hexdigest()


def full_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(8 * CHUNK):
            h.update(block)
    return h.hexdigest()


def parse_cnmt_xml(f: BinaryIO, item: dict) -> dict:
    if item["size"] > 1024 * 1024:
        raise FormatError("CNMT XML exceeds 1 MiB bound")
    raw = read_exact(f, item["absolute_offset"], item["size"])
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise FormatError(f"invalid CNMT XML: {exc}") from exc
    if root.tag != "ContentMeta":
        raise FormatError(f"unexpected CNMT XML root {root.tag!r}")

    def text(name: str) -> str | None:
        node = root.find(name)
        return node.text.strip() if node is not None and node.text else None

    contents = []
    for node in root.findall("Content"):
        entry = {}
        for name in ("Type", "Id", "Size", "Hash", "KeyGeneration"):
            child = node.find(name)
            if child is not None and child.text:
                entry[name.lower()] = child.text.strip()
        contents.append(entry)
    return {
        "type": text("Type"),
        "id": text("Id"),
        "version": text("Version"),
        "original_id": text("OriginalId"),
        "required_system_version": text("RequiredSystemVersion"),
        "key_generation_min": text("KeyGenerationMin"),
        "contents": contents,
    }


def inventory(path: Path, include_sha256: bool = False) -> dict:
    stat = path.stat()
    result = {
        "schema": 1,
        "source": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "quick_fingerprint_sha256": quick_fingerprint(path),
    }
    if include_sha256:
        result["sha256"] = full_sha256(path)
    with path.open("rb") as f:
        magic0 = read_exact(f, 0, 4)
        if magic0 == b"PFS0":
            container = parse_partition(f, Region(0, stat.st_size), b"PFS0")
            result["container"] = container
            cnmt_xml = [item for item in container["files"] if item["name"].endswith(".cnmt.xml")]
            if len(cnmt_xml) > 1:
                raise FormatError("multiple CNMT XML files are outside this inventory subset")
            if cnmt_xml:
                result["content_meta"] = parse_cnmt_xml(f, cnmt_xml[0])
            return result
        xci_magic = read_exact(f, 0x100, 4) if stat.st_size >= 0x104 else b""
        if xci_magic != b"HEAD":
            raise FormatError(f"not PFS0 NSP or XCI HEAD: {magic0!r}/{xci_magic!r}")
        header = read_exact(f, 0x100, 0x70)
        root_offset, root_header_size = struct.unpack_from("<QQ", header, 0x30)
        checked_region(root_offset, root_header_size, stat.st_size, "XCI root header")
        root = parse_partition(f, Region(root_offset, stat.st_size - root_offset), b"HFS0", 0x200)
        partitions = {}
        for item in root["files"]:
            nested_region = Region(item["absolute_offset"], item["size"])
            nested_magic = read_exact(f, nested_region.offset, 4)
            if nested_magic == b"HFS0":
                partitions[item["name"]] = parse_partition(f, nested_region, b"HFS0", 0x200)
        result["xci"] = {
            "magic": "HEAD",
            "root_offset": root_offset,
            "declared_root_header_size": root_header_size,
            "root": root,
            "partitions": partitions,
        }
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", type=Path, dest="json_path")
    parser.add_argument("--sha256", action="store_true", help="read and hash the entire container")
    args = parser.parse_args(argv)
    try:
        data = inventory(args.path, args.sha256)
        rendered = json.dumps(data, indent=2, sort_keys=True)
        if args.json_path:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = args.json_path.with_suffix(args.json_path.suffix + ".tmp")
            tmp.write_bytes((rendered + "\n").encode("utf-8"))
            os.replace(tmp, args.json_path)
        print(rendered)
        return 0
    except (OSError, FormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
