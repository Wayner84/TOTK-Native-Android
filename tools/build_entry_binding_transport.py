#!/usr/bin/env python3
"""Build and validate the deterministic fixed-width entry-binding transport."""
from __future__ import annotations
import argparse, hashlib, os, struct, tempfile
from pathlib import Path
from build_entry_binding import read, validate, canonical

MAGIC = b"TOTK-EBT"
FORMAT_VERSION = 1
MODULE_ORDER = ("main", "subsdk0", "sdk")
MODULE_IDS = {name: i for i, name in enumerate(MODULE_ORDER)}
ENTRY_NAMES = ("nn_init_start", "nn_main")
DIGEST_SIZE = 32
HEADER_FORMAT = "<8sHHII32s32s32s32s12s"
MODULE_FORMAT = "<BBHQQQQQQQQ32s32s44s"
ENTRY_FORMAT = "<BBH Q 16s 8s".replace(" ", "")
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MODULE_SIZE = struct.calcsize(MODULE_FORMAT)
ENTRY_SIZE = struct.calcsize(ENTRY_FORMAT)
PAYLOAD_SIZE = HEADER_SIZE + len(MODULE_ORDER) * MODULE_SIZE + len(ENTRY_NAMES) * ENTRY_SIZE
TOTAL_SIZE = PAYLOAD_SIZE + DIGEST_SIZE
ZERO32 = b"\0" * 32
HEADER_IDENTITY_OFFSET = struct.calcsize("<8sHHII32s32s32s")
MODULE_CARRIER_DIGEST_OFFSET = struct.calcsize("<BBH" + "Q" * 8)
ENTRY_PROVIDER_POLICY = {"nn_init_start": 2, "nn_main": 0}


def _fail(message):
    raise ValueError(message)


def _digest_hex(value, label):
    if not isinstance(value, str) or len(value) != 64:
        _fail(label)
    try:
        out = bytes.fromhex(value)
    except ValueError:
        _fail(label)
    if len(out) != DIGEST_SIZE or out == ZERO32:
        _fail(label)
    return out


def _u64(value, label):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        _fail(label)
    return value


def _end(offset, size, label):
    _u64(offset, label); _u64(size, label)
    if size > 0xFFFFFFFFFFFFFFFF - offset:
        _fail(label)
    return offset + size


def pack(doc):
    """Encode an already-authoritatively-validated canonical binding."""
    validate(doc)
    buf = bytearray(TOTAL_SIZE)
    struct.pack_into(HEADER_FORMAT, buf, 0, MAGIC, FORMAT_VERSION, 0,
                     len(MODULE_ORDER), TOTAL_SIZE,
                     _digest_hex(doc["trusted_manifest_sha256"], "manifest digest"),
                     _digest_hex(doc["relocation_stream_sha256"], "relocation digest"),
                     _digest_hex(doc["self_digest"], "source digest"),
                     hashlib.sha256(canonical(doc)).digest(), b"\0" * 12)
    for index, module in enumerate(doc["modules"]):
        ia = module["init_array"]
        ioff, isize = (0, 0) if ia is None else (ia["offset"], ia["size"])
        struct.pack_into(MODULE_FORMAT, buf, HEADER_SIZE + index * MODULE_SIZE,
                         index, MODULE_IDS[module["module"]], 0,
                         *(_u64(module[k], k) for k in ("image_size", "writable_begin", "writable_size", "dt_init", "ctor_flag")),
                         _u64(ioff, "init-array offset"), _u64(isize, "init-array size"),
                         _u64(module["carrier_size"], "carrier size"),
                         _digest_hex(module["carrier_sha256"], "carrier digest"),
                         ZERO32, b"\0" * 44)
    for index, name in enumerate(ENTRY_NAMES):
        entry = doc["entries"][name]
        struct.pack_into(ENTRY_FORMAT, buf, HEADER_SIZE + len(MODULE_ORDER) * MODULE_SIZE + index * ENTRY_SIZE,
                         entry["provider_id"], 0, 0, entry["offset"],
                         b"verified-elf\0\0\0\0", b"\0" * 8)
    buf[PAYLOAD_SIZE:] = hashlib.sha256(buf[:PAYLOAD_SIZE]).digest()
    return bytes(buf)


def validate_bytes(raw):
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        _fail("transport bytes")
    raw = bytes(raw)
    if len(raw) != TOTAL_SIZE:
        _fail("exact transport length")
    if hashlib.sha256(raw[:PAYLOAD_SIZE]).digest() != raw[PAYLOAD_SIZE:]:
        _fail("transport digest")
    magic, version, reserved, count, total, manifest, relocation, source, _identity, header_reserved = struct.unpack_from(HEADER_FORMAT, raw)
    if magic != MAGIC or version != FORMAT_VERSION or reserved != 0 or count != len(MODULE_ORDER) or total != TOTAL_SIZE:
        _fail("header")
    if header_reserved != b"\0" * 12 or any(x == ZERO32 for x in (manifest, relocation, source, _identity)):
        _fail("header identity")
    modules = []
    for i in range(3):
        fields = struct.unpack_from(MODULE_FORMAT, raw, HEADER_SIZE + i * MODULE_SIZE)
        role, module_id, reserved, image, wb, ws, dt, ctor, iaoff, iasz, carrier_size, carrier_digest, reloc_identity, tail = fields
        if role != i or module_id != i or reserved or tail != b"\0" * 44 or reloc_identity != ZERO32:
            _fail("module identity/reserved")
        if any(x == ZERO32 for x in (carrier_digest,)) or image == 0 or carrier_size == 0 or ws == 0:
            _fail("module identity/size")
        if _end(wb, ws, "writable range") > image or dt == 0 or dt % 4 or dt >= image or ctor % 4 or not wb <= ctor < wb + ws:
            _fail("module geometry")
        if (iaoff, iasz) == (0, 0):
            pass
        elif iaoff == 0 or iasz == 0 or iaoff % 8 or iasz % 8 or _end(iaoff, iasz, "init-array range") > image:
            _fail("init-array geometry")
        modules.append((image, wb, ws, dt, ctor, iaoff, iasz))
    base = HEADER_SIZE + 3 * MODULE_SIZE
    for i in range(2):
        provider, reserved1, reserved2, offset, identity, tail = struct.unpack_from(ENTRY_FORMAT, raw, base + i * ENTRY_SIZE)
        if provider >= 3 or reserved1 or reserved2 or identity != b"verified-elf\0\0\0\0" or tail != b"\0" * 8 or offset == 0 or offset % 4 or offset >= modules[provider][0]:
            _fail("entry provider/range")
    if tuple(struct.unpack_from(ENTRY_FORMAT, raw, base + i * ENTRY_SIZE)[0] for i in range(2)) != (2, 0):
        _fail("entry order")
    # The transport must preserve the authoritative provider policy and the
    # representable metadata/entry alias constraints.
    entries = []
    for i, name in enumerate(ENTRY_NAMES):
        provider, _, _, offset, _, _ = struct.unpack_from(ENTRY_FORMAT, raw, base + i * ENTRY_SIZE)
        image, wb, ws, dt, ctor, iaoff, iasz = modules[provider]
        if provider != ENTRY_PROVIDER_POLICY[name]:
            _fail("entry provider policy")
        if offset in (dt, ctor) or (iasz and iaoff <= offset < iaoff + iasz):
            _fail("entry metadata alias")
        entries.append((provider, offset))
    if entries[0] == entries[1]:
        _fail("entry distinction")
    return True


def build(binding, output):
    doc = read(binding)
    raw = pack(doc)
    validate_bytes(raw)
    path = Path(output); path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        validate_bytes(path.read_bytes())
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    if args.validate_only:
        if args.output is not None: parser.error("--output is invalid with --validate-only")
        if args.binding.suffix.lower() in (".bin", ".transport"):
            validate_bytes(args.binding.read_bytes())
        else:
            read(args.binding)
    else:
        if args.output is None: parser.error("--output is required unless --validate-only")
        build(args.binding, args.output)
    print("PASS: entry-binding transport validated; modules=3 entries=2 mapped=false executed=false")


if __name__ == "__main__":
    main()
