# Bounded relocation stream format v1

`tools/build_relocation_stream.py` converts the validated private NSO planner inputs into a fixed-width, name-free relocation stream. The stream remains private and Git-ignored: it contains proprietary-derived offsets and must not be committed or embedded in a public APK.

## Purpose and boundary

- Carry normalized real relocation operands from the private metadata planner to a future portable loader.
- Keep memory and open-file use bounded while handling more than 500,000 records: the producer uses configurable sorted chunks (8,192 records by default) and multi-pass external merges with at most 64 inputs per pass.
- Validate every record without writing to mapped module bytes.
- Preserve the proven module order `main`, `subsdk0`, `sdk` and first-definition symbol precedence.
- Keep relocation application and guest execution outside this milestone.

All integers are little-endian and all structures are fixed width. Files must have an exact expected length; trailing or truncated data is rejected.

## Header (64 bytes)

Format: `<8sIIIIQQQQQ>`

- Magic: `TOTKRLP1`
- Format version: `1`
- Header, module-descriptor and record sizes
- Module count and total record count
- Guest-window size, module-slot size and layout-start offset

## Module descriptor (48 bytes each)

Format: `<IIQQQQQ>`

- Sequential module ID and a zero reserved field
- Guest-window offset and image size
- Writable-segment begin/end offsets
- Record count for the module

Descriptors contain no module names. Module IDs correspond to the documented fixed order.

## Relocation record (32 bytes each)

Format: `<QIBBHQq>`

- Target image offset (`u64`)
- AArch64 relocation kind (`u32`): `ABS64`, `GLOB_DAT`, `JUMP_SLOT` or `RELATIVE`
- Source (`u8`): RELA or decoded RELR
- Provider module ID (`u8`), or `255` for an unresolved weak symbol that resolves to zero
- Zero reserved field (`u16`)
- Provider-relative symbol value (`u64`)
- Signed addend (`i64`)

Records are grouped by module and strictly sorted by target. Duplicate slots are rejected during the external merge and again by the independent reader. `JUMP_SLOT` addends are canonicalized to zero because AArch64 `JUMP_SLOT` resolves to `S`. RELR records are decoded into ordinary `RELATIVE` records after reading their in-image addends, but no image bytes are changed.

## Private entry binding

The strict private 1.4.3 entry-binding milestone is documented in [`private-entry-binding.md`](private-entry-binding.md). The binding consumes these stream descriptors and does not imply mapping or execution.

## Validation

The reader rejects:

- incompatible magic/version/structure sizes or layout constants;
- oversized module/record counts, truncation or trailing bytes;
- invalid module geometry;
- unsupported kinds/sources or nonzero reserved fields;
- unaligned, unsorted, duplicate or non-writable targets;
- invalid providers, out-of-image symbols, noncanonical `JUMP_SLOT` addends;
- relative or symbolic arithmetic outside the guest window.

Build and validate a private stream:

```bash
python tools/build_relocation_stream.py \
  --input private/extracted/v143/elf \
  --output private/relocations/v143.bin \
  --chunk-records 8192

python tools/build_relocation_stream.py \
  --input private/extracted/v143/elf \
  --output private/relocations/v143.bin \
  --validate-only
```

Run adversarial fixtures:

```bash
python -m unittest discover -s tests -p 'test_build_relocation_stream.py' -v
```
