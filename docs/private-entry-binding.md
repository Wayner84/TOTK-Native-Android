# Private 1.4.3 entry binding

The ignored `private/entry-bindings/v143.entry-binding.json` is a deterministic, host-private identity binding for the three persistent modules in the fixed order `main`, `subsdk0`, `sdk`. It is not an execution or mapping claim.

The schema uses exact key sets, canonical one-line JSON, lowercase SHA-256 fields, bounded integer geometry, a single top-level `entries` object, numeric contiguous provider IDs, and a self-digest over the payload excluding `self_digest`. Module records carry carrier identity and loaded image/writable geometry; entry records carry provider ID and module-relative offset.

Build mode requires exactly the manifest, relocation stream, input directory, and output path. The manifest has exactly three module rows followed by exactly one relocation row. The builder validates the live relocation-stream descriptors (including order, guest offset, image and writable bounds), carrier size/SHA, dynamic singleton metadata, constructor instruction masks/range, and exact symbol definition/provider/range/alignment. It writes atomically, fsyncs the output, fsyncs the containing directory where the host supports directory fsync, and rereads the output through the strict validator.

Validate-only mode requires only `--binding` and never rewrites. Twenty-one focused synthetic/adversarial tests cover schema, canonical framing, first-definition/provider rules, initialized-writable metadata, stream/carrier mismatch rejection and atomic cleanup. The separate binary reader passes 86/86 checks and live admission/consumption passes 121/121. A guarded five-role physical-device run mapped and relocated verified private copies without execution, consumed the binding once, proved transactional rollback, sealed read-only/non-executable, and removed all ten staged paths. Private execution remains pending.

No private paths, addresses, offsets, bytes, symbol names, or digests belong in tracked evidence.
