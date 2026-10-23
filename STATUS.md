# Project status

Updated: 2026-10-23

## Bottom line

This is a strong Android runtime and loader prototype, not a playable TOTK port. The project has not executed a real game entry point and has not rendered a game-generated frame.

Estimated progress toward a title screen: **about 10%**.

## Verified milestones

- A signed NativeActivity diagnostic APK builds for Android ARM64 with 16 KiB-compatible load alignment.
- A physical Android ARM64 device has passed the bounded Vulkan surface/device, swapchain and synthetic-clear gates.
- Verified private 1.4.3 `main`, `subsdk0` and `sdk` analysis carriers can be mapped together as nine non-executable segments.
- A name-free relocation stream containing 554,281 records can be validated and applied transactionally; an injected 277,140-write failure rolls back completely.
- Private module, relocation and binding identities are checked before staging and again at device/application boundaries.
- Mappings remain read-only/non-executable and no private entry point is called.
- Bionic VM queries, signal/ucontext handling, guest x18/TLS ownership, guarded stack switching and host-service callback transitions have physical and portable coverage.
- Private inputs are removed from temporary and app-internal staging after every verified run.

## Current automated checks

- Python: **104/104**.
- Module image: **23/23**.
- Guest window: **13/13**.
- VM query: **19/19**.
- Signal context: **20/20**.
- Guest thread/stack context: **65/65**.
- Startup plan: **56/56**.
- Entry-binding reader: **86/86**.
- Entry-binding consumption: **121/121**.
- Relocation stream: **53/53** synthetic/portable checks, plus private validate-only checks performed locally.
- Vulkan policy/lifecycle: **59/59**.

Public CI exercises only non-proprietary fixtures and host tests.

## Major remaining stages

1. Execute one tightly bounded real leaf entry with deterministic fault/return handling.
2. Implement enough Horizon services, threading and IPC to advance startup.
3. Port the required TOTK NVN/Maxwell semantics to Vulkan.
4. Translate and validate shaders on mobile GPUs.
5. Add audio, input, save, movie, storage and lifecycle support.
6. Measure memory pressure, thermals and performance on multiple Android devices.

## Current risks

- Bionic ABI, TLS, signal and exception differences from Horizon/Darwin.
- Breadth and timing sensitivity of Switch OS services.
- NVN/Maxwell translation and mobile Vulkan driver behaviour.
- Memory footprint and thermal throttling before a first frame exists.
- Exact coupling to supported game versions and private rewrite metadata.

See [ROADMAP.md](ROADMAP.md) for contribution areas and sequencing.