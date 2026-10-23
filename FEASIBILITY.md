# Feasibility assessment

Updated: 2026-10-18

## Verdict

A native Android ARM64 result is technically plausible, but remains a high-risk, multi-stage engineering project. Two complementary demonstrations now exist: `ly05010419/MacNativeGames` runs TOTK 1.0.0/1.1.2/1.4.3 original AArch64 code natively on Apple silicon through verified rewrites and a small Horizon/NVN-on-Metal host; `mamcjr/LASRecompAndroid` runs another first-party Switch title on Android ARM64 with native gameplay and NVN-to-Vulkan. Neither alone is the requested Android TOTK result, but together they substantially reduce the CPU/runtime and Android-platform unknowns.

## Components worth reusing

- **MacNativeGames TOTK runtime**: exact 1.4.3 manifests and patches, NSO rewriter, direct AArch64 loader/relocator, TOTK-specific Horizon services, threads/TLS/exceptions/atomics handling, audio/input/save/movie paths, and a mature TOTK NVN command implementation currently backed by Metal.
- **LASRecomp generator/runtime**: AArch64-to-C lifter, NSO tooling, Horizon kernel/IPC/services and NVN/Maxwell-to-Vulkan renderer for comparison and fallback blocks.
- **LASRecompAndroid**: Android APK/activity, dynamic guest-window placement below the 39-bit VA ceiling, on-device game-code build, SDL input/audio, Vulkan driver probing, Adreno Turnip loading, fallback GPU arena, Android lifecycle/storage and real-device performance instrumentation.
- **Switch emulator projects**: reference implementations for missing services, formats and GPU behavior only where licences are compatible; no emulator frontend or unexamined wholesale import.
- **Android NDK/CMake**: native ARM64 PIE build, 16 KiB-compatible load segments and direct device diagnostics.

## Largest unknowns

1. Porting MacNativeGames' Darwin-specific loader/TLS/signal/thread adaptations to Bionic without invalidating its site-by-site rewrite guarantees.
2. Replacing its Metal 4 backend with Vulkan while preserving the already-covered TOTK NVN command/resource semantics.
3. Maxwell shader translation and mobile Vulkan driver behavior for TOTK's shaders, synchronisation, compute and memory model.
4. Memory and storage footprint under real game startup; synthetic device probes do not establish sustained RAM or thermal requirements.
5. Version coupling: supplied base and patch must be extracted and analysed as an exact, reproducible pair.

## Android-specific constraints

- ARM64 instruction compatibility does not imply ABI or process compatibility. Guest code assumes Horizon layout, TLS, exception ABI, services, thread scheduling and memory semantics.
- Android devices may use 4 KiB or 16 KiB pages; binaries and guest mappings must tolerate both. Android 15+ increasingly requires 16 KiB-compatible native libraries.
- A 39-bit application VA ceiling and existing app mappings constrain the guest window. Dynamic no-replace placement must be measured on the target.
- Mobile Vulkan features, texture formats, subgroup behavior, buffer device addresses and vendor extensions differ. Adreno/Turnip, Qualcomm proprietary, Mali and Xclipse need separate evidence.
- Android storage access, background lifecycle, thermal throttling and memory pressure are part of correctness, not packaging details.

## Proposed architecture

### Primary — direct AArch64 execution plus a narrow compatibility runtime

Port the pinned MacNativeGames TOTK runtime to Android: apply its verified, bounded rewrites to the exact private 1.4.3 modules; map/relocate original AArch64 code; adapt x18/TLS, signals, exceptions, atomics, threads and host gates to Bionic; retain its TOTK-specific Horizon services; and replace the Metal host with a Vulkan path informed by LASRecompAndroid and compatible emulator references. Keep game-derived rewritten modules private and out of repository/releases.

Why primary: direct execution is already demonstrated for this exact game and supplied update version on another ARM64 OS, including 1.4.3-specific rewrites/services/graphics coverage. Android ARM64 still requires explicit adaptation; shared ISA is not treated as binary compatibility.

### Fallback — static recompilation/translation

Adapt LASRecompAndroid's AArch64-to-C/inline-AArch64 pipeline for modules or instruction windows that cannot be executed safely under Bionic, while retaining the same TOTK service/graphics boundary. CPU interpretation or dynamic translation, if introduced for unsupported blocks, must be disclosed.

Readable-source decompilation is a supporting analysis tool, not the critical path.

## First architecture experiment

1. Cross-compile a 16 KiB-aligned Android ARM64 PIE that tests RW→RX generated AArch64 execution, ABI calls, fixed no-replace mappings, page size, TLS, pthreads, atomics and C++ exceptions.
2. Build/adapt LASRecompAndroid's APK probe to measure the actual target's 39-bit guest-window holes and Vulkan capabilities.
3. Run both on the actual phone and preserve output. The approach is invalidated or revised if no suitably large guest window can be reserved, executable mappings are prohibited, required Vulkan features have no viable fallback, or memory limits are clearly insufficient.

## Current evidence boundary

The custom native probe cross-build is verified; its ELF is an AArch64 PIE with 0x4000-aligned load segments. Synthetic loader, thread-context and Vulkan presentation gates have run on a physical Android ARM64 device. These results do not establish game-code execution, a TOTK-generated frame, playability, sustained memory use or performance.
