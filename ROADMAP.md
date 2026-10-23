# Roadmap to a playable Android build

Updated: 2026-10-23

## A. Module loading — advanced prototype

Completed for the current private 1.4.3 research inputs:

- bounded ELF64/AArch64 inspection;
- deterministic guest-window placement;
- three-module mapping;
- validated, name-free relocation streams;
- transactional relocation and rollback;
- strict identity binding;
- non-executable sealing and cleanup.

Remaining: turn the private preparation workflow into a documented, user-local and reproducible pipeline without publishing generated game material.

## B. Safe game-code execution — early

Synthetic ARM64 code, ABI calls, guest/host stack transitions, x18/TLS ownership and fault-related context handling are verified.

Next gates:

1. Select a bounded leaf entry with known inputs and an explicit completion condition.
2. Forbid constructors and unbounded `nnMain` execution initially.
3. Stop deterministically on every unknown host call, fault or completion state.
4. Preserve a no-private-input regression path for CI.

## C. Horizon services — research

Required work includes:

- service dispatch and IPC;
- memory and handle semantics;
- events, timers and synchronization;
- filesystems and save paths;
- threads and scheduling boundaries;
- audio, input and movie services.

This stage is broad and likely to require several contributors working from clearly scoped service contracts.

## D. Graphics — research and highest risk

The Android Vulkan foundation and one synthetic present/clear work. No TOTK graphics command has reached the backend.

Required work includes:

- NVN command/resource semantics;
- Maxwell shader translation;
- texture and format handling;
- descriptors, barriers and synchronization;
- compute support;
- render-target and presentation integration;
- Adreno, Mali and Xclipse validation.

The first game-generated frame is the next major graphics proof point.

## E. Platform integration — planned

- Controller and touch input.
- Audio output and timing.
- Storage Access Framework import flow.
- Saves and user configuration.
- Android lifecycle, pause/resume and surface recreation.
- Thermal and memory-pressure handling.

## F. Performance and compatibility — unknown

The current work proves address-space and bounded runtime mechanisms, not playability. Frame rate, RAM use, shader compilation, storage overhead and sustained thermals remain unknown until real startup and graphics work exist.

## Contribution priorities

Good first areas for experienced contributors:

1. Improve portable build detection and CI.
2. Add non-proprietary adversarial fixtures for parsers and mapping contracts.
3. Review Bionic signal/TLS/stack assumptions.
4. Document Horizon services required by early TOTK startup.
5. Build isolated NVN/Vulkan conformance tests using synthetic commands.
6. Add device capability reporting that contains no personal identifiers.