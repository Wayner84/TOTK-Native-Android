# TOTK Native Android

Experimental Android ARM64 compatibility-runtime research for **The Legend of Zelda: Tears of the Kingdom**.

> **Current state: infrastructure prototype, not a playable port.**
> No game code is executed yet and no game-generated frame has been rendered.

The project investigates whether owner-supplied Switch game modules can run directly on Android ARM64 through a narrow Bionic/Horizon compatibility layer and an eventual NVN-to-Vulkan graphics implementation. It is not an emulator frontend, streaming client, ROM distribution or finished game.

## Verified today

- Android ARM64 NativeActivity probe and signed diagnostic APK.
- Bounded guest address-space reservation and module mapping.
- Three private 1.4.3 modules can be identity-checked, mapped and relocated transactionally on a physical Android device without executing them.
- Relocation rollback, mapping protections and private staging cleanup are verified.
- Bionic signal/ucontext, guest x18/TLS ownership and guarded guest-stack transitions have fail-closed tests.
- Vulkan surface/device selection, swapchain acquire/present and one synthetic clear have been physically verified.
- 104 Python tests and the native host contract suites pass.

## Not implemented

- Real TOTK entry-point execution.
- Horizon service coverage sufficient to start the game.
- NVN/Maxwell-to-Vulkan rendering or shader translation.
- Audio, input, save, movie and Android lifecycle integration for the game.
- A title screen, game-generated frame or playable build.

The current estimate is roughly **10% of the work required to reach a title screen**. Graphics and operating-system services dominate the remaining risk.

## Repository boundary

This repository contains original project code, tests, public documentation and pinned open-source references. It contains **no ROMs, keys, firmware, tickets, certificates, saves, Nintendo binaries, extracted assets or generated game-derived code**.

All contributors must keep those materials outside Git. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Clone and test

```bash
git clone --recurse-submodules https://github.com/Wayner84/TOTK-Native-Android.git
cd TOTK-Native-Android
python -m unittest discover -s tests -v
```

The host-native contract tests require Bash and a C++20 compiler:

```bash
for test in \
  tools/test_module_image.sh \
  tools/test_guest_window.sh \
  tools/test_vm_query.sh \
  tools/test_signal_context.sh \
  tools/test_guest_thread_context.sh \
  tools/test_guest_startup_plan.sh \
  tools/test_entry_binding_reader.sh \
  tools/test_entry_binding_consumption.sh \
  tools/test_relocation_stream.sh; do
  bash "$test"
done
```

## Android probe

Install CMake, Ninja and an Android NDK, then set `ANDROID_NDK_HOME`:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
bash tools/build_android_probe.sh
```

Building the APK additionally requires `ANDROID_HOME` and a standard Android debug keystore:

```bash
export ANDROID_HOME=/path/to/android-sdk
bash tools/build_probe_apk.sh
```

These commands build a synthetic diagnostic probe only. They do not build or package TOTK.

## Where help is useful

- Bionic-safe direct AArch64 execution boundaries.
- Horizon service and IPC implementations.
- NVN/Maxwell command, resource and synchronization research.
- Vulkan and mobile-driver portability, especially Adreno, Mali and Xclipse.
- Maxwell shader translation.
- Android input, audio, storage and lifecycle integration.
- Reproducible public CI and non-proprietary test fixtures.
- Independent review of fail-closed parsers and loaders.

Read [STATUS.md](STATUS.md), [ROADMAP.md](ROADMAP.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Legal and trademark notice

This is an independent, non-commercial interoperability and preservation research project. It is not affiliated with, sponsored by or endorsed by Nintendo. Nintendo, Nintendo Switch, The Legend of Zelda and related marks belong to their respective owners.

You must provide and privately handle any game files you are legally entitled to use. Do not upload proprietary material to this repository, issues, pull requests, CI artifacts or releases.

Project-authored code is licensed under the [MIT License](LICENSE). Third-party submodules retain their own licences and notices.