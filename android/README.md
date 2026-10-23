# Android ARM64 loader probe

This is the first bounded architecture experiment. It builds both an Android AArch64 PIE executable and a signed NativeActivity APK. It contains no game code and is not an emulator.

It reports and tests:

- process page size and pointer width;
- anonymous mapping and RW-to-RX permission transition;
- execution of two generated AArch64 instructions through the Android ABI;
- bounded AArch64 `ABS64`, `GLOB_DAT`, `JUMP_SLOT`, `RELATIVE` and packed RELR relocation into a synthetic four-page module;
- text/data/key/patch page sealing as RX/RW/R/RX, instruction-cache invalidation and execution from both code regions;
- fail-closed `/proc/self/maps` parsing and a non-committing 12.5 GiB guest-window reservation below the 39-bit VA limit;
- bounded ordered export lookup across two synthetic modules, followed by an absolute cross-module relocation and execution through the imported function pointer;
- replacement of owned `PROT_NONE` pages at `+0x100000` and `+0x200000` inside the 12.5 GiB reservation with fixed provider/consumer mappings, followed by the same relocation and execution path;
- non-destructive fixed-address reservations at representative Switch-like virtual addresses using `MAP_FIXED_NOREPLACE`;
- C++ exception/unwinding, thread-local storage isolation, pthreads and lock-free 64-bit atomics.

## Build

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
export ANDROID_HOME=/path/to/android-sdk

cmake -S android -B build/android-arm64 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/android-arm64 --verbose

# Reproducible ELF verification and signed no-Gradle APK packaging:
bash tools/build_android_probe.sh
bash tools/build_probe_apk.sh

# Host-native bounds/overflow tests for the portable relocation core:
bash tools/test_module_image.sh
bash tools/test_guest_window.sh
```

## Run on a real device

```bash
ADB=${ADB:-"$ANDROID_HOME/platform-tools/adb"}
"$ADB" push build/android-arm64/loader_probe /data/local/tmp/totk-loader-probe
"$ADB" shell chmod 755 /data/local/tmp/totk-loader-probe
"$ADB" shell /data/local/tmp/totk-loader-probe

# Preferred APK route (installs, runs and records properties/output):
bash tools/run_probe_android.sh [optional-adb-serial]
```

The APK is assembled directly with CMake/NDK, `aapt2`, `zipalign` and `apksigner`; it does not depend on Gradle. The NativeActivity writes `files/loader-probe.log`, which the run script retrieves through `run-as` because the app is a debug-only diagnostic.

The relocation core fails closed on invalid arguments, relocation slots outside the image or writable range, relative targets outside the image, arithmetic overflow and unknown relocation kinds. Host tests cover these cases without using proprietary bytes.

A cross-compiled/signed APK only verifies the toolchain, packaging and ELF contract. Physical-device results in this repository cover synthetic mapping, protection, execution and Vulkan presentation gates; they do not establish game-code execution, a game-generated frame or playability.
