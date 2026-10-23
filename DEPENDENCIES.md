# Dependencies

## Pinned source dependencies/references

### MacNativeGames (primary TOTK reference/runtime)

- Purpose: exact TOTK 1.0.0/1.1.2/1.4.3 direct-AArch64 rewrite pipeline, loader, Horizon host, services, audio/input/save/movie paths and NVN graphics implementation.
- URL: https://github.com/ly05010419/MacNativeGames
- Pin: `41e1e0caf43d58c4af3c478ca2d1bafd9dba7093` (2026-10-18).
- Licence: MIT project code; third-party notices apply. Its copied D2R rewriter is pinned to `jhaizhou-ops/d2r-mobile` `9f0c25768ac4b231c6f4cb0a9f182ded68d0e7cf` under MIT with documented local changes.
- Local form: Git submodule `third_party/MacNativeGames`; no local changes.
- Compatibility note: production path is macOS/Metal and contains Darwin APIs. Android/Bionic/Vulkan adaptation is required; the repository does not provide an Android build.

### LASRecomp

- Purpose: upstream AArch64-to-C static recompiler, NSO tooling, Horizon runtime, NVN/Maxwell renderer and shader translator.
- URL: https://github.com/peiikai/LASRecomp
- Pin: `09f8e5ebf28aeefd6daa1456c73ae1b7a51efec5` (2026-10-18).
- Licence: MIT for project code; bundled third parties retain their own licences, including GPL helper programs. See upstream `README.md` and `LICENSE`.
- Local form: Git submodule `third_party/LASRecomp`; no local changes.
- Compatibility note: built specifically for Link's Awakening v1.0.0; reusable architecture is not evidence of TOTK instruction/service/renderer coverage.

### LASRecompAndroid

- Purpose: demonstrated Android ARM64 port architecture, APK/activity, guest-window placement, on-device game-code build, Vulkan probes/driver paths, lifecycle, touch/controller and performance work.
- URL: https://github.com/mamcjr/LASRecompAndroid
- Pin: `cbe10d9ba1919da0715ae5baad9d537fb4ae6da6` / preview 0.3.4 (2026-10-18).
- Licence: MIT for project code; third-party licences recorded upstream.
- Nested pin: `bylaws/libadrenotools` `8fae8ce254dfc1344527e05301e43f37dea2df80` (BSD-2-Clause upstream), including `liblinkernsbypass` `aa3975893d83ef1bc84c321ec60c65fbf1287887`.
- Local form: Git submodule `third_party/LASRecompAndroid`; no local changes.
- Compatibility note: real gameplay is reported for Link's Awakening on Android 16/Adreno and experimental Mali; TOTK remains untested and materially more demanding.

### Android NDK r28c

- Purpose: first standalone ARM64 loader-probe cross-build.
- Official archive: https://dl.google.com/android/repository/android-ndk-r28c-windows.zip
- Version: `28.2.13676358`; configured through `ANDROID_NDK_HOME`.
- Integrity: official repository SHA-1 `086bba43ff2f5eb0e387b15c8278bb4e0d89ba1d`; local SHA-256 `6bec98ac2354d8a919760889a1a41d020132e5e8cfa1b1fe51610a72c36a466b`.
- Licence: Android SDK/NDK licence files in the installed distribution; LLVM components use their bundled notices.
- Local changes: none.

### SuperMarioWonderRecomp

- Purpose: second working Android ARM64/NVN-to-Vulkan precedent, including NativeActivity packaging, guest address-space handling, Vulkan presentation, touch/lifecycle integration and measured phone memory/performance diagnostics.
- URL: https://github.com/BelmanteGu/SuperMarioWonderRecomp
- Pin: `ec62e6c34e175e6246bd83daa5c8686a522f7f2f` (2026-10-18).
- Licence: MIT for project code; bundled assets and third parties retain their own notices.
- Local form: Git submodule `third_party/SuperMarioWonderRecomp`; no local changes.
- Compatibility note: upstream reports Super Mario Bros. Wonder gameplay on a Galaxy S23, not TOTK. Reuse only audited platform/runtime patterns; this is supporting evidence rather than the primary TOTK runtime.

### Android probe toolchain additions

- Android NDK r30 `30.0.16248370`, official `android-ndk-r30-windows.zip`: repository SHA-1 `9bf167a1985fa7d4a036186b78f702eab9179408`; local SHA-256 `b830098aaf18b67a42eb831c404e15e5f2990a474f054ac145b0bc957ac6d729`.
- CMake 3.30.4 Windows x86-64: official/local SHA-256 `cd7363aab96a33237b8913024201863ed218000a0535f3bc9cc6519325416dee`.
- Gradle 8.14.3 binary distribution: official/local SHA-256 `bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531`.
- Purpose: reproduce LASRecompAndroid's pinned Android probe build requirements. Local installation paths are intentionally not recorded in the public repository.
- Result: tool distributions verified; Android Gradle plugin 8.13.0 dependency resolution failed over Java networking, so no APK was claimed. See `logs/lasrecomp-android-probe-build.log`.

### REA/Ghidra private-analysis tooling

- Purpose: evidence-backed, read-only function and native-binary investigation of owner-supplied analysis carriers; analysis output is advisory and must be independently verified before implementation.
- Catalogue lead: https://github.com/AIshihzong/awesome-reverse-engineer-anything, pin `31f300ccbed2f217b4e70cdb9d104b5a0670275f`, CC0.
- Official REA: https://github.com/morluto/rea, inspected pin `32f0e5120966be59d17a1e092353816c76a9c5e2`, MIT.
- Container integration: https://github.com/alexmi256/rea-agent-docker, inspected pin `e584319eb69a841535726112717274eb09c0d45b`, MIT; deployed Ghidra-only image digest is recorded in `logs/rea-analysis-summary.json`.
- Runtime versions: REA 6.5.0, Ghidra 12.1.4, JDK 21, isolated Linux/amd64 container. Private targets are read-only mounts; raw Evidence and snapshots stay outside Git.
- Verification: `rea doctor --provider ghidra --json` reports the selected provider healthy. The first default whole-program overview timed out after 30 minutes and produced no claimed snapshot; use narrower operations for subsequent analysis.

For every future dependency record:

- Name and purpose
- Upstream URL
- Pinned commit/tag and retrieval date
- Licence and attribution obligations
- Compatibility rationale
- Local changes and why
- Verification command/result

Do not vendor emulator-scale code until its exact role, licence and integration boundary are understood.
