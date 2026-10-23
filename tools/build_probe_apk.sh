#!/usr/bin/env bash
set -euo pipefail

ROOT_POSIX=$(cd "$(dirname "$0")/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
    ROOT=$(cygpath -m "$ROOT_POSIX")
else
    ROOT=$ROOT_POSIX
fi
SDK=${ANDROID_HOME:-}
NDK=${ANDROID_NDK_HOME:-}
BUILD="$ROOT/build/android-arm64"
APK="$ROOT/build/android-apk"
BUILD_TOOLS_VERSION=${ANDROID_BUILD_TOOLS_VERSION:-35.0.0}
ANDROID_PLATFORM_VERSION=${ANDROID_PLATFORM_VERSION:-35}
BT="$SDK/build-tools/$BUILD_TOOLS_VERSION"
ANDROID_JAR="$SDK/platforms/android-$ANDROID_PLATFORM_VERSION/android.jar"
KEYSTORE=${ANDROID_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}

[[ -n "$SDK" ]] || { echo "ANDROID_HOME must point to an Android SDK" >&2; exit 2; }
[[ -n "$NDK" ]] || { echo "ANDROID_NDK_HOME must point to an Android NDK" >&2; exit 2; }
PREBUILT=$(find "$NDK/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -print -quit)
[[ -n "$PREBUILT" ]] || { echo "missing NDK LLVM prebuilt directory" >&2; exit 2; }
READELF="$PREBUILT/bin/llvm-readelf"
OBJDUMP="$PREBUILT/bin/llvm-objdump"
[[ -f "$READELF.exe" ]] && READELF="$READELF.exe"
[[ -f "$OBJDUMP.exe" ]] && OBJDUMP="$OBJDUMP.exe"
AAPT2="$BT/aapt2"
ZIPALIGN="$BT/zipalign"
APKSIGNER="$BT/apksigner"
[[ -f "$AAPT2.exe" ]] && AAPT2="$AAPT2.exe"
[[ -f "$ZIPALIGN.exe" ]] && ZIPALIGN="$ZIPALIGN.exe"
[[ -f "$APKSIGNER.bat" ]] && APKSIGNER="$APKSIGNER.bat"
mkdir -p "$ROOT/logs"

for required in "$NDK/build/cmake/android.toolchain.cmake" "$AAPT2" \
                "$ZIPALIGN" "$APKSIGNER" "$ANDROID_JAR" "$KEYSTORE"; do
    [[ -e "$required" ]] || { echo "missing prerequisite: $required" >&2; exit 2; }
done

cmake -S "$ROOT/android" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
    -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$BUILD" --target loader_probe_app --clean-first --verbose \
    2>&1 | tee "$ROOT/logs/android-apk-native-build.log"
python "$ROOT/tools/audit_android_thread_registers.py" --objdump "$OBJDUMP" \
    --object-root "$BUILD/CMakeFiles/loader_probe_app.dir/src" \
    | tee "$ROOT/logs/android-apk-thread-register-audit.txt"

python - "$APK" "$BUILD/libloader_probe_app.so" <<'PY'
from pathlib import Path
import shutil, sys
out, library = map(Path, sys.argv[1:])
if out.exists():
    shutil.rmtree(out)
(out / "lib/arm64-v8a").mkdir(parents=True)
shutil.copy2(library, out / "lib/arm64-v8a/libloader_probe_app.so")
PY

"$AAPT2" link -o "$APK/base.apk" -I "$ANDROID_JAR" \
    --manifest "$ROOT/android/app/AndroidManifest.xml" \
    --min-sdk-version 28 --target-sdk-version 35
python - "$APK/base.apk" "$APK/lib/arm64-v8a/libloader_probe_app.so" <<'PY'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import sys
apk, library = map(Path, sys.argv[1:])
with ZipFile(apk, "a", compression=ZIP_DEFLATED, compresslevel=9) as archive:
    archive.write(library, "lib/arm64-v8a/libloader_probe_app.so")
PY
"$ZIPALIGN" -f -p 4 "$APK/base.apk" "$APK/aligned.apk"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --out "$APK/loader-probe.apk" "$APK/aligned.apk"
"$APKSIGNER" verify --verbose --print-certs "$APK/loader-probe.apk" \
    | tee "$ROOT/logs/android-apk-signature.txt"
sha256sum "$APK/loader-probe.apk" | tee "$ROOT/logs/android-apk-sha256.txt"
"$AAPT2" dump badging "$APK/loader-probe.apk" \
    | tee "$ROOT/logs/android-apk-badging.txt"
"$ZIPALIGN" -c -v 4 "$APK/loader-probe.apk" \
    | tee "$ROOT/logs/android-apk-zipalign.txt"
"$READELF" -h -l -d "$APK/lib/arm64-v8a/libloader_probe_app.so" \
    | tee "$ROOT/logs/android-apk-native-elf.txt"
"$READELF" -Ws "$APK/lib/arm64-v8a/libloader_probe_app.so" \
    | grep 'GLOBAL.*ANativeActivity_onCreate' >/dev/null || {
        echo "NativeActivity entry point is not exported" >&2
        exit 1
    }

python - "$ROOT/logs/android-apk-native-build.log" "$ROOT/logs/android-apk-signature.txt" \
    "$ROOT/logs/android-apk-sha256.txt" "$ROOT/logs/android-apk-badging.txt" \
    "$ROOT/logs/android-apk-zipalign.txt" "$ROOT/logs/android-apk-native-elf.txt" \
    "$ROOT/logs/android-apk-thread-register-audit.txt" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[1:]:
    path = Path(name)
    lines = path.read_text(encoding="utf-8").splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    path.write_bytes(("\n".join(line.rstrip() for line in lines) + "\n").encode("utf-8"))
PY
echo "APK: $APK/loader-probe.apk"