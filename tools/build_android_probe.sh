#!/usr/bin/env bash
set -euo pipefail

ROOT_POSIX=$(cd "$(dirname "$0")/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
  ROOT=$(cygpath -m "$ROOT_POSIX")
else
  ROOT=$ROOT_POSIX
fi
NDK=${ANDROID_NDK_HOME:-}
CMAKE=${CMAKE:-cmake}
OUT="$ROOT/build/android-arm64"

if [[ -z "$NDK" ]]; then
  echo "ANDROID_NDK_HOME must point to an installed Android NDK" >&2
  exit 2
fi
if [[ ! -f "$NDK/build/cmake/android.toolchain.cmake" ]]; then
  echo "missing Android NDK toolchain: $NDK" >&2
  exit 2
fi
PREBUILT=$(find "$NDK/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -print -quit)
[[ -n "$PREBUILT" ]] || { echo "missing NDK LLVM prebuilt directory" >&2; exit 2; }
READELF="$PREBUILT/bin/llvm-readelf"
OBJDUMP="$PREBUILT/bin/llvm-objdump"
[[ -f "$READELF.exe" ]] && READELF="$READELF.exe"
[[ -f "$OBJDUMP.exe" ]] && OBJDUMP="$OBJDUMP.exe"
mkdir -p "$ROOT/logs"

"$CMAKE" -S "$ROOT/android" -B "$OUT" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-28 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
"$CMAKE" --build "$OUT" --clean-first --verbose 2>&1 | tee "$ROOT/logs/android-cross-build.log"
python "$ROOT/tools/audit_android_thread_registers.py" --objdump "$OBJDUMP" \
  --object-root "$OUT/CMakeFiles/loader_probe.dir/src" \
  --object-root "$OUT/CMakeFiles/loader_probe_app.dir/src" \
  | tee "$ROOT/logs/android-thread-register-audit.txt"
"$READELF" -h -l -d "$OUT/loader_probe" | tee "$ROOT/logs/android-loader-probe-elf.txt"
sha256sum "$OUT/loader_probe" | tee "$ROOT/logs/android-loader-probe-sha256.txt"

# Windows-hosted LLVM tools can emit CRLF. Keep committed evidence stable and
# whitespace-clean without changing the substantive output.
python - "$ROOT/logs/android-cross-build.log" "$ROOT/logs/android-loader-probe-elf.txt" \
    "$ROOT/logs/android-loader-probe-sha256.txt" \
    "$ROOT/logs/android-thread-register-audit.txt" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[1:]:
    path = Path(name)
    lines = path.read_text(encoding="utf-8").splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    path.write_bytes(("\n".join(line.rstrip() for line in lines) + "\n").encode("utf-8"))
PY

python - "$ROOT/logs/android-loader-probe-elf.txt" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
required = {
    "Machine:                           AArch64": "AArch64 machine",
    "Type:                              DYN": "PIE/DYN ELF",
    "Requesting program interpreter: /system/bin/linker64": "Android linker64",
    " R E 0x4000": "16 KiB-aligned executable LOAD",
}
missing = [label for needle, label in required.items() if needle not in text]
if missing:
    raise SystemExit("ELF verification failed: " + ", ".join(missing))
print("ELF verification PASS: AArch64 PIE, linker64, 16 KiB LOAD alignment")
PY
