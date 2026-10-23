#!/usr/bin/env bash
set -euo pipefail

ROOT_POSIX=$(cd "$(dirname "$0")/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
    ROOT=$(cygpath -m "$ROOT_POSIX")
else
    ROOT=$ROOT_POSIX
fi
BUILD="$ROOT/build/host-tests"
mkdir -p "$BUILD"

g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -static-libgcc -static-libstdc++ \
    -I"$ROOT/android/src" \
    "$ROOT/android/src/relocation_stream.cpp" \
    "$ROOT/tests/relocation_stream_test.cpp" \
    -o "$BUILD/relocation_stream_test.exe"
"$BUILD/relocation_stream_test.exe" "$@"
