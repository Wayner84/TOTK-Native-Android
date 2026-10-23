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

g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 \
    -I"$ROOT/android/src" \
    "$ROOT/android/src/private_elf.cpp" \
    "$ROOT/tests/private_elf_test.cpp" \
    -o "$BUILD/private_elf_test.exe"
"$BUILD/private_elf_test.exe"
