#!/usr/bin/env bash
set -euo pipefail
ROOT_POSIX=$(cd "$(dirname "$0")/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
  ROOT=$(cygpath -m "$ROOT_POSIX")
else
  ROOT=$ROOT_POSIX
fi
mkdir -p "$ROOT/build/host-tests"
c++ -std=c++20 -Wall -Wextra -Werror -I"$ROOT/android/src" "$ROOT/tests/vulkan_probe_test.cpp" "$ROOT/android/src/vulkan_probe.cpp" -o "$ROOT/build/host-tests/vulkan_probe_test"
"$ROOT/build/host-tests/vulkan_probe_test"
