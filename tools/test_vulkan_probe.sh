#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cygpath -m "$(cd "$(dirname "$0")/.." && pwd)")
mkdir -p "$ROOT/build/host-tests"
c++ -std=c++20 -Wall -Wextra -Werror -I"$ROOT/android/src" "$ROOT/tests/vulkan_probe_test.cpp" "$ROOT/android/src/vulkan_probe.cpp" -o "$ROOT/build/host-tests/vulkan_probe_test"
"$ROOT/build/host-tests/vulkan_probe_test"
