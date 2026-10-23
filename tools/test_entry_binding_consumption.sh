#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"; mkdir -p build/host-tests
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -DENTRY_BINDING_READER_TESTING -DENTRY_BINDING_CONSUMPTION_TESTING -Iandroid/src \
  android/src/guest_startup_plan.cpp android/src/entry_binding_reader.cpp android/src/entry_binding_consumption.cpp \
  tests/entry_binding_consumption_test.cpp -o build/host-tests/entry_binding_consumption_test
build/host-tests/entry_binding_consumption_test
