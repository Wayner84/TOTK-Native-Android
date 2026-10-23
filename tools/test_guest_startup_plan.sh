#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"; mkdir -p build/host-tests
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -Iandroid/src android/src/guest_startup_plan.cpp tests/guest_startup_plan_test.cpp -o build/host-tests/guest_startup_plan_test
build/host-tests/guest_startup_plan_test
printf 'guest startup plan: PASS\n'
