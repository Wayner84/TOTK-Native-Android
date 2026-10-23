#!/usr/bin/env bash
set -euo pipefail

ROOT_POSIX=$(cd "$(dirname "$0")/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
    ROOT=$(cygpath -m "$ROOT_POSIX")
else
    ROOT=$ROOT_POSIX
fi
if [[ -z "${ADB:-}" ]]; then
    [[ -n "${ANDROID_HOME:-}" ]] || {
        echo "set ADB or ANDROID_HOME before running the device probe" >&2
        exit 2
    }
    ADB="$ANDROID_HOME/platform-tools/adb"
    [[ -f "$ADB.exe" ]] && ADB="$ADB.exe"
fi
mkdir -p "$ROOT/logs"
APK="$ROOT/build/android-apk/loader-probe.apk"
PACKAGE=com.townsendprecision.totkloaderprobe
if [[ $# -ne 0 && $# -ne 1 && $# -ne 6 ]]; then
    echo "usage: $0 [serial [main-carrier subsdk0-carrier sdk-carrier relocation-stream entry-binding]]" >&2
    exit 2
fi
SERIAL=${1:-}
PRIVATE_MODULES=()
PRIVATE_RELOCATIONS=
PRIVATE_ENTRY_BINDING=
PRIVATE_MANIFEST=${PRIVATE_PROBE_MANIFEST:-$ROOT/private/verified-v143-device-manifest.tsv}
PRIVATE_BINDING_SOURCE=${PRIVATE_BINDING_SOURCE:-$ROOT/private/entry-bindings/v143.entry-binding.json}
MODULE_ROLES=(main subsdk0 sdk)
if [[ $# -eq 6 ]]; then
    PRIVATE_MODULES=("$2" "$3" "$4")
    PRIVATE_RELOCATIONS=$5
    PRIVATE_ENTRY_BINDING=$6
fi
REMOTE_MODULES=(
    /data/local/tmp/totk-private-module-0.elf
    /data/local/tmp/totk-private-module-1.elf
    /data/local/tmp/totk-private-module-2.elf
)
INTERNAL_MODULES=(
    files/private-module-0.elf
    files/private-module-1.elf
    files/private-module-2.elf
)
RELOCATIONS_REMOTE=/data/local/tmp/totk-private-relocations.bin
BINDING_REMOTE=/data/local/tmp/totk-entry-binding.bin
ADB_ARGS=()
if [[ -n "$SERIAL" ]]; then ADB_ARGS=(-s "$SERIAL"); fi
DEVICE_READY=0
STAGING_REQUIRED=0
declare -A TRUSTED_HASH=()
declare -A TRUSTED_SIZE=()
TRUSTED_BINDING_HASH=
TRUSTED_BINDING_SIZE=
EXPECTED_BINDING_TEMP=
if [[ ${#PRIVATE_MODULES[@]} -ne 0 || -n "$PRIVATE_RELOCATIONS" || -n "$PRIVATE_ENTRY_BINDING" ]]; then
    STAGING_REQUIRED=1
fi

cleanup_private() {
    [[ $DEVICE_READY -eq 1 ]] || return 0
    local failed=0
    "$ADB" "${ADB_ARGS[@]}" shell rm -f \
        "${REMOTE_MODULES[@]}" "$RELOCATIONS_REMOTE" "$BINDING_REMOTE" >/dev/null 2>&1 || failed=1
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" rm -f \
        "${INTERNAL_MODULES[@]}" files/private-relocations.bin files/entry-binding.bin >/dev/null 2>&1 || failed=1
    for remote in "${REMOTE_MODULES[@]}" "$RELOCATIONS_REMOTE" "$BINDING_REMOTE"; do
        "$ADB" "${ADB_ARGS[@]}" shell test ! -e "$remote" >/dev/null 2>&1 || failed=1
    done
    for internal in "${INTERNAL_MODULES[@]}" files/private-relocations.bin files/entry-binding.bin; do
        "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" test ! -e "$internal" \
            >/dev/null 2>&1 || failed=1
    done
    return "$failed"
}

on_exit() {
    local original_status=$?
    trap - EXIT
    [[ -z "$EXPECTED_BINDING_TEMP" ]] || rm -f "$EXPECTED_BINDING_TEMP"
    if ! cleanup_private; then
        echo "ERROR: private staging cleanup or absence verification failed" >&2
        [[ $original_status -ne 0 ]] || original_status=1
    fi
    exit "$original_status"
}
trap on_exit EXIT

verify_private_manifest() {
    [[ $STAGING_REQUIRED -eq 1 ]] || return 0
    [[ -f "$PRIVATE_MANIFEST" ]] || {
        echo "missing private trusted manifest; set PRIVATE_PROBE_MANIFEST or create the canonical ignored manifest" >&2
        return 2
    }
    TRUSTED_HASH=()
    TRUSTED_SIZE=()
    local role size digest extra
    while IFS=$'\t' read -r role size digest extra || [[ -n "$role$size$digest$extra" ]]; do
        [[ -n "$role" && -z "$extra" && "$size" =~ ^[0-9]+$ &&
           "$digest" =~ ^[0-9a-f]{64}$ ]] || {
            echo "invalid private trusted manifest record" >&2
            return 2
        }
        case "$role" in main|subsdk0|sdk|relocations) ;; *)
            echo "unexpected role in private trusted manifest" >&2
            return 2
        esac
        [[ -z "${TRUSTED_HASH[$role]+set}" ]] || {
            echo "duplicate role in private trusted manifest" >&2
            return 2
        }
        TRUSTED_SIZE[$role]=$size
        TRUSTED_HASH[$role]=$digest
    done < "$PRIVATE_MANIFEST"
    [[ ${#TRUSTED_HASH[@]} -eq 4 ]] || {
        echo "private trusted manifest must contain exactly four roles" >&2
        return 2
    }
    local roles=("${MODULE_ROLES[@]}")
    local files=("${PRIVATE_MODULES[@]}")
    files+=("$PRIVATE_RELOCATIONS")
    roles+=(relocations)
    local index file actual_size actual_hash
    for index in "${!roles[@]}"; do
        role=${roles[$index]}
        file=${files[$index]}
        [[ -f "$file" ]] || { echo "private probe input not found role=$role" >&2; return 2; }
        actual_size=$(stat -c '%s' "$file")
        actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
        [[ "$actual_size" == "${TRUSTED_SIZE[$role]}" &&
           "$actual_hash" == "${TRUSTED_HASH[$role]}" ]] || {
            echo "private probe input identity mismatch role=$role" >&2
            return 1
        }
    done
    [[ -f "$PRIVATE_BINDING_SOURCE" && -f "$PRIVATE_ENTRY_BINDING" ]] || {
        echo "private entry-binding source or transport not found" >&2
        return 2
    }
    mkdir -p "$ROOT/build/private-staging"
    EXPECTED_BINDING_TEMP=$(mktemp "$ROOT/build/private-staging/entry-binding.XXXXXX.bin")
    python "$ROOT/tools/build_entry_binding_transport.py" \
        --binding "$PRIVATE_BINDING_SOURCE" --output "$EXPECTED_BINDING_TEMP" >/dev/null
    python "$ROOT/tools/build_entry_binding_transport.py" \
        --binding "$PRIVATE_ENTRY_BINDING" --validate-only >/dev/null
    cmp -s "$EXPECTED_BINDING_TEMP" "$PRIVATE_ENTRY_BINDING" || {
        echo "private entry-binding transport differs from canonical source" >&2
        return 1
    }
    TRUSTED_BINDING_SIZE=$(stat -c '%s' "$EXPECTED_BINDING_TEMP")
    TRUSTED_BINDING_HASH=$(sha256sum "$EXPECTED_BINDING_TEMP" | cut -d' ' -f1)
    echo "private trusted identity manifest PASS roles=5 version=1.4.3"
}

[[ -f "$APK" ]] || { echo "missing APK; run bash tools/build_probe_apk.sh" >&2; exit 2; }
verify_private_manifest
"$ADB" "${ADB_ARGS[@]}" get-state >/dev/null
DEVICE_READY=1
"$ADB" "${ADB_ARGS[@]}" install -r "$APK"
"$ADB" "${ADB_ARGS[@]}" shell rm -f "${REMOTE_MODULES[@]}" "$RELOCATIONS_REMOTE" "$BINDING_REMOTE"
"$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" rm -f \
    "${INTERNAL_MODULES[@]}" files/private-relocations.bin files/entry-binding.bin

for index in "${!PRIVATE_MODULES[@]}"; do
    carrier=${PRIVATE_MODULES[$index]}
    remote=${REMOTE_MODULES[$index]}
    internal=${INTERNAL_MODULES[$index]}
    [[ -f "$carrier" ]] || { echo "private carrier not found" >&2; exit 2; }
    host_hash=$(sha256sum "$carrier" | cut -d' ' -f1)
    host_size=$(stat -c '%s' "$carrier")
    trusted_hash=${TRUSTED_HASH[${MODULE_ROLES[$index]}]}
    trusted_size=${TRUSTED_SIZE[${MODULE_ROLES[$index]}]}
    [[ "$host_hash" == "$trusted_hash" && "$host_size" == "$trusted_size" ]] || {
        echo "private carrier changed after trusted identity verification" >&2
        exit 1
    }
    "$ADB" "${ADB_ARGS[@]}" push "$carrier" "$remote" >/dev/null
    device_hash=$("$ADB" "${ADB_ARGS[@]}" shell sha256sum "$remote" | tr -d '\r' | cut -d' ' -f1)
    [[ "$device_hash" == "$trusted_hash" ]] || { echo "private carrier trusted/device digest mismatch" >&2; exit 1; }
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" mkdir -p files
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" cp "$remote" "$internal"
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" chmod 600 "$internal"
    internal_hash=$("$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" sha256sum "$internal" | tr -d '\r' | cut -d' ' -f1)
    "$ADB" "${ADB_ARGS[@]}" shell rm -f "$remote"
    [[ "$internal_hash" == "$trusted_hash" ]] || { echo "private carrier trusted/internal-copy digest mismatch" >&2; exit 1; }
    echo "private carrier staging parity PASS index=$index bytes=$host_size"
done

if [[ -n "$PRIVATE_RELOCATIONS" ]]; then
    [[ -f "$PRIVATE_RELOCATIONS" ]] || { echo "private relocation stream not found" >&2; exit 2; }
    host_hash=$(sha256sum "$PRIVATE_RELOCATIONS" | cut -d' ' -f1)
    host_size=$(stat -c '%s' "$PRIVATE_RELOCATIONS")
    trusted_hash=${TRUSTED_HASH[relocations]}
    trusted_size=${TRUSTED_SIZE[relocations]}
    [[ "$host_hash" == "$trusted_hash" && "$host_size" == "$trusted_size" ]] || {
        echo "private relocation stream changed after trusted identity verification" >&2
        exit 1
    }
    "$ADB" "${ADB_ARGS[@]}" push "$PRIVATE_RELOCATIONS" "$RELOCATIONS_REMOTE" >/dev/null
    device_hash=$("$ADB" "${ADB_ARGS[@]}" shell sha256sum "$RELOCATIONS_REMOTE" | tr -d '\r' | cut -d' ' -f1)
    [[ "$device_hash" == "$trusted_hash" ]] || { echo "private relocation stream trusted/device digest mismatch" >&2; exit 1; }
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" mkdir -p files
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" cp \
        "$RELOCATIONS_REMOTE" files/private-relocations.bin
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" chmod 600 files/private-relocations.bin
    internal_hash=$("$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" \
        sha256sum files/private-relocations.bin | tr -d '\r' | cut -d' ' -f1)
    "$ADB" "${ADB_ARGS[@]}" shell rm -f "$RELOCATIONS_REMOTE"
    [[ "$internal_hash" == "$trusted_hash" ]] || { echo "private relocation stream trusted/internal-copy digest mismatch" >&2; exit 1; }
    echo "private relocation stream staging parity PASS bytes=$host_size"
fi

if [[ -n "$PRIVATE_ENTRY_BINDING" ]]; then
    host_hash=$(sha256sum "$PRIVATE_ENTRY_BINDING" | cut -d' ' -f1)
    host_size=$(stat -c '%s' "$PRIVATE_ENTRY_BINDING")
    [[ "$host_hash" == "$TRUSTED_BINDING_HASH" && "$host_size" == "$TRUSTED_BINDING_SIZE" ]] || {
        echo "private entry-binding changed after canonical verification" >&2
        exit 1
    }
    "$ADB" "${ADB_ARGS[@]}" push "$PRIVATE_ENTRY_BINDING" "$BINDING_REMOTE" >/dev/null
    device_hash=$("$ADB" "${ADB_ARGS[@]}" shell sha256sum "$BINDING_REMOTE" | tr -d '\r' | cut -d' ' -f1)
    [[ "$device_hash" == "$TRUSTED_BINDING_HASH" ]] || { echo "private entry-binding trusted/device digest mismatch" >&2; exit 1; }
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" mkdir -p files
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" cp "$BINDING_REMOTE" files/entry-binding.bin
    "$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" chmod 600 files/entry-binding.bin
    internal_hash=$("$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" sha256sum files/entry-binding.bin | tr -d '\r' | cut -d' ' -f1)
    "$ADB" "${ADB_ARGS[@]}" shell rm -f "$BINDING_REMOTE"
    [[ "$internal_hash" == "$TRUSTED_BINDING_HASH" ]] || { echo "private entry-binding trusted/internal-copy digest mismatch" >&2; exit 1; }
    echo "private entry-binding staging parity PASS bytes=$host_size"
fi

"$ADB" "${ADB_ARGS[@]}" logcat -c
"$ADB" "${ADB_ARGS[@]}" shell am force-stop "$PACKAGE"
"$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" rm -f files/loader-probe.log
"$ADB" "${ADB_ARGS[@]}" shell am start -n "$PACKAGE/android.app.NativeActivity"
PROBE_OUTPUT=
for _attempt in $(seq 1 60); do
    PROBE_OUTPUT=$("$ADB" "${ADB_ARGS[@]}" shell run-as "$PACKAGE" \
        cat files/loader-probe.log 2>/dev/null | tr -d '\r' || true)
    [[ "$PROBE_OUTPUT" == *"summary passed="* ]] && break
    sleep 1
done
printf '%s\n' "$PROBE_OUTPUT" | tee "$ROOT/logs/device-loader-probe.txt"
if [[ $STAGING_REQUIRED -eq 1 ]]; then
    [[ "$PROBE_OUTPUT" == *"test=private_module_set_relocation_success result=PASS"* ]] || {
        echo "private relocation success check missing or failed" >&2
        exit 1
    }
    [[ "$PROBE_OUTPUT" == *"test=private_module_set_relocation_rollback result=PASS"* ]] || {
        echo "private relocation rollback check missing or failed" >&2
        exit 1
    }
fi
[[ "$PROBE_OUTPUT" == *"test=bionic_vm_query result=PASS"* ]] || {
    echo "Bionic VM-query check missing or failed" >&2
    exit 1
}
[[ "$PROBE_OUTPUT" == *"test=bionic_signal_context result=PASS"* ]] || {
    echo "Bionic signal-context check missing or failed" >&2
    exit 1
}
[[ "$PROBE_OUTPUT" == *"test=bionic_guest_thread_context result=PASS"* ]] || {
    echo "Bionic guest-thread context check missing or failed" >&2
    exit 1
}
count_result() {
    awk -v test_name="$1" -v expected_result="$2" \
        '$1 == "test=" test_name && $2 == "result=" expected_result { count++ } END { print count + 0 }'
}
VULKAN_FOUNDATION_PASS_COUNT=$(count_result 'vulkan_surface_device' 'PASS' <<< "$PROBE_OUTPUT")
VULKAN_SWAPCHAIN_PASS_COUNT=$(count_result 'vulkan_swapchain_present' 'PASS' <<< "$PROBE_OUTPUT")
VULKAN_FOUNDATION_FAIL_COUNT=$(count_result 'vulkan_surface_device' 'FAIL' <<< "$PROBE_OUTPUT")
VULKAN_SWAPCHAIN_FAIL_COUNT=$(count_result 'vulkan_swapchain_present' 'FAIL' <<< "$PROBE_OUTPUT")
VULKAN_CLEAR_PASS_COUNT=$(count_result 'vulkan_clear_present' 'PASS' <<< "$PROBE_OUTPUT")
VULKAN_CLEAR_FAIL_COUNT=$(count_result 'vulkan_clear_present' 'FAIL' <<< "$PROBE_OUTPUT")
[[ "$VULKAN_FOUNDATION_PASS_COUNT" -eq 1 && "$VULKAN_SWAPCHAIN_PASS_COUNT" -eq 1 && "$VULKAN_CLEAR_PASS_COUNT" -eq 1 ]] || {
    echo "Vulkan checks must each PASS exactly once" >&2
    exit 1
}
[[ "$VULKAN_FOUNDATION_FAIL_COUNT" -eq 0 && "$VULKAN_SWAPCHAIN_FAIL_COUNT" -eq 0 && "$VULKAN_CLEAR_FAIL_COUNT" -eq 0 ]] || {
    echo "Vulkan check failure reported" >&2
    exit 1
}
EXPECTED_SUMMARY="summary passed=20 failed=0"
EXPECTED_LABEL="synthetic"
if [[ $STAGING_REQUIRED -eq 1 ]]; then
    EXPECTED_SUMMARY="summary passed=23 failed=0"
    EXPECTED_LABEL="private"
fi
[[ "$PROBE_OUTPUT" == *"$EXPECTED_SUMMARY"* ]] || {
    echo "Probe summary did not report the expected $EXPECTED_LABEL result ($EXPECTED_SUMMARY)" >&2
    exit 1
}
cleanup_private
echo "$EXPECTED_LABEL private-artifact cleanup/absence PASS remote=absent internal=absent paths=10"
{
    echo "model=$($ADB "${ADB_ARGS[@]}" shell getprop ro.product.model | tr -d '\r')"
    echo "device=$($ADB "${ADB_ARGS[@]}" shell getprop ro.product.device | tr -d '\r')"
    echo "android_release=$($ADB "${ADB_ARGS[@]}" shell getprop ro.build.version.release | tr -d '\r')"
    echo "sdk=$($ADB "${ADB_ARGS[@]}" shell getprop ro.build.version.sdk | tr -d '\r')"
    echo "abi=$($ADB "${ADB_ARGS[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
    echo "soc=$($ADB "${ADB_ARGS[@]}" shell getprop ro.soc.model | tr -d '\r')"
    echo "hardware=$($ADB "${ADB_ARGS[@]}" shell getprop ro.hardware | tr -d '\r')"
} | tee "$ROOT/logs/device-properties.txt"
LOGCAT_OUTPUT=$("$ADB" "${ADB_ARGS[@]}" logcat -d -s TotkLoaderProbe:V '*:S' | tr -d '\r')
printf '%s\n' "$LOGCAT_OUTPUT" | tee "$ROOT/logs/device-loader-probe-logcat.txt"
[[ "$LOGCAT_OUTPUT" == *"probe finished rc=0"* ]] || {
    echo "native activity did not report rc=0" >&2
    exit 1
}
