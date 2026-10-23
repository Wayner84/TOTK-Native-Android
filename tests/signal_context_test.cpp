#include "signal_context.h"

#include <cstdint>
#include <iostream>

namespace {
int checks = 0;
int failures = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

Aarch64SignalContext make_valid() {
    Aarch64SignalContext state{};
    for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
        state.registers[index] = UINT64_C(0x100000000) + index * 0x10;
    }
    state.sp = UINT64_C(0x7000001000);
    state.pc = UINT64_C(0x100001000);
    state.pstate = UINT64_C(0x60000000);
    return state;
}
}

int main() {
    const auto source = make_valid();
    Aarch64SignalContext destination{};
    expect(restore_aarch64_signal_context_state(&destination, &source) ==
               SignalContextResult::ok &&
               destination == source,
           "restore_exact_state");

    destination = make_valid();
    const auto before_bad_pc = destination;
    auto bad_pc = source;
    bad_pc.pc += 2;
    expect(restore_aarch64_signal_context_state(&destination, &bad_pc) ==
               SignalContextResult::invalid_alignment &&
               destination == before_bad_pc,
           "reject_misaligned_pc_without_mutation");

    destination = make_valid();
    const auto before_bad_sp = destination;
    auto bad_sp = source;
    bad_sp.sp += 8;
    expect(restore_aarch64_signal_context_state(&destination, &bad_sp) ==
               SignalContextResult::invalid_alignment &&
               destination == before_bad_sp,
           "reject_misaligned_sp_without_mutation");

    expect(restore_aarch64_signal_context_state(nullptr, &source) ==
               SignalContextResult::invalid_argument,
           "reject_null_destination");
    expect(restore_aarch64_signal_context_state(&destination, nullptr) ==
               SignalContextResult::invalid_argument,
           "reject_null_source");
    expect(capture_bionic_signal_context(nullptr, &destination) ==
               SignalContextResult::invalid_argument,
           "capture_rejects_null_ucontext");
    expect(capture_bionic_signal_context(&destination, nullptr) ==
               SignalContextResult::invalid_argument,
           "capture_rejects_null_output");
    expect(restore_bionic_signal_context(nullptr, &source) ==
               SignalContextResult::invalid_argument,
           "restore_rejects_null_ucontext");
    expect(restore_bionic_signal_context(&destination, nullptr) ==
               SignalContextResult::invalid_argument,
           "restore_rejects_null_state");

    expect(validate_signal_probe_state(false, false) == SignalContextResult::ok,
           "probe_accepts_unblocked_clear_signal");
    expect(validate_signal_probe_state(true, false) == SignalContextResult::signal_unavailable,
           "probe_rejects_blocked_signal");
    expect(validate_signal_probe_state(false, true) == SignalContextResult::signal_unavailable,
           "probe_rejects_pending_signal");
    expect(signal_probe_stack_can_release(true),
           "release_stack_after_restore");
    expect(signal_probe_stack_can_release(false) == false,
           "retain_stack_after_restore_failure");

    const SignalProbeCandidate candidates[] = {
        {64, false, false, false},
        {63, true, false, true},
        {62, false, true, true},
        {61, false, false, true},
    };
    expect(select_signal_probe_candidate(candidates, 4) == 61,
           "select_first_unblocked_clear_default_signal");
    expect(select_signal_probe_candidate(candidates, 0) == 0,
           "reject_empty_signal_candidates");
    expect(select_signal_probe_candidate(nullptr, 4) == 0,
           "reject_null_signal_candidates");
    expect(signal_probe_delivery_is_authorized(64, 64, true),
           "authorize_expected_signal_on_probe_stack");
    expect(!signal_probe_delivery_is_authorized(64, 63, true),
           "reject_unexpected_signal_delivery");
    expect(!signal_probe_delivery_is_authorized(64, 64, false),
           "reject_delivery_on_another_thread_stack");

    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
