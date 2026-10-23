#pragma once

#include <cstddef>
#include <cstdint>

constexpr size_t aarch64_signal_register_count = 31;

struct Aarch64SignalContext {
    uint64_t registers[aarch64_signal_register_count]{};
    uint64_t sp = 0;
    uint64_t pc = 0;
    uint64_t pstate = 0;

    bool operator==(const Aarch64SignalContext& other) const {
        for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
            if (registers[index] != other.registers[index]) return false;
        }
        return sp == other.sp && pc == other.pc && pstate == other.pstate;
    }
};

enum class SignalContextResult {
    ok,
    invalid_argument,
    invalid_alignment,
    signal_unavailable,
    unsupported_platform,
};

struct SignalProbeCandidate {
    int signal_number = 0;
    bool blocked = false;
    bool pending = false;
    bool default_action = false;
};

// Copies a validated snapshot transactionally. On failure destination is unchanged.
SignalContextResult restore_aarch64_signal_context_state(
    Aarch64SignalContext* destination,
    const Aarch64SignalContext* source);

// Bionic/Linux AArch64 adapters. The void pointer must name a ucontext_t supplied
// by a SA_SIGINFO handler. These functions never retain the pointer.
SignalContextResult capture_bionic_signal_context(
    const void* ucontext,
    Aarch64SignalContext* destination);
SignalContextResult restore_bionic_signal_context(
    void* ucontext,
    const Aarch64SignalContext* source);

SignalContextResult validate_signal_probe_state(bool blocked, bool pending);
bool signal_probe_stack_can_release(bool stack_restored);
int select_signal_probe_candidate(const SignalProbeCandidate* candidates,
                                  size_t candidate_count);
bool signal_probe_delivery_is_authorized(int expected_signal,
                                         int delivered_signal,
                                         bool on_expected_stack);

const char* signal_context_result_name(SignalContextResult result);
