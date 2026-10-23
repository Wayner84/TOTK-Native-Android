#include "signal_context.h"

#if defined(__aarch64__) && defined(__linux__)
#include <ucontext.h>
#endif

namespace {
SignalContextResult validate_state(const Aarch64SignalContext& state) {
    if ((state.pc & UINT64_C(3)) != 0 || (state.sp & UINT64_C(15)) != 0) {
        return SignalContextResult::invalid_alignment;
    }
    return SignalContextResult::ok;
}
}

SignalContextResult restore_aarch64_signal_context_state(
    Aarch64SignalContext* destination,
    const Aarch64SignalContext* source) {
    if (destination == nullptr || source == nullptr) {
        return SignalContextResult::invalid_argument;
    }
    const SignalContextResult valid = validate_state(*source);
    if (valid != SignalContextResult::ok) return valid;
    for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
        destination->registers[index] = source->registers[index];
    }
    destination->sp = source->sp;
    destination->pc = source->pc;
    destination->pstate = source->pstate;
    return SignalContextResult::ok;
}

SignalContextResult capture_bionic_signal_context(
    const void* ucontext,
    Aarch64SignalContext* destination) {
    if (ucontext == nullptr || destination == nullptr) {
        return SignalContextResult::invalid_argument;
    }
#if defined(__aarch64__) && defined(__linux__)
    const auto* context = static_cast<const ucontext_t*>(ucontext);
    Aarch64SignalContext captured{};
    static_assert(sizeof(context->uc_mcontext.regs) / sizeof(context->uc_mcontext.regs[0]) ==
                  aarch64_signal_register_count);
    for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
        captured.registers[index] = context->uc_mcontext.regs[index];
    }
    captured.sp = context->uc_mcontext.sp;
    captured.pc = context->uc_mcontext.pc;
    captured.pstate = context->uc_mcontext.pstate;
    return restore_aarch64_signal_context_state(destination, &captured);
#else
    return SignalContextResult::unsupported_platform;
#endif
}

SignalContextResult restore_bionic_signal_context(
    void* ucontext,
    const Aarch64SignalContext* source) {
    if (ucontext == nullptr || source == nullptr) {
        return SignalContextResult::invalid_argument;
    }
    Aarch64SignalContext validated{};
    const SignalContextResult valid =
        restore_aarch64_signal_context_state(&validated, source);
    if (valid != SignalContextResult::ok) return valid;
#if defined(__aarch64__) && defined(__linux__)
    auto* context = static_cast<ucontext_t*>(ucontext);
    for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
        context->uc_mcontext.regs[index] = validated.registers[index];
    }
    context->uc_mcontext.sp = validated.sp;
    context->uc_mcontext.pc = validated.pc;
    context->uc_mcontext.pstate = validated.pstate;
    return SignalContextResult::ok;
#else
    return SignalContextResult::unsupported_platform;
#endif
}

SignalContextResult validate_signal_probe_state(bool blocked, bool pending) {
    return blocked || pending ? SignalContextResult::signal_unavailable
                              : SignalContextResult::ok;
}

bool signal_probe_stack_can_release(bool stack_restored) {
    return stack_restored;
}

int select_signal_probe_candidate(const SignalProbeCandidate* candidates,
                                  size_t candidate_count) {
    if (candidates == nullptr) return 0;
    for (size_t index = 0; index < candidate_count; ++index) {
        const SignalProbeCandidate& candidate = candidates[index];
        if (candidate.signal_number > 0 && !candidate.blocked &&
            !candidate.pending && candidate.default_action) {
            return candidate.signal_number;
        }
    }
    return 0;
}

bool signal_probe_delivery_is_authorized(int expected_signal,
                                         int delivered_signal,
                                         bool on_expected_stack) {
    return expected_signal > 0 && delivered_signal == expected_signal &&
           on_expected_stack;
}

const char* signal_context_result_name(SignalContextResult result) {
    switch (result) {
        case SignalContextResult::ok: return "ok";
        case SignalContextResult::invalid_argument: return "invalid_argument";
        case SignalContextResult::invalid_alignment: return "invalid_alignment";
        case SignalContextResult::signal_unavailable: return "signal_unavailable";
        case SignalContextResult::unsupported_platform: return "unsupported_platform";
    }
    return "unknown";
}
