#include "guest_thread_context.h"
#include "guest_stack_probe.h"

#include <limits>

namespace {
thread_local GuestThreadContext* current_context = nullptr;
thread_local unsigned char thread_identity_marker = 0;

uintptr_t current_thread_token() {
    return reinterpret_cast<uintptr_t>(&thread_identity_marker);
}
}  // namespace

GuestThreadResult guest_thread_validate_owner(const GuestThreadContext* context) {
    if (context == nullptr) return GuestThreadResult::invalid_argument;
    if (!context->bound_.load(std::memory_order_acquire)) return GuestThreadResult::not_bound;
    if (current_context != context ||
        context->owner_token_.load(std::memory_order_acquire) != current_thread_token()) {
        return GuestThreadResult::not_owner;
    }
    return GuestThreadResult::ok;
}

GuestThreadResult guest_thread_context_init(GuestThreadContext* context,
                                            uintptr_t guest_tls,
                                            uintptr_t guest_tlr) {
    if (context == nullptr) return GuestThreadResult::invalid_argument;
    if (context->bound_.load(std::memory_order_acquire)) return GuestThreadResult::already_bound;

    context->guest_x18_ = 0;
    context->guest_tpidr_el0_ = guest_tls;
    context->guest_tpidrro_el0_ = guest_tlr;
    context->host_stack_low_ = 0;
    context->host_stack_high_ = 0;
    context->host_stack_anchor_ = 0;
    context->owner_token_.store(0, std::memory_order_relaxed);
    context->host_stack_in_use_ = false;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_thread_bind(GuestThreadContext* context) {
    if (context == nullptr) return GuestThreadResult::invalid_argument;
    if (context->bound_.load(std::memory_order_acquire)) return GuestThreadResult::already_bound;
    if (current_context != nullptr) return GuestThreadResult::current_thread_busy;

    bool expected = false;
    if (!context->bound_.compare_exchange_strong(expected, true,
                                                 std::memory_order_acq_rel,
                                                 std::memory_order_acquire)) {
        return GuestThreadResult::already_bound;
    }
    context->owner_token_.store(current_thread_token(), std::memory_order_release);
    current_context = context;
    return GuestThreadResult::ok;
}

GuestThreadContext* guest_thread_current() {
    return current_context;
}

GuestThreadResult guest_thread_unbind(GuestThreadContext* context) {
    if (context == nullptr) return GuestThreadResult::invalid_argument;
    if (!context->bound_.load(std::memory_order_acquire)) return GuestThreadResult::not_bound;
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    if (context->host_stack_in_use_) return GuestThreadResult::stack_in_use;

    current_context = nullptr;
    context->owner_token_.store(0, std::memory_order_release);
    context->bound_.store(false, std::memory_order_release);
    return GuestThreadResult::ok;
}

GuestThreadResult guest_x18_load(const GuestThreadContext* context, uint64_t* value) {
    if (value == nullptr) return GuestThreadResult::invalid_argument;
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    *value = context->guest_x18_;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_x18_store(GuestThreadContext* context, uint64_t value) {
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    context->guest_x18_ = value;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_rewrite_guest_x18_load(const GuestThreadContext* context, uint64_t* value) {
    return guest_x18_load(context, value);
}

GuestThreadResult guest_rewrite_guest_tls_load(const GuestThreadContext* context, uintptr_t* value) {
    return guest_tpidr_el0_load(context, value);
}

GuestThreadResult guest_tpidr_el0_load(const GuestThreadContext* context, uintptr_t* value) {
    if (value == nullptr) return GuestThreadResult::invalid_argument;
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    *value = context->guest_tpidr_el0_;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_tpidr_el0_store(GuestThreadContext* context, uintptr_t value) {
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    context->guest_tpidr_el0_ = value;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_tpidrro_el0_load(const GuestThreadContext* context, uintptr_t* value) {
    if (value == nullptr) return GuestThreadResult::invalid_argument;
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    *value = context->guest_tpidrro_el0_;
    return GuestThreadResult::ok;
}

GuestThreadResult validate_guest_host_stack(uintptr_t low,
                                            uintptr_t high,
                                            uintptr_t anchor) {
    if (low == 0 || high == 0 || high == std::numeric_limits<uintptr_t>::max() || low >= high ||
        anchor < low || anchor >= high) {
        return GuestThreadResult::invalid_stack;
    }
    if ((anchor & uintptr_t{15}) != 0) return GuestThreadResult::invalid_alignment;
    return GuestThreadResult::ok;
}

GuestThreadResult validate_guest_stack(uintptr_t guest_low,
                                       uintptr_t guest_high,
                                       uintptr_t guest_sp,
                                       uintptr_t host_low,
                                       uintptr_t host_high) {
    constexpr uintptr_t minimum_frame_room = 256;
    if (guest_low == 0 || guest_high == 0 || host_low == 0 || host_high == 0 ||
        guest_high == std::numeric_limits<uintptr_t>::max() ||
        host_high == std::numeric_limits<uintptr_t>::max() ||
        guest_low >= guest_high || host_low >= host_high ||
        guest_sp > guest_high || guest_sp < guest_low ||
        guest_low > std::numeric_limits<uintptr_t>::max() - minimum_frame_room ||
        guest_sp < guest_low + minimum_frame_room) {
        return GuestThreadResult::invalid_stack;
    }
    if ((guest_sp & uintptr_t{15}) != 0) return GuestThreadResult::invalid_alignment;
    if (guest_low < host_high && host_low < guest_high) {
        return GuestThreadResult::invalid_stack;
    }
    return GuestThreadResult::ok;
}

GuestThreadResult validate_host_callback_stack(uintptr_t host_low,
                                               uintptr_t host_high,
                                               uintptr_t current_sp,
                                               uintptr_t required_headroom) {
    if (host_low == 0 || host_high == 0 || host_high == std::numeric_limits<uintptr_t>::max() ||
        host_low >= host_high || current_sp < host_low || current_sp >= host_high ||
        required_headroom == 0 || (current_sp & uintptr_t{15}) != 0 ||
        required_headroom > current_sp - host_low) {
        return GuestThreadResult::invalid_stack;
    }
    return GuestThreadResult::ok;
}

GuestThreadResult guest_thread_set_host_stack(GuestThreadContext* context,
                                              uintptr_t low,
                                              uintptr_t high,
                                              uintptr_t anchor) {
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    const GuestThreadResult valid = validate_guest_host_stack(low, high, anchor);
    if (valid != GuestThreadResult::ok) return valid;
    if (context->host_stack_in_use_) return GuestThreadResult::stack_in_use;

    context->host_stack_low_ = low;
    context->host_stack_high_ = high;
    context->host_stack_anchor_ = anchor;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_thread_begin_host_stack_use(GuestThreadContext* context) {
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    if (context->host_stack_in_use_) return GuestThreadResult::stack_in_use;
    if (validate_guest_host_stack(context->host_stack_low_,
                                  context->host_stack_high_,
                                  context->host_stack_anchor_) != GuestThreadResult::ok) {
        return GuestThreadResult::invalid_stack;
    }
    context->host_stack_in_use_ = true;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_thread_end_host_stack_use(GuestThreadContext* context) {
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    if (!context->host_stack_in_use_) return GuestThreadResult::invalid_stack;
    context->host_stack_in_use_ = false;
    return GuestThreadResult::ok;
}

GuestThreadResult guest_host_service_preflight(const GuestThreadContext* context,
                                               const GuestHostServiceRequest& request,
                                               GuestHostCallback callback,
                                               const GuestStackRoundTrip* observation) {
    if (callback == nullptr || observation == nullptr) return GuestThreadResult::invalid_argument;
    const GuestThreadResult owner = guest_thread_validate_owner(context);
    if (owner != GuestThreadResult::ok) return owner;
    if (context->host_stack_in_use_) return GuestThreadResult::stack_in_use;
    constexpr uintptr_t gate_frame = 64;
    if (request.callback_headroom > std::numeric_limits<uintptr_t>::max() - gate_frame)
        return GuestThreadResult::invalid_stack;
    const uintptr_t required = request.callback_headroom + gate_frame;
    const GuestThreadResult guest = validate_guest_stack(request.guest_low, request.guest_high,
                                                          request.guest_sp, context->host_stack_low_,
                                                          context->host_stack_high_);
    if (guest != GuestThreadResult::ok) return guest;
    return validate_host_callback_stack(context->host_stack_low_, context->host_stack_high_,
                                        request.live_host_sp, required);
}

GuestThreadResult guest_host_service_call(GuestThreadContext* context,
                                          const GuestHostServiceRequest& request,
                                          GuestHostCallback callback,
                                          void* opaque,
                                          GuestStackRoundTrip* observation) {
    if (context == nullptr || callback == nullptr || observation == nullptr)
        return GuestThreadResult::invalid_argument;
    GuestHostServiceRequest live_request = request;
#if defined(__aarch64__)
    uintptr_t live_host_sp = 0;
    asm volatile("mov %0, sp" : "=r"(live_host_sp) :: "memory");
    live_request.live_host_sp = live_host_sp;
#else
    (void)opaque;
#endif
    const GuestThreadResult preflight = guest_host_service_preflight(context,
                                                                       live_request,
                                                                       callback,
                                                                       observation);
    if (preflight != GuestThreadResult::ok) return preflight;
#if defined(__aarch64__)
    const GuestThreadResult begin = guest_thread_begin_host_stack_use(context);
    if (begin != GuestThreadResult::ok) return begin;
    const uint64_t result = guest_stack_round_trip_asm(live_request.guest_sp, callback, opaque,
                                                        observation);
    const GuestThreadResult end = guest_thread_end_host_stack_use(context);
    if (end != GuestThreadResult::ok) return end;
    observation->callback_result = result;
    return GuestThreadResult::ok;
#else
    return GuestThreadResult::invalid_stack;
#endif
}

const char* guest_thread_result_name(GuestThreadResult result) {
    switch (result) {
        case GuestThreadResult::ok: return "ok";
        case GuestThreadResult::invalid_argument: return "invalid_argument";
        case GuestThreadResult::invalid_alignment: return "invalid_alignment";
        case GuestThreadResult::invalid_stack: return "invalid_stack";
        case GuestThreadResult::already_bound: return "already_bound";
        case GuestThreadResult::current_thread_busy: return "current_thread_busy";
        case GuestThreadResult::not_bound: return "not_bound";
        case GuestThreadResult::not_owner: return "not_owner";
        case GuestThreadResult::stack_in_use: return "stack_in_use";
    }
    return "unknown";
}
