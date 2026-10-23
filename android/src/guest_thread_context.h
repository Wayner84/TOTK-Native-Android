#pragma once

#include <atomic>
#include <cstdint>

#include "guest_stack_probe.h"

enum class GuestThreadResult {
    ok,
    invalid_argument,
    invalid_alignment,
    invalid_stack,
    already_bound,
    current_thread_busy,
    not_bound,
    not_owner,
    stack_in_use,
};

struct GuestHostServiceRequest;

class GuestThreadContext {
public:
    GuestThreadContext() = default;
    GuestThreadContext(const GuestThreadContext&) = delete;
    GuestThreadContext& operator=(const GuestThreadContext&) = delete;

    bool is_bound() const {
        return bound_.load(std::memory_order_acquire);
    }

private:
    uint64_t guest_x18_ = 0;
    uintptr_t guest_tpidr_el0_ = 0;
    uintptr_t guest_tpidrro_el0_ = 0;

    uintptr_t host_stack_low_ = 0;
    uintptr_t host_stack_high_ = 0;
    uintptr_t host_stack_anchor_ = 0;

    std::atomic<uintptr_t> owner_token_{0};
    std::atomic<bool> bound_{false};
    bool host_stack_in_use_ = false;

    friend GuestThreadResult guest_thread_validate_owner(const GuestThreadContext*);
    friend GuestThreadResult guest_thread_context_init(GuestThreadContext*, uintptr_t, uintptr_t);
    friend GuestThreadResult guest_thread_bind(GuestThreadContext*);
    friend GuestThreadResult guest_thread_unbind(GuestThreadContext*);
    friend GuestThreadResult guest_x18_load(const GuestThreadContext*, uint64_t*);
    friend GuestThreadResult guest_x18_store(GuestThreadContext*, uint64_t);
    friend GuestThreadResult guest_tpidr_el0_load(const GuestThreadContext*, uintptr_t*);
    friend GuestThreadResult guest_tpidr_el0_store(GuestThreadContext*, uintptr_t);
    friend GuestThreadResult guest_tpidrro_el0_load(const GuestThreadContext*, uintptr_t*);
    friend GuestThreadResult guest_thread_set_host_stack(GuestThreadContext*, uintptr_t, uintptr_t,
                                                         uintptr_t);
    friend GuestThreadResult guest_thread_begin_host_stack_use(GuestThreadContext*);
    friend GuestThreadResult guest_thread_end_host_stack_use(GuestThreadContext*);
    friend GuestThreadResult guest_host_service_preflight(const GuestThreadContext*,
                                                           const GuestHostServiceRequest&,
                                                           GuestHostCallback,
                                                           const GuestStackRoundTrip*);
};

GuestThreadResult guest_thread_context_init(GuestThreadContext* context,
                                            uintptr_t guest_tls,
                                            uintptr_t guest_tlr);
GuestThreadResult guest_thread_bind(GuestThreadContext* context);
GuestThreadContext* guest_thread_current();
GuestThreadResult guest_thread_unbind(GuestThreadContext* context);

GuestThreadResult guest_x18_load(const GuestThreadContext* context, uint64_t* value);
GuestThreadResult guest_rewrite_guest_x18_load(const GuestThreadContext* context, uint64_t* value);
GuestThreadResult guest_rewrite_guest_tls_load(const GuestThreadContext* context, uintptr_t* value);
GuestThreadResult guest_x18_store(GuestThreadContext* context, uint64_t value);
GuestThreadResult guest_tpidr_el0_load(const GuestThreadContext* context, uintptr_t* value);
GuestThreadResult guest_tpidr_el0_store(GuestThreadContext* context, uintptr_t value);
GuestThreadResult guest_tpidrro_el0_load(const GuestThreadContext* context, uintptr_t* value);

GuestThreadResult validate_guest_host_stack(uintptr_t low,
                                            uintptr_t high,
                                            uintptr_t anchor);
GuestThreadResult validate_guest_stack(uintptr_t guest_low,
                                       uintptr_t guest_high,
                                       uintptr_t guest_sp,
                                       uintptr_t host_low,
                                       uintptr_t host_high);
GuestThreadResult validate_host_callback_stack(uintptr_t host_low,
                                               uintptr_t host_high,
                                               uintptr_t current_sp,
                                               uintptr_t required_headroom);

struct GuestHostServiceRequest {
    uintptr_t guest_low = 0;
    uintptr_t guest_high = 0;
    uintptr_t guest_sp = 0;
    uintptr_t callback_headroom = 0;
    uintptr_t live_host_sp = 0;
};

// Portable, non-mutating preflight owned by the service contract. It also rejects
// an already-active host-stack use before any entry attempt. Observation is unchanged
// on preflight/platform rejection; it is valid only after successful AArch64 completion.
// If cleanup fails after a callback, observation may contain assembly diagnostics and
// callback success is not returned.
GuestThreadResult guest_host_service_preflight(const GuestThreadContext* context,
                                               const GuestHostServiceRequest& request,
                                               GuestHostCallback callback,
                                               const GuestStackRoundTrip* observation);
GuestThreadResult guest_thread_set_host_stack(GuestThreadContext* context,
                                              uintptr_t low,
                                              uintptr_t high,
                                              uintptr_t anchor);
// Low-level probe/test primitives. Production callers use guest_host_service_call.
GuestThreadResult guest_thread_begin_host_stack_use(GuestThreadContext* context);
GuestThreadResult guest_thread_end_host_stack_use(GuestThreadContext* context);
GuestThreadResult guest_host_service_call(GuestThreadContext* context,
                                          const GuestHostServiceRequest& request,
                                          GuestHostCallback callback,
                                          void* opaque,
                                          GuestStackRoundTrip* observation);

const char* guest_thread_result_name(GuestThreadResult result);
