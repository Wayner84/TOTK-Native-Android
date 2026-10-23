#include "guest_thread_context.h"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <thread>

namespace {
int checks = 0;
int failures = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

uint64_t synthetic_callback(void*, uintptr_t) noexcept { return UINT64_C(0xfeedface); }

bool unchanged(const GuestStackRoundTrip& before, const GuestStackRoundTrip& after) {
    return before.guest_frame_sp == after.guest_frame_sp &&
           before.host_sp_before_callback == after.host_sp_before_callback &&
           before.host_callback_sp == after.host_callback_sp &&
           before.restored_host_sp == after.restored_host_sp &&
           before.callback_result == after.callback_result;
}
}  // namespace

int main() {
    GuestThreadContext context{};
    GuestThreadContext second{};
    expect(guest_thread_context_init(nullptr, 1, 2) == GuestThreadResult::invalid_argument,
           "reject_null_context_init");
    expect(guest_thread_context_init(&context, 0x1000, 0x2000) == GuestThreadResult::ok,
           "initialize_context");
    expect(guest_thread_context_init(&second, 0x3000, 0x4000) == GuestThreadResult::ok,
           "initialize_second_context");
    expect(guest_thread_bind(&context) == GuestThreadResult::ok,
           "bind_context");
    expect(guest_thread_current() == &context,
           "lookup_bound_context");
    uint64_t x18 = UINT64_MAX;
    uintptr_t pointer = 0;
    uintptr_t read_only_pointer = 0;
    expect(guest_x18_load(&context, &x18) == GuestThreadResult::ok && x18 == 0 &&
               guest_tpidr_el0_load(&context, &pointer) == GuestThreadResult::ok &&
               pointer == 0x1000 &&
               guest_tpidrro_el0_load(&context, &read_only_pointer) == GuestThreadResult::ok &&
               read_only_pointer == 0x2000,
           "initialize_independent_guest_state");
    expect(guest_thread_bind(&context) == GuestThreadResult::already_bound,
           "reject_duplicate_bind");
    expect(guest_thread_bind(&second) == GuestThreadResult::current_thread_busy,
           "reject_second_context_on_thread");

    x18 = 0;
    expect(guest_x18_store(&context, UINT64_C(0x1122334455667788)) == GuestThreadResult::ok &&
               guest_x18_load(&context, &x18) == GuestThreadResult::ok &&
               x18 == UINT64_C(0x1122334455667788),
           "roundtrip_guest_x18");
    expect(guest_tpidr_el0_store(&context, 0x5000) == GuestThreadResult::ok &&
               guest_tpidr_el0_load(&context, &pointer) == GuestThreadResult::ok &&
               pointer == 0x5000,
           "roundtrip_mutable_guest_tpidr_el0");
    expect(guest_tpidrro_el0_load(&context, &pointer) == GuestThreadResult::ok &&
               pointer == 0x2000 &&
               guest_x18_load(&context, &x18) == GuestThreadResult::ok &&
               x18 == UINT64_C(0x1122334455667788),
           "preserve_read_only_tlr_and_x18");

    std::atomic<bool> foreign_rejected{false};
    std::thread foreign([&] {
        foreign_rejected =
            guest_x18_store(&context, 7) == GuestThreadResult::not_owner &&
            guest_thread_unbind(&context) == GuestThreadResult::not_owner;
    });
    foreign.join();
    x18 = 0;
    expect(foreign_rejected.load() &&
               guest_x18_load(&context, &x18) == GuestThreadResult::ok &&
               x18 == UINT64_C(0x1122334455667788),
           "reject_foreign_thread_without_mutation");

    expect(validate_guest_host_stack(0x1000, 0x9000, 0x8000) == GuestThreadResult::ok,
           "accept_host_stack_bounds");
    expect(validate_guest_host_stack(0, 0x9000, 0x8000) == GuestThreadResult::invalid_stack,
           "reject_null_host_stack_low");
    expect(validate_guest_host_stack(0x9000, 0x1000, 0x8000) == GuestThreadResult::invalid_stack,
           "reject_inverted_host_stack");
    expect(validate_guest_host_stack(0x1000, UINTPTR_MAX, 0x8000) == GuestThreadResult::invalid_stack,
           "reject_overflow_prone_host_stack");
    expect(validate_guest_host_stack(0x1000, 0x9000, 0x9000) == GuestThreadResult::invalid_stack,
           "reject_anchor_at_stack_end");
    expect(validate_guest_host_stack(0x1000, 0x9000, 0x8008) == GuestThreadResult::invalid_alignment,
           "reject_misaligned_host_stack_anchor");
    expect(validate_guest_stack(0x10000, 0x12000, 0x11ff0, 0x20000, 0x30000) ==
               GuestThreadResult::ok,
           "accept_disjoint_guest_stack");
    expect(validate_guest_stack(0x10000, 0x12000, 0x11ff8, 0x20000, 0x30000) ==
               GuestThreadResult::invalid_alignment,
           "reject_misaligned_guest_sp");
    expect(validate_guest_stack(0x10000, 0x12000, 0x10000, 0x20000, 0x30000) ==
               GuestThreadResult::invalid_stack,
           "reject_guest_sp_without_frame_room");
    expect(validate_guest_stack(0x10000, 0x12000, 0x11ff0, 0x11000, 0x21000) ==
               GuestThreadResult::invalid_stack,
           "reject_guest_host_stack_overlap");
    expect(validate_host_callback_stack(0x1000, 0x10000, 0x9000, 0x4000) ==
               GuestThreadResult::ok,
           "accept_host_callback_headroom");
    expect(validate_host_callback_stack(0x1000, 0x10000, 0x2000, 0x2000) ==
               GuestThreadResult::invalid_stack,
           "reject_insufficient_host_callback_headroom");
    expect(validate_host_callback_stack(0x1000, 0x10000, 0x9000, UINTPTR_MAX) ==
               GuestThreadResult::invalid_stack,
           "reject_overflowing_host_callback_budget");
    expect(guest_thread_set_host_stack(&context, 0x1000, 0x9000, 0x8000) == GuestThreadResult::ok,
           "record_host_stack");

    GuestHostServiceRequest valid_request{0x10000, 0x12000, 0x11ff0, 0x1000, 0x8000};
    const GuestStackRoundTrip sentinel{1, 2, 3, 4, 5};
    GuestStackRoundTrip observation = sentinel;
    expect(guest_host_service_preflight(&context, valid_request, synthetic_callback, &observation) ==
               GuestThreadResult::ok,
           "preflight_valid_request");
    auto rejected_preflight_unchanged = [&](const char* name, const GuestHostServiceRequest& request,
                                            GuestHostCallback callback, GuestThreadResult expected) {
        GuestStackRoundTrip before = sentinel;
        GuestStackRoundTrip after = before;
        const GuestThreadResult result = guest_host_service_preflight(&context, request, callback, &after);
        expect(result == expected && unchanged(before, after), name);
    };
    rejected_preflight_unchanged("preflight_reject_null_callback", valid_request, nullptr,
                                 GuestThreadResult::invalid_argument);
    expect(guest_host_service_preflight(nullptr, valid_request, synthetic_callback, &observation) ==
               GuestThreadResult::invalid_argument && unchanged(sentinel, observation),
           "preflight_reject_null_context");
    expect(guest_host_service_preflight(&context, valid_request, synthetic_callback, nullptr) ==
               GuestThreadResult::invalid_argument,
           "preflight_reject_null_observation");
    GuestHostServiceRequest bad = valid_request;
    bad.guest_sp = 0x11ff8;
    rejected_preflight_unchanged("preflight_reject_misaligned_guest_sp", bad, synthetic_callback,
                                 GuestThreadResult::invalid_alignment);
    bad = valid_request; bad.guest_sp = 0x10000;
    rejected_preflight_unchanged("preflight_reject_guest_frame_room", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.guest_low = 0x7000; bad.guest_high = 0x11000;
    rejected_preflight_unchanged("preflight_reject_guest_host_overlap", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.live_host_sp = 0x8008;
    rejected_preflight_unchanged("preflight_reject_live_host_sp_alignment", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.live_host_sp = 0x1000;
    rejected_preflight_unchanged("preflight_reject_live_host_sp_headroom", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.live_host_sp = 0x9000;
    rejected_preflight_unchanged("preflight_reject_live_host_sp_outside_bounds", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.callback_headroom = UINTPTR_MAX;
    rejected_preflight_unchanged("preflight_reject_gate_budget_overflow", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    bad = valid_request; bad.guest_low = 0; bad.guest_high = 0; bad.guest_sp = 0;
    rejected_preflight_unchanged("preflight_reject_missing_guest_metadata", bad, synthetic_callback,
                                 GuestThreadResult::invalid_stack);
    GuestThreadContext unbound_preflight{};
    expect(guest_thread_context_init(&unbound_preflight, 0x71000, 0x72000) == GuestThreadResult::ok,
           "initialize_unbound_preflight_context");
    observation = sentinel;
    expect(guest_host_service_preflight(&unbound_preflight, valid_request, synthetic_callback,
                                        &observation) == GuestThreadResult::not_bound &&
               unchanged(sentinel, observation),
           "preflight_reject_unbound_context");
    std::atomic<bool> preflight_foreign_rejected{false};
    std::thread preflight_foreign([&] {
        GuestStackRoundTrip foreign_observation = sentinel;
        preflight_foreign_rejected =
            guest_host_service_preflight(&context, valid_request, synthetic_callback,
                                         &foreign_observation) == GuestThreadResult::not_owner &&
            unchanged(sentinel, foreign_observation);
    });
    preflight_foreign.join();
    expect(preflight_foreign_rejected.load(), "preflight_reject_foreign_thread");
    expect(guest_thread_begin_host_stack_use(&context) == GuestThreadResult::ok,
           "begin_host_stack_use");
    expect(guest_host_service_preflight(&context, valid_request, synthetic_callback, &observation) ==
               GuestThreadResult::stack_in_use && unchanged(sentinel, observation),
           "preflight_reject_nested_active_stack");
    expect(guest_thread_begin_host_stack_use(&context) == GuestThreadResult::stack_in_use,
           "reject_nested_host_stack_use");
    expect(guest_thread_unbind(&context) == GuestThreadResult::stack_in_use,
           "reject_unbind_while_host_stack_active");
    expect(guest_thread_end_host_stack_use(&context) == GuestThreadResult::ok,
           "end_host_stack_use");
    expect(guest_thread_unbind(&context) == GuestThreadResult::ok,
           "unbind_context");
    expect(guest_thread_unbind(&context) == GuestThreadResult::not_bound,
           "reject_double_unbind");

    GuestThreadContext missing_host_context{};
    expect(guest_thread_context_init(&missing_host_context, 0x81000, 0x82000) ==
               GuestThreadResult::ok &&
               guest_thread_bind(&missing_host_context) == GuestThreadResult::ok,
           "bind_missing_host_metadata_context");
    observation = sentinel;
    expect(guest_host_service_preflight(&missing_host_context, valid_request, synthetic_callback,
                                        &observation) == GuestThreadResult::invalid_stack &&
               unchanged(sentinel, observation),
           "preflight_reject_missing_host_metadata");
    expect(guest_thread_unbind(&missing_host_context) == GuestThreadResult::ok,
           "unbind_missing_host_metadata_context");

    GuestThreadContext trampoline_context{};
    guest_thread_context_init(&trampoline_context, 0x61000, 0x62000);
    expect(guest_thread_bind(&trampoline_context) == GuestThreadResult::ok,
           "bind_trampoline_context");
    expect(guest_rewrite_guest_x18_load(&trampoline_context, &x18) == GuestThreadResult::ok &&
               x18 == 0,
           "rewritten_guest_x18_access");
    expect(guest_rewrite_guest_tls_load(&trampoline_context, &pointer) == GuestThreadResult::ok &&
               pointer == 0x61000,
           "rewritten_guest_tls_access");
    expect(guest_thread_set_host_stack(&trampoline_context, 0x1000, 0x9000, 0x8000) ==
               GuestThreadResult::ok,
           "record_trampoline_host_stack");
    GuestHostServiceRequest request{0x10000, 0x12000, 0x11ff0, 0x1000, 0x8000};
    expect(guest_host_service_call(&trampoline_context, request, nullptr, nullptr, nullptr) ==
               GuestThreadResult::invalid_argument,
           "reject_null_host_service_callback");
#if !defined(__aarch64__)
    observation = sentinel;
    expect(guest_host_service_call(&trampoline_context, request, synthetic_callback, nullptr,
                                   &observation) == GuestThreadResult::invalid_stack &&
               unchanged(sentinel, observation),
           "host_service_call_reject_non_aarch64_without_mutation");
#endif
    expect(guest_thread_unbind(&trampoline_context) == GuestThreadResult::ok,
           "unbind_trampoline_context");
    expect(guest_rewrite_guest_x18_load(&trampoline_context, &x18) == GuestThreadResult::not_bound &&
               guest_rewrite_guest_tls_load(&trampoline_context, &pointer) == GuestThreadResult::not_bound,
           "rewritten_access_reject_unbound_context");
    expect(guest_rewrite_guest_x18_load(nullptr, &x18) == GuestThreadResult::invalid_argument &&
               guest_rewrite_guest_tls_load(nullptr, &pointer) == GuestThreadResult::invalid_argument,
           "rewritten_access_reject_null_context");
    expect(guest_rewrite_guest_x18_load(&trampoline_context, nullptr) == GuestThreadResult::invalid_argument &&
               guest_rewrite_guest_tls_load(&trampoline_context, nullptr) == GuestThreadResult::invalid_argument,
           "rewritten_access_reject_null_outputs");
    guest_thread_bind(&trampoline_context);
    std::atomic<bool> rewrite_foreign_rejected{false};
    std::thread rewrite_foreign([&] {
        uint64_t foreign_x18 = 0;
        uintptr_t foreign_tls = 0;
        rewrite_foreign_rejected =
            guest_rewrite_guest_x18_load(&trampoline_context, &foreign_x18) == GuestThreadResult::not_owner &&
            guest_rewrite_guest_tls_load(&trampoline_context, &foreign_tls) == GuestThreadResult::not_owner;
    });
    rewrite_foreign.join();
    expect(rewrite_foreign_rejected.load(), "rewritten_access_reject_foreign_thread");
    expect(guest_thread_unbind(&trampoline_context) == GuestThreadResult::ok,
           "rebind_unbind_trampoline_context");

    GuestThreadContext workers[2]{};
    guest_thread_context_init(&workers[0], 0x10000, 0x20000);
    guest_thread_context_init(&workers[1], 0x30000, 0x40000);
    std::atomic<unsigned> ready{0};
    std::atomic<bool> go{false};
    std::atomic<bool> isolated{true};
    auto worker = [&](unsigned index) {
        if (guest_thread_bind(&workers[index]) != GuestThreadResult::ok) {
            isolated = false;
            return;
        }
        ++ready;
        while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
        const uint64_t base = UINT64_C(0xabc0000000000000) + index * UINT64_C(0x100000000);
        const uintptr_t tls_base = 0x50000 + index * 0x10000;
        for (uint64_t iteration = 0; iteration < 50000; ++iteration) {
            uint64_t observed_x18 = 0;
            uintptr_t observed_tls = 0;
            uintptr_t observed_tlr = 0;
            if (guest_x18_store(&workers[index], base + iteration) != GuestThreadResult::ok ||
                guest_tpidr_el0_store(&workers[index], tls_base + iteration) != GuestThreadResult::ok ||
                guest_x18_load(&workers[index], &observed_x18) != GuestThreadResult::ok ||
                guest_tpidr_el0_load(&workers[index], &observed_tls) != GuestThreadResult::ok ||
                guest_tpidrro_el0_load(&workers[index], &observed_tlr) != GuestThreadResult::ok ||
                observed_x18 != base + iteration || observed_tls != tls_base + iteration ||
                observed_tlr != (index == 0 ? 0x20000u : 0x40000u)) {
                isolated = false;
                break;
            }
        }
        if (guest_thread_unbind(&workers[index]) != GuestThreadResult::ok) isolated = false;
    };
    std::thread first(worker, 0);
    std::thread second_thread(worker, 1);
    while (ready.load(std::memory_order_acquire) != 2) std::this_thread::yield();
    go.store(true, std::memory_order_release);
    first.join();
    second_thread.join();
    expect(isolated.load() && !workers[0].is_bound() && !workers[1].is_bound(),
           "isolate_two_thread_guest_state");

    GuestThreadContext contested{};
    guest_thread_context_init(&contested, 0x80000, 0x90000);
    std::atomic<unsigned> attempted{0};
    std::atomic<unsigned> winners{0};
    std::atomic<unsigned> rejected{0};
    std::atomic<bool> winner_unbound{false};
    auto contender = [&] {
        const GuestThreadResult result = guest_thread_bind(&contested);
        if (result == GuestThreadResult::ok) ++winners;
        if (result == GuestThreadResult::already_bound) ++rejected;
        ++attempted;
        if (result == GuestThreadResult::ok) {
            while (attempted.load(std::memory_order_acquire) != 2) std::this_thread::yield();
            winner_unbound = guest_thread_unbind(&contested) == GuestThreadResult::ok;
        }
    };
    std::thread contender_one(contender);
    std::thread contender_two(contender);
    contender_one.join();
    contender_two.join();
    expect(winners.load() == 1 && rejected.load() == 1 && winner_unbound.load() &&
               !contested.is_bound(),
           "serialize_concurrent_bind");

    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
