#pragma once

#include <cstdint>

struct GuestStackRoundTrip {
    uintptr_t guest_frame_sp = 0;
    uintptr_t host_sp_before_callback = 0;
    uintptr_t host_callback_sp = 0;
    uintptr_t restored_host_sp = 0;
    uint64_t callback_result = 0;
};

// Canonical callback ABI. Throwing across this gate violates the ABI and terminates;
// callback-level failures are encoded in the uint64 result/observation contract.
using GuestHostCallback = uint64_t (*)(void* opaque, uintptr_t expected_host_sp) noexcept;

extern "C" uint64_t guest_stack_round_trip_asm(uintptr_t guest_sp,
                                                GuestHostCallback callback,
                                                void* opaque,
                                                GuestStackRoundTrip* observation) noexcept;
