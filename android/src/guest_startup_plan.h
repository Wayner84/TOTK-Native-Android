#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>

constexpr std::size_t kGuestModuleCount = 3;
enum class GuestModuleId : std::uint8_t { main = 0, subsdk0 = 1, sdk = 2 };
enum class GuestStartupResult : std::uint8_t {
    ok,
    null_output,
    invalid_count,
    invalid_order,
    empty_range,
    range_overflow,
    range_not_contained,
    invalid_init,
    invalid_ctor_flag,
    init_array_alignment,
    init_array_size,
    init_array_overflow,
    init_array_not_contained,
    invalid_provider,
    missing_entry,
    entry_outside_provider,
    alias,
    noncanonical_reserved,
    private_execution_forbidden,
};
struct GuestModuleStartup {
    GuestModuleId id{};
    std::uint8_t reserved[7]{};
    std::uint64_t image_begin{}, image_end{};
    std::uint64_t writable_begin{}, writable_end{};
    std::uint64_t dt_init{}, ctor_flag{}, init_array{}, init_array_size{};
};
struct GuestStartupInput {
    std::uint32_t module_count{};
    std::uint8_t reserved[4]{};
    GuestModuleStartup modules[kGuestModuleCount]{};
    std::uint64_t nn_init_start{}, nn_main{};
    std::uint32_t nn_init_provider{}, nn_main_provider{};
    std::uint8_t tail_reserved[8]{};
};
using GuestStartupPlan = GuestStartupInput;
static_assert(std::is_trivially_copyable_v<GuestStartupInput>);
GuestStartupResult guest_startup_plan_validate(const GuestStartupInput&, GuestStartupPlan* output);
GuestStartupResult guest_startup_plan_revalidate(const GuestStartupPlan*);
GuestStartupResult guest_startup_request_execution(const GuestStartupPlan*);
const char* guest_startup_result_name(GuestStartupResult);
