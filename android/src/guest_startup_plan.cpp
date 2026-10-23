#include "guest_startup_plan.h"
#include <limits>

namespace {
constexpr std::uint64_t kPointerAlignment = alignof(void*);
constexpr std::uint64_t kFunctionAlignment = 4;
bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& result) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return true;
    result = a + b;
    return false;
}
bool contains(std::uint64_t begin, std::uint64_t end, std::uint64_t value) {
    return value >= begin && value < end;
}
bool range_contains(std::uint64_t outer_begin, std::uint64_t outer_end,
                    std::uint64_t begin, std::uint64_t end) {
    return begin >= outer_begin && end <= outer_end && begin <= end;
}
template <std::size_t N>
bool all_zero(const std::uint8_t (&bytes)[N]) {
    for (const std::uint8_t byte : bytes) {
        if (byte != 0) return false;
    }
    return true;
}
GuestStartupResult validate(const GuestStartupInput& input) {
    if (input.module_count != kGuestModuleCount) return GuestStartupResult::invalid_count;
    if (!all_zero(input.reserved) || !all_zero(input.tail_reserved))
        return GuestStartupResult::noncanonical_reserved;
    for (std::size_t i = 0; i < kGuestModuleCount; ++i) {
        const GuestModuleStartup& module = input.modules[i];
        if (module.id != static_cast<GuestModuleId>(i)) return GuestStartupResult::invalid_order;
        if (!all_zero(module.reserved)) return GuestStartupResult::noncanonical_reserved;
        if (module.image_begin == module.image_end) return GuestStartupResult::empty_range;
        if (module.writable_begin == module.writable_end) return GuestStartupResult::empty_range;
        if (module.image_end < module.image_begin) return GuestStartupResult::range_overflow;
        if (module.writable_end < module.writable_begin) return GuestStartupResult::range_overflow;
        if (!range_contains(module.image_begin, module.image_end,
                            module.writable_begin, module.writable_end))
            return GuestStartupResult::range_not_contained;
        if (module.dt_init == 0 || !contains(module.image_begin, module.image_end, module.dt_init) ||
            (module.dt_init % kFunctionAlignment) != 0)
            return GuestStartupResult::invalid_init;
        if (module.ctor_flag == 0 || !contains(module.writable_begin, module.writable_end, module.ctor_flag))
            return GuestStartupResult::invalid_ctor_flag;
        if ((module.init_array % kPointerAlignment) != 0)
            return GuestStartupResult::init_array_alignment;
        if ((module.init_array_size % kPointerAlignment) != 0)
            return GuestStartupResult::init_array_size;
        // Pinned source evidence: prepare_runtime.py:125 uses tags.get(25, 0)
        // and tags.get(27, 0), so an absent DT_INIT_ARRAY is canonically {0, 0}.
        if (module.init_array_size == 0) {
            if (module.init_array != 0) return GuestStartupResult::init_array_not_contained;
        } else {
            std::uint64_t end = 0;
            if (add_overflow(module.init_array, module.init_array_size, end))
                return GuestStartupResult::init_array_overflow;
            if (!range_contains(module.image_begin, module.image_end, module.init_array, end))
                return GuestStartupResult::init_array_not_contained;
        }
    }
    if (input.nn_init_provider >= kGuestModuleCount || input.nn_main_provider >= kGuestModuleCount)
        return GuestStartupResult::invalid_provider;
    if (input.nn_init_start == 0 || input.nn_main == 0) return GuestStartupResult::missing_entry;
    const auto& init_provider = input.modules[input.nn_init_provider];
    const auto& main_provider = input.modules[input.nn_main_provider];
    if (input.nn_init_start == input.nn_main) return GuestStartupResult::alias;
    if ((input.nn_init_start % kFunctionAlignment) != 0 ||
        (input.nn_main % kFunctionAlignment) != 0)
        return GuestStartupResult::entry_outside_provider;
    if (!contains(init_provider.image_begin, init_provider.image_end, input.nn_init_start) ||
        !contains(main_provider.image_begin, main_provider.image_end, input.nn_main))
        return GuestStartupResult::entry_outside_provider;
    for (const auto& module : input.modules) {
        if (input.nn_init_start == module.dt_init || input.nn_main == module.dt_init ||
            input.nn_init_start == module.ctor_flag || input.nn_main == module.ctor_flag)
            return GuestStartupResult::alias;
        if (module.init_array_size != 0) {
            std::uint64_t end = module.init_array + module.init_array_size;
            if (input.nn_init_start >= module.init_array && input.nn_init_start < end) return GuestStartupResult::alias;
            if (input.nn_main >= module.init_array && input.nn_main < end) return GuestStartupResult::alias;
        }
    }
    return GuestStartupResult::ok;
}
}
GuestStartupResult guest_startup_plan_validate(const GuestStartupInput& input, GuestStartupPlan* output) {
    if (output == nullptr) return GuestStartupResult::null_output;
    GuestStartupResult result = validate(input);
    if (result != GuestStartupResult::ok) return result;
    GuestStartupPlan candidate{};
    candidate = input;
    *output = candidate;
    return GuestStartupResult::ok;
}
GuestStartupResult guest_startup_plan_revalidate(const GuestStartupPlan* plan) {
    if (plan == nullptr) return GuestStartupResult::null_output;
    return validate(*plan);
}
GuestStartupResult guest_startup_request_execution(const GuestStartupPlan*) {
    return GuestStartupResult::private_execution_forbidden;
}
const char* guest_startup_result_name(GuestStartupResult result) {
    switch (result) {
    case GuestStartupResult::ok: return "ok";
    case GuestStartupResult::null_output: return "null_output";
    case GuestStartupResult::invalid_count: return "invalid_count";
    case GuestStartupResult::invalid_order: return "invalid_order";
    case GuestStartupResult::empty_range: return "empty_range";
    case GuestStartupResult::range_overflow: return "range_overflow";
    case GuestStartupResult::range_not_contained: return "range_not_contained";
    case GuestStartupResult::invalid_init: return "invalid_init";
    case GuestStartupResult::invalid_ctor_flag: return "invalid_ctor_flag";
    case GuestStartupResult::init_array_alignment: return "init_array_alignment";
    case GuestStartupResult::init_array_size: return "init_array_size";
    case GuestStartupResult::init_array_overflow: return "init_array_overflow";
    case GuestStartupResult::init_array_not_contained: return "init_array_not_contained";
    case GuestStartupResult::invalid_provider: return "invalid_provider";
    case GuestStartupResult::missing_entry: return "missing_entry";
    case GuestStartupResult::entry_outside_provider: return "entry_outside_provider";
    case GuestStartupResult::alias: return "alias";
    case GuestStartupResult::noncanonical_reserved: return "noncanonical_reserved";
    case GuestStartupResult::private_execution_forbidden: return "private_execution_forbidden";
    }
    return "unknown";
}
