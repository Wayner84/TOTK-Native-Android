#include "guest_startup_plan.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {
int checks = 0;
void check(const char* name, bool pass) {
    ++checks;
    std::printf("test=%s result=%s\n", name, pass ? "PASS" : "FAIL");
    if (!pass) std::exit(1);
}
GuestStartupInput valid() {
    GuestStartupInput input{};
    input.module_count = 3;
    for (std::size_t i = 0; i < 3; ++i) {
        auto& m = input.modules[i];
        const std::uint64_t base = 0x10000 + i * 0x10000;
        m.id = static_cast<GuestModuleId>(i);
        m.image_begin = base; m.image_end = base + 0x8000;
        m.writable_begin = base + 0x4000; m.writable_end = base + 0x7000;
        m.dt_init = base + 0x100; m.ctor_flag = base + 0x4010;
        m.init_array = base + 0x5000; m.init_array_size = 16;
    }
    input.nn_init_start = 0x10104; input.nn_main = 0x20104;
    input.nn_init_provider = 0; input.nn_main_provider = 1;
    return input;
}
bool rejects(const char* name, GuestStartupInput input, GuestStartupResult expected) {
    GuestStartupPlan output = valid();
    GuestStartupPlan before = output;
    const auto result = guest_startup_plan_validate(input, &output);
    check(name, result == expected && std::memcmp(&output, &before, sizeof output) == 0);
    return true;
}
}
int main() {
    GuestStartupInput input = valid(); GuestStartupPlan plan{};
    check("valid", guest_startup_plan_validate(input, &plan) == GuestStartupResult::ok);
    check("null_output", guest_startup_plan_validate(input, nullptr) == GuestStartupResult::null_output);
    check("revalidate", guest_startup_plan_revalidate(&plan) == GuestStartupResult::ok);
    GuestStartupPlan frozen = plan;
    check("revalidate_immutable", guest_startup_plan_revalidate(&plan) == GuestStartupResult::ok && std::memcmp(&plan, &frozen, sizeof plan) == 0);
    check("revalidate_null", guest_startup_plan_revalidate(nullptr) == GuestStartupResult::null_output);
    input = valid(); input.module_count = 2; rejects("count_low", input, GuestStartupResult::invalid_count);
    input = valid(); input.module_count = 4; rejects("count_high", input, GuestStartupResult::invalid_count);
    input = valid(); input.modules[1].id = GuestModuleId::main; rejects("duplicate_id", input, GuestStartupResult::invalid_order);
    input = valid(); input.modules[0].id = GuestModuleId::subsdk0; rejects("reversed_id", input, GuestStartupResult::invalid_order);
    input = valid(); input.modules[0].image_begin = input.modules[0].image_end; rejects("empty_image", input, GuestStartupResult::empty_range);
    input = valid(); input.modules[0].writable_end = input.modules[0].writable_begin; rejects("empty_writable", input, GuestStartupResult::empty_range);
    input = valid(); input.modules[0].image_end = 0; rejects("image_overflow", input, GuestStartupResult::range_overflow);
    input = valid(); input.modules[0].writable_begin = input.modules[0].image_begin - 4; rejects("writable_not_contained", input, GuestStartupResult::range_not_contained);
    input = valid(); input.modules[0].dt_init = 0; rejects("init_zero", input, GuestStartupResult::invalid_init);
    input = valid(); input.modules[0].dt_init += 2; rejects("init_alignment", input, GuestStartupResult::invalid_init);
    input = valid(); input.modules[0].ctor_flag = 0; rejects("ctor_zero", input, GuestStartupResult::invalid_ctor_flag);
    input = valid(); input.modules[0].ctor_flag = input.modules[0].image_begin; rejects("ctor_outside_writable", input, GuestStartupResult::invalid_ctor_flag);
    input = valid(); input.modules[0].init_array += 1; rejects("array_alignment", input, GuestStartupResult::init_array_alignment);
    input = valid(); input.modules[0].init_array_size = 3; rejects("array_size", input, GuestStartupResult::init_array_size);
    input = valid(); input.modules[0].init_array = std::numeric_limits<std::uint64_t>::max() - 7; input.modules[0].init_array_size = 16; rejects("array_overflow", input, GuestStartupResult::init_array_overflow);
    input = valid(); input.modules[0].init_array = input.modules[0].image_end; rejects("array_not_contained", input, GuestStartupResult::init_array_not_contained);
    input = valid(); input.modules[0].init_array = 0; input.modules[0].init_array_size = 0;
    GuestStartupPlan zero_plan{};
    check("zero_array_canonical", guest_startup_plan_validate(input, &zero_plan) == GuestStartupResult::ok);
    input = valid(); input.modules[0].init_array = 8; input.modules[0].init_array_size = 0; rejects("zero_array_noncanonical", input, GuestStartupResult::init_array_not_contained);
    input = valid(); input.nn_init_provider = 3; rejects("provider_invalid", input, GuestStartupResult::invalid_provider);
    input = valid(); input.nn_init_start = 0; rejects("init_missing", input, GuestStartupResult::missing_entry);
    input = valid(); input.nn_main = 0; rejects("main_missing", input, GuestStartupResult::missing_entry);
    input = valid(); input.nn_main = 0x30000; rejects("main_outside", input, GuestStartupResult::entry_outside_provider);
    input = valid(); input.nn_main = 0x20102; rejects("main_unaligned", input, GuestStartupResult::entry_outside_provider);
    input = valid(); input.nn_main = input.nn_init_start; rejects("entry_alias", input, GuestStartupResult::alias);
    input = valid(); input.nn_main = input.modules[2].dt_init; input.nn_main_provider = 2; rejects("dt_init_alias", input, GuestStartupResult::alias);
    input = valid(); input.nn_main = input.modules[1].ctor_flag; rejects("ctor_alias", input, GuestStartupResult::alias);
    input = valid(); input.nn_main = input.modules[1].init_array; rejects("array_alias", input, GuestStartupResult::alias);
    input = valid(); input.reserved[0] = 1; rejects("input_reserved", input, GuestStartupResult::noncanonical_reserved);
    input = valid(); input.modules[1].reserved[3] = 1; rejects("module_reserved", input, GuestStartupResult::noncanonical_reserved);
    input = valid(); input.tail_reserved[7] = 1; rejects("tail_reserved", input, GuestStartupResult::noncanonical_reserved);
    struct ResultName { GuestStartupResult result; const char* name; };
    const ResultName result_names[] = {
        {GuestStartupResult::ok, "ok"},
        {GuestStartupResult::null_output, "null_output"},
        {GuestStartupResult::invalid_count, "invalid_count"},
        {GuestStartupResult::invalid_order, "invalid_order"},
        {GuestStartupResult::empty_range, "empty_range"},
        {GuestStartupResult::range_overflow, "range_overflow"},
        {GuestStartupResult::range_not_contained, "range_not_contained"},
        {GuestStartupResult::invalid_init, "invalid_init"},
        {GuestStartupResult::invalid_ctor_flag, "invalid_ctor_flag"},
        {GuestStartupResult::init_array_alignment, "init_array_alignment"},
        {GuestStartupResult::init_array_size, "init_array_size"},
        {GuestStartupResult::init_array_overflow, "init_array_overflow"},
        {GuestStartupResult::init_array_not_contained, "init_array_not_contained"},
        {GuestStartupResult::invalid_provider, "invalid_provider"},
        {GuestStartupResult::missing_entry, "missing_entry"},
        {GuestStartupResult::entry_outside_provider, "entry_outside_provider"},
        {GuestStartupResult::alias, "alias"},
        {GuestStartupResult::noncanonical_reserved, "noncanonical_reserved"},
        {GuestStartupResult::private_execution_forbidden, "private_execution_forbidden"},
    };
    for (const auto& item : result_names)
        check(item.name, std::strcmp(guest_startup_result_name(item.result), item.name) == 0);
    check("execution_null", guest_startup_request_execution(nullptr) == GuestStartupResult::private_execution_forbidden);
    check("execution_nonnull", guest_startup_request_execution(&plan) == GuestStartupResult::private_execution_forbidden);
    std::printf("summary passed=%d failed=0\n", checks);
    return 0;
}
