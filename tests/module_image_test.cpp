#include "module_image.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>

namespace {

int failures = 0;
int checks = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

uintptr_t read_slot(const std::array<uint8_t, 128>& image, size_t offset) {
    uintptr_t value = 0;
    std::memcpy(&value, image.data() + offset, sizeof(value));
    return value;
}

}  // namespace

int main() {
    std::array<uint8_t, 128> image{};
    const ModuleRelocation valid[] = {
        {40, ModuleRelocationKind::relative, 0, 12},
        {48, ModuleRelocationKind::absolute64, 0x2000, -0x20},
    };
    auto result = apply_module_relocations(image.data(), image.size(), 32, 64, valid, 2);
    expect(result == ModuleRelocationResult::ok, "valid_relocations");
    expect(read_slot(image, 40) == reinterpret_cast<uintptr_t>(image.data()) + 12,
           "relative_value");
    expect(read_slot(image, 48) == 0x1fe0, "absolute_value");

    const ModuleRelocation slot_oob[] = {{124, ModuleRelocationKind::relative, 0, 0}};
    expect(apply_module_relocations(image.data(), image.size(), 32, 64, slot_oob, 1) ==
               ModuleRelocationResult::slot_out_of_bounds,
           "slot_bounds");

    const ModuleRelocation text_slot[] = {{8, ModuleRelocationKind::relative, 0, 0}};
    expect(apply_module_relocations(image.data(), image.size(), 32, 64, text_slot, 1) ==
               ModuleRelocationResult::slot_not_writable,
           "writable_bounds");

    const ModuleRelocation target_oob[] = {{40, ModuleRelocationKind::relative, 0, 128}};
    expect(apply_module_relocations(image.data(), image.size(), 32, 64, target_oob, 1) ==
               ModuleRelocationResult::target_out_of_bounds,
           "relative_target_bounds");

    const ModuleRelocation underflow[] = {{40, ModuleRelocationKind::absolute64, 0, -1}};
    expect(apply_module_relocations(image.data(), image.size(), 32, 64, underflow, 1) ==
               ModuleRelocationResult::arithmetic_overflow,
           "absolute_underflow");

    const ModuleRelocation unsupported[] = {
        {40, static_cast<ModuleRelocationKind>(999), 0, 0},
    };
    expect(apply_module_relocations(image.data(), image.size(), 32, 64, unsupported, 1) ==
               ModuleRelocationResult::unsupported_kind,
           "unsupported_kind");

    image.fill(0);
    const ModuleRelocation imported_relocations[] = {
        {32, ModuleRelocationKind::glob_dat, 0x4000, 7},
        {40, ModuleRelocationKind::jump_slot, 0x5000, -8},
    };
    expect(apply_module_relocations(image.data(), image.size(), 32, 64,
                                    imported_relocations, 2) == ModuleRelocationResult::ok,
           "import_relocation_kinds");
    uintptr_t glob_value = 0;
    uintptr_t jump_value = 0;
    std::memcpy(&glob_value, image.data() + 32, sizeof(glob_value));
    std::memcpy(&jump_value, image.data() + 40, sizeof(jump_value));
    expect(glob_value == 0x4007 && jump_value == 0x4ff8, "import_relocation_values");

    image.fill(0);
    const uintptr_t relr_addends[] = {1, 2, 3};
    std::memcpy(image.data() + 16, &relr_addends[0], sizeof(uintptr_t));
    std::memcpy(image.data() + 24, &relr_addends[1], sizeof(uintptr_t));
    std::memcpy(image.data() + 40, &relr_addends[2], sizeof(uintptr_t));
    const uint64_t relr_entries[] = {16, 0b1011};
    size_t relr_applied = 0;
    expect(apply_module_relr(image.data(), image.size(), 16, 64, relr_entries, 2,
                             relr_applied) == ModuleRelocationResult::ok && relr_applied == 3,
           "relr_base_and_bitmap");
    uintptr_t relr_values[3]{};
    std::memcpy(&relr_values[0], image.data() + 16, sizeof(uintptr_t));
    std::memcpy(&relr_values[1], image.data() + 24, sizeof(uintptr_t));
    std::memcpy(&relr_values[2], image.data() + 40, sizeof(uintptr_t));
    const uintptr_t image_base = reinterpret_cast<uintptr_t>(image.data());
    expect(relr_values[0] == image_base + 1 && relr_values[1] == image_base + 2 &&
               relr_values[2] == image_base + 3,
           "relr_values");

    const uint64_t bitmap_first[] = {3};
    expect(apply_module_relr(image.data(), image.size(), 16, 64, bitmap_first, 1,
                             relr_applied) == ModuleRelocationResult::malformed_relr,
           "relr_bitmap_before_base");
    image.fill(0);
    const uintptr_t original = 9;
    std::memcpy(image.data() + 16, &original, sizeof(original));
    const uint64_t invalid_after_valid[] = {16, 0x1000};
    expect(apply_module_relr(image.data(), image.size(), 16, 64, invalid_after_valid, 2,
                             relr_applied) == ModuleRelocationResult::slot_out_of_bounds,
           "relr_transactional_validation");
    uintptr_t unchanged = 0;
    std::memcpy(&unchanged, image.data() + 16, sizeof(unchanged));
    expect(unchanged == original, "relr_no_partial_write");

    const ModuleExport first_exports[] = {{"shared", 8, true}, {"undefined", 0, false}};
    const ModuleExport second_exports[] = {{"shared", 24, true}, {"second", 16, true}};
    const ModuleView modules[] = {
        {image.data(), image.size(), first_exports, 2},
        {image.data(), image.size(), second_exports, 2},
    };
    uintptr_t symbol = 0;
    expect(resolve_module_symbol(modules, 2, "shared", symbol) == ModuleSymbolResult::ok &&
               symbol == reinterpret_cast<uintptr_t>(image.data()) + 8,
           "symbol_order");
    expect(resolve_module_symbol(modules, 2, "second", symbol) == ModuleSymbolResult::ok &&
               symbol == reinterpret_cast<uintptr_t>(image.data()) + 16,
           "symbol_cross_module");
    expect(resolve_module_symbol(modules, 2, "missing", symbol) == ModuleSymbolResult::not_found && symbol == 0,
           "symbol_not_found");

    const ModuleExport bad_export[] = {{"bad", image.size(), true}};
    const ModuleView bad_module[] = {{image.data(), image.size(), bad_export, 1}};
    expect(resolve_module_symbol(bad_module, 1, "bad", symbol) ==
               ModuleSymbolResult::export_out_of_bounds,
           "symbol_bounds");

    const ModuleExport empty_export[] = {{"", 0, true}};
    const ModuleView empty_module[] = {{image.data(), image.size(), empty_export, 1}};
    expect(resolve_module_symbol(empty_module, 1, "shared", symbol) ==
               ModuleSymbolResult::malformed_name,
           "symbol_empty_name");
    expect(resolve_module_symbol(modules, 2, "", symbol) == ModuleSymbolResult::invalid_arguments,
           "symbol_empty_query");

    std::array<char, 4096> unterminated_name{};
    std::memset(unterminated_name.data(), 'x', unterminated_name.size());
    const ModuleExport unterminated_export[] = {{unterminated_name.data(), 0, true}};
    const ModuleView malformed_after_match[] = {
        {image.data(), image.size(), first_exports, 2},
        {image.data(), image.size(), unterminated_export, 1},
    };
    expect(resolve_module_symbol(malformed_after_match, 2, "shared", symbol) ==
               ModuleSymbolResult::malformed_name,
           "symbol_validates_all_modules");
    expect(resolve_module_symbol(modules, 2, unterminated_name.data(), symbol) ==
               ModuleSymbolResult::invalid_arguments,
           "symbol_bounded_query");

    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
