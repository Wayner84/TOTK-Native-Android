#pragma once

#include <cstddef>
#include <cstdint>

enum class ModuleRelocationKind : uint32_t {
    absolute64 = 257,
    glob_dat = 1025,
    jump_slot = 1026,
    relative = 1027,
};

struct ModuleRelocation {
    size_t where;
    ModuleRelocationKind kind;
    uintptr_t symbol;
    int64_t addend;
};

enum class ModuleRelocationResult {
    ok,
    invalid_arguments,
    slot_out_of_bounds,
    slot_not_writable,
    target_out_of_bounds,
    arithmetic_overflow,
    unsupported_kind,
    malformed_relr,
};

ModuleRelocationResult apply_module_relocations(
    uint8_t* image,
    size_t image_size,
    size_t writable_begin,
    size_t writable_end,
    const ModuleRelocation* relocations,
    size_t relocation_count);

const char* module_relocation_result_name(ModuleRelocationResult result);

ModuleRelocationResult apply_module_relr(
    uint8_t* image,
    size_t image_size,
    size_t writable_begin,
    size_t writable_end,
    const uint64_t* entries,
    size_t entry_count,
    size_t& applied_count);

struct ModuleExport {
    const char* name;
    size_t value;
    bool defined;
};

struct ModuleView {
    const uint8_t* image;
    size_t image_size;
    const ModuleExport* exports;
    size_t export_count;
};

enum class ModuleSymbolResult {
    ok,
    invalid_arguments,
    malformed_name,
    export_out_of_bounds,
    not_found,
};

ModuleSymbolResult resolve_module_symbol(
    const ModuleView* modules,
    size_t module_count,
    const char* name,
    uintptr_t& value);

const char* module_symbol_result_name(ModuleSymbolResult result);
