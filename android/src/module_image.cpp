#include "module_image.h"

#include <cstring>
#include <limits>

namespace {

bool add_signed(uintptr_t base, int64_t addend, uintptr_t& out) {
    if (addend >= 0) {
        const auto value = static_cast<uint64_t>(addend);
        if (value > std::numeric_limits<uintptr_t>::max() - base) return false;
        out = base + static_cast<uintptr_t>(value);
        return true;
    }
    // Avoid negating INT64_MIN in the signed domain.
    const uint64_t magnitude = static_cast<uint64_t>(-(addend + 1)) + 1;
    if (magnitude > base) return false;
    out = base - static_cast<uintptr_t>(magnitude);
    return true;
}

constexpr size_t max_symbol_name = 4096;

bool bounded_name_length(const char* name, size_t& length) {
    if (name == nullptr) return false;
    for (length = 0; length < max_symbol_name; ++length) {
        if (name[length] == '\0') return length != 0;
    }
    return false;
}

}  // namespace

ModuleRelocationResult apply_module_relocations(
    uint8_t* image,
    size_t image_size,
    size_t writable_begin,
    size_t writable_end,
    const ModuleRelocation* relocations,
    size_t relocation_count) {
    if (image == nullptr || (relocation_count != 0 && relocations == nullptr) ||
        writable_begin > writable_end || writable_end > image_size) {
        return ModuleRelocationResult::invalid_arguments;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(image);
    for (size_t index = 0; index < relocation_count; ++index) {
        const ModuleRelocation& relocation = relocations[index];
        if (relocation.where > image_size || image_size - relocation.where < sizeof(uintptr_t)) {
            return ModuleRelocationResult::slot_out_of_bounds;
        }
        if (relocation.where < writable_begin || relocation.where > writable_end ||
            writable_end - relocation.where < sizeof(uintptr_t)) {
            return ModuleRelocationResult::slot_not_writable;
        }

        uintptr_t value = 0;
        switch (relocation.kind) {
            case ModuleRelocationKind::relative:
                if (relocation.addend < 0 || static_cast<uint64_t>(relocation.addend) >= image_size) {
                    return ModuleRelocationResult::target_out_of_bounds;
                }
                value = base + static_cast<uintptr_t>(relocation.addend);
                break;
            case ModuleRelocationKind::absolute64:
            case ModuleRelocationKind::glob_dat:
            case ModuleRelocationKind::jump_slot:
                if (!add_signed(relocation.symbol, relocation.addend, value)) {
                    return ModuleRelocationResult::arithmetic_overflow;
                }
                break;
            default:
                return ModuleRelocationResult::unsupported_kind;
        }
        std::memcpy(image + relocation.where, &value, sizeof(value));
    }
    return ModuleRelocationResult::ok;
}

const char* module_relocation_result_name(ModuleRelocationResult result) {
    switch (result) {
        case ModuleRelocationResult::ok: return "ok";
        case ModuleRelocationResult::invalid_arguments: return "invalid_arguments";
        case ModuleRelocationResult::slot_out_of_bounds: return "slot_out_of_bounds";
        case ModuleRelocationResult::slot_not_writable: return "slot_not_writable";
        case ModuleRelocationResult::target_out_of_bounds: return "target_out_of_bounds";
        case ModuleRelocationResult::arithmetic_overflow: return "arithmetic_overflow";
        case ModuleRelocationResult::unsupported_kind: return "unsupported_kind";
        case ModuleRelocationResult::malformed_relr: return "malformed_relr";
    }
    return "unknown";
}

ModuleRelocationResult apply_module_relr(
    uint8_t* image,
    size_t image_size,
    size_t writable_begin,
    size_t writable_end,
    const uint64_t* entries,
    size_t entry_count,
    size_t& applied_count) {
    applied_count = 0;
    if (image == nullptr || (entry_count != 0 && entries == nullptr) ||
        writable_begin > writable_end || writable_end > image_size) {
        return ModuleRelocationResult::invalid_arguments;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(image);

    auto process = [&](bool apply) -> ModuleRelocationResult {
        size_t cursor = 0;
        bool have_cursor = false;
        size_t decoded = 0;
        for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
            const uint64_t entry = entries[entry_index];
            auto process_slot = [&](uint64_t raw_offset) -> ModuleRelocationResult {
                if (raw_offset > std::numeric_limits<size_t>::max()) {
                    return ModuleRelocationResult::slot_out_of_bounds;
                }
                const size_t offset = static_cast<size_t>(raw_offset);
                if ((offset & (sizeof(uintptr_t) - 1)) != 0) {
                    return ModuleRelocationResult::malformed_relr;
                }
                if (offset > image_size || image_size - offset < sizeof(uintptr_t)) {
                    return ModuleRelocationResult::slot_out_of_bounds;
                }
                if (offset < writable_begin || offset > writable_end ||
                    writable_end - offset < sizeof(uintptr_t)) {
                    return ModuleRelocationResult::slot_not_writable;
                }
                uintptr_t addend = 0;
                std::memcpy(&addend, image + offset, sizeof(addend));
                if (addend > std::numeric_limits<uintptr_t>::max() - base) {
                    return ModuleRelocationResult::arithmetic_overflow;
                }
                if (apply) {
                    const uintptr_t value = base + addend;
                    std::memcpy(image + offset, &value, sizeof(value));
                }
                ++decoded;
                return ModuleRelocationResult::ok;
            };

            if ((entry & 1U) == 0) {
                if (entry > std::numeric_limits<size_t>::max()) {
                    return ModuleRelocationResult::slot_out_of_bounds;
                }
                const size_t offset = static_cast<size_t>(entry);
                if (have_cursor && offset < cursor) return ModuleRelocationResult::malformed_relr;
                const ModuleRelocationResult result = process_slot(entry);
                if (result != ModuleRelocationResult::ok) return result;
                cursor = offset + sizeof(uintptr_t);
                have_cursor = true;
                continue;
            }

            if (!have_cursor) return ModuleRelocationResult::malformed_relr;
            for (unsigned bit = 1; bit < 64; ++bit) {
                if ((entry & (UINT64_C(1) << bit)) == 0) continue;
                const size_t delta = static_cast<size_t>(bit - 1) * sizeof(uintptr_t);
                if (cursor > std::numeric_limits<size_t>::max() - delta) {
                    return ModuleRelocationResult::slot_out_of_bounds;
                }
                const ModuleRelocationResult result = process_slot(cursor + delta);
                if (result != ModuleRelocationResult::ok) return result;
            }
            constexpr size_t bitmap_span = 63 * sizeof(uintptr_t);
            if (cursor > std::numeric_limits<size_t>::max() - bitmap_span) {
                return ModuleRelocationResult::slot_out_of_bounds;
            }
            cursor += bitmap_span;
        }
        if (apply) applied_count = decoded;
        return ModuleRelocationResult::ok;
    };

    const ModuleRelocationResult validation = process(false);
    return validation == ModuleRelocationResult::ok ? process(true) : validation;
}

ModuleSymbolResult resolve_module_symbol(
    const ModuleView* modules,
    size_t module_count,
    const char* name,
    uintptr_t& value) {
    value = 0;
    size_t query_length = 0;
    if ((module_count != 0 && modules == nullptr) ||
        !bounded_name_length(name, query_length)) {
        return ModuleSymbolResult::invalid_arguments;
    }

    for (size_t module_index = 0; module_index < module_count; ++module_index) {
        const ModuleView& module = modules[module_index];
        if (module.image == nullptr ||
            (module.export_count != 0 && module.exports == nullptr)) {
            return ModuleSymbolResult::invalid_arguments;
        }
        for (size_t export_index = 0; export_index < module.export_count; ++export_index) {
            const ModuleExport& symbol = module.exports[export_index];
            size_t symbol_length = 0;
            if (!bounded_name_length(symbol.name, symbol_length)) {
                return ModuleSymbolResult::malformed_name;
            }
            if (symbol.defined && symbol.value >= module.image_size) {
                return ModuleSymbolResult::export_out_of_bounds;
            }
        }
    }

    for (size_t module_index = 0; module_index < module_count; ++module_index) {
        const ModuleView& module = modules[module_index];
        for (size_t export_index = 0; export_index < module.export_count; ++export_index) {
            const ModuleExport& symbol = module.exports[export_index];
            if (!symbol.defined) continue;
            size_t symbol_length = 0;
            bounded_name_length(symbol.name, symbol_length);
            if (symbol_length == query_length &&
                std::memcmp(symbol.name, name, query_length) == 0) {
                value = reinterpret_cast<uintptr_t>(module.image) + symbol.value;
                return ModuleSymbolResult::ok;
            }
        }
    }
    return ModuleSymbolResult::not_found;
}

const char* module_symbol_result_name(ModuleSymbolResult result) {
    switch (result) {
        case ModuleSymbolResult::ok: return "ok";
        case ModuleSymbolResult::invalid_arguments: return "invalid_arguments";
        case ModuleSymbolResult::malformed_name: return "malformed_name";
        case ModuleSymbolResult::export_out_of_bounds: return "export_out_of_bounds";
        case ModuleSymbolResult::not_found: return "not_found";
    }
    return "unknown";
}
