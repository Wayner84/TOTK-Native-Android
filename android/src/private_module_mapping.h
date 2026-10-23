#pragma once

#include <cstddef>
#include <cstdint>

#include "private_elf.h"
#include "relocation_stream.h"

class EntryBindingAdmissionCapability;

enum class PrivateModuleMapResult {
    ok,
    invalid_arguments,
    invalid_page_size,
    invalid_geometry,
    open_failed,
    io_failed,
    map_failed,
    protect_failed,
    content_mismatch,
    restore_failed,
};

struct PrivateModuleMapSummary {
    uint64_t segment_count;
    uint64_t image_bytes;
    uint64_t file_bytes;
    uint64_t zero_fill_bytes;
};

PrivateModuleMapResult map_private_module_set_no_execute(
    FILE* const* files, const PrivateModuleSetLayout& layouts,
    const RelocationStreamSummary& stream, uint64_t guest_base, size_t page_size,
    RelocationDestinationModule* destinations, size_t destination_count,
    PrivateModuleMapSummary& summary, const EntryBindingAdmissionCapability& capability);

PrivateModuleMapResult verify_private_module_set_matches_carriers(
    FILE* const* files, const PrivateModuleSetLayout& layouts,
    const RelocationStreamSummary& stream, uint64_t guest_base);

PrivateModuleMapResult seal_private_module_set_read_only(
    const PrivateModuleSetLayout& layouts, const RelocationStreamSummary& stream,
    uint64_t guest_base, size_t page_size);

PrivateModuleMapResult restore_private_module_slots(
    const RelocationStreamSummary& stream, uint64_t guest_base);

const char* private_module_map_result_name(PrivateModuleMapResult result);
