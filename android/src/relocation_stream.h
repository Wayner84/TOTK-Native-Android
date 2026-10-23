#pragma once

#include <cstddef>
#include <cstdint>

constexpr size_t relocation_stream_max_modules = 16;

enum class RelocationStreamResult {
    ok,
    invalid_arguments,
    open_failed,
    io_failed,
    invalid_file_size,
    unsupported_format,
    invalid_structure,
    invalid_count,
    incompatible_layout,
    invalid_descriptor,
    invalid_geometry,
    invalid_record,
    unsupported_kind,
    unsupported_source,
    invalid_target,
    invalid_provider,
    invalid_operands,
    arithmetic_out_of_range,
    invalid_destination_geometry,
    invalid_destination_state,
    resource_limit,
    allocation_failed,
    injected_failure,
};

struct RelocationStreamModuleDescriptor {
    uint64_t guest_offset;
    uint64_t image_size;
    uint64_t writable_begin;
    uint64_t writable_end;
    uint64_t record_count;
};

struct RelocationStreamSummary {
    uint64_t file_bytes;
    uint64_t module_count;
    uint64_t record_count;
    uint64_t abs64_count;
    uint64_t glob_dat_count;
    uint64_t jump_slot_count;
    uint64_t relative_count;
    uint64_t rela_count;
    uint64_t relr_count;
    RelocationStreamModuleDescriptor modules[relocation_stream_max_modules];
};

// The caller must exclusively own every destination for the duration of apply.
// Relocations are accepted only while complete images are mapped writable and
// non-executable; descriptor geometry must exactly match the stream.
struct RelocationDestinationModule {
    uint8_t* image;
    uint64_t guest_offset;
    uint64_t image_size;
    uint64_t writable_begin;
    uint64_t writable_end;
    bool mapped;
    bool writable;
    bool executable;
};

struct RelocationApplyOptions {
    uint64_t max_records = UINT64_C(1000000);
    uint64_t max_journal_bytes = UINT64_C(32) * 1024 * 1024;
    // UINT64_MAX disables failure injection. Other values are synthetic-only.
    uint64_t fail_after_writes = UINT64_MAX;
};

struct RelocationApplySummary {
    RelocationStreamSummary stream;
    uint64_t writes_committed;
    uint64_t writes_rolled_back;
};

RelocationStreamResult validate_relocation_stream(const char* path,
                                                  RelocationStreamSummary& summary);
RelocationStreamResult apply_relocation_stream_transactional(
    const char* path, uint64_t guest_base, RelocationDestinationModule* modules,
    size_t module_count, const RelocationApplyOptions& options,
    RelocationApplySummary& summary);
const char* relocation_stream_result_name(RelocationStreamResult result);
