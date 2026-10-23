#pragma once

#include <cstddef>
#include <cstdint>

struct VmRegion {
    uint64_t lo;
    uint64_t hi;
    bool readable;
    bool writable;
    bool executable;
    bool private_mapping;
};

enum class VmQueryResult {
    ok,
    invalid_argument,
    invalid_line,
    unsorted_range,
    capacity_exceeded,
    no_region,
    io_error,
};

VmQueryResult parse_vm_map_region(const char* line, VmRegion& region);

VmQueryResult append_vm_region(
    VmRegion* regions,
    size_t capacity,
    size_t& count,
    VmRegion region);

// Mirrors mach_vm_region's useful lookup behavior: return the region containing
// address, or the first mapped region after an unmapped address. The complete
// supplied table is validated before any answer is returned.
VmQueryResult query_vm_region(
    const VmRegion* regions,
    size_t count,
    uint64_t address,
    VmRegion& region);

VmQueryResult read_vm_regions(
    const char* path,
    VmRegion* regions,
    size_t capacity,
    size_t& count);

const char* vm_query_result_name(VmQueryResult result);
