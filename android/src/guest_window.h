#pragma once

#include <cstddef>
#include <cstdint>

struct GuestAddressRange {
    uint64_t lo;
    uint64_t hi;
};

enum class GuestMapResult {
    ok,
    invalid_argument,
    invalid_line,
    unsorted_range,
    capacity_exceeded,
    no_hole,
};

GuestMapResult parse_guest_map_line(const char* line, GuestAddressRange& range);

GuestMapResult append_guest_map_range(
    GuestAddressRange* ranges,
    size_t capacity,
    size_t& count,
    GuestAddressRange range);

GuestMapResult find_guest_window(
    const GuestAddressRange* ranges,
    size_t count,
    uint64_t floor,
    uint64_t ceiling,
    uint64_t size,
    uint64_t alignment,
    uint64_t& base);

const char* guest_map_result_name(GuestMapResult result);
