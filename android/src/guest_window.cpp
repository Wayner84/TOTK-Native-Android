#include "guest_window.h"

#include <cctype>
#include <limits>

namespace {

bool parse_hex(const char*& cursor, uint64_t& value) {
    value = 0;
    size_t digits = 0;
    while (*cursor != '\0') {
        unsigned digit = 0;
        if (*cursor >= '0' && *cursor <= '9') digit = static_cast<unsigned>(*cursor - '0');
        else if (*cursor >= 'a' && *cursor <= 'f') digit = static_cast<unsigned>(*cursor - 'a' + 10);
        else if (*cursor >= 'A' && *cursor <= 'F') digit = static_cast<unsigned>(*cursor - 'A' + 10);
        else break;
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 16) return false;
        value = value * 16 + digit;
        ++cursor;
        ++digits;
    }
    return digits != 0;
}

bool is_power_of_two(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

bool align_up(uint64_t value, uint64_t alignment, uint64_t& result) {
    const uint64_t mask = alignment - 1;
    if (value > std::numeric_limits<uint64_t>::max() - mask) return false;
    result = (value + mask) & ~mask;
    return true;
}

}  // namespace

GuestMapResult parse_guest_map_line(const char* line, GuestAddressRange& range) {
    if (line == nullptr) return GuestMapResult::invalid_argument;
    const char* cursor = line;
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (!parse_hex(cursor, lo) || *cursor++ != '-' || !parse_hex(cursor, hi) ||
        !std::isspace(static_cast<unsigned char>(*cursor)) || lo >= hi) {
        return GuestMapResult::invalid_line;
    }
    range = {lo, hi};
    return GuestMapResult::ok;
}

GuestMapResult append_guest_map_range(
    GuestAddressRange* ranges,
    size_t capacity,
    size_t& count,
    GuestAddressRange range) {
    if (ranges == nullptr || range.lo >= range.hi || count > capacity) {
        return GuestMapResult::invalid_argument;
    }
    if (count != 0) {
        GuestAddressRange& previous = ranges[count - 1];
        if (range.lo < previous.lo) return GuestMapResult::unsorted_range;
        if (range.lo <= previous.hi) {
            if (range.hi > previous.hi) previous.hi = range.hi;
            return GuestMapResult::ok;
        }
    }
    if (count == capacity) return GuestMapResult::capacity_exceeded;
    ranges[count++] = range;
    return GuestMapResult::ok;
}

GuestMapResult find_guest_window(
    const GuestAddressRange* ranges,
    size_t count,
    uint64_t floor,
    uint64_t ceiling,
    uint64_t size,
    uint64_t alignment,
    uint64_t& base) {
    base = 0;
    if ((count != 0 && ranges == nullptr) || floor >= ceiling || size == 0 ||
        size > ceiling - floor || !is_power_of_two(alignment)) {
        return GuestMapResult::invalid_argument;
    }

    for (size_t index = 0; index < count; ++index) {
        if (ranges[index].lo >= ranges[index].hi ||
            (index != 0 && ranges[index].lo < ranges[index - 1].hi)) {
            return GuestMapResult::unsorted_range;
        }
    }

    uint64_t cursor = floor;
    for (size_t index = 0; index <= count; ++index) {
        uint64_t next = ceiling;
        if (index < count) {
            const GuestAddressRange range = ranges[index];
            if (range.hi <= floor) continue;
            if (range.lo < ceiling) next = range.lo;
        }

        uint64_t candidate = 0;
        if (align_up(cursor, alignment, candidate) && candidate <= next && size <= next - candidate) {
            base = candidate;
            return GuestMapResult::ok;
        }
        if (index < count && ranges[index].hi > cursor) cursor = ranges[index].hi;
        if (cursor >= ceiling) break;
    }
    return GuestMapResult::no_hole;
}

const char* guest_map_result_name(GuestMapResult result) {
    switch (result) {
        case GuestMapResult::ok: return "ok";
        case GuestMapResult::invalid_argument: return "invalid_argument";
        case GuestMapResult::invalid_line: return "invalid_line";
        case GuestMapResult::unsorted_range: return "unsorted_range";
        case GuestMapResult::capacity_exceeded: return "capacity_exceeded";
        case GuestMapResult::no_hole: return "no_hole";
    }
    return "unknown";
}
