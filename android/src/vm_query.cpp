#include "vm_query.h"

#include <cctype>
#include <cstdio>
#include <cstring>
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

bool parse_decimal(const char*& cursor, uint64_t& value) {
    value = 0;
    size_t digits = 0;
    while (*cursor >= '0' && *cursor <= '9') {
        const unsigned digit = static_cast<unsigned>(*cursor - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
        ++cursor;
        ++digits;
    }
    return digits != 0;
}

void skip_space(const char*& cursor) {
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
}

bool same_permissions(const VmRegion& left, const VmRegion& right) {
    return left.readable == right.readable && left.writable == right.writable &&
           left.executable == right.executable &&
           left.private_mapping == right.private_mapping;
}

bool valid_region(const VmRegion& region) {
    return region.lo < region.hi;
}

}  // namespace

VmQueryResult parse_vm_map_region(const char* line, VmRegion& region) {
    if (line == nullptr) return VmQueryResult::invalid_argument;
    const char* cursor = line;
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (!parse_hex(cursor, lo) || *cursor++ != '-' || !parse_hex(cursor, hi) ||
        !std::isspace(static_cast<unsigned char>(*cursor)) || lo >= hi) {
        return VmQueryResult::invalid_line;
    }
    skip_space(cursor);
    if (std::strlen(cursor) < 5) return VmQueryResult::invalid_line;
    const char r = cursor[0];
    const char w = cursor[1];
    const char x = cursor[2];
    const char sharing = cursor[3];
    if (!((r == 'r') || (r == '-')) || !((w == 'w') || (w == '-')) ||
        !((x == 'x') || (x == '-')) || !((sharing == 'p') || (sharing == 's')) ||
        !std::isspace(static_cast<unsigned char>(cursor[4]))) {
        return VmQueryResult::invalid_line;
    }
    cursor += 5;
    skip_space(cursor);
    uint64_t offset = 0;
    uint64_t device_major = 0;
    uint64_t device_minor = 0;
    uint64_t inode = 0;
    if (!parse_hex(cursor, offset) || !std::isspace(static_cast<unsigned char>(*cursor))) {
        return VmQueryResult::invalid_line;
    }
    skip_space(cursor);
    if (!parse_hex(cursor, device_major) || *cursor++ != ':' ||
        !parse_hex(cursor, device_minor) ||
        !std::isspace(static_cast<unsigned char>(*cursor))) {
        return VmQueryResult::invalid_line;
    }
    skip_space(cursor);
    if (!parse_decimal(cursor, inode) ||
        (*cursor != '\0' && *cursor != '\n' &&
         !std::isspace(static_cast<unsigned char>(*cursor)))) {
        return VmQueryResult::invalid_line;
    }
    (void)offset;
    (void)device_major;
    (void)device_minor;
    (void)inode;
    region = {lo, hi, r == 'r', w == 'w', x == 'x', sharing == 'p'};
    return valid_region(region) ? VmQueryResult::ok : VmQueryResult::invalid_line;
}

VmQueryResult append_vm_region(
    VmRegion* regions,
    size_t capacity,
    size_t& count,
    VmRegion region) {
    if (regions == nullptr || count > capacity || !valid_region(region)) {
        return VmQueryResult::invalid_argument;
    }
    if (count != 0) {
        VmRegion& previous = regions[count - 1];
        if (region.lo < previous.hi) return VmQueryResult::unsorted_range;
        if (region.lo == previous.hi && same_permissions(previous, region)) {
            previous.hi = region.hi;
            return VmQueryResult::ok;
        }
    }
    if (count == capacity) return VmQueryResult::capacity_exceeded;
    regions[count++] = region;
    return VmQueryResult::ok;
}

VmQueryResult query_vm_region(
    const VmRegion* regions,
    size_t count,
    uint64_t address,
    VmRegion& region) {
    if ((count != 0 && regions == nullptr)) return VmQueryResult::invalid_argument;
    for (size_t index = 0; index < count; ++index) {
        if (!valid_region(regions[index]) ||
            (index != 0 && regions[index].lo < regions[index - 1].hi)) {
            return VmQueryResult::unsorted_range;
        }
    }
    for (size_t index = 0; index < count; ++index) {
        if (address < regions[index].hi) {
            region = regions[index];
            return VmQueryResult::ok;
        }
    }
    return VmQueryResult::no_region;
}

VmQueryResult read_vm_regions(
    const char* path,
    VmRegion* regions,
    size_t capacity,
    size_t& count) {
    count = 0;
    if (path == nullptr || regions == nullptr || capacity == 0) {
        return VmQueryResult::invalid_argument;
    }
    FILE* maps = std::fopen(path, "r");
    if (maps == nullptr) return VmQueryResult::io_error;
    char line[4096];
    VmQueryResult result = VmQueryResult::ok;
    while (std::fgets(line, sizeof(line), maps) != nullptr) {
        if (std::strchr(line, '\n') == nullptr && std::feof(maps) == 0) {
            result = VmQueryResult::invalid_line;
            break;
        }
        VmRegion region{};
        result = parse_vm_map_region(line, region);
        if (result != VmQueryResult::ok) break;
        result = append_vm_region(regions, capacity, count, region);
        if (result != VmQueryResult::ok) break;
    }
    if (std::ferror(maps) != 0) result = VmQueryResult::io_error;
    if (std::fclose(maps) != 0 && result == VmQueryResult::ok) result = VmQueryResult::io_error;
    if (result != VmQueryResult::ok) count = 0;
    return result;
}

const char* vm_query_result_name(VmQueryResult result) {
    switch (result) {
        case VmQueryResult::ok: return "ok";
        case VmQueryResult::invalid_argument: return "invalid_argument";
        case VmQueryResult::invalid_line: return "invalid_line";
        case VmQueryResult::unsorted_range: return "unsorted_range";
        case VmQueryResult::capacity_exceeded: return "capacity_exceeded";
        case VmQueryResult::no_region: return "no_region";
        case VmQueryResult::io_error: return "io_error";
    }
    return "unknown";
}
