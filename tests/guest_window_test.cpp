#include "guest_window.h"

#include <cstdint>
#include <iostream>

namespace {

int failures = 0;
int checks = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

}  // namespace

int main() {
    GuestAddressRange range{};
    expect(parse_guest_map_line("1000-2000 rw-p 0 00:00 0\n", range) == GuestMapResult::ok &&
               range.lo == 0x1000 && range.hi == 0x2000,
           "parse_valid");
    expect(parse_guest_map_line("ABC-DEF r--p 0 00:00 0", range) == GuestMapResult::ok &&
               range.lo == 0xabc && range.hi == 0xdef,
           "parse_uppercase");
    expect(parse_guest_map_line("1000-2000", range) == GuestMapResult::invalid_line,
           "parse_requires_suffix_separator");
    expect(parse_guest_map_line("1000-1000 r--p", range) == GuestMapResult::invalid_line,
           "parse_rejects_empty_range");
    expect(parse_guest_map_line("10000000000000000-10000000000000001 r--p", range) ==
               GuestMapResult::invalid_line,
           "parse_rejects_overflow");

    GuestAddressRange ranges[4]{};
    size_t count = 0;
    expect(append_guest_map_range(ranges, 4, count, {0x1000, 0x2000}) == GuestMapResult::ok && count == 1,
           "append_first");
    expect(append_guest_map_range(ranges, 4, count, {0x2000, 0x3000}) == GuestMapResult::ok &&
               count == 1 && ranges[0].hi == 0x3000,
           "append_merges_adjacent");
    expect(append_guest_map_range(ranges, 4, count, {0x2800, 0x4000}) == GuestMapResult::ok &&
               count == 1 && ranges[0].hi == 0x4000,
           "append_merges_overlap");
    expect(append_guest_map_range(ranges, 4, count, {0x0800, 0x0900}) == GuestMapResult::unsorted_range,
           "append_rejects_unsorted");

    const GuestAddressRange maps[] = {
        {0x100000000ULL, 0x180000000ULL},
        {0x200000000ULL, 0x280000000ULL},
        {0x600000000ULL, 0x700000000ULL},
    };
    uint64_t base = 0;
    expect(find_guest_window(maps, 3, 0x100000000ULL, 0x800000000ULL,
                             0x100000000ULL, 0x100000000ULL, base) == GuestMapResult::ok &&
               base == 0x300000000ULL,
           "find_aligned_hole");
    expect(find_guest_window(maps, 3, 0x100000000ULL, 0x800000000ULL,
                             0x500000000ULL, 0x100000000ULL, base) == GuestMapResult::no_hole,
           "find_no_hole");
    expect(find_guest_window(maps, 3, 0x100000000ULL, 0x800000000ULL,
                             0x1000ULL, 3, base) == GuestMapResult::invalid_argument,
           "find_rejects_non_power_of_two_alignment");
    const GuestAddressRange unsorted[] = {{0x3000, 0x4000}, {0x2000, 0x2800}};
    expect(find_guest_window(unsorted, 2, 0x1000, 0x8000, 0x1000, 0x1000, base) ==
               GuestMapResult::unsorted_range,
           "find_rejects_unsorted");

    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
