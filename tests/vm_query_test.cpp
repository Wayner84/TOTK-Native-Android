#include "vm_query.h"

#include <cstdio>
#include <cstring>
#include <iostream>

namespace {
int checks = 0;
int failures = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}
}

int main() {
    VmRegion region{};
    expect(parse_vm_map_region("1000-2000 rw-p 00000000 00:00 0\n", region) ==
               VmQueryResult::ok && region.lo == 0x1000 && region.hi == 0x2000 &&
               region.readable && region.writable && !region.executable &&
               region.private_mapping,
           "parse_rw_private");
    expect(parse_vm_map_region("ABC-DEF r-xs 00000000 00:00 0\n", region) ==
               VmQueryResult::ok && region.readable && !region.writable &&
               region.executable && !region.private_mapping,
           "parse_rx_shared_uppercase");
    expect(parse_vm_map_region("1000-2000 rwxp 0 00:00 0\n", region) ==
               VmQueryResult::ok && region.writable && region.executable,
           "parse_reports_writable_executable");
    expect(parse_vm_map_region("1000-2000 rw-z\n", region) == VmQueryResult::invalid_line,
           "reject_bad_sharing");
    expect(parse_vm_map_region("1000-2000 r--", region) == VmQueryResult::invalid_line,
           "reject_truncated_permissions");
    expect(parse_vm_map_region("1000-2000 r--p garbage\n", region) ==
               VmQueryResult::invalid_line,
           "reject_malformed_mandatory_suffix");
    expect(parse_vm_map_region("10000000000000000-10000000000000001 r--p 0 0:0 0\n", region) ==
               VmQueryResult::invalid_line,
           "reject_hex_overflow");

    VmRegion regions[5]{};
    size_t count = 0;
    expect(append_vm_region(regions, 5, count, {0x1000, 0x2000, true, false, true, true}) ==
               VmQueryResult::ok && count == 1,
           "append_first");
    expect(append_vm_region(regions, 5, count, {0x2000, 0x3000, true, false, true, true}) ==
               VmQueryResult::ok && count == 1 && regions[0].hi == 0x3000,
           "merge_adjacent_same_permissions");
    expect(append_vm_region(regions, 5, count, {0x3000, 0x4000, true, true, false, true}) ==
               VmQueryResult::ok && count == 2,
           "preserve_permission_boundary");
    expect(append_vm_region(regions, 5, count, {0x3800, 0x4800, true, false, false, true}) ==
               VmQueryResult::unsorted_range,
           "reject_overlap");
    size_t full_count = 1;
    VmRegion full[1] = {{0x1000, 0x2000, true, false, false, true}};
    expect(append_vm_region(full, 1, full_count,
                            {0x3000, 0x4000, true, false, false, true}) ==
               VmQueryResult::capacity_exceeded,
           "reject_capacity_exhaustion");

    const VmRegion query_regions[] = {
        {0x1000, 0x2000, true, false, true, true},
        {0x3000, 0x4000, true, true, false, true},
        {0x5000, 0x6000, true, false, false, true},
    };
    expect(query_vm_region(query_regions, 3, 0x1800, region) == VmQueryResult::ok &&
               region.lo == 0x1000,
           "query_containing");
    expect(query_vm_region(query_regions, 3, 0x2800, region) == VmQueryResult::ok &&
               region.lo == 0x3000,
           "query_next_region");
    expect(query_vm_region(query_regions, 3, 0x6000, region) == VmQueryResult::no_region,
           "query_after_last");
    const VmRegion malformed_late[] = {
        {0x1000, 0x2000, true, false, true, true},
        {0x1800, 0x3000, true, false, false, true},
    };
    expect(query_vm_region(malformed_late, 2, 0x1000, region) ==
               VmQueryResult::unsorted_range,
           "validate_complete_table_before_answer");

    const char* path = "vm-query-fixture.txt";
    FILE* fixture = std::fopen(path, "w");
    bool fixture_written = false;
    if (fixture != nullptr) {
        const bool wrote = std::fputs(
            "1000-2000 r-xp 00000000 00:00 0\n"
            "2000-3000 r-xp 00000000 00:00 0\n"
            "4000-5000 rw-p 00000000 00:00 0\n",
            fixture) >= 0;
        const bool closed = std::fclose(fixture) == 0;
        fixture_written = wrote && closed;
    }
    VmRegion file_regions[4]{};
    size_t file_count = 0;
    const VmQueryResult file_result = fixture_written
        ? read_vm_regions(path, file_regions, 4, file_count)
        : VmQueryResult::io_error;
    std::remove(path);
    expect(file_result == VmQueryResult::ok && file_count == 2 &&
               file_regions[0].lo == 0x1000 && file_regions[0].hi == 0x3000 &&
               file_regions[1].writable,
           "read_fixture_and_merge");

    fixture = std::fopen(path, "w");
    bool malformed_written = false;
    if (fixture != nullptr) {
        const bool wrote = std::fputs(
            "1000-2000 r--p 00000000 00:00 0\n"
            "malformed late record\n", fixture) >= 0;
        const bool closed = std::fclose(fixture) == 0;
        malformed_written = wrote && closed;
    }
    file_count = 99;
    const VmQueryResult malformed_result = malformed_written
        ? read_vm_regions(path, file_regions, 4, file_count)
        : VmQueryResult::io_error;
    std::remove(path);
    expect(malformed_result == VmQueryResult::invalid_line && file_count == 0,
           "late_malformed_discards_partial_table");

    expect(read_vm_regions(nullptr, file_regions, 4, file_count) ==
               VmQueryResult::invalid_argument && file_count == 0,
           "read_rejects_null_path");

    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
