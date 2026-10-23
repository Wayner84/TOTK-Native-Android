#include "relocation_stream.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kGuestWindow = UINT64_C(0x320000000);
constexpr uint64_t kSlotSize = UINT64_C(0x10000000);
constexpr uint64_t kLayoutStart = UINT64_C(0x10000000);
constexpr size_t kHeaderSize = 64;
constexpr size_t kModuleSize = 48;
constexpr size_t kRecordSize = 32;
constexpr size_t kModuleCount = 2;
constexpr size_t kRecordsOffset = kHeaderSize + kModuleCount * kModuleSize;

int checks = 0;
int failures = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

template <typename T>
void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    for (size_t index = 0; index < sizeof(T); ++index) {
        bytes[offset + index] = static_cast<uint8_t>(value & 0xffU);
        value = static_cast<T>(value >> 8U);
    }
}

void put_i64(std::vector<uint8_t>& bytes, size_t offset, int64_t value) {
    put<uint64_t>(bytes, offset, static_cast<uint64_t>(value));
}

void put_module(std::vector<uint8_t>& bytes, size_t index, uint32_t id,
                uint64_t guest_offset, uint64_t image_size, uint64_t writable_begin,
                uint64_t writable_end, uint64_t records) {
    const size_t offset = kHeaderSize + index * kModuleSize;
    put<uint32_t>(bytes, offset, id);
    put<uint32_t>(bytes, offset + 4, 0);
    put<uint64_t>(bytes, offset + 8, guest_offset);
    put<uint64_t>(bytes, offset + 16, image_size);
    put<uint64_t>(bytes, offset + 24, writable_begin);
    put<uint64_t>(bytes, offset + 32, writable_end);
    put<uint64_t>(bytes, offset + 40, records);
}

void put_record(std::vector<uint8_t>& bytes, size_t index, uint64_t target,
                uint32_t kind, uint8_t source, uint8_t provider,
                uint64_t symbol, int64_t addend) {
    const size_t offset = kRecordsOffset + index * kRecordSize;
    put<uint64_t>(bytes, offset, target);
    put<uint32_t>(bytes, offset + 8, kind);
    bytes[offset + 12] = source;
    bytes[offset + 13] = provider;
    put<uint16_t>(bytes, offset + 14, 0);
    put<uint64_t>(bytes, offset + 16, symbol);
    put_i64(bytes, offset + 24, addend);
}

std::vector<uint8_t> valid_fixture() {
    std::vector<uint8_t> bytes(kRecordsOffset + 4 * kRecordSize);
    const char magic[] = "TOTKRLP1";
    for (size_t index = 0; index < 8; ++index) bytes[index] = static_cast<uint8_t>(magic[index]);
    put<uint32_t>(bytes, 8, 1);
    put<uint32_t>(bytes, 12, kHeaderSize);
    put<uint32_t>(bytes, 16, kModuleSize);
    put<uint32_t>(bytes, 20, kRecordSize);
    put<uint64_t>(bytes, 24, kModuleCount);
    put<uint64_t>(bytes, 32, 4);
    put<uint64_t>(bytes, 40, kGuestWindow);
    put<uint64_t>(bytes, 48, kSlotSize);
    put<uint64_t>(bytes, 56, kLayoutStart);
    put_module(bytes, 0, 0, 0x10000000, 0x3000, 0x2000, 0x2100, 1);
    put_module(bytes, 1, 1, 0x20000000, 0x3000, 0x2000, 0x2100, 3);
    put_record(bytes, 0, 0x2000, 1027, 2, 0, 0, 0x10);
    put_record(bytes, 1, 0x2000, 257, 1, 0, 0x20, 4);
    put_record(bytes, 2, 0x2008, 1025, 1, 0xff, 0, 0);
    put_record(bytes, 3, 0x2010, 1026, 1, 1, 0x28, 0);
    return bytes;
}

void write_bytes(const char* path, const std::vector<uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) std::abort();
}

RelocationStreamResult validate(const char* path, const std::vector<uint8_t>& bytes,
                                RelocationStreamSummary* summary = nullptr) {
    write_bytes(path, bytes);
    RelocationStreamSummary local{};
    return validate_relocation_stream(path, summary == nullptr ? local : *summary);
}

void expect_invalid(const char* path, std::vector<uint8_t> bytes,
                    RelocationStreamResult expected, const char* name) {
    expect(validate(path, bytes) == expected, name);
}

}  // namespace

int main(int argc, char** argv) {
    const char* path = "build/host-tests/relocation_stream_fixture.bin";
    auto bytes = valid_fixture();
    RelocationStreamSummary summary{};
    expect(validate(path, bytes, &summary) == RelocationStreamResult::ok &&
               summary.file_bytes == bytes.size() && summary.module_count == 2 &&
               summary.record_count == 4 && summary.abs64_count == 1 &&
               summary.glob_dat_count == 1 && summary.jump_slot_count == 1 &&
               summary.relative_count == 1 && summary.rela_count == 3 &&
               summary.relr_count == 1 &&
               summary.modules[0].guest_offset == 0x10000000 &&
               summary.modules[0].image_size == 0x3000 &&
               summary.modules[1].writable_begin == 0x2000 &&
               summary.modules[1].writable_end == 0x2100,
           "valid_stream_numeric_summary");
    expect(validate_relocation_stream(nullptr, summary) == RelocationStreamResult::invalid_arguments,
           "reject_null_path");
    expect(validate_relocation_stream("build/host-tests/missing-relocation-stream.bin", summary) ==
               RelocationStreamResult::open_failed,
           "report_open_failure");

    bytes = valid_fixture(); bytes[0] = 'X';
    expect_invalid(path, bytes, RelocationStreamResult::unsupported_format, "reject_magic");
    bytes = valid_fixture(); put<uint32_t>(bytes, 8, 2);
    expect_invalid(path, bytes, RelocationStreamResult::unsupported_format, "reject_version");
    bytes = valid_fixture(); put<uint32_t>(bytes, 12, 63);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_structure, "reject_header_size");
    bytes = valid_fixture(); put<uint32_t>(bytes, 16, 47);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_structure, "reject_descriptor_size");
    bytes = valid_fixture(); put<uint32_t>(bytes, 20, 31);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_structure, "reject_record_size");
    bytes = valid_fixture(); put<uint64_t>(bytes, 24, 0);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_count, "reject_zero_modules");
    bytes = valid_fixture(); put<uint64_t>(bytes, 24, 17);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_count, "reject_too_many_modules");
    bytes = valid_fixture(); put<uint64_t>(bytes, 32, UINT64_MAX);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_count, "reject_record_count_overflow");
    bytes = valid_fixture(); put<uint64_t>(bytes, 40, kGuestWindow + 1);
    expect_invalid(path, bytes, RelocationStreamResult::incompatible_layout, "reject_guest_window_constant");
    bytes = valid_fixture(); put<uint64_t>(bytes, 48, kSlotSize + 1);
    expect_invalid(path, bytes, RelocationStreamResult::incompatible_layout, "reject_slot_constant");
    bytes = valid_fixture(); put<uint64_t>(bytes, 56, kLayoutStart + 1);
    expect_invalid(path, bytes, RelocationStreamResult::incompatible_layout, "reject_layout_start_constant");
    bytes = valid_fixture(); bytes.pop_back();
    expect_invalid(path, bytes, RelocationStreamResult::invalid_file_size, "reject_truncation");
    bytes = valid_fixture(); bytes.push_back(0);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_file_size, "reject_trailing_byte");

    bytes = valid_fixture(); put<uint32_t>(bytes, kHeaderSize, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_descriptor, "reject_nonsequential_module_id");
    bytes = valid_fixture(); put<uint32_t>(bytes, kHeaderSize + 4, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_descriptor, "reject_descriptor_reserved");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 8, 0x11000000);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_geometry, "reject_guest_offset");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 16, 0);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_geometry, "reject_zero_image");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 16, kSlotSize + 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_geometry, "reject_image_over_slot");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 24, 0x2100);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_geometry, "reject_empty_writable_range");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 32, 0x3001);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_geometry, "reject_writable_end_over_image");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 40, 4000001);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_count, "reject_module_record_bound");
    bytes = valid_fixture(); put<uint64_t>(bytes, kHeaderSize + 40, 2);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_count, "reject_descriptor_total_mismatch");

    bytes = valid_fixture(); put<uint16_t>(bytes, kRecordsOffset + 14, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_record, "reject_record_reserved");
    bytes = valid_fixture(); put<uint32_t>(bytes, kRecordsOffset + 8, 999);
    expect_invalid(path, bytes, RelocationStreamResult::unsupported_kind, "reject_kind");
    bytes = valid_fixture(); bytes[kRecordsOffset + 12] = 3;
    expect_invalid(path, bytes, RelocationStreamResult::unsupported_source, "reject_source");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset, 0x2001);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_target, "reject_unaligned_target");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset, 0x1ff8);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_target, "reject_nonwritable_target");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset + kRecordSize * 2, 0x2000);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_target, "reject_duplicate_target");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset + kRecordSize * 3, 0x2000);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_target, "reject_unsorted_target");

    bytes = valid_fixture(); bytes[kRecordsOffset + 13] = 1;
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_relative_provider");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset + 16, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_relative_symbol");
    bytes = valid_fixture(); put_i64(bytes, kRecordsOffset + 24, -1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_relative_negative_addend");
    bytes = valid_fixture(); put_i64(bytes, kRecordsOffset + 24, 0x3000);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_relative_addend_over_image");
    bytes = valid_fixture(); bytes[kRecordsOffset + kRecordSize + 12] = 2;
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_symbolic_relr_source");
    bytes = valid_fixture(); bytes[kRecordsOffset + kRecordSize + 13] = 2;
    expect_invalid(path, bytes, RelocationStreamResult::invalid_provider, "reject_provider_out_of_range");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset + kRecordSize + 16, 0x3000);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_symbol_outside_provider");
    bytes = valid_fixture(); put<uint64_t>(bytes, kRecordsOffset + kRecordSize * 2 + 16, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_weak_zero_symbol");
    bytes = valid_fixture(); put_i64(bytes, kRecordsOffset + kRecordSize * 3 + 24, 1);
    expect_invalid(path, bytes, RelocationStreamResult::invalid_operands, "reject_jump_slot_addend");
    bytes = valid_fixture(); put_i64(bytes, kRecordsOffset + kRecordSize + 24,
                                     -static_cast<int64_t>(kLayoutStart) - 0x21);
    expect_invalid(path, bytes, RelocationStreamResult::arithmetic_out_of_range,
                   "reject_symbolic_guest_underflow");
    bytes = valid_fixture(); put_i64(bytes, kRecordsOffset + kRecordSize + 24,
                                     std::numeric_limits<int64_t>::max());
    expect_invalid(path, bytes, RelocationStreamResult::arithmetic_out_of_range,
                   "reject_symbolic_guest_overflow");

    constexpr uint64_t synthetic_guest_base = UINT64_C(0x100000000);
    std::array<std::vector<uint8_t>, kModuleCount> images = {
        std::vector<uint8_t>(0x3000, 0x5a),
        std::vector<uint8_t>(0x3000, 0xa5),
    };
    const auto reset_images = [&images] {
        std::fill(images[0].begin(), images[0].end(), 0x5a);
        std::fill(images[1].begin(), images[1].end(), 0xa5);
    };
    const auto destinations = [&images] {
        return std::array<RelocationDestinationModule, kModuleCount>{
            RelocationDestinationModule{images[0].data(), 0x10000000, 0x3000,
                                        0x2000, 0x2100, true, true, false},
            RelocationDestinationModule{images[1].data(), 0x20000000, 0x3000,
                                        0x2000, 0x2100, true, true, false},
        };
    };
    const auto read_value = [&images](size_t module, size_t offset) {
        uint64_t value = 0;
        std::memcpy(&value, images[module].data() + offset, sizeof(value));
        return value;
    };
    RelocationApplyOptions options{};
    RelocationApplySummary apply_summary{};
    bytes = valid_fixture();
    write_bytes(path, bytes);
    auto modules = destinations();
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::ok &&
               apply_summary.writes_committed == 4 &&
               apply_summary.writes_rolled_back == 0 &&
               read_value(0, 0x2000) == synthetic_guest_base + 0x10000000 + 0x10 &&
               read_value(1, 0x2000) == synthetic_guest_base + 0x10000000 + 0x24 &&
               read_value(1, 0x2008) == 0 &&
               read_value(1, 0x2010) == synthetic_guest_base + 0x20000000 + 0x28,
           "transactional_apply_valid_stream");

    reset_images();
    const auto before_late_invalid = images;
    bytes = valid_fixture();
    put_i64(bytes, kRecordsOffset + kRecordSize * 3 + 24, 1);
    write_bytes(path, bytes);
    modules = destinations();
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::invalid_operands &&
               images == before_late_invalid && apply_summary.writes_committed == 0 &&
               apply_summary.writes_rolled_back == 0,
           "late_invalid_record_writes_nothing");

    reset_images();
    const auto before_injected_failure = images;
    bytes = valid_fixture();
    write_bytes(path, bytes);
    modules = destinations();
    options.fail_after_writes = 3;
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::injected_failure &&
               images == before_injected_failure && apply_summary.writes_committed == 0 &&
               apply_summary.writes_rolled_back == 3,
           "late_commit_failure_rolls_back_bit_identical");

    reset_images();
    const auto before_resource_limit = images;
    options = {};
    options.max_records = 3;
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::resource_limit &&
               images == before_resource_limit,
           "reject_apply_record_limit_before_write");

    options = {};
    options.max_journal_bytes = 4 * sizeof(uint64_t);
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::resource_limit &&
               images == before_resource_limit,
           "reject_apply_journal_byte_limit_before_write");

    options = {};
    modules = destinations();
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, UINT64_MAX,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::arithmetic_out_of_range &&
               images == before_resource_limit,
           "reject_guest_base_overflow_before_write");

    modules = destinations();
    modules[1].executable = true;
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::invalid_destination_state,
           "reject_executable_destination_before_write");

    modules = destinations();
    modules[1].writable_end -= 8;
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::invalid_destination_geometry,
           "reject_destination_geometry_mismatch_before_write");

    modules = destinations();
    modules[1].image = modules[0].image;
    apply_summary = {};
    expect(apply_relocation_stream_transactional(path, synthetic_guest_base,
                                                 modules.data(), modules.size(),
                                                 options, apply_summary) ==
               RelocationStreamResult::invalid_destination_geometry &&
               images == before_resource_limit,
           "reject_overlapping_destination_images_before_write");

    std::remove(path);
    if (argc == 2) {
        RelocationStreamSummary private_summary{};
        const RelocationStreamResult result =
            validate_relocation_stream(argv[1], private_summary);
        expect(result == RelocationStreamResult::ok, "supplied_stream_validate_only");
        std::cout << "supplied_summary modules=" << private_summary.module_count
                  << " records=" << private_summary.record_count
                  << " bytes=" << private_summary.file_bytes
                  << " abs64=" << private_summary.abs64_count
                  << " glob_dat=" << private_summary.glob_dat_count
                  << " jump_slot=" << private_summary.jump_slot_count
                  << " relative=" << private_summary.relative_count
                  << " rela=" << private_summary.rela_count
                  << " relr=" << private_summary.relr_count
                  << " relocation=not_applied mapped_bytes=not_touched"
                  << " execution=not_attempted\n";
    } else if (argc != 1) {
        std::cerr << "usage: relocation_stream_test [private-stream]\n";
        return 2;
    }
    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
