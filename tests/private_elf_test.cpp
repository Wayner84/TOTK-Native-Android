#include "private_elf.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void expect(bool condition, const char* name) {
    ++checks;
    std::cout << "test=" << name << " result=" << (condition ? "PASS" : "FAIL") << '\n';
    if (!condition) ++failures;
}

template <typename T>
void put(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

struct Program {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
};

std::vector<uint8_t> fixture() {
    std::vector<uint8_t> bytes(0x3800);
    const std::array<unsigned char, 16> ident = {
        0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::memcpy(bytes.data(), ident.data(), ident.size());
    const uint16_t type = 3;
    const uint16_t machine = 183;
    const uint32_t version = 1;
    const uint64_t entry = 0;
    const uint64_t phoff = 64;
    const uint16_t ehsize = 64;
    const uint16_t phentsize = 56;
    const uint16_t phnum = 3;
    put(bytes, 16, type);
    put(bytes, 18, machine);
    put(bytes, 20, version);
    put(bytes, 24, entry);
    put(bytes, 32, phoff);
    put(bytes, 52, ehsize);
    put(bytes, 54, phentsize);
    put(bytes, 56, phnum);
    const Program programs[] = {
        {1, 5, 0x1000, 0x0000, 0, 0x1000, 0x1000, 4096},
        {1, 4, 0x2000, 0x2000, 0, 0x1000, 0x1000, 4096},
        {1, 6, 0x3000, 0x4000, 0, 0x0800, 0x1000, 4096},
    };
    for (size_t index = 0; index < std::size(programs); ++index) {
        put(bytes, 64 + index * sizeof(Program), programs[index]);
    }
    return bytes;
}

void write_fixture(const char* path, const std::vector<uint8_t>& bytes) {
    FILE* output = std::fopen(path, "wb");
    if (output == nullptr || std::fwrite(bytes.data(), 1, bytes.size(), output) != bytes.size() ||
        std::fclose(output) != 0) {
        std::abort();
    }
}

}  // namespace

int main() {
    const char* path = "build/host-tests/private_elf_fixture.bin";
    const std::array<const char*, private_module_count> module_paths = {
        path, path, path,
    };

    auto bytes = fixture();
    write_fixture(path, bytes);
    PrivateElfLayout layout{};
    expect(inspect_private_elf(path, 0x10000000, layout) ==
               PrivateElfResult::ok && layout.segment_count == 3 &&
               layout.image_size == 0x5000 && layout.segments[2].memory_size == 0x1000,
           "valid_analysis_elf");

    bytes = fixture();
    const uint16_t wrong_machine = 62;
    put(bytes, 18, wrong_machine);
    write_fixture(path, bytes);
    expect(inspect_private_elf(path, 0x10000000, layout) ==
               PrivateElfResult::invalid_header,
           "reject_wrong_machine");

    bytes = fixture();
    const uint64_t bad_offset = 0x4000;
    put(bytes, 64 + 2 * sizeof(Program) + 8, bad_offset);
    write_fixture(path, bytes);
    expect(inspect_private_elf(path, 0x10000000, layout) ==
               PrivateElfResult::invalid_segment,
           "reject_file_bounds");

    bytes = fixture();
    const uint64_t overlap_address = 0x0800;
    put(bytes, 64 + sizeof(Program) + 16, overlap_address);
    write_fixture(path, bytes);
    expect(inspect_private_elf(path, 0x10000000, layout) ==
               PrivateElfResult::invalid_segment,
           "reject_alignment_mismatch");

    bytes = fixture();
    const uint32_t writable_text = 7;
    put(bytes, 64 + 4, writable_text);
    write_fixture(path, bytes);
    expect(inspect_private_elf(path, 0x10000000, layout) ==
               PrivateElfResult::unsupported_layout,
           "reject_writable_executable_text");

    bytes = fixture();
    write_fixture(path, bytes);
    const std::array<PrivateModuleDescriptor, private_module_count> descriptors = {{
        {0x10000000, 0x5000, 0x4000, 0x5000},
        {0x20000000, 0x5000, 0x4000, 0x5000},
        {0x30000000, 0x5000, 0x4000, 0x5000},
    }};
    PrivateModuleSetLayout set{};
    expect(inspect_private_elf_set(module_paths.data(), module_paths.size(),
                                   descriptors.data(), descriptors.size(),
                                   0x320000000, 0x10000000, set) ==
               PrivateElfResult::ok && set.module_count == private_module_count &&
               set.total_image_size == 0xf000 && set.total_file_bytes == 0x7800 &&
               set.total_zero_fill == 0x1800,
           "valid_three_module_set_geometry");
    std::array<FILE*, private_module_count> module_files = {
        std::fopen(path, "rb"), std::fopen(path, "rb"), std::fopen(path, "rb"),
    };
    const bool files_open = module_files[0] != nullptr && module_files[1] != nullptr &&
                            module_files[2] != nullptr;
    expect(files_open &&
               inspect_private_elf_file_set(module_files.data(), module_files.size(),
                                             descriptors.data(), descriptors.size(),
                                             0x320000000, 0x10000000, set) ==
                   PrivateElfResult::ok,
           "valid_three_module_open_file_set");
    for (FILE* file : module_files) {
        if (file != nullptr) std::fclose(file);
    }
    expect(inspect_private_elf_set(module_paths.data(), 2, descriptors.data(),
                                   descriptors.size(), 0x320000000, 0x10000000, set) ==
               PrivateElfResult::invalid_module_set,
           "reject_incomplete_persistent_module_set");

    auto mismatched = descriptors;
    mismatched[1].image_size += 0x1000;
    expect(inspect_private_elf_set(module_paths.data(), module_paths.size(), mismatched.data(),
                                   mismatched.size(), 0x320000000, 0x10000000, set) ==
               PrivateElfResult::descriptor_mismatch,
           "reject_stream_image_geometry_mismatch");
    mismatched = descriptors;
    mismatched[2].writable_begin -= 0x1000;
    expect(inspect_private_elf_set(module_paths.data(), module_paths.size(), mismatched.data(),
                                   mismatched.size(), 0x320000000, 0x10000000, set) ==
               PrivateElfResult::descriptor_mismatch,
           "reject_stream_writable_geometry_mismatch");
    mismatched = descriptors;
    mismatched[1].guest_offset = mismatched[0].guest_offset;
    expect(inspect_private_elf_set(module_paths.data(), module_paths.size(), mismatched.data(),
                                   mismatched.size(), 0x320000000, 0x10000000, set) ==
               PrivateElfResult::invalid_module_set,
           "reject_overlapping_module_slots");

    std::remove(path);
    std::cout << "summary passed=" << (checks - failures) << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
