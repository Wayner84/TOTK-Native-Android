#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

constexpr size_t private_elf_max_segments = 8;
constexpr size_t private_module_count = 3;

struct PrivateElfSegment {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
};

struct PrivateElfLayout {
    uint64_t file_size;
    PrivateElfSegment segments[private_elf_max_segments];
    size_t segment_count;
    uint64_t image_size;
};

struct PrivateModuleDescriptor {
    uint64_t guest_offset;
    uint64_t image_size;
    uint64_t writable_begin;
    uint64_t writable_end;
};

struct PrivateModuleSetLayout {
    PrivateElfLayout modules[private_module_count];
    size_t module_count;
    uint64_t total_image_size;
    uint64_t total_file_bytes;
    uint64_t total_zero_fill;
};

enum class PrivateElfResult {
    ok,
    open_failed,
    io_failed,
    invalid_header,
    invalid_program_headers,
    invalid_segment,
    unsupported_layout,
    invalid_module_set,
    descriptor_mismatch,
};

PrivateElfResult inspect_private_elf(const char* path, uint64_t slot_size,
                                     PrivateElfLayout& layout);
PrivateElfResult inspect_private_elf_file(FILE* file, uint64_t slot_size,
                                          PrivateElfLayout& layout);
PrivateElfResult inspect_private_elf_set(
    const char* const* paths, size_t path_count,
    const PrivateModuleDescriptor* descriptors, size_t descriptor_count,
    uint64_t guest_window_size, uint64_t slot_size,
    PrivateModuleSetLayout& layout);
PrivateElfResult inspect_private_elf_file_set(
    FILE* const* files, size_t file_count,
    const PrivateModuleDescriptor* descriptors, size_t descriptor_count,
    uint64_t guest_window_size, uint64_t slot_size,
    PrivateModuleSetLayout& layout);
const char* private_elf_result_name(PrivateElfResult result);
