#include "private_elf.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

constexpr uint64_t max_private_elf_size = UINT64_C(512) * 1024 * 1024;

#pragma pack(push, 1)
struct Elf64Header {
    unsigned char ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_offset;
    uint64_t section_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t program_entry_size;
    uint16_t program_count;
    uint16_t section_entry_size;
    uint16_t section_count;
    uint16_t section_names;
};

struct Elf64ProgramHeader {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
};
#pragma pack(pop)

bool add_fits(uint64_t first, uint64_t second, uint64_t limit) {
    return first <= limit && second <= limit - first;
}

bool seek_read(FILE* file, uint64_t offset, void* destination, size_t size) {
#if defined(_WIN32)
    if (offset > static_cast<uint64_t>(std::numeric_limits<long>::max())) return false;
    if (std::fseek(file, static_cast<long>(offset), SEEK_SET) != 0) return false;
#else
    if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) return false;
    if (fseeko(file, static_cast<off_t>(offset), SEEK_SET) != 0) return false;
#endif
    return std::fread(destination, 1, size, file) == size;
}

PrivateElfResult inspect_private_elf_set_common(
    FILE* const* files, const char* const* paths, size_t input_count,
    const PrivateModuleDescriptor* descriptors, size_t descriptor_count,
    uint64_t guest_window_size, uint64_t slot_size,
    PrivateModuleSetLayout& layout) {
    layout = {};
    if ((files == nullptr) == (paths == nullptr) || descriptors == nullptr ||
        input_count != private_module_count || descriptor_count != private_module_count ||
        guest_window_size == 0 || slot_size == 0) {
        return PrivateElfResult::invalid_module_set;
    }
    uint64_t previous_end = 0;
    for (size_t index = 0; index < private_module_count; ++index) {
        const PrivateModuleDescriptor& descriptor = descriptors[index];
        const uint64_t ordinal = static_cast<uint64_t>(index) + 1;
        if (ordinal > UINT64_MAX / slot_size) {
            return PrivateElfResult::invalid_module_set;
        }
        const uint64_t expected_offset = ordinal * slot_size;
        if (descriptor.guest_offset != expected_offset || descriptor.image_size == 0 ||
            descriptor.image_size > slot_size ||
            !add_fits(descriptor.guest_offset, descriptor.image_size, guest_window_size) ||
            descriptor.guest_offset < previous_end ||
            descriptor.writable_begin >= descriptor.writable_end ||
            descriptor.writable_end > descriptor.image_size) {
            return PrivateElfResult::invalid_module_set;
        }
        PrivateElfLayout& module = layout.modules[index];
        const PrivateElfResult result = files != nullptr
            ? inspect_private_elf_file(files[index], slot_size, module)
            : inspect_private_elf(paths[index], slot_size, module);
        if (result != PrivateElfResult::ok) return result;
        const PrivateElfSegment& writable = module.segments[module.segment_count - 1];
        if (module.image_size != descriptor.image_size ||
            writable.virtual_address != descriptor.writable_begin ||
            writable.memory_size > UINT64_MAX - writable.virtual_address ||
            writable.virtual_address + writable.memory_size != descriptor.writable_end) {
            return PrivateElfResult::descriptor_mismatch;
        }
        if (!add_fits(layout.total_image_size, module.image_size, UINT64_MAX)) {
            return PrivateElfResult::invalid_module_set;
        }
        layout.total_image_size += module.image_size;
        for (size_t segment_index = 0; segment_index < module.segment_count; ++segment_index) {
            const PrivateElfSegment& segment = module.segments[segment_index];
            const uint64_t zero_fill = segment.memory_size - segment.file_size;
            if (!add_fits(layout.total_file_bytes, segment.file_size, UINT64_MAX) ||
                !add_fits(layout.total_zero_fill, zero_fill, UINT64_MAX)) {
                return PrivateElfResult::invalid_module_set;
            }
            layout.total_file_bytes += segment.file_size;
            layout.total_zero_fill += zero_fill;
        }
        previous_end = descriptor.guest_offset + descriptor.image_size;
        ++layout.module_count;
    }
    return PrivateElfResult::ok;
}

}  // namespace

PrivateElfResult inspect_private_elf_file(FILE* file, uint64_t slot_size,
                                          PrivateElfLayout& layout) {
    layout = {};
    if (file == nullptr || slot_size == 0) return PrivateElfResult::invalid_header;
    if (std::fseek(file, 0, SEEK_END) != 0) return PrivateElfResult::io_failed;
    const long measured = std::ftell(file);
    if (measured < 0) return PrivateElfResult::io_failed;
    const uint64_t file_size = static_cast<uint64_t>(measured);
    if (file_size < sizeof(Elf64Header) || file_size > max_private_elf_size) {
        return PrivateElfResult::invalid_header;
    }

    Elf64Header header{};
    if (!seek_read(file, 0, &header, sizeof(header))) return PrivateElfResult::io_failed;
    const unsigned char expected_ident[] = {0x7f, 'E', 'L', 'F', 2, 1, 1};
    if (std::memcmp(header.ident, expected_ident, sizeof(expected_ident)) != 0 ||
        header.type != 3 || header.machine != 183 || header.version != 1 ||
        header.entry != 0 || header.header_size != sizeof(Elf64Header) ||
        header.program_entry_size != sizeof(Elf64ProgramHeader) ||
        header.program_count == 0 || header.program_count > 16 ||
        !add_fits(header.program_offset,
                  static_cast<uint64_t>(header.program_count) * sizeof(Elf64ProgramHeader),
                  file_size)) {
        return PrivateElfResult::invalid_header;
    }

    for (uint16_t index = 0; index < header.program_count; ++index) {
        Elf64ProgramHeader program{};
        const uint64_t offset = header.program_offset +
                                static_cast<uint64_t>(index) * sizeof(program);
        if (!seek_read(file, offset, &program, sizeof(program))) {
            return PrivateElfResult::io_failed;
        }
        if (program.type != 1) continue;
        if (layout.segment_count == private_elf_max_segments) {
            return PrivateElfResult::invalid_program_headers;
        }
        if (program.file_size == 0 || program.file_size > program.memory_size ||
            !add_fits(program.offset, program.file_size, file_size) ||
            !add_fits(program.virtual_address, program.memory_size, slot_size) ||
            program.alignment != 4096 ||
            (program.offset & 4095) != (program.virtual_address & 4095)) {
            return PrivateElfResult::invalid_segment;
        }
        layout.segments[layout.segment_count++] = {
            program.offset,
            program.virtual_address,
            program.file_size,
            program.memory_size,
            program.flags,
        };
    }

    if (layout.segment_count != 3) return PrivateElfResult::unsupported_layout;
    std::sort(layout.segments, layout.segments + layout.segment_count,
              [](const PrivateElfSegment& left, const PrivateElfSegment& right) {
                  return left.virtual_address < right.virtual_address;
              });
    constexpr uint32_t expected_flags[] = {5, 4, 6};
    uint64_t previous_end = 0;
    for (size_t index = 0; index < layout.segment_count; ++index) {
        const PrivateElfSegment& segment = layout.segments[index];
        if (segment.flags != expected_flags[index] ||
            segment.virtual_address < previous_end) {
            return PrivateElfResult::unsupported_layout;
        }
        previous_end = segment.virtual_address + segment.memory_size;
    }
    layout.file_size = file_size;
    layout.image_size = previous_end;
    return PrivateElfResult::ok;
}

PrivateElfResult inspect_private_elf(const char* path, uint64_t slot_size,
                                     PrivateElfLayout& layout) {
    layout = {};
    if (path == nullptr || *path == '\0') return PrivateElfResult::invalid_header;
    FILE* file = std::fopen(path, "rb");
    if (file == nullptr) return PrivateElfResult::open_failed;
    const PrivateElfResult result = inspect_private_elf_file(file, slot_size, layout);
    if (std::fclose(file) != 0 && result == PrivateElfResult::ok) {
        return PrivateElfResult::io_failed;
    }
    return result;
}

PrivateElfResult inspect_private_elf_set(
    const char* const* paths, size_t path_count,
    const PrivateModuleDescriptor* descriptors, size_t descriptor_count,
    uint64_t guest_window_size, uint64_t slot_size,
    PrivateModuleSetLayout& layout) {
    return inspect_private_elf_set_common(nullptr, paths, path_count, descriptors,
                                          descriptor_count, guest_window_size,
                                          slot_size, layout);
}

PrivateElfResult inspect_private_elf_file_set(
    FILE* const* files, size_t file_count,
    const PrivateModuleDescriptor* descriptors, size_t descriptor_count,
    uint64_t guest_window_size, uint64_t slot_size,
    PrivateModuleSetLayout& layout) {
    return inspect_private_elf_set_common(files, nullptr, file_count, descriptors,
                                          descriptor_count, guest_window_size,
                                          slot_size, layout);
}

const char* private_elf_result_name(PrivateElfResult result) {
    switch (result) {
        case PrivateElfResult::ok: return "ok";
        case PrivateElfResult::open_failed: return "open_failed";
        case PrivateElfResult::io_failed: return "io_failed";
        case PrivateElfResult::invalid_header: return "invalid_header";
        case PrivateElfResult::invalid_program_headers: return "invalid_program_headers";
        case PrivateElfResult::invalid_segment: return "invalid_segment";
        case PrivateElfResult::unsupported_layout: return "unsupported_layout";
        case PrivateElfResult::invalid_module_set: return "invalid_module_set";
        case PrivateElfResult::descriptor_mismatch: return "descriptor_mismatch";
    }
    return "unknown";
}
