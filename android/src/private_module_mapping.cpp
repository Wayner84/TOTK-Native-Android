#include "private_module_mapping.h"
#include "entry_binding_reader.h"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace {

constexpr uint64_t kGuestWindowSize = UINT64_C(0x320000000);
constexpr uint64_t kModuleSlotSize = UINT64_C(0x10000000);

bool valid_page_size(size_t page_size) {
    return page_size != 0 && (page_size & (page_size - 1)) == 0 && page_size <= 65536;
}

bool page_span(const PrivateElfSegment& segment, size_t page_size,
               uint64_t& page_start, uint64_t& span) {
    const uint64_t mask = static_cast<uint64_t>(page_size - 1);
    page_start = segment.virtual_address & ~mask;
    const uint64_t delta = segment.virtual_address - page_start;
    if (segment.memory_size > UINT64_MAX - delta) return false;
    const uint64_t unrounded = delta + segment.memory_size;
    if (unrounded > UINT64_MAX - mask) return false;
    span = (unrounded + mask) & ~mask;
    return span != 0 && span <= static_cast<uint64_t>(SIZE_MAX);
}

bool read_exact_at(int file, uint8_t* destination, uint64_t size, uint64_t offset) {
    while (size != 0) {
        const size_t chunk = size > static_cast<uint64_t>(SSIZE_MAX)
                                 ? static_cast<size_t>(SSIZE_MAX)
                                 : static_cast<size_t>(size);
        const ssize_t received = pread(file, destination, chunk, static_cast<off_t>(offset));
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return false;
        destination += static_cast<size_t>(received);
        offset += static_cast<uint64_t>(received);
        size -= static_cast<uint64_t>(received);
    }
    return true;
}

bool descriptor_matches(const PrivateModuleSetLayout& layouts,
                        const RelocationStreamSummary& stream) {
    if (layouts.module_count != private_module_count ||
        stream.module_count != private_module_count) {
        return false;
    }
    for (size_t index = 0; index < private_module_count; ++index) {
        const PrivateElfLayout& layout = layouts.modules[index];
        const RelocationStreamModuleDescriptor& descriptor = stream.modules[index];
        if (layout.segment_count != 3 || layout.image_size != descriptor.image_size) return false;
        const PrivateElfSegment& writable = layout.segments[layout.segment_count - 1];
        if (writable.virtual_address != descriptor.writable_begin ||
            writable.memory_size > UINT64_MAX - writable.virtual_address ||
            writable.virtual_address + writable.memory_size != descriptor.writable_end ||
            descriptor.guest_offset > kGuestWindowSize ||
            descriptor.image_size > kGuestWindowSize - descriptor.guest_offset) {
            return false;
        }
    }
    return true;
}

}  // namespace

PrivateModuleMapResult map_private_module_set_no_execute(
    FILE* const* files, const PrivateModuleSetLayout& layouts,
    const RelocationStreamSummary& stream, uint64_t guest_base, size_t page_size,
    RelocationDestinationModule* destinations, size_t destination_count,
    PrivateModuleMapSummary& summary, const EntryBindingAdmissionCapability& capability) {
    if (!entry_binding_capability_matches_mapping(capability, stream, layouts, guest_base) || files == nullptr || destinations == nullptr ||
        destination_count != private_module_count || guest_base == 0) {
        return PrivateModuleMapResult::invalid_arguments;
    }
    if (!valid_page_size(page_size)) return PrivateModuleMapResult::invalid_page_size;
    if (!descriptor_matches(layouts, stream) || guest_base > UINT64_MAX - kGuestWindowSize) {
        return PrivateModuleMapResult::invalid_geometry;
    }

    for (size_t index = 0; index < private_module_count; ++index) destinations[index] = {};
    for (size_t index = 0; index < private_module_count; ++index) {
        if (files[index] == nullptr) {
            restore_private_module_slots(stream, guest_base);
            return PrivateModuleMapResult::invalid_arguments;
        }
        const int file = fileno(files[index]);
        if (file < 0) {
            restore_private_module_slots(stream, guest_base);
            return PrivateModuleMapResult::open_failed;
        }
        const PrivateElfLayout& layout = layouts.modules[index];
        const RelocationStreamModuleDescriptor& descriptor = stream.modules[index];
        bool ok = true;
        PrivateModuleMapResult error = PrivateModuleMapResult::ok;
        uint64_t previous_page_end = 0;
        for (size_t segment_index = 0; segment_index < layout.segment_count; ++segment_index) {
            const PrivateElfSegment& segment = layout.segments[segment_index];
            uint64_t page_start = 0;
            uint64_t span = 0;
            if (!page_span(segment, page_size, page_start, span) ||
                page_start < previous_page_end || page_start > descriptor.image_size ||
                span > descriptor.image_size - page_start) {
                ok = false;
                error = PrivateModuleMapResult::invalid_geometry;
                break;
            }
            previous_page_end = page_start + span;
            auto* target = reinterpret_cast<uint8_t*>(guest_base + descriptor.guest_offset + page_start);
            void* mapped = mmap(target, static_cast<size_t>(span), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (mapped != target) {
                ok = false;
                error = PrivateModuleMapResult::map_failed;
                break;
            }
            const uint64_t delta = segment.virtual_address - page_start;
            if (!read_exact_at(file, target + delta, segment.file_size, segment.file_offset)) {
                ok = false;
                error = PrivateModuleMapResult::io_failed;
                break;
            }
            const int protection = segment.flags == 6 ? PROT_READ | PROT_WRITE : PROT_READ;
            if (mprotect(target, static_cast<size_t>(span), protection) != 0) {
                ok = false;
                error = PrivateModuleMapResult::protect_failed;
                break;
            }
            ++summary.segment_count;
            summary.file_bytes += segment.file_size;
            summary.zero_fill_bytes += segment.memory_size - segment.file_size;
        }
        if (!ok) {
            restore_private_module_slots(stream, guest_base);
            return error;
        }
        summary.image_bytes += layout.image_size;
        destinations[index] = {
            reinterpret_cast<uint8_t*>(guest_base + descriptor.guest_offset),
            descriptor.guest_offset,
            descriptor.image_size,
            descriptor.writable_begin,
            descriptor.writable_end,
            true,
            true,
            false,
        };
    }
    return PrivateModuleMapResult::ok;
}

PrivateModuleMapResult verify_private_module_set_matches_carriers(
    FILE* const* files, const PrivateModuleSetLayout& layouts,
    const RelocationStreamSummary& stream, uint64_t guest_base) {
    if (files == nullptr || guest_base == 0 || guest_base > UINT64_MAX - kGuestWindowSize ||
        !descriptor_matches(layouts, stream)) {
        return PrivateModuleMapResult::invalid_arguments;
    }
    uint8_t buffer[65536];
    for (size_t index = 0; index < private_module_count; ++index) {
        if (files[index] == nullptr) {
            return PrivateModuleMapResult::invalid_arguments;
        }
        const int file = fileno(files[index]);
        if (file < 0) return PrivateModuleMapResult::open_failed;
        const PrivateElfLayout& layout = layouts.modules[index];
        const RelocationStreamModuleDescriptor& descriptor = stream.modules[index];
        const auto* image = reinterpret_cast<const uint8_t*>(guest_base + descriptor.guest_offset);
        for (size_t segment_index = 0; segment_index < layout.segment_count; ++segment_index) {
            const PrivateElfSegment& segment = layout.segments[segment_index];
            uint64_t remaining = segment.file_size;
            uint64_t offset = segment.file_offset;
            const uint8_t* mapped = image + segment.virtual_address;
            while (remaining != 0) {
                const size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer)
                                                                 : static_cast<size_t>(remaining);
                if (!read_exact_at(file, buffer, chunk, offset)) {
                    return PrivateModuleMapResult::io_failed;
                }
                if (std::memcmp(buffer, mapped, chunk) != 0) {
                    return PrivateModuleMapResult::content_mismatch;
                }
                remaining -= chunk;
                offset += chunk;
                mapped += chunk;
            }
            const uint8_t* zero = image + segment.virtual_address + segment.file_size;
            uint64_t zero_size = segment.memory_size - segment.file_size;
            while (zero_size != 0) {
                const size_t chunk = zero_size > sizeof(buffer) ? sizeof(buffer)
                                                                 : static_cast<size_t>(zero_size);
                for (size_t byte = 0; byte < chunk; ++byte) {
                    if (zero[byte] != 0) {
                        return PrivateModuleMapResult::content_mismatch;
                    }
                }
                zero += chunk;
                zero_size -= chunk;
            }
        }
    }
    return PrivateModuleMapResult::ok;
}

PrivateModuleMapResult seal_private_module_set_read_only(
    const PrivateModuleSetLayout& layouts, const RelocationStreamSummary& stream,
    uint64_t guest_base, size_t page_size) {
    if (guest_base == 0 || guest_base > UINT64_MAX - kGuestWindowSize ||
        !valid_page_size(page_size) ||
        !descriptor_matches(layouts, stream)) {
        return PrivateModuleMapResult::invalid_arguments;
    }
    for (size_t index = 0; index < private_module_count; ++index) {
        const PrivateElfLayout& layout = layouts.modules[index];
        const RelocationStreamModuleDescriptor& descriptor = stream.modules[index];
        for (size_t segment_index = 0; segment_index < layout.segment_count; ++segment_index) {
            uint64_t page_start = 0;
            uint64_t span = 0;
            if (!page_span(layout.segments[segment_index], page_size, page_start, span)) {
                return PrivateModuleMapResult::invalid_geometry;
            }
            void* target = reinterpret_cast<void*>(guest_base + descriptor.guest_offset + page_start);
            if (mprotect(target, static_cast<size_t>(span), PROT_READ) != 0) {
                return PrivateModuleMapResult::protect_failed;
            }
        }
    }
    return PrivateModuleMapResult::ok;
}

PrivateModuleMapResult restore_private_module_slots(
    const RelocationStreamSummary& stream, uint64_t guest_base) {
    if (stream.module_count != private_module_count || guest_base == 0 ||
        guest_base > UINT64_MAX - kGuestWindowSize) {
        return PrivateModuleMapResult::invalid_arguments;
    }
    for (size_t index = 0; index < private_module_count; ++index) {
        const uint64_t offset = stream.modules[index].guest_offset;
        if (offset > kGuestWindowSize || kModuleSlotSize > kGuestWindowSize - offset) {
            return PrivateModuleMapResult::invalid_geometry;
        }
        void* target = reinterpret_cast<void*>(guest_base + offset);
        void* mapped = mmap(target, static_cast<size_t>(kModuleSlotSize), PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
        if (mapped != target) return PrivateModuleMapResult::restore_failed;
    }
    return PrivateModuleMapResult::ok;
}

const char* private_module_map_result_name(PrivateModuleMapResult result) {
    switch (result) {
        case PrivateModuleMapResult::ok: return "ok";
        case PrivateModuleMapResult::invalid_arguments: return "invalid_arguments";
        case PrivateModuleMapResult::invalid_page_size: return "invalid_page_size";
        case PrivateModuleMapResult::invalid_geometry: return "invalid_geometry";
        case PrivateModuleMapResult::open_failed: return "open_failed";
        case PrivateModuleMapResult::io_failed: return "io_failed";
        case PrivateModuleMapResult::map_failed: return "map_failed";
        case PrivateModuleMapResult::protect_failed: return "protect_failed";
        case PrivateModuleMapResult::content_mismatch: return "content_mismatch";
        case PrivateModuleMapResult::restore_failed: return "restore_failed";
    }
    return "unknown";
}
