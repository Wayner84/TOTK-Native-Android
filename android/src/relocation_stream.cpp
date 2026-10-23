#include "relocation_stream.h"

#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

constexpr uint64_t kHeaderSize = 64;
constexpr uint64_t kDescriptorSize = 48;
constexpr uint64_t kRecordSize = 32;
constexpr uint64_t kMaxFileSize = UINT64_C(512) * 1024 * 1024;
constexpr uint64_t kMaxModules = relocation_stream_max_modules;
constexpr uint64_t kMaxRecordsPerModule = 4000000;
constexpr uint64_t kGuestWindowSize = UINT64_C(0x320000000);
constexpr uint64_t kModuleSlotSize = UINT64_C(0x10000000);
constexpr uint64_t kModuleLayoutStart = UINT64_C(0x10000000);
constexpr uint8_t kSourceRela = 1;
constexpr uint8_t kSourceRelr = 2;
constexpr uint8_t kNoProvider = 0xff;
constexpr uint32_t kAbs64 = 257;
constexpr uint32_t kGlobDat = 1025;
constexpr uint32_t kJumpSlot = 1026;
constexpr uint32_t kRelative = 1027;

uint16_t read_u16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8U);
}

uint32_t read_u32(const uint8_t* data) {
    uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value |= static_cast<uint32_t>(data[index]) << (index * 8U);
    }
    return value;
}

uint64_t read_u64(const uint8_t* data) {
    uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(data[index]) << (index * 8U);
    }
    return value;
}

int64_t read_i64(const uint8_t* data) {
    const uint64_t encoded = read_u64(data);
    int64_t value = 0;
    static_assert(sizeof(value) == sizeof(encoded));
    std::memcpy(&value, &encoded, sizeof(value));
    return value;
}

bool add_fits(uint64_t first, uint64_t second, uint64_t limit) {
    return first <= limit && second <= limit - first;
}

bool multiply_fits(uint64_t first, uint64_t second, uint64_t limit, uint64_t& value) {
    if (first != 0 && second > limit / first) return false;
    value = first * second;
    return true;
}

bool add_signed_in_guest(uint64_t base, int64_t addend) {
    if (base >= kGuestWindowSize) return false;
    if (addend >= 0) {
        return static_cast<uint64_t>(addend) < kGuestWindowSize - base;
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(addend + 1)) + 1;
    return magnitude <= base;
}

bool add_signed_value(uint64_t base, int64_t addend, uint64_t& value) {
    if (addend >= 0) {
        const uint64_t positive = static_cast<uint64_t>(addend);
        if (positive > UINT64_MAX - base) return false;
        value = base + positive;
        return true;
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(addend + 1)) + 1;
    if (magnitude > base) return false;
    value = base - magnitude;
    return true;
}

class ExactReader {
public:
    explicit ExactReader(const char* path) {
#if defined(_WIN32)
        fd_ = _open(path, _O_RDONLY | _O_BINARY);
        if (fd_ < 0) return;
        struct _stat64 status {};
        if (_fstat64(fd_, &status) != 0 || status.st_size < 0) {
            _close(fd_);
            fd_ = -1;
            io_error_ = true;
            return;
        }
        size_ = static_cast<uint64_t>(status.st_size);
#else
        fd_ = open(path, O_RDONLY | O_CLOEXEC);
        if (fd_ < 0) return;
        struct stat status {};
        if (fstat(fd_, &status) != 0 || status.st_size < 0) {
            close(fd_);
            fd_ = -1;
            io_error_ = true;
            return;
        }
        size_ = static_cast<uint64_t>(status.st_size);
#endif
    }

    ~ExactReader() {
#if defined(_WIN32)
        if (fd_ >= 0) _close(fd_);
#else
        if (fd_ >= 0) close(fd_);
#endif
    }

    ExactReader(const ExactReader&) = delete;
    ExactReader& operator=(const ExactReader&) = delete;

    bool opened() const {
#if defined(_WIN32)
        return fd_ >= 0;
#else
        return fd_ >= 0;
#endif
    }

    bool io_error() const { return io_error_; }
    uint64_t size() const { return size_; }

    bool read_exact(uint64_t offset, void* destination, size_t length) const {
        if (!add_fits(offset, static_cast<uint64_t>(length), size_)) return false;
        auto* output = static_cast<uint8_t*>(destination);
        size_t completed = 0;
        while (completed < length) {
#if defined(_WIN32)
            const uint64_t current = offset + completed;
            if (current > static_cast<uint64_t>(std::numeric_limits<__int64>::max()) ||
                _lseeki64(fd_, static_cast<__int64>(current), SEEK_SET) < 0) return false;
            const size_t remaining = length - completed;
            const unsigned requested = remaining > static_cast<size_t>(INT_MAX)
                                           ? static_cast<unsigned>(INT_MAX)
                                           : static_cast<unsigned>(remaining);
            const int received = _read(fd_, output + completed, requested);
            if (received <= 0) return false;
            completed += static_cast<size_t>(received);
#else
            const uint64_t current = offset + completed;
            if (current > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) return false;
            const ssize_t received = pread(fd_, output + completed, length - completed,
                                           static_cast<off_t>(current));
            if (received < 0 && errno == EINTR) continue;
            if (received <= 0) return false;
            completed += static_cast<size_t>(received);
#endif
        }
        return true;
    }

private:
#if defined(_WIN32)
    int fd_ = -1;
#else
    int fd_ = -1;
#endif
    uint64_t size_ = 0;
    bool io_error_ = false;
};

struct PlannedWrite {
    uint8_t* target;
    uint64_t previous_value;
    uint64_t replacement_value;
};

struct PlanContext {
    uint64_t guest_base;
    RelocationDestinationModule* destinations;
    size_t destination_count;
    const RelocationApplyOptions* options;
    std::unique_ptr<PlannedWrite[]> writes;
};

RelocationStreamResult fail(RelocationStreamResult result,
                            RelocationStreamSummary& summary) {
    summary = {};
    return result;
}

RelocationStreamResult parse_relocation_stream(const char* path,
                                               RelocationStreamSummary& summary,
                                               PlanContext* plan) {
    summary = {};
    if (path == nullptr || *path == '\0') return RelocationStreamResult::invalid_arguments;

    ExactReader reader(path);
    if (!reader.opened()) {
        return reader.io_error() ? RelocationStreamResult::io_failed
                                 : RelocationStreamResult::open_failed;
    }
    const uint64_t file_size = reader.size();
    if (file_size < kHeaderSize + kDescriptorSize || file_size > kMaxFileSize) {
        return RelocationStreamResult::invalid_file_size;
    }

    std::array<uint8_t, kHeaderSize> header{};
    if (!reader.read_exact(0, header.data(), header.size())) {
        return RelocationStreamResult::io_failed;
    }
    const uint8_t magic[] = {'T', 'O', 'T', 'K', 'R', 'L', 'P', '1'};
    if (std::memcmp(header.data(), magic, sizeof(magic)) != 0 || read_u32(header.data() + 8) != 1) {
        return RelocationStreamResult::unsupported_format;
    }
    if (read_u32(header.data() + 12) != kHeaderSize ||
        read_u32(header.data() + 16) != kDescriptorSize ||
        read_u32(header.data() + 20) != kRecordSize) {
        return RelocationStreamResult::invalid_structure;
    }

    const uint64_t module_count = read_u64(header.data() + 24);
    const uint64_t record_count = read_u64(header.data() + 32);
    if (module_count == 0 || module_count > kMaxModules ||
        record_count > kMaxRecordsPerModule * module_count) {
        return RelocationStreamResult::invalid_count;
    }
    if (read_u64(header.data() + 40) != kGuestWindowSize ||
        read_u64(header.data() + 48) != kModuleSlotSize ||
        read_u64(header.data() + 56) != kModuleLayoutStart) {
        return RelocationStreamResult::incompatible_layout;
    }

    uint64_t descriptor_bytes = 0;
    uint64_t record_bytes = 0;
    if (!multiply_fits(module_count, kDescriptorSize, UINT64_MAX, descriptor_bytes) ||
        !multiply_fits(record_count, kRecordSize, UINT64_MAX, record_bytes) ||
        !add_fits(kHeaderSize, descriptor_bytes, UINT64_MAX) ||
        !add_fits(kHeaderSize + descriptor_bytes, record_bytes, UINT64_MAX) ||
        file_size != kHeaderSize + descriptor_bytes + record_bytes) {
        return RelocationStreamResult::invalid_file_size;
    }
    if (plan != nullptr) {
        if (plan->destination_count != module_count) {
            return RelocationStreamResult::invalid_destination_geometry;
        }
        if (plan->guest_base > UINT64_MAX - kGuestWindowSize) {
            return RelocationStreamResult::arithmetic_out_of_range;
        }
        uint64_t journal_bytes = 0;
        if (record_count > plan->options->max_records ||
            !multiply_fits(record_count, sizeof(PlannedWrite),
                           plan->options->max_journal_bytes, journal_bytes) ||
            journal_bytes > static_cast<uint64_t>(SIZE_MAX)) {
            return RelocationStreamResult::resource_limit;
        }
        if (record_count != 0) {
            plan->writes.reset(new (std::nothrow) PlannedWrite[static_cast<size_t>(record_count)]);
            if (plan->writes == nullptr) return RelocationStreamResult::allocation_failed;
        }
    }

    std::array<RelocationStreamModuleDescriptor, kMaxModules> modules{};
    uint64_t descriptor_total = 0;
    for (uint64_t index = 0; index < module_count; ++index) {
        std::array<uint8_t, kDescriptorSize> encoded{};
        const uint64_t offset = kHeaderSize + index * kDescriptorSize;
        if (!reader.read_exact(offset, encoded.data(), encoded.size())) {
            return fail(RelocationStreamResult::io_failed, summary);
        }
        if (read_u32(encoded.data()) != index || read_u32(encoded.data() + 4) != 0) {
            return fail(RelocationStreamResult::invalid_descriptor, summary);
        }
        RelocationStreamModuleDescriptor& module = modules[index];
        module.guest_offset = read_u64(encoded.data() + 8);
        module.image_size = read_u64(encoded.data() + 16);
        module.writable_begin = read_u64(encoded.data() + 24);
        module.writable_end = read_u64(encoded.data() + 32);
        module.record_count = read_u64(encoded.data() + 40);
        const uint64_t expected_guest = kModuleLayoutStart + index * kModuleSlotSize;
        if (module.guest_offset != expected_guest || module.image_size == 0 ||
            module.image_size > kModuleSlotSize ||
            !add_fits(module.guest_offset, module.image_size, kGuestWindowSize) ||
            module.writable_begin > module.writable_end ||
            module.writable_end > module.image_size ||
            module.writable_end - module.writable_begin < 8) {
            return fail(RelocationStreamResult::invalid_geometry, summary);
        }
        if (plan != nullptr) {
            const RelocationDestinationModule& destination = plan->destinations[index];
            if (destination.image == nullptr ||
                destination.guest_offset != module.guest_offset ||
                destination.image_size != module.image_size ||
                destination.writable_begin != module.writable_begin ||
                destination.writable_end != module.writable_end ||
                module.image_size > static_cast<uint64_t>(SIZE_MAX) ||
                reinterpret_cast<uintptr_t>(destination.image) >
                    UINTPTR_MAX - static_cast<uintptr_t>(module.image_size)) {
                return fail(RelocationStreamResult::invalid_destination_geometry, summary);
            }
            if (!destination.mapped || !destination.writable || destination.executable) {
                return fail(RelocationStreamResult::invalid_destination_state, summary);
            }
            const uintptr_t destination_begin =
                reinterpret_cast<uintptr_t>(destination.image);
            const uintptr_t destination_end =
                destination_begin + static_cast<uintptr_t>(module.image_size);
            for (uint64_t prior_index = 0; prior_index < index; ++prior_index) {
                const RelocationDestinationModule& prior =
                    plan->destinations[prior_index];
                const uintptr_t prior_begin = reinterpret_cast<uintptr_t>(prior.image);
                const uintptr_t prior_end =
                    prior_begin + static_cast<uintptr_t>(prior.image_size);
                if (destination_begin < prior_end && prior_begin < destination_end) {
                    return fail(RelocationStreamResult::invalid_destination_geometry,
                                summary);
                }
            }
        }
        if (module.record_count > kMaxRecordsPerModule ||
            !add_fits(descriptor_total, module.record_count, record_count)) {
            return fail(RelocationStreamResult::invalid_count, summary);
        }
        descriptor_total += module.record_count;
    }
    if (descriptor_total != record_count) {
        return fail(RelocationStreamResult::invalid_count, summary);
    }

    RelocationStreamSummary validated{};
    validated.file_bytes = file_size;
    validated.module_count = module_count;
    validated.record_count = record_count;
    for (uint64_t index = 0; index < module_count; ++index) {
        validated.modules[index] = modules[index];
    }
    uint64_t record_index = 0;
    for (uint64_t module_id = 0; module_id < module_count; ++module_id) {
        const RelocationStreamModuleDescriptor& module = modules[module_id];
        uint64_t previous_target = 0;
        bool has_previous = false;
        for (uint64_t local_index = 0; local_index < module.record_count;
             ++local_index, ++record_index) {
            std::array<uint8_t, kRecordSize> encoded{};
            const uint64_t offset = kHeaderSize + descriptor_bytes + record_index * kRecordSize;
            if (!reader.read_exact(offset, encoded.data(), encoded.size())) {
                return fail(RelocationStreamResult::io_failed, summary);
            }
            const uint64_t target = read_u64(encoded.data());
            const uint32_t kind = read_u32(encoded.data() + 8);
            const uint8_t source = encoded[12];
            const uint8_t provider = encoded[13];
            const uint16_t reserved = read_u16(encoded.data() + 14);
            const uint64_t symbol_value = read_u64(encoded.data() + 16);
            const int64_t addend = read_i64(encoded.data() + 24);
            uint64_t logical_value = 0;
            if (reserved != 0) return fail(RelocationStreamResult::invalid_record, summary);
            if (kind != kAbs64 && kind != kGlobDat && kind != kJumpSlot &&
                kind != kRelative) {
                return fail(RelocationStreamResult::unsupported_kind, summary);
            }
            if (source != kSourceRela && source != kSourceRelr) {
                return fail(RelocationStreamResult::unsupported_source, summary);
            }
            if ((target & 7U) != 0 || target < module.writable_begin ||
                target > module.writable_end - 8 ||
                (has_previous && target <= previous_target)) {
                return fail(RelocationStreamResult::invalid_target, summary);
            }
            previous_target = target;
            has_previous = true;

            if (kind == kRelative) {
                if (provider != module_id || symbol_value != 0 || addend < 0 ||
                    static_cast<uint64_t>(addend) >= module.image_size) {
                    return fail(RelocationStreamResult::invalid_operands, summary);
                }
                if (!add_signed_in_guest(module.guest_offset, addend) ||
                    !add_signed_value(module.guest_offset, addend, logical_value)) {
                    return fail(RelocationStreamResult::arithmetic_out_of_range, summary);
                }
                ++validated.relative_count;
            } else {
                if (source != kSourceRela) {
                    return fail(RelocationStreamResult::invalid_operands, summary);
                }
                if (provider != kNoProvider && provider >= module_count) {
                    return fail(RelocationStreamResult::invalid_provider, summary);
                }
                uint64_t provider_base = 0;
                if (provider == kNoProvider) {
                    if (symbol_value != 0) {
                        return fail(RelocationStreamResult::invalid_operands, summary);
                    }
                } else {
                    const RelocationStreamModuleDescriptor& selected = modules[provider];
                    if (symbol_value >= selected.image_size ||
                        !add_fits(selected.guest_offset, symbol_value, kGuestWindowSize)) {
                        return fail(RelocationStreamResult::invalid_operands, summary);
                    }
                    provider_base = selected.guest_offset + symbol_value;
                }
                if (kind == kJumpSlot && addend != 0) {
                    return fail(RelocationStreamResult::invalid_operands, summary);
                }
                if (!add_signed_in_guest(provider_base, addend) ||
                    !add_signed_value(provider_base, addend, logical_value)) {
                    return fail(RelocationStreamResult::arithmetic_out_of_range, summary);
                }
                if (kind == kAbs64) ++validated.abs64_count;
                if (kind == kGlobDat) ++validated.glob_dat_count;
                if (kind == kJumpSlot) ++validated.jump_slot_count;
            }
            if (source == kSourceRela) ++validated.rela_count;
            if (source == kSourceRelr) ++validated.relr_count;
            if (plan != nullptr) {
                uint64_t replacement = logical_value;
                if (kind == kRelative || provider != kNoProvider) {
                    if (replacement > UINT64_MAX - plan->guest_base) {
                        return fail(RelocationStreamResult::arithmetic_out_of_range, summary);
                    }
                    replacement += plan->guest_base;
                }
                PlannedWrite& write = plan->writes[static_cast<size_t>(record_index)];
                write.target = plan->destinations[module_id].image +
                               static_cast<size_t>(target);
                std::memcpy(&write.previous_value, write.target,
                            sizeof(write.previous_value));
                write.replacement_value = replacement;
            }
        }
    }
    summary = validated;
    return RelocationStreamResult::ok;
}

}  // namespace

RelocationStreamResult validate_relocation_stream(const char* path,
                                                  RelocationStreamSummary& summary) {
    return parse_relocation_stream(path, summary, nullptr);
}

RelocationStreamResult apply_relocation_stream_transactional(
    const char* path, uint64_t guest_base, RelocationDestinationModule* modules,
    size_t module_count, const RelocationApplyOptions& options,
    RelocationApplySummary& summary) {
    summary = {};
    if (path == nullptr || *path == '\0' || modules == nullptr || module_count == 0) {
        return RelocationStreamResult::invalid_arguments;
    }
    PlanContext plan{guest_base, modules, module_count, &options, nullptr};
    RelocationStreamSummary stream_summary{};
    const RelocationStreamResult validation =
        parse_relocation_stream(path, stream_summary, &plan);
    if (validation != RelocationStreamResult::ok) return validation;

    // Recheck the journal snapshot before the first write. This detects caller
    // mutation between planning and commit under the exclusive-ownership contract.
    for (uint64_t index = 0; index < stream_summary.record_count; ++index) {
        uint64_t current = 0;
        std::memcpy(&current, plan.writes[static_cast<size_t>(index)].target,
                    sizeof(current));
        if (current != plan.writes[static_cast<size_t>(index)].previous_value) {
            return RelocationStreamResult::invalid_destination_state;
        }
    }

    summary.stream = stream_summary;
    uint64_t applied = 0;
    for (; applied < stream_summary.record_count; ++applied) {
        if (applied == options.fail_after_writes) {
            for (uint64_t rollback = applied; rollback != 0; --rollback) {
                PlannedWrite& write = plan.writes[static_cast<size_t>(rollback - 1)];
                std::memcpy(write.target, &write.previous_value,
                            sizeof(write.previous_value));
            }
            summary.writes_rolled_back = applied;
            return RelocationStreamResult::injected_failure;
        }
        PlannedWrite& write = plan.writes[static_cast<size_t>(applied)];
        std::memcpy(write.target, &write.replacement_value,
                    sizeof(write.replacement_value));
    }
    summary.writes_committed = applied;
    return RelocationStreamResult::ok;
}

const char* relocation_stream_result_name(RelocationStreamResult result) {
    switch (result) {
        case RelocationStreamResult::ok: return "ok";
        case RelocationStreamResult::invalid_arguments: return "invalid_arguments";
        case RelocationStreamResult::open_failed: return "open_failed";
        case RelocationStreamResult::io_failed: return "io_failed";
        case RelocationStreamResult::invalid_file_size: return "invalid_file_size";
        case RelocationStreamResult::unsupported_format: return "unsupported_format";
        case RelocationStreamResult::invalid_structure: return "invalid_structure";
        case RelocationStreamResult::invalid_count: return "invalid_count";
        case RelocationStreamResult::incompatible_layout: return "incompatible_layout";
        case RelocationStreamResult::invalid_descriptor: return "invalid_descriptor";
        case RelocationStreamResult::invalid_geometry: return "invalid_geometry";
        case RelocationStreamResult::invalid_record: return "invalid_record";
        case RelocationStreamResult::unsupported_kind: return "unsupported_kind";
        case RelocationStreamResult::unsupported_source: return "unsupported_source";
        case RelocationStreamResult::invalid_target: return "invalid_target";
        case RelocationStreamResult::invalid_provider: return "invalid_provider";
        case RelocationStreamResult::invalid_operands: return "invalid_operands";
        case RelocationStreamResult::arithmetic_out_of_range: return "arithmetic_out_of_range";
        case RelocationStreamResult::invalid_destination_geometry:
            return "invalid_destination_geometry";
        case RelocationStreamResult::invalid_destination_state:
            return "invalid_destination_state";
        case RelocationStreamResult::resource_limit: return "resource_limit";
        case RelocationStreamResult::allocation_failed: return "allocation_failed";
        case RelocationStreamResult::injected_failure: return "injected_failure";
    }
    return "unknown";
}
