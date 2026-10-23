#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include "guest_startup_plan.h"
#include "private_elf.h"
#include "relocation_stream.h"

enum class EntryBindingResult : std::uint8_t;
enum class EntryBindingReadResult : std::uint8_t {
    ok, null_input, io_error, truncated, trailing_bytes, bad_magic, bad_header,
    bad_reserved, bad_digest, bad_identity, bad_order, bad_geometry, bad_alignment,
    bad_init_array, bad_entry, bad_provider, bad_alias, unknown_result
};
struct PortableEntryBinding {
    std::uint32_t module_count{};
    std::array<std::uint8_t,32> trusted_manifest_digest{};
    std::array<std::uint8_t,32> relocation_digest{};
    std::array<std::uint8_t,32> source_self_digest{};
    std::array<std::uint8_t,32> canonical_file_digest{};
    struct Module {
        GuestModuleId id{}; std::uint64_t image_size{}, writable_begin{}, writable_size{};
        std::uint64_t dt_init{}, ctor_flag{}, init_array{}, init_array_size{}, carrier_size{};
        std::array<std::uint8_t,32> carrier_digest{};
    } modules[kGuestModuleCount]{};
    struct Entry { std::uint32_t provider{}; std::uint64_t offset{}; } nn_init_start{}, nn_main{};
};

class EntryBindingAdmissionCapability {
public:
    EntryBindingAdmissionCapability() = default;
private:
    bool admitted_ = false;
    PortableEntryBinding binding_{};
    RelocationStreamSummary stream_{};
    PrivateModuleSetLayout layout_{};
    std::uint64_t guest_base_ = 0;
    friend EntryBindingResult admit_entry_binding_live(const PortableEntryBinding&, std::FILE* const*, std::FILE*, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t, GuestStartupPlan&, EntryBindingAdmissionCapability&);
    friend bool entry_binding_capability_matches_mapping(const EntryBindingAdmissionCapability&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t);
    friend bool entry_binding_capability_matches_consumption(const EntryBindingAdmissionCapability&, const PortableEntryBinding&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t);
};
bool entry_binding_capability_matches_mapping(const EntryBindingAdmissionCapability&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t);
bool entry_binding_capability_matches_consumption(const EntryBindingAdmissionCapability&, const PortableEntryBinding&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t);
EntryBindingReadResult read_entry_binding(std::FILE*, PortableEntryBinding&);
const char* entry_binding_read_result_name(EntryBindingReadResult);
#ifdef ENTRY_BINDING_READER_TESTING
std::array<std::uint8_t, 32> entry_binding_test_sha256(const std::uint8_t*, std::size_t);
#endif
