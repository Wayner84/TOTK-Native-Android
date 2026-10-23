#pragma once
#include "entry_binding_reader.h"
#include "private_elf.h"
#include "relocation_stream.h"
#include "guest_startup_plan.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>

enum class EntryBindingResult : std::uint8_t {
 ok, null_input, invalid_count, invalid_order, carrier_mismatch, layout_mismatch,
 stream_mismatch, destination_mismatch, invalid_state, overflow, alignment,
 metadata_mismatch, read_failed, provider_mismatch, containment, plan_validation, plan_mismatch,
 revalidation_failed
};
struct EntryBindingObservation { bool consumed{}; bool no_execute{}; std::uint32_t module_count{}; };

EntryBindingResult admit_entry_binding_live(const PortableEntryBinding&, std::FILE* const*, std::FILE*, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t, GuestStartupPlan&, EntryBindingAdmissionCapability&);
EntryBindingResult consume_admitted_entry_binding(const EntryBindingAdmissionCapability&, const PortableEntryBinding&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, const RelocationDestinationModule*, std::size_t, std::uint64_t guest_base, const GuestStartupPlan&, EntryBindingObservation&);
#ifdef ENTRY_BINDING_CONSUMPTION_TESTING
EntryBindingResult test_admit_entry_binding(const PortableEntryBinding&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, std::uint64_t guest_base, GuestStartupPlan& out);
EntryBindingResult test_consume_entry_binding(const PortableEntryBinding&, const RelocationStreamSummary&, const PrivateModuleSetLayout&, const RelocationDestinationModule*, std::size_t, std::uint64_t guest_base, const GuestStartupPlan&, EntryBindingObservation&);
#endif
const char* entry_binding_result_name(EntryBindingResult);
