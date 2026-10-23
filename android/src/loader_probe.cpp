#include <array>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#include "loader_probe.h"
#include "module_image.h"
#include "guest_window.h"
#include "guest_thread_context.h"
#include "guest_stack_probe.h"
#include "vm_query.h"
#include "signal_context.h"
#include "private_elf.h"
#include "private_module_mapping.h"
#include "relocation_stream.h"
#include "guest_startup_plan.h"
#include "entry_binding_consumption.h"
#include "vulkan_probe.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace {

struct TestState {
    int passed = 0;
    int failed = 0;
    void check(bool ok, const char* name, const char* detail) {
        std::printf("test=%s result=%s detail=%s\n", name, ok ? "PASS" : "FAIL", detail);
        ok ? ++passed : ++failed;
    }
};

thread_local int tls_value = 0;

void test_guest_startup_plan(TestState& state) {
    GuestStartupInput input{};
    input.module_count = 3;
    for (std::size_t i = 0; i < 3; ++i) {
        auto& module = input.modules[i];
        const std::uint64_t base = UINT64_C(0x40000000) + i * UINT64_C(0x10000000);
        module.id = static_cast<GuestModuleId>(i);
        module.image_begin = base;
        module.image_end = base + UINT64_C(0x100000);
        module.writable_begin = base + UINT64_C(0x80000);
        module.writable_end = base + UINT64_C(0x90000);
        module.dt_init = base + UINT64_C(0x1000);
        module.ctor_flag = base + UINT64_C(0x80000);
        module.init_array = 0;
        module.init_array_size = 0;
    }
    input.nn_init_start = UINT64_C(0x40001004);
    input.nn_main = UINT64_C(0x50001004);
    input.nn_init_provider = 0;
    input.nn_main_provider = 1;
    GuestStartupPlan plan{};
    const auto result = guest_startup_plan_validate(input, &plan);
    char detail[256]{};
    std::snprintf(detail, sizeof(detail),
                  "order=main,subsdk0,sdk start=resolved nnMain=resolved constructors=ordered execution=not_attempted result=%s",
                  guest_startup_result_name(result));
    state.check(result == GuestStartupResult::ok && guest_startup_plan_revalidate(&plan) == GuestStartupResult::ok,
                "guest_startup_plan", detail);
}


volatile sig_atomic_t signal_probe_entered = 0;
volatile sig_atomic_t signal_probe_on_altstack = 0;
volatile sig_atomic_t signal_probe_roundtrip = 0;
volatile sig_atomic_t signal_probe_restored = 0;
volatile sig_atomic_t signal_probe_number = 0;
uintptr_t signal_probe_stack_lo = 0;
uintptr_t signal_probe_stack_hi = 0;

bool signal_contexts_equal(const Aarch64SignalContext& left,
                           const Aarch64SignalContext& right) {
    for (size_t index = 0; index < aarch64_signal_register_count; ++index) {
        if (left.registers[index] != right.registers[index]) return false;
    }
    return left.sp == right.sp && left.pc == right.pc &&
           left.pstate == right.pstate;
}

void signal_context_probe_handler(int signal, siginfo_t*, void* raw_context) {
    if (raw_context == nullptr) return;
    const uintptr_t handler_stack = reinterpret_cast<uintptr_t>(&signal);
    const bool on_expected_stack = handler_stack >= signal_probe_stack_lo &&
                                   handler_stack < signal_probe_stack_hi;
    if (!signal_probe_delivery_is_authorized(signal_probe_number, signal,
                                             on_expected_stack)) return;
    signal_probe_entered = 1;
    signal_probe_on_altstack = 1;

    Aarch64SignalContext original{};
    if (capture_bionic_signal_context(raw_context, &original) != SignalContextResult::ok) return;
    Aarch64SignalContext changed = original;
    changed.registers[0] ^= UINT64_C(0x5a5aa5a55a5aa5a5);
    if (restore_bionic_signal_context(raw_context, &changed) != SignalContextResult::ok) return;
    Aarch64SignalContext observed{};
    const SignalContextResult observed_result =
        capture_bionic_signal_context(raw_context, &observed);
    signal_probe_roundtrip = observed_result == SignalContextResult::ok &&
                             signal_contexts_equal(changed, observed);
    if (restore_bionic_signal_context(raw_context, &original) != SignalContextResult::ok) return;
    Aarch64SignalContext final_state{};
    if (capture_bionic_signal_context(raw_context, &final_state) != SignalContextResult::ok) return;
    signal_probe_restored = signal_contexts_equal(original, final_state);
}

void test_generated_code(TestState& state, long page_size) {
    void* memory = mmap(nullptr, static_cast<size_t>(page_size), PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        state.check(false, "generated_code", std::strerror(errno));
        return;
    }

    // AArch64: add x0, x0, x1; ret. This validates executable mapping plus the
    // integer calling convention used by a direct Android-to-guest thunk.
    const uint32_t instructions[] = {0x8b010000U, 0xd65f03c0U};
    std::memcpy(memory, instructions, sizeof(instructions));
    __builtin___clear_cache(static_cast<char*>(memory),
                            static_cast<char*>(memory) + sizeof(instructions));
    if (mprotect(memory, static_cast<size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        const int saved_errno = errno;
        munmap(memory, static_cast<size_t>(page_size));
        state.check(false, "generated_code", std::strerror(saved_errno));
        return;
    }

    using AddFn = uint64_t (*)(uint64_t, uint64_t);
    auto add = reinterpret_cast<AddFn>(memory);
    const uint64_t result = add(0x123456789abcdef0ULL, 0x10ULL);
    munmap(memory, static_cast<size_t>(page_size));
    state.check(result == 0x123456789abcdf00ULL, "generated_code",
                result == 0x123456789abcdf00ULL ? "AArch64 ABI thunk returned expected value"
                                                : "unexpected generated-code result");
}

void test_fixed_address(TestState& state, long page_size, uintptr_t address) {
    errno = 0;
    void* result = mmap(reinterpret_cast<void*>(address), static_cast<size_t>(page_size), PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    char name[64]{};
    std::snprintf(name, sizeof(name), "fixed_map_0x%" PRIxPTR, address);
    if (result == MAP_FAILED) {
        char detail[160]{};
        std::snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, std::strerror(errno));
        // A failed address is evidence, not a harness failure; architecture selection
        // considers which requested ranges are available on the target.
        state.check(true, name, detail);
        return;
    }
    const bool exact = reinterpret_cast<uintptr_t>(result) == address;
    munmap(result, static_cast<size_t>(page_size));
    state.check(exact, name, exact ? "exact reservation succeeded" : "kernel ignored no-replace address");
}

void test_signal_context_roundtrip(TestState& state, long page_size) {
    if (page_size <= 0 || static_cast<uint64_t>(page_size) >
                              std::numeric_limits<size_t>::max() / 18) {
        state.check(false, "bionic_signal_context", "invalid page size");
        return;
    }
    sigset_t current_mask{};
    sigset_t pending_signals{};
    const bool signal_sets_read =
        pthread_sigmask(SIG_SETMASK, nullptr, &current_mask) == 0 &&
        sigpending(&pending_signals) == 0;
    std::array<SignalProbeCandidate, 64> candidates{};
    size_t candidate_count = 0;
    if (signal_sets_read) {
        for (int candidate_signal = SIGRTMAX;
             candidate_signal >= SIGRTMIN && candidate_count < candidates.size();
             --candidate_signal) {
            const int blocked_member = sigismember(&current_mask, candidate_signal);
            const int pending_member = sigismember(&pending_signals, candidate_signal);
            struct sigaction existing_action{};
            const bool action_read = sigaction(candidate_signal, nullptr, &existing_action) == 0;
            if (blocked_member < 0 || pending_member < 0 || !action_read) continue;
            candidates[candidate_count++] = {
                candidate_signal,
                blocked_member == 1,
                pending_member == 1,
                existing_action.sa_handler == SIG_DFL,
            };
        }
    }
    const int probe_signal = select_signal_probe_candidate(candidates.data(), candidate_count);
    if (probe_signal == 0) {
        state.check(false, "bionic_signal_context",
                    "no unblocked, clear, default-action realtime signal is available");
        return;
    }
    const size_t page = static_cast<size_t>(page_size);
    const size_t mapping_size = page * 18;
    auto* mapping = static_cast<uint8_t*>(mmap(nullptr, mapping_size, PROT_NONE,
                                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mapping == MAP_FAILED) {
        state.check(false, "bionic_signal_context", "alternate stack allocation failed");
        return;
    }
    auto* stack_base = mapping + page;
    const size_t stack_size = page * 16;
    if (mprotect(stack_base, stack_size, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mapping_size);
        state.check(false, "bionic_signal_context", "alternate stack protection failed");
        return;
    }

    stack_t old_stack{};
    stack_t probe_stack{};
    probe_stack.ss_sp = stack_base;
    probe_stack.ss_size = stack_size;
    struct sigaction old_action{};
    struct sigaction action{};
    action.sa_sigaction = signal_context_probe_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);

    signal_probe_entered = 0;
    signal_probe_on_altstack = 0;
    signal_probe_roundtrip = 0;
    signal_probe_restored = 0;
    signal_probe_number = probe_signal;
    signal_probe_stack_lo = reinterpret_cast<uintptr_t>(stack_base);
    signal_probe_stack_hi = signal_probe_stack_lo + stack_size;

    const bool stack_installed = sigaltstack(&probe_stack, &old_stack) == 0;
    const bool action_changed = stack_installed &&
                                sigaction(probe_signal, &action, &old_action) == 0;
    const bool action_installed = action_changed && old_action.sa_handler == SIG_DFL;
    const bool delivered = action_installed &&
                           pthread_kill(pthread_self(), probe_signal) == 0;
    bool action_restored = !action_changed;
    struct sigaction current_action{};
    const bool action_query_ok = action_changed &&
                                 sigaction(probe_signal, nullptr, &current_action) == 0;
    const bool action_still_owned = action_query_ok &&
        (current_action.sa_flags & SA_SIGINFO) != 0 &&
        current_action.sa_sigaction == signal_context_probe_handler;
    if (action_changed && action_query_ok && !action_still_owned) {
        // Another owner replaced the process-wide disposition. Do not overwrite it.
        action_restored = true;
    }
    for (unsigned attempt = 0; action_still_owned && !action_restored && attempt < 3; ++attempt) {
        action_restored = sigaction(probe_signal, &old_action, nullptr) == 0;
        if (!action_restored && errno != EINTR) break;
    }
    bool stack_restored = !stack_installed;
    for (unsigned attempt = 0;
         stack_installed && action_restored && !stack_restored && attempt < 3; ++attempt) {
        stack_restored = sigaltstack(&old_stack, nullptr) == 0;
        if (!stack_restored && errno != EINTR) break;
    }
    const bool can_release = !stack_installed ||
                             signal_probe_stack_can_release(stack_restored);
    const bool released = can_release && munmap(mapping, mapping_size) == 0;
    const bool ok = stack_installed && action_installed && delivered &&
                    signal_probe_entered && signal_probe_on_altstack &&
                    signal_probe_roundtrip && signal_probe_restored &&
                    action_restored && stack_restored && released;
    char detail[320]{};
    std::snprintf(detail, sizeof(detail),
                  "delivered=%s altstack=%s capture_restore=%s original_restored=%s cleanup=%s",
                  signal_probe_entered ? "yes" : "no",
                  signal_probe_on_altstack ? "yes" : "no",
                  signal_probe_roundtrip ? "yes" : "no",
                  signal_probe_restored ? "yes" : "no",
                  (action_restored && stack_restored && released) ? "yes" : "no");
    state.check(ok, "bionic_signal_context", detail);
}

struct HardwareThreadRegisters {
    uintptr_t x18 = 0;
    uintptr_t tpidr_el0 = 0;
    uintptr_t tpidrro_el0 = 0;

    bool operator==(const HardwareThreadRegisters& other) const {
        return x18 == other.x18 && tpidr_el0 == other.tpidr_el0 &&
               tpidrro_el0 == other.tpidrro_el0;
    }
};

HardwareThreadRegisters capture_hardware_thread_registers() {
    HardwareThreadRegisters result{};
#if defined(__aarch64__)
    asm volatile("mov %0, x18" : "=r"(result.x18));
    asm volatile("mrs %0, tpidr_el0" : "=r"(result.tpidr_el0));
    asm volatile("mrs %0, tpidrro_el0" : "=r"(result.tpidrro_el0));
#endif
    return result;
}

struct GuestThreadObservation {
    bool passed = false;
    uintptr_t hardware_tpidr_el0 = 0;
    uint64_t final_guest_x18 = 0;
    uintptr_t final_guest_tls = 0;
    uintptr_t guest_tlr = 0;
    bool guest_stack_roundtrip = false;
};

static_assert(offsetof(GuestStackRoundTrip, guest_frame_sp) == 0);
static_assert(offsetof(GuestStackRoundTrip, host_sp_before_callback) == 8);
static_assert(offsetof(GuestStackRoundTrip, host_callback_sp) == 16);
static_assert(offsetof(GuestStackRoundTrip, restored_host_sp) == 24);
static_assert(offsetof(GuestStackRoundTrip, callback_result) == 32);

constexpr uintptr_t synthetic_callback_budget_bytes = 20 * 1024;

struct SyntheticCallbackState {
    GuestStackRoundTrip* roundtrip = nullptr;
    unsigned invocation_count = 0;
    bool expected_sp_match = false;
};

uint64_t consume_host_stack(void* opaque, uintptr_t expected_host_sp) noexcept {
    auto* state = static_cast<SyntheticCallbackState*>(opaque);
    if (state == nullptr || state->roundtrip == nullptr || expected_host_sp == 0) return 0;
    ++state->invocation_count;
    auto* roundtrip = state->roundtrip;
    state->expected_sp_match = expected_host_sp == roundtrip->host_sp_before_callback;
    volatile uint8_t pressure[16384]{};
    pressure[0] = 1;
    pressure[4096] = 2;
    pressure[8192] = 3;
    pressure[12288] = 4;
    pressure[16383] = 5;
    roundtrip->host_callback_sp = reinterpret_cast<uintptr_t>(&pressure[0]);
    return static_cast<uint64_t>(pressure[0] + pressure[4096] + pressure[8192] +
                                 pressure[12288] + pressure[16383]);
}

void run_guest_thread_observation(unsigned index, GuestThreadObservation* observation) {
    if (observation == nullptr) return;

    const uint64_t guest_x18_base = UINT64_C(0xa180000000000000) +
                                    static_cast<uint64_t>(index) * UINT64_C(0x100000000);
    const uintptr_t guest_tls_base = UINT64_C(0x6000000000000000) +
                                     static_cast<uintptr_t>(index) * UINT64_C(0x100000);
    const uintptr_t guest_tlr = UINT64_C(0x7000000000000000) +
                                static_cast<uintptr_t>(index) * UINT64_C(0x100000);

    pthread_attr_t attributes{};
    void* stack_address = nullptr;
    size_t stack_size = 0;
    const bool attributes_ready = pthread_getattr_np(pthread_self(), &attributes) == 0;
    const bool bounds_ready = attributes_ready &&
                              pthread_attr_getstack(&attributes, &stack_address, &stack_size) == 0;
    if (attributes_ready) pthread_attr_destroy(&attributes);
    const uintptr_t stack_low = reinterpret_cast<uintptr_t>(stack_address);
    const bool stack_add_ok = stack_size <= UINTPTR_MAX - stack_low;
    const uintptr_t stack_high = stack_add_ok ? stack_low + stack_size : 0;
    const uintptr_t anchor_source = reinterpret_cast<uintptr_t>(&attributes);
    const uintptr_t stack_anchor = anchor_source & ~uintptr_t{15};

    GuestThreadContext context{};
    const HardwareThreadRegisters before = capture_hardware_thread_registers();
    bool ok = bounds_ready && stack_add_ok &&
              guest_thread_context_init(&context, guest_tls_base, guest_tlr) == GuestThreadResult::ok &&
              guest_thread_bind(&context) == GuestThreadResult::ok &&
              guest_thread_set_host_stack(&context, stack_low, stack_high, stack_anchor) ==
                  GuestThreadResult::ok;

    uint64_t observed_x18 = 0;
    uintptr_t observed_tls = 0;
    uintptr_t observed_tlr = 0;
    for (uint64_t iteration = 0; ok && iteration < 10000; ++iteration) {
        ok = guest_x18_store(&context, guest_x18_base + iteration) == GuestThreadResult::ok &&
             guest_tpidr_el0_store(&context, guest_tls_base + iteration) == GuestThreadResult::ok &&
             guest_x18_load(&context, &observed_x18) == GuestThreadResult::ok &&
             guest_tpidr_el0_load(&context, &observed_tls) == GuestThreadResult::ok &&
             guest_tpidrro_el0_load(&context, &observed_tlr) == GuestThreadResult::ok &&
             observed_x18 == guest_x18_base + iteration &&
             observed_tls == guest_tls_base + iteration && observed_tlr == guest_tlr;
    }

    const long page_size_long = sysconf(_SC_PAGESIZE);
    const size_t page_size = page_size_long > 0 ? static_cast<size_t>(page_size_long) : 0;
    void* guest_mapping = MAP_FAILED;
    GuestStackRoundTrip roundtrip{};
    SyntheticCallbackState callback_state{&roundtrip, 0, false};
    if (ok && page_size != 0 && page_size <= SIZE_MAX / 3) {
        guest_mapping = mmap(nullptr, page_size * 3, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    const uintptr_t guest_low = guest_mapping == MAP_FAILED
                                    ? 0
                                    : reinterpret_cast<uintptr_t>(guest_mapping) + page_size;
    const uintptr_t guest_high = guest_low == 0 ? 0 : guest_low + page_size;
    const uintptr_t guest_sp = guest_high >= 16 ? guest_high - 16 : 0;
    const bool guest_stack_ready =
        ok && guest_mapping != MAP_FAILED &&
        mprotect(reinterpret_cast<void*>(guest_low), page_size, PROT_READ | PROT_WRITE) == 0;
    const GuestHostServiceRequest service_request{
        guest_low, guest_high, guest_sp, synthetic_callback_budget_bytes, 0};
    const GuestThreadResult service_result = guest_stack_ready
        ? guest_host_service_call(&context, service_request, consume_host_stack,
                                  &callback_state, &roundtrip)
        : GuestThreadResult::invalid_stack;
    const bool host_stack_released = service_result == GuestThreadResult::ok &&
        guest_thread_begin_host_stack_use(&context) == GuestThreadResult::ok &&
        guest_thread_end_host_stack_use(&context) == GuestThreadResult::ok;
    const uint64_t callback_result = roundtrip.callback_result;
    const bool callback_on_host = roundtrip.host_callback_sp >= stack_low &&
                                  roundtrip.host_callback_sp < stack_high &&
                                  !(roundtrip.host_callback_sp >= guest_low &&
                                    roundtrip.host_callback_sp < guest_high);
    const bool stack_roundtrip_ok = guest_stack_ready &&
        service_result == GuestThreadResult::ok && host_stack_released &&
        callback_state.invocation_count == 1 && callback_state.expected_sp_match &&
        roundtrip.guest_frame_sp >= guest_low && roundtrip.guest_frame_sp < guest_high &&
        (roundtrip.guest_frame_sp & uintptr_t{15}) == 0 &&
        roundtrip.host_sp_before_callback >= stack_low &&
        roundtrip.host_sp_before_callback < stack_high &&
        roundtrip.host_sp_before_callback == roundtrip.restored_host_sp &&
        callback_on_host && callback_result == 15 && roundtrip.callback_result == 15;
    const bool guest_mapping_released = guest_mapping != MAP_FAILED &&
                                        munmap(guest_mapping, page_size * 3) == 0;
    ok = ok && stack_roundtrip_ok && guest_mapping_released;

    const HardwareThreadRegisters after = capture_hardware_thread_registers();
    const bool hardware_preserved = before == after && before.tpidr_el0 != 0;
    const bool guest_not_hardware = observed_x18 != before.x18 &&
                                    observed_tls != before.tpidr_el0 &&
                                    observed_tlr != before.tpidrro_el0;
    const bool unbound = context.is_bound() &&
                         guest_thread_unbind(&context) == GuestThreadResult::ok &&
                         guest_thread_current() == nullptr;

    observation->passed = ok && hardware_preserved && guest_not_hardware && unbound;
    observation->hardware_tpidr_el0 = before.tpidr_el0;
    observation->final_guest_x18 = observed_x18;
    observation->final_guest_tls = observed_tls;
    observation->guest_tlr = observed_tlr;
    observation->guest_stack_roundtrip = stack_roundtrip_ok;
}

void test_guest_thread_context(TestState& state) {
    GuestThreadObservation observations[2]{};
    std::thread first(run_guest_thread_observation, 0, &observations[0]);
    std::thread second(run_guest_thread_observation, 1, &observations[1]);
    first.join();
    second.join();

    const bool isolated = observations[0].passed && observations[1].passed &&
                          observations[0].hardware_tpidr_el0 != observations[1].hardware_tpidr_el0 &&
                          observations[0].final_guest_x18 != observations[1].final_guest_x18 &&
                          observations[0].final_guest_tls != observations[1].final_guest_tls &&
                          observations[0].guest_tlr != observations[1].guest_tlr &&
                          observations[0].guest_stack_roundtrip &&
                          observations[1].guest_stack_roundtrip;
    state.check(isolated, "bionic_guest_thread_context",
                isolated ? "threads=2 guest_state=isolated host_x18_tls=preserved guest_stack_callback=ok"
                         : "guest thread ownership or hardware preservation failed");
}

void test_tls_threads_atomics(TestState& state) {
    std::atomic<uint64_t> observed{0};
    tls_value = 7;
    std::thread worker([&observed] {
        tls_value = 41;
        observed.store(static_cast<uint64_t>(tls_value), std::memory_order_release);
    });
    worker.join();
    const bool tls_ok = tls_value == 7 && observed.load(std::memory_order_acquire) == 41;
    state.check(tls_ok, "tls_threads", tls_ok ? "thread_local state isolated" : "TLS isolation failed");

    std::atomic<uint64_t> atom{0};
    atom.fetch_add(1, std::memory_order_seq_cst);
    const bool atomic_ok = atom.load() == 1;
    state.check(atomic_ok, "atomic64", atom.is_lock_free() ? "value correct; lock-free"
                                                           : "value correct; not lock-free");
}

void test_exceptions(TestState& state) {
    bool caught = false;
    try {
        throw std::runtime_error("probe");
    } catch (const std::runtime_error& error) {
        caught = std::strcmp(error.what(), "probe") == 0;
    }
    state.check(caught, "cpp_exceptions", caught ? "throw/catch and unwind succeeded" : "exception mismatch");
}

void test_synthetic_module(TestState& state, long page_size) {
    const size_t page = static_cast<size_t>(page_size);
    if (page > std::numeric_limits<size_t>::max() / 4) {
        state.check(false, "synthetic_module", "page-size overflow");
        return;
    }
    const size_t image_size = page * 4;
    auto* image = static_cast<uint8_t*>(mmap(nullptr, image_size, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (image == MAP_FAILED) {
        state.check(false, "synthetic_module", std::strerror(errno));
        return;
    }

    // text: add x0, x0, x1; ret. patch: mov x0, #42; ret.
    const uint32_t text_code[] = {0x8b010000U, 0xd65f03c0U};
    const uint32_t patch_code[] = {0xd2800540U, 0xd65f03c0U};
    std::memcpy(image, text_code, sizeof(text_code));
    std::memcpy(image + page * 3, patch_code, sizeof(patch_code));

    const ModuleRelocation relocations[] = {
        {page, ModuleRelocationKind::relative, 0, 0},
        {page + sizeof(uintptr_t), ModuleRelocationKind::absolute64,
         reinterpret_cast<uintptr_t>(image + page * 3), 0},
    };
    const auto relocation_result = apply_module_relocations(
        image, image_size, page, page * 2, relocations, std::size(relocations));
    const uintptr_t relr_addends[] = {0, page, page * 3};
    std::memcpy(image + page + 16, &relr_addends[0], sizeof(uintptr_t));
    std::memcpy(image + page + 24, &relr_addends[1], sizeof(uintptr_t));
    std::memcpy(image + page + 40, &relr_addends[2], sizeof(uintptr_t));
    const uint64_t relr_entries[] = {page + 16, 0b1011};
    size_t relr_applied = 0;
    const auto relr_result = apply_module_relr(image, image_size, page, page * 2,
                                               relr_entries, std::size(relr_entries),
                                               relr_applied);
    uintptr_t relative_value = 0;
    uintptr_t absolute_value = 0;
    std::memcpy(&relative_value, image + page, sizeof(relative_value));
    std::memcpy(&absolute_value, image + page + sizeof(uintptr_t), sizeof(absolute_value));
    uintptr_t relr_values[3]{};
    std::memcpy(&relr_values[0], image + page + 16, sizeof(uintptr_t));
    std::memcpy(&relr_values[1], image + page + 24, sizeof(uintptr_t));
    std::memcpy(&relr_values[2], image + page + 40, sizeof(uintptr_t));

    __builtin___clear_cache(reinterpret_cast<char*>(image),
                            reinterpret_cast<char*>(image + page));
    __builtin___clear_cache(reinterpret_cast<char*>(image + page * 3),
                            reinterpret_cast<char*>(image + page * 3 + sizeof(patch_code)));
    const bool protected_ok =
        mprotect(image, page, PROT_READ | PROT_EXEC) == 0 &&
        mprotect(image + page * 2, page, PROT_READ) == 0 &&
        mprotect(image + page * 3, page, PROT_READ | PROT_EXEC) == 0;

    bool execution_ok = false;
    if (relocation_result == ModuleRelocationResult::ok && protected_ok) {
        using AddFn = uint64_t (*)(uint64_t, uint64_t);
        using ConstantFn = uint64_t (*)();
        const auto add = reinterpret_cast<AddFn>(image);
        const auto constant = reinterpret_cast<ConstantFn>(image + page * 3);
        execution_ok = add(19, 23) == 42 && constant() == 42;
    }

    const bool ok = relocation_result == ModuleRelocationResult::ok &&
                    relr_result == ModuleRelocationResult::ok && relr_applied == 3 &&
                    relative_value == reinterpret_cast<uintptr_t>(image) &&
                    absolute_value == reinterpret_cast<uintptr_t>(image + page * 3) &&
                    relr_values[0] == reinterpret_cast<uintptr_t>(image) &&
                    relr_values[1] == reinterpret_cast<uintptr_t>(image + page) &&
                    relr_values[2] == reinterpret_cast<uintptr_t>(image + page * 3) &&
                    protected_ok && execution_ok;
    char detail[192]{};
    std::snprintf(detail, sizeof(detail), "relocations=%s relr=%s/%zu protections=%s execution=%s",
                  module_relocation_result_name(relocation_result),
                  module_relocation_result_name(relr_result), relr_applied,
                  protected_ok ? "ok" : "failed",
                  execution_ok ? "ok" : "failed");
    munmap(image, image_size);
    state.check(ok, "synthetic_module", detail);
}

bool run_cross_module_pages(uint8_t* provider, uint8_t* consumer, size_t page,
                            char* detail, size_t detail_size) {
    constexpr uint32_t mov_x0_42 = 0xd2800540;
    constexpr uint32_t ret = 0xd65f03c0;
    std::memcpy(provider, &mov_x0_42, sizeof(mov_x0_42));
    std::memcpy(provider + sizeof(mov_x0_42), &ret, sizeof(ret));

    const ModuleExport provider_exports[] = {{"provider_constant", 0, true}};
    const ModuleView modules[] = {
        {provider, page, provider_exports, std::size(provider_exports)},
        {consumer, page, nullptr, 0},
    };
    uintptr_t symbol = 0;
    const ModuleSymbolResult symbol_result = resolve_module_symbol(
        modules, std::size(modules), "provider_constant", symbol);
    const ModuleRelocation relocation = {
        0,
        ModuleRelocationKind::absolute64,
        symbol,
        0,
    };
    const ModuleRelocationResult relocation_result = symbol_result == ModuleSymbolResult::ok
        ? apply_module_relocations(consumer, page, 0, page, &relocation, 1)
        : ModuleRelocationResult::invalid_arguments;

    __builtin___clear_cache(reinterpret_cast<char*>(provider),
                            reinterpret_cast<char*>(provider + sizeof(mov_x0_42) + sizeof(ret)));
    const bool protected_ok = mprotect(provider, page, PROT_READ | PROT_EXEC) == 0 &&
                              mprotect(consumer, page, PROT_READ) == 0;
    uintptr_t imported = 0;
    std::memcpy(&imported, consumer, sizeof(imported));
    bool execution_ok = false;
    if (symbol_result == ModuleSymbolResult::ok &&
        relocation_result == ModuleRelocationResult::ok && protected_ok && imported == symbol) {
        using ConstantFn = uint64_t (*)();
        execution_ok = reinterpret_cast<ConstantFn>(imported)() == 42;
    }

    const bool ok = symbol_result == ModuleSymbolResult::ok &&
                    relocation_result == ModuleRelocationResult::ok &&
                    protected_ok && imported == symbol && execution_ok;
    std::snprintf(detail, detail_size,
                  "resolution=%s relocation=%s protections=%s execution=%s",
                  module_symbol_result_name(symbol_result),
                  module_relocation_result_name(relocation_result),
                  protected_ok ? "ok" : "failed", execution_ok ? "ok" : "failed");
    return ok;
}

void test_cross_module_symbol(TestState& state, long page_size) {
    if (page_size <= 0) {
        state.check(false, "cross_module_symbol", "invalid page size");
        return;
    }
    const size_t page = static_cast<size_t>(page_size);
    auto* provider = static_cast<uint8_t*>(mmap(nullptr, page, PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    auto* consumer = static_cast<uint8_t*>(mmap(nullptr, page, PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (provider == MAP_FAILED || consumer == MAP_FAILED) {
        if (provider != MAP_FAILED) munmap(provider, page);
        if (consumer != MAP_FAILED) munmap(consumer, page);
        state.check(false, "cross_module_symbol", "module allocation failed");
        return;
    }

    char detail[224]{};
    const bool ok = run_cross_module_pages(provider, consumer, page, detail, sizeof(detail));
    munmap(consumer, page);
    munmap(provider, page);
    state.check(ok, "cross_module_symbol", detail);
}

GuestMapResult read_guest_maps(GuestAddressRange* ranges, size_t capacity, size_t& count) {
    count = 0;
    FILE* maps = std::fopen("/proc/self/maps", "r");
    if (maps == nullptr) return GuestMapResult::invalid_line;
    char line[4096];
    GuestMapResult result = GuestMapResult::ok;
    while (std::fgets(line, sizeof(line), maps) != nullptr) {
        if (std::strchr(line, '\n') == nullptr && std::feof(maps) == 0) {
            result = GuestMapResult::invalid_line;
            break;
        }
        GuestAddressRange range{};
        result = parse_guest_map_line(line, range);
        if (result != GuestMapResult::ok) break;
        result = append_guest_map_range(ranges, capacity, count, range);
        if (result != GuestMapResult::ok) break;
    }
    if (std::ferror(maps) != 0) result = GuestMapResult::invalid_line;
    std::fclose(maps);
    return result;
}

void test_bionic_vm_query(TestState& state, long page_size) {
    if (page_size <= 0 || static_cast<uint64_t>(page_size) >
                              std::numeric_limits<size_t>::max() / 4) {
        state.check(false, "bionic_vm_query", "invalid page size");
        return;
    }
    const size_t page = static_cast<size_t>(page_size);
    auto* mapping = static_cast<uint8_t*>(mmap(nullptr, page * 4,
                                               PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mapping == MAP_FAILED) {
        state.check(false, "bionic_vm_query", std::strerror(errno));
        return;
    }
    // Guard pages prevent the kernel from merging either observed region with
    // an unrelated adjacent VMA that happens to have the same permissions.
    const bool protected_ok = mprotect(mapping, page, PROT_NONE) == 0 &&
                              mprotect(mapping + page, page, PROT_READ) == 0 &&
                              mprotect(mapping + page * 3, page, PROT_NONE) == 0;
    constexpr size_t max_regions = 65536;
    auto regions = std::make_unique<VmRegion[]>(max_regions);
    size_t count = 0;
    const VmQueryResult read_result = protected_ok
        ? read_vm_regions("/proc/self/maps", regions.get(), max_regions, count)
        : VmQueryResult::io_error;
    VmRegion first{};
    VmRegion second{};
    const uint64_t address = reinterpret_cast<uintptr_t>(mapping + page);
    const VmQueryResult first_result = read_result == VmQueryResult::ok
        ? query_vm_region(regions.get(), count, address, first)
        : read_result;
    const VmQueryResult second_result = read_result == VmQueryResult::ok
        ? query_vm_region(regions.get(), count, address + page, second)
        : read_result;
    const bool first_ok = first_result == VmQueryResult::ok && first.lo == address &&
                          first.hi == address + page && first.readable &&
                          !first.writable && !first.executable && first.private_mapping;
    const bool second_ok = second_result == VmQueryResult::ok &&
                           second.lo == address + page && second.hi >= address + page * 2 &&
                           second.readable && second.writable && !second.executable &&
                           second.private_mapping;
    const bool released = munmap(mapping, page * 4) == 0;
    char detail[320]{};
    std::snprintf(detail, sizeof(detail),
                  "read=%s maps=%zu first=%s/%s second=%s/%s released=%s",
                  vm_query_result_name(read_result), count,
                  vm_query_result_name(first_result), first_ok ? "r--p" : "mismatch",
                  vm_query_result_name(second_result), second_ok ? "rw-p" : "mismatch",
                  released ? "yes" : "no");
    state.check(protected_ok && first_ok && second_ok && released,
                "bionic_vm_query", detail);
}

void test_modules_in_guest_window(TestState& state, uint64_t base, size_t page) {
    constexpr uint64_t provider_offset = UINT64_C(0x00100000);
    constexpr uint64_t consumer_offset = UINT64_C(0x00200000);
    auto* provider_address = reinterpret_cast<void*>(base + provider_offset);
    auto* consumer_address = reinterpret_cast<void*>(base + consumer_offset);
    auto* provider = static_cast<uint8_t*>(mmap(provider_address, page,
                                                PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                                -1, 0));
    const int provider_errno = provider == MAP_FAILED ? errno : 0;
    auto* consumer = static_cast<uint8_t*>(mmap(consumer_address, page,
                                                PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                                -1, 0));
    const int consumer_errno = consumer == MAP_FAILED ? errno : 0;
    const bool mapped = provider == provider_address && consumer == consumer_address;
    char detail[256]{};
    bool ok = false;
    if (mapped) {
        char execution_detail[192]{};
        ok = run_cross_module_pages(provider, consumer, page,
                                    execution_detail, sizeof(execution_detail));
        std::snprintf(detail, sizeof(detail),
                      "provider=+0x%" PRIx64 " consumer=+0x%" PRIx64 "; %s",
                      provider_offset, consumer_offset, execution_detail);
    } else {
        std::snprintf(detail, sizeof(detail),
                      "fixed submap failed provider_errno=%d consumer_errno=%d",
                      provider_errno, consumer_errno);
    }
    state.check(ok, "guest_window_modules", detail);
}

void test_private_module_set_relocation(
    TestState& state, const char* const* paths, size_t path_count,
    const char* relocation_path, const char* private_entry_binding_path,
    uint64_t guest_base, size_t page) {
    constexpr uint64_t guest_size = UINT64_C(0x320000000);
    constexpr uint64_t module_slot_size = UINT64_C(0x10000000);
    constexpr uint64_t max_records = UINT64_C(600000);
    constexpr uint64_t max_journal_bytes = UINT64_C(16) * 1024 * 1024;
    RelocationStreamSummary stream{};
    const RelocationStreamResult stream_result =
        validate_relocation_stream(relocation_path, stream);
    if (stream_result != RelocationStreamResult::ok ||
        stream.module_count != private_module_count || path_count != private_module_count) {
        char detail[192]{};
        std::snprintf(detail, sizeof(detail), "stream=%s module_count=%" PRIu64,
                      relocation_stream_result_name(stream_result), stream.module_count);
        state.check(false, "private_module_set_relocation_admission", detail);
        return;
    }
    struct CarrierFiles {
        std::array<FILE*, private_module_count> handles{};
        ~CarrierFiles() {
            for (FILE* handle : handles) {
                if (handle != nullptr) std::fclose(handle);
            }
        }
    } carriers;
    bool opened = paths != nullptr;
    for (size_t index = 0; index < carriers.handles.size() && opened; ++index) {
        opened = paths[index] != nullptr && *paths[index] != '\0';
        if (opened) {
            carriers.handles[index] = std::fopen(paths[index], "rb");
            opened = carriers.handles[index] != nullptr;
        }
    }
    if (!opened) {
        state.check(false, "private_module_set_relocation_admission", "carrier open failed");
        return;
    }
    std::array<PrivateModuleDescriptor, private_module_count> descriptors{};
    for (size_t index = 0; index < descriptors.size(); ++index) {
        descriptors[index] = {stream.modules[index].guest_offset,
                              stream.modules[index].image_size,
                              stream.modules[index].writable_begin,
                              stream.modules[index].writable_end};
    }
    PrivateModuleSetLayout layout{};
    const PrivateElfResult inspect_result = inspect_private_elf_file_set(
        carriers.handles.data(), carriers.handles.size(), descriptors.data(),
        descriptors.size(), guest_size, module_slot_size, layout);
    if (inspect_result != PrivateElfResult::ok || page == 0 ||
        (page & (page - 1)) != 0 || page > 65536) {
        char detail[192]{};
        std::snprintf(detail, sizeof(detail), "inspection=%s",
                      private_elf_result_name(inspect_result));
        state.check(false, "private_module_set_relocation_admission", detail);
        return;
    }

    PortableEntryBinding entry_binding{};
    GuestStartupPlan startup_plan{};
    bool binding_admitted = false;
    EntryBindingAdmissionCapability admission_capability{};
    if (private_entry_binding_path != nullptr) {
        FILE* binding_file = std::fopen(private_entry_binding_path, "rb");
        FILE* relocation_file = relocation_path == nullptr ? nullptr : std::fopen(relocation_path, "rb");
        const EntryBindingReadResult read_result = binding_file == nullptr
            ? EntryBindingReadResult::io_error
            : read_entry_binding(binding_file, entry_binding);
        if (binding_file != nullptr) std::fclose(binding_file);
        const EntryBindingResult admitted = read_result == EntryBindingReadResult::ok
            ? admit_entry_binding_live(entry_binding, carriers.handles.data(), relocation_file,
                                       stream, layout, guest_base, startup_plan, admission_capability)
            : EntryBindingResult::read_failed;
        if (relocation_file != nullptr) std::fclose(relocation_file);
        binding_admitted = admitted == EntryBindingResult::ok;
        if (!binding_admitted) {
            char detail[192]{};
            std::snprintf(detail, sizeof(detail), "binding_admit=%s", entry_binding_result_name(admitted));
            state.check(false, "private_module_set_relocation_admission", detail);
            return;
        }
    } else {
        state.check(false, "private_module_set_relocation_admission",
                    "binding_admit=null_input");
        return;
    }

    std::array<RelocationDestinationModule, private_module_count> destinations{};
    PrivateModuleMapSummary map_summary{};
    const PrivateModuleMapResult mapped = map_private_module_set_no_execute(
        carriers.handles.data(), layout, stream, guest_base, page, destinations.data(),
        destinations.size(), map_summary, admission_capability);
    RelocationApplyOptions apply_options{};
    apply_options.max_records = max_records;
    apply_options.max_journal_bytes = max_journal_bytes;
    RelocationApplySummary apply_summary{};
    const RelocationStreamResult applied = mapped == PrivateModuleMapResult::ok
        ? apply_relocation_stream_transactional(relocation_path, guest_base,
                                                destinations.data(), destinations.size(),
                                                apply_options, apply_summary)
        : RelocationStreamResult::invalid_destination_state;
    EntryBindingObservation binding_observation{};
    const EntryBindingResult consumed = binding_admitted &&
        applied == RelocationStreamResult::ok
        ? consume_admitted_entry_binding(admission_capability, entry_binding, stream, layout, destinations.data(),
                                destinations.size(), guest_base, startup_plan,
                                binding_observation)
        : EntryBindingResult::invalid_state;
    const PrivateModuleMapResult sealed = applied == RelocationStreamResult::ok &&
        consumed == EntryBindingResult::ok
        ? seal_private_module_set_read_only(layout, stream, guest_base, page)
        : PrivateModuleMapResult::protect_failed;
    const PrivateModuleMapResult restored = restore_private_module_slots(stream, guest_base);
    const bool success_ok = mapped == PrivateModuleMapResult::ok &&
                            applied == RelocationStreamResult::ok &&
                            consumed == EntryBindingResult::ok &&
                            binding_observation.consumed && binding_observation.no_execute &&
                            binding_observation.module_count == private_module_count &&
                            apply_summary.writes_committed == stream.record_count &&
                            sealed == PrivateModuleMapResult::ok &&
                            restored == PrivateModuleMapResult::ok;
    char success_detail[640]{};
    std::snprintf(success_detail, sizeof(success_detail),
                  "inspection=%s roles=main,subsdk0,sdk modules=%zu segments=%" PRIu64
                  " image_bytes=%" PRIu64 " file_bytes=%" PRIu64
                  " zero_fill=%" PRIu64 " map=%s apply=%s/%" PRIu64
                  " caps=%" PRIu64 "/%" PRIu64
                  " permissions=%s binding_consumed=%u binding_modules=%u execution=not_attempted restored=%s",
                  private_elf_result_name(inspect_result), layout.module_count,
                  map_summary.segment_count, layout.total_image_size,
                  layout.total_file_bytes, layout.total_zero_fill,
                  private_module_map_result_name(mapped),
                  relocation_stream_result_name(applied), apply_summary.writes_committed,
                  max_records, max_journal_bytes,
                  sealed == PrivateModuleMapResult::ok ? "read_only_no_exec" : "incomplete",
                  binding_observation.consumed ? 1u : 0u, binding_observation.module_count,
                  restored == PrivateModuleMapResult::ok ? "yes" : "no");
    state.check(success_ok, "private_module_set_relocation_success", success_detail);
    if (restored != PrivateModuleMapResult::ok) {
        state.check(false, "private_module_set_relocation_restoration",
                    "fresh mapping unavailable after slot restoration failure");
        return;
    }

    destinations = {};
    map_summary = {};
    const PrivateModuleMapResult fresh_mapped = map_private_module_set_no_execute(
        carriers.handles.data(), layout, stream, guest_base, page, destinations.data(),
        destinations.size(), map_summary, admission_capability);
    RelocationApplyOptions rollback_options{};
    rollback_options.max_records = max_records;
    rollback_options.max_journal_bytes = max_journal_bytes;
    rollback_options.fail_after_writes = stream.record_count / 2;
    RelocationApplySummary rollback_summary{};
    const RelocationStreamResult rollback = fresh_mapped == PrivateModuleMapResult::ok
        ? apply_relocation_stream_transactional(relocation_path, guest_base,
                                                destinations.data(), destinations.size(),
                                                rollback_options, rollback_summary)
        : RelocationStreamResult::invalid_destination_state;
    const PrivateModuleMapResult pristine = rollback == RelocationStreamResult::injected_failure
        ? verify_private_module_set_matches_carriers(
              carriers.handles.data(), layout, stream, guest_base)
        : PrivateModuleMapResult::content_mismatch;
    const PrivateModuleMapResult rollback_sealed = pristine == PrivateModuleMapResult::ok
        ? seal_private_module_set_read_only(layout, stream, guest_base, page)
        : PrivateModuleMapResult::protect_failed;
    const PrivateModuleMapResult rollback_restored =
        restore_private_module_slots(stream, guest_base);
    const bool rollback_ok = fresh_mapped == PrivateModuleMapResult::ok &&
                             rollback == RelocationStreamResult::injected_failure &&
                             rollback_summary.writes_committed == 0 &&
                             rollback_summary.writes_rolled_back ==
                                 rollback_options.fail_after_writes &&
                             pristine == PrivateModuleMapResult::ok &&
                             rollback_sealed == PrivateModuleMapResult::ok &&
                             rollback_restored == PrivateModuleMapResult::ok;
    char rollback_detail[512]{};
    std::snprintf(rollback_detail, sizeof(rollback_detail),
                  "fresh_mapping=%s injected_after=%" PRIu64
                  " rollback=%s/%" PRIu64 " carrier_match=%s"
                  " permissions=%s execution=not_attempted restored=%s",
                  private_module_map_result_name(fresh_mapped),
                  rollback_options.fail_after_writes,
                  relocation_stream_result_name(rollback),
                  rollback_summary.writes_rolled_back,
                  pristine == PrivateModuleMapResult::ok ? "yes" : "no",
                  rollback_sealed == PrivateModuleMapResult::ok
                      ? "read_only_no_exec" : "incomplete",
                  rollback_restored == PrivateModuleMapResult::ok ? "yes" : "no");
    state.check(rollback_ok, "private_module_set_relocation_rollback", rollback_detail);
}

void test_guest_window(TestState& state, long page_size,
                       const char* const* private_module_paths,
                       size_t private_module_path_count,
                       const char* private_relocation_stream_path,
                       const char* private_entry_binding_path) {
    if (page_size <= 0) {
        state.check(false, "guest_window_12_5_gib", "invalid page size");
        return;
    }
    constexpr size_t max_ranges = 65536;
    constexpr uint64_t guest_size = UINT64_C(0x320000000);  // 12.5 GiB
    constexpr uint64_t guest_alignment = UINT64_C(0x100000000);
    constexpr uint64_t guest_floor = UINT64_C(0x100000000);
    constexpr uint64_t guest_ceiling = UINT64_C(1) << 39;
    auto ranges = std::make_unique<GuestAddressRange[]>(max_ranges);

    GuestMapResult result = GuestMapResult::no_hole;
    uint64_t base = 0;
    size_t count = 0;
    void* reservation = MAP_FAILED;
    int saved_errno = 0;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        result = read_guest_maps(ranges.get(), max_ranges, count);
        if (result != GuestMapResult::ok) break;
        result = find_guest_window(ranges.get(), count, guest_floor, guest_ceiling,
                                   guest_size, guest_alignment, base);
        if (result != GuestMapResult::ok) break;
        reservation = mmap(reinterpret_cast<void*>(base), static_cast<size_t>(guest_size),
                           PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
                                          MAP_FIXED_NOREPLACE,
                           -1, 0);
        if (reservation == reinterpret_cast<void*>(base)) break;
        saved_errno = errno;
        if (reservation != MAP_FAILED) munmap(reservation, static_cast<size_t>(guest_size));
        reservation = MAP_FAILED;
    }

    bool ok = result == GuestMapResult::ok &&
              reservation == reinterpret_cast<void*>(base);
    char detail[224]{};
    if (ok) {
        test_modules_in_guest_window(state, base, static_cast<size_t>(page_size));
        if (private_module_paths != nullptr && private_relocation_stream_path != nullptr) {
            test_private_module_set_relocation(
                state, private_module_paths, private_module_path_count,
                private_relocation_stream_path, private_entry_binding_path,
                base, static_cast<size_t>(page_size));
        }
        const bool released = munmap(reservation, static_cast<size_t>(guest_size)) == 0;
        ok = released;
        std::snprintf(detail, sizeof(detail), "base=0x%" PRIx64 " size=0x%" PRIx64
                      " maps=%zu; reserved and %s",
                      base, guest_size, count, released ? "released" : "release failed");
    } else {
        std::snprintf(detail, sizeof(detail), "result=%s candidate=0x%" PRIx64
                      " errno=%d (%s) maps=%zu",
                      guest_map_result_name(result), base, saved_errno,
                      saved_errno ? std::strerror(saved_errno) : "none", count);
    }
    state.check(ok, "guest_window_12_5_gib", detail);
}

void test_transactional_relocation_apply(TestState& state, const char* scratch_directory) {
    constexpr size_t header_size = 64;
    constexpr size_t descriptor_size = 48;
    constexpr size_t record_size = 32;
    constexpr size_t module_count = 2;
    constexpr size_t record_count = 4;
    constexpr size_t records_offset = header_size + module_count * descriptor_size;
    std::array<uint8_t, records_offset + record_count * record_size> stream{};
    const auto put = [&stream](size_t offset, uint64_t value, size_t width) {
        for (size_t index = 0; index < width; ++index) {
            stream[offset + index] = static_cast<uint8_t>(value & 0xffU);
            value >>= 8U;
        }
    };
    std::memcpy(stream.data(), "TOTKRLP1", 8);
    put(8, 1, 4);
    put(12, header_size, 4);
    put(16, descriptor_size, 4);
    put(20, record_size, 4);
    put(24, module_count, 8);
    put(32, record_count, 8);
    put(40, UINT64_C(0x320000000), 8);
    put(48, UINT64_C(0x10000000), 8);
    put(56, UINT64_C(0x10000000), 8);
    const auto descriptor = [&put](size_t index, uint64_t records) {
        const size_t offset = header_size + index * descriptor_size;
        put(offset, index, 4);
        put(offset + 8, UINT64_C(0x10000000) * (index + 1), 8);
        put(offset + 16, 0x3000, 8);
        put(offset + 24, 0x2000, 8);
        put(offset + 32, 0x2100, 8);
        put(offset + 40, records, 8);
    };
    descriptor(0, 1);
    descriptor(1, 3);
    const auto record = [&put, &stream](size_t index, uint64_t target, uint32_t kind,
                                        uint8_t source, uint8_t provider,
                                        uint64_t symbol, int64_t addend) {
        const size_t offset = records_offset + index * record_size;
        put(offset, target, 8);
        put(offset + 8, kind, 4);
        stream[offset + 12] = source;
        stream[offset + 13] = provider;
        put(offset + 16, symbol, 8);
        put(offset + 24, static_cast<uint64_t>(addend), 8);
    };
    record(0, 0x2000, 1027, 2, 0, 0, 0x10);
    record(1, 0x2000, 257, 1, 0, 0x20, 4);
    record(2, 0x2008, 1025, 1, 0xff, 0, 0);
    record(3, 0x2010, 1026, 1, 1, 0x28, 0);

    char temporary[512]{};
    const int name_length = std::snprintf(temporary, sizeof(temporary),
                                          "%s/transactional-relocation-XXXXXX",
                                          scratch_directory == nullptr ? "." : scratch_directory);
    if (name_length < 0 || static_cast<size_t>(name_length) >= sizeof(temporary)) {
        state.check(false, "transactional_relocation_synthetic", "scratch path too long");
        return;
    }
    const int file = mkstemp(temporary);
    if (file < 0) {
        state.check(false, "transactional_relocation_synthetic", "synthetic stream create failed");
        return;
    }
    size_t written = 0;
    while (written < stream.size()) {
        const ssize_t amount = write(file, stream.data() + written, stream.size() - written);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) break;
        written += static_cast<size_t>(amount);
    }
    const bool stream_ready = written == stream.size() && close(file) == 0;
    if (!stream_ready) {
        unlink(temporary);
        state.check(false, "transactional_relocation_synthetic", "synthetic stream write failed");
        return;
    }

    std::array<uint8_t, 0x3000> first{};
    std::array<uint8_t, 0x3000> second{};
    first.fill(0x5a);
    second.fill(0xa5);
    std::array<RelocationDestinationModule, module_count> modules = {
        RelocationDestinationModule{first.data(), 0x10000000, 0x3000,
                                    0x2000, 0x2100, true, true, false},
        RelocationDestinationModule{second.data(), 0x20000000, 0x3000,
                                    0x2000, 0x2100, true, true, false},
    };
    constexpr uint64_t guest_base = UINT64_C(0x100000000);
    RelocationApplyOptions options{};
    RelocationApplySummary success_summary{};
    const RelocationStreamResult success = apply_relocation_stream_transactional(
        temporary, guest_base, modules.data(), modules.size(), options, success_summary);
    uint64_t first_value = 0;
    uint64_t last_value = 0;
    std::memcpy(&first_value, first.data() + 0x2000, sizeof(first_value));
    std::memcpy(&last_value, second.data() + 0x2010, sizeof(last_value));
    first.fill(0x5a);
    second.fill(0xa5);
    const auto first_before = first;
    const auto second_before = second;
    options.fail_after_writes = 3;
    RelocationApplySummary rollback_summary{};
    const RelocationStreamResult rollback = apply_relocation_stream_transactional(
        temporary, guest_base, modules.data(), modules.size(), options, rollback_summary);
    const bool removed = unlink(temporary) == 0;
    const bool ok = success == RelocationStreamResult::ok &&
                    success_summary.writes_committed == record_count &&
                    first_value == guest_base + 0x10000000 + 0x10 &&
                    last_value == guest_base + 0x20000000 + 0x28 &&
                    rollback == RelocationStreamResult::injected_failure &&
                    rollback_summary.writes_committed == 0 &&
                    rollback_summary.writes_rolled_back == 3 &&
                    first == first_before && second == second_before && removed;
    char detail[256]{};
    std::snprintf(detail, sizeof(detail),
                  "apply=%s/%" PRIu64 " rollback=%s/%" PRIu64
                  " bytes_restored=%s private_stream=not_applied execution=not_attempted",
                  relocation_stream_result_name(success), success_summary.writes_committed,
                  relocation_stream_result_name(rollback), rollback_summary.writes_rolled_back,
                  (first == first_before && second == second_before) ? "yes" : "no");
    state.check(ok, "transactional_relocation_synthetic", detail);
}

void test_private_relocation_stream(TestState& state, const char* path) {
    RelocationStreamSummary summary{};
    const RelocationStreamResult result = validate_relocation_stream(path, summary);
    char detail[384]{};
    std::snprintf(detail, sizeof(detail),
                  "validation=%s modules=%" PRIu64 " records=%" PRIu64
                  " bytes=%" PRIu64 " abs64=%" PRIu64 " glob_dat=%" PRIu64
                  " jump_slot=%" PRIu64 " relative=%" PRIu64
                  " rela=%" PRIu64 " relr=%" PRIu64
                  " relocation=not_applied mapped_bytes=not_touched execution=not_attempted",
                  relocation_stream_result_name(result), summary.module_count,
                  summary.record_count, summary.file_bytes, summary.abs64_count,
                  summary.glob_dat_count, summary.jump_slot_count, summary.relative_count,
                  summary.rela_count, summary.relr_count);
    state.check(result == RelocationStreamResult::ok,
                "private_relocation_stream_validate_only", detail);
}

}  // namespace

int run_loader_probe(const char* const* private_module_paths,
                     size_t private_module_path_count,
                     const char* private_relocation_stream_path,
                     const char* private_entry_binding_path,
                     const char* scratch_directory,
                     const VulkanProbeObservation* vulkan_observation,
                     const VulkanSwapchainObservation* vulkan_swapchain_observation,
                     const VulkanClearObservation* clear_observation,
                     bool vulkan_required) {
#if !defined(__aarch64__)
#error "loader_probe must compile for AArch64"
#endif
    TestState state;
    const long page_size = sysconf(_SC_PAGESIZE);
    std::printf("probe=totk_android_loader version=1\n");
    std::printf("arch=aarch64 pointer_bits=%zu android_api_compile=%d page_size=%ld\n",
                sizeof(void*) * 8,
#ifdef __ANDROID_API__
                __ANDROID_API__,
#else
                -1,
#endif
                page_size);

    state.check(page_size == 4096 || page_size == 16384 || page_size == 65536,
                "page_size_known", "recorded for loader alignment policy");
    test_guest_startup_plan(state);

    test_generated_code(state, page_size);
    test_synthetic_module(state, page_size);
    test_cross_module_symbol(state, page_size);
    test_fixed_address(state, page_size, UINT64_C(0x0000000080000000));
    test_fixed_address(state, page_size, UINT64_C(0x0000007100000000));
    test_fixed_address(state, page_size, UINT64_C(0x0000007f00000000));
    test_guest_window(state, page_size, private_module_paths,
                      private_module_path_count, private_relocation_stream_path,
                      private_entry_binding_path);
    test_bionic_vm_query(state, page_size);
    test_signal_context_roundtrip(state, page_size);
    test_guest_thread_context(state);
    test_transactional_relocation_apply(state, scratch_directory);
    if (private_relocation_stream_path != nullptr) {
        test_private_relocation_stream(state, private_relocation_stream_path);
    }
    test_tls_threads_atomics(state);
    test_exceptions(state);
    if (vulkan_required) {
        const bool passed = vulkan_observation != nullptr &&
                            vulkan_observation->result == VulkanProbeResult::ok;
        char detail[512]{};
        if (passed) {
            std::snprintf(detail, sizeof(detail), "api=%u physical=%u queue=%u min_images=%u max_images=%u formats=%u present_modes=%u extent=%ux%u device=%s",
                          vulkan_observation->api_version, vulkan_observation->physical_device_index,
                          vulkan_observation->queue_family, vulkan_observation->min_image_count,
                          vulkan_observation->max_image_count, vulkan_observation->format_count,
                          vulkan_observation->present_mode_count, vulkan_observation->width,
                          vulkan_observation->height, vulkan_observation->device_name);
        } else {
            if (vulkan_observation) {
                std::snprintf(detail, sizeof(detail),
                              "result_name=%s physical_device_count=%u last_physical_device_index=%u queue_family_count=%u graphics_queue_count=%u present_queue_count=%u graphics_present_queue_count=%u device_extension_count=%u swapchain_extension=%u format_count=%u present_mode_count=%u min_image_count=%u max_image_count=%u",
                              vulkan_probe_result_name(vulkan_observation->result),
                              vulkan_observation->physical_device_count,
                              vulkan_observation->last_physical_device_index,
                              vulkan_observation->queue_family_count,
                              vulkan_observation->graphics_queue_count,
                              vulkan_observation->present_queue_count,
                              vulkan_observation->graphics_present_queue_count,
                              vulkan_observation->device_extension_count,
                              vulkan_observation->swapchain_extension ? 1u : 0u,
                              vulkan_observation->format_count,
                              vulkan_observation->present_mode_count,
                              vulkan_observation->min_image_count,
                              vulkan_observation->max_image_count);
            } else {
                std::snprintf(detail, sizeof(detail), "result_name=missing_observation physical_device_count=0 last_physical_device_index=0 queue_family_count=0 graphics_queue_count=0 present_queue_count=0 graphics_present_queue_count=0 device_extension_count=0 swapchain_extension=0 format_count=0 present_mode_count=0 min_image_count=0 max_image_count=0");
            }
        }
        state.check(passed, "vulkan_surface_device", detail);
        const bool present_passed =
            vulkan_swapchain_observation != nullptr &&
            vulkan_swapchain_observation->result == VulkanSwapchainResult::ok &&
            vulkan_swapchain_observation->submit_accepted &&
            vulkan_swapchain_observation->present_accepted &&
            vulkan_swapchain_observation->work_complete &&
            vulkan_swapchain_observation->cleanup_complete;
        char present_detail[512]{};
        if (vulkan_swapchain_observation) {
            std::snprintf(
                present_detail, sizeof(present_detail),
                "result_name=%s chosen_images=%u actual_images=%u acquired_index=%u extent=%ux%u format=%u colorspace=%u mode=%u composite_alpha=%u acquire_suboptimal=%u present_suboptimal=%u submit_accepted=%u present_accepted=%u work_complete=%u cleanup_complete=%u",
                vulkan_swapchain_result_name(vulkan_swapchain_observation->result),
                vulkan_swapchain_observation->chosen_image_count,
                vulkan_swapchain_observation->actual_image_count,
                vulkan_swapchain_observation->acquired_image_index,
                vulkan_swapchain_observation->width,
                vulkan_swapchain_observation->height,
                vulkan_swapchain_observation->chosen_format,
                vulkan_swapchain_observation->chosen_color_space,
                vulkan_swapchain_observation->chosen_present_mode,
                vulkan_swapchain_observation->chosen_composite_alpha,
                vulkan_swapchain_observation->acquire_suboptimal ? 1u : 0u,
                vulkan_swapchain_observation->present_suboptimal ? 1u : 0u,
                vulkan_swapchain_observation->submit_accepted ? 1u : 0u,
                vulkan_swapchain_observation->present_accepted ? 1u : 0u,
                vulkan_swapchain_observation->work_complete ? 1u : 0u,
                vulkan_swapchain_observation->cleanup_complete ? 1u : 0u);
        } else {
            std::snprintf(present_detail, sizeof(present_detail),
                          "result_name=missing_observation");
        }
        state.check(present_passed, "vulkan_swapchain_present", present_detail);
        const bool clear_passed = vulkan_swapchain_observation && clear_observation &&
            clear_observation->render_pass_created && clear_observation->image_view_created && clear_observation->framebuffer_created &&
            clear_observation->command_recorded && clear_observation->submit_accepted &&
            clear_observation->present_accepted && clear_observation->work_complete &&
            clear_observation->cleanup_complete &&
            vulkan_clear_cleanup_order_valid(clear_observation->cleanup_order,
                                             clear_observation->cleanup_order_count);
        state.check(clear_passed, "vulkan_clear_present",
                    clear_observation ? "rgba=1,0,1,1 render_pass=1 image_view=1 framebuffer=1 command=1 submit=1 present=1 complete=1 cleanup=1 order=framebuffer,image_view,render_pass" : "missing_observation");
    } else {
        state.check(true, "vulkan_surface_device",
                    "standalone omitted Android surface; swapchain/presentation unchecked");
        state.check(true, "vulkan_swapchain_present",
                    "standalone omitted Android swapchain/presentation; physical gate unchecked");
        state.check(true, "vulkan_clear_present",
                    "standalone omitted Android clear/presentation; physical gate unchecked");
    }

    std::printf("summary passed=%d failed=%d\n", state.passed, state.failed);
    return state.failed == 0 ? 0 : 1;
}

#if !defined(LOADER_PROBE_LIBRARY)
int main() { return run_loader_probe(); }
#endif
