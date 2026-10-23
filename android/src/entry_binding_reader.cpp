#include "entry_binding_reader.h"
#include "file_identity.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <cerrno>

namespace {
constexpr std::size_t kHeader = 160;
constexpr std::size_t kModule = 176;
constexpr std::size_t kEntry = 36;
constexpr std::size_t kPayload = kHeader + 3 * kModule + 2 * kEntry;
constexpr std::size_t kTotal = kPayload + 32;

struct Sha256 {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                           0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::uint64_t bits = 0;
    std::array<std::uint8_t, 64> block_bytes{};
    std::size_t buffered = 0;

    static std::uint32_t rotate_right(std::uint32_t value, unsigned count) {
        return (value >> count) | (value << (32u - count));
    }

    void compress(const std::uint8_t* input) {
        static constexpr std::uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
            0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
            0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
            0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
            0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
            0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
            0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
            0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
            0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
        std::uint32_t w[64]{};
        for (unsigned i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(input[4 * i]) << 24u) |
                   (static_cast<std::uint32_t>(input[4 * i + 1]) << 16u) |
                   (static_cast<std::uint32_t>(input[4 * i + 2]) << 8u) |
                   static_cast<std::uint32_t>(input[4 * i + 3]);
        }
        for (unsigned i = 16; i < 64; ++i) {
            const auto s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const auto s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        auto a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (unsigned i = 0; i < 64; ++i) {
            const auto s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const auto ch = (e & f) ^ (~e & g);
            const auto t1 = hh + s1 + ch + k[i] + w[i];
            const auto s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = s0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const std::uint8_t* input, std::size_t size) {
        bits += static_cast<std::uint64_t>(size) * 8u;
        while (size != 0) {
            const auto take = (std::min)(size, block_bytes.size() - buffered);
            std::memcpy(block_bytes.data() + buffered, input, take);
            buffered += take; input += take; size -= take;
            if (buffered == block_bytes.size()) { compress(block_bytes.data()); buffered = 0; }
        }
    }

    std::array<std::uint8_t, 32> finish() {
        block_bytes[buffered++] = 0x80;
        if (buffered > 56) { while (buffered < 64) block_bytes[buffered++] = 0; compress(block_bytes.data()); buffered = 0; }
        while (buffered < 56) block_bytes[buffered++] = 0;
        for (int i = 7; i >= 0; --i) block_bytes[buffered++] = static_cast<std::uint8_t>(bits >> (8 * i));
        compress(block_bytes.data());
        std::array<std::uint8_t, 32> result{};
        for (unsigned i = 0; i < 8; ++i) for (unsigned j = 0; j < 4; ++j)
            result[4 * i + j] = static_cast<std::uint8_t>(h[i] >> (24 - 8 * j));
        return result;
    }
};

std::uint16_t u16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8u); }
std::uint32_t u32(const std::uint8_t* p) { return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) | (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u); }
std::uint64_t u64(const std::uint8_t* p) { std::uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8u) | p[i]; return v; }
bool zero(const std::uint8_t* p, std::size_t n) { std::uint8_t v = 0; for (std::size_t i = 0; i < n; ++i) v |= p[i]; return v == 0; }
bool equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) { std::uint8_t v = 0; for (std::size_t i = 0; i < n; ++i) v |= a[i] ^ b[i]; return v == 0; }
bool add(std::uint64_t a, std::uint64_t b, std::uint64_t& result) { if (b > UINT64_MAX - a) return false; result = a + b; return true; }
}

EntryBindingReadResult read_entry_binding(std::FILE* file, PortableEntryBinding& out) {
    if (file == nullptr) return EntryBindingReadResult::null_input;
    std::array<std::uint8_t, kTotal> bytes{};
    const auto got = std::fread(bytes.data(), 1, bytes.size(), file);
    if (got != bytes.size()) return std::ferror(file) ? EntryBindingReadResult::io_error : EntryBindingReadResult::truncated;
    if (std::fgetc(file) != EOF) return EntryBindingReadResult::trailing_bytes;
    if (std::ferror(file)) return EntryBindingReadResult::io_error;
    Sha256 sha; sha.update(bytes.data(), kPayload);
    const auto digest = sha.finish();
    if (!equal(digest.data(), bytes.data() + kPayload, 32)) return EntryBindingReadResult::bad_digest;
    if (std::memcmp(bytes.data(), "TOTK-EBT\0", 8) != 0 || u16(bytes.data() + 8) != 1 || u16(bytes.data() + 10) != 0) return EntryBindingReadResult::bad_magic;
    if (u32(bytes.data() + 12) != 3 || u32(bytes.data() + 16) != kTotal) return EntryBindingReadResult::bad_header;
    if (zero(bytes.data() + 20, 32) || zero(bytes.data() + 52, 32) || zero(bytes.data() + 84, 32) || zero(bytes.data() + 116, 32)) return EntryBindingReadResult::bad_identity;
    if (!zero(bytes.data() + 148, 12)) return EntryBindingReadResult::bad_reserved;
    PortableEntryBinding candidate{}; candidate.module_count = 3;
    std::memcpy(candidate.trusted_manifest_digest.data(), bytes.data() + 20, 32);
    std::memcpy(candidate.relocation_digest.data(), bytes.data() + 52, 32);
    std::memcpy(candidate.source_self_digest.data(), bytes.data() + 84, 32);
    std::memcpy(candidate.canonical_file_digest.data(), bytes.data() + 116, 32);
    for (unsigned i = 0; i < 3; ++i) {
        const auto* p = bytes.data() + kHeader + i * kModule;
        if (p[0] != i || p[1] != i) return EntryBindingReadResult::bad_order;
        if (u16(p + 2) != 0 || !zero(p + 132, 44) || zero(p + 68, 32) || !zero(p + 100, 32) || u64(p + 60) == 0) return EntryBindingReadResult::bad_reserved;
        auto& m = candidate.modules[i]; m.id = static_cast<GuestModuleId>(i);
        m.image_size = u64(p + 4); m.writable_begin = u64(p + 12); m.writable_size = u64(p + 20);
        m.dt_init = u64(p + 28); m.ctor_flag = u64(p + 36); m.init_array = u64(p + 44); m.init_array_size = u64(p + 52); m.carrier_size = u64(p + 60);
        std::memcpy(m.carrier_digest.data(), p + 68, 32); std::uint64_t end = 0;
        if (m.image_size == 0 || m.writable_size == 0 || !add(m.writable_begin, m.writable_size, end) || end > m.image_size || m.dt_init == 0 || m.dt_init % 4 != 0 || m.dt_init >= m.image_size || m.ctor_flag % 4 != 0 || m.ctor_flag < m.writable_begin || m.ctor_flag >= end) return EntryBindingReadResult::bad_geometry;
        if ((m.init_array == 0) != (m.init_array_size == 0) || (m.init_array != 0 && (m.init_array % 8 != 0 || m.init_array_size % 8 != 0 || !add(m.init_array, m.init_array_size, end) || end > m.image_size))) return EntryBindingReadResult::bad_init_array;
    }
    auto read_entry = [&](unsigned i, PortableEntryBinding::Entry& entry) {
        const auto* p = bytes.data() + kHeader + 3 * kModule + i * kEntry;
        entry.provider = p[0]; entry.offset = u64(p + 4);
        if (p[1] != 0 || u16(p + 2) != 0 || std::memcmp(p + 12, "verified-elf\0\0\0\0", 16) != 0 || !zero(p + 28, 8)) return EntryBindingReadResult::bad_reserved;
        if (entry.provider >= 3) return EntryBindingReadResult::bad_provider;
        if (entry.offset == 0 || entry.offset % 4 != 0 || entry.offset >= candidate.modules[entry.provider].image_size) return EntryBindingReadResult::bad_entry;
        return EntryBindingReadResult::ok;
    };
    auto result = read_entry(0, candidate.nn_init_start); if (result != EntryBindingReadResult::ok) return result;
    result = read_entry(1, candidate.nn_main); if (result != EntryBindingReadResult::ok) return result;
    if (candidate.nn_init_start.provider != 2 || candidate.nn_main.provider != 0) return EntryBindingReadResult::bad_provider;
    for (const auto entry : {candidate.nn_init_start, candidate.nn_main}) { const auto& m = candidate.modules[entry.provider]; if (entry.offset == m.dt_init || entry.offset == m.ctor_flag || (m.init_array_size != 0 && entry.offset >= m.init_array && entry.offset < m.init_array + m.init_array_size)) return EntryBindingReadResult::bad_alias; }
    if (candidate.nn_init_start.provider == candidate.nn_main.provider && candidate.nn_init_start.offset == candidate.nn_main.offset) return EntryBindingReadResult::bad_alias;
    out = candidate; return EntryBindingReadResult::ok;
}

#ifdef ENTRY_BINDING_READER_TESTING
std::array<std::uint8_t, 32> entry_binding_test_sha256(const std::uint8_t* data, std::size_t size) {
    Sha256 sha;
    if (size != 0) sha.update(data, size);
    return sha.finish();
}
#endif

FileIdentityResult sha256_file_identity(std::FILE* file, std::uint64_t max_bytes,
                                         std::uint64_t& size, std::array<std::uint8_t, 32>& digest) {
    if (file == nullptr) return FileIdentityResult::null_input;
    const long original = std::ftell(file);
    if (original < 0) return FileIdentityResult::position_error;
    if (std::fseek(file, 0, SEEK_END) != 0) {
        (void)std::fseek(file, original, SEEK_SET);
        return FileIdentityResult::size_error;
    }
    const long end = std::ftell(file);
    if (end < 0) {
        (void)std::fseek(file, original, SEEK_SET);
        return FileIdentityResult::size_error;
    }
    if (std::fseek(file, original, SEEK_SET) != 0) return FileIdentityResult::position_error;
    const std::uint64_t candidate_size = static_cast<std::uint64_t>(end);
    if (candidate_size > max_bytes) return FileIdentityResult::too_large;
    if (std::fseek(file, 0, SEEK_SET) != 0) {
        (void)std::fseek(file, original, SEEK_SET);
        return FileIdentityResult::position_error;
    }
    Sha256 sha;
    std::array<std::uint8_t, 65536> buffer{};
    std::uint64_t remaining = candidate_size;
    while (remaining != 0) {
        const std::size_t want = remaining > buffer.size() ? buffer.size() : static_cast<std::size_t>(remaining);
        const std::size_t got = std::fread(buffer.data(), 1, want, file);
        if (got != want) {
            const bool io_error = std::ferror(file) != 0;
            (void)std::fseek(file, original, SEEK_SET);
            return io_error ? FileIdentityResult::io_error : FileIdentityResult::size_error;
        }
        sha.update(buffer.data(), got); remaining -= got;
    }
    const auto candidate_digest = sha.finish();
    if (std::fseek(file, original, SEEK_SET) != 0) return FileIdentityResult::position_error;
    size = candidate_size;
    digest = candidate_digest;
    return FileIdentityResult::ok;
}

FileIdentityResult sha256_path_identity(const char* path, std::uint64_t max_bytes,
                                        std::uint64_t& size, std::array<std::uint8_t, 32>& digest) {
    if (path == nullptr) return FileIdentityResult::null_input;
    std::FILE* file = std::fopen(path, "rb");
    if (file == nullptr) return FileIdentityResult::io_error;
    const auto result = sha256_file_identity(file, max_bytes, size, digest);
    std::fclose(file);
    return result;
}

const char* entry_binding_read_result_name(EntryBindingReadResult result) {
    switch (result) {
    case EntryBindingReadResult::ok: return "ok"; case EntryBindingReadResult::null_input: return "null_input"; case EntryBindingReadResult::io_error: return "io_error"; case EntryBindingReadResult::truncated: return "truncated"; case EntryBindingReadResult::trailing_bytes: return "trailing_bytes"; case EntryBindingReadResult::bad_magic: return "bad_magic"; case EntryBindingReadResult::bad_header: return "bad_header"; case EntryBindingReadResult::bad_reserved: return "bad_reserved"; case EntryBindingReadResult::bad_digest: return "bad_digest"; case EntryBindingReadResult::bad_identity: return "bad_identity"; case EntryBindingReadResult::bad_order: return "bad_order"; case EntryBindingReadResult::bad_geometry: return "bad_geometry"; case EntryBindingReadResult::bad_alignment: return "bad_alignment"; case EntryBindingReadResult::bad_init_array: return "bad_init_array"; case EntryBindingReadResult::bad_entry: return "bad_entry"; case EntryBindingReadResult::bad_provider: return "bad_provider"; case EntryBindingReadResult::bad_alias: return "bad_alias"; default: return "unknown_result";
    }
}
