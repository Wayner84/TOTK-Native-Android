#pragma once
#include <array>
#include <cstdint>
#include <cstdio>

enum class FileIdentityResult : std::uint8_t { ok, null_input, position_error, size_error, io_error, too_large };

// Hashes at most max_bytes, reports exact size, and restores the original FILE position.
FileIdentityResult sha256_file_identity(std::FILE* file, std::uint64_t max_bytes,
                                        std::uint64_t& size, std::array<std::uint8_t, 32>& digest);
FileIdentityResult sha256_path_identity(const char* path, std::uint64_t max_bytes,
                                        std::uint64_t& size, std::array<std::uint8_t, 32>& digest);
