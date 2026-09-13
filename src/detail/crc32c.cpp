// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/detail/crc32c.hpp"

namespace fcf::detail {
namespace {

/// Software CRC32C table for the reflected polynomial 0x82F63B78.
struct Crc32cTable {
    std::uint32_t entries[256]{};

    constexpr Crc32cTable() noexcept {
        for (std::uint32_t i = 0; i < 256U; ++i) {
            std::uint32_t crc = i;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1U) != 0U ? (crc >> 1U) ^ 0x82F63B78U : (crc >> 1U);
            }
            entries[i] = crc;
        }
    }
};

constexpr Crc32cTable kTable{};

}  // namespace

void Crc32c::update(const void* data, std::size_t length) noexcept {
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::uint32_t crc = state_;
    for (std::size_t i = 0; i < length; ++i) {
        crc = kTable.entries[(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8U);
    }
    state_ = crc;
}

}  // namespace fcf::detail
