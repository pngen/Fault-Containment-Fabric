// Fault Containment Fabric — CRC32C (Castagnoli) integrity protection.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DETAIL_CRC32C_HPP
#define FCF_DETAIL_CRC32C_HPP

#include <cstddef>
#include <cstdint>
#include <span>

namespace fcf::detail {

/// Incremental CRC32C using the reflected Castagnoli polynomial 0x82F63B78.
class Crc32c {
public:
    Crc32c() noexcept = default;

    void update(const void* data, std::size_t length) noexcept;
    void update(std::span<const std::byte> data) noexcept { update(data.data(), data.size()); }

    [[nodiscard]] std::uint32_t value() const noexcept { return state_ ^ 0xFFFFFFFFU; }

    static std::uint32_t compute(const void* data, std::size_t length) noexcept {
        Crc32c crc;
        crc.update(data, length);
        return crc.value();
    }
    static std::uint32_t compute(std::span<const std::byte> data) noexcept {
        return compute(data.data(), data.size());
    }

private:
    std::uint32_t state_ = 0xFFFFFFFFU;
};

}  // namespace fcf::detail

#endif  // FCF_DETAIL_CRC32C_HPP
