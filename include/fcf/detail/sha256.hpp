// Fault Containment Fabric — SHA-256 content integrity digest.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DETAIL_SHA256_HPP
#define FCF_DETAIL_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace fcf::detail {

/// Collision-resistant digest used for evidence identity, duplicate detection and
/// canonical-state fingerprints. A 64-bit non-cryptographic hash would allow
/// adversarial collisions between conflicting evidence records.
class Sha256 {
public:
    static constexpr std::size_t kDigestBytes = 32;

    Sha256() noexcept;
    void update(const void* data, std::size_t length) noexcept;
    void update(std::span<const std::byte> data) noexcept { update(data.data(), data.size()); }
    void update(std::string_view text) noexcept { update(text.data(), text.size()); }
    [[nodiscard]] std::array<std::uint8_t, kDigestBytes> finish() noexcept;

    [[nodiscard]] static std::array<std::uint8_t, kDigestBytes> compute(std::span<const std::byte> data) noexcept {
        Sha256 h;
        h.update(data);
        return h.finish();
    }
    [[nodiscard]] static std::array<std::uint8_t, kDigestBytes> compute(std::string_view text) noexcept {
        Sha256 h;
        h.update(text);
        return h.finish();
    }

private:
    void compress(const std::uint8_t* block) noexcept;

    std::uint32_t state_[8];
    std::uint64_t bit_length_ = 0;
    std::uint8_t buffer_[64]{};
    std::size_t buffered_ = 0;
};

/// Lowercase hex rendering of a digest.
[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> digest);

}  // namespace fcf::detail

#endif  // FCF_DETAIL_SHA256_HPP
