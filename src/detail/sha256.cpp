// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/detail/sha256.hpp"

#include <cstring>

namespace fcf::detail {
namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, std::uint32_t bits) noexcept {
    return (value >> bits) | (value << (32U - bits));
}

}  // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Sha256::compress(const std::uint8_t* block) noexcept {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24U) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7U) ^ rotr(w[i - 15], 18U) ^ (w[i - 15] >> 3U);
        const std::uint32_t s1 = rotr(w[i - 2], 17U) ^ rotr(w[i - 2], 19U) ^ (w[i - 2] >> 10U);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + ch + kK[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, std::size_t length) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    bit_length_ += static_cast<std::uint64_t>(length) * 8U;
    std::size_t index = 0;
    if (buffered_ != 0) {
        while (index < length && buffered_ < 64) {
            buffer_[buffered_++] = bytes[index++];
        }
        if (buffered_ == 64) {
            compress(buffer_);
            buffered_ = 0;
        }
    }
    while (length - index >= 64) {
        compress(bytes + index);
        index += 64;
    }
    while (index < length) {
        if (buffered_ >= 64U) {
            // Unreachable: every full block above is compressed before control reaches
            // here. The explicit bound keeps the write provably in range.
            compress(buffer_);
            buffered_ = 0;
        }
        buffer_[buffered_++] = bytes[index++];
    }
}

std::array<std::uint8_t, Sha256::kDigestBytes> Sha256::finish() noexcept {
    const std::uint64_t bit_length = bit_length_;
    // Padding: a single 0x80 byte, zeros until exactly 56 bytes are buffered, then the
    // 64-bit big-endian message length. Every step goes through update(), which
    // compresses whenever the 64-byte block fills, so the padding length field is
    // written at a fixed, provably in-range offset.
    const std::uint8_t pad = 0x80U;
    update(&pad, 1);
    const std::uint8_t zero = 0x00U;
    while (buffered_ != 56U) {
        update(&zero, 1);
    }
    for (unsigned index = 0; index < 8U; ++index) {
        buffer_[56U + index] =
            static_cast<std::uint8_t>((bit_length >> (56U - index * 8U)) & 0xFFU);
    }
    compress(buffer_);
    buffered_ = 0;

    std::array<std::uint8_t, kDigestBytes> digest{};
    for (int i = 0; i < 8; ++i) {
        digest[static_cast<std::size_t>(i) * 4 + 0] = static_cast<std::uint8_t>((state_[i] >> 24U) & 0xFFU);
        digest[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16U) & 0xFFU);
        digest[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8U) & 0xFFU);
        digest[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
    }
    return digest;
}

std::string to_hex(std::span<const std::uint8_t> digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (const std::uint8_t byte : digest) {
        out.push_back(kHex[(byte >> 4U) & 0x0FU]);
        out.push_back(kHex[byte & 0x0FU]);
    }
    return out;
}

}  // namespace fcf::detail
