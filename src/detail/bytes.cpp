// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/detail/bytes.hpp"

namespace fcf::detail {
namespace {

[[nodiscard]] constexpr bool is_continuation(unsigned char byte) noexcept {
    return (byte & 0xC0U) == 0x80U;
}

}  // namespace

bool is_valid_utf8(std::string_view text) noexcept {
    std::size_t i = 0;
    const std::size_t n = text.size();
    while (i < n) {
        const auto c0 = static_cast<unsigned char>(text[i]);
        if (c0 < 0x80U) {
            ++i;
            continue;
        }
        std::size_t extra = 0;
        std::uint32_t code = 0;
        std::uint32_t minimum = 0;
        if ((c0 & 0xE0U) == 0xC0U) {
            extra = 1;
            code = c0 & 0x1FU;
            minimum = 0x80U;
        } else if ((c0 & 0xF0U) == 0xE0U) {
            extra = 2;
            code = c0 & 0x0FU;
            minimum = 0x800U;
        } else if ((c0 & 0xF8U) == 0xF0U) {
            extra = 3;
            code = c0 & 0x07U;
            minimum = 0x10000U;
        } else {
            return false;  // continuation byte or invalid lead
        }
        if (i + extra >= n) {
            return false;  // truncated sequence
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cc = static_cast<unsigned char>(text[i + k]);
            if (!is_continuation(cc)) {
                return false;
            }
            code = (code << 6U) | (cc & 0x3FU);
        }
        if (code < minimum) {
            return false;  // overlong
        }
        if (code > 0x10FFFFU) {
            return false;
        }
        if (code >= 0xD800U && code <= 0xDFFFU) {
            return false;  // surrogate half
        }
        i += extra + 1;
    }
    return true;
}

void ByteWriter::reserve(std::size_t bytes) {
    if (!ok_) {
        return;
    }
    std::size_t needed = 0;
    if (!checked_add(buffer_.size(), bytes, needed) || needed > kMaxDocumentBytes) {
        ok_ = false;
        return;
    }
    buffer_.reserve(needed);
}

void ByteWriter::u8(std::uint8_t value) noexcept {
    if (!ok_) {
        return;
    }
    if (buffer_.size() + 1 > kMaxDocumentBytes) {
        ok_ = false;
        return;
    }
    buffer_.push_back(static_cast<std::byte>(value));
}

void ByteWriter::u16(std::uint16_t value) noexcept {
    u8(static_cast<std::uint8_t>(value & 0xFFU));
    u8(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void ByteWriter::u32(std::uint32_t value) noexcept {
    u16(static_cast<std::uint16_t>(value & 0xFFFFU));
    u16(static_cast<std::uint16_t>((value >> 16U) & 0xFFFFU));
}

void ByteWriter::u64(std::uint64_t value) noexcept {
    u32(static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    u32(static_cast<std::uint32_t>((value >> 32U) & 0xFFFFFFFFULL));
}

void ByteWriter::i64(std::int64_t value) noexcept {
    u64(static_cast<std::uint64_t>(value));
}

void ByteWriter::raw(const void* data, std::size_t length) {
    if (!ok_ || length == 0) {
        return;
    }
    if (data == nullptr) {
        ok_ = false;
        return;
    }
    std::size_t needed = 0;
    if (!checked_add(buffer_.size(), length, needed) || needed > kMaxDocumentBytes) {
        ok_ = false;
        return;
    }
    const auto* first = static_cast<const std::byte*>(data);
    buffer_.insert(buffer_.end(), first, first + length);
}

void ByteWriter::blob(std::span<const std::byte> data) {
    if (data.size() > kMaxBlobBytes) {
        ok_ = false;
        return;
    }
    u32(static_cast<std::uint32_t>(data.size()));
    raw(data.data(), data.size());
}

void ByteWriter::str(std::string_view text) {
    if (text.size() > kMaxStringBytes) {
        ok_ = false;
        return;
    }
    if (!is_valid_utf8(text)) {
        ok_ = false;
        return;
    }
    u32(static_cast<std::uint32_t>(text.size()));
    raw(text.data(), text.size());
}

std::uint8_t ByteReader::u8() noexcept {
    if (!ok_) {
        return 0;
    }
    if (pos_ + 1 > size_) {
        fail();
        return 0;
    }
    return std::to_integer<std::uint8_t>(data_[pos_++]);
}

std::uint16_t ByteReader::u16() noexcept {
    // Multi-byte reads are atomic: a short read yields zero and latches failure
    // rather than returning a partially assembled value.
    if (!ok_ || size_ - pos_ < 2U) {
        fail();
        return 0;
    }
    const std::uint16_t value = static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(data_[pos_]) |
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data_[pos_ + 1U])) << 8U));
    pos_ += 2U;
    return value;
}

std::uint32_t ByteReader::u32() noexcept {
    if (!ok_ || size_ - pos_ < 4U) {
        fail();
        return 0;
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data_[pos_ + i]))
                 << (8U * static_cast<unsigned>(i));
    }
    pos_ += 4U;
    return value;
}

std::uint64_t ByteReader::u64() noexcept {
    if (!ok_ || size_ - pos_ < 8U) {
        fail();
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data_[pos_ + i]))
                 << (8U * static_cast<unsigned>(i));
    }
    pos_ += 8U;
    return value;
}

std::int64_t ByteReader::i64() noexcept { return static_cast<std::int64_t>(u64()); }

std::span<const std::byte> ByteReader::raw(std::size_t length) noexcept {
    if (!ok_) {
        return {};
    }
    if (length > size_ - pos_) {
        fail();
        return {};
    }
    const std::span<const std::byte> out(data_ + pos_, length);
    pos_ += length;
    return out;
}

std::span<const std::byte> ByteReader::blob() noexcept {
    const std::uint32_t length = u32();
    if (!ok_) {
        return {};
    }
    if (length > kMaxBlobBytes) {
        fail();
        return {};
    }
    return raw(length);
}

std::string ByteReader::str() noexcept {
    const std::uint32_t length = u32();
    if (!ok_) {
        return {};
    }
    if (length > kMaxStringBytes) {
        fail();
        return {};
    }
    const auto bytes = raw(length);
    if (!ok_) {
        return {};
    }
    std::string out(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!is_valid_utf8(out)) {
        fail();
        return {};
    }
    return out;
}

std::uint32_t ByteReader::count(std::uint32_t ceiling) noexcept {
    const std::uint32_t value = u32();
    if (!ok_) {
        return 0;
    }
    if (value > ceiling) {
        fail();
        return 0;
    }
    return value;
}

}  // namespace fcf::detail
