// Fault Containment Fabric — bounded, checked binary codec.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// This codec is the single decode path for durable state and wire payloads.
// It is written as a hostile-input boundary: every length is validated before
// any allocation, all arithmetic is checked, and decoding is bounded.

#ifndef FCF_DETAIL_BYTES_HPP
#define FCF_DETAIL_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fcf/ids.hpp"

namespace fcf::detail {

/// Largest encoded string accepted or produced (bytes, before the length prefix).
inline constexpr std::size_t kMaxStringBytes = 64U * 1024U;
/// Largest encoded opaque blob accepted or produced.
inline constexpr std::size_t kMaxBlobBytes = 4U * 1024U * 1024U;
/// Largest element count accepted for any encoded collection.
inline constexpr std::uint32_t kMaxCollectionCount = 4U * 1024U * 1024U;

/// Checked unsigned addition.
[[nodiscard]] constexpr bool checked_add(std::size_t a, std::size_t b, std::size_t& out) noexcept {
    if (a > SIZE_MAX - b) {
        return false;
    }
    out = a + b;
    return true;
}

/// Checked unsigned multiplication.
[[nodiscard]] constexpr bool checked_mul(std::size_t a, std::size_t b, std::size_t& out) noexcept {
    if (a != 0 && b > SIZE_MAX / a) {
        return false;
    }
    out = a * b;
    return true;
}

/// Strict UTF-8 validation: rejects overlong encodings, surrogates, values above
/// U+10FFFF and truncated sequences.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

/// Little-endian bounded writer. Once a limit is violated the writer latches a
/// failure and every subsequent write is a no-op, so callers can validate once.
class ByteWriter {
public:
    void u8(std::uint8_t value) noexcept;
    void u16(std::uint16_t value) noexcept;
    void u32(std::uint32_t value) noexcept;
    void u64(std::uint64_t value) noexcept;
    void i64(std::int64_t value) noexcept;
    void boolean(bool value) noexcept { u8(value ? 1U : 0U); }
    void raw(const void* data, std::size_t length);
    void raw(std::span<const std::byte> data) { raw(data.data(), data.size()); }
    /// Writes a u32 byte length followed by the bytes themselves.
    void blob(std::span<const std::byte> data);
    /// Writes a u32 byte length followed by validated UTF-8 bytes.
    void str(std::string_view text);

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
    [[nodiscard]] const std::vector<std::byte>& buffer() const noexcept { return buffer_; }
    [[nodiscard]] std::span<const std::byte> span() const noexcept {
        return std::span<const std::byte>(buffer_.data(), buffer_.size());
    }
    [[nodiscard]] std::vector<std::byte> take() { return std::move(buffer_); }
    void clear() noexcept {
        buffer_.clear();
        ok_ = true;
    }
    /// Reserves capacity; a reserve beyond the hard ceiling latches failure.
    void reserve(std::size_t bytes);

private:
    std::vector<std::byte> buffer_;
    bool ok_ = true;
};

/// Little-endian bounded reader. Any out-of-bounds or malformed access latches a
/// failure and yields a zero/empty value; the caller checks ok() once at the end.
class ByteReader {
public:
    ByteReader() noexcept = default;
    explicit ByteReader(std::span<const std::byte> data) noexcept
        : data_(data.data()), size_(data.size()) {}

    [[nodiscard]] std::uint8_t u8() noexcept;
    [[nodiscard]] std::uint16_t u16() noexcept;
    [[nodiscard]] std::uint32_t u32() noexcept;
    [[nodiscard]] std::uint64_t u64() noexcept;
    [[nodiscard]] std::int64_t i64() noexcept;
    [[nodiscard]] bool boolean() noexcept { return u8() != 0U; }
    [[nodiscard]] std::span<const std::byte> raw(std::size_t length) noexcept;
    [[nodiscard]] std::span<const std::byte> blob() noexcept;
    [[nodiscard]] std::string str() noexcept;
    /// Reads a count and checks it against a caller supplied ceiling before use.
    [[nodiscard]] std::uint32_t count(std::uint32_t ceiling) noexcept;

    /// Latches a decode failure when a downstream validator rejects a value that
    /// the primitive reader itself could not detect (bad enum, disorder, duplicates).
    void reject() noexcept { ok_ = false; }

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] bool at_end() const noexcept { return pos_ == size_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return size_ - pos_; }
    [[nodiscard]] std::size_t offset() const noexcept { return pos_; }

private:
    void fail() noexcept { ok_ = false; }

    const std::byte* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

/// Maximum total encoded size this codec will accept for one document.
inline constexpr std::size_t kMaxDocumentBytes = 128U * 1024U * 1024U;

// --- Typed value helpers shared by every encode/decode boundary ------------------------

/// Reads an enumeration value, rejecting anything above the declared maximum.
[[nodiscard]] std::uint16_t rd_enum(ByteReader& reader, std::uint16_t max_value) noexcept;

/// Reads a boolean, rejecting any encoding other than 0 or 1.
[[nodiscard]] bool rd_bool(ByteReader& reader) noexcept;

template <Identity IdT>
[[nodiscard]] IdT rd_id(ByteReader& reader) noexcept {
    return IdT::from_value(reader.u64());
}

template <Identity IdT>
void wr_id(ByteWriter& writer, IdT id) noexcept {
    writer.u64(id.value());
}

/// Reads a strictly increasing identity set, rejecting duplicates and disorder.
template <Identity IdT>
[[nodiscard]] IdSet<IdT> rd_ids(ByteReader& reader, std::uint32_t ceiling) noexcept {
    IdSet<IdT> out;
    const std::uint32_t count = reader.count(ceiling);
    if (count == 0U) {
        return out;
    }
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const IdT value = rd_id<IdT>(reader);
        if (!reader.ok()) {
            return {};
        }
        if (!out.empty() && !(out.back() < value)) {
            reader.reject();
            return {};
        }
        out.push_back(value);
    }
    return out;
}

template <Identity IdT>
void wr_ids(ByteWriter& writer, const IdSet<IdT>& ids) {
    writer.u32(static_cast<std::uint32_t>(ids.size()));
    for (const IdT id : ids) {
        wr_id(writer, id);
    }
}

}  // namespace fcf::detail

#endif  // FCF_DETAIL_BYTES_HPP
