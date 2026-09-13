// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/wire.hpp"

#include <cstring>
#include <string>

#include "fcf/detail/crc32c.hpp"
#include "fcf/version.hpp"

namespace fcf {
namespace {

void put_u16(std::byte* out, std::uint16_t value) {
    out[0] = static_cast<std::byte>(value & 0xFFU);
    out[1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
}

void put_u32(std::byte* out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<std::byte>((value >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
}

std::uint16_t get_u16(const std::byte* in) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(in[0]) |
                                      (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(in[1])) << 8U));
}

std::uint32_t get_u32(const std::byte* in) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[i]))
                 << (8U * static_cast<unsigned>(i));
    }
    return value;
}

}  // namespace

Result<std::vector<std::byte>> encode_frame(MessageKind kind, std::span<const std::byte> payload) {
    if (payload.size() > kMaxFramePayloadBytes) {
        return make_error(ErrorCode::FRAME_TOO_LARGE, "wire.encode",
                          "payload exceeds the hard frame ceiling",
                          std::to_string(payload.size()));
    }
    std::vector<std::byte> out(kWireHeaderBytes + payload.size());
    put_u32(out.data() + 0, kWireMagic);
    put_u16(out.data() + 4, kWireProtocolVersion);
    put_u16(out.data() + 6, static_cast<std::uint16_t>(kind));
    put_u32(out.data() + 8, static_cast<std::uint32_t>(payload.size()));
    const std::uint32_t header_crc =
        detail::Crc32c::compute(std::span<const std::byte>(out.data(), kWireHeaderBytes - 8U));
    put_u32(out.data() + 12, header_crc);
    put_u32(out.data() + 16, detail::Crc32c::compute(payload));
    if (!payload.empty()) {
        std::memcpy(out.data() + kWireHeaderBytes, payload.data(), payload.size());
    }
    return out;
}

Result<Frame> decode_frame(std::span<const std::byte> buffer) {
    FrameDecodeResult streaming = decode_frame_streaming(buffer);
    if (streaming.state == FrameDecodeResult::State::NEED_MORE) {
        return make_error(ErrorCode::FRAME_CORRUPT, "wire.decode", "truncated frame",
                          std::to_string(buffer.size()));
    }
    if (streaming.state == FrameDecodeResult::State::FATAL) {
        return make_error(streaming.error, "wire.decode", streaming.detail);
    }
    if (streaming.consumed != buffer.size()) {
        return make_error(ErrorCode::FRAME_CORRUPT, "wire.decode", "trailing bytes after frame",
                          std::to_string(buffer.size() - streaming.consumed));
    }
    return streaming.frame;
}

FrameDecodeResult decode_frame_streaming(std::span<const std::byte> buffer) {
    FrameDecodeResult result;
    if (buffer.size() >= 4U && get_u32(buffer.data()) != kWireMagic) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::FRAME_CORRUPT;
        result.detail = "bad frame magic";
        return result;
    }
    if (buffer.size() < kWireHeaderBytes) {
        result.state = FrameDecodeResult::State::NEED_MORE;
        return result;
    }
    const std::uint16_t version = get_u16(buffer.data() + 4);
    if (version != kWireProtocolVersion) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::PROTOCOL_VERSION_UNSUPPORTED;
        result.detail = "unsupported protocol version " + std::to_string(version);
        return result;
    }
    const std::uint16_t raw_kind = get_u16(buffer.data() + 6);
    if (raw_kind > kMessageKindMax) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::FRAME_CORRUPT;
        result.detail = "unknown mandatory message type " + std::to_string(raw_kind);
        return result;
    }
    const std::uint32_t payload_len = get_u32(buffer.data() + 8);
    if (payload_len > kMaxFramePayloadBytes) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::FRAME_TOO_LARGE;
        result.detail = "declared payload length " + std::to_string(payload_len) + " exceeds ceiling";
        return result;
    }
    const std::uint32_t expected_header_crc =
        detail::Crc32c::compute(std::span<const std::byte>(buffer.data(), kWireHeaderBytes - 8U));
    if (get_u32(buffer.data() + 12) != expected_header_crc) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::FRAME_CORRUPT;
        result.detail = "header checksum mismatch";
        return result;
    }
    const std::size_t total = kWireHeaderBytes + static_cast<std::size_t>(payload_len);
    if (buffer.size() < total) {
        result.state = FrameDecodeResult::State::NEED_MORE;
        return result;
    }
    const std::span<const std::byte> payload = buffer.subspan(kWireHeaderBytes, payload_len);
    if (detail::Crc32c::compute(payload) != get_u32(buffer.data() + 16)) {
        result.state = FrameDecodeResult::State::FATAL;
        result.error = ErrorCode::FRAME_CORRUPT;
        result.detail = "payload checksum mismatch";
        return result;
    }
    result.state = FrameDecodeResult::State::COMPLETE;
    result.frame.version = version;
    result.frame.kind = static_cast<MessageKind>(raw_kind);
    result.frame.payload.assign(payload.begin(), payload.end());
    result.consumed = total;
    return result;
}

}  // namespace fcf
