// Fault Containment Fabric — framed, bounded wire protocol.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A frame is:
//   [0,4)   magic        0x31464346 ('F','C','F','1')
//   [4,6)   version      little endian
//   [6,8)   kind         little endian
//   [8,12)  payload_len  little endian
//   [12,16) header_crc   CRC32C over bytes [0,12) -- the checksum field itself is
//                        deliberately excluded, so no canonical zeroing is needed
//   [16,20) payload_crc  CRC32C over the payload bytes
//   [20,..) payload
//
// The checksum covers the length field, so a corrupted length can never be used
// to size an allocation.

#ifndef FCF_WIRE_HPP
#define FCF_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "fcf/detail/bytes.hpp"
#include "fcf/detail/enum_macro.hpp"
#include "fcf/result.hpp"

namespace fcf {

inline constexpr std::uint32_t kWireMagic = 0x31464346U;
inline constexpr std::size_t kWireHeaderBytes = 20U;
inline constexpr std::uint32_t kMaxFramePayloadBytes = 1024U * 1024U;

#define FCF_MESSAGE_KINDS(X)     \
    X(HELLO)                     \
    X(HELLO_ACK)                 \
    X(WORKER_EVIDENCE_ACK)       \
    X(HEARTBEAT)                 \
    X(WORKER_EVIDENCE)           \
    X(FAULT_REPORT)              \
    X(ACTION_DISPATCH)           \
    X(ACTION_ACK)                \
    X(ACTION_RESULT)             \
    X(QUERY_REQUEST)             \
    X(QUERY_RESPONSE)            \
    X(CONTROL_REQUEST)           \
    X(CONTROL_RESPONSE)          \
    X(SHUTDOWN)                  \
    X(REJECT)

FCF_DEFINE_ENUM(MessageKind, FCF_MESSAGE_KINDS, REJECT)

/// A decoded frame with its payload.
struct Frame {
    std::uint16_t version = 0;
    MessageKind kind = MessageKind::REJECT;
    std::vector<std::byte> payload;

    [[nodiscard]] detail::ByteReader reader() const noexcept {
        return detail::ByteReader(std::span<const std::byte>(payload.data(), payload.size()));
    }
};

/// Encodes one frame. Fails when the payload exceeds the hard frame ceiling.
[[nodiscard]] Result<std::vector<std::byte>> encode_frame(MessageKind kind,
                                                          std::span<const std::byte> payload);

/// Decodes one frame from a complete buffer. Rejects bad magic, unsupported
/// versions, oversized declared lengths, checksum mismatches, malformed message
/// kinds and trailing bytes.
[[nodiscard]] Result<Frame> decode_frame(std::span<const std::byte> buffer);

/// Result of a bounded streaming decode over a socket-like reader.
struct FrameDecodeResult {
    enum class State : std::uint8_t { COMPLETE, NEED_MORE, FATAL };
    State state = State::NEED_MORE;
    Frame frame;
    std::size_t consumed = 0;
    ErrorCode error = ErrorCode::OK;
    std::string detail;
};

/// Attempts to decode exactly one frame from the head of buffer. When the header
/// is present but the payload is incomplete the result is NEED_MORE and the
/// caller must read more bytes; a header-level violation is FATAL.
[[nodiscard]] FrameDecodeResult decode_frame_streaming(std::span<const std::byte> buffer);

}  // namespace fcf

#endif  // FCF_WIRE_HPP
