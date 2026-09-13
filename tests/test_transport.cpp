// Fault Containment Fabric — framed transport proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <atomic>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

#include "fcf/detail/crc32c.hpp"
#include "fcf/net.hpp"
#include "fcf/protocol.hpp"
#include "fcf/wire.hpp"
#include "framework.hpp"

using namespace fcf;

namespace {

std::vector<std::byte> payload_of(const std::string& text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

void poke(std::vector<std::byte>& bytes, std::size_t offset) {
    bytes[offset] = static_cast<std::byte>(std::to_integer<std::uint8_t>(bytes[offset]) ^ 0x5AU);
}

}  // namespace

FCF_TEST(transport, frame_round_trip_preserves_kind_and_payload) {
    const std::vector<std::byte> payload = payload_of("containment intent");
    const Result<std::vector<std::byte>> encoded =
        encode_frame(MessageKind::ACTION_DISPATCH, payload);
    FCF_REQUIRE(encoded.ok());
    FCF_EQ(encoded.value().size(), kWireHeaderBytes + payload.size());
    const Result<Frame> decoded = decode_frame(encoded.value());
    FCF_REQUIRE(decoded.ok());
    FCF_EQ(decoded.value().kind, MessageKind::ACTION_DISPATCH);
    FCF_EQ(decoded.value().payload.size(), payload.size());
    FCF_REQUIRE(std::equal(payload.begin(), payload.end(), decoded.value().payload.begin()));
}

FCF_TEST(transport, bad_magic_is_rejected) {
    const Result<std::vector<std::byte>> encoded = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> broken = encoded.value();
    poke(broken, 0);
    const Result<Frame> decoded = decode_frame(broken);
    FCF_REQUIRE(!decoded.ok());
    FCF_EQ(decoded.error().code(), ErrorCode::FRAME_CORRUPT);
}

FCF_TEST(transport, unsupported_protocol_version_is_rejected) {
    const Result<std::vector<std::byte>> encoded = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> broken = encoded.value();
    poke(broken, 4);
    const FrameDecodeResult decoded =
        decode_frame_streaming(std::span<const std::byte>(broken.data(), broken.size()));
    FCF_EQ(decoded.state, FrameDecodeResult::State::FATAL);
    FCF_EQ(decoded.error, ErrorCode::PROTOCOL_VERSION_UNSUPPORTED);
}

FCF_TEST(transport, unknown_message_kind_is_rejected) {
    std::vector<std::byte> bytes = payload_of("");
    const Result<std::vector<std::byte>> encoded = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(encoded.ok());
    bytes = encoded.value();
    // Kind 0xFFFF is not a declared message kind and must never be accepted.
    bytes[6] = static_cast<std::byte>(0xFFU);
    bytes[7] = static_cast<std::byte>(0xFFU);
    const FrameDecodeResult decoded =
        decode_frame_streaming(std::span<const std::byte>(bytes.data(), bytes.size()));
    FCF_EQ(decoded.state, FrameDecodeResult::State::FATAL);
    FCF_EQ(decoded.error, ErrorCode::FRAME_CORRUPT);
}

FCF_TEST(transport, header_checksum_corruption_is_detected) {
    const Result<std::vector<std::byte>> encoded =
        encode_frame(MessageKind::HEARTBEAT, payload_of("x"));
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> broken = encoded.value();
    poke(broken, 8);  // corrupt the declared length inside the checksummed header
    const FrameDecodeResult decoded =
        decode_frame_streaming(std::span<const std::byte>(broken.data(), broken.size()));
    FCF_EQ(decoded.state, FrameDecodeResult::State::FATAL);
    FCF_EQ(decoded.error, ErrorCode::FRAME_CORRUPT);
}

FCF_TEST(transport, payload_checksum_corruption_is_detected) {
    const Result<std::vector<std::byte>> encoded =
        encode_frame(MessageKind::ACTION_DISPATCH, payload_of("some payload bytes"));
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> broken = encoded.value();
    poke(broken, kWireHeaderBytes + 3U);
    const FrameDecodeResult decoded =
        decode_frame_streaming(std::span<const std::byte>(broken.data(), broken.size()));
    FCF_EQ(decoded.state, FrameDecodeResult::State::FATAL);
    FCF_EQ(decoded.error, ErrorCode::FRAME_CORRUPT);
}

FCF_TEST(transport, oversized_declared_length_is_rejected_before_any_allocation) {
    const Result<std::vector<std::byte>> encoded = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> broken = encoded.value();
    // Recompute a valid header checksum over an absurd declared length so that the
    // length ceiling, not the checksum, is what rejects the frame.
    broken[8] = static_cast<std::byte>(0xFFU);
    broken[9] = static_cast<std::byte>(0xFFU);
    broken[10] = static_cast<std::byte>(0xFFU);
    broken[11] = static_cast<std::byte>(0x7FU);
    const std::uint32_t crc =
        fcf::detail::Crc32c::compute(std::span<const std::byte>(broken.data(), 12U));
    for (int i = 0; i < 4; ++i) {
        broken[12 + i] = static_cast<std::byte>((crc >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
    const FrameDecodeResult decoded =
        decode_frame_streaming(std::span<const std::byte>(broken.data(), broken.size()));
    FCF_EQ(decoded.state, FrameDecodeResult::State::FATAL);
    FCF_EQ(decoded.error, ErrorCode::FRAME_TOO_LARGE);
}

FCF_TEST(transport, payloads_above_the_frame_ceiling_cannot_be_encoded) {
    std::vector<std::byte> too_large(kMaxFramePayloadBytes + 1U, std::byte{0});
    const Result<std::vector<std::byte>> encoded =
        encode_frame(MessageKind::ACTION_DISPATCH, std::span<const std::byte>(too_large.data(),
                                                                             too_large.size()));
    FCF_REQUIRE(!encoded.ok());
    FCF_EQ(encoded.error().code(), ErrorCode::FRAME_TOO_LARGE);
}

FCF_TEST(transport, truncated_header_and_payload_report_need_more) {
    const Result<std::vector<std::byte>> encoded =
        encode_frame(MessageKind::ACTION_DISPATCH, payload_of("1234567890"));
    FCF_REQUIRE(encoded.ok());
    for (std::size_t length = 0; length < encoded.value().size(); ++length) {
        const FrameDecodeResult decoded = decode_frame_streaming(
            std::span<const std::byte>(encoded.value().data(), length));
        FCF_EQ(decoded.state, FrameDecodeResult::State::NEED_MORE);
    }
    const FrameDecodeResult complete = decode_frame_streaming(
        std::span<const std::byte>(encoded.value().data(), encoded.value().size()));
    FCF_EQ(complete.state, FrameDecodeResult::State::COMPLETE);
    FCF_EQ(complete.consumed, encoded.value().size());
}

FCF_TEST(transport, trailing_bytes_after_a_frame_are_rejected_exactly) {
    const Result<std::vector<std::byte>> encoded = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(encoded.ok());
    std::vector<std::byte> padded = encoded.value();
    padded.push_back(std::byte{0});
    const Result<Frame> decoded = decode_frame(padded);
    FCF_REQUIRE(!decoded.ok());
    FCF_EQ(decoded.error().code(), ErrorCode::FRAME_CORRUPT);
}

FCF_TEST(transport, streaming_decoder_accepts_arbitrary_fragmentation) {
    const Result<std::vector<std::byte>> first =
        encode_frame(MessageKind::ACTION_DISPATCH, payload_of("first frame payload"));
    const Result<std::vector<std::byte>> second = encode_frame(MessageKind::HEARTBEAT, {});
    FCF_REQUIRE(first.ok() && second.ok());

    std::vector<std::byte> stream = first.value();
    stream.insert(stream.end(), second.value().begin(), second.value().end());

    // Feed the stream one byte at a time; framing must never assume one read equals
    // one frame.
    std::vector<std::byte> window;
    std::vector<MessageKind> kinds;
    for (const std::byte byte : stream) {
        window.push_back(byte);
        for (;;) {
            const FrameDecodeResult decoded =
                decode_frame_streaming(std::span<const std::byte>(window.data(), window.size()));
            if (decoded.state != FrameDecodeResult::State::COMPLETE) {
                FCF_REQUIRE(decoded.state == FrameDecodeResult::State::NEED_MORE);
                break;
            }
            kinds.push_back(decoded.frame.kind);
            window.erase(window.begin(),
                         window.begin() + static_cast<std::ptrdiff_t>(decoded.consumed));
        }
    }
    FCF_REQUIRE(window.empty());
    FCF_EQ(kinds.size(), 2U);
    FCF_EQ(kinds[0], MessageKind::ACTION_DISPATCH);
    FCF_EQ(kinds[1], MessageKind::HEARTBEAT);
}

FCF_TEST(transport, message_payloads_round_trip_through_the_shared_codec) {
    HelloMessage hello;
    hello.worker = WorkerId::from_value(4);
    hello.boot = WorkerBootId::from_value(99);
    hello.sequence = EvidenceSequence::from_value(3);
    hello.endpoint = "worker:1234";
    const Result<std::vector<std::byte>> hello_payload = encode_hello(hello);
    FCF_REQUIRE(hello_payload.ok());
    const Result<HelloMessage> hello_back = decode_hello(hello_payload.value());
    FCF_REQUIRE(hello_back.ok());
    FCF_EQ(hello_back.value().worker, hello.worker);
    FCF_EQ(hello_back.value().boot, hello.boot);
    FCF_EQ(hello_back.value().endpoint, hello.endpoint);

    // Trailing bytes inside a message payload are rejected.
    std::vector<std::byte> padded = hello_payload.value();
    padded.push_back(std::byte{0});
    FCF_REQUIRE(!decode_hello(padded).ok());

    // Invalid enum values inside a payload are rejected, not clamped.
    WorkerEvidenceMessage evidence;
    evidence.worker = WorkerId::from_value(1);
    evidence.boot = WorkerBootId::from_value(2);
    evidence.resource = ResourceId::from_value(3);
    evidence.freshness = EvidenceFreshness::FRESH;
    const Result<std::vector<std::byte>> evidence_payload = encode_worker_evidence(evidence);
    FCF_REQUIRE(evidence_payload.ok());
    const Result<WorkerEvidenceMessage> evidence_back = decode_worker_evidence(evidence_payload.value());
    FCF_REQUIRE(evidence_back.ok());
    FCF_EQ(evidence_back.value().resource, evidence.resource);
}

FCF_TEST(transport, real_tcp_carries_frames_in_both_directions) {
    const Status ready = initialise_network();
    FCF_REQUIRE(ready.ok());
    Result<Listener> listener = Listener::bind("127.0.0.1", 0);
    FCF_REQUIRE_MSG(listener.ok(), listener.ok() ? "" : listener.error().to_string());
    Listener bound = std::move(listener.value());
    const std::uint16_t port = bound.port();
    FCF_REQUIRE(port != 0);

    std::atomic<bool> accepted{false};
    std::atomic<bool> server_ok{false};
    std::string server_detail;
    std::thread server([&bound, &accepted, &server_ok, &server_detail]() {
        Result<Socket> peer = bound.accept();
        if (!peer.ok()) {
            server_detail = peer.error().to_string();
            accepted.store(true);
            return;
        }
        accepted.store(true);
        Socket socket = std::move(peer.value());
        const Result<Frame> incoming = socket.receive_frame();
        if (!incoming.ok()) {
            server_detail = incoming.error().to_string();
            return;
        }
        if (incoming.value().kind != MessageKind::CONTROL_REQUEST) {
            server_detail = "unexpected kind";
            return;
        }
        ControlResponse response;
        response.ok = true;
        response.message = "handled";
        response.add("echo");
        const Result<std::vector<std::byte>> payload = encode_control_response(response);
        if (!payload.ok()) {
            server_detail = payload.error().to_string();
            return;
        }
        const Status sent = socket.send_frame(MessageKind::CONTROL_RESPONSE, payload.value());
        if (!sent.ok()) {
            server_detail = sent.error().to_string();
            return;
        }
        server_ok.store(true);
        socket.close();
    });

    Result<Socket> client = Socket::connect("127.0.0.1", port);
    FCF_REQUIRE_MSG(client.ok(), client.ok() ? "" : client.error().to_string());
    Socket socket = std::move(client.value());
    ControlRequest request;
    request.command = "status";
    const Result<std::vector<std::byte>> payload = encode_control_request(request);
    FCF_REQUIRE(payload.ok());
    FCF_REQUIRE(socket.send_frame(MessageKind::CONTROL_REQUEST, payload.value()).ok());
    const Result<Frame> reply = socket.receive_frame();
    FCF_REQUIRE_MSG(reply.ok(), reply.ok() ? "" : reply.error().to_string());
    FCF_EQ(reply.value().kind, MessageKind::CONTROL_RESPONSE);
    const Result<ControlResponse> decoded = decode_control_response(reply.value().payload);
    FCF_REQUIRE(decoded.ok());
    FCF_REQUIRE(decoded.value().ok);
    FCF_EQ(decoded.value().message, std::string("handled"));
    socket.close();
    server.join();
    FCF_REQUIRE(accepted.load());
    FCF_REQUIRE_MSG(server_ok.load(), server_detail);
    bound.close();
    shutdown_network();
}

FCF_TEST(transport, repeated_connect_and_disconnect_is_bounded_and_stable) {
    const Status ready = initialise_network();
    FCF_REQUIRE(ready.ok());
    Result<Listener> listener = Listener::bind("127.0.0.1", 0);
    FCF_REQUIRE(listener.ok());
    Listener bound = std::move(listener.value());
    const std::uint16_t port = bound.port();

    constexpr int kRounds = 40;
    std::atomic<int> handled{0};
    std::thread server([&bound, &handled]() {
        for (int round = 0; round < kRounds; ++round) {
            Result<Socket> peer = bound.accept();
            if (!peer.ok()) {
                return;
            }
            Socket socket = std::move(peer.value());
            const Result<Frame> frame = socket.receive_frame();
            if (!frame.ok()) {
                return;
            }
            (void)socket.send_frame(MessageKind::HEARTBEAT, {});
            handled.fetch_add(1);
            socket.close();
        }
    });

    for (int round = 0; round < kRounds; ++round) {
        Result<Socket> client = Socket::connect("127.0.0.1", port);
        FCF_REQUIRE_MSG(client.ok(), client.ok() ? "" : client.error().to_string());
        Socket socket = std::move(client.value());
        FCF_REQUIRE(socket.send_frame(MessageKind::CONTROL_REQUEST, payload_of("x")).ok());
        const Result<Frame> reply = socket.receive_frame();
        FCF_REQUIRE(reply.ok());
        FCF_EQ(reply.value().kind, MessageKind::HEARTBEAT);
        socket.close();
    }
    server.join();
    FCF_EQ(handled.load(), kRounds);
    bound.close();
    shutdown_network();
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
