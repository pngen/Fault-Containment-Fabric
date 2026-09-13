// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/protocol.hpp"

#include "fcf/detail/bytes.hpp"
#include "state_codec.hpp"

namespace fcf {
namespace {

using detail::ByteReader;
using detail::ByteWriter;

[[nodiscard]] std::vector<std::byte> to_bytes(const ByteWriter& writer) {
    return std::vector<std::byte>(writer.buffer().begin(), writer.buffer().end());
}

[[nodiscard]] Error malformed(const char* stage) {
    return make_error(ErrorCode::FRAME_CORRUPT, stage, "malformed message payload");
}

}  // namespace

Result<std::vector<std::byte>> encode_hello(const HelloMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    detail::wr_id(writer, message.worker);
    detail::wr_id(writer, message.boot);
    detail::wr_id(writer, message.epoch);
    detail::wr_id(writer, message.sequence);
    writer.str(message.endpoint);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.hello", "message did not encode");
    }
    return to_bytes(writer);
}

Result<HelloMessage> decode_hello(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    HelloMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.hello",
                          "unsupported payload version");
    }
    message.worker = detail::rd_id<WorkerId>(reader);
    message.boot = detail::rd_id<WorkerBootId>(reader);
    message.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    message.sequence = detail::rd_id<EvidenceSequence>(reader);
    message.endpoint = reader.str();
    if (!reader.ok() || !reader.at_end() || !message.worker.valid() || !message.boot.valid()) {
        return malformed("protocol.hello");
    }
    return message;
}

Result<std::vector<std::byte>> encode_hello_ack(const HelloAckMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    writer.boolean(message.accepted);
    detail::wr_id(writer, message.epoch);
    detail::wr_id(writer, message.incarnation);
    writer.str(message.detail);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.hello_ack", "message did not encode");
    }
    return to_bytes(writer);
}

Result<HelloAckMessage> decode_hello_ack(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    HelloAckMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.hello_ack",
                          "unsupported payload version");
    }
    const std::uint8_t accepted = reader.u8();
    if (!reader.ok() || accepted > 1U) {
        return malformed("protocol.hello_ack");
    }
    message.accepted = accepted == 1U;
    message.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    message.incarnation = detail::rd_id<WorkerIncarnation>(reader);
    message.detail = reader.str();
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.hello_ack");
    }
    return message;
}

Result<std::vector<std::byte>> encode_worker_evidence(const WorkerEvidenceMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    detail::wr_id(writer, message.worker);
    detail::wr_id(writer, message.boot);
    detail::wr_id(writer, message.epoch);
    detail::wr_id(writer, message.resource);
    detail::wr_id(writer, message.generation);
    writer.u16(static_cast<std::uint16_t>(message.freshness));
    detail::wr_id(writer, message.sequence);
    writer.u16(static_cast<std::uint16_t>(message.mechanism));
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.evidence", "message did not encode");
    }
    return to_bytes(writer);
}

Result<WorkerEvidenceMessage> decode_worker_evidence(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    WorkerEvidenceMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.evidence",
                          "unsupported payload version");
    }
    message.worker = detail::rd_id<WorkerId>(reader);
    message.boot = detail::rd_id<WorkerBootId>(reader);
    message.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    message.resource = detail::rd_id<ResourceId>(reader);
    message.generation = detail::rd_id<ResourceGeneration>(reader);
    message.freshness = static_cast<EvidenceFreshness>(detail::rd_enum(reader, kEvidenceFreshnessMax));
    message.sequence = detail::rd_id<EvidenceSequence>(reader);
    message.mechanism = static_cast<ContainmentMechanism>(detail::rd_enum(reader, kContainmentMechanismMax));
    if (!reader.ok() || !reader.at_end() || !message.worker.valid() || !message.boot.valid() ||
        !message.resource.valid()) {
        return malformed("protocol.evidence");
    }
    return message;
}

Result<std::vector<std::byte>> encode_worker_evidence_ack(const WorkerEvidenceAck& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    writer.boolean(message.granted);
    writer.boolean(message.fenced);
    detail::wr_id(writer, message.generation);
    writer.str(message.detail);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.evidence_ack", "message did not encode");
    }
    return to_bytes(writer);
}

Result<WorkerEvidenceAck> decode_worker_evidence_ack(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    WorkerEvidenceAck message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.evidence_ack",
                          "unsupported payload version");
    }
    const std::uint8_t granted = reader.u8();
    const std::uint8_t fenced = reader.u8();
    if (!reader.ok() || granted > 1U || fenced > 1U) {
        return malformed("protocol.evidence_ack");
    }
    message.granted = granted == 1U;
    message.fenced = fenced == 1U;
    message.generation = detail::rd_id<ResourceGeneration>(reader);
    message.detail = reader.str();
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.evidence_ack");
    }
    return message;
}

Result<std::vector<std::byte>> encode_fault_report(const FaultReportMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    detail::wr_id(writer, message.worker);
    detail::wr_id(writer, message.boot);
    detail::wr_id(writer, message.epoch);
    detail::write_fault_evidence(writer, message.evidence);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.fault_report", "message did not encode");
    }
    return to_bytes(writer);
}

Result<FaultReportMessage> decode_fault_report(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    FaultReportMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.fault_report",
                          "unsupported payload version");
    }
    message.worker = detail::rd_id<WorkerId>(reader);
    message.boot = detail::rd_id<WorkerBootId>(reader);
    message.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    if (!detail::read_fault_evidence(reader, message.evidence)) {
        return malformed("protocol.fault_report");
    }
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.fault_report");
    }
    return message;
}

Result<std::vector<std::byte>> encode_action_dispatch(const ActionDispatchMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    detail::write_action(writer, message.action);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.action_dispatch",
                          "message did not encode");
    }
    return to_bytes(writer);
}

Result<ActionDispatchMessage> decode_action_dispatch(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    ActionDispatchMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.action_dispatch",
                          "unsupported payload version");
    }
    if (!detail::read_action(reader, message.action)) {
        return malformed("protocol.action_dispatch");
    }
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.action_dispatch");
    }
    return message;
}

namespace {

void write_ack_fields(ByteWriter& writer, const ActionAcknowledgment& ack) {
    detail::wr_id(writer, ack.action);
    detail::wr_id(writer, ack.action_generation);
    detail::wr_id(writer, ack.epoch);
    detail::wr_id(writer, ack.worker);
    detail::wr_id(writer, ack.worker_boot);
    writer.boolean(ack.accepted);
    writer.str(ack.executor_token);
    writer.str(ack.detail);
}

bool read_ack_fields(ByteReader& reader, ActionAcknowledgment& ack) {
    ack.action = detail::rd_id<ActionId>(reader);
    ack.action_generation = detail::rd_id<ActionGeneration>(reader);
    ack.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    ack.worker = detail::rd_id<WorkerId>(reader);
    ack.worker_boot = detail::rd_id<WorkerBootId>(reader);
    const std::uint8_t accepted = reader.u8();
    if (!reader.ok() || accepted > 1U) {
        return false;
    }
    ack.accepted = accepted == 1U;
    ack.executor_token = reader.str();
    ack.detail = reader.str();
    return reader.ok() && ack.action.valid();
}

}  // namespace

Result<std::vector<std::byte>> encode_action_ack(const ActionAckMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    write_ack_fields(writer, message.ack);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.action_ack", "message did not encode");
    }
    return to_bytes(writer);
}

Result<ActionAckMessage> decode_action_ack(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    ActionAckMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.action_ack",
                          "unsupported payload version");
    }
    if (!read_ack_fields(reader, message.ack) || !reader.at_end()) {
        return malformed("protocol.action_ack");
    }
    return message;
}

namespace {

void write_result_fields(ByteWriter& writer, const ActionResult& result) {
    detail::wr_id(writer, result.action);
    detail::wr_id(writer, result.action_generation);
    detail::wr_id(writer, result.epoch);
    detail::wr_id(writer, result.worker);
    detail::wr_id(writer, result.worker_boot);
    writer.boolean(result.success);
    writer.u16(static_cast<std::uint16_t>(result.mechanism));
    writer.str(result.detail);
}

bool read_result_fields(ByteReader& reader, ActionResult& result) {
    result.action = detail::rd_id<ActionId>(reader);
    result.action_generation = detail::rd_id<ActionGeneration>(reader);
    result.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    result.worker = detail::rd_id<WorkerId>(reader);
    result.worker_boot = detail::rd_id<WorkerBootId>(reader);
    const std::uint8_t success = reader.u8();
    if (!reader.ok() || success > 1U) {
        return false;
    }
    result.success = success == 1U;
    result.mechanism =
        static_cast<ContainmentMechanism>(detail::rd_enum(reader, kContainmentMechanismMax));
    result.detail = reader.str();
    return reader.ok() && result.action.valid();
}

}  // namespace

Result<std::vector<std::byte>> encode_action_result(const ActionResultMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    write_result_fields(writer, message.result);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.action_result", "message did not encode");
    }
    return to_bytes(writer);
}

Result<ActionResultMessage> decode_action_result(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    ActionResultMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.action_result",
                          "unsupported payload version");
    }
    if (!read_result_fields(reader, message.result) || !reader.at_end()) {
        return malformed("protocol.action_result");
    }
    return message;
}

Result<std::vector<std::byte>> encode_reject(const RejectMessage& message) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    writer.u16(static_cast<std::uint16_t>(message.code));
    writer.str(message.detail);
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.reject", "message did not encode");
    }
    return to_bytes(writer);
}

Result<RejectMessage> decode_reject(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    RejectMessage message;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.reject",
                          "unsupported payload version");
    }
    message.code = static_cast<ErrorCode>(detail::rd_enum(reader, kErrorCodeMax));
    message.detail = reader.str();
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.reject");
    }
    return message;
}

Result<std::vector<std::byte>> encode_control_request(const ControlRequest& request) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    writer.str(request.command);
    writer.u32(static_cast<std::uint32_t>(request.arguments.size()));
    for (const std::string& argument : request.arguments) {
        writer.str(argument);
    }
    if (!writer.ok() || request.command.empty()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.control_request",
                          "request did not encode");
    }
    return to_bytes(writer);
}

Result<ControlRequest> decode_control_request(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    ControlRequest request;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.control_request",
                          "unsupported payload version");
    }
    request.command = reader.str();
    const std::uint32_t count = reader.count(1024U);
    for (std::uint32_t i = 0; i < count && reader.ok(); ++i) {
        request.arguments.push_back(reader.str());
    }
    if (!reader.ok() || !reader.at_end() || request.command.empty()) {
        return malformed("protocol.control_request");
    }
    return request;
}

Result<std::vector<std::byte>> encode_control_response(const ControlResponse& response) {
    ByteWriter writer;
    writer.u32(kProtocolFormatVersion);
    writer.boolean(response.ok);
    writer.u16(static_cast<std::uint16_t>(response.code));
    writer.str(response.message);
    writer.u32(static_cast<std::uint32_t>(response.lines.size()));
    for (const std::string& line : response.lines) {
        writer.str(line);
    }
    if (!writer.ok()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "protocol.control_response",
                          "response did not encode");
    }
    return to_bytes(writer);
}

Result<ControlResponse> decode_control_response(std::span<const std::byte> payload) {
    ByteReader reader(payload);
    ControlResponse response;
    const std::uint32_t version = reader.u32();
    if (!reader.ok() || version != kProtocolFormatVersion) {
        return make_error(ErrorCode::PROTOCOL_VERSION_UNSUPPORTED, "protocol.control_response",
                          "unsupported payload version");
    }
    const std::uint8_t ok = reader.u8();
    if (!reader.ok() || ok > 1U) {
        return malformed("protocol.control_response");
    }
    response.ok = ok == 1U;
    response.code = static_cast<ErrorCode>(detail::rd_enum(reader, kErrorCodeMax));
    response.message = reader.str();
    const std::uint32_t count = reader.count(1U << 20);
    for (std::uint32_t i = 0; i < count && reader.ok(); ++i) {
        response.lines.push_back(reader.str());
    }
    if (!reader.ok() || !reader.at_end()) {
        return malformed("protocol.control_response");
    }
    return response;
}

}  // namespace fcf
