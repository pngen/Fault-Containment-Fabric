// Fault Containment Fabric — worker-plane and controller-plane messages.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every payload is encoded with the shared checked codec and is treated as
// untrusted on decode: malformed identities, invalid enum values, oversized
// strings and trailing bytes are all rejected rather than repaired.

#ifndef FCF_PROTOCOL_HPP
#define FCF_PROTOCOL_HPP

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/engine.hpp"
#include "fcf/fault.hpp"
#include "fcf/ids.hpp"
#include "fcf/result.hpp"

namespace fcf {

inline constexpr std::uint32_t kProtocolFormatVersion = 1U;

struct HelloMessage {
    WorkerId worker{};
    WorkerBootId boot{};
    CoordinatorEpoch epoch{};
    EvidenceSequence sequence{};
    std::string endpoint;
};

struct HelloAckMessage {
    bool accepted = false;
    CoordinatorEpoch epoch{};
    WorkerIncarnation incarnation{};
    std::string detail;
};

struct WorkerEvidenceMessage {
    WorkerId worker{};
    WorkerBootId boot{};
    CoordinatorEpoch epoch{};
    ResourceId resource{};
    ResourceGeneration generation{};
    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
    EvidenceSequence sequence{};
    ContainmentMechanism mechanism = ContainmentMechanism::NONE;
};

struct WorkerEvidenceAck {
    bool granted = false;
    bool fenced = false;
    ResourceGeneration generation{};
    std::string detail;
};

struct FaultReportMessage {
    WorkerId worker{};
    WorkerBootId boot{};
    CoordinatorEpoch epoch{};
    FaultEvidence evidence;
};

struct ActionDispatchMessage {
    ContainmentAction action;
};

struct ActionAckMessage {
    ActionAcknowledgment ack;
};

struct ActionResultMessage {
    ActionResult result;
};

struct RejectMessage {
    ErrorCode code = ErrorCode::INTERNAL;
    std::string detail;
};

/// One controller request. The command vocabulary is closed and validated; this
/// is not a generic remote-execution surface.
struct ControlRequest {
    std::string command;
    std::vector<std::string> arguments;
};

struct ControlResponse {
    bool ok = false;
    ErrorCode code = ErrorCode::OK;
    std::string message;
    std::vector<std::string> lines;

    void add(std::string line) { lines.push_back(std::move(line)); }
};

[[nodiscard]] Result<std::vector<std::byte>> encode_hello(const HelloMessage& message);
[[nodiscard]] Result<HelloMessage> decode_hello(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_hello_ack(const HelloAckMessage& message);
[[nodiscard]] Result<HelloAckMessage> decode_hello_ack(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_worker_evidence(const WorkerEvidenceMessage& message);
[[nodiscard]] Result<WorkerEvidenceMessage> decode_worker_evidence(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_worker_evidence_ack(const WorkerEvidenceAck& message);
[[nodiscard]] Result<WorkerEvidenceAck> decode_worker_evidence_ack(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_fault_report(const FaultReportMessage& message);
[[nodiscard]] Result<FaultReportMessage> decode_fault_report(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_action_dispatch(const ActionDispatchMessage& message);
[[nodiscard]] Result<ActionDispatchMessage> decode_action_dispatch(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_action_ack(const ActionAckMessage& message);
[[nodiscard]] Result<ActionAckMessage> decode_action_ack(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_action_result(const ActionResultMessage& message);
[[nodiscard]] Result<ActionResultMessage> decode_action_result(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_reject(const RejectMessage& message);
[[nodiscard]] Result<RejectMessage> decode_reject(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_control_request(const ControlRequest& request);
[[nodiscard]] Result<ControlRequest> decode_control_request(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_control_response(const ControlResponse& response);
[[nodiscard]] Result<ControlResponse> decode_control_response(std::span<const std::byte> payload);

/// Parses an identity argument. Accepts "<decimal>" or "<Domain>:<decimal>", and
/// "-" or "0" for the invalid sentinel.
template <Identity IdT>
[[nodiscard]] bool parse_id_argument(const std::string& text, IdT& out) noexcept {
    if (text.empty() || text == "-" || text == "0") {
        out = IdT{};
        return true;
    }
    return parse_id<IdT>(text, out);
}

}  // namespace fcf

#endif  // FCF_PROTOCOL_HPP
