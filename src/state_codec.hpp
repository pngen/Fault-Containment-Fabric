// Fault Containment Fabric — internal canonical record codec.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// One encode/decode path is shared by durable state and wire payloads so the two
// boundaries can never disagree about a record's shape. Every decoder validates
// enums, counts, identities and graph references before anything is used.

#ifndef FCF_SRC_STATE_CODEC_HPP
#define FCF_SRC_STATE_CODEC_HPP

#include <cstdint>
#include <map>
#include <vector>

#include "fcf/containment.hpp"
#include "fcf/degraded.hpp"
#include "fcf/dependency.hpp"
#include "fcf/detail/bytes.hpp"
#include "fcf/domain.hpp"
#include "fcf/engine.hpp"
#include "fcf/fault.hpp"
#include "fcf/history.hpp"
#include "fcf/plan.hpp"
#include "fcf/policy.hpp"
#include "fcf/verification.hpp"
#include "fcf/worker.hpp"

namespace fcf::detail {

// --- Record codecs ---------------------------------------------------------------------

void write_resource(ByteWriter& writer, const ResourceRecord& record);
[[nodiscard]] bool read_resource(ByteReader& reader, ResourceRecord& record);

void write_containment_domain(ByteWriter& writer, const ContainmentDomain& domain);
[[nodiscard]] bool read_containment_domain(ByteReader& reader, ContainmentDomain& domain);

void write_isolation_domain(ByteWriter& writer, const IsolationDomain& domain);
[[nodiscard]] bool read_isolation_domain(ByteReader& reader, IsolationDomain& domain);

void write_failure_domain(ByteWriter& writer, const FailureDomain& domain);
[[nodiscard]] bool read_failure_domain(ByteReader& reader, FailureDomain& domain);

void write_dependency(ByteWriter& writer, const DependencyEdge& edge);
[[nodiscard]] bool read_dependency(ByteReader& reader, DependencyEdge& edge);

void write_topology(ByteWriter& writer, const Topology& topology);
[[nodiscard]] bool read_topology(ByteReader& reader, Topology& topology);

void write_fault_evidence(ByteWriter& writer, const FaultEvidence& evidence);
[[nodiscard]] bool read_fault_evidence(ByteReader& reader, FaultEvidence& evidence);

void write_fault(ByteWriter& writer, const FaultRecord& fault);
[[nodiscard]] bool read_fault(ByteReader& reader, FaultRecord& fault);

void write_worker(ByteWriter& writer, const WorkerRecord& worker);
[[nodiscard]] bool read_worker(ByteReader& reader, WorkerRecord& worker);

void write_fault_rule(ByteWriter& writer, const FaultRule& rule);
[[nodiscard]] bool read_fault_rule(ByteReader& reader, FaultRule& rule);

void write_policy(ByteWriter& writer, const ContainmentPolicy& policy);
[[nodiscard]] bool read_policy(ByteReader& reader, ContainmentPolicy& policy);

void write_authority_envelope(ByteWriter& writer, const AuthorityEnvelope& envelope);
[[nodiscard]] bool read_authority_envelope(ByteReader& reader, AuthorityEnvelope& envelope);

void write_action(ByteWriter& writer, const ContainmentAction& action);
[[nodiscard]] bool read_action(ByteReader& reader, ContainmentAction& action);

void write_propagation_hop(ByteWriter& writer, const PropagationHop& hop);
[[nodiscard]] bool read_propagation_hop(ByteReader& reader, PropagationHop& hop);

void write_explanation(ByteWriter& writer, const ContainmentExplanation& explanation);
[[nodiscard]] bool read_explanation(ByteReader& reader, ContainmentExplanation& explanation);

void write_containment(ByteWriter& writer, const ContainmentRecord& record);
[[nodiscard]] bool read_containment(ByteReader& reader, ContainmentRecord& record);

void write_degraded(ByteWriter& writer, const DegradedModeAssessment& assessment);
[[nodiscard]] bool read_degraded(ByteReader& reader, DegradedModeAssessment& assessment);

void write_degraded_contract(ByteWriter& writer, const DegradedModeContract& contract);
[[nodiscard]] bool read_degraded_contract(ByteReader& reader, DegradedModeContract& contract);

void write_verification(ByteWriter& writer, const ContainmentVerification& verification);
[[nodiscard]] bool read_verification(ByteReader& reader, ContainmentVerification& verification);

void write_history_event(ByteWriter& writer, const HistoryEvent& event);
[[nodiscard]] bool read_history_event(ByteReader& reader, HistoryEvent& event);

// --- Whole-document codecs -------------------------------------------------------------

/// Payload written by persist_snapshot and consumed by recover_from_store.
void write_state_document(ByteWriter& writer, const RuntimeSnapshot& snapshot);
[[nodiscard]] bool read_state_document(ByteReader& reader, RuntimeSnapshot& snapshot);

/// Kind tags for durable journal events.
#define FCF_DURABLE_EVENT_KINDS(X) \
    X(RESOURCE_UPSERT)             \
    X(RESOURCE_REMOVE)             \
    X(CONTAINMENT_DOMAIN_UPSERT)   \
    X(CONTAINMENT_DOMAIN_REMOVE)   \
    X(ISOLATION_DOMAIN_UPSERT)     \
    X(ISOLATION_DOMAIN_REMOVE)     \
    X(FAILURE_DOMAIN_UPSERT)       \
    X(FAILURE_DOMAIN_REMOVE)       \
    X(DEPENDENCY_UPSERT)           \
    X(DEPENDENCY_REMOVE)           \
    X(POLICY_SET)                  \
    X(FAULT_UPSERT)                \
    X(CONTAINMENT_UPSERT)          \
    X(ACTION_UPSERT)               \
    X(WORKER_UPSERT)               \
    X(WORKER_CURRENT_BOOT)         \
    X(CURRENT_FAULT)               \
    X(DEGRADED_UPSERT)             \
    X(COUNTERS)                    \
    X(HISTORY)                     \
    X(RECOVERY_MARK)

FCF_DEFINE_ENUM(DurableEventKind, FCF_DURABLE_EVENT_KINDS, RECOVERY_MARK)

/// A journal event: a kind tag, an optional history record and the record payload.
struct DurableEvent {
    DurableEventKind kind = DurableEventKind::RECOVERY_MARK;
    bool has_history = false;
    HistoryEvent history;
    std::vector<std::byte> payload;
};

void write_durable_event(ByteWriter& writer, const DurableEvent& event);
[[nodiscard]] bool read_durable_event(ByteReader& reader, DurableEvent& event);

/// Reads a whole journal event from raw bytes, rejecting trailing data.
[[nodiscard]] bool decode_durable_event(std::span<const std::byte> bytes, DurableEvent& event);

}  // namespace fcf::detail

#endif  // FCF_SRC_STATE_CODEC_HPP
