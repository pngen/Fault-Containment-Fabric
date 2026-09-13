// Fault Containment Fabric — append-only history.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_HISTORY_HPP
#define FCF_HISTORY_HPP

#include <cstdint>
#include <string>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/ids.hpp"

namespace fcf {

#define FCF_HISTORY_EVENT_TYPES(X)     \
    X(COORDINATOR_STARTED)             \
    X(EPOCH_ADVANCED)                  \
    X(TOPOLOGY_UPDATED)                \
    X(DOMAIN_REGISTERED)               \
    X(DOMAIN_UPDATED)                  \
    X(DOMAIN_REMOVED)                  \
    X(DEPENDENCY_REGISTERED)           \
    X(DEPENDENCY_REMOVED)              \
    X(RESOURCE_REGISTERED)             \
    X(RESOURCE_EVIDENCE_UPDATED)       \
    X(WORKER_REGISTERED)               \
    X(WORKER_RETIRED)                  \
    X(WORKER_AUTHORITY_REVOKED)        \
    X(FAULT_PUBLISHED)                 \
    X(FAULT_DUPLICATE_IGNORED)         \
    X(FAULT_CONFLICT_REJECTED)         \
    X(FAULT_SUPERSEDED)                \
    X(FAULT_STATE_CHANGED)             \
    X(CONTAINMENT_EVALUATED)           \
    X(CONTAINMENT_COMMITTED)           \
    X(ACTION_PLANNED)                  \
    X(ACTION_AUTHORIZED)               \
    X(ACTION_DISPATCHED)               \
    X(ACTION_ACKNOWLEDGED)             \
    X(ACTION_RESULT_RECORDED)          \
    X(ACTION_REJECTED)                 \
    X(ACTION_CANCELLED)                \
    X(CONTAINMENT_VERIFIED)            \
    X(DEGRADED_AUTHORIZED)             \
    X(DEGRADED_REVALIDATED)            \
    X(RELEASE_REQUESTED)               \
    X(RELEASE_GRANTED)                 \
    X(RELEASE_REFUSED)                 \
    X(STALE_MESSAGE_REJECTED)          \
    X(RECOVERY_APPLIED)                \
    X(PERSISTENCE_FAULT)

FCF_DEFINE_ENUM(HistoryEventType, FCF_HISTORY_EVENT_TYPES, PERSISTENCE_FAULT)

/// One immutable audit record. History is append-only; current-state changes never
/// overwrite an earlier decision.
struct HistoryEvent {
    HistorySequence sequence{};
    std::uint64_t timestamp_ms = 0;
    CoordinatorEpoch epoch{};
    HistoryEventType type = HistoryEventType::COORDINATOR_STARTED;

    ResourceId resource{};
    FaultId fault{};
    ActionId action{};
    ContainmentGeneration containment{};
    VerificationGeneration verification{};

    std::string detail;
    /// Rendered authority envelope that governed the transition.
    std::string authority;
};

}  // namespace fcf

#endif  // FCF_HISTORY_HPP
