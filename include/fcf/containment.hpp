// Fault Containment Fabric — committed containment state.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_CONTAINMENT_HPP
#define FCF_CONTAINMENT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/blast_radius.hpp"
#include "fcf/degraded.hpp"
#include "fcf/detail/enum_macro.hpp"
#include "fcf/ids.hpp"
#include "fcf/verification.hpp"

namespace fcf {

#define FCF_CONTAINMENT_STATUSES(X) \
    X(COMMITTED)                    \
    X(ENFORCING)                    \
    X(VERIFIED_CONTAINED)           \
    X(PARTIAL)                      \
    X(FAILED)                       \
    X(RELEASED)                     \
    X(SUPERSEDED)

FCF_DEFINE_ENUM(ContainmentStatus, FCF_CONTAINMENT_STATUSES, SUPERSEDED)

/// True while the containment still forbids new authorised work on its members.
[[nodiscard]] constexpr bool containment_is_live(ContainmentStatus status) noexcept {
    switch (status) {
        case ContainmentStatus::RELEASED:
        case ContainmentStatus::SUPERSEDED:
            return false;
        default:
            return true;
    }
}

/// The authoritative record of one containment decision.
struct ContainmentRecord {
    ContainmentGeneration generation{};
    CoordinatorEpoch epoch{};
    FaultId fault{};
    FaultGeneration fault_generation{};
    PolicyGeneration policy_generation{};
    TopologyGeneration topology_generation{};

    ContainmentActionKind outcome = ContainmentActionKind::NO_ACTION_REQUIRED;
    ContainmentStatus status = ContainmentStatus::COMMITTED;

    IdSet<ResourceId> mandatory;
    IdSet<ResourceId> precautionary;
    IdSet<ResourceId> unaffected;
    IdSet<ResourceId> unresolved;
    IdSet<ResourceId> released;

    std::vector<PropagationHop> propagation;
    std::vector<ActionId> actions;

    VerificationGeneration verification_generation{};
    VerificationOutcome verification_outcome = VerificationOutcome::OUTCOME_UNKNOWN;
    /// Full record of the most recent verification, preserved across restart.
    ContainmentVerification verification;

    DegradedModeId degraded_contract{};
    DegradedModeStatus degraded_status = DegradedModeStatus::NO_LEGAL_DEGRADED_MODE;

    std::uint64_t committed_at_ms = 0;
    std::uint64_t updated_at_ms = 0;
    bool verified = false;
    bool released_flag = false;
    ContainmentExplanation explanation;
};

#define FCF_RELEASE_DECISIONS(X) \
    X(RELEASE_GRANTED)           \
    X(RELEASE_DENIED_EVIDENCE)   \
    X(RELEASE_DENIED_AUTHORITY)  \
    X(RELEASE_DENIED_PROPAGATION)\
    X(RELEASE_DENIED_UNVERIFIED) \
    X(RELEASE_DENIED_POLICY)     \
    X(RELEASE_UNKNOWN)

FCF_DEFINE_ENUM(ReleaseDecision, FCF_RELEASE_DECISIONS, RELEASE_UNKNOWN)

/// The outcome of a release request, with the full criterion checklist.
struct ReleaseAssessment {
    ReleaseDecision decision = ReleaseDecision::RELEASE_UNKNOWN;
    ReleaseGeneration generation{};
    ContainmentGeneration containment_generation{};
    ResourceId resource{};
    std::vector<VerificationFinding> criteria;
    std::string summary;
    bool granted = false;
};

}  // namespace fcf

#endif  // FCF_CONTAINMENT_HPP
