// Fault Containment Fabric — post-action containment verification.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_VERIFICATION_HPP
#define FCF_VERIFICATION_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/ids.hpp"

namespace fcf {

/// ACKNOWLEDGED is not CONTAINED. A dispatched action without fresh post-action
/// evidence remains unverified, and the honest outcome is OUTCOME_UNKNOWN.
#define FCF_VERIFICATION_OUTCOMES(X) \
    X(CONTAINED)                     \
    X(PARTIALLY_CONTAINED)           \
    X(NOT_CONTAINED)                 \
    X(CONTAINMENT_BREACHED)          \
    X(PROPAGATION_BLOCKED)           \
    X(PROPAGATION_CONTINUED)         \
    X(SECONDARY_FAILURE_CREATED)     \
    X(DEGRADED_MODE_VALID)           \
    X(DEGRADED_MODE_INVALID)         \
    X(OUTCOME_UNKNOWN)

FCF_DEFINE_ENUM(VerificationOutcome, FCF_VERIFICATION_OUTCOMES, OUTCOME_UNKNOWN)

/// One named check and its result. Names are stable so tests can assert on them.
struct VerificationFinding {
    std::string check;
    bool passed = false;
    std::string detail;
};

/// The result of verifying one committed containment.
struct ContainmentVerification {
    VerificationGeneration generation{};
    ContainmentGeneration containment_generation{};
    CoordinatorEpoch epoch{};
    PolicyGeneration policy_generation{};
    TopologyGeneration topology_generation{};

    VerificationOutcome outcome = VerificationOutcome::OUTCOME_UNKNOWN;
    std::vector<VerificationFinding> findings;

    IdSet<ResourceId> proven_contained;
    IdSet<ResourceId> unproven;

    bool blast_radius_increased = false;
    bool secondary_failure = false;
    bool propagation_blocked = false;
    bool propagation_continued = false;
    bool degraded_mode_valid = false;

    EvidenceSequence evidence_sequence{};
    std::uint64_t verified_at_ms = 0;
    std::string summary;
};

}  // namespace fcf

#endif  // FCF_VERIFICATION_HPP
