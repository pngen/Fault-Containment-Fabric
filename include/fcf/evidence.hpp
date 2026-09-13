// Fault Containment Fabric — evidence trust and enforcement-mechanism classification.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_EVIDENCE_HPP
#define FCF_EVIDENCE_HPP

#include "fcf/detail/enum_macro.hpp"

namespace fcf {

// Where an observation came from.
#define FCF_PROVENANCES(X)     \
    X(WORKER_REPORT)           \
    X(COORDINATOR_OBSERVATION) \
    X(OPERATOR)                \
    X(TOPOLOGY_IMPORT)         \
    X(SYNTHETIC_INJECTION)     \
    X(DERIVED)                 \
    X(UNKNOWN)

FCF_DEFINE_ENUM(EvidenceProvenance, FCF_PROVENANCES, UNKNOWN)

#define FCF_FRESHNESS(X)         \
    X(FRESH)                     \
    X(AGING)                     \
    X(STALE)                     \
    X(REVALIDATION_REQUIRED)     \
    X(UNKNOWN)

FCF_DEFINE_ENUM(EvidenceFreshness, FCF_FRESHNESS, UNKNOWN)

/// Only FRESH evidence proves a resource is outside the blast radius. UNKNOWN
/// never counts as proof of safety.
[[nodiscard]] constexpr bool is_proof_of_freshness(EvidenceFreshness freshness) noexcept {
    return freshness == EvidenceFreshness::FRESH;
}

#define FCF_INTEGRITY_STATUSES(X) \
    X(VERIFIED)                   \
    X(UNVERIFIED)                 \
    X(SUSPECT)                    \
    X(CORRUPT)

FCF_DEFINE_ENUM(IntegrityStatus, FCF_INTEGRITY_STATUSES, CORRUPT)

/// How containment for a resource is actually enforced. Logical fencing must
/// never be described as hardware isolation.
#define FCF_CONTAINMENT_MECHANISMS(X) \
    X(NONE)                           \
    X(LOGICAL_CONTAINMENT)            \
    X(PROCESS_CONTAINMENT)            \
    X(RESOURCE_CONTAINMENT)           \
    X(HARDWARE_ENFORCED_CONTAINMENT)  \
    X(SYNTHETIC_CONTAINMENT)          \
    X(UNSUPPORTED_CONTAINMENT)

FCF_DEFINE_ENUM(ContainmentMechanism, FCF_CONTAINMENT_MECHANISMS, UNSUPPORTED_CONTAINMENT)

/// True only for mechanisms that act on real hardware or real OS process state.
[[nodiscard]] constexpr bool is_physically_enforcing(ContainmentMechanism mechanism) noexcept {
    switch (mechanism) {
        case ContainmentMechanism::PROCESS_CONTAINMENT:
        case ContainmentMechanism::HARDWARE_ENFORCED_CONTAINMENT:
            return true;
        default:
            return false;
    }
}

/// True when the mechanism fails closed for new authorised work.
[[nodiscard]] constexpr bool mechanism_fails_closed(ContainmentMechanism mechanism) noexcept {
    return mechanism != ContainmentMechanism::NONE;
}

}  // namespace fcf

#endif  // FCF_EVIDENCE_HPP
