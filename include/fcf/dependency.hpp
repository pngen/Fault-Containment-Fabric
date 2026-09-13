// Fault Containment Fabric — typed directional dependencies and the propagation graph.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DEPENDENCY_HPP
#define FCF_DEPENDENCY_HPP

#include <cstdint>
#include <map>
#include <string>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/evidence.hpp"
#include "fcf/ids.hpp"

namespace fcf {

#define FCF_DEPENDENCY_KINDS(X)   \
    X(EXECUTION_DEPENDS_ON)       \
    X(STATE_OWNED_BY)             \
    X(MEMORY_OWNED_BY)            \
    X(ROUTE_DEPENDS_ON)           \
    X(SERVICE_DEPENDS_ON)         \
    X(REPLICA_MEMBER_OF)          \
    X(SHARES_FAILURE_DOMAIN_WITH) \
    X(SHARES_AUTHORITY_WITH)      \
    X(CONTROLLED_BY)              \
    X(REQUIRES_CAPABILITY_FROM)   \
    X(RESERVATION_BOUND_TO)       \
    X(LEASE_BOUND_TO)             \
    X(REGISTRATION_BOUND_TO)

FCF_DEFINE_ENUM(DependencyKind, FCF_DEPENDENCY_KINDS, REGISTRATION_BOUND_TO)

/// Direction of traversal for a dependency of a given kind when computing propagation.
#define FCF_PROPAGATION_DIRECTIONS(X) \
    X(FORWARD)                        \
    X(BIDIRECTIONAL)                  \
    X(NONE)

FCF_DEFINE_ENUM(PropagationDirection, FCF_PROPAGATION_DIRECTIONS, NONE)

/// A single directed dependency edge. Every field required by the containment
/// model is present: provenance, generation, freshness, confidence and evidence source.
struct DependencyEdge {
    DependencyId id{};
    DependencyGeneration generation{};
    ResourceId source{};
    ResourceId destination{};
    DependencyKind kind = DependencyKind::SERVICE_DEPENDS_ON;

    EvidenceProvenance provenance = EvidenceProvenance::UNKNOWN;
    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
    IntegrityStatus integrity = IntegrityStatus::UNVERIFIED;

    /// Supplemental only. Confidence never grants permission and never overrides
    /// a mandatory containment predicate.
    std::uint16_t confidence_permille = 1000U;
    /// True when propagation through this edge depends on additional conditions.
    bool conditional = false;
    EvidenceSequence observed_sequence{};
    std::string evidence_source;
};

/// Outcome classification for a single propagation question. Typed rather than a
/// bare score; confidence may supplement but never replace these.
#define FCF_PROPAGATION_OUTCOMES(X) \
    X(PROPAGATION_IMPOSSIBLE)       \
    X(PROPAGATION_BLOCKED)          \
    X(PROPAGATION_POSSIBLE)         \
    X(PROPAGATION_LIKELY)           \
    X(PROPAGATION_CONFIRMED)        \
    X(PROPAGATION_UNKNOWN)

FCF_DEFINE_ENUM(PropagationOutcome, FCF_PROPAGATION_OUTCOMES, PROPAGATION_UNKNOWN)

/// True when the outcome permits new work to be treated as unaffected.
[[nodiscard]] constexpr bool permits_continued_operation(PropagationOutcome outcome) noexcept {
    return outcome == PropagationOutcome::PROPAGATION_IMPOSSIBLE ||
           outcome == PropagationOutcome::PROPAGATION_BLOCKED;
}

/// Why a resource ended up inside the computed mandatory set.
#define FCF_INCLUSION_REASONS(X)               \
    X(FAULT_SUBJECT)                           \
    X(FAULT_SUBJECT_WORKER_INCARNATION)        \
    X(SHARED_AUTHORITY)                        \
    X(STATE_OWNERSHIP_BOUND)                   \
    X(MEMORY_OWNERSHIP_BOUND)                  \
    X(SHARED_ISOLATION_DOMAIN)                 \
    X(SHARED_FAILURE_DOMAIN)                   \
    X(MANDATORY_CO_ISOLATION_RULE)             \
    X(DOMAIN_CO_ISOLATION)                     \
    X(PROPAGATION_HARD_EDGE)                   \
    X(PROPAGATION_CONDITIONAL_EDGE)            \
    X(ESCALATED_UNCERTAINTY)                   \
    X(UNKNOWN_EVIDENCE_FAIL_CLOSED)            \
    X(ADMINISTRATIVE_OVERRIDE)                 \
    X(ACTION_REQUIRED_BY_POLICY)

FCF_DEFINE_ENUM(InclusionReason, FCF_INCLUSION_REASONS, ACTION_REQUIRED_BY_POLICY)

/// Why a resource was proven to remain outside the blast radius.
#define FCF_EXCLUSION_REASONS(X)             \
    X(NO_PROVEN_PROPAGATION_PATH)            \
    X(FRESH_INDEPENDENT_AUTHORITY)           \
    X(SEPARATE_ISOLATION_DOMAIN)             \
    X(SEPARATE_FAILURE_DOMAIN)               \
    X(DEPENDENCY_KIND_DOES_NOT_PROPAGATE)    \
    X(PROPAGATION_PATH_ALREADY_SEVERED)      \
    X(CONDITIONAL_ONLY_INCLUSION)            \
    X(DEGRADED_MODE_PERMITTED_INDEPENDENCE)

FCF_DEFINE_ENUM(ExclusionReason, FCF_EXCLUSION_REASONS, DEGRADED_MODE_PERMITTED_INDEPENDENCE)

/// Why a resource could not be classified either way.
#define FCF_UNRESOLVED_REASONS(X) \
    X(EVIDENCE_STALE)             \
    X(EVIDENCE_INVALID)           \
    X(EVIDENCE_MISSING)           \
    X(TOPOLOGY_UNKNOWN)           \
    X(DEPENDENCY_FRESHNESS_UNKNOWN) \
    X(AUTHORITY_STATE_UNKNOWN)

FCF_DEFINE_ENUM(UnresolvedReason, FCF_UNRESOLVED_REASONS, AUTHORITY_STATE_UNKNOWN)

/// A single edge traversal responsible for including a resource in the radius.
struct PropagationHop {
    ResourceId from{};
    ResourceId to{};
    DependencyId dependency{};
    DependencyKind kind = DependencyKind::SERVICE_DEPENDS_ON;
    PropagationOutcome outcome = PropagationOutcome::PROPAGATION_UNKNOWN;
    InclusionReason reason = InclusionReason::PROPAGATION_HARD_EDGE;
};

/// The propagation graph: ordered edge map plus deterministic adjacency indexes.
struct DependencyGraph {
    std::map<DependencyId, DependencyEdge> edges;
    std::map<ResourceId, IdSet<DependencyId>> outgoing;
    std::map<ResourceId, IdSet<DependencyId>> incoming;

    [[nodiscard]] const DependencyEdge* find(DependencyId id) const {
        const auto it = edges.find(id);
        return it == edges.end() ? nullptr : &it->second;
    }

    [[nodiscard]] const IdSet<DependencyId>* outgoing_of(ResourceId id) const {
        const auto it = outgoing.find(id);
        return it == outgoing.end() ? nullptr : &it->second;
    }

    [[nodiscard]] const IdSet<DependencyId>* incoming_of(ResourceId id) const {
        const auto it = incoming.find(id);
        return it == incoming.end() ? nullptr : &it->second;
    }

    void insert(const DependencyEdge& edge);
    bool erase(DependencyId id);
    void rebuild_indexes();
    [[nodiscard]] bool references(ResourceId resource) const;
};

}  // namespace fcf

#endif  // FCF_DEPENDENCY_HPP
