// Fault Containment Fabric — deterministic blast-radius results.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_BLAST_RADIUS_HPP
#define FCF_BLAST_RADIUS_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/dependency.hpp"
#include "fcf/explain.hpp"
#include "fcf/ids.hpp"

namespace fcf {

/// Why one resource sits in one bucket of the result.
struct ClassifiedResource {
    ResourceId resource{};
    ResourceGeneration generation{};
    InclusionReason inclusion = InclusionReason::FAULT_SUBJECT;
    ExclusionReason exclusion = ExclusionReason::NO_PROVEN_PROPAGATION_PATH;
    UnresolvedReason unresolved = UnresolvedReason::EVIDENCE_MISSING;
    bool has_inclusion = false;
    bool has_exclusion = false;
    bool has_unresolved = false;
    std::string detail;
};

/// The deterministic result of evaluating containment for one fault.
struct BlastRadius {
    ContainmentGeneration generation{};

    IdSet<ResourceId> mandatory;
    IdSet<ResourceId> precautionary;
    IdSet<ResourceId> unaffected;
    IdSet<ResourceId> unresolved;

    /// Per-resource classification detail, ordered by resource identity.
    std::map<ResourceId, ClassifiedResource> classifications;
    /// Propagation hops that caused inclusion, in deterministic traversal order.
    std::vector<PropagationHop> propagation;
    /// Every propagation question examined, including those answered IMPOSSIBLE.
    std::map<DependencyId, PropagationOutcome> edge_outcomes;

    std::vector<ContainmentActionKind> legal_actions;
    std::vector<ContainmentActionKind> illegal_actions;

    ContainmentActionKind recommended = ContainmentActionKind::NO_ACTION_REQUIRED;

    /// True when every hard constraint in the policy was satisfied by this result.
    bool hard_constraints_satisfied = true;
    bool uncertainty_escalated = false;
    bool fail_closed_applied = false;
    bool budget_exhausted = false;

    PolicyGeneration policy_generation{};
    TopologyGeneration topology_generation{};
    CoordinatorEpoch epoch{};
    FaultId fault{};
    FaultGeneration fault_generation{};

    ContainmentExplanation explanation;
};

}  // namespace fcf

#endif  // FCF_BLAST_RADIUS_HPP
