// Fault Containment Fabric — containment plans.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_PLAN_HPP
#define FCF_PLAN_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/blast_radius.hpp"
#include "fcf/degraded.hpp"
#include "fcf/ids.hpp"

namespace fcf {

/// A complete, self-describing containment plan. Planning is not enforcement and
/// enforcement is not verification; the plan records which stage it reached.
struct ContainmentPlan {
    ContainmentGeneration generation{};
    CoordinatorEpoch epoch{};
    FaultId fault{};
    FaultGeneration fault_generation{};
    PolicyGeneration policy_generation{};
    TopologyGeneration topology_generation{};

    ContainmentActionKind recommended = ContainmentActionKind::NO_ACTION_REQUIRED;
    BlastRadius radius{};
    DegradedModeAssessment degraded{};

    std::vector<ContainmentAction> actions;
    std::vector<ActionId> rejected_actions;

    bool approved = false;
    bool dispatched = false;
    bool any_acknowledged = false;
    bool any_verified = false;

    std::uint64_t created_at_ms = 0;

    /// Stable one-line rendering of the envelope this plan is authoritative under.
    [[nodiscard]] std::string authority_summary() const;
};

}  // namespace fcf

#endif  // FCF_PLAN_HPP
