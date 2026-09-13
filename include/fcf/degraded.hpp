// Fault Containment Fabric — degraded-mode contracts and assessments.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DEGRADED_HPP
#define FCF_DEGRADED_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/domain.hpp"
#include "fcf/ids.hpp"

namespace fcf {

#define FCF_DEGRADED_STATUSES(X)      \
    X(NORMAL)                         \
    X(DEGRADED_AUTHORIZED)            \
    X(DEGRADED_REVALIDATION_REQUIRED) \
    X(DEGRADED_UNSAFE)                \
    X(NO_LEGAL_DEGRADED_MODE)

FCF_DEFINE_ENUM(DegradedModeStatus, FCF_DEGRADED_STATUSES, NO_LEGAL_DEGRADED_MODE)

/// True only for the status that asserts unimpaired operation.
[[nodiscard]] constexpr bool claims_full_health(DegradedModeStatus status) noexcept {
    return status == DegradedModeStatus::NORMAL;
}

/// A degraded-mode contract: the explicit legal envelope for continuing work
/// while part of the infrastructure is contained.
struct DegradedModeContract {
    DegradedModeId id{};
    std::string name;

    TopologyGeneration topology_generation{};
    ContainmentGeneration containment_generation{};

    IdSet<ResourceId> permitted_resources;
    IdSet<ResourceId> prohibited_resources;

    std::uint32_t reduced_capacity_percent = 100U;
    std::uint32_t required_redundancy = 1U;

    std::vector<std::string> disabled_features;
    EnumSet<ResourceClass> legal_workload_classes;
    std::vector<std::string> hard_safety_constraints;

    std::uint64_t max_evidence_age_ms = 30000U;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t revalidate_every_ms = 0;
    std::vector<std::string> exit_preconditions;

    bool permit_by_default = true;
};

/// The runtime's assessment of what degraded operation is currently legal.
struct DegradedModeAssessment {
    DegradedModeId contract{};
    DegradedModeStatus status = DegradedModeStatus::NO_LEGAL_DEGRADED_MODE;

    IdSet<ResourceId> permitted;
    IdSet<ResourceId> prohibited;
    IdSet<ResourceId> revalidation_required;

    std::uint32_t available_capacity_percent = 0U;
    std::uint32_t required_redundancy = 1U;
    std::uint32_t available_redundancy = 0U;

    std::vector<std::string> reasons;
    TopologyGeneration topology_generation{};
    CoordinatorEpoch epoch{};
    std::uint64_t assessed_at_ms = 0;
    bool authorized = false;
};

/// True when the assessment separates permitted and prohibited sets cleanly.
/// A degraded mode that consumes a prohibited resource is never legal.
[[nodiscard]] bool degraded_sets_are_disjoint(const DegradedModeAssessment& assessment) noexcept;

}  // namespace fcf

#endif  // FCF_DEGRADED_HPP
