// Fault Containment Fabric — internal blast-radius computation surface.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_SRC_BLAST_RADIUS_INTERNAL_HPP
#define FCF_SRC_BLAST_RADIUS_INTERNAL_HPP

#include "fcf/blast_radius.hpp"
#include "fcf/domain.hpp"
#include "fcf/fault.hpp"
#include "fcf/policy.hpp"
#include "fcf/result.hpp"
#include "fcf/worker.hpp"

namespace fcf {

/// Everything the computation is allowed to depend on. The input is treated as
/// immutable, so the same canonical input always yields the same result.
struct BlastRadiusInput {
    const Topology* topology = nullptr;
    const ContainmentPolicy* policy = nullptr;
    const FaultRecord* fault = nullptr;
    const WorkerRegistry* workers = nullptr;
    CoordinatorEpoch epoch{};
    ContainmentGeneration generation{};
};

/// Deterministic blast-radius computation. Hard constraints are applied before any
/// ranking; ranking never rescues a failed mandatory isolation predicate.
[[nodiscard]] Result<BlastRadius> compute_blast_radius(const BlastRadiusInput& input);

/// Classification of one propagation question between two resources.
[[nodiscard]] PropagationOutcome classify_propagation(const BlastRadiusInput& input, const FaultRule& rule,
                                                      const DependencyEdge& edge, bool destination_contained,
                                                      bool destination_already_mandatory) noexcept;

/// Human readable rendering of a blast radius, byte-identical for identical inputs.
[[nodiscard]] std::string render_blast_radius(const BlastRadius& radius);

}  // namespace fcf

#endif  // FCF_SRC_BLAST_RADIUS_INTERNAL_HPP
