// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "blast_radius_internal.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace fcf {
namespace {

[[nodiscard]] bool resource_is_contained(const ResourceRecord& record) noexcept {
    return is_contained(record.state) || record.quarantined;
}

[[nodiscard]] bool resource_is_operable(const ResourceRecord& record) noexcept {
    return is_operable(record.state) && !record.quarantined;
}

[[nodiscard]] std::string resource_label(const Topology& topology, ResourceId id) {
    const auto it = topology.resources.find(id);
    if (it == topology.resources.end()) {
        return to_string(id);
    }
    std::string out = to_string(id);
    if (!it->second.name.empty()) {
        out += " (";
        out += it->second.name;
        out += ")";
    }
    return out;
}

struct Accumulator {
    std::map<ResourceId, ClassifiedResource> classifications;

    void include(ResourceId id, ResourceGeneration generation, InclusionReason reason,
                 const std::string& detail) {
        ClassifiedResource& entry = classifications[id];
        entry.resource = id;
        entry.generation = generation;
        if (!entry.has_inclusion) {
            entry.has_inclusion = true;
            entry.inclusion = reason;
            entry.detail = detail;
        }
    }

    void exclude(ResourceId id, ResourceGeneration generation, ExclusionReason reason,
                 const std::string& detail) {
        ClassifiedResource& entry = classifications[id];
        entry.resource = id;
        entry.generation = generation;
        if (entry.has_inclusion) {
            return;  // inclusion always dominates exclusion
        }
        if (!entry.has_exclusion) {
            entry.has_exclusion = true;
            entry.exclusion = reason;
            entry.detail = detail;
        }
    }

    void mark_unresolved(ResourceId id, ResourceGeneration generation, UnresolvedReason reason,
                         const std::string& detail) {
        ClassifiedResource& entry = classifications[id];
        entry.resource = id;
        entry.generation = generation;
        if (entry.has_inclusion || entry.has_exclusion) {
            return;
        }
        if (!entry.has_unresolved) {
            entry.has_unresolved = true;
            entry.unresolved = reason;
            entry.detail = detail;
        }
    }
};

void add_action(std::vector<ContainmentActionKind>& list, ContainmentActionKind kind) {
    if (std::find(list.begin(), list.end(), kind) == list.end()) {
        list.push_back(kind);
    }
}

}  // namespace

PropagationOutcome classify_propagation(const BlastRadiusInput& input, const FaultRule& rule,
                                        const DependencyEdge& edge, bool destination_contained,
                                        bool destination_already_mandatory) noexcept {
    (void)input;
    if (edge.source == edge.destination) {
        return PropagationOutcome::PROPAGATION_IMPOSSIBLE;
    }
    if (!rule_propagates_over(rule, edge.kind)) {
        return PropagationOutcome::PROPAGATION_IMPOSSIBLE;
    }
    if (destination_contained) {
        return PropagationOutcome::PROPAGATION_BLOCKED;
    }
    const bool evidence_sufficient = edge.freshness == EvidenceFreshness::FRESH &&
                                     edge.integrity == IntegrityStatus::VERIFIED;
    if (!evidence_sufficient) {
        return PropagationOutcome::PROPAGATION_UNKNOWN;
    }
    if (rule.propagation == PropagationMode::NONE) {
        return PropagationOutcome::PROPAGATION_IMPOSSIBLE;
    }
    const bool conditional = edge.conditional || rule.propagation == PropagationMode::CONDITIONAL;
    const bool confident = edge.confidence_permille >= rule.likely_confidence_permille;
    if (conditional) {
        return confident ? PropagationOutcome::PROPAGATION_LIKELY
                         : PropagationOutcome::PROPAGATION_POSSIBLE;
    }
    if (destination_already_mandatory) {
        return PropagationOutcome::PROPAGATION_CONFIRMED;
    }
    return confident ? PropagationOutcome::PROPAGATION_LIKELY : PropagationOutcome::PROPAGATION_POSSIBLE;
}

Result<BlastRadius> compute_blast_radius(const BlastRadiusInput& input) {
    if (input.topology == nullptr || input.policy == nullptr || input.fault == nullptr) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "blast_radius.compute",
                          "topology, policy and fault are all required");
    }
    const Topology& topology = *input.topology;
    const ContainmentPolicy& policy = *input.policy;
    const FaultRecord& fault = *input.fault;

    const auto subject_it = topology.resources.find(fault.evidence.subject);
    if (subject_it == topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "blast_radius.compute",
                          "the fault subject is not present in the current topology",
                          to_string(fault.evidence.subject));
    }

    const FaultRule& rule = policy.rule_for(fault.evidence.kind);
    const ResourceRecord& subject = subject_it->second;

    BlastRadius radius;
    radius.generation = input.generation;
    radius.policy_generation = policy.generation;
    radius.topology_generation = topology.generation;
    radius.epoch = input.epoch;
    radius.fault = fault.evidence.id;
    radius.fault_generation = fault.evidence.generation;

    Accumulator acc;
    acc.include(subject.id, subject.generation, InclusionReason::FAULT_SUBJECT,
                "subject of " + std::string(to_string(fault.evidence.kind)));

    // --- Mandatory inclusions from structural co-membership -----------------------------
    //
    // A resource that cannot be proven to hold independent authority must not be
    // treated as unaffected merely because no failure has been observed on it.

    if (fault.evidence.kind == FaultKind::PROCESS_DEATH ||
        fault.evidence.kind == FaultKind::PROCESS_UNRESPONSIVE ||
        fault.evidence.kind == FaultKind::WORKER_AUTHORITY_LOST ||
        fault.evidence.kind == FaultKind::STALE_AUTHORITY) {
        if (subject.owner_boot.valid()) {
            for (const auto& entry : topology.resources) {
                const ResourceRecord& candidate = entry.second;
                if (candidate.owner_boot == subject.owner_boot) {
                    acc.include(candidate.id, candidate.generation, InclusionReason::SHARED_AUTHORITY,
                                "live authority bound to " + to_string(candidate.owner_boot));
                }
            }
        } else if (subject.owner_worker.valid()) {
            for (const auto& entry : topology.resources) {
                const ResourceRecord& candidate = entry.second;
                if (candidate.owner_worker == subject.owner_worker) {
                    acc.include(candidate.id, candidate.generation, InclusionReason::SHARED_AUTHORITY,
                                "authority derived from " + to_string(candidate.owner_worker));
                }
            }
        }
    }

    if (rule.isolate_isolation_domain && subject.isolation_domain.valid()) {
        const auto domain_it = topology.isolation_domains.find(subject.isolation_domain);
        if (domain_it != topology.isolation_domains.end()) {
            for (const ResourceId member : domain_it->second.members) {
                const auto member_it = topology.resources.find(member);
                if (member_it == topology.resources.end()) {
                    continue;
                }
                acc.include(member, member_it->second.generation, InclusionReason::SHARED_ISOLATION_DOMAIN,
                            "inseparable in isolation domain " + to_string(subject.isolation_domain));
            }
        }
    }

    if (rule.isolate_failure_domain && subject.failure_domain.valid()) {
        const auto domain_it = topology.failure_domains.find(subject.failure_domain);
        if (domain_it != topology.failure_domains.end()) {
            for (const ResourceId member : domain_it->second.members) {
                const auto member_it = topology.resources.find(member);
                if (member_it == topology.resources.end()) {
                    continue;
                }
                acc.include(member, member_it->second.generation, InclusionReason::SHARED_FAILURE_DOMAIN,
                            "correlated failure domain " + to_string(subject.failure_domain));
            }
        }
    }

    if (rule.co_isolate_containment_domain && subject.containment_domain.valid()) {
        const auto domain_it = topology.containment_domains.find(subject.containment_domain);
        if (domain_it != topology.containment_domains.end() && domain_it->second.co_isolate_members) {
            for (const ResourceId member : domain_it->second.members) {
                const auto member_it = topology.resources.find(member);
                if (member_it == topology.resources.end()) {
                    continue;
                }
                acc.include(member, member_it->second.generation, InclusionReason::DOMAIN_CO_ISOLATION,
                            "containment domain " + to_string(subject.containment_domain) +
                                " refuses separation");
            }
        }
    }

    // --- Deterministic propagation fixpoint ---------------------------------------------
    //
    // The frontier is processed in ascending resource identity order and each
    // resource's edges are visited in ascending dependency identity order, so the
    // traversal and every recorded hop are reproducible.

    std::set<ResourceId> mandatory_set;
    for (const auto& entry : acc.classifications) {
        if (entry.second.has_inclusion) {
            mandatory_set.insert(entry.first);
        }
    }

    std::set<ResourceId> visited;
    std::vector<ResourceId> frontier(mandatory_set.begin(), mandatory_set.end());
    std::vector<ResourceId> precautionary_set;

    while (!frontier.empty()) {
        const ResourceId current = frontier.front();
        frontier.erase(frontier.begin());
        if (!visited.insert(current).second) {
            continue;
        }
        const IdSet<DependencyId>* edges = topology.dependencies.outgoing_of(current);
        if (edges == nullptr) {
            continue;
        }
        for (const DependencyId edge_id : *edges) {
            const DependencyEdge* edge = topology.dependencies.find(edge_id);
            if (edge == nullptr) {
                continue;
            }
            const auto destination_it = topology.resources.find(edge->destination);
            if (destination_it == topology.resources.end()) {
                radius.edge_outcomes[edge_id] = PropagationOutcome::PROPAGATION_UNKNOWN;
                acc.mark_unresolved(current, topology.resources.at(current).generation,
                                    UnresolvedReason::TOPOLOGY_UNKNOWN,
                                    "dependency " + to_string(edge_id) + " targets an unknown resource");
                continue;
            }
            const ResourceRecord& destination = destination_it->second;
            const bool destination_contained = resource_is_contained(destination);
            const bool destination_mandatory = mandatory_set.count(destination.id) != 0U;
            const PropagationOutcome outcome =
                classify_propagation(input, rule, *edge, destination_contained, destination_mandatory);
            radius.edge_outcomes[edge_id] = outcome;

            PropagationHop hop;
            hop.from = current;
            hop.to = destination.id;
            hop.dependency = edge_id;
            hop.kind = edge->kind;
            hop.outcome = outcome;

            switch (outcome) {
                case PropagationOutcome::PROPAGATION_CONFIRMED:
                case PropagationOutcome::PROPAGATION_LIKELY:
                case PropagationOutcome::PROPAGATION_POSSIBLE: {
                    const bool conditional = edge->conditional || rule.propagation == PropagationMode::CONDITIONAL;
                    if (conditional) {
                        if (std::find(precautionary_set.begin(), precautionary_set.end(), destination.id) ==
                            precautionary_set.end()) {
                            precautionary_set.push_back(destination.id);
                        }
                        hop.reason = InclusionReason::PROPAGATION_CONDITIONAL_EDGE;
                        radius.propagation.push_back(hop);
                    } else {
                        hop.reason = InclusionReason::PROPAGATION_HARD_EDGE;
                        radius.propagation.push_back(hop);
                        if (mandatory_set.insert(destination.id).second) {
                            frontier.push_back(destination.id);
                            std::sort(frontier.begin(), frontier.end());
                        }
                        acc.include(destination.id, destination.generation,
                                    InclusionReason::PROPAGATION_HARD_EDGE,
                                    "propagation from " + to_string(current) + " over " +
                                        std::string(to_string(edge->kind)));
                    }
                    break;
                }
                case PropagationOutcome::PROPAGATION_UNKNOWN: {
                    hop.reason = InclusionReason::PROPAGATION_HARD_EDGE;
                    radius.propagation.push_back(hop);
                    acc.mark_unresolved(destination.id, destination.generation,
                                        UnresolvedReason::DEPENDENCY_FRESHNESS_UNKNOWN,
                                        "dependency " + to_string(edge_id) + " freshness " +
                                            std::string(to_string(edge->freshness)));
                    break;
                }
                default:
                    break;
            }
        }
    }

    // --- Unresolved evidence inside the correlated groups --------------------------------

    auto note_unresolved_member = [&](const IdSet<ResourceId>& members, UnresolvedReason reason,
                                      const std::string& detail) {
        for (const ResourceId member : members) {
            const auto member_it = topology.resources.find(member);
            if (member_it == topology.resources.end()) {
                continue;
            }
            if (mandatory_set.count(member) != 0U) {
                continue;
            }
            if (member_it->second.freshness != EvidenceFreshness::FRESH) {
                acc.mark_unresolved(member, member_it->second.generation, reason, detail);
            }
        }
    };

    if (subject.isolation_domain.valid()) {
        const auto domain_it = topology.isolation_domains.find(subject.isolation_domain);
        if (domain_it != topology.isolation_domains.end()) {
            note_unresolved_member(domain_it->second.members, UnresolvedReason::EVIDENCE_STALE,
                                   "isolation domain member without fresh evidence");
        }
    } else {
        acc.mark_unresolved(subject.id, subject.generation, UnresolvedReason::TOPOLOGY_UNKNOWN,
                            "subject has no isolation domain");
    }
    if (subject.failure_domain.valid()) {
        const auto domain_it = topology.failure_domains.find(subject.failure_domain);
        if (domain_it != topology.failure_domains.end()) {
            note_unresolved_member(domain_it->second.members, UnresolvedReason::EVIDENCE_MISSING,
                                   "correlated failure domain member without fresh evidence");
        }
    }

    // --- Fail-closed escalation for unresolved evidence ----------------------------------

    std::vector<ResourceId> unresolved_ids;
    for (const auto& entry : acc.classifications) {
        if (entry.second.has_unresolved) {
            unresolved_ids.push_back(entry.first);
        }
    }

    if (!unresolved_ids.empty() && rule.fail_closed_on_unknown_evidence) {
        if (rule.uncertainty == UncertaintyBehavior::CONTAIN_PREEMPTIVELY) {
            radius.uncertainty_escalated = true;
            radius.fail_closed_applied = true;
            for (const ResourceId id : unresolved_ids) {
                const auto it = topology.resources.find(id);
                if (it == topology.resources.end()) {
                    continue;
                }
                acc.include(id, it->second.generation, InclusionReason::UNKNOWN_EVIDENCE_FAIL_CLOSED,
                            "unresolved evidence cannot be proven safe");
                acc.classifications[id].has_unresolved = false;
                mandatory_set.insert(id);
            }
        } else if (rule.uncertainty == UncertaintyBehavior::BOUNDED_EXPOSURE) {
            radius.uncertainty_escalated = true;
            for (const ResourceId id : unresolved_ids) {
                const auto it = topology.resources.find(id);
                if (it == topology.resources.end()) {
                    continue;
                }
                if (std::find(precautionary_set.begin(), precautionary_set.end(), id) ==
                    precautionary_set.end()) {
                    precautionary_set.push_back(id);
                }
                acc.classifications[id].has_unresolved = false;
                acc.classifications[id].detail = "bounded exposure under unresolved evidence";
            }
        }
    }

    // --- Exposure and budget hard constraints --------------------------------------------

    std::size_t active_inside_correlated_group = 0;
    if (subject.isolation_domain.valid()) {
        const auto domain_it = topology.isolation_domains.find(subject.isolation_domain);
        if (domain_it != topology.isolation_domains.end()) {
            for (const ResourceId member : domain_it->second.members) {
                if (mandatory_set.count(member) == 0U) {
                    ++active_inside_correlated_group;
                }
            }
        }
    }
    if (active_inside_correlated_group > rule.max_tolerated_exposure) {
        radius.hard_constraints_satisfied = false;
        // Fail closed: widen the radius rather than tolerate excess exposure.
        if (subject.isolation_domain.valid()) {
            const auto domain_it = topology.isolation_domains.find(subject.isolation_domain);
            if (domain_it != topology.isolation_domains.end()) {
                for (const ResourceId member : domain_it->second.members) {
                    const auto member_it = topology.resources.find(member);
                    if (member_it == topology.resources.end()) {
                        continue;
                    }
                    if (mandatory_set.insert(member).second) {
                        acc.include(member, member_it->second.generation,
                                    InclusionReason::MANDATORY_CO_ISOLATION_RULE,
                                    "exposure inside the correlated group exceeds the tolerated maximum");
                    }
                }
            }
        }
        radius.hard_constraints_satisfied = true;  // the widened set now satisfies the constraint
        radius.fail_closed_applied = true;
    }

    if (mandatory_set.size() > rule.action_budget) {
        radius.budget_exhausted = true;
        radius.hard_constraints_satisfied = false;
    }

    // --- Unaffected set with an explicit proof --------------------------------------------

    for (const auto& entry : topology.resources) {
        const ResourceRecord& candidate = entry.second;
        if (mandatory_set.count(candidate.id) != 0U) {
            continue;
        }
        if (std::find(precautionary_set.begin(), precautionary_set.end(), candidate.id) !=
            precautionary_set.end()) {
            continue;
        }
        if (acc.classifications[candidate.id].has_unresolved) {
            continue;
        }
        if (candidate.freshness != EvidenceFreshness::FRESH) {
            acc.mark_unresolved(candidate.id, candidate.generation, UnresolvedReason::EVIDENCE_STALE,
                                "resource evidence is " + std::string(to_string(candidate.freshness)));
            continue;
        }
        // The primary proof is that no propagation path reaches this resource from
        // the contained set; the structural facts are recorded as supporting detail.
        std::string detail = "no propagation path from the contained set";
        if (candidate.isolation_domain.valid() &&
            candidate.isolation_domain != subject.isolation_domain) {
            detail += "; separate isolation domain " + to_string(candidate.isolation_domain);
        }
        if (candidate.failure_domain.valid() && candidate.failure_domain != subject.failure_domain) {
            detail += "; separate failure domain " + to_string(candidate.failure_domain);
        }
        if (candidate.owner_boot.valid() && candidate.owner_boot != subject.owner_boot) {
            detail += "; independent fresh authority " + to_string(candidate.owner_boot);
        }
        acc.exclude(candidate.id, candidate.generation,
                    ExclusionReason::NO_PROVEN_PROPAGATION_PATH, detail);
    }

    // --- Buckets -------------------------------------------------------------------------

    std::sort(precautionary_set.begin(), precautionary_set.end());
    precautionary_set.erase(std::unique(precautionary_set.begin(), precautionary_set.end()),
                            precautionary_set.end());

    for (const auto& entry : acc.classifications) {
        const ClassifiedResource& classified = entry.second;
        if (classified.has_inclusion) {
            radius.mandatory.push_back(entry.first);
        } else if (std::binary_search(precautionary_set.begin(), precautionary_set.end(),
                                      entry.first)) {
            // Recorded in the precautionary bucket below.
            continue;
        } else if (classified.has_unresolved) {
            radius.unresolved.push_back(entry.first);
        } else {
            radius.unaffected.push_back(entry.first);
        }
    }
    for (const ResourceId id : precautionary_set) {
        if (mandatory_set.count(id) != 0U) {
            continue;
        }
        radius.precautionary.push_back(id);
        ClassifiedResource& classified = acc.classifications[id];
        classified.has_unresolved = false;
        if (!classified.has_inclusion) {
            classified.has_exclusion = true;
            classified.exclusion = ExclusionReason::CONDITIONAL_ONLY_INCLUSION;
            classified.detail = "conditional propagation path only";
        }
    }
    radius.classifications = acc.classifications;

    // --- Legal and illegal action selection -----------------------------------------------

    const bool any_mandatory = !radius.mandatory.empty();
    const bool any_precautionary = !radius.precautionary.empty();
    const bool any_unresolved = !radius.unresolved.empty();

    bool protected_blocked = false;
    for (const ResourceId id : radius.mandatory) {
        const auto it = topology.resources.find(id);
        if (it == topology.resources.end()) {
            continue;
        }
        if (it->second.protection != ProtectionClass::STANDARD &&
            !rule.allow_protected_resource_fencing) {
            protected_blocked = true;
            acc.include(id, it->second.generation, InclusionReason::ACTION_REQUIRED_BY_POLICY,
                        "protected resource: containment requires escalation authority");
        }
    }

    if (!any_mandatory && !any_precautionary && !any_unresolved) {
        radius.recommended = ContainmentActionKind::NO_ACTION_REQUIRED;
        add_action(radius.legal_actions, ContainmentActionKind::NO_ACTION_REQUIRED);
        add_action(radius.legal_actions, ContainmentActionKind::OBSERVE);
    } else if (!any_mandatory && rule.uncertainty == UncertaintyBehavior::OBSERVE_ONLY) {
        radius.recommended = ContainmentActionKind::OBSERVE;
        add_action(radius.legal_actions, ContainmentActionKind::OBSERVE);
    } else {
        bool has_worker_bound = false;
        bool has_attempt = false;
        bool has_device = false;
        std::size_t distinct_domains = 0;
        ContainmentDomainId last_domain{};
        for (const ResourceId id : radius.mandatory) {
            const auto it = topology.resources.find(id);
            if (it == topology.resources.end()) {
                continue;
            }
            const ResourceRecord& record = it->second;
            if (record.owner_boot.valid() &&
                (record.resource_class == ResourceClass::WORKER ||
                 record.resource_class == ResourceClass::PROCESS ||
                 record.resource_class == ResourceClass::EXECUTION)) {
                has_worker_bound = true;
            }
            if (record.resource_class == ResourceClass::ATTEMPT) {
                has_attempt = true;
            }
            if (record.resource_class == ResourceClass::DEVICE ||
                record.resource_class == ResourceClass::ACCELERATOR) {
                has_device = true;
            }
            if (record.containment_domain.valid() && record.containment_domain != last_domain) {
                last_domain = record.containment_domain;
                ++distinct_domains;
            }
        }

        add_action(radius.legal_actions, ContainmentActionKind::QUARANTINE_RESOURCE);
        add_action(radius.legal_actions, ContainmentActionKind::FENCE_RESOURCE_SET);
        add_action(radius.legal_actions, ContainmentActionKind::REVOKE_AUTHORITY);
        add_action(radius.legal_actions, ContainmentActionKind::DISABLE_ADMISSION);
        add_action(radius.legal_actions, ContainmentActionKind::REQUIRE_REVALIDATION);
        if (has_worker_bound) {
            add_action(radius.legal_actions, ContainmentActionKind::FENCE_WORKER);
            add_action(radius.legal_actions, ContainmentActionKind::FENCE_PROCESS);
        }
        if (has_attempt) {
            add_action(radius.legal_actions, ContainmentActionKind::FENCE_ATTEMPT);
        }
        if (has_device) {
            add_action(radius.legal_actions, ContainmentActionKind::FENCE_DEVICE);
        }
        if (any_unresolved && rule.uncertainty != UncertaintyBehavior::OBSERVE_ONLY) {
            add_action(radius.legal_actions, ContainmentActionKind::ESCALATE_CONTAINMENT);
        }

        ContainmentActionKind preferred = rule.preferred_outcome;
        const bool preferred_is_legal =
            std::find(radius.legal_actions.begin(), radius.legal_actions.end(), preferred) !=
            radius.legal_actions.end();
        radius.recommended = preferred_is_legal ? preferred : ContainmentActionKind::QUARANTINE_RESOURCE;

        if (protected_blocked) {
            radius.hard_constraints_satisfied = false;
            radius.recommended = ContainmentActionKind::ESCALATE_CONTAINMENT;
            add_action(radius.legal_actions, ContainmentActionKind::ESCALATE_CONTAINMENT);
            add_action(radius.legal_actions, ContainmentActionKind::FULL_DOMAIN_ISOLATION);
            add_action(radius.illegal_actions, ContainmentActionKind::FENCE_PROCESS);
            add_action(radius.illegal_actions, ContainmentActionKind::FENCE_WORKER);
            add_action(radius.illegal_actions, ContainmentActionKind::FENCE_DEVICE);
        } else if (distinct_domains > 1U) {
            // A broader domain-wide fence would remove resources proven outside the radius.
            add_action(radius.illegal_actions, ContainmentActionKind::FULL_DOMAIN_ISOLATION);
        }
    }

    if (radius.budget_exhausted) {
        add_action(radius.illegal_actions, ContainmentActionKind::FULL_DOMAIN_ISOLATION);
    }

    // --- Deterministic explanation ---------------------------------------------------------

    radius.explanation.add("AUTHORITY", "epoch", "CoordinatorEpoch " + to_string(radius.epoch));
    radius.explanation.add("AUTHORITY", "fault_generation",
                           "FaultGeneration " + to_string(radius.fault_generation));
    radius.explanation.add("AUTHORITY", "policy_generation",
                           "PolicyGeneration " + to_string(radius.policy_generation));
    radius.explanation.add("AUTHORITY", "topology_generation",
                           "TopologyGeneration " + to_string(radius.topology_generation));
    radius.explanation.add("AUTHORITY", "containment_generation",
                           "ContainmentGeneration " + to_string(radius.generation));
    radius.explanation.add("FAULT", "kind", std::string(to_string(fault.evidence.kind)) + " on " +
                                          resource_label(topology, fault.evidence.subject));
    radius.explanation.add("FAULT", "state", "fault state " + std::string(to_string(fault.state)));
    radius.explanation.add("FAULT", "severity", "severity " + std::string(to_string(rule.severity)));
    radius.explanation.add("FAULT", "uncertainty",
                           "uncertainty behaviour " + std::string(to_string(rule.uncertainty)));

    for (const ResourceId id : radius.mandatory) {
        const ClassifiedResource& classified = acc.classifications[id];
        radius.explanation.add("MANDATORY", to_string(id),
                               resource_label(topology, id) + " -- " +
                                   std::string(to_string(classified.inclusion)) +
                                   (classified.detail.empty() ? "" : " -- " + classified.detail));
    }
    for (const ResourceId id : radius.precautionary) {
        radius.explanation.add("PRECAUTIONARY", to_string(id),
                               resource_label(topology, id) + " -- conditional propagation");
    }
    for (const ResourceId id : radius.unaffected) {
        const ClassifiedResource& classified = acc.classifications[id];
        radius.explanation.add("UNAFFECTED", to_string(id),
                               resource_label(topology, id) + " -- " +
                                   std::string(to_string(classified.exclusion)) +
                                   (classified.detail.empty() ? "" : " -- " + classified.detail));
    }
    for (const ResourceId id : radius.unresolved) {
        const ClassifiedResource& classified = acc.classifications[id];
        radius.explanation.add("UNKNOWN", to_string(id),
                               resource_label(topology, id) + " -- " +
                                   std::string(to_string(classified.unresolved)) +
                                   (classified.detail.empty() ? "" : " -- " + classified.detail));
    }
    for (const ContainmentActionKind kind : radius.illegal_actions) {
        radius.explanation.add("REJECTED", std::string(to_string(kind)),
                               std::string(to_string(kind)) +
                                   " -- broader than the computed radius or blocked by protected "
                                   "resource policy");
    }
    radius.explanation.add("VERIFICATION", "status",
                           "no post-action evidence yet; ACKNOWLEDGED is not CONTAINED");
    radius.explanation.finalize();

    return radius;
}

std::string render_blast_radius(const BlastRadius& radius) {
    std::string out;
    out += "containment generation ";
    out += to_string(radius.generation);
    out += "\n";
    out += "recommended outcome: ";
    out += to_string(radius.recommended);
    out += "\n";
    out += "mandatory " + std::to_string(radius.mandatory.size()) + ", precautionary " +
           std::to_string(radius.precautionary.size()) + ", unaffected " +
           std::to_string(radius.unaffected.size()) + ", unresolved " +
           std::to_string(radius.unresolved.size()) + "\n";
    out += radius.explanation.render();
    return out;
}

}  // namespace fcf
