// Fault Containment Fabric — explicit containment policy.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_POLICY_HPP
#define FCF_POLICY_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/dependency.hpp"
#include "fcf/fault.hpp"
#include "fcf/ids.hpp"

namespace fcf {

/// Behaviour when the evidence is not conclusive. All three behaviours are legal;
/// collapsing every uncertainty to SAFE or FAILED is not.
#define FCF_UNCERTAINTY_BEHAVIORS(X) \
    X(CONTAIN_PREEMPTIVELY)          \
    X(BOUNDED_EXPOSURE)              \
    X(OBSERVE_ONLY)

FCF_DEFINE_ENUM(UncertaintyBehavior, FCF_UNCERTAINTY_BEHAVIORS, OBSERVE_ONLY)

#define FCF_PROPAGATION_MODES(X) \
    X(HARD)                      \
    X(CONDITIONAL)               \
    X(NONE)

FCF_DEFINE_ENUM(PropagationMode, FCF_PROPAGATION_MODES, NONE)

/// How candidates are ordered once every hard constraint has already been applied.
/// Ranking never rescues a failed mandatory isolation predicate.
#define FCF_RANKING_PREFERENCES(X) \
    X(SMALLEST_LEGAL_RADIUS)       \
    X(PREFER_PROCESS_SCOPE)        \
    X(PREFER_DOMAIN_SCOPE)

FCF_DEFINE_ENUM(RankingPreference, FCF_RANKING_PREFERENCES, PREFER_DOMAIN_SCOPE)

/// Administrative override. An override can redirect ranking, escalate scope and
/// authorise release, but it can never remove a mandatory hard inclusion.
struct AdministrativeOverride {
    bool active = false;
    std::string authority;
    PolicyGeneration policy_generation{};
    std::uint64_t not_before_ms = 0;
    std::uint64_t expires_at_ms = 0;
    ContainmentActionKind forced_outcome = ContainmentActionKind::OUTCOME_UNKNOWN;
    IdSet<ResourceId> scope;
    /// Always true in this implementation: overrides are ranking/authority level only.
    bool ranking_and_authority_only = true;
};

/// The complete containment rule for one fault kind.
struct FaultRule {
    FaultKind kind = FaultKind::UNKNOWN_FAULT;
    ContainmentActionKind preferred_outcome = ContainmentActionKind::ESCALATE_CONTAINMENT;
    ContainmentActionKind escalation_outcome = ContainmentActionKind::FULL_DOMAIN_ISOLATION;
    FaultSeverity severity = FaultSeverity::HIGH;

    /// When true the rule's mandatory predicates may not be relaxed by ranking,
    /// cost, preference, utilisation or availability.
    bool mandatory_containment = true;

    UncertaintyBehavior uncertainty = UncertaintyBehavior::CONTAIN_PREEMPTIVELY;
    PropagationMode propagation = PropagationMode::HARD;

    /// Confidence at or above which a POSSIBLE propagation is reported LIKELY.
    std::uint16_t likely_confidence_permille = 700U;
    /// Maximum number of resources that may remain active inside the correlated group.
    std::uint32_t max_tolerated_exposure = 0;

    bool permit_degraded_mode = true;
    bool require_fresh_evidence = true;
    std::uint64_t max_evidence_age_ms = 30000U;

    bool allow_release = true;
    std::uint32_t min_redundancy = 1;

    std::uint32_t action_budget = 1024U;

    bool isolate_failure_domain = true;
    bool isolate_isolation_domain = true;
    bool co_isolate_containment_domain = false;

    RankingPreference ranking = RankingPreference::SMALLEST_LEGAL_RADIUS;

    EnumSet<DependencyKind> propagating_kinds;
    EnumSet<DependencyKind> non_propagating_kinds;

    /// When true, unresolved evidence forces the unresolved set into the
    /// precautionary (BOUNDED_EXPOSURE) or mandatory (CONTAIN_PREEMPTIVELY) set.
    bool fail_closed_on_unknown_evidence = true;

    /// When true, PROTECTED/CRITICAL resources may be fenced under this rule.
    bool allow_protected_resource_fencing = false;
};

/// The full policy document. Rules execute before ranking.
struct ContainmentPolicy {
    PolicyGeneration generation{};
    std::string name = "default";
    std::map<FaultKind, FaultRule> rules;
    /// Applied to faults with no explicit rule. Deliberately conservative.
    FaultRule fallback{};
    std::uint32_t max_actions_per_containment = 4096U;
    bool allow_degraded_mode_by_default = true;
    std::uint64_t default_max_evidence_age_ms = 30000U;
    AdministrativeOverride admin_override{};

    [[nodiscard]] const FaultRule& rule_for(FaultKind kind) const {
        const auto it = rules.find(kind);
        return it == rules.end() ? fallback : it->second;
    }
};

/// Validates internal consistency: no dependency kind may be listed as both
/// propagating and non-propagating, budgets must be non-zero, and a mandatory
/// rule may not be configured with OBSERVE_ONLY uncertainty.
[[nodiscard]] Status validate_policy(const ContainmentPolicy& policy);

/// A conservative default policy covering every fault kind in the taxonomy.
[[nodiscard]] ContainmentPolicy make_default_policy();

/// True when the fault rule makes the dependency kind carry propagation.
[[nodiscard]] bool rule_propagates_over(const FaultRule& rule, DependencyKind kind) noexcept;

}  // namespace fcf

#endif  // FCF_POLICY_HPP
