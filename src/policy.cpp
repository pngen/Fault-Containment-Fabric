// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/policy.hpp"

#include <algorithm>

namespace fcf {
namespace {

struct RuleAdjustment {
    FaultKind kind;
    ContainmentActionKind preferred;
    FaultSeverity severity;
    PropagationMode propagation;
    UncertaintyBehavior uncertainty;
    bool isolate_failure_domain;
    bool isolate_isolation_domain;
    bool co_isolate_containment_domain;
    bool permit_degraded_mode;
};

constexpr RuleAdjustment kAdjustments[] = {
    {FaultKind::PROCESS_DEATH, ContainmentActionKind::FENCE_WORKER, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, true},
    {FaultKind::PROCESS_UNRESPONSIVE, ContainmentActionKind::FENCE_PROCESS, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, true},
    {FaultKind::WORKER_AUTHORITY_LOST, ContainmentActionKind::REVOKE_AUTHORITY, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, true},
    {FaultKind::DEVICE_FAILURE, ContainmentActionKind::FENCE_DEVICE, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, false},
    {FaultKind::DEVICE_UNAVAILABLE, ContainmentActionKind::QUARANTINE_RESOURCE, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, true},
    {FaultKind::DEVICE_RESET, ContainmentActionKind::REQUIRE_REVALIDATION, FaultSeverity::MEDIUM,
     PropagationMode::CONDITIONAL, UncertaintyBehavior::BOUNDED_EXPOSURE, false, false, false, true},
    {FaultKind::MEMORY_INTEGRITY_FAILURE, ContainmentActionKind::QUARANTINE_RESOURCE, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, true, false},
    {FaultKind::PERSISTENCE_CORRUPTION, ContainmentActionKind::QUARANTINE_DOMAIN, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, true, false},
    {FaultKind::TRANSPORT_PARTITION, ContainmentActionKind::QUARANTINE_DOMAIN, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, true},
    {FaultKind::TRANSPORT_CORRUPTION, ContainmentActionKind::REVOKE_ROUTE, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, false, true, false, true},
    {FaultKind::CONTROL_PLANE_LOSS, ContainmentActionKind::DISABLE_ADMISSION, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, true, true},
    {FaultKind::COORDINATOR_RESTART, ContainmentActionKind::REQUIRE_REVALIDATION, FaultSeverity::HIGH,
     PropagationMode::CONDITIONAL, UncertaintyBehavior::BOUNDED_EXPOSURE, false, false, false, true},
    {FaultKind::STALE_AUTHORITY, ContainmentActionKind::REVOKE_AUTHORITY, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, false, true, false, true},
    {FaultKind::RESOURCE_EXHAUSTION, ContainmentActionKind::DISABLE_ADMISSION, FaultSeverity::HIGH,
     PropagationMode::CONDITIONAL, UncertaintyBehavior::BOUNDED_EXPOSURE, false, false, false, true},
    {FaultKind::THERMAL_VIOLATION, ContainmentActionKind::DRAIN_DOMAIN, FaultSeverity::HIGH,
     PropagationMode::CONDITIONAL, UncertaintyBehavior::BOUNDED_EXPOSURE, true, false, false, true},
    {FaultKind::POWER_VIOLATION, ContainmentActionKind::DRAIN_DOMAIN, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, false, false, false},
    {FaultKind::TOPOLOGY_INCONSISTENCY, ContainmentActionKind::REQUIRE_REVALIDATION, FaultSeverity::MEDIUM,
     PropagationMode::CONDITIONAL, UncertaintyBehavior::BOUNDED_EXPOSURE, false, false, false, true},
    {FaultKind::DEPENDENCY_FAILURE, ContainmentActionKind::QUARANTINE_RESOURCE, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, false, true, false, true},
    {FaultKind::HEALTH_DEGRADED, ContainmentActionKind::OBSERVE, FaultSeverity::LOW,
     PropagationMode::NONE, UncertaintyBehavior::OBSERVE_ONLY, false, false, false, true},
    {FaultKind::SECURITY_ISOLATION_REQUEST, ContainmentActionKind::FULL_DOMAIN_ISOLATION,
     FaultSeverity::CRITICAL, PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true,
     true, false},
    {FaultKind::ADMINISTRATIVE_QUARANTINE, ContainmentActionKind::QUARANTINE_DOMAIN, FaultSeverity::HIGH,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, true, true},
    {FaultKind::UNKNOWN_FAULT, ContainmentActionKind::ESCALATE_CONTAINMENT, FaultSeverity::CRITICAL,
     PropagationMode::HARD, UncertaintyBehavior::CONTAIN_PREEMPTIVELY, true, true, false, false},
};

}  // namespace

bool rule_propagates_over(const FaultRule& rule, DependencyKind kind) noexcept {
    if (enum_set_contains(rule.non_propagating_kinds, kind)) {
        return false;
    }
    if (enum_set_contains(rule.propagating_kinds, kind)) {
        return rule.propagation != PropagationMode::NONE;
    }
    // Unlisted kinds follow the rule's default propagation mode.
    return rule.propagation == PropagationMode::HARD;
}

ContainmentPolicy make_default_policy() {
    ContainmentPolicy policy;
    policy.generation = PolicyGeneration::from_value(1);
    policy.name = "fcf-default/v1";

    FaultRule base;
    base.mandatory_containment = true;
    base.uncertainty = UncertaintyBehavior::CONTAIN_PREEMPTIVELY;
    base.propagation = PropagationMode::HARD;
    base.severity = FaultSeverity::HIGH;
    base.preferred_outcome = ContainmentActionKind::QUARANTINE_RESOURCE;
    base.escalation_outcome = ContainmentActionKind::FULL_DOMAIN_ISOLATION;
    base.likely_confidence_permille = 700U;
    base.max_tolerated_exposure = 0U;
    base.permit_degraded_mode = true;
    base.require_fresh_evidence = true;
    base.max_evidence_age_ms = 30000U;
    base.allow_release = true;
    base.min_redundancy = 1U;
    base.action_budget = 4096U;
    base.isolate_failure_domain = true;
    base.isolate_isolation_domain = true;
    base.co_isolate_containment_domain = false;
    base.ranking = RankingPreference::SMALLEST_LEGAL_RADIUS;
    base.fail_closed_on_unknown_evidence = true;
    base.allow_protected_resource_fencing = false;
    base.propagating_kinds = {
        DependencyKind::EXECUTION_DEPENDS_ON,  DependencyKind::STATE_OWNED_BY,
        DependencyKind::MEMORY_OWNED_BY,       DependencyKind::ROUTE_DEPENDS_ON,
        DependencyKind::SERVICE_DEPENDS_ON,    DependencyKind::REPLICA_MEMBER_OF,
        DependencyKind::SHARES_AUTHORITY_WITH, DependencyKind::CONTROLLED_BY,
        DependencyKind::REQUIRES_CAPABILITY_FROM, DependencyKind::RESERVATION_BOUND_TO,
        DependencyKind::LEASE_BOUND_TO,        DependencyKind::REGISTRATION_BOUND_TO};
    // SHARES_FAILURE_DOMAIN_WITH is answered by failure-domain membership, not by
    // edge traversal, so it never carries propagation on its own.
    base.non_propagating_kinds = {DependencyKind::SHARES_FAILURE_DOMAIN_WITH};

    for (const RuleAdjustment& adjustment : kAdjustments) {
        FaultRule rule = base;
        rule.kind = adjustment.kind;
        rule.preferred_outcome = adjustment.preferred;
        rule.severity = adjustment.severity;
        rule.propagation = adjustment.propagation;
        rule.uncertainty = adjustment.uncertainty;
        rule.isolate_failure_domain = adjustment.isolate_failure_domain;
        rule.isolate_isolation_domain = adjustment.isolate_isolation_domain;
        rule.co_isolate_containment_domain = adjustment.co_isolate_containment_domain;
        rule.permit_degraded_mode = adjustment.permit_degraded_mode;
        if (adjustment.uncertainty == UncertaintyBehavior::OBSERVE_ONLY) {
            rule.mandatory_containment = false;
            rule.preferred_outcome = ContainmentActionKind::OBSERVE;
        }
        if (adjustment.kind == FaultKind::UNKNOWN_FAULT) {
            rule.allow_protected_resource_fencing = true;
        }
        policy.rules.emplace(adjustment.kind, rule);
    }

    policy.fallback = base;
    policy.fallback.kind = FaultKind::UNKNOWN_FAULT;
    policy.fallback.preferred_outcome = ContainmentActionKind::ESCALATE_CONTAINMENT;
    policy.fallback.severity = FaultSeverity::CRITICAL;
    policy.fallback.allow_protected_resource_fencing = true;
    policy.max_actions_per_containment = 4096U;
    policy.allow_degraded_mode_by_default = true;
    policy.default_max_evidence_age_ms = 30000U;
    return policy;
}

Status validate_policy(const ContainmentPolicy& policy) {
    for (const auto& entry : policy.rules) {
        const FaultRule& rule = entry.second;
        if (entry.first != rule.kind) {
            return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                        "rule map key does not match the rule's fault kind");
        }
        if (rule.action_budget == 0U) {
            return fail(ErrorCode::POLICY_INVALID, "policy.validate", "action budget must be non-zero",
                        std::string(to_string(rule.kind)));
        }
        if (rule.min_redundancy == 0U) {
            return fail(ErrorCode::POLICY_INVALID, "policy.validate", "minimum redundancy must be non-zero",
                        std::string(to_string(rule.kind)));
        }
        if (rule.mandatory_containment && rule.uncertainty == UncertaintyBehavior::OBSERVE_ONLY) {
            return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                        "a mandatory rule may not run in OBSERVE_ONLY uncertainty mode",
                        std::string(to_string(rule.kind)));
        }
        auto is_canonical = [](const EnumSet<DependencyKind>& set) {
            for (std::size_t index = 1; index < set.size(); ++index) {
                if (static_cast<std::uint16_t>(set[index - 1]) >= static_cast<std::uint16_t>(set[index])) {
                    return false;
                }
            }
            return true;
        };
        if (!is_canonical(rule.propagating_kinds) || !is_canonical(rule.non_propagating_kinds)) {
            return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                        "dependency kind lists must be sorted and duplicate-free",
                        std::string(to_string(rule.kind)));
        }
        for (const DependencyKind kind : rule.propagating_kinds) {
            if (enum_set_contains(rule.non_propagating_kinds, kind)) {
                return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                            "dependency kind listed as both propagating and non-propagating",
                            std::string(to_string(kind)));
            }
        }
        if (rule.propagation == PropagationMode::NONE && rule.mandatory_containment &&
            rule.uncertainty == UncertaintyBehavior::CONTAIN_PREEMPTIVELY &&
            rule.max_tolerated_exposure == 0U && rule.isolate_failure_domain &&
            rule.isolate_isolation_domain) {
            // Legal but worth flagging is not an error; the combination is coherent.
        }
    }
    if (policy.max_actions_per_containment == 0U) {
        return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                    "max_actions_per_containment must be non-zero");
    }
    if (policy.admin_override.active && policy.admin_override.authority.empty()) {
        return fail(ErrorCode::POLICY_INVALID, "policy.validate",
                    "an active administrative override requires a named authority");
    }
    return ok_status();
}

}  // namespace fcf
