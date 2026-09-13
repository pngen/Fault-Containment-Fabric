// Fault Containment Fabric — containment actions, authority envelopes and executor intents.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_ACTIONS_HPP
#define FCF_ACTIONS_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/evidence.hpp"
#include "fcf/ids.hpp"
#include "fcf/result.hpp"

namespace fcf {

/// The complete set of containment outcomes the fabric may select. Selections are
/// typed intents: where the fabric does not own the mechanism it emits an intent
/// through the narrow Executor interface instead of performing it directly.
#define FCF_ACTION_KINDS(X)     \
    X(NO_ACTION_REQUIRED)       \
    X(OBSERVE)                  \
    X(FENCE_PROCESS)            \
    X(FENCE_WORKER)             \
    X(FENCE_ATTEMPT)            \
    X(FENCE_DEVICE)             \
    X(FENCE_RESOURCE_SET)       \
    X(QUARANTINE_RESOURCE)      \
    X(QUARANTINE_DOMAIN)        \
    X(DRAIN_DOMAIN)             \
    X(DISABLE_ADMISSION)        \
    X(REVOKE_AUTHORITY)         \
    X(REVOKE_RESERVATION)       \
    X(REVOKE_ROUTE)             \
    X(REVOKE_REGISTRATION)      \
    X(DEGRADE_SERVICE)          \
    X(REQUIRE_REVALIDATION)     \
    X(ESCALATE_CONTAINMENT)     \
    X(FULL_DOMAIN_ISOLATION)    \
    X(OUTCOME_UNKNOWN)

FCF_DEFINE_ENUM(ContainmentActionKind, FCF_ACTION_KINDS, OUTCOME_UNKNOWN)

/// True when the action changes the authority of a target rather than merely
/// recording that revalidation is needed.
[[nodiscard]] constexpr bool is_enforcing_action(ContainmentActionKind kind) noexcept {
    switch (kind) {
        case ContainmentActionKind::NO_ACTION_REQUIRED:
        case ContainmentActionKind::OBSERVE:
        case ContainmentActionKind::REQUIRE_REVALIDATION:
        case ContainmentActionKind::OUTCOME_UNKNOWN:
            return false;
        default:
            return true;
    }
}

/// True when re-dispatching the action after an ambiguous failure could cause
/// harm that cannot be undone by repeating it.
[[nodiscard]] constexpr bool is_destructive_action(ContainmentActionKind kind) noexcept {
    switch (kind) {
        case ContainmentActionKind::FENCE_PROCESS:
        case ContainmentActionKind::FENCE_WORKER:
        case ContainmentActionKind::FENCE_DEVICE:
        case ContainmentActionKind::QUARANTINE_RESOURCE:
        case ContainmentActionKind::QUARANTINE_DOMAIN:
        case ContainmentActionKind::FULL_DOMAIN_ISOLATION:
            return true;
        default:
            return false;
    }
}

#define FCF_ACTION_STATUSES(X) \
    X(CANDIDATE)               \
    X(REJECTED_INFEASIBLE)     \
    X(REJECTED_UNSAFE)         \
    X(PLANNED)                 \
    X(AUTHORIZED)              \
    X(DISPATCHED)              \
    X(ACKNOWLEDGED)            \
    X(RESULT_RECORDED)         \
    X(VERIFIED_EFFECTIVE)      \
    X(VERIFIED_INEFFECTIVE)    \
    X(AMBIGUOUS)               \
    X(SUPERSEDED)              \
    X(CANCELLED)

FCF_DEFINE_ENUM(ActionStatus, FCF_ACTION_STATUSES, CANCELLED)

/// The authority a containment decision was made under. Every field is revalidated
/// immediately before dispatch; a mismatch refuses the dispatch rather than
/// applying a stale plan.
struct AuthorityEnvelope {
    CoordinatorEpoch epoch{};
    FaultId fault{};
    FaultGeneration fault_generation{};
    ContainmentGeneration containment_generation{};
    PolicyGeneration policy_generation{};
    TopologyGeneration topology_generation{};
    ActionId action{};
    ActionGeneration action_generation{};
    WorkerId worker{};
    WorkerBootId worker_boot{};
    ResourceId target{};
    ResourceGeneration target_generation{};
    EvidenceSequence required_evidence_sequence{};
    ReservationId reservation{};
    LeaseId lease{};
    /// Resource generations the action depends on beyond the primary target.
    std::map<ResourceId, ResourceGeneration> required_resource_generations;
    std::uint64_t issued_at_ms = 0;
};

/// A single planned containment action with its lifecycle state.
struct ContainmentAction {
    ActionId id{};
    ActionGeneration generation{};
    ContainmentActionKind kind = ContainmentActionKind::OUTCOME_UNKNOWN;
    ResourceId target{};
    ResourceGeneration target_generation{};
    ContainmentDomainId domain{};
    IsolationDomainId isolation_domain{};
    ContainmentMechanism mechanism = ContainmentMechanism::NONE;

    AuthorityEnvelope envelope{};
    ActionStatus status = ActionStatus::CANDIDATE;
    ErrorCode rejection_code = ErrorCode::OK;
    std::string rejection_detail;

    std::uint64_t created_at_ms = 0;
    std::uint64_t dispatched_at_ms = 0;
    std::uint64_t acknowledged_at_ms = 0;
    std::uint64_t completed_at_ms = 0;

    VerificationGeneration verification_generation{};
    /// Opaque token echoed by the executor; never treated as proof of effect.
    std::string executor_token;
    bool destructive = false;
};

/// The executor's view of a dispatched action. Acceptance is not containment.
struct ActionAcknowledgment {
    ActionId action{};
    ActionGeneration action_generation{};
    CoordinatorEpoch epoch{};
    WorkerId worker{};
    WorkerBootId worker_boot{};
    bool accepted = false;
    std::string executor_token;
    std::string detail;
};

/// The executor's report of what it actually did. Still not proof of effect.
struct ActionResult {
    ActionId action{};
    ActionGeneration action_generation{};
    CoordinatorEpoch epoch{};
    WorkerId worker{};
    WorkerBootId worker_boot{};
    bool success = false;
    ContainmentMechanism mechanism = ContainmentMechanism::NONE;
    std::string detail;
};

/// Narrow executor interface. Fault Containment Fabric owns containment authority,
/// not the underlying mechanism; it emits intents here.
class Executor {
public:
    Executor() = default;
    Executor(const Executor&) = delete;
    Executor& operator=(const Executor&) = delete;
    virtual ~Executor() = default;

    /// Returns an opaque token on acceptance. Returning an error means the intent
    /// was not accepted; it never means containment happened.
    [[nodiscard]] virtual Result<std::string> dispatch(const ContainmentAction& action) = 0;
};

/// Stable one-line rendering of an action for history, CLI output and explanations.
[[nodiscard]] std::string describe_action(const ContainmentAction& action);

/// Stable one-line rendering of the authority an action was planned under.
[[nodiscard]] std::string describe_envelope(const AuthorityEnvelope& envelope);

}  // namespace fcf

#endif  // FCF_ACTIONS_HPP
