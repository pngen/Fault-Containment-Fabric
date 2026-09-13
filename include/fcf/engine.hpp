// Fault Containment Fabric — the containment runtime.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_ENGINE_HPP
#define FCF_ENGINE_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include "fcf/actions.hpp"
#include "fcf/blast_radius.hpp"
#include "fcf/containment.hpp"
#include "fcf/degraded.hpp"
#include "fcf/dependency.hpp"
#include "fcf/domain.hpp"
#include "fcf/fault.hpp"
#include "fcf/history.hpp"
#include "fcf/persistence.hpp"
#include "fcf/plan.hpp"
#include "fcf/policy.hpp"
#include "fcf/result.hpp"
#include "fcf/verification.hpp"
#include "fcf/worker.hpp"

namespace fcf {

/// An immutable, self-consistent read view. Returned by value/shared_ptr so that
/// callers never observe mutable internals or a torn intermediate state.
struct RuntimeSnapshot {
    CoordinatorEpoch epoch{};
    TopologyGeneration topology_generation{};
    PolicyGeneration policy_generation{};
    ContainmentGeneration containment_generation{};
    VerificationGeneration verification_generation{};
    ReleaseGeneration release_generation{};
    HistorySequence history_sequence{};
    std::uint64_t now_ms = 0;

    Topology topology;
    ContainmentPolicy policy;
    std::map<FaultId, FaultRecord> faults;
    WorkerRegistry workers;
    std::map<ContainmentGeneration, ContainmentRecord> containments;
    std::map<ActionId, ContainmentAction> actions;
    std::map<DegradedModeId, DegradedModeAssessment> degraded_modes;
    std::map<DegradedModeId, DegradedModeContract> degraded_contracts;
    std::vector<HistoryEvent> history;
    std::uint64_t history_total = 0;
};

struct ResourceStatusView {
    ResourceRecord resource;
    bool contained = false;
    bool quarantined = false;
    bool operable = false;
    bool release_permitted = false;
    ContainmentGeneration containment_generation{};
    std::vector<std::string> reasons;
};

struct DomainStatusView {
    ContainmentDomain domain;
    std::size_t active_members = 0;
    std::size_t contained_members = 0;
    std::size_t unresolved_members = 0;
    std::vector<std::string> reasons;
};

struct SystemStatus {
    CoordinatorEpoch epoch{};
    TopologyGeneration topology_generation{};
    PolicyGeneration policy_generation{};
    ContainmentGeneration containment_generation{};
    VerificationGeneration verification_generation{};
    HistorySequence history_sequence{};

    std::size_t resource_count = 0;
    std::size_t dependency_count = 0;
    std::size_t fault_count = 0;
    std::size_t current_fault_count = 0;
    std::size_t live_containment_count = 0;
    std::size_t quarantined_resource_count = 0;
    std::size_t worker_incarnation_count = 0;
    std::size_t live_worker_count = 0;
    std::size_t live_authority_count = 0;
    std::size_t unresolved_resource_count = 0;

    DegradedModeStatus degraded_status = DegradedModeStatus::NORMAL;
    bool durability_healthy = true;
    bool recovery_incomplete = false;
    std::vector<std::string> notes;
};

struct DispatchSummary {
    ContainmentGeneration containment_generation{};
    std::vector<ActionId> dispatched;
    std::vector<ActionId> refused;
    std::vector<std::string> refusals;
    std::size_t budget_remaining = 0;
};

struct ReleaseRequest {
    ResourceId resource{};
    ResourceGeneration expected_generation{};
    ContainmentGeneration containment_generation{};
    CoordinatorEpoch epoch{};
    WorkerId requester_worker{};
    WorkerBootId requester_boot{};
    EvidenceSequence evidence_sequence{};
    std::string authority;
};

/// The Fault Containment Fabric runtime.
///
/// Concurrency model: every public method is safe to call concurrently. Reads take
/// a shared lock; mutations take an exclusive lock. Internal locks are never held
/// across executor calls, persistence I/O, network waits or user callbacks.
class Engine {
public:
    using Clock = std::function<std::uint64_t()>;

    struct Config {
        CoordinatorEpoch initial_epoch{CoordinatorEpoch::from_value(1)};
        Clock clock;
        std::size_t max_history_in_memory = 100000U;
        std::size_t max_resources = 200000U;
        std::size_t max_dependencies = 1000000U;
        std::size_t max_faults = 1000000U;
        std::size_t max_actions = 1000000U;
        std::size_t max_containments = 200000U;
        std::size_t max_workers = 100000U;
        std::uint32_t max_traversal_nodes = 1000000U;
        std::uint32_t max_resources_per_request = 100000U;
        std::uint32_t max_dependencies_per_request = 500000U;
    };

    explicit Engine(Config config = {});
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    ~Engine();

    // --- Coordinator epoch and recovery -----------------------------------------

    [[nodiscard]] CoordinatorEpoch epoch() const;
    /// Advances the coordinator epoch and marks every dynamic evidence item as
    /// requiring revalidation. Live authority never survives this call.
    Result<CoordinatorEpoch> begin_epoch(std::uint64_t now_ms, std::string reason);
    [[nodiscard]] bool recovery_incomplete() const;

    // --- Topology ----------------------------------------------------------------

    Result<ContainmentDomain> register_domain(ContainmentDomain domain);
    Status update_domain(ContainmentDomain domain, TopologyGeneration expected);
    Status remove_domain(ContainmentDomainId id, TopologyGeneration expected);

    Result<IsolationDomain> register_isolation_domain(IsolationDomain domain);
    Result<FailureDomain> register_failure_domain(FailureDomain domain);
    Status remove_failure_domain(FailureDomainId id, TopologyGeneration expected);
    Status remove_isolation_domain(IsolationDomainId id, TopologyGeneration expected);

    Result<ResourceRecord> register_resource(ResourceRecord record);
    Result<ResourceRecord> update_resource(ResourceRecord record, ResourceGeneration expected);
    Status remove_resource(ResourceId id, ResourceGeneration expected);

    Result<DependencyEdge> register_dependency(DependencyEdge edge);
    Status remove_dependency(DependencyId id, DependencyGeneration expected);

    Status set_policy(ContainmentPolicy policy);
    [[nodiscard]] ContainmentPolicy policy() const;

    // --- Evidence ----------------------------------------------------------------

    Result<ResourceRecord> publish_resource_evidence(ResourceId id, ResourceGeneration expected,
                                                     EvidenceFreshness freshness,
                                                     EvidenceSequence sequence,
                                                     ContainmentMechanism mechanism,
                                                     std::string source);

    // --- Workers -----------------------------------------------------------------

    Result<WorkerRecord> register_worker(WorkerId worker, WorkerBootId boot, std::string endpoint,
                                         EvidenceSequence sequence);
    Status retire_worker(WorkerId worker, WorkerBootId boot, std::string reason);
    /// Records the coordinator's observation that an incarnation is gone: revokes its
    /// live authority, marks its dynamic evidence for revalidation, raises the fault
    /// and commits containment for the resulting blast radius.
    Result<ContainmentRecord> worker_authority_lost(WorkerId worker, WorkerBootId boot,
                                                    FaultKind kind, std::string detail,
                                                    std::uint64_t observation_time_ms);
    [[nodiscard]] Result<WorkerRecord> query_worker(WorkerId worker, WorkerBootId boot) const;

    // --- Faults ------------------------------------------------------------------

    /// Publishes one observation. Identical duplicates are idempotent; a duplicate
    /// identity with different content is rejected as DUPLICATE_CONFLICT.
    Result<FaultRecord> publish_fault(FaultEvidence evidence, bool* was_duplicate = nullptr);
    Result<FaultRecord> supersede_fault(FaultId id, FaultGeneration expected, std::string reason);
    [[nodiscard]] Result<FaultRecord> query_fault(FaultId id) const;

    // --- Blast radius and containment --------------------------------------------

    [[nodiscard]] Result<BlastRadius> evaluate_containment(FaultId id, FaultGeneration expected) const;
    [[nodiscard]] Result<BlastRadius> query_blast_radius(FaultId id) const;
    [[nodiscard]] Result<ContainmentExplanation> explain(ContainmentGeneration generation) const;
    [[nodiscard]] Result<ContainmentExplanation> explain_fault(FaultId id) const;

    Result<ContainmentRecord> authorize_containment(FaultId id, FaultGeneration expected);
    Result<ContainmentRecord> query_containment(ContainmentGeneration generation) const;
    [[nodiscard]] std::vector<ContainmentRecord> list_containments() const;

    Result<DispatchSummary> dispatch_containment(ContainmentGeneration generation, Executor* executor);
    Status record_action_ack(const ActionAcknowledgment& ack);
    Status record_action_result(const ActionResult& result);
    [[nodiscard]] Result<ContainmentAction> query_action(ActionId id) const;

    Result<ContainmentVerification> verify_containment(ContainmentGeneration generation);
    Result<ContainmentVerification> query_verification(ContainmentGeneration generation) const;

    // --- Degraded mode -----------------------------------------------------------

    Result<DegradedModeAssessment> authorize_degraded_mode(DegradedModeContract contract);
    Result<DegradedModeAssessment> revalidate_degraded_mode(DegradedModeId id);
    [[nodiscard]] Result<DegradedModeAssessment> query_degraded_mode(DegradedModeId id) const;

    // --- Release -----------------------------------------------------------------

    Result<ReleaseAssessment> request_release(const ReleaseRequest& request);
    Result<ReleaseAssessment> authorize_release(const ReleaseRequest& request);
    [[nodiscard]] Result<ReleaseAssessment> query_release(ResourceId resource) const;

    // --- Queries -----------------------------------------------------------------

    [[nodiscard]] Result<ResourceStatusView> query_resource_status(ResourceId id) const;
    [[nodiscard]] Result<DomainStatusView> query_domain_status(ContainmentDomainId id) const;
    [[nodiscard]] SystemStatus query_system_status() const;
    [[nodiscard]] std::shared_ptr<const RuntimeSnapshot> snapshot() const;
    [[nodiscard]] std::vector<HistoryEvent> history(std::uint64_t from_sequence, std::size_t limit) const;

    // --- Durability --------------------------------------------------------------

    /// Attaches a durable store. Durable mutations are appended and flushed before
    /// they are reported as committed.
    Status attach_store(DurableStore* store);
    Result<CoordinatorEpoch> recover_from_store(DurableStore& store, std::uint64_t now_ms);
    Status persist_snapshot();
    [[nodiscard]] bool durability_healthy() const;

    // --- Lifecycle ---------------------------------------------------------------

    void shutdown();
    [[nodiscard]] bool shutting_down() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Human readable rendering of a blast radius, byte-identical for identical
/// canonical inputs.
[[nodiscard]] std::string render_blast_radius(const BlastRadius& radius);

}  // namespace fcf

#endif  // FCF_ENGINE_HPP
