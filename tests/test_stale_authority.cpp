// Fault Containment Fabric — stale authority rejection proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/engine.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

class NullExecutor : public Executor {
public:
    Result<std::string> dispatch(const ContainmentAction& action) override {
        return std::string("null:") + to_string(action.id);
    }
};

struct Fixture {
    LogicalClock clock;
    Engine engine;
    Fixture() : engine(make_config(clock)) {
        (void)engine.register_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "A",
                                     EvidenceSequence::from_value(1));
        (void)engine.register_isolation_domain(make_isolation_domain(101, "iso-A", {1, 2}));
        add_resource(engine, ResourceSpec{1, "worker-A", ResourceClass::WORKER, ProtectionClass::STANDARD,
                                          0, 101, 0, 1, 11});
        add_resource(engine, ResourceSpec{2, "exec-A", ResourceClass::EXECUTION,
                                          ProtectionClass::STANDARD, 0, 101, 0, 1, 11});
    }

    ContainmentGeneration contain() {
        FaultEvidence evidence;
        evidence.kind = FaultKind::PROCESS_DEATH;
        evidence.subject = ResourceId::from_value(1);
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        const Result<FaultRecord> fault = engine.publish_fault(evidence);
        FCF_REQUIRE(fault.ok());
        const Result<ContainmentRecord> containment =
            engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
        FCF_REQUIRE_MSG(containment.ok(), containment.ok() ? "" : containment.error().to_string());
        return containment.value().generation;
    }
};

}  // namespace

FCF_TEST(stale_authority, acknowledgment_from_a_revoked_incarnation_is_refused) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    NullExecutor executor;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    FCF_REQUIRE(!summary.value().dispatched.empty());
    const ActionId action_id = summary.value().dispatched.front();
    const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
    FCF_REQUIRE(action.ok());

    // The incarnation is revoked by a fresh boot.
    FCF_REQUIRE(fixture.engine
                    .register_worker(WorkerId::from_value(1), WorkerBootId::from_value(12), "A",
                                     EvidenceSequence::from_value(2))
                    .ok());

    ActionAcknowledgment ack;
    ack.action = action_id;
    ack.action_generation = action.value().generation;
    ack.epoch = fixture.engine.epoch();
    ack.worker = WorkerId::from_value(1);
    ack.worker_boot = WorkerBootId::from_value(11);
    ack.accepted = true;
    const Status recorded = fixture.engine.record_action_ack(ack);
    FCF_REQUIRE(!recorded.ok());
    FCF_EQ(recorded.error().code(), ErrorCode::STALE_WORKER_BOOT);

    ActionResult result;
    result.action = action_id;
    result.action_generation = action.value().generation;
    result.epoch = fixture.engine.epoch();
    result.worker = WorkerId::from_value(1);
    result.worker_boot = WorkerBootId::from_value(11);
    result.success = true;
    const Status result_status = fixture.engine.record_action_result(result);
    FCF_REQUIRE(!result_status.ok());
    FCF_EQ(result_status.error().code(), ErrorCode::STALE_WORKER_BOOT);
}

FCF_TEST(stale_authority, stale_epoch_and_action_generation_are_refused) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    NullExecutor executor;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    const ActionId action_id = summary.value().dispatched.front();
    const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
    FCF_REQUIRE(action.ok());

    ActionAcknowledgment stale_epoch;
    stale_epoch.action = action_id;
    stale_epoch.action_generation = action.value().generation;
    stale_epoch.epoch = CoordinatorEpoch::from_value(fixture.engine.epoch().value() + 100U);
    stale_epoch.accepted = true;
    const Status epoch_status = fixture.engine.record_action_ack(stale_epoch);
    FCF_REQUIRE(!epoch_status.ok());
    FCF_EQ(epoch_status.error().code(), ErrorCode::STALE_EPOCH);

    ActionAcknowledgment stale_generation;
    stale_generation.action = action_id;
    stale_generation.action_generation = ActionGeneration::from_value(action.value().generation.value() + 5U);
    stale_generation.epoch = fixture.engine.epoch();
    stale_generation.accepted = true;
    const Status generation_status = fixture.engine.record_action_ack(stale_generation);
    FCF_REQUIRE(!generation_status.ok());
    FCF_EQ(generation_status.error().code(), ErrorCode::STALE_ACTION_GENERATION);
}

FCF_TEST(stale_authority, acknowledgment_before_dispatch_is_refused) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    FCF_REQUIRE(!record.value().actions.empty());
    const Result<ContainmentAction> action = fixture.engine.query_action(record.value().actions.front());
    FCF_REQUIRE(action.ok());
    ActionAcknowledgment ack;
    ack.action = action.value().id;
    ack.action_generation = action.value().generation;
    ack.epoch = fixture.engine.epoch();
    ack.accepted = true;
    const Status status = fixture.engine.record_action_ack(ack);
    FCF_REQUIRE(!status.ok());
    FCF_EQ(status.error().code(), ErrorCode::ACTION_REVALIDATION_FAILED);
}

FCF_TEST(stale_authority, acknowledgment_and_result_are_idempotent_but_never_commit_twice) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    NullExecutor executor;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    const ActionId action_id = summary.value().dispatched.front();
    const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
    FCF_REQUIRE(action.ok());

    ActionAcknowledgment ack;
    ack.action = action_id;
    ack.action_generation = action.value().generation;
    ack.epoch = fixture.engine.epoch();
    ack.accepted = true;
    FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
    FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());

    ActionResult result;
    result.action = action_id;
    result.action_generation = action.value().generation;
    result.epoch = fixture.engine.epoch();
    result.success = true;
    FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
    FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
    const Result<ContainmentAction> after = fixture.engine.query_action(action_id);
    FCF_REQUIRE(after.ok());
    FCF_EQ(after.value().status, ActionStatus::RESULT_RECORDED);
}

FCF_TEST(stale_authority, stale_fault_generation_and_superseded_faults_are_refused) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    (void)generation;
    const std::shared_ptr<const RuntimeSnapshot> snapshot = fixture.engine.snapshot();
    FCF_EQ(snapshot->faults.size(), 1U);
    const FaultId fault = snapshot->faults.begin()->first;
    const FaultGeneration generation_value = snapshot->faults.begin()->second.evidence.generation;

    FCF_REQUIRE(fixture.engine
                    .supersede_fault(fault, FaultGeneration::from_value(generation_value.value() + 3U),
                                     "wrong generation")
                    .ok() == false);

    FCF_REQUIRE(fixture.engine.supersede_fault(fault, generation_value, "administratively closed").ok());
    const Result<FaultRecord> superseded = fixture.engine.query_fault(fault);
    FCF_REQUIRE(superseded.ok());
    FCF_EQ(superseded.value().state, FaultState::SUPERSEDED);
    FCF_REQUIRE(!superseded.value().actionable);
    // A superseded fault can never be re-opened.
    FCF_REQUIRE(!fixture.engine.supersede_fault(fault, superseded.value().evidence.generation, "again").ok());
}

FCF_TEST(stale_authority, dispatch_is_refused_once_the_topology_has_moved) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    // Any topology mutation advances the topology generation the plan was bound to.
    (void)fixture.engine.register_isolation_domain(make_isolation_domain(103, "iso-C", {}));
    NullExecutor executor;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    FCF_REQUIRE(summary.value().dispatched.empty());
    FCF_REQUIRE(!summary.value().refused.empty());
    for (const ActionId action_id : summary.value().refused) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        FCF_EQ(action.value().status, ActionStatus::SUPERSEDED);
        FCF_EQ(action.value().rejection_code, ErrorCode::STALE_TOPOLOGY_GENERATION);
    }
}

FCF_TEST(stale_authority, epoch_advance_invalidates_live_authority_and_in_flight_actions) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.contain();
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());

    const Result<CoordinatorEpoch> advanced = fixture.engine.begin_epoch(5000, "test restart");
    FCF_REQUIRE(advanced.ok());

    const Result<WorkerRecord> worker =
        fixture.engine.query_worker(WorkerId::from_value(1), WorkerBootId::from_value(11));
    FCF_REQUIRE(worker.ok());
    FCF_REQUIRE(!holds_live_authority(worker.value().state));

    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    for (const ActionId action_id : record.value().actions) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        FCF_REQUIRE_MSG(action.value().status == ActionStatus::AMBIGUOUS,
                        std::string("status ") + std::string(to_string(action.value().status)));
    }
    FCF_REQUIRE(fixture.engine.recovery_incomplete());
}

FCF_TEST(stale_authority, evidence_for_a_superseded_resource_generation_is_refused) {
    Fixture fixture;
    const std::shared_ptr<const RuntimeSnapshot> snapshot = fixture.engine.snapshot();
    const ResourceGeneration observed = snapshot->topology.resources.at(ResourceId::from_value(1)).generation;
    FCF_REQUIRE(fixture.engine
                    .publish_resource_evidence(ResourceId::from_value(1), observed,
                                               EvidenceFreshness::FRESH, EvidenceSequence::from_value(2),
                                               ContainmentMechanism::NONE, "test")
                    .ok());
    const Result<ResourceRecord> stale = fixture.engine.publish_resource_evidence(
        ResourceId::from_value(1), observed, EvidenceFreshness::FRESH, EvidenceSequence::from_value(3),
        ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(!stale.ok());
    FCF_EQ(stale.error().code(), ErrorCode::STALE_RESOURCE_GENERATION);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
