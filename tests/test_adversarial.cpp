// Fault Containment Fabric — adversarial hardening proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>
#include <vector>

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
        (void)engine.register_worker(WorkerId::from_value(2), WorkerBootId::from_value(21), "B",
                                     EvidenceSequence::from_value(1));
        (void)engine.register_isolation_domain(make_isolation_domain(101, "iso-A", {1, 2}));
        (void)engine.register_isolation_domain(make_isolation_domain(102, "iso-B", {3}));
        add_resource(engine, ResourceSpec{1, "worker-A", ResourceClass::WORKER, ProtectionClass::STANDARD,
                                          0, 101, 0, 1, 11});
        add_resource(engine, ResourceSpec{2, "exec-A", ResourceClass::EXECUTION,
                                          ProtectionClass::STANDARD, 0, 101, 0, 1, 11});
        add_resource(engine, ResourceSpec{3, "worker-B", ResourceClass::WORKER,
                                          ProtectionClass::STANDARD, 0, 102, 0, 2, 21});
    }

    ContainmentGeneration lose_worker_a() {
        const Result<ContainmentRecord> containment = engine.worker_authority_lost(
            WorkerId::from_value(1), WorkerBootId::from_value(11), FaultKind::PROCESS_DEATH, "died", 1000);
        FCF_REQUIRE_MSG(containment.ok(), containment.ok() ? "" : containment.error().to_string());
        return containment.value().generation;
    }
};

}  // namespace

FCF_TEST(adversarial, delayed_completion_from_a_dead_incarnation_cannot_commit) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.lose_worker_a();
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    FCF_REQUIRE(!record.value().actions.empty());
    const Result<ContainmentAction> action = fixture.engine.query_action(record.value().actions.front());
    FCF_REQUIRE(action.ok());

    // A delayed completion arrives from the incarnation that died.
    ActionResult delayed;
    delayed.action = action.value().id;
    delayed.action_generation = action.value().generation;
    delayed.epoch = fixture.engine.epoch();
    delayed.worker = WorkerId::from_value(1);
    delayed.worker_boot = WorkerBootId::from_value(11);
    delayed.success = true;
    const Status status = fixture.engine.record_action_result(delayed);
    FCF_REQUIRE(!status.ok());
    FCF_EQ(status.error().code(), ErrorCode::STALE_WORKER_BOOT);
    const Result<ContainmentAction> unchanged = fixture.engine.query_action(action.value().id);
    FCF_REQUIRE(unchanged.ok());
    FCF_NE(unchanged.value().status, ActionStatus::RESULT_RECORDED);
}

FCF_TEST(adversarial, acknowledgment_after_the_target_generation_changed_is_refused) {
    Fixture fixture;
    FaultEvidence evidence;
    evidence.kind = FaultKind::PROCESS_DEATH;
    evidence.subject = ResourceId::from_value(1);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = fixture.engine.epoch();
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    const Result<FaultRecord> fault = fixture.engine.publish_fault(evidence);
    FCF_REQUIRE(fault.ok());
    const Result<ContainmentRecord> containment =
        fixture.engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
    FCF_REQUIRE(containment.ok());
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(containment.value().generation, &executor).ok());
    const Result<ContainmentAction> action =
        fixture.engine.query_action(containment.value().actions.front());
    FCF_REQUIRE(action.ok());

    // The target moves on before the acknowledgment arrives.
    FCF_REQUIRE(fixture.engine
                    .publish_resource_evidence(action.value().target, ResourceGeneration{},
                                               EvidenceFreshness::FRESH, EvidenceSequence::from_value(9),
                                               ContainmentMechanism::NONE, "test")
                    .ok());
    ActionAcknowledgment ack;
    ack.action = action.value().id;
    ack.action_generation = action.value().generation;
    ack.epoch = fixture.engine.epoch();
    ack.accepted = true;
    FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
    ActionResult result;
    result.action = action.value().id;
    result.action_generation = action.value().generation;
    result.epoch = fixture.engine.epoch();
    result.success = true;
    FCF_REQUIRE(fixture.engine.record_action_result(result).ok());

    // A second dispatch attempt on the same containment revalidates and refuses,
    // because the plan no longer matches the current topology generation.
    const Result<DispatchSummary> again =
        fixture.engine.dispatch_containment(containment.value().generation, &executor);
    FCF_REQUIRE(again.ok());
    FCF_REQUIRE(again.value().dispatched.empty());
}

FCF_TEST(adversarial, a_resource_becoming_healthy_during_containment_stays_fenced) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.lose_worker_a();
    // Fresh evidence and a healthy-looking report arrive mid-containment.
    const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
        ResourceId::from_value(2), ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(77), ContainmentMechanism::LOGICAL_CONTAINMENT, "test");
    FCF_REQUIRE(fresh.ok());
    const Result<ResourceStatusView> view =
        fixture.engine.query_resource_status(ResourceId::from_value(2));
    FCF_REQUIRE(view.ok());
    FCF_REQUIRE_MSG(view.value().quarantined, "fresh evidence must not lift a quarantine");
    FCF_REQUIRE(!view.value().operable);

    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    FCF_REQUIRE(id_set_contains(record.value().mandatory, ResourceId::from_value(2)));
}

FCF_TEST(adversarial, degraded_request_against_stale_evidence_does_not_grant_capacity) {
    Fixture fixture;
    (void)fixture.lose_worker_a();
    DegradedModeContract contract;
    contract.name = "stale-attempt";
    contract.required_redundancy = 1U;
    const Result<DegradedModeAssessment> first = fixture.engine.authorize_degraded_mode(contract);
    FCF_REQUIRE(first.ok());
    FCF_REQUIRE(!claims_full_health(first.value().status));

    // A later request evaluated against evidence that is still not fresh cannot
    // increase the permitted set.
    const Result<DegradedModeAssessment> revalidated =
        fixture.engine.revalidate_degraded_mode(first.value().contract);
    FCF_REQUIRE(revalidated.ok());
    FCF_REQUIRE(revalidated.value().permitted.size() <= first.value().permitted.size());
    FCF_REQUIRE(degraded_sets_are_disjoint(revalidated.value()));
}

FCF_TEST(adversarial, release_from_a_stale_worker_is_refused) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.lose_worker_a();
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    for (const ActionId action_id : record.value().actions) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        ActionAcknowledgment ack;
        ack.action = action_id;
        ack.action_generation = action.value().generation;
        ack.epoch = fixture.engine.epoch();
        ack.accepted = true;
        FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
        ActionResult result;
        result.action = action_id;
        result.action_generation = action.value().generation;
        result.epoch = fixture.engine.epoch();
        result.success = true;
        FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
    }
    FCF_REQUIRE(fixture.engine.verify_containment(generation).ok());
    const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
        ResourceId::from_value(1), ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(90), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(fresh.ok());

    ReleaseRequest request;
    request.resource = ResourceId::from_value(1);
    request.containment_generation = generation;
    request.expected_generation = fresh.value().generation;
    request.evidence_sequence = fresh.value().evidence_sequence;
    request.authority = "operator:ticket";
    request.requester_worker = WorkerId::from_value(1);
    request.requester_boot = WorkerBootId::from_value(11);
    const Result<ReleaseAssessment> assessment = fixture.engine.authorize_release(request);
    FCF_REQUIRE(assessment.ok());
    FCF_REQUIRE(!assessment.value().granted);
    FCF_EQ(assessment.value().decision, ReleaseDecision::RELEASE_DENIED_AUTHORITY);
}

FCF_TEST(adversarial, repeated_contain_and_release_cycles_stay_consistent) {
    for (int cycle = 0; cycle < 6; ++cycle) {
        Fixture fixture;
        const ContainmentGeneration generation = fixture.lose_worker_a();
        NullExecutor executor;
        FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
        const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
        FCF_REQUIRE(record.ok());
        for (const ActionId action_id : record.value().actions) {
            const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
            FCF_REQUIRE(action.ok());
            ActionAcknowledgment ack;
            ack.action = action_id;
            ack.action_generation = action.value().generation;
            ack.epoch = fixture.engine.epoch();
            ack.accepted = true;
            FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
            ActionResult result;
            result.action = action_id;
            result.action_generation = action.value().generation;
            result.epoch = fixture.engine.epoch();
            result.success = true;
            FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
        }
        FCF_REQUIRE(fixture.engine.verify_containment(generation).ok());
        for (const ResourceId resource : {ResourceId::from_value(1), ResourceId::from_value(2)}) {
            const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
                resource, ResourceGeneration{}, EvidenceFreshness::FRESH,
                EvidenceSequence::from_value(100U + static_cast<std::uint64_t>(cycle)),
                ContainmentMechanism::NONE, "test");
            FCF_REQUIRE(fresh.ok());
            ReleaseRequest request;
            request.resource = resource;
            request.containment_generation = generation;
            request.expected_generation = fresh.value().generation;
            request.evidence_sequence = fresh.value().evidence_sequence;
            request.authority = "operator:cycle";
            const Result<ReleaseAssessment> assessment = fixture.engine.authorize_release(request);
            FCF_REQUIRE(assessment.ok());
            FCF_REQUIRE_MSG(assessment.value().granted, assessment.value().summary);
        }
        const Result<ResourceStatusView> view =
            fixture.engine.query_resource_status(ResourceId::from_value(2));
        FCF_REQUIRE(view.ok());
        FCF_REQUIRE(!view.value().quarantined);
    }
}

FCF_TEST(adversarial, identity_collisions_and_sentinel_identities_are_refused) {
    Fixture fixture;
    // Sentinel identities can never be registered.
    ResourceRecord sentinel;
    sentinel.id = ResourceId{};
    FCF_EQ(fixture.engine.register_resource(sentinel).error().code(), ErrorCode::INVALID_ID);

    ContainmentDomain sentinel_domain;
    sentinel_domain.id = ContainmentDomainId{};
    FCF_EQ(fixture.engine.register_domain(sentinel_domain).error().code(), ErrorCode::INVALID_ID);

    FCF_EQ(fixture.engine
               .register_worker(WorkerId{}, WorkerBootId::from_value(1), "x", EvidenceSequence::from_value(1))
               .error()
               .code(),
           ErrorCode::INVALID_ID);
    FCF_EQ(fixture.engine
               .register_worker(WorkerId::from_value(1), WorkerBootId{}, "x", EvidenceSequence::from_value(1))
               .error()
               .code(),
           ErrorCode::INVALID_ID);

    DependencyEdge sentinel_edge;
    sentinel_edge.id = DependencyId{};
    sentinel_edge.source = ResourceId::from_value(1);
    sentinel_edge.destination = ResourceId::from_value(2);
    FCF_EQ(fixture.engine.register_dependency(sentinel_edge).error().code(), ErrorCode::INVALID_ID);

    // A fault whose subject is a sentinel is refused.
    FaultEvidence sentinel_fault;
    sentinel_fault.kind = FaultKind::PROCESS_DEATH;
    sentinel_fault.subject = ResourceId{};
    sentinel_fault.epoch = fixture.engine.epoch();
    FCF_EQ(fixture.engine.publish_fault(sentinel_fault).error().code(), ErrorCode::INVALID_ID);
}

FCF_TEST(adversarial, a_secondary_failure_inside_the_radius_is_reported_as_such) {
    Fixture fixture;
    const ContainmentGeneration generation = fixture.lose_worker_a();
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    for (const ActionId action_id : record.value().actions) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        ActionAcknowledgment ack;
        ack.action = action_id;
        ack.action_generation = action.value().generation;
        ack.epoch = fixture.engine.epoch();
        ack.accepted = true;
        FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
        ActionResult result;
        result.action = action_id;
        result.action_generation = action.value().generation;
        result.epoch = fixture.engine.epoch();
        result.success = true;
        FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
    }

    // A second, independent fault appears on a resource that is already contained.
    FaultEvidence secondary;
    secondary.kind = FaultKind::MEMORY_INTEGRITY_FAILURE;
    secondary.subject = ResourceId::from_value(2);
    secondary.reporter_kind = ReporterKind::OPERATOR;
    secondary.epoch = fixture.engine.epoch();
    secondary.observation_sequence = EvidenceSequence::from_value(5);
    secondary.freshness = EvidenceFreshness::FRESH;
    secondary.integrity = IntegrityStatus::VERIFIED;
    FCF_REQUIRE(fixture.engine.publish_fault(secondary).ok());

    const Result<ContainmentVerification> verification =
        fixture.engine.verify_containment(generation);
    FCF_REQUIRE(verification.ok());
    FCF_REQUIRE(verification.value().secondary_failure);
    FCF_EQ(verification.value().outcome, VerificationOutcome::SECONDARY_FAILURE_CREATED);
}

FCF_TEST(adversarial, overlapping_containments_do_not_release_early) {
    Fixture fixture;
    const ContainmentGeneration first = fixture.lose_worker_a();
    NullExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(first, &executor).ok());
    {
        const Result<ContainmentRecord> initial = fixture.engine.query_containment(first);
        FCF_REQUIRE(initial.ok());
        for (const ActionId action_id : initial.value().actions) {
            const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
            FCF_REQUIRE(action.ok());
            ActionAcknowledgment ack;
            ack.action = action_id;
            ack.action_generation = action.value().generation;
            ack.epoch = fixture.engine.epoch();
            ack.accepted = true;
            FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
            ActionResult result;
            result.action = action_id;
            result.action_generation = action.value().generation;
            result.epoch = fixture.engine.epoch();
            result.success = true;
            FCF_REQUIRE(fixture.engine.record_action_result(result).ok());
        }
    }
    const Result<ContainmentVerification> verified = fixture.engine.verify_containment(first);
    FCF_REQUIRE(verified.ok());
    FCF_EQ(verified.value().outcome, VerificationOutcome::CONTAINED);

    // A second containment covers an overlapping resource.
    FaultEvidence second;
    second.kind = FaultKind::MEMORY_INTEGRITY_FAILURE;
    second.subject = ResourceId::from_value(2);
    second.reporter_kind = ReporterKind::OPERATOR;
    second.epoch = fixture.engine.epoch();
    second.observation_sequence = EvidenceSequence::from_value(2);
    second.freshness = EvidenceFreshness::FRESH;
    second.integrity = IntegrityStatus::VERIFIED;
    const Result<FaultRecord> published = fixture.engine.publish_fault(second);
    FCF_REQUIRE(published.ok());
    const Result<ContainmentRecord> overlapping = fixture.engine.authorize_containment(
        published.value().evidence.id, published.value().evidence.generation);
    FCF_REQUIRE(overlapping.ok());
    FCF_NE(overlapping.value().generation, first);

    const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
        ResourceId::from_value(2), ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(120), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(fresh.ok());
    ReleaseRequest request;
    request.resource = ResourceId::from_value(2);
    request.containment_generation = first;
    request.expected_generation = fresh.value().generation;
    request.evidence_sequence = fresh.value().evidence_sequence;
    request.authority = "operator:overlap";
    const Result<ReleaseAssessment> assessment = fixture.engine.authorize_release(request);
    FCF_REQUIRE(assessment.ok());
    FCF_REQUIRE_MSG(!assessment.value().granted,
                    "a resource covered by another live containment must not be released");
    FCF_EQ(assessment.value().decision, ReleaseDecision::RELEASE_DENIED_PROPAGATION);
}

FCF_TEST(adversarial, resource_membership_cannot_be_stolen_by_a_second_domain) {
    Fixture fixture;
    FCF_REQUIRE(fixture.engine.register_domain(make_domain(301, "cd-one", false, {1})).ok());
    const Result<ContainmentDomain> conflicting =
        fixture.engine.register_domain(make_domain(302, "cd-two", false, {1}));
    FCF_REQUIRE(!conflicting.ok());
    FCF_EQ(conflicting.error().code(), ErrorCode::INVALID_DOMAIN_GRAPH);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
