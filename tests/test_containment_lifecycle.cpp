// Fault Containment Fabric — containment lifecycle proof obligations.
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

class RecordingExecutor : public Executor {
public:
    Result<std::string> dispatch(const ContainmentAction& action) override {
        dispatched.push_back(action.id);
        if (fail_next) {
            return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "test.executor", "refused on purpose");
        }
        return std::string("token:") + to_string(action.id);
    }
    std::vector<ActionId> dispatched;
    bool fail_next = false;
};

struct Fixture {
    LogicalClock clock;
    Engine engine;
    ResourceId subject{ResourceId::from_value(1)};
    Fixture() : engine(make_config(clock)) {
        (void)engine.register_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "A",
                                     EvidenceSequence::from_value(1));
        (void)engine.register_isolation_domain(make_isolation_domain(101, "iso-A", {1, 2}));
        (void)engine.register_isolation_domain(make_isolation_domain(102, "iso-B", {3}));
        (void)engine.register_failure_domain(make_failure_domain(201, "fd-A", {1, 2}));
        (void)engine.register_failure_domain(make_failure_domain(202, "fd-B", {3}));
        add_resource(engine, ResourceSpec{1, "worker-A", ResourceClass::WORKER, ProtectionClass::STANDARD,
                                          0, 101, 201, 1, 11});
        add_resource(engine, ResourceSpec{2, "exec-A", ResourceClass::EXECUTION,
                                          ProtectionClass::STANDARD, 0, 101, 201, 1, 11});
        add_resource(engine, ResourceSpec{3, "worker-B", ResourceClass::WORKER,
                                          ProtectionClass::STANDARD, 0, 102, 202, 2, 21});
    }

    FaultId raise() {
        FaultEvidence evidence;
        evidence.kind = FaultKind::PROCESS_DEATH;
        evidence.subject = subject;
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        const Result<FaultRecord> published = engine.publish_fault(evidence);
        FCF_REQUIRE_MSG(published.ok(), published.ok() ? "" : published.error().to_string());
        return published.value().evidence.id;
    }

    ContainmentGeneration contain(FaultId fault) {
        const Result<FaultRecord> record = engine.query_fault(fault);
        FCF_REQUIRE(record.ok());
        const Result<ContainmentRecord> containment =
            engine.authorize_containment(fault, record.value().evidence.generation);
        FCF_REQUIRE_MSG(containment.ok(), containment.ok() ? "" : containment.error().to_string());
        return containment.value().generation;
    }

    void settle(ContainmentGeneration generation) {
        const Result<ContainmentRecord> containment = engine.query_containment(generation);
        FCF_REQUIRE(containment.ok());
        for (const ActionId action_id : containment.value().actions) {
            const Result<ContainmentAction> action = engine.query_action(action_id);
            FCF_REQUIRE(action.ok());
            ActionAcknowledgment ack;
            ack.action = action_id;
            ack.action_generation = action.value().generation;
            ack.epoch = engine.epoch();
            ack.accepted = true;
            ack.executor_token = "test";
            FCF_REQUIRE(engine.record_action_ack(ack).ok());
            ActionResult result;
            result.action = action_id;
            result.action_generation = action.value().generation;
            result.epoch = engine.epoch();
            result.success = true;
            result.mechanism = ContainmentMechanism::PROCESS_CONTAINMENT;
            FCF_REQUIRE(engine.record_action_result(result).ok());
        }
    }
};

}  // namespace

FCF_TEST(containment_lifecycle, authorization_fences_the_radius_without_touching_unaffected_work) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    FCF_EQ(record.value().mandatory.size(), 2U);
    FCF_REQUIRE(contains(record.value().unaffected, 3));

    const Result<ResourceStatusView> contained =
        fixture.engine.query_resource_status(ResourceId::from_value(2));
    FCF_REQUIRE(contained.ok());
    FCF_REQUIRE(contained.value().quarantined);
    FCF_REQUIRE(!contained.value().operable);

    const Result<ResourceStatusView> untouched =
        fixture.engine.query_resource_status(ResourceId::from_value(3));
    FCF_REQUIRE(untouched.ok());
    FCF_REQUIRE(!untouched.value().quarantined);
    FCF_REQUIRE(untouched.value().operable);
}

FCF_TEST(containment_lifecycle, acknowledged_is_not_contained) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    RecordingExecutor executor;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    FCF_REQUIRE(!summary.value().dispatched.empty());

    // Only acknowledgments so far: acceptance is not evidence of effect.
    for (const ActionId action_id : summary.value().dispatched) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        ActionAcknowledgment ack;
        ack.action = action_id;
        ack.action_generation = action.value().generation;
        ack.epoch = fixture.engine.epoch();
        ack.accepted = true;
        FCF_REQUIRE(fixture.engine.record_action_ack(ack).ok());
    }
    const Result<ContainmentVerification> verification =
        fixture.engine.verify_containment(generation);
    FCF_REQUIRE(verification.ok());
    FCF_EQ(verification.value().outcome, VerificationOutcome::OUTCOME_UNKNOWN);
    FCF_REQUIRE(!verification.value().findings.empty());
    bool found = false;
    for (const VerificationFinding& finding : verification.value().findings) {
        if (finding.check == "actions_have_post_action_evidence") {
            found = true;
            FCF_REQUIRE(!finding.passed);
        }
    }
    FCF_REQUIRE(found);
}

FCF_TEST(containment_lifecycle, full_sequence_reaches_contained) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    RecordingExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    fixture.settle(generation);

    const Result<ContainmentVerification> verification =
        fixture.engine.verify_containment(generation);
    FCF_REQUIRE(verification.ok());
    FCF_EQ(verification.value().outcome, VerificationOutcome::CONTAINED);
    FCF_REQUIRE(verification.value().propagation_blocked);
    FCF_REQUIRE(!verification.value().secondary_failure);
    FCF_REQUIRE(!verification.value().blast_radius_increased);
    FCF_REQUIRE(verification.value().degraded_mode_valid);

    const Result<ContainmentRecord> record = fixture.engine.query_containment(generation);
    FCF_REQUIRE(record.ok());
    FCF_EQ(record.value().status, ContainmentStatus::VERIFIED_CONTAINED);

    const Result<FaultRecord> fault_record = fixture.engine.query_fault(fault);
    FCF_REQUIRE(fault_record.ok());
    FCF_EQ(fault_record.value().state, FaultState::CONTAINED);
}

FCF_TEST(containment_lifecycle, containment_cannot_be_committed_twice_for_the_same_fault) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    (void)fixture.contain(fault);
    const Result<FaultRecord> record = fixture.engine.query_fault(fault);
    FCF_REQUIRE(record.ok());
    const Result<ContainmentRecord> again =
        fixture.engine.authorize_containment(fault, record.value().evidence.generation);
    FCF_REQUIRE(!again.ok());
    FCF_EQ(again.error().code(), ErrorCode::CONTAINMENT_ALREADY_COMMITTED);
}

FCF_TEST(containment_lifecycle, executor_refusal_is_reported_and_never_treated_as_success) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    RecordingExecutor executor;
    executor.fail_next = true;
    const Result<DispatchSummary> summary = fixture.engine.dispatch_containment(generation, &executor);
    FCF_REQUIRE(summary.ok());
    FCF_REQUIRE(summary.value().dispatched.empty());
    FCF_EQ(summary.value().refused.size(), summary.value().refusals.size());
    for (const ActionId action_id : summary.value().refused) {
        const Result<ContainmentAction> action = fixture.engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        FCF_EQ(action.value().status, ActionStatus::REJECTED_INFEASIBLE);
        FCF_EQ(action.value().rejection_code, ErrorCode::EXECUTOR_UNAVAILABLE);
    }
}

FCF_TEST(containment_lifecycle, degraded_mode_is_explicit_and_excludes_quarantined_resources) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);

    DegradedModeContract contract;
    contract.name = "test-degraded";
    contract.reduced_capacity_percent = 40U;
    contract.required_redundancy = 1U;
    const Result<DegradedModeAssessment> assessment =
        fixture.engine.authorize_degraded_mode(contract);
    FCF_REQUIRE(assessment.ok());
    FCF_EQ(assessment.value().status, DegradedModeStatus::DEGRADED_AUTHORIZED);
    FCF_REQUIRE(degraded_sets_are_disjoint(assessment.value()));
    FCF_REQUIRE(!claims_full_health(assessment.value().status));
    for (const ResourceId id : assessment.value().prohibited) {
        FCF_REQUIRE(!id_set_contains(assessment.value().permitted, id));
    }
    FCF_REQUIRE(id_set_contains(assessment.value().permitted, ResourceId::from_value(3)));
    FCF_REQUIRE(!id_set_contains(assessment.value().permitted, ResourceId::from_value(2)));
    FCF_REQUIRE(assessment.value().available_capacity_percent <= 40U);

    // Revalidation refreshes the assessment without inventing capacity.
    const Result<DegradedModeAssessment> revalidated =
        fixture.engine.revalidate_degraded_mode(assessment.value().contract);
    FCF_REQUIRE(revalidated.ok());
    FCF_REQUIRE(degraded_sets_are_disjoint(revalidated.value()));
    FCF_EQ(revalidated.value().contract, assessment.value().contract);
}

FCF_TEST(containment_lifecycle, contract_that_contradicts_itself_is_rejected) {
    Fixture fixture;
    DegradedModeContract contract;
    contract.name = "contradiction";
    contract.permitted_resources = {ResourceId::from_value(3)};
    contract.prohibited_resources = {ResourceId::from_value(3)};
    const Result<DegradedModeAssessment> assessment =
        fixture.engine.authorize_degraded_mode(contract);
    FCF_REQUIRE(!assessment.ok());
    FCF_EQ(assessment.error().code(), ErrorCode::DEGRADED_MODE_FORBIDDEN);
}

FCF_TEST(containment_lifecycle, release_requires_verification_fresh_evidence_and_authority) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    RecordingExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    fixture.settle(generation);
    FCF_REQUIRE(fixture.engine.verify_containment(generation).ok());

    ReleaseRequest request;
    request.resource = ResourceId::from_value(1);
    request.containment_generation = generation;
    request.epoch = fixture.engine.epoch();
    request.authority = "operator:ticket-1";

    // No explicit authority.
    ReleaseRequest no_authority = request;
    no_authority.authority.clear();
    const Result<ReleaseAssessment> denied_authority =
        fixture.engine.authorize_release(no_authority);
    FCF_REQUIRE(denied_authority.ok());
    FCF_REQUIRE(!denied_authority.value().granted);
    FCF_EQ(denied_authority.value().decision, ReleaseDecision::RELEASE_DENIED_AUTHORITY);

    // Stale worker incarnation requesting release.
    ReleaseRequest stale_worker = request;
    stale_worker.requester_worker = WorkerId::from_value(1);
    stale_worker.requester_boot = WorkerBootId::from_value(99);
    const Result<ReleaseAssessment> denied_worker =
        fixture.engine.authorize_release(stale_worker);
    FCF_REQUIRE(denied_worker.ok());
    FCF_EQ(denied_worker.value().decision, ReleaseDecision::RELEASE_DENIED_AUTHORITY);

    // Aging evidence is not sufficient proof for a release.
    const Result<ResourceRecord> aging = fixture.engine.publish_resource_evidence(
        request.resource, ResourceGeneration{}, EvidenceFreshness::AGING,
        EvidenceSequence::from_value(45), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(aging.ok());
    request.expected_generation = aging.value().generation;
    request.evidence_sequence = aging.value().evidence_sequence;
    const Result<ReleaseAssessment> denied_evidence = fixture.engine.authorize_release(request);
    FCF_REQUIRE(denied_evidence.ok());
    FCF_REQUIRE(!denied_evidence.value().granted);
    FCF_EQ(denied_evidence.value().decision, ReleaseDecision::RELEASE_DENIED_EVIDENCE);

    // Fresh evidence arrives.
    const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
        request.resource, ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(50), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(fresh.ok());
    request.expected_generation = fresh.value().generation;
    request.evidence_sequence = fresh.value().evidence_sequence;

    const Result<ReleaseAssessment> granted = fixture.engine.authorize_release(request);
    FCF_REQUIRE(granted.ok());
    FCF_REQUIRE(granted.value().granted);
    FCF_EQ(granted.value().decision, ReleaseDecision::RELEASE_GRANTED);

    const Result<ResourceStatusView> after =
        fixture.engine.query_resource_status(request.resource);
    FCF_REQUIRE(after.ok());
    FCF_REQUIRE(!after.value().quarantined);
    FCF_REQUIRE(after.value().operable);
    FCF_EQ(after.value().resource.state, ResourceOperationalState::ACTIVE);
}

FCF_TEST(containment_lifecycle, release_before_verification_is_refused) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    ReleaseRequest request;
    request.resource = ResourceId::from_value(1);
    request.containment_generation = generation;
    request.authority = "operator:ticket-2";
    const Result<ReleaseAssessment> assessment = fixture.engine.authorize_release(request);
    FCF_REQUIRE(assessment.ok());
    FCF_REQUIRE(!assessment.value().granted);
    FCF_EQ(assessment.value().decision, ReleaseDecision::RELEASE_DENIED_UNVERIFIED);
}

FCF_TEST(containment_lifecycle, release_of_an_unproven_containment_is_refused) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    RecordingExecutor executor;
    FCF_REQUIRE(fixture.engine.dispatch_containment(generation, &executor).ok());
    // Dispatched but never acknowledged: verification cannot conclude containment.
    FCF_REQUIRE(fixture.engine.verify_containment(generation).ok());
    const Result<ResourceRecord> fresh = fixture.engine.publish_resource_evidence(
        ResourceId::from_value(1), ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(60), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(fresh.ok());
    ReleaseRequest request;
    request.resource = ResourceId::from_value(1);
    request.containment_generation = generation;
    request.authority = "operator:ticket-3";
    request.expected_generation = fresh.value().generation;
    request.evidence_sequence = fresh.value().evidence_sequence;
    const Result<ReleaseAssessment> assessment = fixture.engine.authorize_release(request);
    FCF_REQUIRE(assessment.ok());
    FCF_REQUIRE(!assessment.value().granted);
    FCF_EQ(assessment.value().decision, ReleaseDecision::RELEASE_DENIED_UNVERIFIED);
}

FCF_TEST(containment_lifecycle, explain_is_stable_and_covers_every_bucket) {
    Fixture fixture;
    const FaultId fault = fixture.raise();
    const ContainmentGeneration generation = fixture.contain(fault);
    const Result<ContainmentExplanation> first = fixture.engine.explain(generation);
    const Result<ContainmentExplanation> second = fixture.engine.explain(generation);
    FCF_REQUIRE(first.ok() && second.ok());
    FCF_EQ(first.value().render(), second.value().render());
    const std::string text = first.value().render();
    FCF_REQUIRE(text.find("MANDATORY:") != std::string::npos);
    FCF_REQUIRE(text.find("UNAFFECTED:") != std::string::npos);
    FCF_REQUIRE(text.find("AUTHORITY:") != std::string::npos);
    FCF_REQUIRE(text.find("VERIFICATION:") != std::string::npos);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
