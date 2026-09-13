// Fault Containment Fabric — quarantine, revalidation and release.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Quarantine never expires because time passed. Release requires current
// generations, fresh evidence, a verified containment and explicit authority.

#include <iostream>
#include <string>

#include "fcf/engine.hpp"

namespace {

/// A minimal executor: it records what it was asked to do and confirms that the
/// intent reached an enforcement point. Acceptance is still not containment.
class DemoExecutor : public fcf::Executor {
public:
    fcf::Result<std::string> dispatch(const fcf::ContainmentAction& action) override {
        std::cout << "  executor received " << fcf::to_string(action.kind) << " for "
                  << fcf::to_string(action.target) << "\n";
        return std::string("demo:") + fcf::to_string(action.id);
    }
};

void settle(fcf::Engine& engine, fcf::ContainmentGeneration generation) {
    const auto containment = engine.query_containment(generation);
    if (!containment.ok()) {
        return;
    }
    for (const fcf::ActionId action_id : containment.value().actions) {
        const auto action = engine.query_action(action_id);
        if (!action.ok()) {
            continue;
        }
        fcf::ActionAcknowledgment ack;
        ack.action = action_id;
        ack.action_generation = action.value().generation;
        ack.epoch = engine.epoch();
        ack.accepted = true;
        ack.executor_token = "demo";
        ack.detail = "intent received";
        (void)engine.record_action_ack(ack);

        fcf::ActionResult result;
        result.action = action_id;
        result.action_generation = action.value().generation;
        result.epoch = engine.epoch();
        result.success = true;
        result.mechanism = fcf::ContainmentMechanism::PROCESS_CONTAINMENT;
        result.detail = "enforcement point stopped admitting work for the target";
        (void)engine.record_action_result(result);
    }
}

}  // namespace

int main() {
    fcf::Engine engine;

    fcf::IsolationDomain iso;
    iso.id = fcf::IsolationDomainId::from_value(1);
    iso.name = "iso";
    iso.members = {fcf::ResourceId::from_value(1)};
    (void)engine.register_isolation_domain(iso);

    fcf::ResourceRecord record;
    record.id = fcf::ResourceId::from_value(1);
    record.name = "worker-A";
    record.resource_class = fcf::ResourceClass::WORKER;
    record.isolation_domain = iso.id;
    record.owner_worker = fcf::WorkerId::from_value(1);
    record.owner_boot = fcf::WorkerBootId::from_value(11);
    record.freshness = fcf::EvidenceFreshness::FRESH;
    record.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(record);
    (void)engine.register_worker(fcf::WorkerId::from_value(1), fcf::WorkerBootId::from_value(11), "A",
                                 fcf::EvidenceSequence::from_value(1));

    const auto containment = engine.worker_authority_lost(
        fcf::WorkerId::from_value(1), fcf::WorkerBootId::from_value(11), fcf::FaultKind::PROCESS_DEATH,
        "worker A stopped", 4000);
    if (!containment.ok()) {
        std::cerr << containment.error().to_string() << "\n";
        return 1;
    }
    const fcf::ContainmentGeneration generation = containment.value().generation;

    DemoExecutor executor;
    const auto dispatch = engine.dispatch_containment(generation, &executor);
    if (!dispatch.ok()) {
        std::cerr << dispatch.error().to_string() << "\n";
        return 1;
    }
    settle(engine, generation);

    const auto verification = engine.verify_containment(generation);
    if (!verification.ok()) {
        std::cerr << verification.error().to_string() << "\n";
        return 1;
    }
    std::cout << "verification: " << fcf::to_string(verification.value().outcome) << " -- "
              << verification.value().summary << "\n";

    const auto snapshot = engine.snapshot();
    fcf::ReleaseRequest request;
    request.resource = fcf::ResourceId::from_value(1);
    request.containment_generation = generation;
    request.expected_generation = snapshot->topology.resources.at(request.resource).generation;
    request.evidence_sequence = snapshot->topology.resources.at(request.resource).evidence_sequence;
    request.authority = "operator:release-ticket-7";

    // The resource is still marked as requiring revalidation, so release is refused.
    const auto denied = engine.authorize_release(request);
    if (denied.ok()) {
        std::cout << "release before revalidation: " << fcf::to_string(denied.value().decision) << " ("
                  << denied.value().summary << ")\n";
    }

    // Fresh evidence from the live incarnation arrives; the resource generation moved.
    const auto fresh = engine.publish_resource_evidence(
        request.resource, fcf::ResourceGeneration{}, fcf::EvidenceFreshness::FRESH,
        fcf::EvidenceSequence::from_value(99), fcf::ContainmentMechanism::NONE, "worker-A-operator");
    if (!fresh.ok()) {
        std::cerr << fresh.error().to_string() << "\n";
        return 1;
    }
    request.expected_generation = fresh.value().generation;
    request.evidence_sequence = fresh.value().evidence_sequence;

    const auto granted = engine.authorize_release(request);
    if (!granted.ok()) {
        std::cerr << granted.error().to_string() << "\n";
        return 1;
    }
    std::cout << "release decision: " << fcf::to_string(granted.value().decision) << " -- "
              << granted.value().summary << "\n";
    for (const fcf::VerificationFinding& criterion : granted.value().criteria) {
        std::cout << "  " << (criterion.passed ? "pass " : "fail ") << criterion.check << " -- "
                  << criterion.detail << "\n";
    }

    const auto after = engine.query_resource_status(request.resource);
    std::cout << "after release: quarantined=" << (after.value().quarantined ? "yes" : "no")
              << " operable=" << (after.value().operable ? "yes" : "no") << "\n";
    return 0;
}
