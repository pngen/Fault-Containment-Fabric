// Fault Containment Fabric — stale authority rejection.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every generation-bearing operation is refused once the state it was decided
// under has advanced. Nothing stale is repaired or reinterpreted.

#include <iostream>

#include "fcf/engine.hpp"

namespace {

template <class T>
void report(const char* what, const fcf::Result<T>& result) {
    if (result.ok()) {
        std::cout << what << ": accepted\n";
    } else {
        std::cout << what << ": refused " << fcf::to_string(result.error().code()) << " ("
                  << result.error().message() << ")\n";
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

    const auto snapshot = engine.snapshot();
    const fcf::ResourceGeneration observed = snapshot->topology.resources.at(record.id).generation;

    // A newer incarnation appears; the observed generation is now history.
    (void)engine.register_worker(fcf::WorkerId::from_value(1), fcf::WorkerBootId::from_value(12), "A",
                                 fcf::EvidenceSequence::from_value(2));
    report("evidence under the superseded resource generation",
           engine.publish_resource_evidence(record.id, observed, fcf::EvidenceFreshness::FRESH,
                                            fcf::EvidenceSequence::from_value(5),
                                            fcf::ContainmentMechanism::NONE, "example"));

    // An observation reported under an older coordinator epoch is refused.
    fcf::FaultEvidence stale_fault;
    stale_fault.kind = fcf::FaultKind::PROCESS_DEATH;
    stale_fault.subject = record.id;
    stale_fault.epoch = fcf::CoordinatorEpoch::from_value(99);
    stale_fault.freshness = fcf::EvidenceFreshness::FRESH;
    stale_fault.integrity = fcf::IntegrityStatus::VERIFIED;
    const auto stale_result = engine.publish_fault(stale_fault);
    std::cout << "fault under a stale coordinator epoch: "
              << (stale_result.ok() ? "accepted" : fcf::to_string(stale_result.error().code()))
              << "\n";

    // Acknowledging an action for an incarnation that no longer holds authority.
    fcf::ActionAcknowledgment ack;
    ack.action = fcf::ActionId::from_value(1);
    ack.action_generation = fcf::ActionGeneration::from_value(1);
    ack.epoch = engine.epoch();
    ack.worker = fcf::WorkerId::from_value(1);
    ack.worker_boot = fcf::WorkerBootId::from_value(11);
    ack.accepted = true;
    report("acknowledgment from a revoked incarnation", engine.record_action_ack(ack));
    return 0;
}
