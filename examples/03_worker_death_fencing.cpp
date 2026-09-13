// Fault Containment Fabric — worker death fencing.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A worker incarnation is lost; its live authority is revoked, everything bound
// to that incarnation is fenced, an independent worker keeps running.

#include <iostream>

#include "fcf/engine.hpp"

namespace {

fcf::ResourceId add(fcf::Engine& engine, std::uint64_t id, const char* name, fcf::ResourceClass klass,
                    std::uint64_t owner_worker, std::uint64_t owner_boot, std::uint64_t isolation) {
    fcf::IsolationDomain iso;
    iso.id = fcf::IsolationDomainId::from_value(isolation);
    iso.name = std::string("iso-") + name;
    iso.members = {fcf::ResourceId::from_value(id)};
    (void)engine.register_isolation_domain(iso);
    fcf::ResourceRecord record;
    record.id = fcf::ResourceId::from_value(id);
    record.name = name;
    record.resource_class = klass;
    record.isolation_domain = iso.id;
    record.owner_worker = fcf::WorkerId::from_value(owner_worker);
    record.owner_boot = fcf::WorkerBootId::from_value(owner_boot);
    record.freshness = fcf::EvidenceFreshness::FRESH;
    record.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(record);
    return record.id;
}

}  // namespace

int main() {
    fcf::Engine engine;
    const auto boot_a = fcf::WorkerBootId::from_value(11);
    const auto boot_b = fcf::WorkerBootId::from_value(21);
    (void)engine.register_worker(fcf::WorkerId::from_value(1), boot_a, "A", fcf::EvidenceSequence::from_value(1));
    (void)engine.register_worker(fcf::WorkerId::from_value(2), boot_b, "B", fcf::EvidenceSequence::from_value(1));

    const fcf::ResourceId worker_a = add(engine, 1, "worker-A", fcf::ResourceClass::WORKER, 1, 11, 101);
    const fcf::ResourceId execution_a =
        add(engine, 2, "execution-A", fcf::ResourceClass::EXECUTION, 1, 11, 102);
    (void)add(engine, 3, "worker-B", fcf::ResourceClass::WORKER, 2, 21, 103);

    const auto containment =
        engine.worker_authority_lost(fcf::WorkerId::from_value(1), boot_a, fcf::FaultKind::PROCESS_DEATH,
                                     "worker A process died", 5000);
    if (!containment.ok()) {
        std::cerr << containment.error().to_string() << "\n";
        return 1;
    }
    std::cout << "containment " << fcf::to_string(containment.value().generation) << " mandatory="
              << containment.value().mandatory.size() << " unaffected="
              << containment.value().unaffected.size() << "\n";

    const auto fenced = engine.query_resource_status(execution_a);
    const auto alive = engine.query_resource_status(fcf::ResourceId::from_value(3));
    std::cout << "execution-A quarantined=" << (fenced.value().quarantined ? "yes" : "no")
              << " operable=" << (fenced.value().operable ? "yes" : "no") << "\n";
    std::cout << "worker-B    operable=" << (alive.value().operable ? "yes" : "no") << "\n";

    const auto verification = engine.verify_containment(containment.value().generation);
    if (verification.ok()) {
        std::cout << "verification " << fcf::to_string(verification.value().outcome) << ": "
                  << verification.value().summary << "\n";
    }
    std::cout << fcf::render_blast_radius(
        engine.evaluate_containment(containment.value().fault, fcf::FaultGeneration{}).value());
    (void)worker_a;
    return 0;
}
