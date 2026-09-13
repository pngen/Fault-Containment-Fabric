// Fault Containment Fabric — explicit degraded operation.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A contained accelerator must not silently keep working, but independent CPU
// work is explicitly permitted. The degraded assessment proves the separation.

#include <iostream>

#include "fcf/engine.hpp"

int main() {
    fcf::Engine engine;

    fcf::IsolationDomain gpu_iso;
    gpu_iso.id = fcf::IsolationDomainId::from_value(1);
    gpu_iso.name = "gpu";
    gpu_iso.members = {fcf::ResourceId::from_value(1)};
    (void)engine.register_isolation_domain(gpu_iso);

    fcf::IsolationDomain cpu_iso;
    cpu_iso.id = fcf::IsolationDomainId::from_value(2);
    cpu_iso.name = "cpu";
    cpu_iso.members = {fcf::ResourceId::from_value(2)};
    (void)engine.register_isolation_domain(cpu_iso);

    fcf::ResourceRecord gpu;
    gpu.id = fcf::ResourceId::from_value(1);
    gpu.name = "accelerator";
    gpu.resource_class = fcf::ResourceClass::ACCELERATOR;
    gpu.isolation_domain = gpu_iso.id;
    gpu.freshness = fcf::EvidenceFreshness::FRESH;
    gpu.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(gpu);

    fcf::ResourceRecord cpu;
    cpu.id = fcf::ResourceId::from_value(2);
    cpu.name = "cpu-service";
    cpu.resource_class = fcf::ResourceClass::SERVICE;
    cpu.isolation_domain = cpu_iso.id;
    cpu.freshness = fcf::EvidenceFreshness::FRESH;
    cpu.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(cpu);

    fcf::FaultEvidence fault;
    fault.kind = fcf::FaultKind::DEVICE_FAILURE;
    fault.subject = gpu.id;
    fault.reporter_kind = fcf::ReporterKind::OPERATOR;
    fault.epoch = engine.epoch();
    fault.freshness = fcf::EvidenceFreshness::FRESH;
    fault.integrity = fcf::IntegrityStatus::VERIFIED;
    const auto published = engine.publish_fault(fault);
    if (!published.ok()) {
        std::cerr << published.error().to_string() << "\n";
        return 1;
    }
    const auto containment = engine.authorize_containment(published.value().evidence.id,
                                                          published.value().evidence.generation);
    if (!containment.ok()) {
        std::cerr << containment.error().to_string() << "\n";
        return 1;
    }

    fcf::DegradedModeContract contract;
    contract.name = "cpu-continues";
    contract.reduced_capacity_percent = 50;
    contract.required_redundancy = 1;
    contract.legal_workload_classes = {fcf::ResourceClass::SERVICE,
                                       fcf::ResourceClass::WORKER};
    const auto assessment = engine.authorize_degraded_mode(contract);
    if (!assessment.ok()) {
        std::cerr << assessment.error().to_string() << "\n";
        return 1;
    }
    std::cout << "degraded status: " << fcf::to_string(assessment.value().status) << "\n";
    std::cout << "permitted=" << assessment.value().permitted.size()
              << " prohibited=" << assessment.value().prohibited.size() << "\n";
    std::cout << "capacity=" << assessment.value().available_capacity_percent << "%\n";
    std::cout << "permitted/prohibited disjoint: "
              << (fcf::degraded_sets_are_disjoint(assessment.value()) ? "yes" : "no") << "\n";
    for (const fcf::ResourceId id : assessment.value().permitted) {
        std::cout << "  permitted " << fcf::to_string(id) << "\n";
    }
    for (const fcf::ResourceId id : assessment.value().prohibited) {
        std::cout << "  prohibited " << fcf::to_string(id) << "\n";
    }
    return 0;
}
