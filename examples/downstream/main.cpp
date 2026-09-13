// Fault Containment Fabric — independent downstream consumer.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Links only against the installed FaultContainmentFabric::fcf target and exercises
// the public API: topology registration, fault publication, blast-radius evaluation,
// containment authorization, verification, degraded-mode assessment and explanation.

#include <fcf/engine.hpp>
#include <fcf/version.hpp>

#include <iostream>
#include <string>

int main() {
    std::cout << "Fault Containment Fabric " << fcf::version_string() << " downstream consumer\n";

    fcf::Engine engine;

    fcf::IsolationDomain accelerator_domain;
    accelerator_domain.id = fcf::IsolationDomainId::from_value(1);
    accelerator_domain.name = "accelerator-0";
    accelerator_domain.members = {fcf::ResourceId::from_value(1)};
    if (!engine.register_isolation_domain(accelerator_domain).ok()) {
        std::cerr << "failed to register the isolation domain\n";
        return 1;
    }

    fcf::IsolationDomain cpu_domain;
    cpu_domain.id = fcf::IsolationDomainId::from_value(2);
    cpu_domain.name = "cpu-pool";
    cpu_domain.members = {fcf::ResourceId::from_value(2)};
    if (!engine.register_isolation_domain(cpu_domain).ok()) {
        std::cerr << "failed to register the isolation domain\n";
        return 1;
    }

    fcf::ResourceRecord accelerator;
    accelerator.id = fcf::ResourceId::from_value(1);
    accelerator.name = "accelerator-0";
    accelerator.resource_class = fcf::ResourceClass::ACCELERATOR;
    accelerator.isolation_domain = accelerator_domain.id;
    accelerator.freshness = fcf::EvidenceFreshness::FRESH;
    accelerator.state = fcf::ResourceOperationalState::ACTIVE;
    if (!engine.register_resource(accelerator).ok()) {
        std::cerr << "failed to register the accelerator\n";
        return 1;
    }

    fcf::ResourceRecord cpu;
    cpu.id = fcf::ResourceId::from_value(2);
    cpu.name = "cpu-pool";
    cpu.resource_class = fcf::ResourceClass::SERVICE;
    cpu.isolation_domain = cpu_domain.id;
    cpu.freshness = fcf::EvidenceFreshness::FRESH;
    cpu.state = fcf::ResourceOperationalState::ACTIVE;
    if (!engine.register_resource(cpu).ok()) {
        std::cerr << "failed to register the cpu pool\n";
        return 1;
    }

    fcf::FaultEvidence fault;
    fault.kind = fcf::FaultKind::DEVICE_FAILURE;
    fault.subject = accelerator.id;
    fault.reporter_kind = fcf::ReporterKind::OPERATOR;
    fault.epoch = engine.epoch();
    fault.freshness = fcf::EvidenceFreshness::FRESH;
    fault.integrity = fcf::IntegrityStatus::VERIFIED;
    fault.details = "downstream consumer demonstration";
    const auto published = engine.publish_fault(fault);
    if (!published.ok()) {
        std::cerr << published.error().to_string() << "\n";
        return 1;
    }

    const auto radius =
        engine.evaluate_containment(published.value().evidence.id, fcf::FaultGeneration{});
    if (!radius.ok()) {
        std::cerr << radius.error().to_string() << "\n";
        return 1;
    }
    std::cout << fcf::render_blast_radius(radius.value());

    const auto containment =
        engine.authorize_containment(published.value().evidence.id, published.value().evidence.generation);
    if (!containment.ok()) {
        std::cerr << containment.error().to_string() << "\n";
        return 1;
    }

    fcf::DegradedModeContract contract;
    contract.name = "cpu-continues";
    contract.required_redundancy = 1U;
    const auto degraded = engine.authorize_degraded_mode(contract);
    if (!degraded.ok()) {
        std::cerr << degraded.error().to_string() << "\n";
        return 1;
    }
    std::cout << "degraded status: " << fcf::to_string(degraded.value().status) << "\n";
    std::cout << "permitted=" << degraded.value().permitted.size()
              << " prohibited=" << degraded.value().prohibited.size() << "\n";

    const auto accelerator_status = engine.query_resource_status(accelerator.id);
    const auto cpu_status = engine.query_resource_status(cpu.id);
    if (!accelerator_status.ok() || !cpu_status.ok()) {
        std::cerr << "resource status query failed\n";
        return 1;
    }
    if (accelerator_status.value().operable || !cpu_status.value().operable) {
        std::cerr << "the blast radius did not separate the failed accelerator from the cpu pool\n";
        return 1;
    }

    std::cout << "downstream consumer completed successfully\n";
    return 0;
}
