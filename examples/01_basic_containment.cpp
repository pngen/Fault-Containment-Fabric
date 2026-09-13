// Fault Containment Fabric — basic containment.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shows the smallest complete containment decision: register two independent
// domains, publish one fault, evaluate the blast radius and render the decision.

#include <iostream>

#include "fcf/engine.hpp"

int main() {
    fcf::Engine engine;

    fcf::IsolationDomain left;
    left.id = fcf::IsolationDomainId::from_value(1);
    left.name = "left";
    left.members = {fcf::ResourceId::from_value(1)};
    (void)engine.register_isolation_domain(left);

    fcf::IsolationDomain right;
    right.id = fcf::IsolationDomainId::from_value(2);
    right.name = "right";
    right.members = {fcf::ResourceId::from_value(2)};
    (void)engine.register_isolation_domain(right);

    fcf::ResourceRecord first;
    first.id = fcf::ResourceId::from_value(1);
    first.name = "accelerator-0";
    first.resource_class = fcf::ResourceClass::ACCELERATOR;
    first.isolation_domain = left.id;
    first.freshness = fcf::EvidenceFreshness::FRESH;
    first.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(first);

    fcf::ResourceRecord second;
    second.id = fcf::ResourceId::from_value(2);
    second.name = "cpu-pool";
    second.resource_class = fcf::ResourceClass::SERVICE;
    second.isolation_domain = right.id;
    second.freshness = fcf::EvidenceFreshness::FRESH;
    second.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(second);

    fcf::FaultEvidence fault;
    fault.kind = fcf::FaultKind::DEVICE_FAILURE;
    fault.subject = first.id;
    fault.reporter_kind = fcf::ReporterKind::OPERATOR;
    fault.epoch = engine.epoch();
    fault.freshness = fcf::EvidenceFreshness::FRESH;
    fault.integrity = fcf::IntegrityStatus::VERIFIED;
    fault.details = "accelerator 0 stopped responding";
    const auto published = engine.publish_fault(fault);
    if (!published.ok()) {
        std::cerr << published.error().to_string() << "\n";
        return 1;
    }

    const auto radius = engine.evaluate_containment(published.value().evidence.id, fcf::FaultGeneration{});
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
    std::cout << "containment " << fcf::to_string(containment.value().generation) << " committed with "
              << containment.value().mandatory.size() << " mandatory resource(s)\n";
    return 0;
}
