// Fault Containment Fabric — dependency-driven blast radius.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A hard dependency propagates containment; a conditional dependency produces a
// precautionary classification instead of a mandatory fence.

#include <iostream>

#include "fcf/engine.hpp"

namespace {

fcf::ResourceId add(fcf::Engine& engine, std::uint64_t id, const char* name, std::uint64_t isolation,
                    std::uint64_t failure) {
    fcf::IsolationDomain iso;
    iso.id = fcf::IsolationDomainId::from_value(isolation);
    iso.name = std::string("iso-") + name;
    iso.members = {fcf::ResourceId::from_value(id)};
    (void)engine.register_isolation_domain(iso);
    fcf::FailureDomain fail;
    fail.id = fcf::FailureDomainId::from_value(failure);
    fail.name = std::string("fd-") + name;
    fail.kind = fcf::FailureDomainKind::SYNTHETIC_CORRELATED_GROUP;
    fail.members = {fcf::ResourceId::from_value(id)};
    fail.freshness = fcf::EvidenceFreshness::FRESH;
    (void)engine.register_failure_domain(fail);
    fcf::ResourceRecord record;
    record.id = fcf::ResourceId::from_value(id);
    record.name = name;
    record.isolation_domain = iso.id;
    record.failure_domain = fail.id;
    record.freshness = fcf::EvidenceFreshness::FRESH;
    record.state = fcf::ResourceOperationalState::ACTIVE;
    (void)engine.register_resource(record);
    return record.id;
}

void link(fcf::Engine& engine, std::uint64_t id, std::uint64_t source, std::uint64_t destination,
          fcf::DependencyKind kind, bool conditional) {
    fcf::DependencyEdge edge;
    edge.id = fcf::DependencyId::from_value(id);
    edge.source = fcf::ResourceId::from_value(source);
    edge.destination = fcf::ResourceId::from_value(destination);
    edge.kind = kind;
    edge.conditional = conditional;
    edge.freshness = fcf::EvidenceFreshness::FRESH;
    edge.integrity = fcf::IntegrityStatus::VERIFIED;
    edge.confidence_permille = 1000U;
    edge.evidence_source = "example";
    (void)engine.register_dependency(edge);
}

}  // namespace

int main() {
    fcf::Engine engine;
    const fcf::ResourceId worker = add(engine, 1, "worker", 101, 201);
    const fcf::ResourceId execution = add(engine, 2, "execution", 102, 202);
    const fcf::ResourceId state = add(engine, 3, "state", 103, 203);
    const fcf::ResourceId optional = add(engine, 4, "optional-cache", 104, 204);

    link(engine, 401, 1, 2, fcf::DependencyKind::EXECUTION_DEPENDS_ON, false);
    link(engine, 402, 2, 3, fcf::DependencyKind::STATE_OWNED_BY, false);
    link(engine, 403, 3, 4, fcf::DependencyKind::SERVICE_DEPENDS_ON, true);

    fcf::FaultEvidence fault;
    fault.kind = fcf::FaultKind::PROCESS_DEATH;
    fault.subject = worker;
    fault.reporter_kind = fcf::ReporterKind::OPERATOR;
    fault.epoch = engine.epoch();
    fault.freshness = fcf::EvidenceFreshness::FRESH;
    fault.integrity = fcf::IntegrityStatus::VERIFIED;
    const auto published = engine.publish_fault(fault);
    if (!published.ok()) {
        std::cerr << published.error().to_string() << "\n";
        return 1;
    }

    const auto radius =
        engine.query_blast_radius(published.value().evidence.id);
    if (!radius.ok()) {
        std::cerr << radius.error().to_string() << "\n";
        return 1;
    }
    std::cout << "mandatory   : " << radius.value().mandatory.size() << "\n";
    std::cout << "precautionary: " << radius.value().precautionary.size() << "\n";
    std::cout << "unaffected  : " << radius.value().unaffected.size() << "\n";
    std::cout << "unresolved  : " << radius.value().unresolved.size() << "\n";
    for (const fcf::PropagationHop& hop : radius.value().propagation) {
        std::cout << "  hop " << fcf::to_string(hop.from) << " -> " << fcf::to_string(hop.to) << " via "
                  << fcf::to_string(hop.kind) << " (" << fcf::to_string(hop.outcome) << ")\n";
    }
    (void)execution;
    (void)state;
    (void)optional;
    return 0;
}
