// Fault Containment Fabric — persistence and conservative restart.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Durable containment history survives a restart. Live authority does not: after
// recovery the epoch advances, dynamic evidence requires revalidation and stale
// traffic is refused.

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "fcf/engine.hpp"
#include "fcf/persistence.hpp"

int main() {
    const std::filesystem::path directory =
        std::filesystem::temp_directory_path() / "fcf-example-07-state";
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);

    fcf::DurableStore::Options options;
    options.directory = directory.string();

    {
        auto store = fcf::DurableStore::open(options);
        if (!store.ok()) {
            std::cerr << store.error().to_string() << "\n";
            return 1;
        }
        fcf::Engine engine;
        (void)engine.attach_store(store.value().get());

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
        record.freshness = fcf::EvidenceFreshness::FRESH;
        record.state = fcf::ResourceOperationalState::ACTIVE;
        (void)engine.register_resource(record);

        const auto fault = [&]() {
            fcf::FaultEvidence evidence;
            evidence.kind = fcf::FaultKind::PROCESS_DEATH;
            evidence.subject = record.id;
            evidence.reporter_kind = fcf::ReporterKind::OPERATOR;
            evidence.epoch = engine.epoch();
            evidence.freshness = fcf::EvidenceFreshness::FRESH;
            evidence.integrity = fcf::IntegrityStatus::VERIFIED;
            return engine.publish_fault(evidence);
        }();
        if (!fault.ok()) {
            std::cerr << fault.error().to_string() << "\n";
            return 1;
        }
        const auto containment =
            engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
        if (!containment.ok()) {
            std::cerr << containment.error().to_string() << "\n";
            return 1;
        }
        std::cout << "before restart: epoch " << fcf::to_string(engine.epoch()) << " containment "
                  << fcf::to_string(containment.value().generation) << "\n";
        const auto persisted = engine.persist_snapshot();
        if (!persisted.ok()) {
            std::cerr << persisted.error().to_string() << "\n";
            return 1;
        }
    }

    {
        auto store = fcf::DurableStore::open(options);
        if (!store.ok()) {
            std::cerr << store.error().to_string() << "\n";
            return 1;
        }
        fcf::Engine engine;
        const auto recovered = engine.recover_from_store(*store.value(), 9000);
        if (!recovered.ok()) {
            std::cerr << recovered.error().to_string() << "\n";
            return 1;
        }
        std::cout << "after restart : epoch " << fcf::to_string(engine.epoch()) << "\n";

        const fcf::SystemStatus status = engine.query_system_status();
        std::cout << "durable containments survived: " << status.live_containment_count << "\n";
        std::cout << "resources requiring revalidation: " << status.unresolved_resource_count << "\n";

        const auto resource = engine.query_resource_status(fcf::ResourceId::from_value(1));
        if (resource.ok()) {
            std::cout << "resource state " << fcf::to_string(resource.value().resource.state)
                      << " freshness " << fcf::to_string(resource.value().resource.freshness) << "\n";
        }

        // Traffic from the previous epoch is refused rather than resurrected.
        fcf::FaultEvidence stale;
        stale.kind = fcf::FaultKind::PROCESS_DEATH;
        stale.subject = fcf::ResourceId::from_value(1);
        stale.epoch = fcf::CoordinatorEpoch::from_value(1);
        stale.freshness = fcf::EvidenceFreshness::FRESH;
        stale.integrity = fcf::IntegrityStatus::VERIFIED;
        const auto refused = engine.publish_fault(stale);
        std::cout << "old-epoch fault publication: "
                  << (refused.ok() ? "accepted" : fcf::to_string(refused.error().code())) << "\n";
    }

    std::filesystem::remove_all(directory, ec);
    return 0;
}
