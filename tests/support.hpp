// Fault Containment Fabric — shared test scenario helpers.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_TESTS_SUPPORT_HPP
#define FCF_TESTS_SUPPORT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fcf/engine.hpp"
#include "framework.hpp"

namespace fcf::test {

/// Deterministic logical clock so evidence publication times are reproducible.
class LogicalClock {
public:
    [[nodiscard]] std::uint64_t operator()() const noexcept { return now_; }
    void advance(std::uint64_t milliseconds) noexcept { now_ += milliseconds; }

private:
    std::uint64_t now_ = 1000;
};

inline Engine::Config make_config(LogicalClock& clock) {
    Engine::Config config;
    config.clock = [&clock]() { return clock(); };
    config.initial_epoch = CoordinatorEpoch::from_value(1);
    return config;
}

inline ContainmentDomain make_domain(std::uint64_t id, const std::string& name, bool co_isolate,
                                     const std::vector<std::uint64_t>& members) {
    ContainmentDomain domain;
    domain.id = ContainmentDomainId::from_value(id);
    domain.name = name;
    domain.co_isolate_members = co_isolate;
    for (const std::uint64_t member : members) {
        id_set_insert(domain.members, ResourceId::from_value(member));
    }
    return domain;
}

inline IsolationDomain make_isolation_domain(std::uint64_t id, const std::string& name,
                                             const std::vector<std::uint64_t>& members) {
    IsolationDomain domain;
    domain.id = IsolationDomainId::from_value(id);
    domain.name = name;
    domain.mechanism = ContainmentMechanism::LOGICAL_CONTAINMENT;
    enum_set_insert(domain.classes, IsolationClass::AUTHORITY);
    for (const std::uint64_t member : members) {
        id_set_insert(domain.members, ResourceId::from_value(member));
    }
    return domain;
}

inline FailureDomain make_failure_domain(std::uint64_t id, const std::string& name,
                                         const std::vector<std::uint64_t>& members) {
    FailureDomain domain;
    domain.id = FailureDomainId::from_value(id);
    domain.name = name;
    domain.kind = FailureDomainKind::SYNTHETIC_CORRELATED_GROUP;
    domain.provenance = EvidenceProvenance::TOPOLOGY_IMPORT;
    domain.freshness = EvidenceFreshness::FRESH;
    for (const std::uint64_t member : members) {
        id_set_insert(domain.members, ResourceId::from_value(member));
    }
    return domain;
}

struct ResourceSpec {
    std::uint64_t id = 0;
    std::string name;
    ResourceClass resource_class = ResourceClass::GENERIC;
    ProtectionClass protection = ProtectionClass::STANDARD;
    std::uint64_t containment_domain = 0;
    std::uint64_t isolation_domain = 0;
    std::uint64_t failure_domain = 0;
    std::uint64_t owner_worker = 0;
    std::uint64_t owner_boot = 0;
    EvidenceFreshness freshness = EvidenceFreshness::FRESH;
    ResourceOperationalState state = ResourceOperationalState::ACTIVE;
};

inline ResourceId add_resource(Engine& engine, const ResourceSpec& spec) {
    ResourceRecord record;
    record.id = ResourceId::from_value(spec.id);
    record.name = spec.name;
    record.resource_class = spec.resource_class;
    record.protection = spec.protection;
    record.containment_domain = ContainmentDomainId::from_value(spec.containment_domain);
    record.isolation_domain = IsolationDomainId::from_value(spec.isolation_domain);
    record.failure_domain = FailureDomainId::from_value(spec.failure_domain);
    record.owner_worker = WorkerId::from_value(spec.owner_worker);
    record.owner_boot = WorkerBootId::from_value(spec.owner_boot);
    record.freshness = spec.freshness;
    record.state = spec.state;
    record.evidence_sequence = EvidenceSequence::from_value(1);
    const Result<ResourceRecord> stored = engine.register_resource(record);
    FCF_REQUIRE_MSG(stored.ok(), stored.ok() ? "" : stored.error().to_string());
    return stored.value().id;
}

inline void add_dependency(Engine& engine, std::uint64_t id, std::uint64_t source,
                           std::uint64_t destination, DependencyKind kind, bool conditional = false) {
    DependencyEdge edge;
    edge.id = DependencyId::from_value(id);
    edge.source = ResourceId::from_value(source);
    edge.destination = ResourceId::from_value(destination);
    edge.kind = kind;
    edge.provenance = EvidenceProvenance::TOPOLOGY_IMPORT;
    edge.freshness = EvidenceFreshness::FRESH;
    edge.integrity = IntegrityStatus::VERIFIED;
    edge.confidence_permille = 1000U;
    edge.conditional = conditional;
    edge.observed_sequence = EvidenceSequence::from_value(1);
    edge.evidence_source = "test";
    const Result<DependencyEdge> stored = engine.register_dependency(edge);
    FCF_REQUIRE_MSG(stored.ok(), stored.ok() ? "" : stored.error().to_string());
}

inline FaultId publish_fault(Engine& engine, std::uint64_t id, FaultKind kind, std::uint64_t subject,
                             const std::string& details = {}, std::uint64_t sequence = 1) {
    FaultEvidence evidence;
    evidence.id = FaultId::from_value(id);
    evidence.kind = kind;
    evidence.subject = ResourceId::from_value(subject);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = engine.epoch();
    evidence.provenance = EvidenceProvenance::OPERATOR;
    evidence.observation_sequence = EvidenceSequence::from_value(sequence);
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    evidence.confidence_permille = 1000U;
    evidence.details = details;
    const Result<FaultRecord> stored = engine.publish_fault(evidence);
    FCF_REQUIRE_MSG(stored.ok(), stored.ok() ? "" : stored.error().to_string());
    return stored.value().evidence.id;
}

inline bool contains(const IdSet<ResourceId>& set, std::uint64_t id) {
    return id_set_contains(set, ResourceId::from_value(id));
}

inline std::vector<BlastRadius> evaluate_all(Engine& engine) {
    std::vector<BlastRadius> out;
    const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
    for (const auto& entry : snapshot->faults) {
        const Result<BlastRadius> radius =
            engine.evaluate_containment(entry.first, entry.second.evidence.generation);
        FCF_REQUIRE_MSG(radius.ok(), radius.ok() ? "" : radius.error().to_string());
        out.push_back(radius.value());
    }
    return out;
}

}  // namespace fcf::test

#endif  // FCF_TESTS_SUPPORT_HPP
