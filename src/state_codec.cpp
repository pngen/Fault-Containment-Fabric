// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "state_codec.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

namespace fcf::detail {
namespace {

constexpr std::uint32_t kMaxMembersPerRecord = 1000000U;
constexpr std::uint32_t kMaxRules = 4096U;
constexpr std::uint32_t kMaxEnvelopeTargets = 100000U;

template <class E>
void wr_enum(ByteWriter& writer, E value) {
    writer.u16(static_cast<std::uint16_t>(value));
}

template <class E>
E rd_enum_checked(ByteReader& reader, std::uint16_t max_value) {
    const std::uint16_t raw = reader.u16();
    if (!reader.ok()) {
        return static_cast<E>(0);
    }
    if (raw > max_value) {
        reader.reject();
        return static_cast<E>(0);
    }
    return static_cast<E>(raw);
}

template <class E>
void wr_enum_set(ByteWriter& writer, const EnumSet<E>& set) {
    writer.u32(static_cast<std::uint32_t>(set.size()));
    for (const E value : set) {
        writer.u16(static_cast<std::uint16_t>(value));
    }
}

template <class E>
[[nodiscard]] EnumSet<E> rd_enum_set(ByteReader& reader, std::uint32_t ceiling, std::uint16_t max_value) {
    EnumSet<E> out;
    const std::uint32_t count = reader.count(ceiling);
    if (count == 0U) {
        return out;
    }
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint16_t raw = reader.u16();
        if (!reader.ok()) {
            return {};
        }
        if (raw > max_value) {
            reader.reject();
            return {};
        }
        const E value = static_cast<E>(raw);
        if (!out.empty() && static_cast<std::uint16_t>(out.back()) >= raw) {
            reader.reject();
            return {};
        }
        out.push_back(value);
    }
    return out;
}

}  // namespace

std::uint16_t rd_enum(ByteReader& reader, std::uint16_t max_value) noexcept {
    const std::uint16_t raw = reader.u16();
    if (!reader.ok()) {
        return 0;
    }
    if (raw > max_value) {
        reader.reject();
        return 0;
    }
    return raw;
}

bool rd_bool(ByteReader& reader) noexcept {
    const std::uint8_t raw = reader.u8();
    if (!reader.ok()) {
        return false;
    }
    if (raw > 1U) {
        reader.reject();
        return false;
    }
    return raw == 1U;
}

// --- Resources -------------------------------------------------------------------------

void write_resource(ByteWriter& writer, const ResourceRecord& record) {
    wr_id(writer, record.id);
    wr_id(writer, record.generation);
    writer.str(record.name);
    wr_enum(writer, record.resource_class);
    wr_enum(writer, record.protection);
    wr_enum(writer, record.state);
    wr_id(writer, record.containment_domain);
    wr_id(writer, record.isolation_domain);
    wr_id(writer, record.failure_domain);
    wr_id(writer, record.owner_worker);
    wr_id(writer, record.owner_boot);
    wr_id(writer, record.node);
    wr_id(writer, record.host);
    wr_id(writer, record.device);
    wr_id(writer, record.accelerator);
    wr_id(writer, record.service);
    wr_id(writer, record.workload);
    wr_id(writer, record.execution);
    wr_id(writer, record.attempt);
    wr_id(writer, record.reservation);
    wr_id(writer, record.lease);
    wr_enum(writer, record.freshness);
    wr_id(writer, record.evidence_sequence);
    writer.u64(record.updated_at_ms);
    writer.boolean(record.quarantined);
    wr_enum(writer, record.mechanism);
    wr_id(writer, record.containment_generation);
    wr_id(writer, record.release_generation);
}

bool read_resource(ByteReader& reader, ResourceRecord& record) {
    record = ResourceRecord{};
    record.id = rd_id<ResourceId>(reader);
    record.generation = rd_id<ResourceGeneration>(reader);
    record.name = reader.str();
    record.resource_class = rd_enum_checked<ResourceClass>(reader, kResourceClassMax);
    record.protection = rd_enum_checked<ProtectionClass>(reader, kProtectionClassMax);
    record.state = rd_enum_checked<ResourceOperationalState>(reader, kResourceOperationalStateMax);
    record.containment_domain = rd_id<ContainmentDomainId>(reader);
    record.isolation_domain = rd_id<IsolationDomainId>(reader);
    record.failure_domain = rd_id<FailureDomainId>(reader);
    record.owner_worker = rd_id<WorkerId>(reader);
    record.owner_boot = rd_id<WorkerBootId>(reader);
    record.node = rd_id<NodeId>(reader);
    record.host = rd_id<HostId>(reader);
    record.device = rd_id<DeviceId>(reader);
    record.accelerator = rd_id<AcceleratorId>(reader);
    record.service = rd_id<ServiceId>(reader);
    record.workload = rd_id<WorkloadId>(reader);
    record.execution = rd_id<ExecutionId>(reader);
    record.attempt = rd_id<AttemptId>(reader);
    record.reservation = rd_id<ReservationId>(reader);
    record.lease = rd_id<LeaseId>(reader);
    record.freshness = rd_enum_checked<EvidenceFreshness>(reader, kEvidenceFreshnessMax);
    record.evidence_sequence = rd_id<EvidenceSequence>(reader);
    record.updated_at_ms = reader.u64();
    record.quarantined = rd_bool(reader);
    record.mechanism = rd_enum_checked<ContainmentMechanism>(reader, kContainmentMechanismMax);
    record.containment_generation = rd_id<ContainmentGeneration>(reader);
    record.release_generation = rd_id<ReleaseGeneration>(reader);
    if (!reader.ok() || !record.id.valid()) {
        return false;
    }
    return true;
}

// --- Domains ---------------------------------------------------------------------------

void write_containment_domain(ByteWriter& writer, const ContainmentDomain& domain) {
    wr_id(writer, domain.id);
    wr_id(writer, domain.generation);
    writer.str(domain.name);
    wr_ids(writer, domain.members);
    wr_enum(writer, domain.protection);
    writer.boolean(domain.co_isolate_members);
}

bool read_containment_domain(ByteReader& reader, ContainmentDomain& domain) {
    domain = ContainmentDomain{};
    domain.id = rd_id<ContainmentDomainId>(reader);
    domain.generation = rd_id<TopologyGeneration>(reader);
    domain.name = reader.str();
    domain.members = rd_ids<ResourceId>(reader, kMaxMembersPerRecord);
    domain.protection = rd_enum_checked<ProtectionClass>(reader, kProtectionClassMax);
    domain.co_isolate_members = rd_bool(reader);
    return reader.ok() && domain.id.valid();
}

void write_isolation_domain(ByteWriter& writer, const IsolationDomain& domain) {
    wr_id(writer, domain.id);
    wr_id(writer, domain.generation);
    writer.str(domain.name);
    wr_ids(writer, domain.members);
    wr_enum_set(writer, domain.classes);
    wr_enum(writer, domain.mechanism);
}

bool read_isolation_domain(ByteReader& reader, IsolationDomain& domain) {
    domain = IsolationDomain{};
    domain.id = rd_id<IsolationDomainId>(reader);
    domain.generation = rd_id<TopologyGeneration>(reader);
    domain.name = reader.str();
    domain.members = rd_ids<ResourceId>(reader, kMaxMembersPerRecord);
    domain.classes = rd_enum_set<IsolationClass>(reader, kIsolationClassMax + 1U, kIsolationClassMax);
    domain.mechanism = rd_enum_checked<ContainmentMechanism>(reader, kContainmentMechanismMax);
    return reader.ok() && domain.id.valid();
}

void write_failure_domain(ByteWriter& writer, const FailureDomain& domain) {
    wr_id(writer, domain.id);
    wr_id(writer, domain.generation);
    writer.str(domain.name);
    wr_enum(writer, domain.kind);
    wr_ids(writer, domain.members);
    wr_enum(writer, domain.provenance);
    wr_enum(writer, domain.freshness);
}

bool read_failure_domain(ByteReader& reader, FailureDomain& domain) {
    domain = FailureDomain{};
    domain.id = rd_id<FailureDomainId>(reader);
    domain.generation = rd_id<TopologyGeneration>(reader);
    domain.name = reader.str();
    domain.kind = rd_enum_checked<FailureDomainKind>(reader, kFailureDomainKindMax);
    domain.members = rd_ids<ResourceId>(reader, kMaxMembersPerRecord);
    domain.provenance = rd_enum_checked<EvidenceProvenance>(reader, kEvidenceProvenanceMax);
    domain.freshness = rd_enum_checked<EvidenceFreshness>(reader, kEvidenceFreshnessMax);
    return reader.ok() && domain.id.valid();
}

// --- Dependencies ----------------------------------------------------------------------

void write_dependency(ByteWriter& writer, const DependencyEdge& edge) {
    wr_id(writer, edge.id);
    wr_id(writer, edge.generation);
    wr_id(writer, edge.source);
    wr_id(writer, edge.destination);
    wr_enum(writer, edge.kind);
    wr_enum(writer, edge.provenance);
    wr_enum(writer, edge.freshness);
    wr_enum(writer, edge.integrity);
    writer.u16(edge.confidence_permille);
    writer.boolean(edge.conditional);
    wr_id(writer, edge.observed_sequence);
    writer.str(edge.evidence_source);
}

bool read_dependency(ByteReader& reader, DependencyEdge& edge) {
    edge = DependencyEdge{};
    edge.id = rd_id<DependencyId>(reader);
    edge.generation = rd_id<DependencyGeneration>(reader);
    edge.source = rd_id<ResourceId>(reader);
    edge.destination = rd_id<ResourceId>(reader);
    edge.kind = rd_enum_checked<DependencyKind>(reader, kDependencyKindMax);
    edge.provenance = rd_enum_checked<EvidenceProvenance>(reader, kEvidenceProvenanceMax);
    edge.freshness = rd_enum_checked<EvidenceFreshness>(reader, kEvidenceFreshnessMax);
    edge.integrity = rd_enum_checked<IntegrityStatus>(reader, kIntegrityStatusMax);
    edge.confidence_permille = reader.u16();
    edge.conditional = rd_bool(reader);
    edge.observed_sequence = rd_id<EvidenceSequence>(reader);
    edge.evidence_source = reader.str();
    if (!reader.ok()) {
        return false;
    }
    if (edge.confidence_permille > 1000U) {
        reader.reject();
        return false;
    }
    return edge.id.valid() && edge.source.valid() && edge.destination.valid();
}

// --- Topology --------------------------------------------------------------------------

void write_topology(ByteWriter& writer, const Topology& topology) {
    wr_id(writer, topology.generation);
    writer.u32(static_cast<std::uint32_t>(topology.resources.size()));
    for (const auto& entry : topology.resources) {
        write_resource(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(topology.containment_domains.size()));
    for (const auto& entry : topology.containment_domains) {
        write_containment_domain(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(topology.isolation_domains.size()));
    for (const auto& entry : topology.isolation_domains) {
        write_isolation_domain(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(topology.failure_domains.size()));
    for (const auto& entry : topology.failure_domains) {
        write_failure_domain(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(topology.dependencies.edges.size()));
    for (const auto& entry : topology.dependencies.edges) {
        write_dependency(writer, entry.second);
    }
}

bool read_topology(ByteReader& reader, Topology& topology) {
    topology = Topology{};
    topology.generation = rd_id<TopologyGeneration>(reader);
    const std::uint32_t resource_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < resource_count && reader.ok(); ++i) {
        ResourceRecord record;
        if (!read_resource(reader, record)) {
            return false;
        }
        if (topology.resources.find(record.id) != topology.resources.end()) {
            reader.reject();
            return false;
        }
        topology.resources.emplace(record.id, std::move(record));
    }
    const std::uint32_t containment_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < containment_count && reader.ok(); ++i) {
        ContainmentDomain domain;
        if (!read_containment_domain(reader, domain)) {
            return false;
        }
        if (topology.containment_domains.find(domain.id) != topology.containment_domains.end()) {
            reader.reject();
            return false;
        }
        topology.containment_domains.emplace(domain.id, std::move(domain));
    }
    const std::uint32_t isolation_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < isolation_count && reader.ok(); ++i) {
        IsolationDomain domain;
        if (!read_isolation_domain(reader, domain)) {
            return false;
        }
        if (topology.isolation_domains.find(domain.id) != topology.isolation_domains.end()) {
            reader.reject();
            return false;
        }
        topology.isolation_domains.emplace(domain.id, std::move(domain));
    }
    const std::uint32_t failure_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < failure_count && reader.ok(); ++i) {
        FailureDomain domain;
        if (!read_failure_domain(reader, domain)) {
            return false;
        }
        if (topology.failure_domains.find(domain.id) != topology.failure_domains.end()) {
            reader.reject();
            return false;
        }
        topology.failure_domains.emplace(domain.id, std::move(domain));
    }
    const std::uint32_t dependency_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < dependency_count && reader.ok(); ++i) {
        DependencyEdge edge;
        if (!read_dependency(reader, edge)) {
            return false;
        }
        if (topology.dependencies.edges.find(edge.id) != topology.dependencies.edges.end()) {
            reader.reject();
            return false;
        }
        topology.dependencies.insert(edge);
    }
    if (!reader.ok()) {
        return false;
    }
    // Durable topology must be completely resolvable: a persisted domain or
    // dependency that references a missing resource is corruption, not a
    // forward declaration.
    auto member_ok = [&topology](const IdSet<ResourceId>& members) {
        for (const ResourceId member : members) {
            if (topology.resources.find(member) == topology.resources.end()) {
                return false;
            }
        }
        return true;
    };
    for (const auto& entry : topology.containment_domains) {
        if (!member_ok(entry.second.members)) {
            reader.reject();
            return false;
        }
    }
    for (const auto& entry : topology.isolation_domains) {
        if (!member_ok(entry.second.members)) {
            reader.reject();
            return false;
        }
    }
    for (const auto& entry : topology.failure_domains) {
        if (!member_ok(entry.second.members)) {
            reader.reject();
            return false;
        }
    }
    for (const auto& entry : topology.dependencies.edges) {
        if (topology.resources.find(entry.second.source) == topology.resources.end() ||
            topology.resources.find(entry.second.destination) == topology.resources.end()) {
            reader.reject();
            return false;
        }
    }
    for (const auto& entry : topology.resources) {
        const ResourceRecord& record = entry.second;
        if (record.containment_domain.valid() &&
            topology.containment_domains.find(record.containment_domain) ==
                topology.containment_domains.end()) {
            reader.reject();
            return false;
        }
        if (record.isolation_domain.valid() &&
            topology.isolation_domains.find(record.isolation_domain) ==
                topology.isolation_domains.end()) {
            reader.reject();
            return false;
        }
        if (record.failure_domain.valid() &&
            topology.failure_domains.find(record.failure_domain) == topology.failure_domains.end()) {
            reader.reject();
            return false;
        }
    }
    return true;
}

// --- Faults ----------------------------------------------------------------------------

void write_fault_evidence(ByteWriter& writer, const FaultEvidence& evidence) {
    wr_id(writer, evidence.id);
    wr_id(writer, evidence.generation);
    wr_enum(writer, evidence.kind);
    wr_id(writer, evidence.subject);
    wr_id(writer, evidence.subject_generation);
    wr_enum(writer, evidence.reporter_kind);
    wr_id(writer, evidence.reporter_worker);
    wr_id(writer, evidence.reporter_boot);
    wr_id(writer, evidence.epoch);
    wr_enum(writer, evidence.provenance);
    wr_id(writer, evidence.observation_sequence);
    writer.u64(evidence.publication_time_ms);
    wr_enum(writer, evidence.freshness);
    wr_enum(writer, evidence.integrity);
    writer.u16(evidence.confidence_permille);
    writer.str(evidence.details);
    writer.raw(evidence.digest.data(), evidence.digest.size());
}

bool read_fault_evidence(ByteReader& reader, FaultEvidence& evidence) {
    evidence = FaultEvidence{};
    evidence.id = rd_id<FaultId>(reader);
    evidence.generation = rd_id<FaultGeneration>(reader);
    evidence.kind = rd_enum_checked<FaultKind>(reader, kFaultKindMax);
    evidence.subject = rd_id<ResourceId>(reader);
    evidence.subject_generation = rd_id<ResourceGeneration>(reader);
    evidence.reporter_kind = rd_enum_checked<ReporterKind>(reader, kReporterKindMax);
    evidence.reporter_worker = rd_id<WorkerId>(reader);
    evidence.reporter_boot = rd_id<WorkerBootId>(reader);
    evidence.epoch = rd_id<CoordinatorEpoch>(reader);
    evidence.provenance = rd_enum_checked<EvidenceProvenance>(reader, kEvidenceProvenanceMax);
    evidence.observation_sequence = rd_id<EvidenceSequence>(reader);
    evidence.publication_time_ms = reader.u64();
    evidence.freshness = rd_enum_checked<EvidenceFreshness>(reader, kEvidenceFreshnessMax);
    evidence.integrity = rd_enum_checked<IntegrityStatus>(reader, kIntegrityStatusMax);
    evidence.confidence_permille = reader.u16();
    evidence.details = reader.str();
    const auto digest = reader.raw(evidence.digest.size());
    if (!reader.ok() || digest.size() != evidence.digest.size()) {
        return false;
    }
    for (std::size_t i = 0; i < evidence.digest.size(); ++i) {
        evidence.digest[i] = std::to_integer<std::uint8_t>(digest[i]);
    }
    if (evidence.confidence_permille > 1000U) {
        reader.reject();
        return false;
    }
    return evidence.id.valid();
}

void write_fault(ByteWriter& writer, const FaultRecord& fault) {
    write_fault_evidence(writer, fault.evidence);
    wr_enum(writer, fault.state);
    wr_enum(writer, fault.severity);
    wr_id(writer, fault.containment_generation);
    writer.u64(fault.first_seen_ms);
    writer.u64(fault.last_updated_ms);
    writer.boolean(fault.actionable);
    writer.u32(fault.duplicate_count);
    wr_id(writer, fault.verification_generation);
    writer.str(fault.details);
}

bool read_fault(ByteReader& reader, FaultRecord& fault) {
    fault = FaultRecord{};
    if (!read_fault_evidence(reader, fault.evidence)) {
        return false;
    }
    fault.state = rd_enum_checked<FaultState>(reader, kFaultStateMax);
    fault.severity = rd_enum_checked<FaultSeverity>(reader, kFaultSeverityMax);
    fault.containment_generation = rd_id<ContainmentGeneration>(reader);
    fault.first_seen_ms = reader.u64();
    fault.last_updated_ms = reader.u64();
    fault.actionable = rd_bool(reader);
    fault.duplicate_count = reader.u32();
    fault.verification_generation = rd_id<VerificationGeneration>(reader);
    fault.details = reader.str();
    return reader.ok();
}

// --- Workers ---------------------------------------------------------------------------

void write_worker(ByteWriter& writer, const WorkerRecord& worker) {
    wr_id(writer, worker.key.worker);
    wr_id(writer, worker.key.boot);
    wr_id(writer, worker.incarnation);
    wr_id(writer, worker.registered_epoch);
    wr_enum(writer, worker.state);
    wr_id(writer, worker.last_sequence);
    wr_enum(writer, worker.freshness);
    wr_ids(writer, worker.live_authority);
    writer.u64(worker.registered_at_ms);
    writer.u64(worker.last_seen_ms);
    writer.str(worker.endpoint);
    writer.str(worker.details);
}

bool read_worker(ByteReader& reader, WorkerRecord& worker) {
    worker = WorkerRecord{};
    worker.key.worker = rd_id<WorkerId>(reader);
    worker.key.boot = rd_id<WorkerBootId>(reader);
    worker.incarnation = rd_id<WorkerIncarnation>(reader);
    worker.registered_epoch = rd_id<CoordinatorEpoch>(reader);
    worker.state = rd_enum_checked<WorkerState>(reader, kWorkerStateMax);
    worker.last_sequence = rd_id<EvidenceSequence>(reader);
    worker.freshness = rd_enum_checked<EvidenceFreshness>(reader, kEvidenceFreshnessMax);
    worker.live_authority = rd_ids<ResourceId>(reader, kMaxMembersPerRecord);
    worker.registered_at_ms = reader.u64();
    worker.last_seen_ms = reader.u64();
    worker.endpoint = reader.str();
    worker.details = reader.str();
    return reader.ok() && worker.key.worker.valid() && worker.key.boot.valid();
}

// --- Policy ----------------------------------------------------------------------------

void write_fault_rule(ByteWriter& writer, const FaultRule& rule) {
    wr_enum(writer, rule.kind);
    wr_enum(writer, rule.preferred_outcome);
    wr_enum(writer, rule.escalation_outcome);
    wr_enum(writer, rule.severity);
    writer.boolean(rule.mandatory_containment);
    wr_enum(writer, rule.uncertainty);
    wr_enum(writer, rule.propagation);
    writer.u16(rule.likely_confidence_permille);
    writer.u32(rule.max_tolerated_exposure);
    writer.boolean(rule.permit_degraded_mode);
    writer.boolean(rule.require_fresh_evidence);
    writer.u64(rule.max_evidence_age_ms);
    writer.boolean(rule.allow_release);
    writer.u32(rule.min_redundancy);
    writer.u32(rule.action_budget);
    writer.boolean(rule.isolate_failure_domain);
    writer.boolean(rule.isolate_isolation_domain);
    writer.boolean(rule.co_isolate_containment_domain);
    wr_enum(writer, rule.ranking);
    wr_enum_set(writer, rule.propagating_kinds);
    wr_enum_set(writer, rule.non_propagating_kinds);
    writer.boolean(rule.fail_closed_on_unknown_evidence);
    writer.boolean(rule.allow_protected_resource_fencing);
}

bool read_fault_rule(ByteReader& reader, FaultRule& rule) {
    rule = FaultRule{};
    rule.kind = rd_enum_checked<FaultKind>(reader, kFaultKindMax);
    rule.preferred_outcome = rd_enum_checked<ContainmentActionKind>(reader, kContainmentActionKindMax);
    rule.escalation_outcome = rd_enum_checked<ContainmentActionKind>(reader, kContainmentActionKindMax);
    rule.severity = rd_enum_checked<FaultSeverity>(reader, kFaultSeverityMax);
    rule.mandatory_containment = rd_bool(reader);
    rule.uncertainty = rd_enum_checked<UncertaintyBehavior>(reader, kUncertaintyBehaviorMax);
    rule.propagation = rd_enum_checked<PropagationMode>(reader, kPropagationModeMax);
    rule.likely_confidence_permille = reader.u16();
    rule.max_tolerated_exposure = reader.u32();
    rule.permit_degraded_mode = rd_bool(reader);
    rule.require_fresh_evidence = rd_bool(reader);
    rule.max_evidence_age_ms = reader.u64();
    rule.allow_release = rd_bool(reader);
    rule.min_redundancy = reader.u32();
    rule.action_budget = reader.u32();
    rule.isolate_failure_domain = rd_bool(reader);
    rule.isolate_isolation_domain = rd_bool(reader);
    rule.co_isolate_containment_domain = rd_bool(reader);
    rule.ranking = rd_enum_checked<RankingPreference>(reader, kRankingPreferenceMax);
    rule.propagating_kinds = rd_enum_set<DependencyKind>(reader, kDependencyKindMax + 1U, kDependencyKindMax);
    rule.non_propagating_kinds =
        rd_enum_set<DependencyKind>(reader, kDependencyKindMax + 1U, kDependencyKindMax);
    rule.fail_closed_on_unknown_evidence = rd_bool(reader);
    rule.allow_protected_resource_fencing = rd_bool(reader);
    if (!reader.ok()) {
        return false;
    }
    if (rule.likely_confidence_permille > 1000U || rule.min_redundancy == 0U || rule.action_budget == 0U) {
        reader.reject();
        return false;
    }
    return true;
}

void write_policy(ByteWriter& writer, const ContainmentPolicy& policy) {
    wr_id(writer, policy.generation);
    writer.str(policy.name);
    writer.u32(static_cast<std::uint32_t>(policy.rules.size()));
    for (const auto& entry : policy.rules) {
        write_fault_rule(writer, entry.second);
    }
    write_fault_rule(writer, policy.fallback);
    writer.u32(policy.max_actions_per_containment);
    writer.boolean(policy.allow_degraded_mode_by_default);
    writer.u64(policy.default_max_evidence_age_ms);

    const AdministrativeOverride& admin = policy.admin_override;
    writer.boolean(admin.active);
    writer.str(admin.authority);
    wr_id(writer, admin.policy_generation);
    writer.u64(admin.not_before_ms);
    writer.u64(admin.expires_at_ms);
    wr_enum(writer, admin.forced_outcome);
    wr_ids(writer, admin.scope);
    writer.boolean(admin.ranking_and_authority_only);
}

bool read_policy(ByteReader& reader, ContainmentPolicy& policy) {
    policy = ContainmentPolicy{};
    policy.generation = rd_id<PolicyGeneration>(reader);
    policy.name = reader.str();
    const std::uint32_t rule_count = reader.count(kMaxRules);
    for (std::uint32_t i = 0; i < rule_count && reader.ok(); ++i) {
        FaultRule rule;
        if (!read_fault_rule(reader, rule)) {
            return false;
        }
        if (policy.rules.find(rule.kind) != policy.rules.end()) {
            reader.reject();
            return false;
        }
        policy.rules.emplace(rule.kind, rule);
    }
    if (!read_fault_rule(reader, policy.fallback)) {
        return false;
    }
    policy.max_actions_per_containment = reader.u32();
    policy.allow_degraded_mode_by_default = rd_bool(reader);
    policy.default_max_evidence_age_ms = reader.u64();

    AdministrativeOverride& admin = policy.admin_override;
    admin.active = rd_bool(reader);
    admin.authority = reader.str();
    admin.policy_generation = rd_id<PolicyGeneration>(reader);
    admin.not_before_ms = reader.u64();
    admin.expires_at_ms = reader.u64();
    admin.forced_outcome = rd_enum_checked<ContainmentActionKind>(reader, kContainmentActionKindMax);
    admin.scope = rd_ids<ResourceId>(reader, kMaxMembersPerRecord);
    admin.ranking_and_authority_only = rd_bool(reader);
    if (!reader.ok()) {
        return false;
    }
    if (policy.max_actions_per_containment == 0U) {
        reader.reject();
        return false;
    }
    return true;
}

// --- Actions ---------------------------------------------------------------------------

void write_authority_envelope(ByteWriter& writer, const AuthorityEnvelope& envelope) {
    wr_id(writer, envelope.epoch);
    wr_id(writer, envelope.fault);
    wr_id(writer, envelope.fault_generation);
    wr_id(writer, envelope.containment_generation);
    wr_id(writer, envelope.policy_generation);
    wr_id(writer, envelope.topology_generation);
    wr_id(writer, envelope.action);
    wr_id(writer, envelope.action_generation);
    wr_id(writer, envelope.worker);
    wr_id(writer, envelope.worker_boot);
    wr_id(writer, envelope.target);
    wr_id(writer, envelope.target_generation);
    wr_id(writer, envelope.required_evidence_sequence);
    wr_id(writer, envelope.reservation);
    wr_id(writer, envelope.lease);
    writer.u32(static_cast<std::uint32_t>(envelope.required_resource_generations.size()));
    for (const auto& entry : envelope.required_resource_generations) {
        wr_id(writer, entry.first);
        wr_id(writer, entry.second);
    }
    writer.u64(envelope.issued_at_ms);
}

bool read_authority_envelope(ByteReader& reader, AuthorityEnvelope& envelope) {
    envelope = AuthorityEnvelope{};
    envelope.epoch = rd_id<CoordinatorEpoch>(reader);
    envelope.fault = rd_id<FaultId>(reader);
    envelope.fault_generation = rd_id<FaultGeneration>(reader);
    envelope.containment_generation = rd_id<ContainmentGeneration>(reader);
    envelope.policy_generation = rd_id<PolicyGeneration>(reader);
    envelope.topology_generation = rd_id<TopologyGeneration>(reader);
    envelope.action = rd_id<ActionId>(reader);
    envelope.action_generation = rd_id<ActionGeneration>(reader);
    envelope.worker = rd_id<WorkerId>(reader);
    envelope.worker_boot = rd_id<WorkerBootId>(reader);
    envelope.target = rd_id<ResourceId>(reader);
    envelope.target_generation = rd_id<ResourceGeneration>(reader);
    envelope.required_evidence_sequence = rd_id<EvidenceSequence>(reader);
    envelope.reservation = rd_id<ReservationId>(reader);
    envelope.lease = rd_id<LeaseId>(reader);
    const std::uint32_t count = reader.count(kMaxEnvelopeTargets);
    for (std::uint32_t i = 0; i < count && reader.ok(); ++i) {
        const ResourceId resource = rd_id<ResourceId>(reader);
        const ResourceGeneration generation = rd_id<ResourceGeneration>(reader);
        if (!reader.ok() || !resource.valid()) {
            return false;
        }
        if (envelope.required_resource_generations.find(resource) !=
            envelope.required_resource_generations.end()) {
            reader.reject();
            return false;
        }
        envelope.required_resource_generations.emplace(resource, generation);
    }
    envelope.issued_at_ms = reader.u64();
    return reader.ok();
}

void write_action(ByteWriter& writer, const ContainmentAction& action) {
    wr_id(writer, action.id);
    wr_id(writer, action.generation);
    wr_enum(writer, action.kind);
    wr_id(writer, action.target);
    wr_id(writer, action.target_generation);
    wr_id(writer, action.domain);
    wr_id(writer, action.isolation_domain);
    wr_enum(writer, action.mechanism);
    write_authority_envelope(writer, action.envelope);
    wr_enum(writer, action.status);
    wr_enum(writer, action.rejection_code);
    writer.str(action.rejection_detail);
    writer.u64(action.created_at_ms);
    writer.u64(action.dispatched_at_ms);
    writer.u64(action.acknowledged_at_ms);
    writer.u64(action.completed_at_ms);
    wr_id(writer, action.verification_generation);
    writer.str(action.executor_token);
    writer.boolean(action.destructive);
}

bool read_action(ByteReader& reader, ContainmentAction& action) {
    action = ContainmentAction{};
    action.id = rd_id<ActionId>(reader);
    action.generation = rd_id<ActionGeneration>(reader);
    action.kind = rd_enum_checked<ContainmentActionKind>(reader, kContainmentActionKindMax);
    action.target = rd_id<ResourceId>(reader);
    action.target_generation = rd_id<ResourceGeneration>(reader);
    action.domain = rd_id<ContainmentDomainId>(reader);
    action.isolation_domain = rd_id<IsolationDomainId>(reader);
    action.mechanism = rd_enum_checked<ContainmentMechanism>(reader, kContainmentMechanismMax);
    if (!read_authority_envelope(reader, action.envelope)) {
        return false;
    }
    action.status = rd_enum_checked<ActionStatus>(reader, kActionStatusMax);
    action.rejection_code = rd_enum_checked<ErrorCode>(reader, kErrorCodeMax);
    action.rejection_detail = reader.str();
    action.created_at_ms = reader.u64();
    action.dispatched_at_ms = reader.u64();
    action.acknowledged_at_ms = reader.u64();
    action.completed_at_ms = reader.u64();
    action.verification_generation = rd_id<VerificationGeneration>(reader);
    action.executor_token = reader.str();
    action.destructive = rd_bool(reader);
    return reader.ok() && action.id.valid();
}

// --- Containment -----------------------------------------------------------------------

void write_propagation_hop(ByteWriter& writer, const PropagationHop& hop) {
    wr_id(writer, hop.from);
    wr_id(writer, hop.to);
    wr_id(writer, hop.dependency);
    wr_enum(writer, hop.kind);
    wr_enum(writer, hop.outcome);
    wr_enum(writer, hop.reason);
}

bool read_propagation_hop(ByteReader& reader, PropagationHop& hop) {
    hop = PropagationHop{};
    hop.from = rd_id<ResourceId>(reader);
    hop.to = rd_id<ResourceId>(reader);
    hop.dependency = rd_id<DependencyId>(reader);
    hop.kind = rd_enum_checked<DependencyKind>(reader, kDependencyKindMax);
    hop.outcome = rd_enum_checked<PropagationOutcome>(reader, kPropagationOutcomeMax);
    hop.reason = rd_enum_checked<InclusionReason>(reader, kInclusionReasonMax);
    return reader.ok();
}

void write_explanation(ByteWriter& writer, const ContainmentExplanation& explanation) {
    writer.u32(static_cast<std::uint32_t>(explanation.lines.size()));
    for (const ExplanationLine& line : explanation.lines) {
        writer.str(line.category);
        writer.str(line.sort_key);
        writer.str(line.text);
    }
}

bool read_explanation(ByteReader& reader, ContainmentExplanation& explanation) {
    explanation = ContainmentExplanation{};
    const std::uint32_t count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < count && reader.ok(); ++i) {
        ExplanationLine line;
        line.category = reader.str();
        line.sort_key = reader.str();
        line.text = reader.str();
        if (!reader.ok()) {
            return false;
        }
        explanation.lines.push_back(std::move(line));
    }
    return reader.ok();
}

void write_containment(ByteWriter& writer, const ContainmentRecord& record) {
    wr_id(writer, record.generation);
    wr_id(writer, record.epoch);
    wr_id(writer, record.fault);
    wr_id(writer, record.fault_generation);
    wr_id(writer, record.policy_generation);
    wr_id(writer, record.topology_generation);
    wr_enum(writer, record.outcome);
    wr_enum(writer, record.status);
    wr_ids(writer, record.mandatory);
    wr_ids(writer, record.precautionary);
    wr_ids(writer, record.unaffected);
    wr_ids(writer, record.unresolved);
    wr_ids(writer, record.released);
    writer.u32(static_cast<std::uint32_t>(record.propagation.size()));
    for (const PropagationHop& hop : record.propagation) {
        write_propagation_hop(writer, hop);
    }
    wr_ids(writer, record.actions);
    wr_id(writer, record.verification_generation);
    wr_enum(writer, record.verification_outcome);
    write_verification(writer, record.verification);
    wr_id(writer, record.degraded_contract);
    wr_enum(writer, record.degraded_status);
    writer.u64(record.committed_at_ms);
    writer.u64(record.updated_at_ms);
    writer.boolean(record.verified);
    writer.boolean(record.released_flag);
    write_explanation(writer, record.explanation);
}

bool read_containment(ByteReader& reader, ContainmentRecord& record) {
    record = ContainmentRecord{};
    record.generation = rd_id<ContainmentGeneration>(reader);
    record.epoch = rd_id<CoordinatorEpoch>(reader);
    record.fault = rd_id<FaultId>(reader);
    record.fault_generation = rd_id<FaultGeneration>(reader);
    record.policy_generation = rd_id<PolicyGeneration>(reader);
    record.topology_generation = rd_id<TopologyGeneration>(reader);
    record.outcome = rd_enum_checked<ContainmentActionKind>(reader, kContainmentActionKindMax);
    record.status = rd_enum_checked<ContainmentStatus>(reader, kContainmentStatusMax);
    record.mandatory = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    record.precautionary = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    record.unaffected = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    record.unresolved = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    record.released = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    const std::uint32_t hop_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < hop_count && reader.ok(); ++i) {
        PropagationHop hop;
        if (!read_propagation_hop(reader, hop)) {
            return false;
        }
        record.propagation.push_back(hop);
    }
    record.actions = rd_ids<ActionId>(reader, kMaxCollectionCount);
    record.verification_generation = rd_id<VerificationGeneration>(reader);
    record.verification_outcome = rd_enum_checked<VerificationOutcome>(reader, kVerificationOutcomeMax);
    if (!read_verification(reader, record.verification)) {
        return false;
    }
    record.degraded_contract = rd_id<DegradedModeId>(reader);
    record.degraded_status = rd_enum_checked<DegradedModeStatus>(reader, kDegradedModeStatusMax);
    record.committed_at_ms = reader.u64();
    record.updated_at_ms = reader.u64();
    record.verified = rd_bool(reader);
    record.released_flag = rd_bool(reader);
    if (!read_explanation(reader, record.explanation)) {
        return false;
    }
    return reader.ok() && record.generation.valid();
}

// --- Degraded mode ---------------------------------------------------------------------

void write_degraded(ByteWriter& writer, const DegradedModeAssessment& assessment) {
    wr_id(writer, assessment.contract);
    wr_enum(writer, assessment.status);
    wr_ids(writer, assessment.permitted);
    wr_ids(writer, assessment.prohibited);
    wr_ids(writer, assessment.revalidation_required);
    writer.u32(assessment.available_capacity_percent);
    writer.u32(assessment.required_redundancy);
    writer.u32(assessment.available_redundancy);
    writer.u32(static_cast<std::uint32_t>(assessment.reasons.size()));
    for (const std::string& reason : assessment.reasons) {
        writer.str(reason);
    }
    wr_id(writer, assessment.topology_generation);
    wr_id(writer, assessment.epoch);
    writer.u64(assessment.assessed_at_ms);
    writer.boolean(assessment.authorized);
}

bool read_degraded(ByteReader& reader, DegradedModeAssessment& assessment) {
    assessment = DegradedModeAssessment{};
    assessment.contract = rd_id<DegradedModeId>(reader);
    assessment.status = rd_enum_checked<DegradedModeStatus>(reader, kDegradedModeStatusMax);
    assessment.permitted = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    assessment.prohibited = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    assessment.revalidation_required = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    assessment.available_capacity_percent = reader.u32();
    assessment.required_redundancy = reader.u32();
    assessment.available_redundancy = reader.u32();
    const std::uint32_t reason_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < reason_count && reader.ok(); ++i) {
        assessment.reasons.push_back(reader.str());
    }
    assessment.topology_generation = rd_id<TopologyGeneration>(reader);
    assessment.epoch = rd_id<CoordinatorEpoch>(reader);
    assessment.assessed_at_ms = reader.u64();
    assessment.authorized = rd_bool(reader);
    if (!reader.ok()) {
        return false;
    }
    if (assessment.available_capacity_percent > 100U) {
        reader.reject();
        return false;
    }
    return true;
}

void write_degraded_contract(ByteWriter& writer, const DegradedModeContract& contract) {
    wr_id(writer, contract.id);
    writer.str(contract.name);
    wr_id(writer, contract.topology_generation);
    wr_id(writer, contract.containment_generation);
    wr_ids(writer, contract.permitted_resources);
    wr_ids(writer, contract.prohibited_resources);
    writer.u32(contract.reduced_capacity_percent);
    writer.u32(contract.required_redundancy);
    writer.u32(static_cast<std::uint32_t>(contract.disabled_features.size()));
    for (const std::string& feature : contract.disabled_features) {
        writer.str(feature);
    }
    wr_enum_set(writer, contract.legal_workload_classes);
    writer.u32(static_cast<std::uint32_t>(contract.hard_safety_constraints.size()));
    for (const std::string& constraint : contract.hard_safety_constraints) {
        writer.str(constraint);
    }
    writer.u64(contract.max_evidence_age_ms);
    writer.u64(contract.expires_at_ms);
    writer.u64(contract.revalidate_every_ms);
    writer.u32(static_cast<std::uint32_t>(contract.exit_preconditions.size()));
    for (const std::string& precondition : contract.exit_preconditions) {
        writer.str(precondition);
    }
    writer.boolean(contract.permit_by_default);
}

bool read_degraded_contract(ByteReader& reader, DegradedModeContract& contract) {
    contract = DegradedModeContract{};
    contract.id = rd_id<DegradedModeId>(reader);
    contract.name = reader.str();
    contract.topology_generation = rd_id<TopologyGeneration>(reader);
    contract.containment_generation = rd_id<ContainmentGeneration>(reader);
    contract.permitted_resources = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    contract.prohibited_resources = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    contract.reduced_capacity_percent = reader.u32();
    contract.required_redundancy = reader.u32();
    const std::uint32_t feature_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < feature_count && reader.ok(); ++i) {
        contract.disabled_features.push_back(reader.str());
    }
    contract.legal_workload_classes =
        rd_enum_set<ResourceClass>(reader, kResourceClassMax + 1U, kResourceClassMax);
    const std::uint32_t constraint_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < constraint_count && reader.ok(); ++i) {
        contract.hard_safety_constraints.push_back(reader.str());
    }
    contract.max_evidence_age_ms = reader.u64();
    contract.expires_at_ms = reader.u64();
    contract.revalidate_every_ms = reader.u64();
    const std::uint32_t precondition_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < precondition_count && reader.ok(); ++i) {
        contract.exit_preconditions.push_back(reader.str());
    }
    contract.permit_by_default = rd_bool(reader);
    if (!reader.ok()) {
        return false;
    }
    if (contract.reduced_capacity_percent > 100U || contract.required_redundancy == 0U) {
        reader.reject();
        return false;
    }
    return true;
}

// --- Verification ----------------------------------------------------------------------

void write_verification(ByteWriter& writer, const ContainmentVerification& verification) {
    wr_id(writer, verification.generation);
    wr_id(writer, verification.containment_generation);
    wr_id(writer, verification.epoch);
    wr_id(writer, verification.policy_generation);
    wr_id(writer, verification.topology_generation);
    wr_enum(writer, verification.outcome);
    writer.u32(static_cast<std::uint32_t>(verification.findings.size()));
    for (const VerificationFinding& finding : verification.findings) {
        writer.str(finding.check);
        writer.boolean(finding.passed);
        writer.str(finding.detail);
    }
    wr_ids(writer, verification.proven_contained);
    wr_ids(writer, verification.unproven);
    writer.boolean(verification.blast_radius_increased);
    writer.boolean(verification.secondary_failure);
    writer.boolean(verification.propagation_blocked);
    writer.boolean(verification.propagation_continued);
    writer.boolean(verification.degraded_mode_valid);
    wr_id(writer, verification.evidence_sequence);
    writer.u64(verification.verified_at_ms);
    writer.str(verification.summary);
}

bool read_verification(ByteReader& reader, ContainmentVerification& verification) {
    verification = ContainmentVerification{};
    verification.generation = rd_id<VerificationGeneration>(reader);
    verification.containment_generation = rd_id<ContainmentGeneration>(reader);
    verification.epoch = rd_id<CoordinatorEpoch>(reader);
    verification.policy_generation = rd_id<PolicyGeneration>(reader);
    verification.topology_generation = rd_id<TopologyGeneration>(reader);
    verification.outcome = rd_enum_checked<VerificationOutcome>(reader, kVerificationOutcomeMax);
    const std::uint32_t finding_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < finding_count && reader.ok(); ++i) {
        VerificationFinding finding;
        finding.check = reader.str();
        finding.passed = rd_bool(reader);
        finding.detail = reader.str();
        if (!reader.ok()) {
            return false;
        }
        verification.findings.push_back(std::move(finding));
    }
    verification.proven_contained = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    verification.unproven = rd_ids<ResourceId>(reader, kMaxCollectionCount);
    verification.blast_radius_increased = rd_bool(reader);
    verification.secondary_failure = rd_bool(reader);
    verification.propagation_blocked = rd_bool(reader);
    verification.propagation_continued = rd_bool(reader);
    verification.degraded_mode_valid = rd_bool(reader);
    verification.evidence_sequence = rd_id<EvidenceSequence>(reader);
    verification.verified_at_ms = reader.u64();
    verification.summary = reader.str();
    return reader.ok();
}

void write_history_event(ByteWriter& writer, const HistoryEvent& event) {
    wr_id(writer, event.sequence);
    writer.u64(event.timestamp_ms);
    wr_id(writer, event.epoch);
    wr_enum(writer, event.type);
    wr_id(writer, event.resource);
    wr_id(writer, event.fault);
    wr_id(writer, event.action);
    wr_id(writer, event.containment);
    wr_id(writer, event.verification);
    writer.str(event.detail);
    writer.str(event.authority);
}

bool read_history_event(ByteReader& reader, HistoryEvent& event) {
    event = HistoryEvent{};
    event.sequence = rd_id<HistorySequence>(reader);
    event.timestamp_ms = reader.u64();
    event.epoch = rd_id<CoordinatorEpoch>(reader);
    event.type = rd_enum_checked<HistoryEventType>(reader, kHistoryEventTypeMax);
    event.resource = rd_id<ResourceId>(reader);
    event.fault = rd_id<FaultId>(reader);
    event.action = rd_id<ActionId>(reader);
    event.containment = rd_id<ContainmentGeneration>(reader);
    event.verification = rd_id<VerificationGeneration>(reader);
    event.detail = reader.str();
    event.authority = reader.str();
    return reader.ok();
}

// --- Whole-document codecs -------------------------------------------------------------

void write_state_document(ByteWriter& writer, const RuntimeSnapshot& snapshot) {
    writer.u32(1U);  // document version
    wr_id(writer, snapshot.epoch);
    wr_id(writer, snapshot.topology_generation);
    wr_id(writer, snapshot.policy_generation);
    wr_id(writer, snapshot.containment_generation);
    wr_id(writer, snapshot.verification_generation);
    wr_id(writer, snapshot.release_generation);
    wr_id(writer, snapshot.history_sequence);
    writer.u64(snapshot.now_ms);
    write_topology(writer, snapshot.topology);
    write_policy(writer, snapshot.policy);

    writer.u32(static_cast<std::uint32_t>(snapshot.faults.size()));
    for (const auto& entry : snapshot.faults) {
        write_fault(writer, entry.second);
    }

    writer.u32(static_cast<std::uint32_t>(snapshot.workers.incarnations.size()));
    for (const auto& entry : snapshot.workers.incarnations) {
        write_worker(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.workers.current_boot.size()));
    for (const auto& entry : snapshot.workers.current_boot) {
        wr_id(writer, entry.first);
        wr_id(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.workers.last_incarnation.size()));
    for (const auto& entry : snapshot.workers.last_incarnation) {
        wr_id(writer, entry.first);
        wr_id(writer, entry.second);
    }

    writer.u32(static_cast<std::uint32_t>(snapshot.containments.size()));
    for (const auto& entry : snapshot.containments) {
        write_containment(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.actions.size()));
    for (const auto& entry : snapshot.actions) {
        write_action(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.degraded_modes.size()));
    for (const auto& entry : snapshot.degraded_modes) {
        write_degraded(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.degraded_contracts.size()));
    for (const auto& entry : snapshot.degraded_contracts) {
        write_degraded_contract(writer, entry.second);
    }
    writer.u32(static_cast<std::uint32_t>(snapshot.history.size()));
    for (const HistoryEvent& event : snapshot.history) {
        write_history_event(writer, event);
    }
    writer.u64(snapshot.history_total);
}

bool read_state_document(ByteReader& reader, RuntimeSnapshot& snapshot) {
    snapshot = RuntimeSnapshot{};
    const std::uint32_t document_version = reader.u32();
    if (!reader.ok() || document_version != 1U) {
        reader.reject();
        return false;
    }
    snapshot.epoch = rd_id<CoordinatorEpoch>(reader);
    snapshot.topology_generation = rd_id<TopologyGeneration>(reader);
    snapshot.policy_generation = rd_id<PolicyGeneration>(reader);
    snapshot.containment_generation = rd_id<ContainmentGeneration>(reader);
    snapshot.verification_generation = rd_id<VerificationGeneration>(reader);
    snapshot.release_generation = rd_id<ReleaseGeneration>(reader);
    snapshot.history_sequence = rd_id<HistorySequence>(reader);
    snapshot.now_ms = reader.u64();
    if (!read_topology(reader, snapshot.topology)) {
        return false;
    }
    if (!read_policy(reader, snapshot.policy)) {
        return false;
    }

    const std::uint32_t fault_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < fault_count && reader.ok(); ++i) {
        FaultRecord fault;
        if (!read_fault(reader, fault)) {
            return false;
        }
        snapshot.faults.emplace(fault.evidence.id, std::move(fault));
    }
    const std::uint32_t worker_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < worker_count && reader.ok(); ++i) {
        WorkerRecord worker;
        if (!read_worker(reader, worker)) {
            return false;
        }
        snapshot.workers.incarnations.emplace(worker.key, std::move(worker));
    }
    const std::uint32_t boot_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < boot_count && reader.ok(); ++i) {
        const WorkerId worker = rd_id<WorkerId>(reader);
        const WorkerBootId boot = rd_id<WorkerBootId>(reader);
        if (!reader.ok()) {
            return false;
        }
        snapshot.workers.current_boot.emplace(worker, boot);
    }
    const std::uint32_t incarnation_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < incarnation_count && reader.ok(); ++i) {
        const WorkerId worker = rd_id<WorkerId>(reader);
        const WorkerIncarnation incarnation = rd_id<WorkerIncarnation>(reader);
        if (!reader.ok()) {
            return false;
        }
        snapshot.workers.last_incarnation.emplace(worker, incarnation);
    }
    const std::uint32_t containment_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < containment_count && reader.ok(); ++i) {
        ContainmentRecord record;
        if (!read_containment(reader, record)) {
            return false;
        }
        snapshot.containments.emplace(record.generation, std::move(record));
    }
    const std::uint32_t action_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < action_count && reader.ok(); ++i) {
        ContainmentAction action;
        if (!read_action(reader, action)) {
            return false;
        }
        snapshot.actions.emplace(action.id, std::move(action));
    }
    const std::uint32_t degraded_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < degraded_count && reader.ok(); ++i) {
        DegradedModeAssessment assessment;
        if (!read_degraded(reader, assessment)) {
            return false;
        }
        snapshot.degraded_modes.emplace(assessment.contract, std::move(assessment));
    }
    const std::uint32_t contract_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < contract_count && reader.ok(); ++i) {
        DegradedModeContract contract;
        if (!read_degraded_contract(reader, contract)) {
            return false;
        }
        snapshot.degraded_contracts.emplace(contract.id, std::move(contract));
    }
    const std::uint32_t history_count = reader.count(kMaxCollectionCount);
    for (std::uint32_t i = 0; i < history_count && reader.ok(); ++i) {
        HistoryEvent event;
        if (!read_history_event(reader, event)) {
            return false;
        }
        snapshot.history.push_back(std::move(event));
    }
    snapshot.history_total = reader.u64();
    if (!reader.ok()) {
        return false;
    }
    if (snapshot.history_total < snapshot.history.size()) {
        reader.reject();
        return false;
    }
    return true;
}

// --- Durable events --------------------------------------------------------------------

void write_durable_event(ByteWriter& writer, const DurableEvent& event) {
    wr_enum(writer, event.kind);
    writer.boolean(event.has_history);
    if (event.has_history) {
        write_history_event(writer, event.history);
    }
    writer.blob(event.payload);
}

bool read_durable_event(ByteReader& reader, DurableEvent& event) {
    event = DurableEvent{};
    event.kind = rd_enum_checked<DurableEventKind>(reader, kDurableEventKindMax);
    event.has_history = rd_bool(reader);
    if (event.has_history) {
        if (!read_history_event(reader, event.history)) {
            return false;
        }
    }
    const auto payload = reader.blob();
    if (!reader.ok()) {
        return false;
    }
    event.payload.assign(payload.begin(), payload.end());
    return true;
}

bool decode_durable_event(std::span<const std::byte> bytes, DurableEvent& event) {
    ByteReader reader(bytes);
    if (!read_durable_event(reader, event)) {
        return false;
    }
    return reader.ok() && reader.at_end();
}

}  // namespace fcf::detail
