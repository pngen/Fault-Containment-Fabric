// Fault Containment Fabric — domain model, topology and authority proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/engine.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

DependencyEdge make_edge(std::uint64_t id, std::uint64_t source, std::uint64_t destination,
                         DependencyKind kind, bool conditional = false) {
    DependencyEdge edge;
    edge.id = DependencyId::from_value(id);
    edge.source = ResourceId::from_value(source);
    edge.destination = ResourceId::from_value(destination);
    edge.kind = kind;
    edge.conditional = conditional;
    edge.provenance = EvidenceProvenance::TOPOLOGY_IMPORT;
    edge.freshness = EvidenceFreshness::FRESH;
    edge.integrity = IntegrityStatus::VERIFIED;
    edge.confidence_permille = 1000U;
    edge.evidence_source = "test";
    return edge;
}

void build_two_isolation_domains(Engine& engine) {
    FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(101, "iso", {1, 2})).ok());
    add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0, 101,
                                      0, 0, 0});
    add_resource(engine, ResourceSpec{2, "r2", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0, 101,
                                      0, 0, 0});
}

}  // namespace

FCF_TEST(domain_model, registration_advances_the_topology_generation) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    const TopologyGeneration start = engine.query_system_status().topology_generation;
    FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(101, "iso", {1})).ok());
    add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0, 101,
                                      0, 0, 0});
    FCF_REQUIRE(engine.query_system_status().topology_generation > start);
}

FCF_TEST(domain_model, duplicate_identities_are_rejected) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(101, "iso", {1})).ok());
    const Result<IsolationDomain> duplicate =
        engine.register_isolation_domain(make_isolation_domain(101, "iso", {1}));
    FCF_REQUIRE(!duplicate.ok());
    FCF_EQ(duplicate.error().code(), ErrorCode::DUPLICATE_ID);

    add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0, 101,
                                      0, 0, 0});
    ResourceRecord again;
    again.id = ResourceId::from_value(1);
    again.isolation_domain = IsolationDomainId::from_value(101);
    const Result<ResourceRecord> rejected = engine.register_resource(again);
    FCF_REQUIRE(!rejected.ok());
    FCF_EQ(rejected.error().code(), ErrorCode::DUPLICATE_ID);
}

FCF_TEST(domain_model, impossible_graph_references_are_rejected) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    ResourceRecord record;
    record.id = ResourceId::from_value(1);
    record.isolation_domain = IsolationDomainId::from_value(999);
    const Result<ResourceRecord> rejected = engine.register_resource(record);
    FCF_REQUIRE(!rejected.ok());
    FCF_EQ(rejected.error().code(), ErrorCode::INVALID_DOMAIN_GRAPH);

    // A boundary may be declared before its members exist, but membership mutation
    // of an existing domain must resolve every member.
    const Result<ContainmentDomain> declared = engine.register_domain(make_domain(301, "cd", false, {}));
    FCF_REQUIRE(declared.ok());
    const Status bad_update =
        engine.update_domain(make_domain(301, "cd", false, {77}), declared.value().generation);
    FCF_REQUIRE(!bad_update.ok());
    FCF_EQ(bad_update.error().code(), ErrorCode::INVALID_DOMAIN_GRAPH);
}

FCF_TEST(domain_model, self_dependencies_and_missing_endpoints_are_rejected) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build_two_isolation_domains(engine);

    const Result<DependencyEdge> self =
        engine.register_dependency(make_edge(401, 1, 1, DependencyKind::EXECUTION_DEPENDS_ON));
    FCF_REQUIRE(!self.ok());
    FCF_EQ(self.error().code(), ErrorCode::INVALID_DEPENDENCY);

    const Result<DependencyEdge> dangling =
        engine.register_dependency(make_edge(402, 1, 99, DependencyKind::EXECUTION_DEPENDS_ON));
    FCF_REQUIRE(!dangling.ok());
    FCF_EQ(dangling.error().code(), ErrorCode::INVALID_DEPENDENCY);

    FCF_REQUIRE(engine.register_dependency(make_edge(403, 1, 2, DependencyKind::SERVICE_DEPENDS_ON)).ok());
    const Result<DependencyEdge> duplicate =
        engine.register_dependency(make_edge(403, 2, 1, DependencyKind::SERVICE_DEPENDS_ON));
    FCF_REQUIRE(!duplicate.ok());
    FCF_EQ(duplicate.error().code(), ErrorCode::DUPLICATE_ID);

    DependencyEdge bad_confidence = make_edge(404, 2, 1, DependencyKind::SERVICE_DEPENDS_ON);
    bad_confidence.confidence_permille = 1001U;
    const Result<DependencyEdge> rejected = engine.register_dependency(bad_confidence);
    FCF_REQUIRE(!rejected.ok());
    FCF_EQ(rejected.error().code(), ErrorCode::INVALID_ARGUMENT);
}

FCF_TEST(domain_model, stale_resource_updates_are_refused) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build_two_isolation_domains(engine);
    const Result<ResourceStatusView> first = engine.query_resource_status(ResourceId::from_value(1));
    FCF_REQUIRE(first.ok());
    const ResourceGeneration generation = first.value().resource.generation;

    const Result<ResourceRecord> updated = engine.publish_resource_evidence(
        ResourceId::from_value(1), generation, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(2), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(updated.ok());

    const Result<ResourceRecord> stale = engine.publish_resource_evidence(
        ResourceId::from_value(1), generation, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(3), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(!stale.ok());
    FCF_EQ(stale.error().code(), ErrorCode::STALE_RESOURCE_GENERATION);
}

FCF_TEST(domain_model, stale_evidence_sequence_is_refused) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build_two_isolation_domains(engine);
    FCF_REQUIRE(engine
                    .publish_resource_evidence(ResourceId::from_value(1), ResourceGeneration{},
                                               EvidenceFreshness::FRESH, EvidenceSequence::from_value(9),
                                               ContainmentMechanism::NONE, "test")
                    .ok());
    const Result<ResourceRecord> older = engine.publish_resource_evidence(
        ResourceId::from_value(1), ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(4), ContainmentMechanism::NONE, "test");
    FCF_REQUIRE(!older.ok());
    FCF_EQ(older.error().code(), ErrorCode::STALE_EVIDENCE);
}

FCF_TEST(domain_model, worker_reincarnation_revokes_the_previous_incarnation) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build_two_isolation_domains(engine);
    const Result<WorkerRecord> first = engine.register_worker(
        WorkerId::from_value(1), WorkerBootId::from_value(11), "endpoint", EvidenceSequence::from_value(1));
    FCF_REQUIRE(first.ok());
    FCF_EQ(first.value().incarnation.value(), 1U);

    add_resource(engine, ResourceSpec{5, "owned", ResourceClass::WORKER, ProtectionClass::STANDARD, 0, 101,
                                      0, 1, 11});
    const Result<WorkerRecord> second = engine.register_worker(
        WorkerId::from_value(1), WorkerBootId::from_value(12), "endpoint", EvidenceSequence::from_value(2));
    FCF_REQUIRE(second.ok());
    FCF_EQ(second.value().incarnation.value(), 2U);

    const Result<WorkerRecord> old_boot =
        engine.query_worker(WorkerId::from_value(1), WorkerBootId::from_value(11));
    FCF_REQUIRE(old_boot.ok());
    FCF_EQ(old_boot.value().state, WorkerState::AUTHORITY_REVOKED);
    FCF_REQUIRE(!holds_live_authority(old_boot.value().state));

    // Re-registering the same boot with conflicting details is a conflict, not a reset.
    const Result<WorkerRecord> conflicting = engine.register_worker(
        WorkerId::from_value(1), WorkerBootId::from_value(12), "other", EvidenceSequence::from_value(3));
    FCF_REQUIRE(!conflicting.ok());
    FCF_EQ(conflicting.error().code(), ErrorCode::DUPLICATE_CONFLICT);
}

FCF_TEST(domain_model, retired_worker_holds_no_live_authority) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build_two_isolation_domains(engine);
    FCF_REQUIRE(engine
                    .register_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "e",
                                     EvidenceSequence::from_value(1))
                    .ok());
    FCF_REQUIRE(engine.retire_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "ordered")
                    .ok());
    const Result<WorkerRecord> record =
        engine.query_worker(WorkerId::from_value(1), WorkerBootId::from_value(11));
    FCF_REQUIRE(record.ok());
    FCF_EQ(record.value().state, WorkerState::RETIRED);
    // Retirement is idempotent.
    FCF_REQUIRE(engine.retire_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "again").ok());
}

FCF_TEST(domain_model, policy_validation_rejects_incoherent_rules) {
    ContainmentPolicy policy = make_default_policy();
    FCF_REQUIRE(validate_policy(policy).ok());

    policy.rules[FaultKind::PROCESS_DEATH].mandatory_containment = true;
    policy.rules[FaultKind::PROCESS_DEATH].uncertainty = UncertaintyBehavior::OBSERVE_ONLY;
    FCF_REQUIRE(!validate_policy(policy).ok());

    ContainmentPolicy second = make_default_policy();
    second.rules[FaultKind::DEVICE_FAILURE].non_propagating_kinds.push_back(
        DependencyKind::STATE_OWNED_BY);
    FCF_REQUIRE(!validate_policy(second).ok());

    ContainmentPolicy third = make_default_policy();
    third.max_actions_per_containment = 0U;
    FCF_REQUIRE(!validate_policy(third).ok());
}

FCF_TEST(domain_model, policy_update_advances_the_policy_generation) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    const PolicyGeneration before = engine.policy().generation;
    ContainmentPolicy policy = make_default_policy();
    FCF_REQUIRE(engine.set_policy(policy).ok());
    FCF_REQUIRE(engine.query_system_status().policy_generation > before);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
