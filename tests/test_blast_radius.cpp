// Fault Containment Fabric — deterministic blast-radius proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <string>
#include <vector>

#include "fcf/engine.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

/// Registers one resource in its own isolation and failure domain, so that only
/// explicit dependency edges can pull it into a blast radius.
void add_isolated_resource(Engine& engine, std::uint64_t id,
                           ResourceClass resource_class = ResourceClass::GENERIC,
                           std::uint64_t owner_worker = 0, std::uint64_t owner_boot = 0) {
    FCF_REQUIRE(engine
                    .register_isolation_domain(
                        make_isolation_domain(1000 + id, "iso-" + std::to_string(id), {id}))
                    .ok());
    FCF_REQUIRE(engine
                    .register_failure_domain(
                        make_failure_domain(2000 + id, "fd-" + std::to_string(id), {id}))
                    .ok());
    add_resource(engine, ResourceSpec{id, "r" + std::to_string(id), resource_class,
                                      ProtectionClass::STANDARD, 0, 1000 + id, 2000 + id, owner_worker,
                                      owner_boot});
}

void add_edge(Engine& engine, std::uint64_t id, std::uint64_t source, std::uint64_t destination,
              DependencyKind kind, bool conditional = false,
              EvidenceFreshness freshness = EvidenceFreshness::FRESH) {
    DependencyEdge edge;
    edge.id = DependencyId::from_value(id);
    edge.source = ResourceId::from_value(source);
    edge.destination = ResourceId::from_value(destination);
    edge.kind = kind;
    edge.conditional = conditional;
    edge.provenance = EvidenceProvenance::TOPOLOGY_IMPORT;
    edge.freshness = freshness;
    edge.integrity = freshness == EvidenceFreshness::FRESH ? IntegrityStatus::VERIFIED
                                                           : IntegrityStatus::UNVERIFIED;
    edge.confidence_permille = 1000U;
    edge.evidence_source = "test";
    const Result<DependencyEdge> stored = engine.register_dependency(edge);
    FCF_REQUIRE_MSG(stored.ok(), stored.ok() ? "" : stored.error().to_string());
}

struct Fixture {
    LogicalClock clock;
    Engine engine;
    Fixture() : engine(make_config(clock)) {}
};

}  // namespace

FCF_TEST(blast_radius, chain_propagation_includes_every_reachable_resource) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U, 3U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(fixture.engine, 402, 2, 3, DependencyKind::STATE_OWNED_BY);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 3U);
    FCF_REQUIRE(contains(radius.value().mandatory, 1));
    FCF_REQUIRE(contains(radius.value().mandatory, 2));
    FCF_REQUIRE(contains(radius.value().mandatory, 3));
    FCF_REQUIRE(radius.value().unaffected.empty());
    FCF_REQUIRE(radius.value().hard_constraints_satisfied);
}

FCF_TEST(blast_radius, disconnected_component_is_proven_unaffected) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U, 5U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 2U);
    FCF_EQ(radius.value().unaffected.size(), 1U);
    FCF_REQUIRE(contains(radius.value().unaffected, 5));
    const ClassifiedResource& classification = radius.value().classifications.at(ResourceId::from_value(5));
    FCF_EQ(classification.exclusion, ExclusionReason::NO_PROVEN_PROPAGATION_PATH);
}

FCF_TEST(blast_radius, star_and_diamond_shapes_include_all_reachable_leaves) {
    Fixture star;
    for (std::uint64_t id : {1U, 2U, 3U, 4U}) {
        add_isolated_resource(star.engine, id);
    }
    add_edge(star.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(star.engine, 402, 1, 3, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(star.engine, 403, 1, 4, DependencyKind::EXECUTION_DEPENDS_ON);
    publish_fault(star.engine, 501, FaultKind::PROCESS_DEATH, 1);
    const Result<BlastRadius> star_radius =
        star.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(star_radius.ok());
    FCF_EQ(star_radius.value().mandatory.size(), 4U);

    Fixture diamond;
    for (std::uint64_t id : {1U, 2U, 3U, 4U}) {
        add_isolated_resource(diamond.engine, id);
    }
    add_edge(diamond.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(diamond.engine, 402, 1, 3, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(diamond.engine, 403, 2, 4, DependencyKind::STATE_OWNED_BY);
    add_edge(diamond.engine, 404, 3, 4, DependencyKind::STATE_OWNED_BY);
    publish_fault(diamond.engine, 501, FaultKind::PROCESS_DEATH, 1);
    const Result<BlastRadius> diamond_radius =
        diamond.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(diamond_radius.ok());
    FCF_EQ(diamond_radius.value().mandatory.size(), 4U);
}

FCF_TEST(blast_radius, legal_cycle_terminates_and_is_deterministic) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U, 3U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(fixture.engine, 402, 2, 3, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(fixture.engine, 403, 3, 1, DependencyKind::EXECUTION_DEPENDS_ON);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> first =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    const Result<BlastRadius> second =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(first.ok() && second.ok());
    FCF_EQ(first.value().mandatory.size(), 3U);
    FCF_EQ(render_blast_radius(first.value()), render_blast_radius(second.value()));
}

FCF_TEST(blast_radius, conditional_dependency_is_precautionary_not_mandatory) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::SERVICE_DEPENDS_ON, true);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 1U);
    FCF_EQ(radius.value().precautionary.size(), 1U);
    FCF_REQUIRE(contains(radius.value().precautionary, 2));
    FCF_REQUIRE(radius.value().unaffected.empty());
}

FCF_TEST(blast_radius, non_propagating_dependency_kind_blocks_propagation) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::SHARES_FAILURE_DOMAIN_WITH);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 1U);
    FCF_EQ(radius.value().precautionary.size(), 0U);
    FCF_REQUIRE(contains(radius.value().unaffected, 2));
    FCF_EQ(radius.value().edge_outcomes.at(DependencyId::from_value(401)),
           PropagationOutcome::PROPAGATION_IMPOSSIBLE);
}

FCF_TEST(blast_radius, unknown_evidence_never_silently_becomes_safe) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON, false,
             EvidenceFreshness::STALE);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().edge_outcomes.at(DependencyId::from_value(401)),
           PropagationOutcome::PROPAGATION_UNKNOWN);
    // The default PROCESS_DEATH rule contains preemptively, so the unresolvable
    // resource is fenced rather than assumed safe.
    FCF_REQUIRE(radius.value().fail_closed_applied);
    FCF_REQUIRE(contains(radius.value().mandatory, 2));
    FCF_EQ(radius.value().classifications.at(ResourceId::from_value(2)).inclusion,
           InclusionReason::UNKNOWN_EVIDENCE_FAIL_CLOSED);
    FCF_REQUIRE(radius.value().unaffected.empty());
}

FCF_TEST(blast_radius, unknown_evidence_stays_unresolved_under_observe_only_policy) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON, false,
             EvidenceFreshness::STALE);

    ContainmentPolicy policy = make_default_policy();
    FaultRule& rule = policy.rules[FaultKind::HEALTH_DEGRADED];
    rule.mandatory_containment = false;
    rule.uncertainty = UncertaintyBehavior::OBSERVE_ONLY;
    rule.propagation = PropagationMode::HARD;
    rule.fail_closed_on_unknown_evidence = false;
    FCF_REQUIRE(fixture.engine.set_policy(policy).ok());

    publish_fault(fixture.engine, 501, FaultKind::HEALTH_DEGRADED, 1);
    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 1U);
    FCF_REQUIRE(contains(radius.value().unresolved, 2));
    FCF_REQUIRE(!radius.value().fail_closed_applied);
}

FCF_TEST(blast_radius, shared_worker_incarnation_is_fenced_with_the_failed_worker) {
    Fixture fixture;
    add_isolated_resource(fixture.engine, 1, ResourceClass::WORKER, 1, 11);
    add_isolated_resource(fixture.engine, 2, ResourceClass::EXECUTION, 1, 11);
    add_isolated_resource(fixture.engine, 3, ResourceClass::WORKER, 2, 21);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_REQUIRE(contains(radius.value().mandatory, 2));
    FCF_EQ(radius.value().classifications.at(ResourceId::from_value(2)).inclusion,
           InclusionReason::SHARED_AUTHORITY);
    // An independent incarnation with fresh evidence is not swept in.
    FCF_REQUIRE(!contains(radius.value().mandatory, 3));
    FCF_REQUIRE(contains(radius.value().unaffected, 3));
}

FCF_TEST(blast_radius, correlated_failure_domain_members_are_included) {
    Fixture fixture;
    FCF_REQUIRE(fixture.engine
                    .register_isolation_domain(make_isolation_domain(101, "iso-1", {1}))
                    .ok());
    FCF_REQUIRE(fixture.engine
                    .register_isolation_domain(make_isolation_domain(102, "iso-2", {2}))
                    .ok());
    FCF_REQUIRE(fixture.engine.register_failure_domain(make_failure_domain(201, "fd", {1, 2})).ok());
    add_resource(fixture.engine, ResourceSpec{1, "r1", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 0, 101, 201, 0, 0});
    add_resource(fixture.engine, ResourceSpec{2, "r2", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 0, 102, 201, 0, 0});
    publish_fault(fixture.engine, 501, FaultKind::DEVICE_FAILURE, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 2U);
    FCF_EQ(radius.value().classifications.at(ResourceId::from_value(2)).inclusion,
           InclusionReason::SHARED_FAILURE_DOMAIN);
}

FCF_TEST(blast_radius, inseparable_isolation_domain_is_fenced_together) {
    Fixture fixture;
    FCF_REQUIRE(fixture.engine
                    .register_isolation_domain(make_isolation_domain(101, "iso", {1, 2}))
                    .ok());
    add_resource(fixture.engine, ResourceSpec{1, "r1", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 0, 101, 0, 0, 0});
    add_resource(fixture.engine, ResourceSpec{2, "r2", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 0, 101, 0, 0, 0});
    publish_fault(fixture.engine, 501, FaultKind::MEMORY_INTEGRITY_FAILURE, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    FCF_EQ(radius.value().mandatory.size(), 2U);
    FCF_EQ(radius.value().classifications.at(ResourceId::from_value(2)).inclusion,
           InclusionReason::SHARED_ISOLATION_DOMAIN);
}

FCF_TEST(blast_radius, protected_resource_escalates_instead_of_being_fenced_silently) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U}) {
        add_isolated_resource(fixture.engine, id);
    }
    // Make resource 2 protected by re-registering the topology through a policy-free path.
    FCF_REQUIRE(fixture.engine
                    .register_isolation_domain(make_isolation_domain(3002, "iso-p", {2}))
                    .ok());
    {
        const Result<ResourceStatusView> current =
            fixture.engine.query_resource_status(ResourceId::from_value(2));
        FCF_REQUIRE(current.ok());
        ResourceRecord record = current.value().resource;
        record.protection = ProtectionClass::CRITICAL;
        const Result<ResourceRecord> updated =
            fixture.engine.update_resource(record, record.generation);
        FCF_REQUIRE_MSG(updated.ok(), updated.ok() ? "" : updated.error().to_string());
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    // Safety still wins: the protected resource stays mandatory, but the decision
    // escalates and the direct fencing actions are reported as unavailable.
    FCF_REQUIRE(contains(radius.value().mandatory, 2));
    FCF_REQUIRE(!radius.value().hard_constraints_satisfied);
    FCF_EQ(radius.value().recommended, ContainmentActionKind::ESCALATE_CONTAINMENT);
    FCF_REQUIRE(std::find(radius.value().illegal_actions.begin(), radius.value().illegal_actions.end(),
                          ContainmentActionKind::FENCE_WORKER) != radius.value().illegal_actions.end());
}

FCF_TEST(blast_radius, broad_domain_fencing_is_reported_as_illegal_when_narrower_scope_suffices) {
    Fixture fixture;
    FCF_REQUIRE(fixture.engine.register_isolation_domain(make_isolation_domain(101, "iso-1", {1})).ok());
    FCF_REQUIRE(fixture.engine.register_isolation_domain(make_isolation_domain(102, "iso-2", {2})).ok());
    FCF_REQUIRE(fixture.engine.register_isolation_domain(make_isolation_domain(103, "iso-3", {3})).ok());
    FCF_REQUIRE(fixture.engine.register_domain(make_domain(301, "cd-1", false, {1, 2})).ok());
    FCF_REQUIRE(fixture.engine.register_domain(make_domain(302, "cd-2", false, {3})).ok());
    add_resource(fixture.engine, ResourceSpec{1, "r1", ResourceClass::WORKER, ProtectionClass::STANDARD,
                                              301, 101, 0, 0, 0});
    add_resource(fixture.engine, ResourceSpec{2, "r2", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 301, 102, 0, 0, 0});
    add_resource(fixture.engine, ResourceSpec{3, "r3", ResourceClass::GENERIC,
                                              ProtectionClass::STANDARD, 302, 103, 0, 0, 0});
    add_edge(fixture.engine, 401, 1, 3, DependencyKind::EXECUTION_DEPENDS_ON);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> radius =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(radius.ok());
    // The mandatory set spans two containment domains, so a whole-domain fence
    // would remove resources that were never in the radius.
    FCF_EQ(radius.value().mandatory.size(), 2U);
    FCF_REQUIRE(contains(radius.value().unaffected, 2));
    FCF_REQUIRE(std::find(radius.value().illegal_actions.begin(), radius.value().illegal_actions.end(),
                          ContainmentActionKind::FULL_DOMAIN_ISOLATION) !=
                radius.value().illegal_actions.end());
}

FCF_TEST(blast_radius, evaluation_is_reproducible_for_identical_canonical_input) {
    Fixture fixture;
    for (std::uint64_t id : {1U, 2U, 3U, 4U, 9U}) {
        add_isolated_resource(fixture.engine, id);
    }
    add_edge(fixture.engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
    add_edge(fixture.engine, 402, 1, 3, DependencyKind::MEMORY_OWNED_BY);
    add_edge(fixture.engine, 403, 3, 4, DependencyKind::REPLICA_MEMBER_OF, true);
    publish_fault(fixture.engine, 501, FaultKind::PROCESS_DEATH, 1);

    const Result<BlastRadius> first =
        fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
    FCF_REQUIRE(first.ok());
    const std::string rendered = render_blast_radius(first.value());
    FCF_REQUIRE(!rendered.empty());
    for (int i = 0; i < 5; ++i) {
        const Result<BlastRadius> repeat =
            fixture.engine.evaluate_containment(FaultId::from_value(501), FaultGeneration{});
        FCF_REQUIRE(repeat.ok());
        FCF_EQ(render_blast_radius(repeat.value()), rendered);
    }
    FCF_REQUIRE(rendered.find("MANDATORY:") != std::string::npos);
    FCF_REQUIRE(rendered.find("UNAFFECTED:") != std::string::npos);
    FCF_REQUIRE(rendered.find("AUTHORITY:") != std::string::npos);
}

FCF_TEST(blast_radius, duplicate_fault_publication_is_idempotent_and_conflicts_are_rejected) {
    Fixture fixture;
    add_isolated_resource(fixture.engine, 1);
    FaultEvidence evidence;
    evidence.id = FaultId::from_value(501);
    evidence.kind = FaultKind::PROCESS_DEATH;
    evidence.subject = ResourceId::from_value(1);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = fixture.engine.epoch();
    evidence.observation_sequence = EvidenceSequence::from_value(3);
    evidence.publication_time_ms = 500;
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    evidence.details = "identical";

    bool duplicate = false;
    const Result<FaultRecord> first = fixture.engine.publish_fault(evidence, &duplicate);
    FCF_REQUIRE(first.ok());
    FCF_REQUIRE(!duplicate);
    const Result<FaultRecord> second = fixture.engine.publish_fault(evidence, &duplicate);
    FCF_REQUIRE(second.ok());
    FCF_REQUIRE(duplicate);
    FCF_EQ(second.value().duplicate_count, 1U);
    FCF_EQ(fixture.engine.query_system_status().fault_count, 1U);

    // A different observation reusing the same fault identity is a conflict, never a merge.
    FaultEvidence conflicting = evidence;
    conflicting.kind = FaultKind::DEVICE_FAILURE;
    conflicting.details = "different content under the same identity";
    const Result<FaultRecord> conflict = fixture.engine.publish_fault(conflicting, &duplicate);
    FCF_REQUIRE(!conflict.ok());
    FCF_EQ(conflict.error().code(), ErrorCode::DUPLICATE_CONFLICT);
    FCF_EQ(fixture.engine.query_system_status().fault_count, 1U);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
