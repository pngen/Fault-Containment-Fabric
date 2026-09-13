// Fault Containment Fabric — seeded randomized proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every case prints its seed and complete reproduction parameters on failure.

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "fcf/engine.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

/// Deterministic xorshift generator: the same seed always builds the same graph.
class Seeded {
public:
    explicit Seeded(std::uint64_t seed) : state_(seed == 0U ? 0x9E3779B97F4A7C15ULL : seed) {}
    [[nodiscard]] std::uint64_t next() {
        state_ ^= state_ << 13U;
        state_ ^= state_ >> 7U;
        state_ ^= state_ << 17U;
        return state_;
    }
    [[nodiscard]] std::uint64_t below(std::uint64_t bound) { return bound == 0U ? 0U : next() % bound; }
    [[nodiscard]] std::uint64_t seed() const { return seed_; }

private:
    std::uint64_t state_;
    std::uint64_t seed_ = 0;
};

struct Generated {
    std::vector<std::uint64_t> resources;
    std::vector<std::uint64_t> faults;
    std::size_t edges = 0;
    std::string parameters;
};

Generated generate(Engine& engine, Seeded& random, std::size_t resource_count) {
    Generated out;
    out.parameters = "seed=" + std::to_string(random.seed()) +
                     " resources=" + std::to_string(resource_count);
    const std::size_t groups = std::max<std::size_t>(1U, resource_count / 6U);
    for (std::size_t group = 1; group <= groups; ++group) {
        std::vector<std::uint64_t> members;
        for (std::size_t index = 0; index < resource_count; ++index) {
            if ((index % groups) + 1U == group) {
                members.push_back(index + 1U);
            }
        }
        FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(group, "iso", members)).ok());
        FCF_REQUIRE(engine.register_failure_domain(make_failure_domain(group, "fd", members)).ok());
    }
    for (std::size_t index = 1; index <= resource_count; ++index) {
        const std::uint64_t group = ((index - 1U) % groups) + 1U;
        ResourceSpec spec;
        spec.id = index;
        spec.name = "r" + std::to_string(index);
        spec.resource_class = (index % 6U == 0U) ? ResourceClass::WORKER : ResourceClass::EXECUTION;
        spec.isolation_domain = group;
        spec.failure_domain = group;
        spec.owner_worker = group;
        spec.owner_boot = group;
        spec.freshness = (random.below(10U) == 0U) ? EvidenceFreshness::STALE : EvidenceFreshness::FRESH;
        add_resource(engine, spec);
        out.resources.push_back(index);
    }
    const std::size_t edge_target = resource_count * 2U;
    for (std::size_t attempt = 0; attempt < edge_target; ++attempt) {
        const std::uint64_t source = 1U + random.below(resource_count);
        const std::uint64_t destination = 1U + random.below(resource_count);
        if (source == destination) {
            continue;
        }
        DependencyEdge edge;
        edge.id = DependencyId::from_value(100000U + attempt);
        edge.source = ResourceId::from_value(source);
        edge.destination = ResourceId::from_value(destination);
        edge.kind = static_cast<DependencyKind>(random.below(kDependencyKindMax + 1U));
        edge.conditional = random.below(4U) == 0U;
        edge.freshness = (random.below(8U) == 0U) ? EvidenceFreshness::STALE : EvidenceFreshness::FRESH;
        edge.integrity = edge.freshness == EvidenceFreshness::FRESH ? IntegrityStatus::VERIFIED
                                                                   : IntegrityStatus::UNVERIFIED;
        edge.confidence_permille = static_cast<std::uint16_t>(random.below(1001U));
        edge.evidence_source = "property";
        if (engine.register_dependency(edge).ok()) {
            ++out.edges;
        }
    }
    const std::size_t fault_count = std::max<std::size_t>(1U, resource_count / 4U);
    for (std::size_t index = 0; index < fault_count; ++index) {
        FaultEvidence evidence;
        evidence.id = FaultId::from_value(500000U + index);
        evidence.kind = static_cast<FaultKind>(random.below(kFaultKindMax + 1U));
        evidence.subject = ResourceId::from_value(1U + random.below(resource_count));
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.observation_sequence = EvidenceSequence::from_value(index + 1U);
        evidence.publication_time_ms = index;
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        evidence.confidence_permille = 1000U;
        const Result<FaultRecord> published = engine.publish_fault(evidence);
        if (published.ok()) {
            out.faults.push_back(evidence.id.value());
        }
    }
    return out;
}

void check_invariants(Engine& engine, const Generated& generated) {
    const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
    for (const std::uint64_t fault : generated.faults) {
        const Result<BlastRadius> evaluated =
            engine.evaluate_containment(FaultId::from_value(fault), FaultGeneration{});
        FCF_REQUIRE_MSG(evaluated.ok(),
                        generated.parameters + " evaluate failed: " + evaluated.error().to_string());
        const BlastRadius& radius = evaluated.value();

        // Buckets are disjoint.
        for (const ResourceId id : radius.mandatory) {
            FCF_REQUIRE_MSG(!id_set_contains(radius.unaffected, id), generated.parameters);
            FCF_REQUIRE_MSG(!id_set_contains(radius.unresolved, id), generated.parameters);
            FCF_REQUIRE_MSG(!id_set_contains(radius.precautionary, id), generated.parameters);
            const ClassifiedResource& classified = radius.classifications.at(id);
            FCF_REQUIRE_MSG(classified.has_inclusion, generated.parameters);
        }
        for (const ResourceId id : radius.unaffected) {
            const ClassifiedResource& classified = radius.classifications.at(id);
            FCF_REQUIRE_MSG(classified.has_exclusion, generated.parameters);
        }
        // Every resource is classified exactly once.
        FCF_EQ(radius.mandatory.size() + radius.precautionary.size() + radius.unaffected.size() +
                   radius.unresolved.size(),
               snapshot->topology.resources.size());
        // The fault subject is always inside the mandatory set.
        if (snapshot->faults.count(FaultId::from_value(fault)) != 0U) {
            FCF_REQUIRE_MSG(
                id_set_contains(radius.mandatory, snapshot->faults.at(FaultId::from_value(fault))
                                                      .evidence.subject),
                generated.parameters);
        }
        // Determinism: the same canonical input renders byte-identical output.
        const Result<BlastRadius> again =
            engine.evaluate_containment(FaultId::from_value(fault), FaultGeneration{});
        FCF_REQUIRE(again.ok());
        FCF_REQUIRE_MSG(render_blast_radius(again.value()) == render_blast_radius(radius),
                        generated.parameters);
    }
}

}  // namespace

FCF_TEST(property, random_graphs_keep_every_containment_invariant) {
    for (std::uint64_t seed = 1; seed <= 12; ++seed) {
        Seeded random(seed);
        LogicalClock clock;
        Engine engine(make_config(clock));
        const std::size_t resource_count = 6U + static_cast<std::size_t>(random.below(24U));
        const Generated generated = generate(engine, random, resource_count);
        check_invariants(engine, generated);
    }
}

FCF_TEST(property, identical_seeds_produce_identical_decisions) {
    for (std::uint64_t seed = 100; seed <= 104; ++seed) {
        std::string first_render;
        for (int run = 0; run < 2; ++run) {
            Seeded random(seed);
            LogicalClock clock;
            Engine engine(make_config(clock));
            const Generated generated = generate(engine, random, 18U);
            std::string combined;
            for (const std::uint64_t fault : generated.faults) {
                const Result<BlastRadius> radius =
                    engine.evaluate_containment(FaultId::from_value(fault), FaultGeneration{});
                FCF_REQUIRE(radius.ok());
                combined += render_blast_radius(radius.value());
            }
            if (run == 0) {
                first_render = combined;
            } else {
                FCF_REQUIRE_MSG(combined == first_render, "seed " + std::to_string(seed));
            }
        }
    }
}

FCF_TEST(property, dense_graphs_and_shared_dependencies_stay_classified) {
    Seeded random(4242);
    LogicalClock clock;
    Engine engine(make_config(clock));
    // A dense synthetic graph: every group shares a dependency spine.
    for (std::uint64_t group = 1; group <= 10; ++group) {
        std::vector<std::uint64_t> members;
        for (std::uint64_t index = group; index <= 90U; index += 10U) {
            members.push_back(index);
        }
        FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(group, "iso", members)).ok());
    }
    for (std::uint64_t index = 1; index <= 90U; ++index) {
        ResourceSpec spec;
        spec.id = index;
        spec.name = "n" + std::to_string(index);
        spec.isolation_domain = ((index - 1U) % 10U) + 1U;
        add_resource(engine, spec);
    }
    std::uint64_t edge_id = 1;
    for (std::uint64_t index = 1; index <= 90U; ++index) {
        for (std::uint64_t step = 1; step <= 3U; ++step) {
            const std::uint64_t destination = ((index + step * 7U - 1U) % 90U) + 1U;
            if (destination == index) {
                continue;
            }
            add_dependency(engine, edge_id++, index, destination, DependencyKind::STATE_OWNED_BY,
                           step == 3U);
        }
    }
    (void)random;
    for (std::uint64_t subject = 1; subject <= 12U; ++subject) {
        FaultEvidence evidence;
        evidence.id = FaultId::from_value(900000U + subject);
        evidence.kind = FaultKind::PROCESS_DEATH;
        evidence.subject = ResourceId::from_value(subject);
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        FCF_REQUIRE(engine.publish_fault(evidence).ok());
    }
    Generated generated;
    for (std::uint64_t subject = 1; subject <= 12U; ++subject) {
        generated.faults.push_back(900000U + subject);
    }
    generated.parameters = "dense graph, 90 resources, 12 faults";
    check_invariants(engine, generated);
}

FCF_TEST(property, random_stale_evidence_and_uncertainty_never_produce_silent_safety) {
    for (std::uint64_t seed = 7; seed <= 16; ++seed) {
        Seeded random(seed);
        LogicalClock clock;
        Engine engine(make_config(clock));
        const Generated generated = generate(engine, random, 12U);
        for (const std::uint64_t fault : generated.faults) {
            const Result<BlastRadius> radius =
                engine.evaluate_containment(FaultId::from_value(fault), FaultGeneration{});
            FCF_REQUIRE(radius.ok());
            // Anything that could not be proven is never reported unaffected.
            for (const ResourceId id : radius.value().unresolved) {
                FCF_REQUIRE(!id_set_contains(radius.value().unaffected, id));
                FCF_REQUIRE(!id_set_contains(radius.value().mandatory, id));
            }
            const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
            for (const ResourceId id : radius.value().unaffected) {
                const auto resource = snapshot->topology.resources.find(id);
                FCF_REQUIRE(resource != snapshot->topology.resources.end());
                FCF_EQ(resource->second.freshness, EvidenceFreshness::FRESH);
            }
        }
    }
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
