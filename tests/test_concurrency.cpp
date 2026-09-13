// Fault Containment Fabric — concurrency proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include "fcf/engine.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

class NullExecutor : public Executor {
public:
    Result<std::string> dispatch(const ContainmentAction& action) override {
        return std::string("null:") + to_string(action.id);
    }
};

void build(Engine& engine, std::size_t count) {
    for (std::size_t index = 1; index <= count; ++index) {
        std::vector<std::uint64_t> members{index};
        const std::uint64_t isolation = 100U + index;
        FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(isolation, "iso", members)).ok());
        add_resource(engine, ResourceSpec{index, "r" + std::to_string(index),
                                          index % 5U == 0U ? ResourceClass::WORKER
                                                           : ResourceClass::EXECUTION,
                                          ProtectionClass::STANDARD, 0, isolation, 0, 1, 11});
    }
    for (std::size_t index = 1; index < count; ++index) {
        add_dependency(engine, 10000U + index, index, index + 1, DependencyKind::EXECUTION_DEPENDS_ON);
    }
}

}  // namespace

FCF_TEST(concurrency, readers_and_a_writer_never_observe_a_torn_state) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build(engine, 40U);

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> evaluations{0};
    std::atomic<std::uint64_t> snapshots{0};
    std::vector<std::thread> readers;
    for (int index = 0; index < 4; ++index) {
        readers.emplace_back([&engine, &stop, &evaluations, &snapshots]() {
            while (!stop.load()) {
                const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
                for (const auto& entry : snapshot->topology.dependencies.edges) {
                    // Every dependency in an observed snapshot must reference
                    // resources that exist in that same snapshot.
                    if (snapshot->topology.resources.count(entry.second.source) == 0U ||
                        snapshot->topology.resources.count(entry.second.destination) == 0U) {
                        FCF_FAIL("a snapshot exposed a dependency with a dangling endpoint");
                    }
                }
                snapshots.fetch_add(1);
                for (const auto& fault : snapshot->faults) {
                    const Result<BlastRadius> radius =
                        engine.evaluate_containment(fault.first, FaultGeneration{});
                    if (radius.ok()) {
                        for (const ResourceId id : radius.value().mandatory) {
                            if (id_set_contains(radius.value().unaffected, id)) {
                                FCF_FAIL("a resource appeared in two buckets");
                            }
                        }
                        evaluations.fetch_add(1);
                    }
                }
            }
        });
    }

    std::thread writer([&engine, &stop]() {
        for (std::uint64_t index = 0; index < 60U && !stop.load(); ++index) {
            FaultEvidence evidence;
            evidence.id = FaultId::from_value(5000U + index);
            evidence.kind = FaultKind::PROCESS_DEATH;
            evidence.subject = ResourceId::from_value((index % 40U) + 1U);
            evidence.reporter_kind = ReporterKind::OPERATOR;
            evidence.epoch = engine.epoch();
            evidence.observation_sequence = EvidenceSequence::from_value(index + 1U);
            evidence.publication_time_ms = index;
            evidence.freshness = EvidenceFreshness::FRESH;
            evidence.integrity = IntegrityStatus::VERIFIED;
            (void)engine.publish_fault(evidence);
            std::this_thread::yield();
        }
        stop.store(true);
    });
    writer.join();
    for (std::thread& reader : readers) {
        reader.join();
    }
    FCF_REQUIRE(snapshots.load() > 0U);
    FCF_REQUIRE(evaluations.load() > 0U);
}

FCF_TEST(concurrency, concurrent_acknowledgments_never_double_commit) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build(engine, 4U);
    FaultEvidence evidence;
    evidence.kind = FaultKind::PROCESS_DEATH;
    evidence.subject = ResourceId::from_value(1);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = engine.epoch();
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    const Result<FaultRecord> fault = engine.publish_fault(evidence);
    FCF_REQUIRE(fault.ok());
    const Result<ContainmentRecord> containment =
        engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
    FCF_REQUIRE(containment.ok());
    NullExecutor executor;
    const Result<DispatchSummary> summary =
        engine.dispatch_containment(containment.value().generation, &executor);
    FCF_REQUIRE(summary.ok());

    std::vector<std::thread> threads;
    for (const ActionId action_id : summary.value().dispatched) {
        for (int copy = 0; copy < 4; ++copy) {
            threads.emplace_back([&engine, action_id]() {
                const Result<ContainmentAction> action = engine.query_action(action_id);
                if (!action.ok()) {
                    return;
                }
                ActionAcknowledgment ack;
                ack.action = action_id;
                ack.action_generation = action.value().generation;
                ack.epoch = engine.epoch();
                ack.accepted = true;
                (void)engine.record_action_ack(ack);
                ActionResult result;
                result.action = action_id;
                result.action_generation = action.value().generation;
                result.epoch = engine.epoch();
                result.success = true;
                (void)engine.record_action_result(result);
            });
        }
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    for (const ActionId action_id : summary.value().dispatched) {
        const Result<ContainmentAction> action = engine.query_action(action_id);
        FCF_REQUIRE(action.ok());
        FCF_EQ(action.value().status, ActionStatus::RESULT_RECORDED);
    }
}

FCF_TEST(concurrency, shutdown_stops_new_dispatch_and_preserves_committed_state) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build(engine, 4U);
    FaultEvidence evidence;
    evidence.kind = FaultKind::PROCESS_DEATH;
    evidence.subject = ResourceId::from_value(1);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = engine.epoch();
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    const Result<FaultRecord> fault = engine.publish_fault(evidence);
    FCF_REQUIRE(fault.ok());
    const Result<ContainmentRecord> containment =
        engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
    FCF_REQUIRE(containment.ok());

    engine.shutdown();
    FCF_REQUIRE(engine.shutting_down());
    NullExecutor executor;
    const Result<DispatchSummary> refused =
        engine.dispatch_containment(containment.value().generation, &executor);
    FCF_REQUIRE(!refused.ok());
    FCF_EQ(refused.error().code(), ErrorCode::SHUTTING_DOWN);

    // Already-committed containment stays exactly as it was.
    const Result<ContainmentRecord> after = engine.query_containment(containment.value().generation);
    FCF_REQUIRE(after.ok());
    FCF_EQ(after.value().status, ContainmentStatus::COMMITTED);
    const Result<ResourceStatusView> resource =
        engine.query_resource_status(ResourceId::from_value(2));
    FCF_REQUIRE(resource.ok());
    FCF_REQUIRE(resource.value().quarantined);
}

FCF_TEST(concurrency, repeated_start_stop_cycles_leave_accounting_clean) {
    for (int cycle = 0; cycle < 12; ++cycle) {
        LogicalClock clock;
        Engine engine(make_config(clock));
        build(engine, 12U);
        FaultEvidence evidence;
        evidence.kind = FaultKind::PROCESS_DEATH;
        evidence.subject = ResourceId::from_value(1);
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        const Result<FaultRecord> fault = engine.publish_fault(evidence);
        FCF_REQUIRE(fault.ok());
        FCF_REQUIRE(engine
                        .authorize_containment(fault.value().evidence.id, fault.value().evidence.generation)
                        .ok());
        const SystemStatus before = engine.query_system_status();
        engine.shutdown();
        const SystemStatus after = engine.query_system_status();
        FCF_EQ(after.resource_count, before.resource_count);
        FCF_EQ(after.live_containment_count, before.live_containment_count);
        FCF_EQ(after.quarantined_resource_count, before.quarantined_resource_count);
    }
}

FCF_TEST(concurrency, repeated_epoch_advance_is_monotonic_and_serialised) {
    LogicalClock clock;
    Engine engine(make_config(clock));
    build(engine, 6U);
    std::vector<std::thread> threads;
    std::vector<CoordinatorEpoch> results(8);
    for (std::size_t index = 0; index < results.size(); ++index) {
        threads.emplace_back([&engine, &results, index]() {
            const Result<CoordinatorEpoch> advanced =
                engine.begin_epoch(static_cast<std::uint64_t>(index) * 10U, "concurrent");
            if (advanced.ok()) {
                results[index] = advanced.value();
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    for (std::size_t index = 0; index < results.size(); ++index) {
        for (std::size_t other = index + 1; other < results.size(); ++other) {
            FCF_REQUIRE(results[index] != results[other]);
        }
    }
    FCF_EQ(engine.epoch().value(), 1U + results.size());
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
