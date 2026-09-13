// Fault Containment Fabric — benchmarks.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every benchmark measures completed work, never asynchronous submission.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fcf/engine.hpp"
#include "fcf/persistence.hpp"

namespace {

using Clock = std::chrono::steady_clock;

class Timer {
public:
    void start() { begin_ = Clock::now(); }
    [[nodiscard]] double seconds() const {
        return std::chrono::duration<double>(Clock::now() - begin_).count();
    }

private:
    Clock::time_point begin_{};
};

void report(const char* name, double total_seconds, std::uint64_t operations, const char* unit) {
    const double per_operation = operations == 0U ? 0.0 : total_seconds / static_cast<double>(operations);
    std::printf("%-46s %12llu %-10s %10.4f s  %12.3f us/op\n", name,
                static_cast<unsigned long long>(operations), unit, total_seconds, per_operation * 1e6);
}

[[nodiscard]] std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
}

/// Builds a synthetic containment graph: a chain of fan-out groups with a shared
/// dependency spine, which is the shape containment decisions actually traverse.
void build_graph(fcf::Engine& engine, std::size_t resources, std::size_t& dependency_count) {
    dependency_count = 0;
    const std::size_t groups = std::max<std::size_t>(1, resources / 8U);
    for (std::size_t group = 0; group < groups; ++group) {
        fcf::IsolationDomain iso;
        iso.id = fcf::IsolationDomainId::from_value(group + 1U);
        iso.name = "iso-" + std::to_string(group);
        (void)engine.register_isolation_domain(iso);
        fcf::FailureDomain fail;
        fail.id = fcf::FailureDomainId::from_value(group + 1U);
        fail.name = "fd-" + std::to_string(group);
        fail.kind = fcf::FailureDomainKind::SYNTHETIC_CORRELATED_GROUP;
        fail.freshness = fcf::EvidenceFreshness::FRESH;
        (void)engine.register_failure_domain(fail);
    }
    for (std::size_t index = 0; index < resources; ++index) {
        const std::size_t group = index / 8U;
        fcf::ResourceRecord record;
        record.id = fcf::ResourceId::from_value(index + 1U);
        record.name = "r" + std::to_string(index);
        record.resource_class = index % 8U == 0U ? fcf::ResourceClass::WORKER : fcf::ResourceClass::EXECUTION;
        record.isolation_domain = fcf::IsolationDomainId::from_value(group + 1U);
        record.failure_domain = fcf::FailureDomainId::from_value(group + 1U);
        record.owner_worker = fcf::WorkerId::from_value(group + 1U);
        record.owner_boot = fcf::WorkerBootId::from_value(group + 1U);
        record.freshness = fcf::EvidenceFreshness::FRESH;
        record.state = fcf::ResourceOperationalState::ACTIVE;
        (void)engine.register_resource(record);
    }
    std::uint64_t next_dependency = 1;
    for (std::size_t index = 1; index < resources; ++index) {
        fcf::DependencyEdge edge;
        edge.id = fcf::DependencyId::from_value(next_dependency++);
        edge.source = fcf::ResourceId::from_value(index);
        edge.destination = fcf::ResourceId::from_value(index + 1U);
        edge.kind = index % 8U == 0U ? fcf::DependencyKind::EXECUTION_DEPENDS_ON
                                     : fcf::DependencyKind::STATE_OWNED_BY;
        edge.freshness = fcf::EvidenceFreshness::FRESH;
        edge.integrity = fcf::IntegrityStatus::VERIFIED;
        edge.confidence_permille = 1000U;
        edge.evidence_source = "benchmark";
        if (engine.register_dependency(edge).ok()) {
            ++dependency_count;
        }
    }
}

void benchmark_graph_size(std::size_t resources) {
    fcf::Engine engine;
    std::size_t dependencies = 0;
    Timer build;
    build.start();
    build_graph(engine, resources, dependencies);
    std::printf("  graph %zu resources / %zu dependencies built in %.4f s\n", resources, dependencies,
                build.seconds());

    const std::string label = "blast radius @" + std::to_string(resources) + " resources";
    fcf::FaultEvidence fault;
    fault.kind = fcf::FaultKind::PROCESS_DEATH;
    fault.subject = fcf::ResourceId::from_value(1);
    fault.reporter_kind = fcf::ReporterKind::OPERATOR;
    fault.epoch = engine.epoch();
    fault.freshness = fcf::EvidenceFreshness::FRESH;
    fault.integrity = fcf::IntegrityStatus::VERIFIED;
    const auto published = engine.publish_fault(fault);
    if (!published.ok()) {
        std::printf("  fault publication failed\n");
        return;
    }

    const std::uint64_t iterations = resources >= 10000U ? 20U : (resources >= 1000U ? 100U : 500U);
    Timer timer;
    timer.start();
    std::uint64_t completed = 0;
    for (std::uint64_t i = 0; i < iterations; ++i) {
        const auto radius =
            engine.evaluate_containment(published.value().evidence.id, fcf::FaultGeneration{});
        if (radius.ok()) {
            ++completed;
        }
    }
    report(label.c_str(), timer.seconds(), completed, "evaluations");
}

}  // namespace

int main() {
    std::printf("Fault Containment Fabric benchmarks (completed work only)\n");
    std::printf("%-46s %12s %-10s %12s  %14s\n", "benchmark", "count", "unit", "total", "per operation");

    // Containment evaluation over a realistic graph.
    for (const std::size_t resources : {100U, 1000U, 10000U}) {
        benchmark_graph_size(resources);
    }

    // Fault ingestion throughput on a fixed small graph.
    {
        fcf::Engine engine;
        std::size_t dependencies = 0;
        build_graph(engine, 1000U, dependencies);
        Timer timer;
        timer.start();
        std::uint64_t completed = 0;
        constexpr std::uint64_t kFaults = 2000U;
        for (std::uint64_t i = 0; i < kFaults; ++i) {
            fcf::FaultEvidence fault;
            fault.id = fcf::FaultId::from_value(i + 1U);
            fault.kind = fcf::FaultKind::HEALTH_DEGRADED;
            fault.subject = fcf::ResourceId::from_value((i % 1000U) + 1U);
            fault.reporter_kind = fcf::ReporterKind::OPERATOR;
            fault.epoch = engine.epoch();
            fault.observation_sequence = fcf::EvidenceSequence::from_value(i + 1U);
            fault.freshness = fcf::EvidenceFreshness::FRESH;
            fault.integrity = fcf::IntegrityStatus::VERIFIED;
            fault.publication_time_ms = now_ms();
            if (engine.publish_fault(fault).ok()) {
                ++completed;
            }
        }
        report("fault ingestion", timer.seconds(), completed, "faults");
    }

    // Dependency graph update throughput.
    {
        fcf::Engine engine;
        std::size_t dependencies = 0;
        build_graph(engine, 1000U, dependencies);
        Timer timer;
        timer.start();
        std::uint64_t completed = 0;
        for (std::uint64_t i = 0; i < 1000U; ++i) {
            fcf::DependencyEdge edge;
            edge.id = fcf::DependencyId::from_value(100000U + i);
            edge.source = fcf::ResourceId::from_value((i % 500U) + 1U);
            edge.destination = fcf::ResourceId::from_value((i % 500U) + 500U);
            edge.kind = fcf::DependencyKind::SERVICE_DEPENDS_ON;
            edge.freshness = fcf::EvidenceFreshness::FRESH;
            edge.integrity = fcf::IntegrityStatus::VERIFIED;
            edge.confidence_permille = 1000U;
            edge.evidence_source = "benchmark";
            if (engine.register_dependency(edge).ok()) {
                ++completed;
            }
        }
        report("dependency graph update", timer.seconds(), completed, "registrations");
    }

    // Snapshot creation and deterministic explanation rendering.
    {
        fcf::Engine engine;
        std::size_t dependencies = 0;
        build_graph(engine, 10000U, dependencies);
        Timer snapshot_timer;
        snapshot_timer.start();
        std::uint64_t snapshots = 0;
        for (int i = 0; i < 20; ++i) {
            const std::shared_ptr<const fcf::RuntimeSnapshot> snapshot = engine.snapshot();
            if (snapshot != nullptr && snapshot->topology.resources.size() == 10000U) {
                ++snapshots;
            }
        }
        report("snapshot creation @10000 resources", snapshot_timer.seconds(), snapshots, "snapshots");

        fcf::FaultEvidence fault;
        fault.kind = fcf::FaultKind::PROCESS_DEATH;
        fault.subject = fcf::ResourceId::from_value(1);
        fault.reporter_kind = fcf::ReporterKind::OPERATOR;
        fault.epoch = engine.epoch();
        fault.freshness = fcf::EvidenceFreshness::FRESH;
        fault.integrity = fcf::IntegrityStatus::VERIFIED;
        const auto published = engine.publish_fault(fault);
        const auto radius =
            engine.evaluate_containment(published.value().evidence.id, fcf::FaultGeneration{});
        Timer explain_timer;
        explain_timer.start();
        std::uint64_t rendered = 0;
        for (int i = 0; i < 200; ++i) {
            if (!fcf::render_blast_radius(radius.value()).empty()) {
                ++rendered;
            }
        }
        report("deterministic explanation @10000 resources", explain_timer.seconds(), rendered,
               "renderings");
    }

    // Containment verification.
    {
        fcf::Engine engine;
        std::size_t dependencies = 0;
        build_graph(engine, 1000U, dependencies);
        fcf::FaultEvidence fault;
        fault.kind = fcf::FaultKind::PROCESS_DEATH;
        fault.subject = fcf::ResourceId::from_value(1);
        fault.reporter_kind = fcf::ReporterKind::OPERATOR;
        fault.epoch = engine.epoch();
        fault.freshness = fcf::EvidenceFreshness::FRESH;
        fault.integrity = fcf::IntegrityStatus::VERIFIED;
        const auto published = engine.publish_fault(fault);
        const auto containment = engine.authorize_containment(published.value().evidence.id,
                                                              published.value().evidence.generation);
        Timer timer;
        timer.start();
        std::uint64_t completed = 0;
        for (int i = 0; i < 100; ++i) {
            if (containment.ok() && engine.verify_containment(containment.value().generation).ok()) {
                ++completed;
            }
        }
        report("containment verification", timer.seconds(), completed, "verifications");
    }

    // Concurrent read and evaluate workload.
    {
        fcf::Engine engine;
        std::size_t dependencies = 0;
        build_graph(engine, 1000U, dependencies);
        fcf::FaultEvidence fault;
        fault.kind = fcf::FaultKind::PROCESS_DEATH;
        fault.subject = fcf::ResourceId::from_value(1);
        fault.reporter_kind = fcf::ReporterKind::OPERATOR;
        fault.epoch = engine.epoch();
        fault.freshness = fcf::EvidenceFreshness::FRESH;
        fault.integrity = fcf::IntegrityStatus::VERIFIED;
        const auto published = engine.publish_fault(fault);
        const unsigned threads = std::max(2U, std::thread::hardware_concurrency());
        std::vector<std::thread> workers;
        std::vector<std::uint64_t> counts(threads, 0U);
        Timer timer;
        timer.start();
        for (unsigned index = 0; index < threads; ++index) {
            workers.emplace_back([&engine, &published, &counts, index]() {
                for (int iteration = 0; iteration < 200; ++iteration) {
                    if (engine.evaluate_containment(published.value().evidence.id, fcf::FaultGeneration{})
                            .ok()) {
                        ++counts[index];
                    }
                }
            });
        }
        for (std::thread& worker : workers) {
            worker.join();
        }
        std::uint64_t total = 0;
        for (const std::uint64_t count : counts) {
            total += count;
        }
        report("concurrent evaluation (all threads)", timer.seconds(), total, "evaluations");
    }

    // Persistence save and load.
    {
        const std::filesystem::path directory =
            std::filesystem::temp_directory_path() / "fcf-benchmark-state";
        std::error_code ec;
        std::filesystem::remove_all(directory, ec);
        fcf::DurableStore::Options options;
        options.directory = directory.string();
        auto store = fcf::DurableStore::open(options);
        if (store.ok()) {
            fcf::Engine engine;
            (void)engine.attach_store(store.value().get());
            std::size_t dependencies = 0;
            build_graph(engine, 1000U, dependencies);
            Timer timer;
            timer.start();
            std::uint64_t saves = 0;
            for (int i = 0; i < 20; ++i) {
                if (engine.persist_snapshot().ok()) {
                    ++saves;
                }
            }
            report("persistence save @1000 resources", timer.seconds(), saves, "snapshots");

            Timer load_timer;
            load_timer.start();
            std::uint64_t loads = 0;
            for (int i = 0; i < 20; ++i) {
                fcf::Engine restored;
                if (restored.recover_from_store(*store.value(), 1).ok()) {
                    ++loads;
                }
            }
            report("persistence load @1000 resources", load_timer.seconds(), loads, "recoveries");
        }
        std::filesystem::remove_all(directory, ec);
    }

    return 0;
}
