// Fault Containment Fabric — durable state proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fcf/detail/crc32c.hpp"
#include "fcf/engine.hpp"
#include "fcf/persistence.hpp"
#include "framework.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

/// A scratch state directory that is removed when the case finishes.
class ScratchDirectory {
public:
    ScratchDirectory() {
        static int counter = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("fcf-test-state-" + std::to_string(++counter) + "-" +
                 std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    ~ScratchDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;
    [[nodiscard]] const std::string& text() const { return path_text_; }
    [[nodiscard]] const std::filesystem::path& path() { path_text_ = path_.string(); return path_; }

private:
    std::filesystem::path path_;
    std::string path_text_;
};

std::string directory_of(ScratchDirectory& scratch) { return scratch.path().string(); }

Result<std::unique_ptr<DurableStore>> open_store(const std::string& directory) {
    DurableStore::Options options;
    options.directory = directory;
    return DurableStore::open(options);
}

void build_small_topology(Engine& engine) {
    FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(101, "iso", {1, 2})).ok());
    add_resource(engine, ResourceSpec{1, "r1", ResourceClass::WORKER, ProtectionClass::STANDARD, 0, 101,
                                      0, 0, 0});
    add_resource(engine, ResourceSpec{2, "r2", ResourceClass::EXECUTION, ProtectionClass::STANDARD, 0,
                                      101, 0, 0, 0});
    add_dependency(engine, 401, 1, 2, DependencyKind::EXECUTION_DEPENDS_ON);
}

FaultId raise_fault(Engine& engine) {
    FaultEvidence evidence;
    evidence.kind = FaultKind::PROCESS_DEATH;
    evidence.subject = ResourceId::from_value(1);
    evidence.reporter_kind = ReporterKind::OPERATOR;
    evidence.epoch = engine.epoch();
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    const Result<FaultRecord> published = engine.publish_fault(evidence);
    FCF_REQUIRE(published.ok());
    return published.value().evidence.id;
}

void mutate_file(const std::string& path, const std::function<void(std::vector<char>&)>& mutator) {
    std::ifstream in(path, std::ios::binary);
    FCF_REQUIRE(in.good());
    std::vector<char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    mutator(bytes);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    FCF_REQUIRE(out.good());
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

FCF_TEST(persistence, snapshot_survives_restart_with_history_and_containment) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE_MSG(store.ok(), store.ok() ? "" : store.error().to_string());

    CoordinatorEpoch original_epoch{};
    ContainmentGeneration containment{};
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        const FaultId fault = raise_fault(engine);
        const Result<FaultRecord> record = engine.query_fault(fault);
        FCF_REQUIRE(record.ok());
        const Result<ContainmentRecord> committed =
            engine.authorize_containment(fault, record.value().evidence.generation);
        FCF_REQUIRE(committed.ok());
        containment = committed.value().generation;
        original_epoch = engine.epoch();
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }

    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 7000);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    FCF_REQUIRE(recovered.value() > original_epoch);

    const SystemStatus status = restored.query_system_status();
    FCF_EQ(status.live_containment_count, 1U);
    FCF_EQ(status.fault_count, 1U);
    FCF_EQ(status.resource_count, 2U);
    FCF_EQ(status.dependency_count, 1U);
    FCF_REQUIRE(status.unresolved_resource_count > 0);

    const Result<ContainmentRecord> record = restored.query_containment(containment);
    FCF_REQUIRE(record.ok());
    FCF_EQ(record.value().status, ContainmentStatus::COMMITTED);
    FCF_REQUIRE(id_set_contains(record.value().mandatory, ResourceId::from_value(2)));

    // Containment still forbids work after recovery.
    const Result<ResourceStatusView> contained =
        restored.query_resource_status(ResourceId::from_value(2));
    FCF_REQUIRE(contained.ok());
    FCF_REQUIRE(contained.value().quarantined);
    FCF_REQUIRE(!contained.value().operable);
}

FCF_TEST(persistence, journal_replay_recovers_mutations_that_were_never_snapshotted) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        (void)raise_fault(engine);
        // No snapshot is written: only journal records exist.
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    FCF_EQ(restored.query_system_status().fault_count, 1U);
    FCF_EQ(restored.query_system_status().resource_count, 2U);
}

FCF_TEST(persistence, live_authority_does_not_survive_recovery) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        FCF_REQUIRE(engine
                        .register_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "A",
                                         EvidenceSequence::from_value(1))
                        .ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    FCF_REQUIRE(restored.recover_from_store(*store.value(), 100).ok());
    const Result<WorkerRecord> worker =
        restored.query_worker(WorkerId::from_value(1), WorkerBootId::from_value(11));
    FCF_REQUIRE(worker.ok());
    FCF_REQUIRE(!holds_live_authority(worker.value().state));
    FCF_EQ(worker.value().state, WorkerState::SUSPECT);
    FCF_REQUIRE(restored.recovery_incomplete());
}

FCF_TEST(persistence, truncated_snapshot_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    mutate_file(store.value()->snapshot_path(), [](std::vector<char>& bytes) {
        bytes.resize(bytes.size() - 5U);
    });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, trailing_garbage_after_the_snapshot_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    mutate_file(store.value()->snapshot_path(), [](std::vector<char>& bytes) {
        bytes.push_back('X');
    });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, corrupted_snapshot_payload_checksum_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    mutate_file(store.value()->snapshot_path(), [](std::vector<char>& bytes) {
        bytes[bytes.size() / 2U] = static_cast<char>(bytes[bytes.size() / 2U] ^ 0x5A);
    });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, unsupported_snapshot_version_is_rejected_distinctly) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    // Rewrite the version field and repair the header checksum so the version, not
    // the checksum, is what rejects the file.
    const std::string path = store.value()->snapshot_path();
    std::vector<char> bytes;
    {
        std::ifstream in(path, std::ios::binary);
        bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    FCF_REQUIRE(bytes.size() > 24U);
    bytes[8] = 99;
    const std::uint32_t crc = detail::Crc32c::compute(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), 20U));
    for (int i = 0; i < 4; ++i) {
        bytes[20 + i] = static_cast<char>((crc >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_UNSUPPORTED_VERSION);
}

FCF_TEST(persistence, bad_snapshot_magic_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    mutate_file(store.value()->snapshot_path(), [](std::vector<char>& bytes) { bytes[0] = 'Z'; });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, torn_journal_tail_is_discarded_rather_than_repaired) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        (void)raise_fault(engine);
    }
    // Simulate a crash in the middle of the final append.
    mutate_file(store.value()->journal_path(), [](std::vector<char>& bytes) { bytes.resize(bytes.size() - 4U); });
    const Result<DurableStore::Recovery> recovery = store.value()->recover();
    FCF_REQUIRE_MSG(recovery.ok(), recovery.ok() ? "" : recovery.error().to_string());
    // The final record was cut short, so its bytes are reported and discarded rather
    // than being treated as corruption or silently repaired.
    FCF_REQUIRE_MSG(recovery.value().torn_tail_bytes > 0U,
                    "a truncated final record must be reported as a torn tail");
    FCF_REQUIRE(recovery.value().torn_tail_bytes < 4096U);

    LogicalClock clock;
    Engine restored(make_config(clock));
    FCF_REQUIRE(restored.recover_from_store(*store.value(), 100).ok());
}

FCF_TEST(persistence, corrupted_journal_record_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        (void)raise_fault(engine);
    }
    mutate_file(store.value()->journal_path(), [](std::vector<char>& bytes) {
        // Corrupt a byte inside the first record's payload region.
        if (bytes.size() > 20U) {
            bytes[16] = static_cast<char>(bytes[16] ^ 0x33);
        }
    });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, journal_magic_corruption_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
    }
    mutate_file(store.value()->journal_path(), [](std::vector<char>& bytes) { bytes[0] = 'Q'; });
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE(!recovered.ok());
    FCF_EQ(recovered.error().code(), ErrorCode::PERSISTENCE_CORRUPT);
}

FCF_TEST(persistence, durable_mutation_is_flushed_before_it_is_acknowledged) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    LogicalClock clock;
    Engine engine(make_config(clock));
    FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
    build_small_topology(engine);

    // A second, independent reader sees every durable mutation immediately after the
    // mutating call returned.
    const Result<DurableStore::Recovery> first = store.value()->recover();
    FCF_REQUIRE(first.ok());
    const std::size_t records_after_topology = first.value().journal_records.size();
    FCF_REQUIRE(records_after_topology > 0U);

    (void)raise_fault(engine);
    const Result<DurableStore::Recovery> second = store.value()->recover();
    FCF_REQUIRE(second.ok());
    FCF_REQUIRE(second.value().journal_records.size() > records_after_topology);
}

FCF_TEST(persistence, snapshot_payload_bitflip_is_rejected) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    // Flip a byte inside the payload; the payload checksum must catch it.
    mutate_file(store.value()->snapshot_path(), [](std::vector<char>& bytes) {
        bytes[40] = static_cast<char>(bytes[40] ^ 0x11);
    });
    LogicalClock clock;
    Engine restored(make_config(clock));
    FCF_REQUIRE(!restored.recover_from_store(*store.value(), 100).ok());
}

FCF_TEST(persistence, worker_loss_without_bound_resources_keeps_the_journal_replayable) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    const WorkerId worker = WorkerId::from_value(1);
    const WorkerBootId boot = WorkerBootId::from_value(11);
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        FCF_REQUIRE(engine.register_worker(worker, boot, "A", EvidenceSequence::from_value(1)).ok());
        // The incarnation dies before any resource was bound to it. Its authority is
        // revoked; the containment itself cannot be scoped and is refused.
        const Result<ContainmentRecord> lost = engine.worker_authority_lost(
            worker, boot, FaultKind::PROCESS_DEATH, "connection closed", 5);
        FCF_REQUIRE(!lost.ok());
        FCF_EQ(lost.error().code(), ErrorCode::UNKNOWN_RESOURCE);
        // Durable mutations continue afterwards.
        build_small_topology(engine);
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    FCF_EQ(restored.query_system_status().resource_count, 2U);
    // The revocation the coordinator acted on is durable too.
    const Result<WorkerRecord> record = restored.query_worker(worker, boot);
    FCF_REQUIRE(record.ok());
    FCF_EQ(record.value().state, WorkerState::AUTHORITY_REVOKED);
}

FCF_TEST(persistence, snapshot_keeps_journal_records_newer_than_itself) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    const std::vector<std::byte> body(16U, std::byte{0x5A});
    for (std::uint64_t sequence = 1; sequence <= 3U; ++sequence) {
        FCF_REQUIRE(store.value()->append_record(sequence, body).ok());
    }
    // The snapshot covers the state up to sequence 2. The third record belongs to a
    // mutation that was acknowledged while the snapshot was being written.
    FCF_REQUIRE(store.value()->save_snapshot(body, 2U).ok());
    const Result<DurableStore::Recovery> recovery = store.value()->recover();
    FCF_REQUIRE_MSG(recovery.ok(), recovery.ok() ? "" : recovery.error().to_string());
    FCF_EQ(recovery.value().snapshot_sequence, 2U);
    FCF_REQUIRE_MSG(recovery.value().journal_records.size() == 1U,
                    "an acknowledged record newer than the snapshot was discarded");
    FCF_EQ(recovery.value().journal_sequences.front(), 3U);

    // A snapshot that covers everything still empties the journal.
    FCF_REQUIRE(store.value()->save_snapshot(body, 3U).ok());
    const Result<DurableStore::Recovery> compacted = store.value()->recover();
    FCF_REQUIRE(compacted.ok());
    FCF_EQ(compacted.value().journal_records.size(), 0U);
    FCF_EQ(std::filesystem::file_size(store.value()->journal_path()), 0U);
    // Appending continues from there.
    FCF_REQUIRE(store.value()->append_record(4U, body).ok());
    const Result<DurableStore::Recovery> continued = store.value()->recover();
    FCF_REQUIRE(continued.ok());
    FCF_EQ(continued.value().journal_records.size(), 1U);
    FCF_EQ(continued.value().journal_sequences.front(), 4U);
}

FCF_TEST(persistence, journal_stays_replayable_after_a_torn_tail_and_new_appends) {
    ScratchDirectory scratch;
    const std::string directory = directory_of(scratch);
    std::string journal_path;
    {
        auto store = open_store(directory);
        FCF_REQUIRE(store.ok());
        journal_path = store.value()->journal_path();
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        build_small_topology(engine);
        (void)raise_fault(engine);
    }
    // A crash in the middle of the final append.
    mutate_file(journal_path, [](std::vector<char>& bytes) { bytes.resize(bytes.size() - 4U); });
    {
        // The restarted coordinator recovers, discards the torn record and keeps working.
        auto store = open_store(directory);
        FCF_REQUIRE(store.ok());
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.recover_from_store(*store.value(), 100).ok());
        add_resource(engine, ResourceSpec{3, "r3", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0, 0,
                                          0, 0, 0});
    }
    // A second restart must still read everything that was acknowledged.
    auto store = open_store(directory);
    FCF_REQUIRE(store.ok());
    const Result<DurableStore::Recovery> recovery = store.value()->recover();
    FCF_REQUIRE_MSG(recovery.ok(), recovery.ok() ? "" : recovery.error().to_string());
    FCF_EQ(recovery.value().torn_tail_bytes, 0U);
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 200);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    FCF_EQ(restored.query_system_status().resource_count, 3U);
}

FCF_TEST(persistence, snapshot_with_a_forward_declared_domain_member_is_recoverable) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        // A boundary may be declared before every member exists; member 9 never appears.
        FCF_REQUIRE(engine.register_domain(make_domain(301, "cd", true, {1, 9})).ok());
        add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 301,
                                          0, 0, 0, 0});
        FCF_REQUIRE(engine.persist_snapshot().ok());
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    const Result<DomainStatusView> view =
        restored.query_domain_status(ContainmentDomainId::from_value(301));
    FCF_REQUIRE(view.ok());
    FCF_EQ(view.value().domain.members.size(), 2U);
    FCF_EQ(view.value().unresolved_members, 1U);
}

FCF_TEST(persistence, journal_replay_restores_domain_membership) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        // Boundaries declared first; the resources join them by reference.
        FCF_REQUIRE(engine.register_domain(make_domain(301, "cd", true, {})).ok());
        FCF_REQUIRE(engine.register_isolation_domain(make_isolation_domain(101, "iso", {})).ok());
        add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 301,
                                          101, 0, 0, 0});
        add_resource(engine, ResourceSpec{2, "r2", ResourceClass::GENERIC, ProtectionClass::STANDARD, 301,
                                          101, 0, 0, 0});
        // A correlated failure boundary declared over resources that already exist.
        FCF_REQUIRE(engine.register_failure_domain(make_failure_domain(201, "fd", {1, 2})).ok());
        // No snapshot: only the journal exists, exactly as after a crash.
    }
    LogicalClock clock;
    Engine restored(make_config(clock));
    const Result<CoordinatorEpoch> recovered = restored.recover_from_store(*store.value(), 100);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    const std::shared_ptr<const RuntimeSnapshot> snapshot = restored.snapshot();
    const Topology& topology = snapshot->topology;
    const IdSet<ResourceId>& containment =
        topology.containment_domains.at(ContainmentDomainId::from_value(301)).members;
    FCF_REQUIRE_MSG(contains(containment, 1) && contains(containment, 2),
                    "the containment boundary lost its members across the restart");
    const IdSet<ResourceId>& isolation =
        topology.isolation_domains.at(IsolationDomainId::from_value(101)).members;
    FCF_REQUIRE_MSG(contains(isolation, 1) && contains(isolation, 2),
                    "the isolation boundary lost its members across the restart");
    FCF_EQ(topology.resources.at(ResourceId::from_value(1)).failure_domain,
           FailureDomainId::from_value(201));
    FCF_EQ(topology.resources.at(ResourceId::from_value(2)).failure_domain,
           FailureDomainId::from_value(201));
}

FCF_TEST(persistence, domain_removal_survives_replay_and_a_later_snapshot) {
    ScratchDirectory scratch;
    auto store = open_store(directory_of(scratch));
    FCF_REQUIRE(store.ok());
    {
        LogicalClock clock;
        Engine engine(make_config(clock));
        FCF_REQUIRE(engine.attach_store(store.value().get()).ok());
        const Result<IsolationDomain> declared =
            engine.register_isolation_domain(make_isolation_domain(101, "iso", {}));
        FCF_REQUIRE(declared.ok());
        add_resource(engine, ResourceSpec{1, "r1", ResourceClass::GENERIC, ProtectionClass::STANDARD, 0,
                                          101, 0, 0, 0});
        FCF_REQUIRE(engine
                        .remove_isolation_domain(IsolationDomainId::from_value(101),
                                                 declared.value().generation)
                        .ok());
    }
    {
        // Crash recovery from the journal alone, then an ordinary snapshot.
        LogicalClock clock;
        Engine second(make_config(clock));
        const Result<CoordinatorEpoch> recovered = second.recover_from_store(*store.value(), 100);
        FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
        FCF_REQUIRE_MSG(!second.snapshot()
                             ->topology.resources.at(ResourceId::from_value(1))
                             .isolation_domain.valid(),
                        "the resource still references the removed boundary");
        FCF_REQUIRE(second.persist_snapshot().ok());
    }
    LogicalClock clock;
    Engine third(make_config(clock));
    const Result<CoordinatorEpoch> recovered = third.recover_from_store(*store.value(), 200);
    FCF_REQUIRE_MSG(recovered.ok(), recovered.ok() ? "" : recovered.error().to_string());
    FCF_EQ(third.query_system_status().resource_count, 1U);
}

FCF_TEST(persistence, concurrent_mutations_reach_the_journal_in_sequence_order) {
    ScratchDirectory scratch;
    DurableStore::Options options;
    options.directory = directory_of(scratch);
    // Ordering, not flush latency, is what this case observes.
    options.flush_on_append = false;
    auto store = DurableStore::open(options);
    FCF_REQUIRE(store.ok());
    LogicalClock clock;
    Engine engine(make_config(clock));
    FCF_REQUIRE(engine.attach_store(store.value().get()).ok());

    constexpr std::uint64_t kThreads = 6U;
    constexpr std::uint64_t kPerThread = 60U;
    std::atomic<std::uint64_t> refused{0};
    std::vector<std::thread> threads;
    for (std::uint64_t thread = 0; thread < kThreads; ++thread) {
        threads.emplace_back([&engine, &refused, thread]() {
            for (std::uint64_t index = 0; index < kPerThread; ++index) {
                ResourceRecord record;
                record.id = ResourceId::from_value(1U + thread * 1000U + index);
                record.name = "r";
                record.state = ResourceOperationalState::ACTIVE;
                record.freshness = EvidenceFreshness::FRESH;
                if (!engine.register_resource(record).ok()) {
                    refused.fetch_add(1);
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    FCF_EQ(refused.load(), 0U);

    // A crash can cut the journal at any byte. Every prefix is replayable only if the
    // records were appended in the order their sequence numbers were assigned.
    std::vector<char> bytes;
    {
        std::ifstream in(store.value()->journal_path(), std::ios::binary);
        FCF_REQUIRE(in.good());
        bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    auto little_endian = [&bytes](std::size_t offset, std::size_t width) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < width; ++i) {
            value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + i])) << (8U * i);
        }
        return value;
    };
    std::size_t offset = 0;
    std::uint64_t previous = 0;
    std::uint64_t records = 0;
    while (offset + 20U <= bytes.size()) {
        const std::uint64_t length = little_endian(offset + 4U, 4U);
        const std::uint64_t sequence = little_endian(offset + 12U, 8U);
        if (previous != 0U) {
            FCF_REQUIRE_MSG(sequence == previous + 1U,
                            "sequence " + std::to_string(sequence) + " was appended after " +
                                std::to_string(previous));
        }
        previous = sequence;
        offset += 12U + static_cast<std::size_t>(length);
        ++records;
    }
    FCF_EQ(offset, bytes.size());
    FCF_REQUIRE(records >= kThreads * kPerThread);
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
