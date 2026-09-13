// Fault Containment Fabric — durable state proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
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

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
