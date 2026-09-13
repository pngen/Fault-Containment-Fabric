// Fault Containment Fabric — the containment runtime implementation.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "blast_radius_internal.hpp"
#include "fcf/detail/sha256.hpp"
#include "state_codec.hpp"

namespace fcf {
namespace {

using Digest = std::array<std::uint8_t, 32>;

[[nodiscard]] std::uint64_t default_clock_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

[[nodiscard]] bool resource_is_contained(const ResourceRecord& record) noexcept {
    return is_contained(record.state) || record.quarantined;
}

struct PendingWrite {
    std::uint64_t sequence = 0;
    std::vector<std::byte> bytes;
};

struct Counters {
    CoordinatorEpoch epoch{};
    TopologyGeneration topology_generation{};
    PolicyGeneration policy_generation{};
    ContainmentGeneration containment_generation{};
    VerificationGeneration verification_generation{};
    ReleaseGeneration release_generation{};
    HistorySequence history_sequence{};
    std::uint64_t next_fault_id = 0;
    std::uint64_t next_action_id = 0;
    std::uint64_t next_degraded_id = 0;
};

void write_counters(detail::ByteWriter& writer, const Counters& counters) {
    detail::wr_id(writer, counters.epoch);
    detail::wr_id(writer, counters.topology_generation);
    detail::wr_id(writer, counters.policy_generation);
    detail::wr_id(writer, counters.containment_generation);
    detail::wr_id(writer, counters.verification_generation);
    detail::wr_id(writer, counters.release_generation);
    detail::wr_id(writer, counters.history_sequence);
    writer.u64(counters.next_fault_id);
    writer.u64(counters.next_action_id);
    writer.u64(counters.next_degraded_id);
}

bool read_counters(detail::ByteReader& reader, Counters& counters) {
    counters.epoch = detail::rd_id<CoordinatorEpoch>(reader);
    counters.topology_generation = detail::rd_id<TopologyGeneration>(reader);
    counters.policy_generation = detail::rd_id<PolicyGeneration>(reader);
    counters.containment_generation = detail::rd_id<ContainmentGeneration>(reader);
    counters.verification_generation = detail::rd_id<VerificationGeneration>(reader);
    counters.release_generation = detail::rd_id<ReleaseGeneration>(reader);
    counters.history_sequence = detail::rd_id<HistorySequence>(reader);
    counters.next_fault_id = reader.u64();
    counters.next_action_id = reader.u64();
    counters.next_degraded_id = reader.u64();
    return reader.ok();
}

[[nodiscard]] ContainmentMechanism default_mechanism_for(const ResourceRecord& record) noexcept {
    switch (record.resource_class) {
        case ResourceClass::WORKER:
        case ResourceClass::PROCESS:
        case ResourceClass::EXECUTION:
        case ResourceClass::ATTEMPT:
            return ContainmentMechanism::LOGICAL_CONTAINMENT;
        default:
            return ContainmentMechanism::RESOURCE_CONTAINMENT;
    }
}

}  // namespace

// --- Implementation state --------------------------------------------------------------

struct Engine::Impl {
    Config config;
    mutable std::shared_mutex mutex;
    RuntimeSnapshot state;
    DurableStore* store = nullptr;
    std::uint64_t durable_sequence = 0;
    bool durability_healthy = true;
    bool shutting_down = false;

    std::map<FaultId, Digest> digest_by_fault;
    std::map<Digest, FaultId> fault_by_digest;
    std::map<ResourceId, ReleaseAssessment> releases;
    /// Authority-loss faults already raised per incarnation, so a repeated report
    /// about the same dead incarnation never produces a second fault.
    std::map<WorkerKey, FaultId> authority_loss_faults;

    Impl() {
        config.clock = &default_clock_ms;
    }

    [[nodiscard]] std::uint64_t now() const {
        return config.clock ? config.clock() : default_clock_ms();
    }

    // --- identifier allocation (caller holds the exclusive lock) ---
    std::uint64_t next_fault = 1;
    std::uint64_t next_action = 1;
    std::uint64_t next_degraded = 1;

    [[nodiscard]] FaultId allocate_fault_id() { return FaultId::from_value(next_fault++); }
    [[nodiscard]] ActionId allocate_action_id() { return ActionId::from_value(next_action++); }
    [[nodiscard]] DegradedModeId allocate_degraded_id() {
        return DegradedModeId::from_value(next_degraded++);
    }

    // --- counters ---
    [[nodiscard]] Counters counters() const {
        Counters out;
        out.epoch = state.epoch;
        out.topology_generation = state.topology_generation;
        out.policy_generation = state.policy_generation;
        out.containment_generation = state.containment_generation;
        out.verification_generation = state.verification_generation;
        out.history_sequence = state.history_sequence;
        out.next_fault_id = next_fault;
        out.next_action_id = next_action;
        out.next_degraded_id = next_degraded;
        return out;
    }

    void apply_counters(const Counters& counters) {
        state.epoch = counters.epoch;
        state.topology_generation = counters.topology_generation;
        state.policy_generation = counters.policy_generation;
        state.containment_generation = counters.containment_generation;
        state.verification_generation = counters.verification_generation;
        state.history_sequence = counters.history_sequence;
        next_fault = counters.next_fault_id;
        next_action = counters.next_action_id;
        next_degraded = counters.next_degraded_id;
    }

    // --- history (caller holds the exclusive lock) ---
    HistoryEvent add_history(HistoryEventType type, std::string detail, std::string authority,
                             ResourceId resource = {}, FaultId fault = {}, ActionId action = {},
                             ContainmentGeneration containment = {},
                             VerificationGeneration verification = {}) {
        HistoryEvent event;
        event.sequence = next_generation(state.history_sequence);
        state.history_sequence = event.sequence;
        event.timestamp_ms = now();
        event.epoch = state.epoch;
        event.type = type;
        event.resource = resource;
        event.fault = fault;
        event.action = action;
        event.containment = containment;
        event.verification = verification;
        event.detail = std::move(detail);
        event.authority = std::move(authority);
        state.history.push_back(event);
        ++state.history_total;
        const std::size_t cap = config.max_history_in_memory;
        if (cap > 0U && state.history.size() > cap + cap / 4U) {
            const std::size_t drop = state.history.size() - cap;
            state.history.erase(state.history.begin(),
                                state.history.begin() + static_cast<std::ptrdiff_t>(drop));
        }
        return event;
    }

    /// Stages a durable journal record. Caller must hold the exclusive lock.
    template <class Body>
    void stage(std::vector<PendingWrite>& pending, detail::DurableEventKind kind, bool has_history,
               const HistoryEvent& history, Body&& body) {
        detail::DurableEvent event;
        event.kind = kind;
        event.has_history = has_history;
        event.history = history;
        detail::ByteWriter writer;
        body(writer);
        if (!writer.ok()) {
            return;
        }
        event.payload = writer.take();

        detail::ByteWriter record_writer;
        detail::write_durable_event(record_writer, event);
        if (!record_writer.ok()) {
            return;
        }
        PendingWrite write;
        write.sequence = ++durable_sequence;
        write.bytes = record_writer.take();
        pending.push_back(std::move(write));
    }

    void stage_counters(std::vector<PendingWrite>& pending) {
        stage(pending, detail::DurableEventKind::COUNTERS, false, HistoryEvent{},
              [this](detail::ByteWriter& writer) { write_counters(writer, counters()); });
    }

    /// Appends and flushes staged records. Never called while holding the state lock.
    Status flush(std::vector<PendingWrite>& pending) {
        if (store == nullptr) {
            return ok_status();
        }
        for (const PendingWrite& write : pending) {
            const Status status = store->append_record(write.sequence, write.bytes);
            if (!status.ok()) {
                std::unique_lock<std::shared_mutex> lock(mutex);
                durability_healthy = false;
                add_history(HistoryEventType::PERSISTENCE_FAULT, status.error().to_string(), {});
                return status;
            }
        }
        return ok_status();
    }

    void rebuild_digest_index() {
        digest_by_fault.clear();
        fault_by_digest.clear();
        for (const auto& entry : state.faults) {
            digest_by_fault[entry.first] = entry.second.evidence.digest;
            fault_by_digest[entry.second.evidence.digest] = entry.first;
        }
    }

    [[nodiscard]] bool has_live_containment_for(ResourceId resource) const {
        for (const auto& entry : state.containments) {
            if (!containment_is_live(entry.second.status)) {
                continue;
            }
            if (id_set_contains(entry.second.mandatory, resource) &&
                !id_set_contains(entry.second.released, resource)) {
                return true;
            }
        }
        return false;
    }
};

// --- Construction ----------------------------------------------------------------------

Engine::Engine(Config config) : impl_(std::make_unique<Impl>()) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    impl_->config = std::move(config);
    if (!impl_->config.clock) {
        impl_->config.clock = &default_clock_ms;
    }
    impl_->state.epoch = impl_->config.initial_epoch.valid() ? impl_->config.initial_epoch
                                                             : CoordinatorEpoch::from_value(1);
    impl_->state.policy = make_default_policy();
    impl_->state.policy_generation = impl_->state.policy.generation;
    impl_->state.topology_generation = TopologyGeneration::from_value(1);
    impl_->state.now_ms = impl_->now();
    impl_->add_history(HistoryEventType::COORDINATOR_STARTED,
                       "runtime constructed at epoch " + to_string(impl_->state.epoch), {});
}

Engine::~Engine() = default;

CoordinatorEpoch Engine::epoch() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return impl_->state.epoch;
}

bool Engine::recovery_incomplete() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    for (const auto& entry : impl_->state.topology.resources) {
        if (entry.second.freshness != EvidenceFreshness::FRESH) {
            return true;
        }
    }
    return false;
}

bool Engine::durability_healthy() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return impl_->durability_healthy;
}

bool Engine::shutting_down() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return impl_->shutting_down;
}

void Engine::shutdown() {
    {
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        if (impl_->shutting_down) {
            return;
        }
        impl_->shutting_down = true;
        impl_->add_history(HistoryEventType::RECOVERY_APPLIED, "shutdown requested", {});
    }
    const Status persisted = persist_snapshot();
    (void)persisted;
}

Status Engine::attach_store(DurableStore* store) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (store == nullptr) {
        impl_->store = nullptr;
        return ok_status();
    }
    if (impl_->store != nullptr && impl_->store != store) {
        return fail(ErrorCode::BUSY, "persist.attach",
                    "a different durable store is already attached to this runtime");
    }
    impl_->store = store;
    // The durable sequence is never reset here: reusing a sequence number would make
    // the journal ambiguous after a restart.
    return ok_status();
}

Result<CoordinatorEpoch> Engine::begin_epoch(std::uint64_t now_ms, std::string reason) {
    std::vector<PendingWrite> pending;
    {
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        impl_->state.epoch = next_generation(impl_->state.epoch);
        impl_->state.now_ms = now_ms;
        // Live authority never survives an epoch advance.
        for (const auto& entry : impl_->state.workers.incarnations) {
            if (holds_live_authority(entry.second.state)) {
                WorkerRecord& worker = impl_->state.workers.incarnations[entry.first];
                worker.state = WorkerState::SUSPECT;
                worker.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
            }
        }
        for (auto& entry : impl_->state.topology.resources) {
            entry.second.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
        }
        for (auto& entry : impl_->state.actions) {
            if (entry.second.status == ActionStatus::DISPATCHED ||
                entry.second.status == ActionStatus::ACKNOWLEDGED ||
                entry.second.status == ActionStatus::AUTHORIZED) {
                entry.second.status = ActionStatus::AMBIGUOUS;
                entry.second.rejection_code = ErrorCode::REVALIDATION_REQUIRED;
                entry.second.rejection_detail = "coordinator epoch advanced before completion";
            }
        }
        const HistoryEvent history = impl_->add_history(
            HistoryEventType::EPOCH_ADVANCED,
            "epoch advanced to " + to_string(impl_->state.epoch) + ": " + reason,
            "CoordinatorEpoch " + to_string(impl_->state.epoch));
        impl_->stage(pending, detail::DurableEventKind::HISTORY, true, history,
                     [](detail::ByteWriter&) {});
        impl_->stage_counters(pending);
        const CoordinatorEpoch result = impl_->state.epoch;
        lock.unlock();
        const Status status = impl_->flush(pending);
        if (!status.ok()) {
            return status.error();
        }
        return result;
    }
}

// --- Topology --------------------------------------------------------------------------

Result<ContainmentDomain> Engine::register_domain(ContainmentDomain domain) {
    if (!domain.id.valid()) {
        return make_error(ErrorCode::INVALID_ID, "domain.register", "domain identity is invalid");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    // A boundary may be declared before the resources that will live inside it.
    // Membership is reconciled when those resources register, and any member that
    // never appears is reported as unresolved rather than silently assumed safe.
    const auto existing = impl_->state.topology.containment_domains.find(domain.id);
    if (existing != impl_->state.topology.containment_domains.end()) {
        return make_error(ErrorCode::DUPLICATE_ID, "domain.register", "containment domain already exists",
                          to_string(domain.id));
    }
    domain.generation = next_generation(impl_->state.topology_generation);
    impl_->state.topology_generation = domain.generation;
    for (const ResourceId member : domain.members) {
        const auto record_it = impl_->state.topology.resources.find(member);
        if (record_it == impl_->state.topology.resources.end()) {
            continue;  // forward declaration
        }
        if (record_it->second.containment_domain.valid() &&
            record_it->second.containment_domain != domain.id) {
            return make_error(ErrorCode::INVALID_DOMAIN_GRAPH, "domain.register",
                              "resource already belongs to another containment domain",
                              to_string(member));
        }
        record_it->second.containment_domain = domain.id;
    }
    const ContainmentDomain stored = domain;
    impl_->state.topology.containment_domains.emplace(stored.id, stored);
    for (const ResourceId member : stored.members) {
        const auto record_it = impl_->state.topology.resources.find(member);
        if (record_it != impl_->state.topology.resources.end()) {
            const ResourceRecord record = record_it->second;
            impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, false, HistoryEvent{},
                         [&record](detail::ByteWriter& writer) {
                             detail::write_resource(writer, record);
                         });
        }
    }
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REGISTERED, "containment domain " + to_string(stored.id) + " " + stored.name,
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_DOMAIN_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_containment_domain(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::update_domain(ContainmentDomain domain, TopologyGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.containment_domains.find(domain.id);
    if (it == impl_->state.topology.containment_domains.end()) {
        return fail(ErrorCode::UNKNOWN_DOMAIN, "domain.update", "containment domain not found",
                    to_string(domain.id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return fail(ErrorCode::STALE_TOPOLOGY_GENERATION, "domain.update",
                    "domain generation has advanced", to_string(it->second.generation));
    }
    for (const ResourceId member : domain.members) {
        if (impl_->state.topology.resources.find(member) == impl_->state.topology.resources.end()) {
            return fail(ErrorCode::INVALID_DOMAIN_GRAPH, "domain.update",
                        "domain references a resource that is not registered", to_string(member));
        }
    }
    const IdSet<ResourceId> previous_members = it->second.members;
    domain.generation = next_generation(impl_->state.topology_generation);
    impl_->state.topology_generation = domain.generation;
    impl_->state.topology.containment_domains[domain.id] = domain;
    for (const ResourceId member : domain.members) {
        impl_->state.topology.resources[member].containment_domain = domain.id;
    }
    for (const ResourceId member : previous_members) {
        if (!id_set_contains(domain.members, member)) {
            ResourceRecord& record = impl_->state.topology.resources[member];
            if (record.containment_domain == domain.id) {
                record.containment_domain = ContainmentDomainId{};
            }
        }
    }
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_UPDATED, "containment domain " + to_string(domain.id) + " updated",
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_DOMAIN_UPSERT, true, history,
                 [&domain](detail::ByteWriter& writer) {
                     detail::write_containment_domain(writer, domain);
                 });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Status Engine::remove_domain(ContainmentDomainId id, TopologyGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.containment_domains.find(id);
    if (it == impl_->state.topology.containment_domains.end()) {
        return fail(ErrorCode::UNKNOWN_DOMAIN, "domain.remove", "containment domain not found",
                    to_string(id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return fail(ErrorCode::STALE_TOPOLOGY_GENERATION, "domain.remove", "domain generation has advanced",
                    to_string(it->second.generation));
    }
    const IdSet<ResourceId> members = it->second.members;
    impl_->state.topology.containment_domains.erase(it);
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    for (const ResourceId member : members) {
        ResourceRecord& record = impl_->state.topology.resources[member];
        if (record.containment_domain == id) {
            record.containment_domain = ContainmentDomainId{};
        }
    }
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REMOVED, "containment domain " + to_string(id) + " removed",
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_DOMAIN_REMOVE, true, history,
                 [id](detail::ByteWriter& writer) { detail::wr_id(writer, id); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Result<IsolationDomain> Engine::register_isolation_domain(IsolationDomain domain) {
    if (!domain.id.valid()) {
        return make_error(ErrorCode::INVALID_ID, "isolation_domain.register", "identity is invalid");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto existing = impl_->state.topology.isolation_domains.find(domain.id);
    if (existing != impl_->state.topology.isolation_domains.end()) {
        return make_error(ErrorCode::DUPLICATE_ID, "isolation_domain.register", "already exists",
                          to_string(domain.id));
    }
    domain.generation = next_generation(impl_->state.topology_generation);
    impl_->state.topology_generation = domain.generation;
    enum_set_normalize(domain.classes);
    for (const ResourceId member : domain.members) {
        const auto record_it = impl_->state.topology.resources.find(member);
        if (record_it != impl_->state.topology.resources.end()) {
            record_it->second.isolation_domain = domain.id;
        }
    }
    const IsolationDomain stored = domain;
    impl_->state.topology.isolation_domains.emplace(stored.id, stored);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REGISTERED, "isolation domain " + to_string(stored.id) + " " + stored.name,
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::ISOLATION_DOMAIN_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_isolation_domain(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::remove_isolation_domain(IsolationDomainId id, TopologyGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.isolation_domains.find(id);
    if (it == impl_->state.topology.isolation_domains.end()) {
        return fail(ErrorCode::UNKNOWN_DOMAIN, "isolation_domain.remove", "not found", to_string(id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return fail(ErrorCode::STALE_TOPOLOGY_GENERATION, "isolation_domain.remove",
                    "generation has advanced", to_string(it->second.generation));
    }
    const IdSet<ResourceId> members = it->second.members;
    impl_->state.topology.isolation_domains.erase(it);
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    for (const ResourceId member : members) {
        ResourceRecord& record = impl_->state.topology.resources[member];
        if (record.isolation_domain == id) {
            record.isolation_domain = IsolationDomainId{};
        }
    }
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REMOVED, "isolation domain " + to_string(id) + " removed",
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::ISOLATION_DOMAIN_REMOVE, true, history,
                 [id](detail::ByteWriter& writer) { detail::wr_id(writer, id); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Result<FailureDomain> Engine::register_failure_domain(FailureDomain domain) {
    if (!domain.id.valid()) {
        return make_error(ErrorCode::INVALID_ID, "failure_domain.register", "identity is invalid");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto existing = impl_->state.topology.failure_domains.find(domain.id);
    if (existing != impl_->state.topology.failure_domains.end()) {
        return make_error(ErrorCode::DUPLICATE_ID, "failure_domain.register", "already exists",
                          to_string(domain.id));
    }
    domain.generation = next_generation(impl_->state.topology_generation);
    impl_->state.topology_generation = domain.generation;
    for (const ResourceId member : domain.members) {
        const auto record_it = impl_->state.topology.resources.find(member);
        if (record_it != impl_->state.topology.resources.end()) {
            record_it->second.failure_domain = domain.id;
        }
    }
    const FailureDomain stored = domain;
    impl_->state.topology.failure_domains.emplace(stored.id, stored);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REGISTERED, "failure domain " + to_string(stored.id) + " " + stored.name,
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::FAILURE_DOMAIN_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_failure_domain(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::remove_failure_domain(FailureDomainId id, TopologyGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.failure_domains.find(id);
    if (it == impl_->state.topology.failure_domains.end()) {
        return fail(ErrorCode::UNKNOWN_DOMAIN, "failure_domain.remove", "not found", to_string(id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return fail(ErrorCode::STALE_TOPOLOGY_GENERATION, "failure_domain.remove",
                    "generation has advanced", to_string(it->second.generation));
    }
    const IdSet<ResourceId> members = it->second.members;
    impl_->state.topology.failure_domains.erase(it);
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    for (const ResourceId member : members) {
        ResourceRecord& record = impl_->state.topology.resources[member];
        if (record.failure_domain == id) {
            record.failure_domain = FailureDomainId{};
        }
    }
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DOMAIN_REMOVED, "failure domain " + to_string(id) + " removed",
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::FAILURE_DOMAIN_REMOVE, true, history,
                 [id](detail::ByteWriter& writer) { detail::wr_id(writer, id); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Result<ResourceRecord> Engine::register_resource(ResourceRecord record) {
    if (!record.id.valid()) {
        return make_error(ErrorCode::INVALID_ID, "resource.register", "resource identity is invalid");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (impl_->state.topology.resources.size() >= impl_->config.max_resources) {
        return make_error(ErrorCode::RESOURCE_EXHAUSTED, "resource.register",
                          "resource ceiling reached");
    }
    if (impl_->state.topology.resources.find(record.id) != impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::DUPLICATE_ID, "resource.register", "resource already registered",
                          to_string(record.id));
    }
    if (record.containment_domain.valid() &&
        impl_->state.topology.containment_domains.find(record.containment_domain) ==
            impl_->state.topology.containment_domains.end()) {
        return make_error(ErrorCode::INVALID_DOMAIN_GRAPH, "resource.register",
                          "unknown containment domain", to_string(record.containment_domain));
    }
    if (record.isolation_domain.valid() &&
        impl_->state.topology.isolation_domains.find(record.isolation_domain) ==
            impl_->state.topology.isolation_domains.end()) {
        return make_error(ErrorCode::INVALID_DOMAIN_GRAPH, "resource.register", "unknown isolation domain",
                          to_string(record.isolation_domain));
    }
    if (record.failure_domain.valid() &&
        impl_->state.topology.failure_domains.find(record.failure_domain) ==
            impl_->state.topology.failure_domains.end()) {
        return make_error(ErrorCode::INVALID_DOMAIN_GRAPH, "resource.register", "unknown failure domain",
                          to_string(record.failure_domain));
    }
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    record.generation = next_generation(record.generation);
    record.updated_at_ms = impl_->now();
    if (record.owner_boot.valid()) {
        // Only a real incarnation may accumulate live authority. Attributing it to a
        // worker that has not registered would manufacture authority out of nothing.
        const auto incarnation =
            impl_->state.workers.incarnations.find(WorkerKey{record.owner_worker, record.owner_boot});
        if (incarnation != impl_->state.workers.incarnations.end()) {
            id_set_insert(incarnation->second.live_authority, record.id);
        }
    }
    // A resource joins every domain it references, so domain membership and resource
    // placement can never drift apart through a second bookkeeping step.
    if (record.containment_domain.valid()) {
        id_set_insert(impl_->state.topology.containment_domains[record.containment_domain].members,
                      record.id);
    }
    if (record.isolation_domain.valid()) {
        id_set_insert(impl_->state.topology.isolation_domains[record.isolation_domain].members,
                      record.id);
    }
    if (record.failure_domain.valid()) {
        id_set_insert(impl_->state.topology.failure_domains[record.failure_domain].members, record.id);
    }
    const ResourceRecord stored = record;
    impl_->state.topology.resources.emplace(stored.id, stored);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::RESOURCE_REGISTERED, "resource " + to_string(stored.id) + " " + stored.name,
        "TopologyGeneration " + to_string(impl_->state.topology_generation), stored.id);
    impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_resource(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Result<ResourceRecord> Engine::update_resource(ResourceRecord record, ResourceGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.resources.find(record.id);
    if (it == impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "resource.update", "resource not found",
                          to_string(record.id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return make_error(ErrorCode::STALE_RESOURCE_GENERATION, "resource.update",
                          "resource generation has advanced", to_string(it->second.generation));
    }
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    record.generation = next_generation(record.generation);
    record.updated_at_ms = impl_->now();
    const ResourceRecord previous = it->second;
    auto move_membership = [&record, &previous](auto& domains, const auto& old_id, const auto& new_id) {
        if (old_id.valid() && old_id != new_id) {
            const auto old_domain = domains.find(old_id);
            if (old_domain != domains.end()) {
                id_set_erase(old_domain->second.members, record.id);
            }
        }
        if (new_id.valid()) {
            const auto new_domain = domains.find(new_id);
            if (new_domain != domains.end()) {
                id_set_insert(new_domain->second.members, record.id);
            }
        }
    };
    move_membership(impl_->state.topology.containment_domains, previous.containment_domain,
                    record.containment_domain);
    move_membership(impl_->state.topology.isolation_domains, previous.isolation_domain,
                    record.isolation_domain);
    move_membership(impl_->state.topology.failure_domains, previous.failure_domain,
                    record.failure_domain);
    const ResourceRecord stored = record;
    impl_->state.topology.resources[stored.id] = stored;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::TOPOLOGY_UPDATED, "resource " + to_string(stored.id) + " updated",
        "TopologyGeneration " + to_string(impl_->state.topology_generation), stored.id);
    impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_resource(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::remove_resource(ResourceId id, ResourceGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.resources.find(id);
    if (it == impl_->state.topology.resources.end()) {
        return fail(ErrorCode::UNKNOWN_RESOURCE, "resource.remove", "resource not found", to_string(id));
    }
    if (!expected.valid() || it->second.generation != expected) {
        return fail(ErrorCode::STALE_RESOURCE_GENERATION, "resource.remove",
                    "resource generation has advanced", to_string(it->second.generation));
    }
    for (const auto& containment : impl_->state.containments) {
        if (containment_is_live(containment.second.status) &&
            id_set_contains(containment.second.mandatory, id)) {
            return fail(ErrorCode::REVALIDATION_REQUIRED, "resource.remove",
                        "resource is a member of a live containment", to_string(id));
        }
    }
    impl_->state.topology.dependencies.rebuild_indexes();
    std::vector<DependencyId> to_remove;
    for (const auto& edge : impl_->state.topology.dependencies.edges) {
        if (edge.second.source == id || edge.second.destination == id) {
            to_remove.push_back(edge.first);
        }
    }
    for (const DependencyId dependency : to_remove) {
        impl_->state.topology.dependencies.erase(dependency);
    }
    const ResourceRecord removed = it->second;
    if (removed.containment_domain.valid()) {
        const auto domain = impl_->state.topology.containment_domains.find(removed.containment_domain);
        if (domain != impl_->state.topology.containment_domains.end()) {
            id_set_erase(domain->second.members, id);
        }
    }
    if (removed.isolation_domain.valid()) {
        const auto domain = impl_->state.topology.isolation_domains.find(removed.isolation_domain);
        if (domain != impl_->state.topology.isolation_domains.end()) {
            id_set_erase(domain->second.members, id);
        }
    }
    if (removed.failure_domain.valid()) {
        const auto domain = impl_->state.topology.failure_domains.find(removed.failure_domain);
        if (domain != impl_->state.topology.failure_domains.end()) {
            id_set_erase(domain->second.members, id);
        }
    }
    impl_->state.topology.resources.erase(it);
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::TOPOLOGY_UPDATED, "resource " + to_string(id) + " removed",
        "TopologyGeneration " + to_string(impl_->state.topology_generation), id);
    impl_->stage(pending, detail::DurableEventKind::RESOURCE_REMOVE, true, history,
                 [id](detail::ByteWriter& writer) { detail::wr_id(writer, id); });
    for (const DependencyId dependency : to_remove) {
        impl_->stage(pending, detail::DurableEventKind::DEPENDENCY_REMOVE, false, HistoryEvent{},
                     [dependency](detail::ByteWriter& writer) { detail::wr_id(writer, dependency); });
    }
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Result<DependencyEdge> Engine::register_dependency(DependencyEdge edge) {
    if (!edge.id.valid()) {
        return make_error(ErrorCode::INVALID_ID, "dependency.register", "identity is invalid");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (impl_->state.topology.dependencies.edges.size() >= impl_->config.max_dependencies) {
        return make_error(ErrorCode::RESOURCE_EXHAUSTED, "dependency.register",
                          "dependency ceiling reached");
    }
    if (edge.source == edge.destination) {
        return make_error(ErrorCode::INVALID_DEPENDENCY, "dependency.register", "self dependency",
                          to_string(edge.source));
    }
    if (impl_->state.topology.resources.find(edge.source) == impl_->state.topology.resources.end() ||
        impl_->state.topology.resources.find(edge.destination) == impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::INVALID_DEPENDENCY, "dependency.register",
                          "dependency endpoints must both be registered resources");
    }
    if (impl_->state.topology.dependencies.edges.find(edge.id) !=
        impl_->state.topology.dependencies.edges.end()) {
        return make_error(ErrorCode::DUPLICATE_ID, "dependency.register", "dependency already exists",
                          to_string(edge.id));
    }
    if (edge.confidence_permille > 1000U) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "dependency.register",
                          "confidence must be at most 1000 permille");
    }
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    edge.generation = next_generation(edge.generation);
    const DependencyEdge stored = edge;
    impl_->state.topology.dependencies.insert(stored);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DEPENDENCY_REGISTERED,
        "dependency " + to_string(stored.id) + " " + std::string(to_string(stored.kind)) + " " +
            to_string(stored.source) + " -> " + to_string(stored.destination),
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::DEPENDENCY_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_dependency(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::remove_dependency(DependencyId id, DependencyGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const DependencyEdge* edge = impl_->state.topology.dependencies.find(id);
    if (edge == nullptr) {
        return fail(ErrorCode::INVALID_DEPENDENCY, "dependency.remove", "dependency not found",
                    to_string(id));
    }
    if (!expected.valid() || edge->generation != expected) {
        return fail(ErrorCode::STALE_TOPOLOGY_GENERATION, "dependency.remove",
                    "dependency generation has advanced", to_string(edge->generation));
    }
    impl_->state.topology.dependencies.erase(id);
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DEPENDENCY_REMOVED, "dependency " + to_string(id) + " removed",
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::DEPENDENCY_REMOVE, true, history,
                 [id](detail::ByteWriter& writer) { detail::wr_id(writer, id); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Status Engine::set_policy(ContainmentPolicy policy) {
    const Status valid = validate_policy(policy);
    if (!valid.ok()) {
        return valid;
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    policy.generation = next_generation(impl_->state.policy_generation);
    impl_->state.policy_generation = policy.generation;
    const ContainmentPolicy stored = policy;
    impl_->state.policy = stored;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::TOPOLOGY_UPDATED, "policy updated to " + stored.name,
        "PolicyGeneration " + to_string(impl_->state.policy_generation));
    impl_->stage(pending, detail::DurableEventKind::POLICY_SET, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_policy(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

ContainmentPolicy Engine::policy() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return impl_->state.policy;
}

// --- Evidence --------------------------------------------------------------------------

Result<ResourceRecord> Engine::publish_resource_evidence(ResourceId id, ResourceGeneration expected,
                                                         EvidenceFreshness freshness,
                                                         EvidenceSequence sequence,
                                                         ContainmentMechanism mechanism,
                                                         std::string source) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.resources.find(id);
    if (it == impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "evidence.publish", "resource not found",
                          to_string(id));
    }
    if (expected.valid() && it->second.generation != expected) {
        return make_error(ErrorCode::STALE_RESOURCE_GENERATION, "evidence.publish",
                          "resource generation has advanced", to_string(it->second.generation));
    }
    if (sequence.valid() && it->second.evidence_sequence.valid() && sequence < it->second.evidence_sequence) {
        return make_error(ErrorCode::STALE_EVIDENCE, "evidence.publish",
                          "evidence sequence is older than the current one",
                          to_string(sequence) + " < " + to_string(it->second.evidence_sequence));
    }
    ResourceRecord& record = it->second;
    record.freshness = freshness;
    record.evidence_sequence = sequence.valid() ? sequence : next_generation(record.evidence_sequence);
    if (mechanism != ContainmentMechanism::NONE) {
        record.mechanism = mechanism;
    }
    // Fresh evidence updates trust, never authority: a contained resource stays
    // contained until an explicit release is authorised.
    if (!record.quarantined && record.state == ResourceOperationalState::UNKNOWN &&
        freshness == EvidenceFreshness::FRESH) {
        record.state = ResourceOperationalState::ACTIVE;
    }
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    record.generation = next_generation(record.generation);
    record.updated_at_ms = impl_->now();
    const ResourceRecord stored = record;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::RESOURCE_EVIDENCE_UPDATED,
        "evidence for " + to_string(id) + " is " + std::string(to_string(freshness)) +
            (source.empty() ? "" : " from " + source),
        "ResourceGeneration " + to_string(stored.generation), id);
    impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_resource(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

// --- Workers ---------------------------------------------------------------------------

Result<WorkerRecord> Engine::register_worker(WorkerId worker, WorkerBootId boot, std::string endpoint,
                                             EvidenceSequence sequence) {
    if (!worker.valid() || !boot.valid()) {
        return make_error(ErrorCode::INVALID_ID, "worker.register",
                          "worker identity and boot identity are both required");
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (impl_->state.workers.incarnations.size() >= impl_->config.max_workers) {
        return make_error(ErrorCode::RESOURCE_EXHAUSTED, "worker.register", "worker ceiling reached");
    }
    const WorkerKey key{worker, boot};
    auto existing = impl_->state.workers.incarnations.find(key);
    if (existing != impl_->state.workers.incarnations.end() &&
        !existing->second.registered_epoch.valid()) {
        // A placeholder created by resource attribution is not a registration.
        impl_->state.workers.incarnations.erase(existing);
        existing = impl_->state.workers.incarnations.end();
    }
    if (existing != impl_->state.workers.incarnations.end()) {
        if (existing->second.endpoint != endpoint) {
            return make_error(ErrorCode::DUPLICATE_CONFLICT, "worker.register",
                              "the same boot identity registered with conflicting details",
                              to_string(boot));
        }
        if (existing->second.state == WorkerState::SUSPECT &&
            existing->second.registered_epoch != impl_->state.epoch) {
            // A surviving incarnation reattaches to a new coordinator epoch. It is
            // re-admitted, but its evidence is not restored: every resource bound to
            // it still requires fresh evidence before it is trusted again.
            existing->second.state = WorkerState::ACTIVE;
            existing->second.registered_epoch = impl_->state.epoch;
            existing->second.last_seen_ms = impl_->now();
            const WorkerRecord reopened = existing->second;
            const HistoryEvent history = impl_->add_history(
                HistoryEventType::WORKER_REGISTERED,
                "incarnation " + to_string(boot) + " reattached at epoch " +
                    to_string(impl_->state.epoch) + "; evidence revalidation still required",
                "CoordinatorEpoch " + to_string(impl_->state.epoch) + "; WorkerBootId " + to_string(boot));
            impl_->stage(pending, detail::DurableEventKind::WORKER_UPSERT, true, history,
                         [&reopened](detail::ByteWriter& writer) {
                             detail::write_worker(writer, reopened);
                         });
            impl_->stage_counters(pending);
            lock.unlock();
            const Status status = impl_->flush(pending);
            if (!status.ok()) {
                return status.error();
            }
            return reopened;
        }
        return existing->second;
    }

    // A fresh incarnation for a worker immediately invalidates the previous one.
    const auto current = impl_->state.workers.current_boot.find(worker);
    if (current != impl_->state.workers.current_boot.end() && current->second != boot) {
        const WorkerKey previous{worker, current->second};
        const auto previous_it = impl_->state.workers.incarnations.find(previous);
        if (previous_it != impl_->state.workers.incarnations.end()) {
            previous_it->second.state = WorkerState::AUTHORITY_REVOKED;
            previous_it->second.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
            for (const ResourceId resource : previous_it->second.live_authority) {
                const auto record_it = impl_->state.topology.resources.find(resource);
                if (record_it != impl_->state.topology.resources.end()) {
                    record_it->second.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
                }
            }
            const HistoryEvent revoked = impl_->add_history(
                HistoryEventType::WORKER_AUTHORITY_REVOKED,
                "previous incarnation " + to_string(previous.boot) + " revoked by fresh boot " +
                    to_string(boot),
                "WorkerBootId " + to_string(previous.boot));
            impl_->stage(pending, detail::DurableEventKind::WORKER_UPSERT, true, revoked,
                         [&previous_it](detail::ByteWriter& writer) {
                             detail::write_worker(writer, previous_it->second);
                         });
        }
    }

    WorkerRecord record;
    record.key = key;
    record.incarnation = next_generation(impl_->state.workers.last_incarnation[worker]);
    impl_->state.workers.last_incarnation[worker] = record.incarnation;
    record.registered_epoch = impl_->state.epoch;
    record.state = WorkerState::ACTIVE;
    record.last_sequence = sequence;
    record.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
    record.registered_at_ms = impl_->now();
    record.last_seen_ms = record.registered_at_ms;
    record.endpoint = std::move(endpoint);
    for (const auto& entry : impl_->state.topology.resources) {
        if (entry.second.owner_boot == boot && entry.second.owner_worker == worker) {
            id_set_insert(record.live_authority, entry.first);
        }
    }
    const WorkerRecord stored = record;
    impl_->state.workers.incarnations[key] = stored;
    impl_->state.workers.current_boot[worker] = boot;

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::WORKER_REGISTERED,
        "worker " + to_string(worker) + " registered as boot " + to_string(boot) + " incarnation " +
            to_string(stored.incarnation),
        "CoordinatorEpoch " + to_string(impl_->state.epoch) + "; WorkerBootId " + to_string(boot));
    impl_->stage(pending, detail::DurableEventKind::WORKER_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_worker(writer, stored); });
    impl_->stage(pending, detail::DurableEventKind::WORKER_CURRENT_BOOT, false, HistoryEvent{},
                 [worker, boot](detail::ByteWriter& writer) {
                     detail::wr_id(writer, worker);
                     detail::wr_id(writer, boot);
                 });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Status Engine::retire_worker(WorkerId worker, WorkerBootId boot, std::string reason) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const WorkerKey key{worker, boot};
    const auto it = impl_->state.workers.incarnations.find(key);
    if (it == impl_->state.workers.incarnations.end()) {
        return fail(ErrorCode::UNKNOWN_WORKER, "worker.retire", "worker incarnation not found",
                    to_string(boot));
    }
    if (it->second.state == WorkerState::RETIRED) {
        return ok_status();  // idempotent
    }
    it->second.state = WorkerState::RETIRED;
    it->second.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
    it->second.live_authority.clear();
    const WorkerRecord stored = it->second;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::WORKER_RETIRED, "worker boot " + to_string(boot) + " retired: " + reason,
        "WorkerBootId " + to_string(boot));
    impl_->stage(pending, detail::DurableEventKind::WORKER_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_worker(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Result<WorkerRecord> Engine::query_worker(WorkerId worker, WorkerBootId boot) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.workers.incarnations.find(WorkerKey{worker, boot});
    if (it == impl_->state.workers.incarnations.end()) {
        return make_error(ErrorCode::UNKNOWN_WORKER, "worker.query", "worker incarnation not found",
                          to_string(boot));
    }
    return it->second;
}

// --- Faults ----------------------------------------------------------------------------

Result<FaultRecord> Engine::publish_fault(FaultEvidence evidence, bool* was_duplicate) {
    if (was_duplicate != nullptr) {
        *was_duplicate = false;
    }
    if (!evidence.subject.valid()) {
        return make_error(ErrorCode::INVALID_ID, "fault.publish", "fault subject is invalid");
    }

    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (impl_->state.faults.size() >= impl_->config.max_faults) {
        return make_error(ErrorCode::RESOURCE_EXHAUSTED, "fault.publish", "fault ceiling reached");
    }
    if (!evidence.id.valid()) {
        evidence.id = impl_->allocate_fault_id();
    }
    if (!evidence.generation.valid()) {
        evidence.generation = FaultGeneration::from_value(1);
    }
    if (!evidence.epoch.valid()) {
        evidence.epoch = impl_->state.epoch;
    }
    if (evidence.epoch != impl_->state.epoch) {
        return make_error(ErrorCode::STALE_EPOCH, "fault.publish", "observation epoch is not current",
                          to_string(evidence.epoch) + " != " + to_string(impl_->state.epoch));
    }
    // The digest covers every containment-relevant field except the identity, and is
    // computed only after normalisation so a republished identical observation is
    // recognised as a duplicate.
    evidence.digest = compute_evidence_digest(evidence);

    const auto duplicate = impl_->fault_by_digest.find(evidence.digest);
    if (duplicate != impl_->fault_by_digest.end()) {
        FaultRecord& existing = impl_->state.faults[duplicate->second];
        ++existing.duplicate_count;
        existing.last_updated_ms = impl_->now();
        if (was_duplicate != nullptr) {
            *was_duplicate = true;
        }
        const FaultRecord copy = existing;
        const HistoryEvent history = impl_->add_history(
            HistoryEventType::FAULT_DUPLICATE_IGNORED,
            "identical duplicate observation ignored for fault " + to_string(copy.evidence.id),
            {}, copy.evidence.subject, copy.evidence.id);
        impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, true, history,
                     [&copy](detail::ByteWriter& writer) { detail::write_fault(writer, copy); });
        lock.unlock();
        const Status status = impl_->flush(pending);
        if (!status.ok()) {
            return status.error();
        }
        return copy;
    }

    const auto by_id = impl_->state.faults.find(evidence.id);
    if (by_id != impl_->state.faults.end()) {
        return make_error(ErrorCode::DUPLICATE_CONFLICT, "fault.publish",
                          "a different observation already uses this fault identity",
                          to_string(evidence.id));
    }
    if (impl_->state.topology.resources.find(evidence.subject) ==
        impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "fault.publish",
                          "fault subject is not a registered resource", to_string(evidence.subject));
    }
    if (evidence.reporter_kind == ReporterKind::WORKER && evidence.reporter_boot.valid()) {
        const WorkerKey key{evidence.reporter_worker, evidence.reporter_boot};
        const auto reporter = impl_->state.workers.incarnations.find(key);
        if (reporter == impl_->state.workers.incarnations.end() ||
            !holds_live_authority(reporter->second.state)) {
            return make_error(ErrorCode::STALE_WORKER_BOOT, "fault.publish",
                              "reporter incarnation holds no live authority",
                              to_string(evidence.reporter_boot));
        }
    }

    FaultRecord record;
    record.evidence = evidence;
    record.state = FaultState::OBSERVED;
    const FaultRule& rule = impl_->state.policy.rule_for(evidence.kind);
    record.severity = rule.severity;
    record.actionable = true;
    record.first_seen_ms = impl_->now();
    record.last_updated_ms = record.first_seen_ms;
    if (rule.mandatory_containment) {
        record.state = FaultState::CONTAINMENT_REQUIRED;
    }
    const FaultRecord stored = record;
    impl_->state.faults.emplace(stored.evidence.id, stored);
    impl_->digest_by_fault[stored.evidence.id] = stored.evidence.digest;
    impl_->fault_by_digest[stored.evidence.digest] = stored.evidence.id;

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::FAULT_PUBLISHED,
        std::string(to_string(stored.evidence.kind)) + " on " + to_string(stored.evidence.subject) +
            " (state " + std::string(to_string(stored.state)) + ")",
        "FaultGeneration " + to_string(stored.evidence.generation) + "; CoordinatorEpoch " +
            to_string(stored.evidence.epoch),
        stored.evidence.subject, stored.evidence.id);
    impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_fault(writer, stored); });
    impl_->stage(pending, detail::DurableEventKind::CURRENT_FAULT, false, HistoryEvent{},
                 [&stored](detail::ByteWriter& writer) { detail::wr_id(writer, stored.evidence.id); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Result<FaultRecord> Engine::supersede_fault(FaultId id, FaultGeneration expected, std::string reason) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.faults.find(id);
    if (it == impl_->state.faults.end()) {
        return make_error(ErrorCode::UNKNOWN_FAULT, "fault.supersede", "fault not found", to_string(id));
    }
    if (!expected.valid() || it->second.evidence.generation != expected) {
        return make_error(ErrorCode::STALE_FAULT_GENERATION, "fault.supersede",
                          "fault generation has advanced",
                          to_string(it->second.evidence.generation));
    }
    if (!is_fault_current(it->second.state) ||
        !is_legal_fault_transition(it->second.state, FaultState::SUPERSEDED)) {
        return make_error(ErrorCode::FAULT_NOT_CURRENT, "fault.supersede",
                          "fault state cannot be superseded",
                          std::string(to_string(it->second.state)));
    }
    it->second.state = FaultState::SUPERSEDED;
    it->second.actionable = false;
    it->second.details = std::move(reason);
    it->second.last_updated_ms = impl_->now();
    it->second.evidence.generation = next_generation(it->second.evidence.generation);
    const FaultRecord stored = it->second;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::FAULT_SUPERSEDED, "fault " + to_string(id) + " superseded: " + stored.details,
        "FaultGeneration " + to_string(stored.evidence.generation), stored.evidence.subject, id);
    impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, true, history,
                 [&stored](detail::ByteWriter& writer) { detail::write_fault(writer, stored); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Result<FaultRecord> Engine::query_fault(FaultId id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.faults.find(id);
    if (it == impl_->state.faults.end()) {
        return make_error(ErrorCode::UNKNOWN_FAULT, "fault.query", "fault not found", to_string(id));
    }
    return it->second;
}

// --- Blast radius ----------------------------------------------------------------------

Result<BlastRadius> Engine::evaluate_containment(FaultId id, FaultGeneration expected) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.faults.find(id);
    if (it == impl_->state.faults.end()) {
        return make_error(ErrorCode::UNKNOWN_FAULT, "containment.evaluate", "fault not found",
                          to_string(id));
    }
    if (expected.valid() && it->second.evidence.generation != expected) {
        return make_error(ErrorCode::STALE_FAULT_GENERATION, "containment.evaluate",
                          "fault generation has advanced",
                          to_string(it->second.evidence.generation));
    }
    BlastRadiusInput input;
    input.topology = &impl_->state.topology;
    input.policy = &impl_->state.policy;
    input.fault = &it->second;
    input.workers = &impl_->state.workers;
    input.epoch = impl_->state.epoch;
    input.generation = next_generation(impl_->state.containment_generation);
    return compute_blast_radius(input);
}

Result<BlastRadius> Engine::query_blast_radius(FaultId id) const {
    return evaluate_containment(id, FaultGeneration{});
}

Result<ContainmentExplanation> Engine::explain(ContainmentGeneration generation) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.containments.find(generation);
    if (it == impl_->state.containments.end()) {
        return make_error(ErrorCode::UNKNOWN_CONTAINMENT, "containment.explain",
                          "containment not found", to_string(generation));
    }
    return it->second.explanation;
}

Result<ContainmentExplanation> Engine::explain_fault(FaultId id) const {
    const Result<BlastRadius> radius = query_blast_radius(id);
    if (!radius.ok()) {
        return radius.error();
    }
    return radius.value().explanation;
}

// --- Containment authorization ---------------------------------------------------------

namespace {

[[nodiscard]] ContainmentActionKind action_for_resource(ContainmentActionKind preferred,
                                                        const ResourceRecord& record) noexcept {
    switch (preferred) {
        case ContainmentActionKind::FENCE_WORKER:
            return record.owner_boot.valid() ? ContainmentActionKind::FENCE_WORKER
                                             : ContainmentActionKind::QUARANTINE_RESOURCE;
        case ContainmentActionKind::FENCE_PROCESS:
            return record.owner_boot.valid() ? ContainmentActionKind::FENCE_PROCESS
                                             : ContainmentActionKind::QUARANTINE_RESOURCE;
        case ContainmentActionKind::FENCE_ATTEMPT:
            return record.resource_class == ResourceClass::ATTEMPT
                       ? ContainmentActionKind::FENCE_ATTEMPT
                       : ContainmentActionKind::QUARANTINE_RESOURCE;
        case ContainmentActionKind::FENCE_DEVICE:
            return (record.resource_class == ResourceClass::DEVICE ||
                    record.resource_class == ResourceClass::ACCELERATOR)
                       ? ContainmentActionKind::FENCE_DEVICE
                       : ContainmentActionKind::QUARANTINE_RESOURCE;
        case ContainmentActionKind::REVOKE_AUTHORITY:
            return record.owner_boot.valid() ? ContainmentActionKind::REVOKE_AUTHORITY
                                             : ContainmentActionKind::QUARANTINE_RESOURCE;
        case ContainmentActionKind::QUARANTINE_DOMAIN:
            return ContainmentActionKind::QUARANTINE_DOMAIN;
        case ContainmentActionKind::DRAIN_DOMAIN:
            return ContainmentActionKind::DRAIN_DOMAIN;
        case ContainmentActionKind::DISABLE_ADMISSION:
            return ContainmentActionKind::DISABLE_ADMISSION;
        case ContainmentActionKind::REQUIRE_REVALIDATION:
            return ContainmentActionKind::REQUIRE_REVALIDATION;
        case ContainmentActionKind::FULL_DOMAIN_ISOLATION:
            return ContainmentActionKind::FULL_DOMAIN_ISOLATION;
        default:
            return ContainmentActionKind::QUARANTINE_RESOURCE;
    }
}

[[nodiscard]] bool outcome_quarantines(ContainmentActionKind kind) noexcept {
    switch (kind) {
        case ContainmentActionKind::QUARANTINE_DOMAIN:
        case ContainmentActionKind::FULL_DOMAIN_ISOLATION:
        case ContainmentActionKind::QUARANTINE_RESOURCE:
            return true;
        default:
            return false;
    }
}

/// Assessment of what degraded operation is currently legal. Permitted and
/// prohibited sets are computed independently and are never allowed to overlap.
[[nodiscard]] DegradedModeAssessment assess_degraded_mode(const RuntimeSnapshot& state,
                                                          const DegradedModeContract* contract,
                                                          DegradedModeId id, std::uint64_t now_ms) {
    DegradedModeAssessment assessment;
    assessment.contract = id;
    assessment.epoch = state.epoch;
    assessment.topology_generation = state.topology_generation;
    assessment.assessed_at_ms = now_ms;
    if (contract != nullptr) {
        assessment.required_redundancy = contract->required_redundancy;
    }

    bool any_live_containment = false;
    for (const auto& entry : state.containments) {
        if (!containment_is_live(entry.second.status)) {
            continue;
        }
        any_live_containment = true;
        for (const ResourceId resource : entry.second.mandatory) {
            if (!id_set_contains(entry.second.released, resource)) {
                id_set_insert(assessment.prohibited, resource);
            }
        }
        for (const ResourceId resource : entry.second.precautionary) {
            id_set_insert(assessment.prohibited, resource);
        }
    }
    if (contract != nullptr) {
        for (const ResourceId resource : contract->prohibited_resources) {
            id_set_insert(assessment.prohibited, resource);
        }
    }

    for (const auto& entry : state.topology.resources) {
        const ResourceRecord& record = entry.second;
        const bool contained = resource_is_contained(record);
        if (contained || id_set_contains(assessment.prohibited, record.id)) {
            id_set_insert(assessment.prohibited, record.id);
        }
        // Revalidation is a property of the evidence, not of containment: a resource
        // whose evidence is not fresh must be revalidated before it can rejoin,
        // whether or not it is also currently fenced.
        if (record.freshness != EvidenceFreshness::FRESH) {
            id_set_insert(assessment.revalidation_required, record.id);
            continue;
        }
        if (contained) {
            continue;
        }
        if (!is_operable(record.state)) {
            continue;
        }
        id_set_insert(assessment.permitted, record.id);
        switch (record.resource_class) {
            case ResourceClass::WORKER:
            case ResourceClass::SERVICE:
            case ResourceClass::SERVICE_REPLICA_GROUP:
                ++assessment.available_redundancy;
                break;
            default:
                break;
        }
    }

    const std::size_t total = state.topology.resources.size();
    assessment.available_capacity_percent =
        total == 0U ? 0U : static_cast<std::uint32_t>((assessment.permitted.size() * 100U) / total);

    if (contract != nullptr &&
        assessment.available_capacity_percent > contract->reduced_capacity_percent) {
        assessment.available_capacity_percent = contract->reduced_capacity_percent;
    }

    if (!degraded_sets_are_disjoint(assessment)) {
        assessment.status = DegradedModeStatus::DEGRADED_UNSAFE;
        assessment.reasons.push_back("permitted and prohibited sets overlap");
        return assessment;
    }
    if (!any_live_containment && assessment.revalidation_required.empty()) {
        assessment.status = DegradedModeStatus::NORMAL;
        assessment.authorized = true;
        assessment.reasons.push_back("no live containment and no outstanding revalidation");
        return assessment;
    }
    if (assessment.permitted.empty()) {
        assessment.status = assessment.revalidation_required.empty()
                                ? DegradedModeStatus::NO_LEGAL_DEGRADED_MODE
                                : DegradedModeStatus::DEGRADED_REVALIDATION_REQUIRED;
        assessment.reasons.push_back("no resource is both permitted and currently proven");
        return assessment;
    }
    if (assessment.available_redundancy < assessment.required_redundancy) {
        assessment.status = DegradedModeStatus::NO_LEGAL_DEGRADED_MODE;
        assessment.reasons.push_back("available redundancy " +
                                     std::to_string(assessment.available_redundancy) +
                                     " is below the required " +
                                     std::to_string(assessment.required_redundancy));
        return assessment;
    }
    if (!assessment.revalidation_required.empty()) {
        assessment.status = DegradedModeStatus::DEGRADED_REVALIDATION_REQUIRED;
        assessment.authorized = true;
        assessment.reasons.push_back(
            std::to_string(assessment.revalidation_required.size()) +
            " resource(s) require revalidation before rejoining degraded operation");
        return assessment;
    }
    assessment.status = DegradedModeStatus::DEGRADED_AUTHORIZED;
    assessment.authorized = true;
    assessment.reasons.push_back("degraded operation authorised within the contract envelope");
    return assessment;
}

}  // namespace

Result<ContainmentRecord> Engine::authorize_containment(FaultId id, FaultGeneration expected) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto fault_it = impl_->state.faults.find(id);
    if (fault_it == impl_->state.faults.end()) {
        return make_error(ErrorCode::UNKNOWN_FAULT, "containment.authorize", "fault not found",
                          to_string(id));
    }
    FaultRecord& fault = fault_it->second;
    if (expected.valid() && fault.evidence.generation != expected) {
        return make_error(ErrorCode::STALE_FAULT_GENERATION, "containment.authorize",
                          "fault generation has advanced",
                          to_string(fault.evidence.generation));
    }
    if (!is_fault_current(fault.state)) {
        return make_error(ErrorCode::FAULT_NOT_CURRENT, "containment.authorize",
                          "fault is no longer current", std::string(to_string(fault.state)));
    }
    if (!fault.actionable) {
        return make_error(ErrorCode::FAULT_NOT_ACTIONABLE, "containment.authorize",
                          "fault is not actionable");
    }
    if (fault.containment_generation.valid()) {
        const auto existing = impl_->state.containments.find(fault.containment_generation);
        if (existing != impl_->state.containments.end() &&
            containment_is_live(existing->second.status)) {
            return make_error(ErrorCode::CONTAINMENT_ALREADY_COMMITTED, "containment.authorize",
                              "a live containment already exists for this fault",
                              to_string(fault.containment_generation));
        }
    }

    BlastRadiusInput input;
    input.topology = &impl_->state.topology;
    input.policy = &impl_->state.policy;
    input.fault = &fault;
    input.workers = &impl_->state.workers;
    input.epoch = impl_->state.epoch;
    input.generation = next_generation(impl_->state.containment_generation);
    Result<BlastRadius> computed = compute_blast_radius(input);
    if (!computed.ok()) {
        return computed.error();
    }
    BlastRadius radius = std::move(computed.value());
    if (radius.budget_exhausted) {
        return make_error(ErrorCode::NO_LEGAL_CONTAINMENT, "containment.authorize",
                          "the computed radius exceeds the configured action budget",
                          std::to_string(radius.mandatory.size()));
    }
    if (!is_legal_fault_transition(fault.state, FaultState::CONTAINMENT_IN_PROGRESS)) {
        return make_error(ErrorCode::FAULT_NOT_ACTIONABLE, "containment.authorize",
                          "illegal fault state transition", std::string(to_string(fault.state)));
    }

    const FaultRule& rule = impl_->state.policy.rule_for(fault.evidence.kind);
    const std::uint64_t now_ms = impl_->now();

    ContainmentRecord record;
    record.generation = radius.generation;
    record.epoch = impl_->state.epoch;
    record.fault = id;
    record.fault_generation = fault.evidence.generation;
    record.policy_generation = impl_->state.policy_generation;
    record.topology_generation = impl_->state.topology_generation;
    record.outcome = radius.recommended;
    record.status = ContainmentStatus::COMMITTED;
    record.mandatory = radius.mandatory;
    record.precautionary = radius.precautionary;
    record.unaffected = radius.unaffected;
    record.unresolved = radius.unresolved;
    record.propagation = radius.propagation;
    record.committed_at_ms = now_ms;
    record.updated_at_ms = now_ms;
    record.explanation = radius.explanation;

    fault.state = FaultState::CONTAINMENT_IN_PROGRESS;
    fault.containment_generation = record.generation;
    fault.last_updated_ms = now_ms;

    std::size_t budget = rule.action_budget;
    if (impl_->state.policy.max_actions_per_containment < budget) {
        budget = impl_->state.policy.max_actions_per_containment;
    }

    auto fence_resource = [&](ResourceId resource_id, bool quarantine) {
        const auto record_it = impl_->state.topology.resources.find(resource_id);
        if (record_it == impl_->state.topology.resources.end()) {
            return;
        }
        ResourceRecord& resource = record_it->second;
        ContainmentMechanism mechanism = default_mechanism_for(resource);
        if (resource.owner_boot.valid()) {
            const auto incarnation = impl_->state.workers.incarnations.find(
                WorkerKey{resource.owner_worker, resource.owner_boot});
            if (incarnation != impl_->state.workers.incarnations.end() &&
                !holds_live_authority(incarnation->second.state)) {
                // The owning incarnation is demonstrably gone, so enforcement is real
                // process containment rather than a purely logical fence.
                mechanism = ContainmentMechanism::PROCESS_CONTAINMENT;
            }
        }
        resource.state = quarantine ? ResourceOperationalState::QUARANTINED
                                    : ResourceOperationalState::FENCED;
        resource.quarantined = true;
        resource.mechanism = mechanism;
        resource.containment_generation = record.generation;
        impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
        resource.generation = next_generation(resource.generation);
        resource.updated_at_ms = now_ms;
        const ResourceRecord frozen = resource;
        impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, false, HistoryEvent{},
                     [&frozen](detail::ByteWriter& writer) {
                         detail::write_resource(writer, frozen);
                     });
    };

    const bool quarantine = outcome_quarantines(record.outcome);
    for (const ResourceId resource_id : radius.mandatory) {
        fence_resource(resource_id, quarantine);
    }
    for (const ResourceId resource_id : radius.precautionary) {
        const auto record_it = impl_->state.topology.resources.find(resource_id);
        if (record_it == impl_->state.topology.resources.end()) {
            continue;
        }
        ResourceRecord& resource = record_it->second;
        if (is_operable(resource.state)) {
            resource.state = ResourceOperationalState::DRAINING;
            impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
            resource.generation = next_generation(resource.generation);
            resource.updated_at_ms = now_ms;
            const ResourceRecord frozen = resource;
            impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, false, HistoryEvent{},
                         [&frozen](detail::ByteWriter& writer) {
                             detail::write_resource(writer, frozen);
                         });
        }
    }

    // Action planning: candidate generation, safety, then authority assignment.
    for (const ResourceId resource_id : radius.mandatory) {
        if (record.actions.size() >= budget) {
            break;
        }
        const auto record_it = impl_->state.topology.resources.find(resource_id);
        if (record_it == impl_->state.topology.resources.end()) {
            continue;
        }
        const ResourceRecord& resource = record_it->second;
        ContainmentAction action;
        action.id = impl_->allocate_action_id();
        action.generation = ActionGeneration::from_value(1);
        action.kind = action_for_resource(record.outcome, resource);
        action.target = resource_id;
        action.target_generation = resource.generation;
        action.domain = resource.containment_domain;
        action.isolation_domain = resource.isolation_domain;
        action.mechanism = resource.mechanism;
        action.status = ActionStatus::PLANNED;
        action.destructive = is_destructive_action(action.kind);
        action.created_at_ms = now_ms;
        action.envelope.epoch = impl_->state.epoch;
        action.envelope.fault = id;
        action.envelope.fault_generation = fault.evidence.generation;
        action.envelope.containment_generation = record.generation;
        action.envelope.policy_generation = impl_->state.policy_generation;
        action.envelope.topology_generation = impl_->state.topology_generation;
        action.envelope.action = action.id;
        action.envelope.action_generation = action.generation;
        action.envelope.worker = resource.owner_worker;
        action.envelope.worker_boot = resource.owner_boot;
        action.envelope.target = resource_id;
        action.envelope.target_generation = resource.generation;
        action.envelope.required_evidence_sequence = resource.evidence_sequence;
        action.envelope.reservation = resource.reservation;
        action.envelope.lease = resource.lease;
        action.envelope.issued_at_ms = now_ms;
        if (resource.containment_domain.valid()) {
            const auto domain =
                impl_->state.topology.containment_domains.find(resource.containment_domain);
            if (domain != impl_->state.topology.containment_domains.end()) {
                for (const ResourceId member : domain->second.members) {
                    const auto member_it = impl_->state.topology.resources.find(member);
                    if (member_it != impl_->state.topology.resources.end()) {
                        action.envelope.required_resource_generations[member] =
                            member_it->second.generation;
                    }
                }
            }
        }
        const ContainmentAction frozen = action;
        impl_->state.actions.emplace(frozen.id, frozen);
        record.actions.push_back(frozen.id);
        impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, false, HistoryEvent{},
                     [&frozen](detail::ByteWriter& writer) { detail::write_action(writer, frozen); });
    }

    const DegradedModeAssessment assessment = assess_degraded_mode(impl_->state, nullptr, {}, now_ms);
    record.degraded_status = assessment.status;

    impl_->state.containment_generation = record.generation;
    impl_->state.containments.emplace(record.generation, record);

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::CONTAINMENT_COMMITTED,
        "containment " + to_string(record.generation) + " committed for fault " + to_string(id) +
            ": mandatory=" + std::to_string(record.mandatory.size()) +
            " precautionary=" + std::to_string(record.precautionary.size()) +
            " unaffected=" + std::to_string(record.unaffected.size()) +
            " unresolved=" + std::to_string(record.unresolved.size()),
        "CoordinatorEpoch " + to_string(record.epoch) + "; ContainmentGeneration " +
            to_string(record.generation),
        fault.evidence.subject, id, {}, record.generation);
    impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_UPSERT, true, history,
                 [&record](detail::ByteWriter& writer) { detail::write_containment(writer, record); });
    impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, false, HistoryEvent{},
                 [&fault](detail::ByteWriter& writer) { detail::write_fault(writer, fault); });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return record;
}

Result<ContainmentRecord> Engine::query_containment(ContainmentGeneration generation) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.containments.find(generation);
    if (it == impl_->state.containments.end()) {
        return make_error(ErrorCode::UNKNOWN_CONTAINMENT, "containment.query", "containment not found",
                          to_string(generation));
    }
    return it->second;
}

std::vector<ContainmentRecord> Engine::list_containments() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    std::vector<ContainmentRecord> out;
    out.reserve(impl_->state.containments.size());
    for (const auto& entry : impl_->state.containments) {
        out.push_back(entry.second);
    }
    return out;
}

Result<ContainmentAction> Engine::query_action(ActionId id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.actions.find(id);
    if (it == impl_->state.actions.end()) {
        return make_error(ErrorCode::UNKNOWN_ACTION, "action.query", "action not found", to_string(id));
    }
    return it->second;
}

// --- Dispatch, acknowledgment and results ----------------------------------------------

namespace {

/// Revalidates every material generation and authority field immediately before a
/// containment action is dispatched. A stale plan is refused, never applied.
[[nodiscard]] ErrorCode revalidate_action(const RuntimeSnapshot& state, const ContainmentRecord& record,
                                          const ContainmentAction& action) {
    const AuthorityEnvelope& envelope = action.envelope;
    if (envelope.epoch != state.epoch) {
        return ErrorCode::STALE_EPOCH;
    }
    if (envelope.action_generation != action.generation) {
        return ErrorCode::STALE_ACTION_GENERATION;
    }
    if (envelope.containment_generation != record.generation) {
        return ErrorCode::STALE_CONTAINMENT_GENERATION;
    }
    if (envelope.policy_generation != state.policy_generation) {
        return ErrorCode::STALE_POLICY_GENERATION;
    }
    if (envelope.topology_generation.valid() && envelope.topology_generation != state.topology_generation) {
        return ErrorCode::STALE_TOPOLOGY_GENERATION;
    }
    const auto resource = state.topology.resources.find(action.target);
    if (resource == state.topology.resources.end()) {
        return ErrorCode::UNKNOWN_RESOURCE;
    }
    if (envelope.target_generation != resource->second.generation) {
        return ErrorCode::STALE_RESOURCE_GENERATION;
    }
    if (envelope.worker_boot.valid() && resource->second.owner_boot != envelope.worker_boot) {
        return ErrorCode::STALE_WORKER_BOOT;
    }
    const auto fault = state.faults.find(record.fault);
    if (fault == state.faults.end()) {
        return ErrorCode::UNKNOWN_FAULT;
    }
    if (fault->second.evidence.generation != envelope.fault_generation) {
        return ErrorCode::STALE_FAULT_GENERATION;
    }
    if (!is_fault_current(fault->second.state)) {
        return ErrorCode::FAULT_NOT_CURRENT;
    }
    for (const auto& required : envelope.required_resource_generations) {
        const auto entry = state.topology.resources.find(required.first);
        if (entry == state.topology.resources.end()) {
            return ErrorCode::UNKNOWN_RESOURCE;
        }
        if (entry->second.generation != required.second) {
            return ErrorCode::STALE_RESOURCE_GENERATION;
        }
    }
    return ErrorCode::OK;
}

}  // namespace

Result<DispatchSummary> Engine::dispatch_containment(ContainmentGeneration generation,
                                                     Executor* executor) {
    DispatchSummary summary;
    summary.containment_generation = generation;
    std::vector<PendingWrite> pending;
    std::vector<ContainmentAction> to_dispatch;

    {
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        if (impl_->shutting_down) {
            return make_error(ErrorCode::SHUTTING_DOWN, "containment.dispatch",
                              "the runtime is shutting down and will not dispatch new actions");
        }
        const auto it = impl_->state.containments.find(generation);
        if (it == impl_->state.containments.end()) {
            return make_error(ErrorCode::UNKNOWN_CONTAINMENT, "containment.dispatch",
                              "containment not found", to_string(generation));
        }
        ContainmentRecord& record = it->second;
        if (!containment_is_live(record.status)) {
            return make_error(ErrorCode::STALE_CONTAINMENT_GENERATION, "containment.dispatch",
                              "containment is no longer live", std::string(to_string(record.status)));
        }
        if (executor == nullptr) {
            return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "containment.dispatch",
                              "no executor is attached");
        }
        const std::uint64_t now_ms = impl_->now();
        for (const ActionId action_id : record.actions) {
            const auto action_it = impl_->state.actions.find(action_id);
            if (action_it == impl_->state.actions.end()) {
                continue;
            }
            ContainmentAction& action = action_it->second;
            if (action.status != ActionStatus::PLANNED && action.status != ActionStatus::AUTHORIZED) {
                continue;
            }
            const ErrorCode refusal = revalidate_action(impl_->state, record, action);
            if (refusal != ErrorCode::OK) {
                action.status = ActionStatus::SUPERSEDED;
                action.rejection_code = refusal;
                action.rejection_detail = "revalidation refused immediately before dispatch";
                summary.refused.push_back(action.id);
                summary.refusals.push_back(to_string(action.id) + ": " + std::string(to_string(refusal)));
                const ContainmentAction frozen = action;
                const HistoryEvent history = impl_->add_history(
                    HistoryEventType::ACTION_REJECTED,
                    "action " + to_string(action.id) + " refused: " + std::string(to_string(refusal)),
                    "ActionGeneration " + to_string(action.generation), action.target, record.fault,
                    action.id, record.generation);
                impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                             [&frozen](detail::ByteWriter& writer) {
                                 detail::write_action(writer, frozen);
                             });
                continue;
            }
            action.status = ActionStatus::AUTHORIZED;
            action.envelope.issued_at_ms = now_ms;
            const ContainmentAction frozen = action;
            to_dispatch.push_back(frozen);
            const HistoryEvent history = impl_->add_history(
                HistoryEventType::ACTION_AUTHORIZED,
                "action " + to_string(action.id) + " " + std::string(to_string(action.kind)) +
                    " authorised for " + to_string(action.target),
                "CoordinatorEpoch " + to_string(action.envelope.epoch) + "; ActionGeneration " +
                    to_string(action.generation),
                action.target, record.fault, action.id, record.generation);
            impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                         [&frozen](detail::ByteWriter& writer) {
                             detail::write_action(writer, frozen);
                         });
        }
        impl_->stage_counters(pending);
    }
    Status status = impl_->flush(pending);

    // The executor is invoked with no internal lock held.
    struct Attempt {
        ContainmentAction action;
        Result<std::string> outcome;
    };
    std::vector<Attempt> attempts;
    attempts.reserve(to_dispatch.size());
    for (const ContainmentAction& action : to_dispatch) {
        Result<std::string> outcome = executor->dispatch(action);
        attempts.push_back(Attempt{action, std::move(outcome)});
    }

    pending.clear();
    {
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        const std::uint64_t now_ms = impl_->now();
        for (Attempt& attempt : attempts) {
            const auto action_it = impl_->state.actions.find(attempt.action.id);
            if (action_it == impl_->state.actions.end()) {
                continue;
            }
            ContainmentAction& action = action_it->second;
            if (action.status != ActionStatus::AUTHORIZED) {
                continue;  // superseded while the executor was running
            }
            if (attempt.outcome.ok()) {
                action.status = ActionStatus::DISPATCHED;
                action.executor_token = attempt.outcome.value();
                action.dispatched_at_ms = now_ms;
                summary.dispatched.push_back(action.id);
                const HistoryEvent history = impl_->add_history(
                    HistoryEventType::ACTION_DISPATCHED,
                    "action " + to_string(action.id) + " dispatched to the executor",
                    "ActionGeneration " + to_string(action.generation), action.target, {}, action.id);
                impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                             [&action](detail::ByteWriter& writer) {
                                 detail::write_action(writer, action);
                             });
            } else {
                action.status = ActionStatus::REJECTED_INFEASIBLE;
                action.rejection_code = attempt.outcome.error().code();
                action.rejection_detail = attempt.outcome.error().to_string();
                summary.refused.push_back(action.id);
                summary.refusals.push_back(to_string(action.id) + ": " +
                                           attempt.outcome.error().to_string());
                const HistoryEvent history = impl_->add_history(
                    HistoryEventType::ACTION_REJECTED,
                    "action " + to_string(action.id) + " not accepted by the executor",
                    "ActionGeneration " + to_string(action.generation), action.target, {}, action.id);
                impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                             [&action](detail::ByteWriter& writer) {
                                 detail::write_action(writer, action);
                             });
            }
        }
        summary.budget_remaining = 0;
        impl_->stage_counters(pending);
    }
    const Status flush_status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    if (!flush_status.ok()) {
        return flush_status.error();
    }
    return summary;
}

Status Engine::record_action_ack(const ActionAcknowledgment& ack) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.actions.find(ack.action);
    if (it == impl_->state.actions.end()) {
        return fail(ErrorCode::UNKNOWN_ACTION, "action.ack", "action not found", to_string(ack.action));
    }
    ContainmentAction& action = it->second;
    if (ack.epoch != impl_->state.epoch) {
        return fail(ErrorCode::STALE_EPOCH, "action.ack", "acknowledgment epoch is not current",
                    to_string(ack.epoch) + " != " + to_string(impl_->state.epoch));
    }
    if (ack.action_generation != action.generation) {
        return fail(ErrorCode::STALE_ACTION_GENERATION, "action.ack",
                    "action generation has advanced", to_string(action.generation));
    }
    if (ack.worker_boot.valid()) {
        const auto incarnation = impl_->state.workers.incarnations.find(
            WorkerKey{ack.worker, ack.worker_boot});
        if (incarnation == impl_->state.workers.incarnations.end()) {
            return fail(ErrorCode::STALE_WORKER_BOOT, "action.ack", "unknown worker incarnation",
                        to_string(ack.worker_boot));
        }
        if (!holds_live_authority(incarnation->second.state)) {
            return fail(ErrorCode::STALE_WORKER_BOOT, "action.ack",
                        "the acknowledging incarnation holds no live authority",
                        to_string(ack.worker_boot));
        }
    }
    if (action.status == ActionStatus::ACKNOWLEDGED || action.status == ActionStatus::RESULT_RECORDED ||
        action.status == ActionStatus::VERIFIED_EFFECTIVE ||
        action.status == ActionStatus::VERIFIED_INEFFECTIVE) {
        return ok_status();  // idempotent duplicate acknowledgment
    }
    if (action.status != ActionStatus::DISPATCHED) {
        return fail(ErrorCode::ACTION_REVALIDATION_FAILED, "action.ack",
                    "only a dispatched action may be acknowledged",
                    std::string(to_string(action.status)));
    }
    // ACKNOWLEDGED is not CONTAINED: no resource state changes here.
    action.status = ActionStatus::ACKNOWLEDGED;
    action.acknowledged_at_ms = impl_->now();
    action.executor_token = ack.executor_token;
    const ContainmentAction frozen = action;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::ACTION_ACKNOWLEDGED,
        "action " + to_string(action.id) + " acknowledged (not yet contained): " + ack.detail,
        "ActionGeneration " + to_string(action.generation), action.target, {}, action.id);
    impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                 [&frozen](detail::ByteWriter& writer) { detail::write_action(writer, frozen); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

Status Engine::record_action_result(const ActionResult& result) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.actions.find(result.action);
    if (it == impl_->state.actions.end()) {
        return fail(ErrorCode::UNKNOWN_ACTION, "action.result", "action not found",
                    to_string(result.action));
    }
    ContainmentAction& action = it->second;
    if (result.epoch != impl_->state.epoch) {
        return fail(ErrorCode::STALE_EPOCH, "action.result", "result epoch is not current",
                    to_string(result.epoch) + " != " + to_string(impl_->state.epoch));
    }
    if (result.action_generation != action.generation) {
        return fail(ErrorCode::STALE_ACTION_GENERATION, "action.result",
                    "action generation has advanced", to_string(action.generation));
    }
    if (result.worker_boot.valid()) {
        const auto incarnation = impl_->state.workers.incarnations.find(
            WorkerKey{result.worker, result.worker_boot});
        if (incarnation == impl_->state.workers.incarnations.end()) {
            return fail(ErrorCode::STALE_WORKER_BOOT, "action.result", "unknown worker incarnation",
                        to_string(result.worker_boot));
        }
        if (!holds_live_authority(incarnation->second.state)) {
            return fail(ErrorCode::STALE_WORKER_BOOT, "action.result",
                        "the reporting incarnation holds no live authority",
                        to_string(result.worker_boot));
        }
    }
    if (action.status == ActionStatus::RESULT_RECORDED ||
        action.status == ActionStatus::VERIFIED_EFFECTIVE ||
        action.status == ActionStatus::VERIFIED_INEFFECTIVE) {
        return ok_status();  // idempotent: an action never commits twice
    }
    if (action.status != ActionStatus::ACKNOWLEDGED && action.status != ActionStatus::DISPATCHED) {
        return fail(ErrorCode::ACTION_REVALIDATION_FAILED, "action.result",
                    "only a dispatched or acknowledged action may report a result",
                    std::string(to_string(action.status)));
    }
    action.status = ActionStatus::RESULT_RECORDED;
    action.completed_at_ms = impl_->now();
    if (result.mechanism != ContainmentMechanism::NONE) {
        action.mechanism = result.mechanism;
    }
    // Record what the executor claims. This is still not proof of effect; only
    // verify_containment() may conclude that containment holds.
    const auto resource_it = impl_->state.topology.resources.find(action.target);
    if (resource_it != impl_->state.topology.resources.end() && result.success) {
        ResourceRecord& resource = resource_it->second;
        if (result.mechanism != ContainmentMechanism::NONE) {
            resource.mechanism = result.mechanism;
        }
        impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
        resource.generation = next_generation(resource.generation);
        const ResourceRecord frozen = resource;
        impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, false, HistoryEvent{},
                     [&frozen](detail::ByteWriter& writer) {
                         detail::write_resource(writer, frozen);
                     });
    }
    const ContainmentAction frozen = action;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::ACTION_RESULT_RECORDED,
        "action " + to_string(action.id) + (result.success ? " reported success" : " reported failure") +
            ": " + result.detail,
        "ActionGeneration " + to_string(action.generation), action.target, {}, action.id);
    impl_->stage(pending, detail::DurableEventKind::ACTION_UPSERT, true, history,
                 [&frozen](detail::ByteWriter& writer) { detail::write_action(writer, frozen); });
    impl_->stage_counters(pending);
    lock.unlock();
    return impl_->flush(pending);
}

// --- Verification ----------------------------------------------------------------------

Result<ContainmentVerification> Engine::verify_containment(ContainmentGeneration generation) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.containments.find(generation);
    if (it == impl_->state.containments.end()) {
        return make_error(ErrorCode::UNKNOWN_CONTAINMENT, "containment.verify", "containment not found",
                          to_string(generation));
    }
    ContainmentRecord& record = it->second;
    if (!containment_is_live(record.status)) {
        return make_error(ErrorCode::STALE_CONTAINMENT_GENERATION, "containment.verify",
                          "containment is no longer live", std::string(to_string(record.status)));
    }

    const std::uint64_t now_ms = impl_->now();
    const RuntimeSnapshot& state = impl_->state;
    ContainmentVerification verification;
    verification.generation = next_generation(state.verification_generation);
    verification.containment_generation = generation;
    verification.epoch = state.epoch;
    verification.policy_generation = state.policy_generation;
    verification.topology_generation = state.topology_generation;
    verification.verified_at_ms = now_ms;
    verification.evidence_sequence = state.topology.resources.empty()
                                         ? EvidenceSequence{}
                                         : state.topology.resources.rbegin()->second.evidence_sequence;

    auto check = [&verification](std::string name, bool passed, std::string detail) {
        verification.findings.push_back(VerificationFinding{std::move(name), passed, std::move(detail)});
        return passed;
    };

    bool envelope_current = record.epoch == state.epoch &&
                            record.policy_generation == state.policy_generation;
    check("authority_envelope_current", envelope_current,
          "containment committed at epoch " + to_string(record.epoch) + " policy " +
              to_string(record.policy_generation) + "; current epoch " + to_string(state.epoch) +
              " policy " + to_string(state.policy_generation));

    std::size_t contained = 0;
    for (const ResourceId resource_id : record.mandatory) {
        const auto resource = state.topology.resources.find(resource_id);
        if (resource == state.topology.resources.end()) {
            verification.unproven.push_back(resource_id);
            continue;
        }
        if (is_contained(resource->second.state) && resource->second.quarantined) {
            verification.proven_contained.push_back(resource_id);
            ++contained;
        } else {
            verification.unproven.push_back(resource_id);
        }
    }
    check("mandatory_resources_contained", contained == record.mandatory.size(),
          std::to_string(contained) + " of " + std::to_string(record.mandatory.size()) +
              " mandatory resources are fenced and quarantined");

    bool authority_revoked = true;
    for (const ResourceId resource_id : record.mandatory) {
        const auto resource = state.topology.resources.find(resource_id);
        if (resource == state.topology.resources.end() || !resource->second.owner_boot.valid()) {
            continue;
        }
        const auto incarnation = state.workers.incarnations.find(
            WorkerKey{resource->second.owner_worker, resource->second.owner_boot});
        if (incarnation == state.workers.incarnations.end()) {
            continue;
        }
        if (holds_live_authority(incarnation->second.state)) {
            authority_revoked = false;
        }
    }
    check("failed_authority_cannot_authorise_new_work", authority_revoked,
          "no contained resource is bound to an incarnation that still holds live authority");

    const auto fault_it = state.faults.find(record.fault);
    const FaultKind contained_fault_kind =
        fault_it != state.faults.end() ? fault_it->second.evidence.kind : FaultKind::UNKNOWN_FAULT;

    bool propagation_continued = false;
    for (const PropagationHop& hop : record.propagation) {
        if (hop.outcome == PropagationOutcome::PROPAGATION_IMPOSSIBLE ||
            hop.outcome == PropagationOutcome::PROPAGATION_BLOCKED) {
            continue;
        }
        const auto destination = state.topology.resources.find(hop.to);
        if (destination == state.topology.resources.end()) {
            continue;
        }
        if (resource_is_contained(destination->second)) {
            continue;
        }
        const DependencyEdge* edge = state.topology.dependencies.find(hop.dependency);
        if (edge != nullptr && edge->freshness == EvidenceFreshness::FRESH &&
            rule_propagates_over(state.policy.rule_for(contained_fault_kind), edge->kind)) {
            propagation_continued = true;
        }
    }
    verification.propagation_continued = propagation_continued;
    verification.propagation_blocked = !propagation_continued;
    check("propagation_paths_severed", !propagation_continued,
          propagation_continued ? "a recorded propagation path is still live"
                                : "every recorded propagation path is severed or blocked");

    const DegradedModeAssessment assessment = assess_degraded_mode(state, nullptr, {}, now_ms);
    bool excludes_quarantined = true;
    for (const ResourceId resource_id : record.mandatory) {
        if (id_set_contains(assessment.permitted, resource_id)) {
            excludes_quarantined = false;
        }
    }
    verification.degraded_mode_valid = degraded_sets_are_disjoint(assessment) && excludes_quarantined;
    check("degraded_mode_excludes_quarantined", verification.degraded_mode_valid,
          "permitted and prohibited degraded-mode sets are disjoint and exclude contained resources");

    std::size_t active_unaffected = 0;
    for (const ResourceId resource_id : record.unaffected) {
        const auto resource = state.topology.resources.find(resource_id);
        if (resource != state.topology.resources.end() && is_operable(resource->second.state)) {
            ++active_unaffected;
        }
    }
    check("unaffected_resources_remain_operational",
          record.unaffected.empty() || active_unaffected > 0,
          std::to_string(active_unaffected) + " of " + std::to_string(record.unaffected.size()) +
              " explicitly unaffected resources remain operable");

    if (fault_it != state.faults.end()) {
        BlastRadiusInput input;
        input.topology = &state.topology;
        input.policy = &state.policy;
        input.fault = &fault_it->second;
        input.workers = &state.workers;
        input.epoch = state.epoch;
        input.generation = record.generation;
        const Result<BlastRadius> recomputed = compute_blast_radius(input);
        if (recomputed.ok()) {
            verification.blast_radius_increased =
                recomputed.value().mandatory.size() > record.mandatory.size();
        }
    }
    check("blast_radius_did_not_increase", !verification.blast_radius_increased,
          verification.blast_radius_increased ? "the recomputed radius is larger than the committed one"
                                              : "the recomputed radius is not larger");

    for (const auto& entry : state.faults) {
        if (entry.first == record.fault || !is_fault_current(entry.second.state)) {
            continue;
        }
        if (id_set_contains(record.mandatory, entry.second.evidence.subject) &&
            entry.second.first_seen_ms >= record.committed_at_ms) {
            verification.secondary_failure = true;
        }
    }
    check("no_secondary_failure_inside_the_radius", !verification.secondary_failure,
          verification.secondary_failure ? "a new current fault appeared inside the contained set"
                                         : "no new current fault appeared inside the contained set");

    std::size_t evidenced_actions = 0;
    for (const ActionId action_id : record.actions) {
        const auto action = state.actions.find(action_id);
        if (action == state.actions.end()) {
            continue;
        }
        if (action->second.status == ActionStatus::RESULT_RECORDED ||
            action->second.status == ActionStatus::VERIFIED_EFFECTIVE ||
            action->second.status == ActionStatus::VERIFIED_INEFFECTIVE) {
            ++evidenced_actions;
        }
    }
    const bool all_actions_evidenced =
        record.actions.empty() || evidenced_actions == record.actions.size();
    check("actions_have_post_action_evidence", all_actions_evidenced,
          std::to_string(evidenced_actions) + " of " + std::to_string(record.actions.size()) +
              " actions have a recorded result");

    if (!envelope_current) {
        verification.outcome = VerificationOutcome::OUTCOME_UNKNOWN;
        verification.summary = "the containment was committed under a superseded authority envelope";
    } else if (verification.secondary_failure) {
        verification.outcome = VerificationOutcome::SECONDARY_FAILURE_CREATED;
        verification.summary = "a secondary failure appeared inside the contained set";
    } else if (!verification.degraded_mode_valid) {
        verification.outcome = VerificationOutcome::DEGRADED_MODE_INVALID;
        verification.summary = "the degraded-mode envelope is not valid for this containment";
    } else if (propagation_continued) {
        verification.outcome = VerificationOutcome::CONTAINMENT_BREACHED;
        verification.summary = "a recorded propagation path is still live";
    } else if (!all_actions_evidenced) {
        verification.outcome = VerificationOutcome::OUTCOME_UNKNOWN;
        verification.summary = "actions are dispatched without fresh post-action evidence";
    } else if (contained == record.mandatory.size()) {
        verification.outcome = VerificationOutcome::CONTAINED;
        verification.summary = "every mandatory resource is fenced, quarantined and evidenced";
    } else if (contained == 0) {
        verification.outcome = VerificationOutcome::NOT_CONTAINED;
        verification.summary = "no mandatory resource is currently fenced";
    } else {
        verification.outcome = VerificationOutcome::PARTIALLY_CONTAINED;
        verification.summary = "only part of the mandatory set is currently fenced";
    }

    record.verified = true;
    record.verification = verification;
    record.verification_generation = verification.generation;
    record.verification_outcome = verification.outcome;
    record.updated_at_ms = now_ms;
    impl_->state.verification_generation = verification.generation;

    switch (verification.outcome) {
        case VerificationOutcome::CONTAINED:
            record.status = ContainmentStatus::VERIFIED_CONTAINED;
            break;
        case VerificationOutcome::PARTIALLY_CONTAINED:
            record.status = ContainmentStatus::PARTIAL;
            break;
        case VerificationOutcome::NOT_CONTAINED:
        case VerificationOutcome::CONTAINMENT_BREACHED:
        case VerificationOutcome::SECONDARY_FAILURE_CREATED:
            record.status = ContainmentStatus::FAILED;
            break;
        default:
            record.status = ContainmentStatus::ENFORCING;
            break;
    }

    if (fault_it != state.faults.end()) {
        FaultRecord& fault = impl_->state.faults[record.fault];
        FaultState target = FaultState::CONTAINED;
        switch (verification.outcome) {
            case VerificationOutcome::PARTIALLY_CONTAINED:
                target = FaultState::CONTAINMENT_PARTIAL;
                break;
            case VerificationOutcome::NOT_CONTAINED:
            case VerificationOutcome::CONTAINMENT_BREACHED:
            case VerificationOutcome::SECONDARY_FAILURE_CREATED:
                target = FaultState::CONTAINMENT_FAILED;
                break;
            default:
                target = FaultState::CONTAINED;
                break;
        }
        if (verification.outcome == VerificationOutcome::OUTCOME_UNKNOWN) {
            target = FaultState::REVALIDATION_REQUIRED;
        }
        if (is_legal_fault_transition(fault.state, target)) {
            fault.state = target;
            fault.verification_generation = verification.generation;
            fault.last_updated_ms = now_ms;
            const FaultRecord frozen = fault;
            impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, false, HistoryEvent{},
                         [&frozen](detail::ByteWriter& writer) {
                             detail::write_fault(writer, frozen);
                         });
        }
    }

    const ContainmentRecord frozen_record = record;
    const HistoryEvent history = impl_->add_history(
        HistoryEventType::CONTAINMENT_VERIFIED,
        "containment " + to_string(generation) + " verification outcome " +
            std::string(to_string(verification.outcome)) + ": " + verification.summary,
        "VerificationGeneration " + to_string(verification.generation),
        record.mandatory.empty() ? ResourceId{} : record.mandatory.front(), record.fault, {},
        generation, verification.generation);
    impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_UPSERT, true, history,
                 [&frozen_record](detail::ByteWriter& writer) {
                     detail::write_containment(writer, frozen_record);
                 });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return verification;
}

Result<ContainmentVerification> Engine::query_verification(ContainmentGeneration generation) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.containments.find(generation);
    if (it == impl_->state.containments.end()) {
        return make_error(ErrorCode::UNKNOWN_CONTAINMENT, "containment.verification",
                          "containment not found", to_string(generation));
    }
    if (!it->second.verified) {
        return make_error(ErrorCode::VERIFICATION_REQUIRED, "containment.verification",
                          "containment has never been verified");
    }
    return it->second.verification;
}

// --- Degraded mode ---------------------------------------------------------------------

Result<DegradedModeAssessment> Engine::authorize_degraded_mode(DegradedModeContract contract) {
    for (const ResourceId resource : contract.prohibited_resources) {
        if (id_set_contains(contract.permitted_resources, resource)) {
            return make_error(ErrorCode::DEGRADED_MODE_FORBIDDEN, "degraded.authorize",
                              "the contract lists a resource as both permitted and prohibited",
                              to_string(resource));
        }
    }
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    for (const ResourceId resource : contract.prohibited_resources) {
        if (impl_->state.topology.resources.find(resource) == impl_->state.topology.resources.end()) {
            return make_error(ErrorCode::UNKNOWN_RESOURCE, "degraded.authorize",
                              "contract references an unknown prohibited resource", to_string(resource));
        }
    }
    for (const ResourceId resource : contract.permitted_resources) {
        if (impl_->state.topology.resources.find(resource) == impl_->state.topology.resources.end()) {
            return make_error(ErrorCode::UNKNOWN_RESOURCE, "degraded.authorize",
                              "contract references an unknown permitted resource", to_string(resource));
        }
    }

    if (!contract.id.valid()) {
        contract.id = impl_->allocate_degraded_id();
    }
    contract.topology_generation = impl_->state.topology_generation;
    contract.containment_generation = impl_->state.containment_generation;
    const std::uint64_t now_ms = impl_->now();

    DegradedModeAssessment assessment =
        assess_degraded_mode(impl_->state, &contract, contract.id, now_ms);
    // Apply the contract allow-list and workload-class restrictions. Anything the
    // contract forbids is moved to the prohibited set, never silently permitted.
    IdSet<ResourceId> filtered;
    for (const ResourceId resource : assessment.permitted) {
        bool allowed = contract.permitted_resources.empty() ||
                       id_set_contains(contract.permitted_resources, resource);
        if (allowed && !contract.legal_workload_classes.empty()) {
            const auto record = impl_->state.topology.resources.find(resource);
            if (record != impl_->state.topology.resources.end()) {
                allowed = enum_set_contains(contract.legal_workload_classes,
                                            record->second.resource_class);
            }
        }
        if (allowed) {
            filtered.push_back(resource);
        } else {
            id_set_insert(assessment.prohibited, resource);
        }
    }
    assessment.permitted = filtered;
    if (!contract.prohibited_resources.empty()) {
        for (const ResourceId resource : contract.prohibited_resources) {
            id_set_erase(assessment.permitted, resource);
            id_set_erase(assessment.revalidation_required, resource);
            id_set_insert(assessment.prohibited, resource);
        }
    }
    const std::size_t total = impl_->state.topology.resources.size();
    assessment.available_capacity_percent =
        total == 0U ? 0U : static_cast<std::uint32_t>((assessment.permitted.size() * 100U) / total);
    if (assessment.available_capacity_percent > contract.reduced_capacity_percent) {
        assessment.available_capacity_percent = contract.reduced_capacity_percent;
    }
    assessment.required_redundancy = contract.required_redundancy;

    if (!degraded_sets_are_disjoint(assessment)) {
        assessment.status = DegradedModeStatus::DEGRADED_UNSAFE;
        assessment.authorized = false;
        assessment.reasons.push_back("contract restrictions produced overlapping sets");
    } else if (assessment.status == DegradedModeStatus::DEGRADED_AUTHORIZED &&
               assessment.available_redundancy < contract.required_redundancy) {
        assessment.status = DegradedModeStatus::NO_LEGAL_DEGRADED_MODE;
        assessment.authorized = false;
        assessment.reasons.push_back("the contract requires redundancy that is not available");
    }

    const DegradedModeContract stored_contract = contract;
    const DegradedModeAssessment stored_assessment = assessment;
    impl_->state.degraded_contracts[stored_contract.id] = stored_contract;
    impl_->state.degraded_modes[stored_assessment.contract] = stored_assessment;

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DEGRADED_AUTHORIZED,
        "degraded mode " + to_string(stored_contract.id) + " assessed " +
            std::string(to_string(stored_assessment.status)) + ": permitted=" +
            std::to_string(stored_assessment.permitted.size()) + " prohibited=" +
            std::to_string(stored_assessment.prohibited.size()) + " revalidation=" +
            std::to_string(stored_assessment.revalidation_required.size()),
        "CoordinatorEpoch " + to_string(impl_->state.epoch) + "; ContainmentGeneration " +
            to_string(impl_->state.containment_generation));
    impl_->stage(pending, detail::DurableEventKind::DEGRADED_UPSERT, true, history,
                 [&stored_contract, &stored_assessment](detail::ByteWriter& writer) {
                     detail::write_degraded_contract(writer, stored_contract);
                     detail::write_degraded(writer, stored_assessment);
                 });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored_assessment;
}

Result<DegradedModeAssessment> Engine::revalidate_degraded_mode(DegradedModeId id) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const auto contract_it = impl_->state.degraded_contracts.find(id);
    if (contract_it == impl_->state.degraded_contracts.end()) {
        return make_error(ErrorCode::NOT_FOUND, "degraded.revalidate", "degraded mode not found",
                          to_string(id));
    }
    DegradedModeContract contract = contract_it->second;
    const std::uint64_t now_ms = impl_->now();
    DegradedModeAssessment assessment = assess_degraded_mode(impl_->state, &contract, id, now_ms);
    IdSet<ResourceId> filtered;
    for (const ResourceId resource : assessment.permitted) {
        bool allowed = contract.permitted_resources.empty() ||
                       id_set_contains(contract.permitted_resources, resource);
        if (allowed && !contract.legal_workload_classes.empty()) {
            const auto record = impl_->state.topology.resources.find(resource);
            if (record != impl_->state.topology.resources.end()) {
                allowed =
                    enum_set_contains(contract.legal_workload_classes, record->second.resource_class);
            }
        }
        if (allowed) {
            filtered.push_back(resource);
        } else {
            id_set_insert(assessment.prohibited, resource);
        }
    }
    assessment.permitted = filtered;
    for (const ResourceId resource : contract.prohibited_resources) {
        id_set_erase(assessment.permitted, resource);
        id_set_insert(assessment.prohibited, resource);
    }
    const std::size_t total = impl_->state.topology.resources.size();
    assessment.available_capacity_percent =
        total == 0U ? 0U : static_cast<std::uint32_t>((assessment.permitted.size() * 100U) / total);
    if (assessment.available_capacity_percent > contract.reduced_capacity_percent) {
        assessment.available_capacity_percent = contract.reduced_capacity_percent;
    }
    assessment.required_redundancy = contract.required_redundancy;
    if (!degraded_sets_are_disjoint(assessment)) {
        assessment.status = DegradedModeStatus::DEGRADED_UNSAFE;
        assessment.authorized = false;
    }
    assessment.topology_generation = impl_->state.topology_generation;
    assessment.epoch = impl_->state.epoch;
    const DegradedModeAssessment stored = assessment;
    impl_->state.degraded_modes[id] = stored;
    impl_->state.degraded_contracts[id] = contract;

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::DEGRADED_REVALIDATED,
        "degraded mode " + to_string(id) + " revalidated as " +
            std::string(to_string(stored.status)),
        "TopologyGeneration " + to_string(impl_->state.topology_generation));
    impl_->stage(pending, detail::DurableEventKind::DEGRADED_UPSERT, true, history,
                 [&contract, &stored](detail::ByteWriter& writer) {
                     detail::write_degraded_contract(writer, contract);
                     detail::write_degraded(writer, stored);
                 });
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return stored;
}

Result<DegradedModeAssessment> Engine::query_degraded_mode(DegradedModeId id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.degraded_modes.find(id);
    if (it == impl_->state.degraded_modes.end()) {
        return make_error(ErrorCode::NOT_FOUND, "degraded.query", "degraded mode not found",
                          to_string(id));
    }
    return it->second;
}

// --- Release ---------------------------------------------------------------------------

namespace {

/// Explicit release criteria. Time passing is never sufficient; every criterion is
/// evaluated against current evidence and current generations.
[[nodiscard]] ReleaseAssessment assess_release(const RuntimeSnapshot& state,
                                               const ReleaseRequest& request, std::uint64_t now_ms) {
    // The assessment is purely evidence-based; time alone never grants a release.
    (void)now_ms;
    ReleaseAssessment assessment;
    assessment.resource = request.resource;
    assessment.containment_generation = request.containment_generation;

    auto criterion = [&assessment](std::string name, bool passed, std::string detail) {
        assessment.criteria.push_back(VerificationFinding{std::move(name), passed, std::move(detail)});
        return passed;
    };

    const auto resource_it = state.topology.resources.find(request.resource);

    const ContainmentRecord* containment = nullptr;
    if (request.containment_generation.valid()) {
        const auto it = state.containments.find(request.containment_generation);
        if (it != state.containments.end()) {
            containment = &it->second;
        }
    } else {
        for (const auto& entry : state.containments) {
            if (containment_is_live(entry.second.status) &&
                (id_set_contains(entry.second.mandatory, request.resource) ||
                 id_set_contains(entry.second.precautionary, request.resource))) {
                containment = &entry.second;
                break;
            }
        }
    }

    const bool known_resource = resource_it != state.topology.resources.end();
    criterion("resource_exists", known_resource,
              known_resource ? "resource is present in the current topology" : "unknown resource");
    const bool known_containment = containment != nullptr;
    criterion("containment_exists", known_containment,
              known_containment ? "a containment covers this resource"
                                : "no containment covers this resource");
    if (!known_resource || !known_containment) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_POLICY;
        assessment.summary = "release criteria cannot be evaluated";
        return assessment;
    }
    assessment.containment_generation = containment->generation;

    const bool generation_current = !request.expected_generation.valid() ||
                                    resource_it->second.generation == request.expected_generation;
    criterion("resource_generation_current", generation_current,
              "request expected " + to_string(request.expected_generation) + ", current " +
                  to_string(resource_it->second.generation));
    if (!generation_current) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_EVIDENCE;
        assessment.summary = "the request targets a superseded resource generation";
        return assessment;
    }

    if (request.requester_boot.valid()) {
        const auto incarnation =
            state.workers.incarnations.find(WorkerKey{request.requester_worker, request.requester_boot});
        const bool live = incarnation != state.workers.incarnations.end() &&
                          holds_live_authority(incarnation->second.state);
        criterion("requester_authority_live", live,
                  live ? "the requesting incarnation holds live authority"
                       : "the requesting incarnation holds no live authority");
        if (!live) {
            assessment.decision = ReleaseDecision::RELEASE_DENIED_AUTHORITY;
            assessment.summary = "a stale worker incarnation requested release";
            return assessment;
        }
    } else {
        criterion("requester_authority_live", true, "coordinator-authorised release");
    }

    const bool explicit_authority = !request.authority.empty();
    criterion("explicit_release_authority", explicit_authority,
              explicit_authority ? "release authority: " + request.authority
                                 : "no release authority supplied");
    if (!explicit_authority) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_AUTHORITY;
        assessment.summary = "release requires an explicit authority";
        return assessment;
    }

    criterion("containment_verified", containment->verified,
              containment->verified ? "the containment has been verified"
                                    : "release before verification is refused");
    if (!containment->verified) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_UNVERIFIED;
        assessment.summary = "containment has not been verified";
        return assessment;
    }

    const bool fresh_evidence = resource_it->second.freshness == EvidenceFreshness::FRESH &&
                                (!request.evidence_sequence.valid() ||
                                 resource_it->second.evidence_sequence >= request.evidence_sequence);
    criterion("fresh_evidence", fresh_evidence,
              "evidence freshness " + std::string(to_string(resource_it->second.freshness)) +
                  ", sequence " + to_string(resource_it->second.evidence_sequence));
    if (!fresh_evidence) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_EVIDENCE;
        assessment.summary = "release requires fresh current evidence";
        return assessment;
    }

    const auto fault_it = state.faults.find(containment->fault);
    const FaultRule& rule = fault_it != state.faults.end()
                                ? state.policy.rule_for(fault_it->second.evidence.kind)
                                : state.policy.fallback;
    criterion("policy_permits_release", rule.allow_release,
              rule.allow_release ? "policy permits release for this fault kind"
                                 : "policy forbids release for this fault kind");
    if (!rule.allow_release) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_POLICY;
        assessment.summary = "policy forbids release";
        return assessment;
    }

    bool other_containment = false;
    for (const auto& entry : state.containments) {
        if (entry.first == containment->generation || !containment_is_live(entry.second.status)) {
            continue;
        }
        if (id_set_contains(entry.second.mandatory, request.resource) &&
            !id_set_contains(entry.second.released, request.resource)) {
            other_containment = true;
        }
    }
    criterion("no_other_live_containment", !other_containment,
              other_containment ? "another live containment still requires this resource fenced"
                                : "no other live containment covers this resource");
    if (other_containment) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_PROPAGATION;
        assessment.summary = "another live containment still requires this resource";
        return assessment;
    }

    const bool effective = containment->verification.outcome == VerificationOutcome::CONTAINED;
    criterion("containment_proven_effective", effective,
              std::string("verification outcome is ") +
                  std::string(to_string(containment->verification.outcome)));
    if (!effective) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_UNVERIFIED;
        assessment.summary = "release requires a containment that was verified as CONTAINED";
        return assessment;
    }

    criterion("no_unresolved_propagation", containment->verification.propagation_blocked,
              containment->verification.propagation_blocked
                  ? "every recorded propagation path is severed"
                  : "a propagation path is still live or unproven");
    if (!containment->verification.propagation_blocked) {
        assessment.decision = ReleaseDecision::RELEASE_DENIED_PROPAGATION;
        assessment.summary = "unresolved propagation prevents release";
        return assessment;
    }

    assessment.decision = ReleaseDecision::RELEASE_GRANTED;
    assessment.granted = true;
    assessment.summary = "release criteria satisfied";
    return assessment;
}

}  // namespace

Result<ReleaseAssessment> Engine::request_release(const ReleaseRequest& request) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return assess_release(impl_->state, request, impl_->now());
}

Result<ReleaseAssessment> Engine::authorize_release(const ReleaseRequest& request) {
    std::vector<PendingWrite> pending;
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    ReleaseAssessment assessment = assess_release(impl_->state, request, impl_->now());
    const ReleaseGeneration release_generation = next_generation(impl_->state.release_generation);
    assessment.generation = release_generation;
    impl_->releases[request.resource] = assessment;

    if (!assessment.granted) {
        const HistoryEvent history = impl_->add_history(
            HistoryEventType::RELEASE_REFUSED,
            "release refused for " + to_string(request.resource) + ": " + assessment.summary,
            "CoordinatorEpoch " + to_string(impl_->state.epoch), request.resource, {}, {},
            assessment.containment_generation);
        impl_->stage(pending, detail::DurableEventKind::HISTORY, true, history,
                     [](detail::ByteWriter&) {});
        impl_->stage_counters(pending);
        lock.unlock();
        const Status status = impl_->flush(pending);
        if (!status.ok()) {
            return status.error();
        }
        return assessment;
    }

    const auto resource_it = impl_->state.topology.resources.find(request.resource);
    if (resource_it == impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "release.authorize", "resource not found",
                          to_string(request.resource));
    }
    ResourceRecord& resource = resource_it->second;
    resource.state = ResourceOperationalState::ACTIVE;
    resource.quarantined = false;
    resource.mechanism = ContainmentMechanism::NONE;
    resource.release_generation = release_generation;
    impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
    resource.generation = next_generation(resource.generation);
    resource.updated_at_ms = impl_->now();
    const ResourceRecord frozen_resource = resource;

    impl_->state.release_generation = release_generation;
    ContainmentRecord* containment = nullptr;
    const auto containment_it = impl_->state.containments.find(assessment.containment_generation);
    if (containment_it != impl_->state.containments.end()) {
        containment = &containment_it->second;
        id_set_insert(containment->released, request.resource);
        id_set_erase(containment->mandatory, request.resource);
        id_set_erase(containment->precautionary, request.resource);
        containment->updated_at_ms = impl_->now();
        bool all_released = true;
        for (const ResourceId mandatory : containment->mandatory) {
            if (!id_set_contains(containment->released, mandatory)) {
                all_released = false;
            }
        }
        if (containment->mandatory.empty()) {
            containment->status = ContainmentStatus::RELEASED;
            containment->released_flag = true;
            const auto fault_it = impl_->state.faults.find(containment->fault);
            if (fault_it != impl_->state.faults.end() &&
                is_legal_fault_transition(fault_it->second.state, FaultState::CLEARED)) {
                fault_it->second.state = FaultState::CLEARED;
                fault_it->second.last_updated_ms = impl_->now();
                const FaultRecord frozen_fault = fault_it->second;
                impl_->stage(pending, detail::DurableEventKind::FAULT_UPSERT, false, HistoryEvent{},
                             [&frozen_fault](detail::ByteWriter& writer) {
                                 detail::write_fault(writer, frozen_fault);
                             });
            }
        }
        (void)all_released;
    }

    const HistoryEvent history = impl_->add_history(
        HistoryEventType::RELEASE_GRANTED,
        "release granted for " + to_string(request.resource) + ": " + assessment.summary,
        "ReleaseGeneration " + to_string(release_generation), request.resource, {}, {},
        assessment.containment_generation);
    impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, true, history,
                 [&frozen_resource](detail::ByteWriter& writer) {
                     detail::write_resource(writer, frozen_resource);
                 });
    if (containment != nullptr) {
        const ContainmentRecord frozen_containment = *containment;
        impl_->stage(pending, detail::DurableEventKind::CONTAINMENT_UPSERT, false, HistoryEvent{},
                     [&frozen_containment](detail::ByteWriter& writer) {
                         detail::write_containment(writer, frozen_containment);
                     });
    }
    impl_->stage_counters(pending);
    lock.unlock();
    const Status status = impl_->flush(pending);
    if (!status.ok()) {
        return status.error();
    }
    return assessment;
}

Result<ReleaseAssessment> Engine::query_release(ResourceId resource) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->releases.find(resource);
    if (it == impl_->releases.end()) {
        return make_error(ErrorCode::NOT_FOUND, "release.query", "no release assessment recorded",
                          to_string(resource));
    }
    return it->second;
}

// --- Queries ---------------------------------------------------------------------------

Result<ResourceStatusView> Engine::query_resource_status(ResourceId id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.resources.find(id);
    if (it == impl_->state.topology.resources.end()) {
        return make_error(ErrorCode::UNKNOWN_RESOURCE, "resource.status", "resource not found",
                          to_string(id));
    }
    ResourceStatusView view;
    view.resource = it->second;
    view.contained = is_contained(view.resource.state);
    view.quarantined = view.resource.quarantined;
    view.operable = is_operable(view.resource.state) && !view.resource.quarantined;
    view.containment_generation = view.resource.containment_generation;
    view.release_permitted = view.resource.freshness == EvidenceFreshness::FRESH &&
                             !impl_->has_live_containment_for(id);
    view.reasons.push_back("state " + std::string(to_string(view.resource.state)));
    view.reasons.push_back("freshness " + std::string(to_string(view.resource.freshness)));
    view.reasons.push_back("mechanism " + std::string(to_string(view.resource.mechanism)));
    if (view.quarantined) {
        view.reasons.push_back(
            "quarantined: no new authorised work may be dispatched until release is granted");
    }
    return view;
}

Result<DomainStatusView> Engine::query_domain_status(ContainmentDomainId id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const auto it = impl_->state.topology.containment_domains.find(id);
    if (it == impl_->state.topology.containment_domains.end()) {
        return make_error(ErrorCode::UNKNOWN_DOMAIN, "domain.status", "containment domain not found",
                          to_string(id));
    }
    DomainStatusView view;
    view.domain = it->second;
    for (const ResourceId member : view.domain.members) {
        const auto resource = impl_->state.topology.resources.find(member);
        if (resource == impl_->state.topology.resources.end()) {
            ++view.unresolved_members;
            continue;
        }
        if (is_contained(resource->second.state) || resource->second.quarantined) {
            ++view.contained_members;
        } else if (is_operable(resource->second.state)) {
            ++view.active_members;
        } else {
            ++view.unresolved_members;
        }
    }
    if (view.domain.co_isolate_members) {
        view.reasons.push_back("members may not be separated by a containment decision");
    }
    return view;
}

SystemStatus Engine::query_system_status() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    const RuntimeSnapshot& state = impl_->state;
    SystemStatus status;
    status.epoch = state.epoch;
    status.topology_generation = state.topology_generation;
    status.policy_generation = state.policy_generation;
    status.containment_generation = state.containment_generation;
    status.verification_generation = state.verification_generation;
    status.history_sequence = state.history_sequence;
    status.resource_count = state.topology.resources.size();
    status.dependency_count = state.topology.dependencies.edges.size();
    status.fault_count = state.faults.size();
    status.worker_incarnation_count = state.workers.incarnations.size();
    for (const auto& entry : state.faults) {
        if (is_fault_current(entry.second.state)) {
            ++status.current_fault_count;
        }
    }
    for (const auto& entry : state.containments) {
        if (containment_is_live(entry.second.status)) {
            ++status.live_containment_count;
        }
    }
    for (const auto& entry : state.workers.incarnations) {
        if (holds_live_authority(entry.second.state)) {
            ++status.live_worker_count;
            status.live_authority_count += entry.second.live_authority.size();
        }
    }
    for (const auto& entry : state.topology.resources) {
        if (entry.second.quarantined || is_contained(entry.second.state)) {
            ++status.quarantined_resource_count;
        }
        if (entry.second.freshness != EvidenceFreshness::FRESH) {
            ++status.unresolved_resource_count;
        }
    }
    const DegradedModeAssessment assessment = assess_degraded_mode(state, nullptr, {}, 0);
    status.degraded_status = assessment.status;
    if (assessment.status == DegradedModeStatus::DEGRADED_REVALIDATION_REQUIRED) {
        status.notes.push_back("revalidation required for " +
                               std::to_string(assessment.revalidation_required.size()) +
                               " resource(s)");
    }
    status.durability_healthy = impl_->durability_healthy;
    status.recovery_incomplete = status.unresolved_resource_count > 0;
    if (state.containments.empty() && status.current_fault_count == 0) {
        status.notes.push_back("no containment is currently active");
    }
    return status;
}

std::shared_ptr<const RuntimeSnapshot> Engine::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return std::make_shared<const RuntimeSnapshot>(impl_->state);
}

std::vector<HistoryEvent> Engine::history(std::uint64_t from_sequence, std::size_t limit) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    std::vector<HistoryEvent> out;
    for (const HistoryEvent& event : impl_->state.history) {
        if (event.sequence.value() < from_sequence) {
            continue;
        }
        out.push_back(event);
        if (limit != 0U && out.size() >= limit) {
            break;
        }
    }
    return out;
}

// --- Worker authority loss -------------------------------------------------------------

Result<ContainmentRecord> Engine::worker_authority_lost(WorkerId worker, WorkerBootId boot,
                                                       FaultKind kind, std::string detail,
                                                       std::uint64_t observation_time_ms) {
    const WorkerKey key{worker, boot};
    ResourceId subject;
    ResourceGeneration subject_generation;
    {
        std::vector<PendingWrite> pending;
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        const auto it = impl_->state.workers.incarnations.find(key);
        if (it == impl_->state.workers.incarnations.end()) {
            return make_error(ErrorCode::UNKNOWN_WORKER, "worker.authority_lost",
                              "worker incarnation not found", to_string(boot));
        }
        const auto current = impl_->state.workers.current_boot.find(worker);
        if (current == impl_->state.workers.current_boot.end() || current->second != boot) {
            return make_error(ErrorCode::STALE_WORKER_BOOT, "worker.authority_lost",
                              "a newer incarnation is already current", to_string(boot));
        }
        const auto already = impl_->authority_loss_faults.find(key);
        if (already != impl_->authority_loss_faults.end()) {
            const auto fault_it = impl_->state.faults.find(already->second);
            if (fault_it != impl_->state.faults.end() &&
                fault_it->second.containment_generation.valid()) {
                const auto containment =
                    impl_->state.containments.find(fault_it->second.containment_generation);
                if (containment != impl_->state.containments.end()) {
                    return containment->second;  // idempotent repeat observation
                }
            }
        }

        if (it->second.state != WorkerState::AUTHORITY_REVOKED) {
            it->second.state = WorkerState::AUTHORITY_REVOKED;
            it->second.last_seen_ms = observation_time_ms;
        }
        it->second.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
        const WorkerRecord frozen_worker = it->second;
        const HistoryEvent revoked = impl_->add_history(
            HistoryEventType::WORKER_AUTHORITY_REVOKED,
            "authority revoked for boot " + to_string(boot) + ": " + detail,
            "WorkerBootId " + to_string(boot));
        impl_->stage(pending, detail::DurableEventKind::WORKER_UPSERT, true, revoked,
                     [&frozen_worker](detail::ByteWriter& writer) {
                         detail::write_worker(writer, frozen_worker);
                     });

        for (const auto& entry : impl_->state.topology.resources) {
            if (entry.second.owner_boot != boot) {
                continue;
            }
            if (!subject.valid() || entry.second.resource_class == ResourceClass::WORKER) {
                subject = entry.first;
            }
        }
        if (!subject.valid()) {
            lock.unlock();
            return make_error(ErrorCode::UNKNOWN_RESOURCE, "worker.authority_lost",
                              "no resource is bound to this worker incarnation, so the blast radius "
                              "cannot be scoped; register the worker's resources before registering "
                              "the worker",
                              to_string(boot));
        }

        const std::uint64_t now_ms = impl_->now();
        std::vector<ResourceId> bound;
        for (const auto& entry : impl_->state.topology.resources) {
            if (entry.second.owner_boot == boot) {
                bound.push_back(entry.first);
            }
        }
        for (const ResourceId resource_id : bound) {
            ResourceRecord& resource = impl_->state.topology.resources[resource_id];
            resource.state = ResourceOperationalState::FENCED;
            resource.quarantined = true;
            // The incarnation is demonstrably gone: this is real process containment.
            resource.mechanism = ContainmentMechanism::PROCESS_CONTAINMENT;
            resource.freshness = EvidenceFreshness::REVALIDATION_REQUIRED;
            impl_->state.topology_generation = next_generation(impl_->state.topology_generation);
            resource.generation = next_generation(resource.generation);
            resource.updated_at_ms = now_ms;
            if (resource_id == subject) {
                subject_generation = resource.generation;
            }
            const ResourceRecord frozen = resource;
            impl_->stage(pending, detail::DurableEventKind::RESOURCE_UPSERT, false, HistoryEvent{},
                         [&frozen](detail::ByteWriter& writer) {
                             detail::write_resource(writer, frozen);
                         });
        }
        impl_->stage_counters(pending);
        lock.unlock();
        const Status status = impl_->flush(pending);
        if (!status.ok()) {
            return status.error();
        }
    }

    FaultEvidence evidence;
    evidence.kind = kind;
    evidence.subject = subject;
    evidence.subject_generation = subject_generation;
    evidence.reporter_kind = ReporterKind::COORDINATOR;
    evidence.epoch = epoch();
    evidence.provenance = EvidenceProvenance::COORDINATOR_OBSERVATION;
    evidence.observation_sequence = EvidenceSequence::from_value(observation_time_ms);
    evidence.publication_time_ms = observation_time_ms;
    evidence.freshness = EvidenceFreshness::FRESH;
    evidence.integrity = IntegrityStatus::VERIFIED;
    evidence.confidence_permille = 1000U;
    evidence.details = detail;

    Result<FaultRecord> fault = publish_fault(evidence);
    if (!fault.ok()) {
        return fault.error();
    }
    const FaultId fault_id = fault.value().evidence.id;
    const FaultGeneration fault_generation = fault.value().evidence.generation;
    {
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        impl_->authority_loss_faults[key] = fault_id;
    }
    return authorize_containment(fault_id, fault_generation);
}

// --- Durability ------------------------------------------------------------------------

Status Engine::persist_snapshot() {
    if (impl_->store == nullptr) {
        return ok_status();
    }
    std::shared_ptr<const RuntimeSnapshot> document;
    std::uint64_t sequence = 0;
    {
        std::shared_lock<std::shared_mutex> lock(impl_->mutex);
        document = std::make_shared<const RuntimeSnapshot>(impl_->state);
        sequence = impl_->durable_sequence;
    }
    detail::ByteWriter writer;
    detail::write_state_document(writer, *document);
    if (!writer.ok()) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.snapshot", "state document encoding failed");
    }
    return impl_->store->save_snapshot(writer.span(), sequence);
}

Result<CoordinatorEpoch> Engine::recover_from_store(DurableStore& store, std::uint64_t now_ms) {
    Result<DurableStore::Recovery> recovered = store.recover();
    if (!recovered.ok()) {
        return recovered.error();
    }
    DurableStore::Recovery& recovery = recovered.value();

    std::uint64_t last_sequence = recovery.snapshot_sequence;
    bool corrupted = false;
    std::string corruption_detail;
    {
        std::vector<PendingWrite> pending;
        std::unique_lock<std::shared_mutex> lock(impl_->mutex);
        impl_->store = &store;
        impl_->state = RuntimeSnapshot{};
        impl_->state.policy = make_default_policy();
        impl_->state.policy_generation = impl_->state.policy.generation;
        impl_->state.topology_generation = TopologyGeneration::from_value(1);
        impl_->state.epoch = impl_->config.initial_epoch.valid() ? impl_->config.initial_epoch
                                                                 : CoordinatorEpoch::from_value(1);
        impl_->releases.clear();
        impl_->authority_loss_faults.clear();
        impl_->next_fault = 1;
        impl_->next_action = 1;
        impl_->next_degraded = 1;

        if (recovery.snapshot_present) {
            detail::ByteReader reader(std::span<const std::byte>(recovery.snapshot_payload.data(),
                                                                 recovery.snapshot_payload.size()));
            RuntimeSnapshot loaded;
            if (!detail::read_state_document(reader, loaded) || !reader.ok() || !reader.at_end()) {
                return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                                  "the durable snapshot is corrupt or was not consumed exactly");
            }
            impl_->state = std::move(loaded);
        }

        auto apply_event = [&](const detail::DurableEvent& event) -> bool {
            detail::ByteReader reader(
                std::span<const std::byte>(event.payload.data(), event.payload.size()));
            switch (event.kind) {
                case detail::DurableEventKind::RESOURCE_UPSERT: {
                    ResourceRecord record;
                    if (!detail::read_resource(reader, record)) {
                        return false;
                    }
                    impl_->state.topology.resources[record.id] = record;
                    break;
                }
                case detail::DurableEventKind::RESOURCE_REMOVE: {
                    const ResourceId id = detail::rd_id<ResourceId>(reader);
                    impl_->state.topology.resources.erase(id);
                    break;
                }
                case detail::DurableEventKind::CONTAINMENT_DOMAIN_UPSERT: {
                    ContainmentDomain domain;
                    if (!detail::read_containment_domain(reader, domain)) {
                        return false;
                    }
                    impl_->state.topology.containment_domains[domain.id] = domain;
                    break;
                }
                case detail::DurableEventKind::CONTAINMENT_DOMAIN_REMOVE: {
                    impl_->state.topology.containment_domains.erase(
                        detail::rd_id<ContainmentDomainId>(reader));
                    break;
                }
                case detail::DurableEventKind::ISOLATION_DOMAIN_UPSERT: {
                    IsolationDomain domain;
                    if (!detail::read_isolation_domain(reader, domain)) {
                        return false;
                    }
                    impl_->state.topology.isolation_domains[domain.id] = domain;
                    break;
                }
                case detail::DurableEventKind::ISOLATION_DOMAIN_REMOVE: {
                    impl_->state.topology.isolation_domains.erase(
                        detail::rd_id<IsolationDomainId>(reader));
                    break;
                }
                case detail::DurableEventKind::FAILURE_DOMAIN_UPSERT: {
                    FailureDomain domain;
                    if (!detail::read_failure_domain(reader, domain)) {
                        return false;
                    }
                    impl_->state.topology.failure_domains[domain.id] = domain;
                    break;
                }
                case detail::DurableEventKind::FAILURE_DOMAIN_REMOVE: {
                    impl_->state.topology.failure_domains.erase(
                        detail::rd_id<FailureDomainId>(reader));
                    break;
                }
                case detail::DurableEventKind::DEPENDENCY_UPSERT: {
                    DependencyEdge edge;
                    if (!detail::read_dependency(reader, edge)) {
                        return false;
                    }
                    impl_->state.topology.dependencies.insert(edge);
                    break;
                }
                case detail::DurableEventKind::DEPENDENCY_REMOVE: {
                    impl_->state.topology.dependencies.erase(detail::rd_id<DependencyId>(reader));
                    break;
                }
                case detail::DurableEventKind::POLICY_SET: {
                    ContainmentPolicy policy;
                    if (!detail::read_policy(reader, policy)) {
                        return false;
                    }
                    impl_->state.policy = policy;
                    impl_->state.policy_generation = policy.generation;
                    break;
                }
                case detail::DurableEventKind::FAULT_UPSERT: {
                    FaultRecord fault;
                    if (!detail::read_fault(reader, fault)) {
                        return false;
                    }
                    impl_->state.faults[fault.evidence.id] = fault;
                    break;
                }
                case detail::DurableEventKind::CONTAINMENT_UPSERT: {
                    ContainmentRecord record;
                    if (!detail::read_containment(reader, record)) {
                        return false;
                    }
                    impl_->state.containments[record.generation] = record;
                    break;
                }
                case detail::DurableEventKind::ACTION_UPSERT: {
                    ContainmentAction action;
                    if (!detail::read_action(reader, action)) {
                        return false;
                    }
                    impl_->state.actions[action.id] = action;
                    break;
                }
                case detail::DurableEventKind::WORKER_UPSERT: {
                    WorkerRecord worker;
                    if (!detail::read_worker(reader, worker)) {
                        return false;
                    }
                    impl_->state.workers.incarnations[worker.key] = worker;
                    break;
                }
                case detail::DurableEventKind::WORKER_CURRENT_BOOT: {
                    const WorkerId worker = detail::rd_id<WorkerId>(reader);
                    const WorkerBootId boot = detail::rd_id<WorkerBootId>(reader);
                    if (!reader.ok()) {
                        return false;
                    }
                    impl_->state.workers.current_boot[worker] = boot;
                    break;
                }
                case detail::DurableEventKind::CURRENT_FAULT: {
                    (void)detail::rd_id<FaultId>(reader);
                    break;
                }
                case detail::DurableEventKind::DEGRADED_UPSERT: {
                    DegradedModeContract contract;
                    DegradedModeAssessment assessment;
                    if (!detail::read_degraded_contract(reader, contract)) {
                        return false;
                    }
                    if (!detail::read_degraded(reader, assessment)) {
                        return false;
                    }
                    impl_->state.degraded_contracts[contract.id] = contract;
                    impl_->state.degraded_modes[assessment.contract] = assessment;
                    break;
                }
                case detail::DurableEventKind::COUNTERS: {
                    Counters counters;
                    if (!read_counters(reader, counters)) {
                        return false;
                    }
                    impl_->apply_counters(counters);
                    break;
                }
                case detail::DurableEventKind::HISTORY: {
                    // The audit record travels in the event envelope, not the payload.
                    if (!event.has_history) {
                        return false;
                    }
                    impl_->state.history.push_back(event.history);
                    ++impl_->state.history_total;
                    if (impl_->state.history_sequence < event.history.sequence) {
                        impl_->state.history_sequence = event.history.sequence;
                    }
                    break;
                }
                case detail::DurableEventKind::RECOVERY_MARK:
                    break;
            }
            if (!reader.ok()) {
                return false;
            }
            if (!event.payload.empty() && !reader.at_end()) {
                // Trailing bytes inside a record mean the record does not decode cleanly.
                return false;
            }
            return true;
        };

        for (std::size_t index = 0; index < recovery.journal_records.size(); ++index) {
            detail::DurableEvent event;
            if (!detail::decode_durable_event(recovery.journal_records[index], event)) {
                corrupted = true;
                corruption_detail = "journal record " + std::to_string(index) + " does not decode";
                break;
            }
            if (!apply_event(event)) {
                corrupted = true;
                corruption_detail = "journal record " + std::to_string(index) + " (sequence " +
                                    std::to_string(recovery.journal_sequences[index]) + ", kind " +
                                    std::string(to_string(event.kind)) + ", " +
                                    std::to_string(event.payload.size()) + " payload bytes) is invalid";
                break;
            }
            last_sequence = recovery.journal_sequences[index];
        }

        if (!corrupted) {
            // Derive the monotonic counters from the recovered state as a safety net.
            for (const auto& entry : impl_->state.faults) {
                if (entry.first.value() >= impl_->next_fault) {
                    impl_->next_fault = entry.first.value() + 1U;
                }
            }
            for (const auto& entry : impl_->state.actions) {
                if (entry.first.value() >= impl_->next_action) {
                    impl_->next_action = entry.first.value() + 1U;
                }
            }
            for (const auto& entry : impl_->state.degraded_modes) {
                if (entry.first.value() >= impl_->next_degraded) {
                    impl_->next_degraded = entry.first.value() + 1U;
                }
            }
            for (const auto& entry : impl_->state.containments) {
                if (entry.first > impl_->state.containment_generation) {
                    impl_->state.containment_generation = entry.first;
                }
                if (entry.second.verification_generation > impl_->state.verification_generation) {
                    impl_->state.verification_generation = entry.second.verification_generation;
                }
            }
            for (const auto& entry : impl_->state.workers.incarnations) {
                impl_->state.workers.last_incarnation[entry.first.worker] =
                    std::max(impl_->state.workers.last_incarnation[entry.first.worker],
                             entry.second.incarnation);
                if (impl_->state.workers.current_boot.find(entry.first.worker) ==
                    impl_->state.workers.current_boot.end()) {
                    impl_->state.workers.current_boot[entry.first.worker] = entry.first.boot;
                }
            }
            impl_->rebuild_digest_index();
            impl_->durable_sequence = last_sequence;
            impl_->state.now_ms = now_ms;
            impl_->state.history.shrink_to_fit();
            if (recovery.torn_tail_bytes != 0) {
                impl_->add_history(HistoryEventType::RECOVERY_APPLIED,
                                   "discarded " + std::to_string(recovery.torn_tail_bytes) +
                                       " torn journal bytes from the last crash",
                                   {});
            }
            impl_->add_history(HistoryEventType::RECOVERY_APPLIED,
                               "recovered durable state at epoch " + to_string(impl_->state.epoch) +
                                   "; snapshot=" + (recovery.snapshot_present ? "yes" : "no") +
                                   " journal records applied=" +
                                   std::to_string(recovery.journal_records_applied),
                               {});
            const HistoryEvent history = impl_->state.history.back();
            impl_->stage(pending, detail::DurableEventKind::RECOVERY_MARK, true, history,
                         [](detail::ByteWriter&) {});
            impl_->stage_counters(pending);
            lock.unlock();
            const Status status = impl_->flush(pending);
            if (!status.ok()) {
                return status.error();
            }
        }
    }

    if (corrupted) {
        return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                          "durable journal cannot be replayed: " + corruption_detail);
    }
    return begin_epoch(now_ms, "coordinator restart; live authority requires revalidation");
}

}  // namespace fcf
