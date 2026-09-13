// Fault Containment Fabric — worker identities and process incarnations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_WORKER_HPP
#define FCF_WORKER_HPP

#include <cstdint>
#include <map>
#include <string>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/evidence.hpp"
#include "fcf/ids.hpp"

namespace fcf {

/// A process identity and a process incarnation are distinct. Every restart
/// creates a fresh WorkerBootId, and the previous incarnation's authority is
/// revoked before the new one may act.
struct WorkerKey {
    WorkerId worker{};
    WorkerBootId boot{};

    friend bool operator==(const WorkerKey&, const WorkerKey&) noexcept = default;
    friend std::strong_ordering operator<=>(const WorkerKey&, const WorkerKey&) noexcept = default;
};

#define FCF_WORKER_STATES(X) \
    X(REGISTERED)            \
    X(ACTIVE)                \
    X(SUSPECT)               \
    X(AUTHORITY_REVOKED)     \
    X(RETIRED)

FCF_DEFINE_ENUM(WorkerState, FCF_WORKER_STATES, RETIRED)

/// True while the incarnation may still hold live authority. A SUSPECT
/// incarnation is deliberately excluded: uncertainty must fail closed, so a
/// suspected-dead worker cannot acknowledge actions or publish current evidence.
[[nodiscard]] constexpr bool holds_live_authority(WorkerState state) noexcept {
    return state == WorkerState::REGISTERED || state == WorkerState::ACTIVE;
}

struct WorkerRecord {
    WorkerKey key{};
    WorkerIncarnation incarnation{};
    CoordinatorEpoch registered_epoch{};
    WorkerState state = WorkerState::REGISTERED;
    EvidenceSequence last_sequence{};
    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
    /// Resources whose current live authority derives from this exact incarnation.
    IdSet<ResourceId> live_authority;
    std::uint64_t registered_at_ms = 0;
    std::uint64_t last_seen_ms = 0;
    std::string endpoint;
    std::string details;
};

/// The whole worker registry: every incarnation ever registered, plus the current
/// boot per worker identity.
struct WorkerRegistry {
    std::map<WorkerKey, WorkerRecord> incarnations;
    std::map<WorkerId, WorkerBootId> current_boot;
    std::map<WorkerId, WorkerIncarnation> current_incarnation;
    /// Monotonic per-worker incarnation counter, bumped on every fresh boot.
    std::map<WorkerId, WorkerIncarnation> last_incarnation;
};

[[nodiscard]] const WorkerRecord* find_incarnation(const WorkerRegistry& registry, WorkerKey key);
[[nodiscard]] const WorkerRecord* find_current_incarnation(const WorkerRegistry& registry,
                                                           WorkerId worker);
/// True only when the boot is the one currently recorded for the worker identity.
[[nodiscard]] bool boot_is_current(const WorkerRegistry& registry, WorkerId worker,
                                   WorkerBootId boot) noexcept;
[[nodiscard]] std::size_t count_live_incarnations(const WorkerRegistry& registry) noexcept;

}  // namespace fcf

#endif  // FCF_WORKER_HPP
