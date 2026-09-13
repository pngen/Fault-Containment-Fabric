// Fault Containment Fabric — typed fault taxonomy, evidence and fault state.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_FAULT_HPP
#define FCF_FAULT_HPP

#include <array>
#include <cstdint>
#include <string>

#include "fcf/detail/enum_macro.hpp"
#include "fcf/domain.hpp"
#include "fcf/ids.hpp"

namespace fcf {

#define FCF_FAULT_KINDS(X)               \
    X(PROCESS_DEATH)                     \
    X(PROCESS_UNRESPONSIVE)              \
    X(WORKER_AUTHORITY_LOST)             \
    X(DEVICE_FAILURE)                    \
    X(DEVICE_UNAVAILABLE)                \
    X(DEVICE_RESET)                      \
    X(MEMORY_INTEGRITY_FAILURE)          \
    X(PERSISTENCE_CORRUPTION)            \
    X(TRANSPORT_PARTITION)               \
    X(TRANSPORT_CORRUPTION)              \
    X(CONTROL_PLANE_LOSS)                \
    X(COORDINATOR_RESTART)               \
    X(STALE_AUTHORITY)                   \
    X(RESOURCE_EXHAUSTION)               \
    X(THERMAL_VIOLATION)                 \
    X(POWER_VIOLATION)                   \
    X(TOPOLOGY_INCONSISTENCY)            \
    X(DEPENDENCY_FAILURE)                \
    X(HEALTH_DEGRADED)                   \
    X(SECURITY_ISOLATION_REQUEST)        \
    X(ADMINISTRATIVE_QUARANTINE)         \
    X(UNKNOWN_FAULT)

FCF_DEFINE_ENUM(FaultKind, FCF_FAULT_KINDS, UNKNOWN_FAULT)

#define FCF_FAULT_STATES(X)          \
    X(OBSERVED)                      \
    X(SUSPECTED)                     \
    X(CONFIRMED)                     \
    X(CONTAINMENT_REQUIRED)          \
    X(CONTAINMENT_IN_PROGRESS)       \
    X(CONTAINED)                     \
    X(CONTAINMENT_PARTIAL)           \
    X(CONTAINMENT_FAILED)            \
    X(REVALIDATION_REQUIRED)         \
    X(CLEARED)                       \
    X(SUPERSEDED)

FCF_DEFINE_ENUM(FaultState, FCF_FAULT_STATES, SUPERSEDED)

/// Legal fault state transitions. Anything not listed is rejected, so a fault can
/// never jump from CLEARED back to CONTAINED, nor be re-opened without a fresh
/// observation.
[[nodiscard]] constexpr bool is_legal_fault_transition(FaultState from, FaultState to) noexcept {
    if (from == to) {
        return true;
    }
    switch (from) {
        case FaultState::OBSERVED:
            return to == FaultState::SUSPECTED || to == FaultState::CONFIRMED ||
                   to == FaultState::CONTAINMENT_REQUIRED || to == FaultState::SUPERSEDED ||
                   to == FaultState::CLEARED || to == FaultState::REVALIDATION_REQUIRED;
        case FaultState::SUSPECTED:
            return to == FaultState::CONFIRMED || to == FaultState::CONTAINMENT_REQUIRED ||
                   to == FaultState::CLEARED || to == FaultState::SUPERSEDED ||
                   to == FaultState::REVALIDATION_REQUIRED;
        case FaultState::CONFIRMED:
            return to == FaultState::CONTAINMENT_REQUIRED || to == FaultState::CONTAINMENT_IN_PROGRESS ||
                   to == FaultState::CLEARED || to == FaultState::SUPERSEDED ||
                   to == FaultState::REVALIDATION_REQUIRED;
        case FaultState::CONTAINMENT_REQUIRED:
            return to == FaultState::CONTAINMENT_IN_PROGRESS || to == FaultState::CONTAINED ||
                   to == FaultState::CONTAINMENT_PARTIAL || to == FaultState::CONTAINMENT_FAILED ||
                   to == FaultState::REVALIDATION_REQUIRED || to == FaultState::SUPERSEDED;
        case FaultState::CONTAINMENT_IN_PROGRESS:
            return to == FaultState::CONTAINED || to == FaultState::CONTAINMENT_PARTIAL ||
                   to == FaultState::CONTAINMENT_FAILED || to == FaultState::REVALIDATION_REQUIRED ||
                   to == FaultState::SUPERSEDED;
        case FaultState::CONTAINED:
            return to == FaultState::CONTAINMENT_PARTIAL || to == FaultState::CONTAINMENT_FAILED ||
                   to == FaultState::REVALIDATION_REQUIRED || to == FaultState::CLEARED ||
                   to == FaultState::SUPERSEDED;
        case FaultState::CONTAINMENT_PARTIAL:
            return to == FaultState::CONTAINED || to == FaultState::CONTAINMENT_FAILED ||
                   to == FaultState::CONTAINMENT_IN_PROGRESS || to == FaultState::REVALIDATION_REQUIRED ||
                   to == FaultState::SUPERSEDED;
        case FaultState::CONTAINMENT_FAILED:
            return to == FaultState::CONTAINMENT_IN_PROGRESS || to == FaultState::CONTAINMENT_REQUIRED ||
                   to == FaultState::REVALIDATION_REQUIRED || to == FaultState::SUPERSEDED;
        case FaultState::REVALIDATION_REQUIRED:
            return to == FaultState::CONFIRMED || to == FaultState::CONTAINMENT_REQUIRED ||
                   to == FaultState::CONTAINED || to == FaultState::CLEARED ||
                   to == FaultState::SUPERSEDED;
        case FaultState::CLEARED:
            return to == FaultState::SUPERSEDED;
        case FaultState::SUPERSEDED:
            return false;
    }
    return false;
}

/// True while the fault still governs current containment decisions.
[[nodiscard]] constexpr bool is_fault_current(FaultState state) noexcept {
    switch (state) {
        case FaultState::CLEARED:
        case FaultState::SUPERSEDED:
            return false;
        default:
            return true;
    }
}

#define FCF_FAULT_SEVERITIES(X) \
    X(LOW)                     \
    X(MEDIUM)                  \
    X(HIGH)                    \
    X(CRITICAL)

FCF_DEFINE_ENUM(FaultSeverity, FCF_FAULT_SEVERITIES, CRITICAL)

#define FCF_REPORTER_KINDS(X) \
    X(WORKER)                 \
    X(COORDINATOR)            \
    X(OPERATOR)               \
    X(SYNTHETIC_INJECTOR)     \
    X(DERIVED)

FCF_DEFINE_ENUM(ReporterKind, FCF_REPORTER_KINDS, DERIVED)

/// The observation itself. Every field needed to decide whether the evidence may
/// still be trusted is carried explicitly.
struct FaultEvidence {
    FaultId id{};
    FaultGeneration generation{};
    FaultKind kind = FaultKind::UNKNOWN_FAULT;

    ResourceId subject{};
    ResourceGeneration subject_generation{};

    ReporterKind reporter_kind = ReporterKind::COORDINATOR;
    WorkerId reporter_worker{};
    WorkerBootId reporter_boot{};

    CoordinatorEpoch epoch{};
    EvidenceProvenance provenance = EvidenceProvenance::UNKNOWN;
    EvidenceSequence observation_sequence{};
    std::uint64_t publication_time_ms = 0;
    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
    IntegrityStatus integrity = IntegrityStatus::UNVERIFIED;
    std::uint16_t confidence_permille = 1000U;
    std::string details;

    /// SHA-256 over the canonical encoding of every field above. Two observations
    /// with the same identity but different contents can never be silently merged.
    std::array<std::uint8_t, 32> digest{};
};

struct FaultRecord {
    FaultEvidence evidence;
    FaultState state = FaultState::OBSERVED;
    FaultSeverity severity = FaultSeverity::MEDIUM;
    ContainmentGeneration containment_generation{};
    std::uint64_t first_seen_ms = 0;
    std::uint64_t last_updated_ms = 0;
    bool actionable = true;
    std::uint32_t duplicate_count = 0;
    VerificationGeneration verification_generation{};
    std::string details;
};

/// Canonical digest of the containment-relevant content of an observation.
[[nodiscard]] std::array<std::uint8_t, 32> compute_evidence_digest(const FaultEvidence& evidence);

/// Hex rendering of a fault's evidence digest.
[[nodiscard]] std::string evidence_digest_hex(const FaultRecord& record);

}  // namespace fcf

#endif  // FCF_FAULT_HPP
