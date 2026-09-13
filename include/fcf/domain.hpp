// Fault Containment Fabric — containment structure: domains and resources.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DOMAIN_HPP
#define FCF_DOMAIN_HPP

#include <cstdint>
#include <map>
#include <string>

#include "fcf/dependency.hpp"
#include "fcf/detail/enum_macro.hpp"
#include "fcf/evidence.hpp"
#include "fcf/ids.hpp"
#include "fcf/provenance.hpp"

namespace fcf {

// --- Enumerations ---------------------------------------------------------------------

#define FCF_RESOURCE_CLASSES(X)  \
    X(WORKER)                    \
    X(PROCESS)                   \
    X(ACCELERATOR)               \
    X(ACCELERATOR_PARTITION)     \
    X(DEVICE)                    \
    X(HOST)                      \
    X(RACK_LOCAL_GROUP)          \
    X(SERVICE)                   \
    X(SERVICE_REPLICA_GROUP)     \
    X(MEMORY_DEPENDENCY_SET)     \
    X(CLUSTER_PARTITION)         \
    X(ATTEMPT)                   \
    X(EXECUTION)                 \
    X(MEMORY_OWNERSHIP)          \
    X(ASSIGNMENT)                \
    X(ROUTE)                     \
    X(REGISTRATION)              \
    X(LEASE)                     \
    X(RESERVATION)               \
    X(STATE_STORE)               \
    X(CAPABILITY)                \
    X(GENERIC)

FCF_DEFINE_ENUM(ResourceClass, FCF_RESOURCE_CLASSES, GENERIC)

/// A resource whose protection class is PROTECTED or CRITICAL may not be fenced
/// unless policy explicitly authorises it; the class never grants an exemption
/// from a mandatory containment predicate.
#define FCF_PROTECTION_CLASSES(X) \
    X(STANDARD)                   \
    X(PROTECTED)                  \
    X(CRITICAL)

FCF_DEFINE_ENUM(ProtectionClass, FCF_PROTECTION_CLASSES, CRITICAL)

#define FCF_RESOURCE_STATES(X) \
    X(ACTIVE)                  \
    X(FENCED)                  \
    X(QUARANTINED)             \
    X(DRAINING)                \
    X(DISABLED)                \
    X(RELEASED)                \
    X(SUPERSEDED)              \
    X(UNKNOWN)

FCF_DEFINE_ENUM(ResourceOperationalState, FCF_RESOURCE_STATES, UNKNOWN)

/// True when the resource may receive newly authorised work or accept new state.
[[nodiscard]] constexpr bool is_operable(ResourceOperationalState state) noexcept {
    return state == ResourceOperationalState::ACTIVE || state == ResourceOperationalState::DRAINING;
}

/// True when containment currently forbids new work on the resource.
[[nodiscard]] constexpr bool is_contained(ResourceOperationalState state) noexcept {
    switch (state) {
        case ResourceOperationalState::FENCED:
        case ResourceOperationalState::QUARANTINED:
        case ResourceOperationalState::DISABLED:
            return true;
        default:
            return false;
    }
}

#define FCF_FAILURE_DOMAIN_KINDS(X) \
    X(PROCESS)                      \
    X(HOST)                         \
    X(PCIE_ROOT)                    \
    X(NUMA_DOMAIN)                  \
    X(POWER_DOMAIN)                 \
    X(RACK)                         \
    X(NETWORK_PARTITION)            \
    X(SYNTHETIC_CORRELATED_GROUP)   \
    X(UNKNOWN)

FCF_DEFINE_ENUM(FailureDomainKind, FCF_FAILURE_DOMAIN_KINDS, UNKNOWN)

/// Why a set of resources must be fenced together.
#define FCF_ISOLATION_CLASSES(X) \
    X(AUTHORITY)                 \
    X(HARDWARE)                  \
    X(STATE)                     \
    X(TRANSPORT)                 \
    X(SECURITY)                  \
    X(SYNTHETIC)

FCF_DEFINE_ENUM(IsolationClass, FCF_ISOLATION_CLASSES, SYNTHETIC)

// --- Records ---------------------------------------------------------------------------

/// A resource the fabric can reason about. Everything here is containment-relevant
/// metadata; the fabric never owns the underlying mechanism.
struct ResourceRecord {
    ResourceId id{};
    ResourceGeneration generation{};
    std::string name;
    ResourceClass resource_class = ResourceClass::GENERIC;
    ProtectionClass protection = ProtectionClass::STANDARD;
    ResourceOperationalState state = ResourceOperationalState::UNKNOWN;

    ContainmentDomainId containment_domain{};
    IsolationDomainId isolation_domain{};
    FailureDomainId failure_domain{};

    // Live authority binding. When owner_boot is valid, only that exact worker
    // incarnation may authorise new work on this resource.
    WorkerId owner_worker{};
    WorkerBootId owner_boot{};

    NodeId node{};
    HostId host{};
    DeviceId device{};
    AcceleratorId accelerator{};
    ServiceId service{};
    WorkloadId workload{};
    ExecutionId execution{};
    AttemptId attempt{};
    ReservationId reservation{};
    LeaseId lease{};

    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
    EvidenceSequence evidence_sequence{};
    std::uint64_t updated_at_ms = 0;

    /// True from the moment containment commits until release authority is granted.
    bool quarantined = false;
    ContainmentMechanism mechanism = ContainmentMechanism::NONE;
    ContainmentGeneration containment_generation{};
    ReleaseGeneration release_generation{};
};

/// A logical boundary within which faults may be tolerated or isolated.
struct ContainmentDomain {
    ContainmentDomainId id{};
    TopologyGeneration generation{};
    std::string name;
    IdSet<ResourceId> members;
    ProtectionClass protection = ProtectionClass::STANDARD;
    /// When set, members of this domain may never be separated by containment.
    bool co_isolate_members = false;
};

/// A set of resources that must be fenced together under specified failure classes.
struct IsolationDomain {
    IsolationDomainId id{};
    TopologyGeneration generation{};
    std::string name;
    IdSet<ResourceId> members;
    EnumSet<IsolationClass> classes;
    /// The strongest mechanism actually available for this domain.
    ContainmentMechanism mechanism = ContainmentMechanism::LOGICAL_CONTAINMENT;
};

/// A physical or logical correlated-failure boundary.
struct FailureDomain {
    FailureDomainId id{};
    TopologyGeneration generation{};
    std::string name;
    FailureDomainKind kind = FailureDomainKind::UNKNOWN;
    IdSet<ResourceId> members;
    EvidenceProvenance provenance = EvidenceProvenance::UNKNOWN;
    EvidenceFreshness freshness = EvidenceFreshness::UNKNOWN;
};

/// The full structural topology. All maps are ordered by strongly typed identity,
/// so iteration and serialization are deterministic.
struct Topology {
    TopologyGeneration generation{};
    std::map<ResourceId, ResourceRecord> resources;
    std::map<ContainmentDomainId, ContainmentDomain> containment_domains;
    std::map<IsolationDomainId, IsolationDomain> isolation_domains;
    std::map<FailureDomainId, FailureDomain> failure_domains;
    DependencyGraph dependencies;
};

}  // namespace fcf

#endif  // FCF_DOMAIN_HPP
