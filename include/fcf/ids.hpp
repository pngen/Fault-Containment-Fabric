// Fault Containment Fabric — strongly typed identities.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_IDS_HPP
#define FCF_IDS_HPP

#include <compare>
#include <concepts>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace fcf {

/// A strongly typed, opaque identity.
///
/// The tag parameter makes every identity domain distinct at compile time: an
/// Id<WorkerIdTag> can never be assigned, compared or passed where an
/// Id<ResourceIdTag> is expected. Value 0 is the reserved invalid sentinel and is
/// never produced by the runtime for a real entity.
template <class Tag>
class Id {
public:
    using tag_type = Tag;
    using value_type = std::uint64_t;

    constexpr Id() noexcept = default;
    constexpr explicit Id(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] static constexpr Id from_value(std::uint64_t value) noexcept { return Id(value); }

    [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return valid(); }

    friend constexpr bool operator==(const Id&, const Id&) noexcept = default;
    friend constexpr std::strong_ordering operator<=>(const Id&, const Id&) noexcept = default;

private:
    std::uint64_t value_ = 0;
};

/// Constrains a type to be one of the strongly typed identity domains.
template <class T>
concept Identity = requires { typename T::tag_type; };

/// Human/machine readable name of an identity domain, e.g. "WorkerId".
template <Identity IdT>
[[nodiscard]] constexpr std::string_view id_domain_name() noexcept {
    return IdT::tag_type::kName;
}

/// Renders an identity as "<Domain>:<decimal>", or "<Domain>:invalid" for the sentinel.
template <Identity IdT>
[[nodiscard]] std::string to_string(IdT id) {
    std::string out(id_domain_name<IdT>());
    out.push_back(':');
    if (!id.valid()) {
        out += "invalid";
        return out;
    }
    char buffer[24];
    std::uint64_t value = id.value();
    int position = 24;
    while (value != 0) {
        buffer[--position] = static_cast<char>('0' + static_cast<int>(value % 10U));
        value /= 10U;
    }
    out.append(buffer + position, static_cast<std::size_t>(24 - position));
    return out;
}

/// Parses "<Domain>:<decimal>" or "<decimal>". Rejects empty input, signs,
/// overflow, embedded whitespace and any non-digit character.
template <Identity IdT>
[[nodiscard]] bool parse_id(std::string_view text, IdT& out) noexcept {
    if (text.empty()) {
        return false;
    }
    const std::size_t colon = text.find(':');
    if (colon != std::string_view::npos) {
        if (text.substr(0, colon) != id_domain_name<IdT>()) {
            return false;
        }
        text.remove_prefix(colon + 1);
        if (text.empty()) {
            return false;
        }
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10U) {
            return false;  // overflow
        }
        value = value * 10U + digit;
    }
    out = IdT::from_value(value);
    return true;
}

// --- Identity domains -----------------------------------------------------------------
//
// Each tag type carries its own name; each alias is a distinct Id instantiation.
// Because the tags are distinct types, accidental interchange is a compile error:
// a WorkerId is not a ResourceId and a ResourceId is not a ContainmentDomainId.

namespace detail {
#define FCF_ID_TAG_DECL(Name)                            \
    struct Name##Tag {                                   \
        static constexpr std::string_view kName = #Name; \
    };
#define FCF_ID_TAGS(X)            \
    X(CoordinatorEpoch)           \
    X(WorkerId)                   \
    X(WorkerBootId)               \
    X(WorkerIncarnation)          \
    X(NodeId)                     \
    X(HostId)                     \
    X(ProcessId)                  \
    X(DeviceId)                   \
    X(AcceleratorId)              \
    X(ResourceId)                 \
    X(WorkloadId)                 \
    X(ServiceId)                  \
    X(AttemptId)                  \
    X(ExecutionId)                \
    X(ContainmentDomainId)        \
    X(IsolationDomainId)          \
    X(FailureDomainId)            \
    X(DependencyId)               \
    X(FaultId)                    \
    X(FaultGeneration)            \
    X(TopologyGeneration)         \
    X(PolicyGeneration)           \
    X(ResourceGeneration)         \
    X(DependencyGeneration)       \
    X(ContainmentGeneration)      \
    X(ActionId)                   \
    X(ActionGeneration)           \
    X(VerificationGeneration)     \
    X(ReleaseGeneration)          \
    X(DegradedModeId)             \
    X(ReservationId)              \
    X(LeaseId)                    \
    X(EvidenceSequence)           \
    X(HistorySequence)
FCF_ID_TAGS(FCF_ID_TAG_DECL)
#undef FCF_ID_TAG_DECL
#undef FCF_ID_TAGS
}  // namespace detail

#define FCF_ID_ALIAS(Name) using Name = Id<detail::Name##Tag>;
FCF_ID_ALIAS(CoordinatorEpoch)
FCF_ID_ALIAS(WorkerId)
FCF_ID_ALIAS(WorkerBootId)
FCF_ID_ALIAS(WorkerIncarnation)
FCF_ID_ALIAS(NodeId)
FCF_ID_ALIAS(HostId)
FCF_ID_ALIAS(ProcessId)
FCF_ID_ALIAS(DeviceId)
FCF_ID_ALIAS(AcceleratorId)
FCF_ID_ALIAS(ResourceId)
FCF_ID_ALIAS(WorkloadId)
FCF_ID_ALIAS(ServiceId)
FCF_ID_ALIAS(AttemptId)
FCF_ID_ALIAS(ExecutionId)
FCF_ID_ALIAS(ContainmentDomainId)
FCF_ID_ALIAS(IsolationDomainId)
FCF_ID_ALIAS(FailureDomainId)
FCF_ID_ALIAS(DependencyId)
FCF_ID_ALIAS(FaultId)
FCF_ID_ALIAS(FaultGeneration)
FCF_ID_ALIAS(TopologyGeneration)
FCF_ID_ALIAS(PolicyGeneration)
FCF_ID_ALIAS(ResourceGeneration)
FCF_ID_ALIAS(DependencyGeneration)
FCF_ID_ALIAS(ContainmentGeneration)
FCF_ID_ALIAS(ActionId)
FCF_ID_ALIAS(ActionGeneration)
FCF_ID_ALIAS(VerificationGeneration)
FCF_ID_ALIAS(ReleaseGeneration)
FCF_ID_ALIAS(DegradedModeId)
FCF_ID_ALIAS(ReservationId)
FCF_ID_ALIAS(LeaseId)
FCF_ID_ALIAS(EvidenceSequence)
FCF_ID_ALIAS(HistorySequence)
#undef FCF_ID_ALIAS

/// Sorted, duplicate-free collection of identities of one domain.
template <Identity IdT>
using IdSet = std::vector<IdT>;

/// Returns the next value of a monotonic identity/generation counter. Saturates at
/// the maximum representable value rather than wrapping, so a generation can never
/// silently return to an older value.
template <Identity IdT>
[[nodiscard]] constexpr IdT next_generation(IdT current) noexcept {
    if (current.value() == UINT64_MAX) {
        return current;
    }
    return IdT::from_value(current.value() + 1U);
}

template <Identity IdT>
[[nodiscard]] bool id_set_contains(const IdSet<IdT>& set, IdT id) noexcept {
    for (const IdT entry : set) {
        if (entry == id) {
            return true;
        }
        if (entry > id) {
            return false;
        }
    }
    return false;
}

/// Inserts into a sorted id set, preserving order and uniqueness.
template <Identity IdT>
bool id_set_insert(IdSet<IdT>& set, IdT id) {
    auto it = set.begin();
    while (it != set.end() && *it < id) {
        ++it;
    }
    if (it != set.end() && *it == id) {
        return false;
    }
    set.insert(it, id);
    return true;
}

template <Identity IdT>
bool id_set_erase(IdSet<IdT>& set, IdT id) {
    for (auto it = set.begin(); it != set.end(); ++it) {
        if (*it == id) {
            set.erase(it);
            return true;
        }
        if (*it > id) {
            return false;
        }
    }
    return false;
}

}  // namespace fcf

namespace std {
template <class Tag>
struct hash<fcf::Id<Tag>> {
    [[nodiscard]] std::size_t operator()(const fcf::Id<Tag>& id) const noexcept {
        return std::hash<std::uint64_t>{}(id.value());
    }
};
}  // namespace std

#endif  // FCF_IDS_HPP
