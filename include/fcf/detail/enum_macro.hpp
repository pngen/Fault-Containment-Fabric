// Fault Containment Fabric — scoped enum declaration with stable name table.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_DETAIL_ENUM_MACRO_HPP
#define FCF_DETAIL_ENUM_MACRO_HPP

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

// Internal helpers. Do not invoke directly; use FCF_DEFINE_ENUM.
#define FCF_DETAIL_ENUM_ITEM(name) name,
#define FCF_DETAIL_ENUM_CASE(name) \
    case name:                     \
        return std::string_view{#name};

// Declares a scoped enumeration together with:
//   * k<EnumName>Max     — the highest declared enumerator, used for range checks
//   * to_string()        — total name table, "<invalid>" for undefined values
//   * parse_<EnumName>() — strict parser that rejects unknown spellings
//
// List is an X-macro invoked once per enumerator; Last names the final enumerator.
#define FCF_DEFINE_ENUM(EnumName, List, Last)                                                    \
    enum class EnumName : std::uint16_t {                                                        \
        List(FCF_DETAIL_ENUM_ITEM)                                                               \
    };                                                                                           \
    inline constexpr std::uint16_t k##EnumName##Max = static_cast<std::uint16_t>(EnumName::Last); \
    [[nodiscard]] constexpr std::string_view to_string(EnumName value) noexcept {                 \
        using enum EnumName;                                                                      \
        switch (value) {                                                                          \
            List(FCF_DETAIL_ENUM_CASE)                                                            \
        }                                                                                         \
        return std::string_view{"<invalid>"};                                                     \
    }                                                                                             \
    [[nodiscard]] inline bool parse_##EnumName(std::string_view text, EnumName& out) noexcept {   \
        for (std::uint16_t i = 0; i <= k##EnumName##Max; ++i) {                                   \
            const auto candidate = static_cast<EnumName>(i);                                      \
            if (to_string(candidate) == text) {                                                   \
                out = candidate;                                                                  \
                return true;                                                                      \
            }                                                                                     \
        }                                                                                         \
        return false;                                                                             \
    }

namespace fcf {

/// Sorted, duplicate-free collection of enumerators of one type. Iteration order
/// is by underlying value, so serialization and traversal stay deterministic.
template <class E>
using EnumSet = std::vector<E>;

template <class E>
[[nodiscard]] bool enum_set_contains(const EnumSet<E>& set, E value) noexcept {
    const auto key = static_cast<std::uint16_t>(value);
    for (const E entry : set) {
        const auto entry_key = static_cast<std::uint16_t>(entry);
        if (entry_key == key) {
            return true;
        }
        if (entry_key > key) {
            return false;
        }
    }
    return false;
}

template <class E>
bool enum_set_insert(EnumSet<E>& set, E value) {
    const auto key = static_cast<std::uint16_t>(value);
    auto it = set.begin();
    while (it != set.end() && static_cast<std::uint16_t>(*it) < key) {
        ++it;
    }
    if (it != set.end() && static_cast<std::uint16_t>(*it) == key) {
        return false;
    }
    set.insert(it, value);
    return true;
}

template <class E>
void enum_set_normalize(EnumSet<E>& set) {
    std::sort(set.begin(), set.end(), [](E a, E b) {
        return static_cast<std::uint16_t>(a) < static_cast<std::uint16_t>(b);
    });
    set.erase(std::unique(set.begin(), set.end()), set.end());
}

}  // namespace fcf

#endif  // FCF_DETAIL_ENUM_MACRO_HPP
