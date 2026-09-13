// Fault Containment Fabric — version and capability metadata.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_VERSION_HPP
#define FCF_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace fcf {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

/// Semantic version string of the library, e.g. "1.0.0".
[[nodiscard]] constexpr std::string_view version_string() noexcept { return "1.0.0"; }

/// Version of the public C++ ABI/API surface. Bumped on incompatible public changes.
inline constexpr std::uint32_t kApiVersion = 1;

/// On-disk snapshot format version understood by this build.
inline constexpr std::uint32_t kSnapshotFormatVersion = 1;

/// On-disk journal format version understood by this build.
inline constexpr std::uint32_t kJournalFormatVersion = 1;

/// Wire protocol version understood by this build.
inline constexpr std::uint16_t kWireProtocolVersion = 1;

}  // namespace fcf

#endif  // FCF_VERSION_HPP
