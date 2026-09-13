// Fault Containment Fabric — REAL / SYNTHETIC / UNSUPPORTED capability provenance.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_PROVENANCE_HPP
#define FCF_PROVENANCE_HPP

#include <string>
#include <utility>
#include <vector>

#include "fcf/detail/enum_macro.hpp"

namespace fcf {

// Every environment-dependent capability the runtime reports must carry one of
// these labels. A SYNTHETIC capability is never silently upgraded to REAL.
#define FCF_CAPABILITY_PROVENANCE(X) \
    X(REAL)                          \
    X(SYNTHETIC)                     \
    X(UNSUPPORTED)

FCF_DEFINE_ENUM(CapabilityProvenance, FCF_CAPABILITY_PROVENANCE, UNSUPPORTED)

/// A single labelled capability statement.
struct CapabilityStatement {
    std::string capability;
    CapabilityProvenance provenance = CapabilityProvenance::UNSUPPORTED;
    std::string detail;
};

/// The environment facts a process actually proved at runtime.
struct CapabilityReport {
    std::vector<CapabilityStatement> statements;

    void add(std::string capability, CapabilityProvenance provenance, std::string detail) {
        statements.push_back(CapabilityStatement{std::move(capability), provenance, std::move(detail)});
    }
};

}  // namespace fcf

#endif  // FCF_PROVENANCE_HPP
