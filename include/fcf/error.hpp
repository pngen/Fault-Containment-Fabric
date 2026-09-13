// Fault Containment Fabric — typed error semantics.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_ERROR_HPP
#define FCF_ERROR_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "fcf/detail/enum_macro.hpp"

namespace fcf {

// Typed failure classification. Normal policy outcomes are NOT errors: they are
// returned as structured results. These codes describe refusals, staleness and
// integrity failures that a caller must handle distinctly.
#define FCF_ERROR_CODES(X)             \
    X(OK)                              \
    X(INVALID_ARGUMENT)                \
    X(INVALID_ID)                      \
    X(INVALID_DOMAIN_GRAPH)            \
    X(INVALID_DEPENDENCY)              \
    X(UNKNOWN_RESOURCE)                \
    X(UNKNOWN_DOMAIN)                  \
    X(UNKNOWN_WORKER)                  \
    X(UNKNOWN_FAULT)                   \
    X(UNKNOWN_ACTION)                  \
    X(UNKNOWN_CONTAINMENT)             \
    X(DUPLICATE_ID)                    \
    X(DUPLICATE_CONFLICT)              \
    X(STALE_EPOCH)                     \
    X(STALE_WORKER)                    \
    X(STALE_WORKER_BOOT)               \
    X(STALE_FAULT_GENERATION)          \
    X(STALE_POLICY_GENERATION)         \
    X(STALE_TOPOLOGY_GENERATION)       \
    X(STALE_RESOURCE_GENERATION)       \
    X(STALE_ACTION_GENERATION)         \
    X(STALE_CONTAINMENT_GENERATION)    \
    X(STALE_EVIDENCE)                  \
    X(FAULT_NOT_CURRENT)               \
    X(FAULT_NOT_ACTIONABLE)            \
    X(CONTAINMENT_ALREADY_COMMITTED)   \
    X(NO_LEGAL_CONTAINMENT)            \
    X(ACTION_INFEASIBLE)               \
    X(ACTION_REVALIDATION_FAILED)      \
    X(EXECUTOR_UNAVAILABLE)            \
    X(PROPAGATION_UNKNOWN)             \
    X(DEGRADED_MODE_FORBIDDEN)         \
    X(RELEASE_FORBIDDEN)               \
    X(REVALIDATION_REQUIRED)           \
    X(VERIFICATION_REQUIRED)           \
    X(POLICY_INVALID)                  \
    X(PERSISTENCE_CORRUPT)             \
    X(PERSISTENCE_UNSUPPORTED_VERSION) \
    X(PERSISTENCE_IO)                  \
    X(FRAME_CORRUPT)                   \
    X(FRAME_TOO_LARGE)                 \
    X(PROTOCOL_VERSION_UNSUPPORTED)    \
    X(BUDGET_EXHAUSTED)                \
    X(RESOURCE_EXHAUSTED)              \
    X(NOT_FOUND)                       \
    X(BUSY)                            \
    X(SHUTTING_DOWN)                   \
    X(CANCELLED)                       \
    X(UNSUPPORTED)                     \
    X(CAPABILITY_ABSENT)               \
    X(INTERNAL)

FCF_DEFINE_ENUM(ErrorCode, FCF_ERROR_CODES, INTERNAL)

/// True when the code reports a generation/incarnation/epoch mismatch.
[[nodiscard]] constexpr bool is_stale(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::STALE_EPOCH:
        case ErrorCode::STALE_WORKER:
        case ErrorCode::STALE_WORKER_BOOT:
        case ErrorCode::STALE_FAULT_GENERATION:
        case ErrorCode::STALE_POLICY_GENERATION:
        case ErrorCode::STALE_TOPOLOGY_GENERATION:
        case ErrorCode::STALE_RESOURCE_GENERATION:
        case ErrorCode::STALE_ACTION_GENERATION:
        case ErrorCode::STALE_CONTAINMENT_GENERATION:
        case ErrorCode::STALE_EVIDENCE:
            return true;
        default:
            return false;
    }
}

/// True when the code reports damage to durable or wire data.
[[nodiscard]] constexpr bool is_integrity_failure(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::PERSISTENCE_CORRUPT:
        case ErrorCode::PERSISTENCE_UNSUPPORTED_VERSION:
        case ErrorCode::FRAME_CORRUPT:
        case ErrorCode::FRAME_TOO_LARGE:
        case ErrorCode::PROTOCOL_VERSION_UNSUPPORTED:
        case ErrorCode::DUPLICATE_CONFLICT:
            return true;
        default:
            return false;
    }
}

/// An error carries the code, the stage that produced it, a short context label
/// and a human readable message. Nothing is flattened into a bare boolean.
class Error {
public:
    Error() = default;
    Error(ErrorCode code, std::string message, std::string stage = {}, std::string context = {})
        : code_(code), message_(std::move(message)), stage_(std::move(stage)), context_(std::move(context)) {}

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }
    [[nodiscard]] const std::string& stage() const noexcept { return stage_; }
    [[nodiscard]] const std::string& context() const noexcept { return context_; }
    [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::OK; }

    /// Stable single-line rendering: "STAGE:CODE context: message".
    [[nodiscard]] std::string to_string() const;

private:
    ErrorCode code_ = ErrorCode::OK;
    std::string message_;
    std::string stage_;
    std::string context_;
};

/// Convenience constructor used throughout the runtime.
[[nodiscard]] inline Error make_error(ErrorCode code, std::string stage, std::string message,
                                      std::string context = {}) {
    return Error(code, std::move(message), std::move(stage), std::move(context));
}

}  // namespace fcf

#endif  // FCF_ERROR_HPP
