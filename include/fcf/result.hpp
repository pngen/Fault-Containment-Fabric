// Fault Containment Fabric — structured result type.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_RESULT_HPP
#define FCF_RESULT_HPP

#include <utility>
#include <variant>

#include "fcf/error.hpp"

namespace fcf {

/// Unit type for operations that carry no payload on success.
struct Unit {};

/// Either a value or a typed Error. Policy outcomes are values, not errors.
template <class T>
class Result {
public:
    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}

    [[nodiscard]] bool ok() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
    [[nodiscard]] T& value() & { return std::get<0>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

    /// Returns the error, or an empty OK error when the result carries a value.
    /// This never throws, so error-reporting paths cannot turn a success into an
    /// exception while they are being formatted.
    [[nodiscard]] const Error& error() const& {
        static const Error kNoError{};
        return storage_.index() == 1 ? std::get<1>(storage_) : kNoError;
    }
    [[nodiscard]] Error& error() & {
        static Error kNoError{};
        return storage_.index() == 1 ? std::get<1>(storage_) : kNoError;
    }

    [[nodiscard]] const T& operator*() const& { return value(); }
    [[nodiscard]] T& operator*() & { return value(); }
    [[nodiscard]] const T* operator->() const& { return &value(); }
    [[nodiscard]] T* operator->() & { return &value(); }

    /// Returns the value on success, otherwise the supplied fallback.
    template <class U>
    [[nodiscard]] T value_or(U&& fallback) const {
        return ok() ? value() : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::variant<T, Error> storage_;
};

using Status = Result<Unit>;

[[nodiscard]] inline Status ok_status() { return Status(Unit{}); }

[[nodiscard]] inline Status fail(ErrorCode code, std::string stage, std::string message,
                                 std::string context = {}) {
    return Status(make_error(code, std::move(stage), std::move(message), std::move(context)));
}

}  // namespace fcf

#endif  // FCF_RESULT_HPP
