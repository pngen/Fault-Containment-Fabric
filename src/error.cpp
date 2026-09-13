// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/error.hpp"

namespace fcf {

std::string Error::to_string() const {
    std::string out;
    if (!stage_.empty()) {
        out += stage_;
        out += ':';
    }
    out += fcf::to_string(code_);
    if (!context_.empty()) {
        out.push_back(' ');
        out += context_;
    }
    if (!message_.empty()) {
        out += ": ";
        out += message_;
    }
    return out;
}

}  // namespace fcf
