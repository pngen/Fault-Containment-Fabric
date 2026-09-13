// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/explain.hpp"

#include <algorithm>
#include <tuple>

namespace fcf {
namespace {

constexpr const char* kCategoryOrder[] = {"AUTHORITY", "FAULT",  "MANDATORY", "PRECAUTIONARY",
                                          "UNAFFECTED", "UNKNOWN", "DEGRADED",  "REJECTED",
                                          "VERIFICATION"};

}  // namespace

int explanation_category_rank(const std::string& category) noexcept {
    int rank = 0;
    for (const char* known : kCategoryOrder) {
        if (category == known) {
            return rank;
        }
        ++rank;
    }
    return rank + 1000;
}

void ContainmentExplanation::finalize() {
    std::stable_sort(lines.begin(), lines.end(), [](const ExplanationLine& a, const ExplanationLine& b) {
        const int rank_a = explanation_category_rank(a.category);
        const int rank_b = explanation_category_rank(b.category);
        if (rank_a != rank_b) {
            return rank_a < rank_b;
        }
        if (a.category != b.category) {
            return a.category < b.category;
        }
        if (a.sort_key != b.sort_key) {
            return a.sort_key < b.sort_key;
        }
        return a.text < b.text;
    });
    lines.erase(std::unique(lines.begin(), lines.end(),
                            [](const ExplanationLine& a, const ExplanationLine& b) {
                                return a.category == b.category && a.sort_key == b.sort_key &&
                                       a.text == b.text;
                            }),
                lines.end());
}

std::string ContainmentExplanation::render() const {
    std::string out;
    std::string current_category;
    for (const ExplanationLine& line : lines) {
        if (line.category != current_category) {
            if (!out.empty()) {
                out.push_back('\n');
            }
            out += line.category;
            out += ':';
            out.push_back('\n');
            current_category = line.category;
        }
        out += "  ";
        out += line.text;
        out.push_back('\n');
    }
    return out;
}

}  // namespace fcf
