// Fault Containment Fabric — deterministic structured explanations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef FCF_EXPLAIN_HPP
#define FCF_EXPLAIN_HPP

#include <string>
#include <vector>

namespace fcf {

/// One line of a containment explanation. Lines are emitted in a stable,
/// category-major order so an identical canonical state renders byte-identical text.
struct ExplanationLine {
    std::string category;
    std::string sort_key;
    std::string text;
};

struct ContainmentExplanation {
    std::vector<ExplanationLine> lines;

    void add(std::string category, std::string sort_key, std::string text) {
        lines.push_back(ExplanationLine{std::move(category), std::move(sort_key), std::move(text)});
    }

    /// Orders lines by (category rank, sort key, text) using the fixed category
    /// ranking below, then collapses duplicates while preserving order.
    void finalize();

    [[nodiscard]] std::string render() const;
};

/// Fixed render order. Unknown categories sort last, lexicographically.
[[nodiscard]] int explanation_category_rank(const std::string& category) noexcept;

}  // namespace fcf

#endif  // FCF_EXPLAIN_HPP
