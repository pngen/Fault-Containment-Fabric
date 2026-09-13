// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/degraded.hpp"

namespace fcf {

bool degraded_sets_are_disjoint(const DegradedModeAssessment& assessment) noexcept {
    for (const ResourceId permitted : assessment.permitted) {
        for (const ResourceId prohibited : assessment.prohibited) {
            if (permitted == prohibited) {
                return false;
            }
        }
    }
    for (const ResourceId permitted : assessment.permitted) {
        for (const ResourceId blocked : assessment.revalidation_required) {
            if (permitted == blocked) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace fcf
