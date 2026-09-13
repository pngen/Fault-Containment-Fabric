// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/plan.hpp"

#include <string>

namespace fcf {

std::string ContainmentPlan::authority_summary() const {
    std::string out;
    out += "CoordinatorEpoch ";
    out += to_string(epoch);
    out += "; FaultGeneration ";
    out += to_string(fault_generation);
    out += "; ContainmentGeneration ";
    out += to_string(generation);
    out += "; PolicyGeneration ";
    out += to_string(policy_generation);
    out += "; TopologyGeneration ";
    out += to_string(topology_generation);
    return out;
}

}  // namespace fcf
