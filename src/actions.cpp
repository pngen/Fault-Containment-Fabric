// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/actions.hpp"

#include <string>

namespace fcf {

std::string describe_action(const ContainmentAction& action) {
    std::string out = to_string(action.id);
    out += " ";
    out += to_string(action.kind);
    out += " target=";
    out += to_string(action.target);
    out += " generation=";
    out += to_string(action.generation);
    out += " status=";
    out += to_string(action.status);
    out += " mechanism=";
    out += to_string(action.mechanism);
    if (action.rejection_code != ErrorCode::OK) {
        out += " rejected=";
        out += to_string(action.rejection_code);
        if (!action.rejection_detail.empty()) {
            out += " (";
            out += action.rejection_detail;
            out += ")";
        }
    }
    return out;
}

std::string describe_envelope(const AuthorityEnvelope& envelope) {
    std::string out;
    out += "CoordinatorEpoch ";
    out += to_string(envelope.epoch);
    out += "; FaultGeneration ";
    out += to_string(envelope.fault_generation);
    out += "; ContainmentGeneration ";
    out += to_string(envelope.containment_generation);
    out += "; PolicyGeneration ";
    out += to_string(envelope.policy_generation);
    out += "; TopologyGeneration ";
    out += to_string(envelope.topology_generation);
    out += "; ActionGeneration ";
    out += to_string(envelope.action_generation);
    out += "; TargetGeneration ";
    out += to_string(envelope.target_generation);
    if (envelope.worker_boot.valid()) {
        out += "; WorkerBootId ";
        out += to_string(envelope.worker_boot);
    }
    if (!envelope.required_resource_generations.empty()) {
        out += "; RequiredResourceGenerations ";
        out += std::to_string(envelope.required_resource_generations.size());
    }
    return out;
}

}  // namespace fcf
