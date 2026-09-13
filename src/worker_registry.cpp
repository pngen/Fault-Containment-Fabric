// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/worker.hpp"

namespace fcf {

const WorkerRecord* find_incarnation(const WorkerRegistry& registry, WorkerKey key) {
    const auto it = registry.incarnations.find(key);
    return it == registry.incarnations.end() ? nullptr : &it->second;
}

const WorkerRecord* find_current_incarnation(const WorkerRegistry& registry, WorkerId worker) {
    const auto boot = registry.current_boot.find(worker);
    if (boot == registry.current_boot.end()) {
        return nullptr;
    }
    return find_incarnation(registry, WorkerKey{worker, boot->second});
}

bool boot_is_current(const WorkerRegistry& registry, WorkerId worker, WorkerBootId boot) noexcept {
    const auto it = registry.current_boot.find(worker);
    return it != registry.current_boot.end() && it->second == boot;
}

std::size_t count_live_incarnations(const WorkerRegistry& registry) noexcept {
    std::size_t count = 0;
    for (const auto& entry : registry.incarnations) {
        if (holds_live_authority(entry.second.state)) {
            ++count;
        }
    }
    return count;
}

}  // namespace fcf
