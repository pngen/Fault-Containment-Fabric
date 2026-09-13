// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/dependency.hpp"

namespace fcf {

void DependencyGraph::insert(const DependencyEdge& edge) {
    edges[edge.id] = edge;
    id_set_insert(outgoing[edge.source], edge.id);
    id_set_insert(incoming[edge.destination], edge.id);
}

bool DependencyGraph::erase(DependencyId id) {
    const auto it = edges.find(id);
    if (it == edges.end()) {
        return false;
    }
    const ResourceId source = it->second.source;
    const ResourceId destination = it->second.destination;
    edges.erase(it);

    const auto out_it = outgoing.find(source);
    if (out_it != outgoing.end()) {
        id_set_erase(out_it->second, id);
        if (out_it->second.empty()) {
            outgoing.erase(out_it);
        }
    }
    const auto in_it = incoming.find(destination);
    if (in_it != incoming.end()) {
        id_set_erase(in_it->second, id);
        if (in_it->second.empty()) {
            incoming.erase(in_it);
        }
    }
    return true;
}

void DependencyGraph::rebuild_indexes() {
    outgoing.clear();
    incoming.clear();
    for (const auto& entry : edges) {
        const DependencyEdge& edge = entry.second;
        id_set_insert(outgoing[edge.source], edge.id);
        id_set_insert(incoming[edge.destination], edge.id);
    }
}

bool DependencyGraph::references(ResourceId resource) const {
    return outgoing.find(resource) != outgoing.end() || incoming.find(resource) != incoming.end();
}

}  // namespace fcf
