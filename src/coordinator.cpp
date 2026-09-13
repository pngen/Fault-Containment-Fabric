// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/coordinator.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fcf/net.hpp"

namespace fcf {
namespace {

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
    }
    out = value;
    return true;
}

[[nodiscard]] bool parse_flag(const std::string& text, bool& out) noexcept {
    if (text == "1" || text == "true" || text == "yes") {
        out = true;
        return true;
    }
    if (text == "0" || text == "false" || text == "no") {
        out = false;
        return true;
    }
    return false;
}

[[nodiscard]] std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> out;
    if (text == "-" || text.empty()) {
        return out;
    }
    std::string current;
    for (const char c : text) {
        if (c == ',') {
            out.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    out.push_back(current);
    return out;
}

template <Identity IdT>
[[nodiscard]] bool id_argument(const std::string& text, IdT& out) {
    return parse_id_argument<IdT>(text, out);
}

[[nodiscard]] ControlResponse failure(ErrorCode code, std::string message) {
    ControlResponse response;
    response.ok = false;
    response.code = code;
    response.message = std::move(message);
    return response;
}

[[nodiscard]] ControlResponse success() {
    ControlResponse response;
    response.ok = true;
    return response;
}

[[nodiscard]] std::string join_ids(const IdSet<ResourceId>& ids) {
    std::string out;
    for (const ResourceId id : ids) {
        if (!out.empty()) {
            out.push_back(',');
        }
        out += to_string(id);
    }
    return out;
}

[[nodiscard]] ControlResponse status_command(Engine& engine) {
    const SystemStatus status = engine.query_system_status();
    ControlResponse response = success();
    response.add("epoch=" + to_string(status.epoch));
    response.add("topology_generation=" + to_string(status.topology_generation));
    response.add("policy_generation=" + to_string(status.policy_generation));
    response.add("containment_generation=" + to_string(status.containment_generation));
    response.add("verification_generation=" + to_string(status.verification_generation));
    response.add("history_sequence=" + to_string(status.history_sequence));
    response.add("resources=" + std::to_string(status.resource_count));
    response.add("dependencies=" + std::to_string(status.dependency_count));
    response.add("faults=" + std::to_string(status.fault_count));
    response.add("current_faults=" + std::to_string(status.current_fault_count));
    response.add("live_containments=" + std::to_string(status.live_containment_count));
    response.add("quarantined_resources=" + std::to_string(status.quarantined_resource_count));
    response.add("worker_incarnations=" + std::to_string(status.worker_incarnation_count));
    response.add("live_workers=" + std::to_string(status.live_worker_count));
    response.add("degraded_status=" + std::string(to_string(status.degraded_status)));
    response.add("durability_healthy=" + std::string(status.durability_healthy ? "1" : "0"));
    response.add("recovery_incomplete=" + std::string(status.recovery_incomplete ? "1" : "0"));
    for (const std::string& note : status.notes) {
        response.add("note=" + note);
    }
    return response;
}

}  // namespace

Result<ControlResponse> execute_engine_control(Engine& engine, const ControlRequest& request) {
    const std::string& command = request.command;
    const std::vector<std::string>& args = request.arguments;

    if (command == "status") {
        return status_command(engine);
    }
    if (command == "faults") {
        ControlResponse response = success();
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
        for (const auto& entry : snapshot->faults) {
            response.add(to_string(entry.first) + " kind=" +
                         std::string(to_string(entry.second.evidence.kind)) + " state=" +
                         std::string(to_string(entry.second.state)) + " subject=" +
                         to_string(entry.second.evidence.subject) + " generation=" +
                         to_string(entry.second.evidence.generation) + " containment=" +
                         to_string(entry.second.containment_generation) + " duplicates=" +
                         std::to_string(entry.second.duplicate_count));
        }
        return response;
    }
    if (command == "containments") {
        ControlResponse response = success();
        for (const ContainmentRecord& record : engine.list_containments()) {
            response.add(to_string(record.generation) + " fault=" + to_string(record.fault) +
                         " status=" + std::string(to_string(record.status)) + " outcome=" +
                         std::string(to_string(record.outcome)) + " mandatory=" +
                         std::to_string(record.mandatory.size()) + " unaffected=" +
                         std::to_string(record.unaffected.size()) + " unresolved=" +
                         std::to_string(record.unresolved.size()) + " verified=" +
                         (record.verified ? "1" : "0"));
        }
        return response;
    }
    if (command == "workers") {
        ControlResponse response = success();
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
        for (const auto& entry : snapshot->workers.incarnations) {
            response.add(to_string(entry.first.worker) + " boot=" + to_string(entry.first.boot) +
                         " incarnation=" + to_string(entry.second.incarnation) + " state=" +
                         std::string(to_string(entry.second.state)) + " freshness=" +
                         std::string(to_string(entry.second.freshness)) + " authority=" +
                         join_ids(entry.second.live_authority));
        }
        return response;
    }
    if (command == "history") {
        std::uint64_t from = 1;
        std::uint64_t limit = 200;
        if (args.size() >= 1 && !parse_u64(args[0], from)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "history: <from_sequence> must be numeric");
        }
        if (args.size() >= 2 && !parse_u64(args[1], limit)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "history: <limit> must be numeric");
        }
        ControlResponse response = success();
        for (const HistoryEvent& event : engine.history(from, static_cast<std::size_t>(limit))) {
            response.add(to_string(event.sequence) + " " + std::string(to_string(event.type)) + " " +
                         event.detail);
        }
        return response;
    }
    if (command == "register-domain") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "register-domain <id> <name> <co_isolate> [members csv]");
        }
        ContainmentDomain domain;
        if (!id_argument<ContainmentDomainId>(args[0], domain.id)) {
            return failure(ErrorCode::INVALID_ID, "register-domain: bad domain identity");
        }
        domain.name = args[1];
        if (!parse_flag(args[2], domain.co_isolate_members)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-domain: co_isolate must be 0 or 1");
        }
        if (args.size() >= 4) {
            for (const std::string& member : split_csv(args[3])) {
                ResourceId id;
                if (!id_argument<ResourceId>(member, id) || !id.valid()) {
                    return failure(ErrorCode::INVALID_ID, "register-domain: bad member identity");
                }
                id_set_insert(domain.members, id);
            }
        }
        const Result<ContainmentDomain> stored = engine.register_domain(domain);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("containment_domain=" + to_string(stored.value().id));
        return response;
    }
    if (command == "register-isolation-domain") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "register-isolation-domain <id> <name> <mechanism> [members csv]");
        }
        IsolationDomain domain;
        if (!id_argument<IsolationDomainId>(args[0], domain.id)) {
            return failure(ErrorCode::INVALID_ID, "register-isolation-domain: bad identity");
        }
        domain.name = args[1];
        if (!parse_ContainmentMechanism(args[2], domain.mechanism)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-isolation-domain: bad mechanism");
        }
        if (args.size() >= 4) {
            for (const std::string& member : split_csv(args[3])) {
                ResourceId id;
                if (!id_argument<ResourceId>(member, id) || !id.valid()) {
                    return failure(ErrorCode::INVALID_ID, "register-isolation-domain: bad member");
                }
                id_set_insert(domain.members, id);
            }
        }
        const Result<IsolationDomain> stored = engine.register_isolation_domain(domain);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("isolation_domain=" + to_string(stored.value().id));
        return response;
    }
    if (command == "register-failure-domain") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "register-failure-domain <id> <name> <kind> [members csv]");
        }
        FailureDomain domain;
        if (!id_argument<FailureDomainId>(args[0], domain.id)) {
            return failure(ErrorCode::INVALID_ID, "register-failure-domain: bad identity");
        }
        domain.name = args[1];
        if (!parse_FailureDomainKind(args[2], domain.kind)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-failure-domain: bad kind");
        }
        domain.provenance = EvidenceProvenance::OPERATOR;
        domain.freshness = EvidenceFreshness::FRESH;
        if (args.size() >= 4) {
            for (const std::string& member : split_csv(args[3])) {
                ResourceId id;
                if (!id_argument<ResourceId>(member, id) || !id.valid()) {
                    return failure(ErrorCode::INVALID_ID, "register-failure-domain: bad member");
                }
                id_set_insert(domain.members, id);
            }
        }
        const Result<FailureDomain> stored = engine.register_failure_domain(domain);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("failure_domain=" + to_string(stored.value().id));
        return response;
    }
    if (command == "register-resource") {
        if (args.size() < 9) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "register-resource <id> <name> <class> <protection> <cd> <idom> <fdom> "
                           "<worker> <boot>");
        }
        ResourceRecord record;
        if (!id_argument<ResourceId>(args[0], record.id)) {
            return failure(ErrorCode::INVALID_ID, "register-resource: bad resource identity");
        }
        record.name = args[1];
        if (!parse_ResourceClass(args[2], record.resource_class)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-resource: bad class");
        }
        if (!parse_ProtectionClass(args[3], record.protection)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-resource: bad protection class");
        }
        if (!id_argument<ContainmentDomainId>(args[4], record.containment_domain) ||
            !id_argument<IsolationDomainId>(args[5], record.isolation_domain) ||
            !id_argument<FailureDomainId>(args[6], record.failure_domain) ||
            !id_argument<WorkerId>(args[7], record.owner_worker) ||
            !id_argument<WorkerBootId>(args[8], record.owner_boot)) {
            return failure(ErrorCode::INVALID_ID, "register-resource: bad identity argument");
        }
        record.state = ResourceOperationalState::UNKNOWN;
        record.freshness = EvidenceFreshness::UNKNOWN;
        const Result<ResourceRecord> stored = engine.register_resource(record);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("resource=" + to_string(stored.value().id));
        response.add("resource_generation=" + to_string(stored.value().generation));
        return response;
    }
    if (command == "set-resource-owner") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT, "set-resource-owner <resource> <worker> <boot>");
        }
        ResourceId resource;
        WorkerId worker;
        WorkerBootId boot;
        if (!id_argument<ResourceId>(args[0], resource) || !id_argument<WorkerId>(args[1], worker) ||
            !id_argument<WorkerBootId>(args[2], boot)) {
            return failure(ErrorCode::INVALID_ID, "set-resource-owner: bad identity argument");
        }
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
        const auto existing = snapshot->topology.resources.find(resource);
        if (existing == snapshot->topology.resources.end()) {
            return failure(ErrorCode::UNKNOWN_RESOURCE, "set-resource-owner: unknown resource");
        }
        ResourceRecord record = existing->second;
        const ResourceGeneration expected = record.generation;
        record.owner_worker = worker;
        record.owner_boot = boot;
        record.state = ResourceOperationalState::ACTIVE;
        record.freshness = EvidenceFreshness::FRESH;
        record.evidence_sequence = next_generation(record.evidence_sequence);
        const Result<ResourceRecord> stored = engine.update_resource(record, expected);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("resource=" + to_string(stored.value().id));
        response.add("resource_generation=" + to_string(stored.value().generation));
        return response;
    }
    if (command == "register-dependency") {
        if (args.size() < 4) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "register-dependency <id> <source> <destination> <kind> [conditional]");
        }
        DependencyEdge edge;
        if (!id_argument<DependencyId>(args[0], edge.id) ||
            !id_argument<ResourceId>(args[1], edge.source) ||
            !id_argument<ResourceId>(args[2], edge.destination)) {
            return failure(ErrorCode::INVALID_ID, "register-dependency: bad identity argument");
        }
        if (!parse_DependencyKind(args[3], edge.kind)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-dependency: bad dependency kind");
        }
        if (args.size() >= 5 && !parse_flag(args[4], edge.conditional)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "register-dependency: conditional must be 0 or 1");
        }
        edge.provenance = EvidenceProvenance::OPERATOR;
        edge.freshness = EvidenceFreshness::FRESH;
        edge.integrity = IntegrityStatus::VERIFIED;
        edge.confidence_permille = 1000U;
        edge.evidence_source = "control-plane";
        const Result<DependencyEdge> stored = engine.register_dependency(edge);
        if (!stored.ok()) {
            return failure(stored.error().code(), stored.error().to_string());
        }
        ControlResponse response = success();
        response.add("dependency=" + to_string(stored.value().id));
        return response;
    }
    if (command == "publish-fault") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "publish-fault <id> <kind> <subject> [details]");
        }
        FaultEvidence evidence;
        if (!id_argument<FaultId>(args[0], evidence.id) ||
            !id_argument<ResourceId>(args[2], evidence.subject)) {
            return failure(ErrorCode::INVALID_ID, "publish-fault: bad identity argument");
        }
        if (!parse_FaultKind(args[1], evidence.kind)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "publish-fault: bad fault kind");
        }
        evidence.details = args.size() >= 4 ? args[3] : std::string{};
        evidence.reporter_kind = ReporterKind::OPERATOR;
        evidence.epoch = engine.epoch();
        evidence.provenance = EvidenceProvenance::OPERATOR;
        evidence.observation_sequence = EvidenceSequence::from_value(1);
        evidence.publication_time_ms = 0;
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        evidence.confidence_permille = 1000U;
        EvidenceSequence sequence{};
        bool duplicate = false;
        Result<FaultRecord> published = engine.publish_fault(evidence, &duplicate);
        while (!published.ok() && published.error().code() == ErrorCode::DUPLICATE_CONFLICT &&
               !sequence.valid()) {
            // Distinct observations of the same subject need distinct sequences.
            const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
            std::uint64_t highest = 0;
            for (const auto& entry : snapshot->faults) {
                if (entry.second.evidence.subject == evidence.subject &&
                    entry.second.evidence.kind == evidence.kind) {
                    highest = std::max(highest, entry.second.evidence.observation_sequence.value());
                }
            }
            sequence = EvidenceSequence::from_value(highest + 1U);
            evidence.observation_sequence = sequence;
            published = engine.publish_fault(evidence, &duplicate);
        }
        if (!published.ok()) {
            return failure(published.error().code(), published.error().to_string());
        }
        ControlResponse response = success();
        response.add("fault=" + to_string(published.value().evidence.id));
        response.add("fault_generation=" + to_string(published.value().evidence.generation));
        response.add("duplicate=" + std::string(duplicate ? "1" : "0"));
        response.add("state=" + std::string(to_string(published.value().state)));
        return response;
    }
    if (command == "worker-lost") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT, "worker-lost <worker> <boot> <fault kind>");
        }
        WorkerId worker;
        WorkerBootId boot;
        FaultKind kind = FaultKind::PROCESS_DEATH;
        if (!id_argument<WorkerId>(args[0], worker) || !id_argument<WorkerBootId>(args[1], boot)) {
            return failure(ErrorCode::INVALID_ID, "worker-lost: bad identity argument");
        }
        if (!parse_FaultKind(args[2], kind)) {
            return failure(ErrorCode::INVALID_ARGUMENT, "worker-lost: bad fault kind");
        }
        const Result<ContainmentRecord> containment = engine.worker_authority_lost(
            worker, boot, kind, "operator-observed authority loss", 0);
        if (!containment.ok()) {
            return failure(containment.error().code(), containment.error().to_string());
        }
        ControlResponse response = success();
        response.add("containment=" + to_string(containment.value().generation));
        response.add("mandatory=" + std::to_string(containment.value().mandatory.size()));
        return response;
    }
    if (command == "evaluate") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "evaluate <fault>");
        }
        FaultId fault;
        if (!id_argument<FaultId>(args[0], fault)) {
            return failure(ErrorCode::INVALID_ID, "evaluate: bad fault identity");
        }
        const Result<BlastRadius> radius = engine.evaluate_containment(fault, FaultGeneration{});
        if (!radius.ok()) {
            return failure(radius.error().code(), radius.error().to_string());
        }
        ControlResponse response = success();
        response.add("recommended=" + std::string(to_string(radius.value().recommended)));
        response.add("mandatory=" + join_ids(radius.value().mandatory));
        response.add("precautionary=" + join_ids(radius.value().precautionary));
        response.add("unaffected=" + join_ids(radius.value().unaffected));
        response.add("unresolved=" + join_ids(radius.value().unresolved));
        response.add("hard_constraints_satisfied=" +
                     std::string(radius.value().hard_constraints_satisfied ? "1" : "0"));
        for (const ExplanationLine& line : radius.value().explanation.lines) {
            response.add("explain " + line.category + " " + line.text);
        }
        return response;
    }
    if (command == "contain") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "contain <fault>");
        }
        FaultId fault;
        if (!id_argument<FaultId>(args[0], fault)) {
            return failure(ErrorCode::INVALID_ID, "contain: bad fault identity");
        }
        const Result<FaultRecord> record = engine.query_fault(fault);
        if (!record.ok()) {
            return failure(record.error().code(), record.error().to_string());
        }
        const Result<ContainmentRecord> containment =
            engine.authorize_containment(fault, record.value().evidence.generation);
        if (!containment.ok()) {
            return failure(containment.error().code(), containment.error().to_string());
        }
        ControlResponse response = success();
        response.add("containment=" + to_string(containment.value().generation));
        response.add("status=" + std::string(to_string(containment.value().status)));
        response.add("outcome=" + std::string(to_string(containment.value().outcome)));
        response.add("mandatory=" + join_ids(containment.value().mandatory));
        response.add("precautionary=" + join_ids(containment.value().precautionary));
        response.add("unaffected=" + join_ids(containment.value().unaffected));
        response.add("unresolved=" + join_ids(containment.value().unresolved));
        response.add("action_count=" + std::to_string(containment.value().actions.size()));
        for (const ActionId action_id : containment.value().actions) {
            response.add("action=" + to_string(action_id));
        }
        return response;
    }
    if (command == "containment") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "containment <generation>");
        }
        ContainmentGeneration generation;
        if (!id_argument<ContainmentGeneration>(args[0], generation)) {
            return failure(ErrorCode::INVALID_ID, "containment: bad generation");
        }
        const Result<ContainmentRecord> record = engine.query_containment(generation);
        if (!record.ok()) {
            return failure(record.error().code(), record.error().to_string());
        }
        ControlResponse response = success();
        response.add("generation=" + to_string(record.value().generation));
        response.add("status=" + std::string(to_string(record.value().status)));
        response.add("verified=" + std::string(record.value().verified ? "1" : "0"));
        response.add("verification_outcome=" +
                     std::string(to_string(record.value().verification_outcome)));
        response.add("degraded_status=" + std::string(to_string(record.value().degraded_status)));
        response.add("mandatory=" + join_ids(record.value().mandatory));
        response.add("unaffected=" + join_ids(record.value().unaffected));
        response.add("released=" + join_ids(record.value().released));
        response.add("action_count=" + std::to_string(record.value().actions.size()));
        for (const ActionId action_id : record.value().actions) {
            response.add("action=" + to_string(action_id));
        }
        return response;
    }
    if (command == "explain") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "explain <containment>");
        }
        ContainmentGeneration generation;
        if (!id_argument<ContainmentGeneration>(args[0], generation)) {
            return failure(ErrorCode::INVALID_ID, "explain: bad generation");
        }
        const Result<ContainmentExplanation> explanation = engine.explain(generation);
        if (!explanation.ok()) {
            return failure(explanation.error().code(), explanation.error().to_string());
        }
        ControlResponse response = success();
        for (const ExplanationLine& line : explanation.value().lines) {
            response.add(line.category + " " + line.text);
        }
        return response;
    }
    if (command == "dispatch") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "dispatch <containment>");
        }
        ContainmentGeneration generation;
        if (!id_argument<ContainmentGeneration>(args[0], generation)) {
            return failure(ErrorCode::INVALID_ID, "dispatch: bad generation");
        }
        ControlResponse response = success();
        response.add("dispatch_requires_executor=1");
        return response;
    }
    if (command == "verify") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "verify <containment>");
        }
        ContainmentGeneration generation;
        if (!id_argument<ContainmentGeneration>(args[0], generation)) {
            return failure(ErrorCode::INVALID_ID, "verify: bad generation");
        }
        const Result<ContainmentVerification> verification = engine.verify_containment(generation);
        if (!verification.ok()) {
            return failure(verification.error().code(), verification.error().to_string());
        }
        ControlResponse response = success();
        response.add("outcome=" + std::string(to_string(verification.value().outcome)));
        response.add("proven_contained=" + std::to_string(verification.value().proven_contained.size()));
        response.add("unproven=" + std::to_string(verification.value().unproven.size()));
        response.add("propagation_blocked=" +
                     std::string(verification.value().propagation_blocked ? "1" : "0"));
        response.add("degraded_mode_valid=" +
                     std::string(verification.value().degraded_mode_valid ? "1" : "0"));
        response.add("blast_radius_increased=" +
                     std::string(verification.value().blast_radius_increased ? "1" : "0"));
        response.add("secondary_failure=" +
                     std::string(verification.value().secondary_failure ? "1" : "0"));
        response.add("summary=" + verification.value().summary);
        for (const VerificationFinding& finding : verification.value().findings) {
            response.add("check " + finding.check + "=" + std::string(finding.passed ? "pass" : "fail") +
                         " " + finding.detail);
        }
        return response;
    }
    if (command == "resource") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "resource <id>");
        }
        ResourceId id;
        if (!id_argument<ResourceId>(args[0], id)) {
            return failure(ErrorCode::INVALID_ID, "resource: bad identity");
        }
        const Result<ResourceStatusView> view = engine.query_resource_status(id);
        if (!view.ok()) {
            return failure(view.error().code(), view.error().to_string());
        }
        ControlResponse response = success();
        response.add("resource=" + to_string(view.value().resource.id));
        response.add("state=" + std::string(to_string(view.value().resource.state)));
        response.add("generation=" + to_string(view.value().resource.generation));
        response.add("quarantined=" + std::string(view.value().quarantined ? "1" : "0"));
        response.add("operable=" + std::string(view.value().operable ? "1" : "0"));
        response.add("contained=" + std::string(view.value().contained ? "1" : "0"));
        response.add("freshness=" + std::string(to_string(view.value().resource.freshness)));
        response.add("mechanism=" + std::string(to_string(view.value().resource.mechanism)));
        response.add("owner_boot=" + to_string(view.value().resource.owner_boot));
        response.add("containment=" + to_string(view.value().containment_generation));
        return response;
    }
    if (command == "action") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "action <id>");
        }
        ActionId id;
        if (!id_argument<ActionId>(args[0], id)) {
            return failure(ErrorCode::INVALID_ID, "action: bad identity");
        }
        const Result<ContainmentAction> action = engine.query_action(id);
        if (!action.ok()) {
            return failure(action.error().code(), action.error().to_string());
        }
        ControlResponse response = success();
        response.add("action=" + to_string(action.value().id));
        response.add("kind=" + std::string(to_string(action.value().kind)));
        response.add("status=" + std::string(to_string(action.value().status)));
        response.add("target=" + to_string(action.value().target));
        response.add("rejection_code=" + std::string(to_string(action.value().rejection_code)));
        response.add("rejection_detail=" + action.value().rejection_detail);
        return response;
    }
    if (command == "degraded") {
        if (args.size() < 1) {
            return failure(ErrorCode::INVALID_ARGUMENT, "degraded <containment>");
        }
        ContainmentGeneration generation;
        if (!id_argument<ContainmentGeneration>(args[0], generation)) {
            return failure(ErrorCode::INVALID_ID, "degraded: bad generation");
        }
        const Result<ContainmentRecord> record = engine.query_containment(generation);
        if (!record.ok()) {
            return failure(record.error().code(), record.error().to_string());
        }
        DegradedModeContract contract;
        contract.name = "auto/" + to_string(generation);
        contract.containment_generation = generation;
        const Result<DegradedModeAssessment> assessment = engine.authorize_degraded_mode(contract);
        if (!assessment.ok()) {
            return failure(assessment.error().code(), assessment.error().to_string());
        }
        ControlResponse response = success();
        response.add("status=" + std::string(to_string(assessment.value().status)));
        response.add("permitted=" + join_ids(assessment.value().permitted));
        response.add("prohibited=" + join_ids(assessment.value().prohibited));
        response.add("revalidation_required=" + join_ids(assessment.value().revalidation_required));
        response.add("capacity_percent=" + std::to_string(assessment.value().available_capacity_percent));
        response.add("contract=" + to_string(assessment.value().contract));
        return response;
    }
    if (command == "release") {
        if (args.size() < 3) {
            return failure(ErrorCode::INVALID_ARGUMENT,
                           "release <resource> <containment> <authority>");
        }
        ReleaseRequest release_request;
        if (!id_argument<ResourceId>(args[0], release_request.resource) ||
            !id_argument<ContainmentGeneration>(args[1], release_request.containment_generation)) {
            return failure(ErrorCode::INVALID_ID, "release: bad identity argument");
        }
        release_request.authority = args[2];
        release_request.epoch = engine.epoch();
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
        const auto resource = snapshot->topology.resources.find(release_request.resource);
        if (resource != snapshot->topology.resources.end()) {
            release_request.expected_generation = resource->second.generation;
            release_request.evidence_sequence = resource->second.evidence_sequence;
        }
        const Result<ReleaseAssessment> assessment = engine.authorize_release(release_request);
        if (!assessment.ok()) {
            return failure(assessment.error().code(), assessment.error().to_string());
        }
        ControlResponse response = success();
        response.add("decision=" + std::string(to_string(assessment.value().decision)));
        response.add("granted=" + std::string(assessment.value().granted ? "1" : "0"));
        response.add("release_generation=" + to_string(assessment.value().generation));
        response.add("summary=" + assessment.value().summary);
        for (const VerificationFinding& finding : assessment.value().criteria) {
            response.add("criterion " + finding.check + "=" +
                         std::string(finding.passed ? "pass" : "fail") + " " + finding.detail);
        }
        return response;
    }
    if (command == "snapshot-info") {
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine.snapshot();
        ControlResponse response = success();
        response.add("epoch=" + to_string(snapshot->epoch));
        response.add("resources=" + std::to_string(snapshot->topology.resources.size()));
        response.add("domains=" + std::to_string(snapshot->topology.containment_domains.size()));
        response.add("isolation_domains=" +
                     std::to_string(snapshot->topology.isolation_domains.size()));
        response.add("failure_domains=" + std::to_string(snapshot->topology.failure_domains.size()));
        response.add("dependencies=" + std::to_string(snapshot->topology.dependencies.edges.size()));
        response.add("faults=" + std::to_string(snapshot->faults.size()));
        response.add("containments=" + std::to_string(snapshot->containments.size()));
        response.add("actions=" + std::to_string(snapshot->actions.size()));
        response.add("history_in_memory=" + std::to_string(snapshot->history.size()));
        response.add("history_total=" + std::to_string(snapshot->history_total));
        response.add("durability_healthy=" + std::string(engine.durability_healthy() ? "1" : "0"));
        return response;
    }
    if (command == "shutdown") {
        ControlResponse response = success();
        response.add("shutdown=accepted");
        return response;
    }
    return failure(ErrorCode::NOT_FOUND, "unknown control command: " + command);
}

// --- Coordinator -----------------------------------------------------------------------

struct Coordinator::Impl {
    Config config;
    std::unique_ptr<Engine> engine;
    Listener listener;
    std::thread acceptor;
    std::atomic<bool> stopped{false};

    std::mutex connection_mutex;
    std::condition_variable connection_drained;
    std::size_t active_connections = 0;
    std::vector<Socket*> live_sockets;
    std::map<WorkerBootId, Socket*> peer_sockets;

    std::mutex shutdown_mutex;
    std::condition_variable shutdown_cv;
    bool shutdown_requested = false;

    /// Control commands that need coordinator-level state rather than engine state.
    Result<ControlResponse> execute(const ControlRequest& request);

    class SocketExecutor : public Executor {
    public:
        explicit SocketExecutor(Impl& owner) : owner_(owner) {}

        Result<std::string> dispatch(const ContainmentAction& action) override {
            if (!action.envelope.worker_boot.valid()) {
                // The coordinator owns logical containment for unowned resources:
                // revoking authority and disabling admission rather than pretending
                // to perform hardware isolation.
                return std::string("coordinator:logical:") + to_string(action.id);
            }
            Socket* peer = nullptr;
            {
                std::lock_guard<std::mutex> guard(owner_.connection_mutex);
                const auto it = owner_.peer_sockets.find(action.envelope.worker_boot);
                if (it != owner_.peer_sockets.end()) {
                    peer = it->second;
                }
            }
            if (peer == nullptr) {
                // An incarnation that is no longer live cannot execute anything. Its
                // authority is already revoked, so the coordinator is the correct
                // enforcement point: the containment is real process containment of a
                // process the coordinator observed dying.
                const std::shared_ptr<const RuntimeSnapshot> snapshot = owner_.engine->snapshot();
                const ResourceId target = action.envelope.target;
                const auto resource = snapshot->topology.resources.find(target);
                const bool same_incarnation =
                    resource != snapshot->topology.resources.end() &&
                    resource->second.owner_boot == action.envelope.worker_boot;
                const auto incarnation = snapshot->workers.incarnations.find(
                    WorkerKey{action.envelope.worker, action.envelope.worker_boot});
                const bool dead = incarnation != snapshot->workers.incarnations.end() &&
                                  !holds_live_authority(incarnation->second.state);
                if (same_incarnation && dead) {
                    return std::string("coordinator:dead-incarnation:") + to_string(action.id);
                }
                return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "coordinator.dispatch",
                                  "no live connection for the target worker incarnation",
                                  to_string(action.envelope.worker_boot));
            }
            const Result<std::vector<std::byte>> payload =
                encode_action_dispatch(ActionDispatchMessage{action});
            if (!payload.ok()) {
                return payload.error();
            }
            const Status sent = peer->send_frame(MessageKind::ACTION_DISPATCH, payload.value());
            if (!sent.ok()) {
                return sent.error();
            }
            return std::string("peer:") + to_string(action.envelope.worker_boot);
        }

    private:
        Impl& owner_;
    };

    /// Dispatches a committed containment and records the coordinator's own
    /// acknowledgments for actions it enforces itself.
    void dispatch_and_settle(ContainmentGeneration generation) {
        SocketExecutor executor(*this);
        const Result<DispatchSummary> summary = engine->dispatch_containment(generation, &executor);
        if (!summary.ok()) {
            return;
        }
        const std::shared_ptr<const RuntimeSnapshot> snapshot = engine->snapshot();
        const auto containment = snapshot->containments.find(generation);
        if (containment == snapshot->containments.end()) {
            return;
        }
        for (const ActionId action_id : summary.value().dispatched) {
            const auto action = snapshot->actions.find(action_id);
            if (action == snapshot->actions.end()) {
                continue;
            }
            ContainmentMechanism mechanism = ContainmentMechanism::LOGICAL_CONTAINMENT;
            if (action->second.envelope.worker_boot.valid()) {
                const auto incarnation = snapshot->workers.incarnations.find(
                    WorkerKey{action->second.envelope.worker, action->second.envelope.worker_boot});
                if (incarnation == snapshot->workers.incarnations.end() ||
                    holds_live_authority(incarnation->second.state)) {
                    // A live peer owns this action; it will report its own outcome.
                    continue;
                }
                // The owning process is gone: the coordinator enforces containment for
                // an incarnation that can no longer run anything.
                mechanism = ContainmentMechanism::PROCESS_CONTAINMENT;
            }
            ActionAcknowledgment ack;
            ack.action = action_id;
            ack.action_generation = action->second.generation;
            ack.epoch = engine->epoch();
            ack.accepted = true;
            ack.executor_token = "coordinator:enforcement";
            ack.detail = "containment enforced by the coordinator";
            (void)engine->record_action_ack(ack);

            ActionResult result;
            result.action = action_id;
            result.action_generation = action->second.generation;
            result.epoch = engine->epoch();
            result.success = true;
            result.mechanism = mechanism;
            result.detail = mechanism == ContainmentMechanism::PROCESS_CONTAINMENT
                                ? "the owning process was observed dead and its authority revoked"
                                : "authority revoked and admission disabled by the coordinator";
            (void)engine->record_action_result(result);
        }
    }

    /// Serves one connection. The socket object lives in a shared_ptr owned by the
    /// connection thread and registered in live_sockets, so shutdown can close the
    /// exact socket the thread is blocked on.
    void serve(Socket& socket);

    void handle_frame(Socket& socket, const Frame& frame, WorkerId& worker, WorkerBootId& boot,
                      bool& hello_done);
};

void Coordinator::Impl::handle_frame(Socket& socket, const Frame& frame, WorkerId& worker,
                                     WorkerBootId& boot, bool& hello_done) {
    auto reject = [&socket](ErrorCode code, const std::string& detail) {
        const Result<std::vector<std::byte>> payload = encode_reject(RejectMessage{code, detail});
        if (payload.ok()) {
            (void)socket.send_frame(MessageKind::REJECT, payload.value());
        }
    };

    switch (frame.kind) {
        case MessageKind::HELLO: {
            const Result<HelloMessage> hello = decode_hello(frame.payload);
            if (!hello.ok()) {
                reject(hello.error().code(), hello.error().to_string());
                return;
            }
            const Result<WorkerRecord> record =
                engine->register_worker(hello.value().worker, hello.value().boot, hello.value().endpoint,
                                        hello.value().sequence);
            HelloAckMessage ack;
            if (!record.ok()) {
                ack.accepted = false;
                ack.detail = record.error().to_string();
            } else {
                ack.accepted = true;
                ack.epoch = engine->epoch();
                ack.incarnation = record.value().incarnation;
                ack.detail = "registered";
                worker = hello.value().worker;
                boot = hello.value().boot;
                hello_done = true;
                const std::lock_guard<std::mutex> guard(connection_mutex);
                peer_sockets[boot] = &socket;
            }
            const Result<std::vector<std::byte>> payload = encode_hello_ack(ack);
            if (!payload.ok()) {
                reject(payload.error().code(), payload.error().to_string());
                return;
            }
            (void)socket.send_frame(MessageKind::HELLO_ACK, payload.value());
            return;
        }
        case MessageKind::WORKER_EVIDENCE: {
            const Result<WorkerEvidenceMessage> evidence = decode_worker_evidence(frame.payload);
            if (!evidence.ok()) {
                reject(evidence.error().code(), evidence.error().to_string());
                return;
            }
            WorkerEvidenceAck ack;
            if (!hello_done || evidence.value().boot != boot) {
                ack.granted = false;
                ack.detail = "evidence for an incarnation that did not complete the handshake";
                reject(ErrorCode::STALE_WORKER_BOOT, ack.detail);
                return;
            }
            if (evidence.value().epoch != engine->epoch()) {
                ack.granted = false;
                ack.detail = "stale coordinator epoch";
                reject(ErrorCode::STALE_EPOCH, ack.detail);
                return;
            }
            const std::shared_ptr<const RuntimeSnapshot> snapshot = engine->snapshot();
            const auto resource = snapshot->topology.resources.find(evidence.value().resource);
            if (resource == snapshot->topology.resources.end()) {
                ack.granted = false;
                ack.detail = "unknown resource";
                reject(ErrorCode::UNKNOWN_RESOURCE, ack.detail);
                return;
            }
            if (evidence.value().generation.valid() &&
                evidence.value().generation != resource->second.generation) {
                ack.granted = false;
                ack.detail = "evidence targets a superseded resource generation";
                reject(ErrorCode::STALE_RESOURCE_GENERATION, ack.detail);
                return;
            }
            if (resource->second.quarantined || is_contained(resource->second.state)) {
                // The resource stays fenced: a fresh incarnation never inherits the
                // authority of the incarnation that was contained.
                const Result<ResourceRecord> published = engine->publish_resource_evidence(
                    evidence.value().resource, ResourceGeneration{}, evidence.value().freshness,
                    evidence.value().sequence, evidence.value().mechanism,
                    "worker " + to_string(evidence.value().boot));
                ack.granted = false;
                ack.fenced = true;
                ack.generation = published.ok() ? published.value().generation : ResourceGeneration{};
                ack.detail = "resource is under containment; evidence recorded without granting authority";
                const Result<std::vector<std::byte>> payload = encode_worker_evidence_ack(ack);
                if (payload.ok()) {
                    (void)socket.send_frame(MessageKind::WORKER_EVIDENCE_ACK, payload.value());
                }
                return;
            }
            ResourceRecord record = resource->second;
            const ResourceGeneration expected = record.generation;
            record.owner_worker = evidence.value().worker;
            record.owner_boot = evidence.value().boot;
            record.state = ResourceOperationalState::ACTIVE;
            const Result<ResourceRecord> updated = engine->update_resource(record, expected);
            if (!updated.ok()) {
                ack.granted = false;
                ack.detail = updated.error().to_string();
                reject(updated.error().code(), ack.detail);
                return;
            }
            const Result<ResourceRecord> published = engine->publish_resource_evidence(
                evidence.value().resource, updated.value().generation, EvidenceFreshness::FRESH,
                evidence.value().sequence, evidence.value().mechanism,
                "worker " + to_string(evidence.value().boot));
            if (!published.ok()) {
                ack.granted = false;
                ack.detail = published.error().to_string();
                reject(published.error().code(), ack.detail);
                return;
            }
            ack.granted = true;
            ack.generation = published.value().generation;
            ack.detail = "evidence accepted and authority granted";
            const Result<std::vector<std::byte>> payload = encode_worker_evidence_ack(ack);
            if (!payload.ok()) {
                reject(payload.error().code(), payload.error().to_string());
                return;
            }
            (void)socket.send_frame(MessageKind::WORKER_EVIDENCE_ACK, payload.value());
            return;
        }
        case MessageKind::HEARTBEAT:
            // Liveness is evidenced by the open connection itself; no state changes.
            return;
        case MessageKind::FAULT_REPORT: {
            const Result<FaultReportMessage> report = decode_fault_report(frame.payload);
            if (!report.ok()) {
                reject(report.error().code(), report.error().to_string());
                return;
            }
            if (!hello_done || report.value().boot != boot) {
                reject(ErrorCode::STALE_WORKER_BOOT, "fault report from an unhandshaken incarnation");
                return;
            }
            FaultEvidence evidence = report.value().evidence;
            evidence.reporter_kind = ReporterKind::WORKER;
            evidence.reporter_worker = report.value().worker;
            evidence.reporter_boot = report.value().boot;
            bool duplicate = false;
            const Result<FaultRecord> published = engine->publish_fault(evidence, &duplicate);
            if (!published.ok()) {
                reject(published.error().code(), published.error().to_string());
                return;
            }
            if (!duplicate && is_fault_current(published.value().state)) {
                const Result<ContainmentRecord> containment = engine->authorize_containment(
                    published.value().evidence.id, published.value().evidence.generation);
                if (containment.ok()) {
                    dispatch_and_settle(containment.value().generation);
                }
            }
            return;
        }
        case MessageKind::ACTION_ACK: {
            const Result<ActionAckMessage> ack = decode_action_ack(frame.payload);
            if (!ack.ok()) {
                reject(ack.error().code(), ack.error().to_string());
                return;
            }
            if (!hello_done) {
                reject(ErrorCode::STALE_WORKER_BOOT, "acknowledgment from an unhandshaken connection");
                return;
            }
            const Status recorded = engine->record_action_ack(ack.value().ack);
            if (!recorded.ok()) {
                reject(recorded.error().code(), recorded.error().to_string());
            }
            return;
        }
        case MessageKind::ACTION_RESULT: {
            const Result<ActionResultMessage> result = decode_action_result(frame.payload);
            if (!result.ok()) {
                reject(result.error().code(), result.error().to_string());
                return;
            }
            if (!hello_done) {
                reject(ErrorCode::STALE_WORKER_BOOT, "result from an unhandshaken connection");
                return;
            }
            const Status recorded = engine->record_action_result(result.value().result);
            if (!recorded.ok()) {
                reject(recorded.error().code(), recorded.error().to_string());
            }
            return;
        }
        case MessageKind::CONTROL_REQUEST: {
            const Result<ControlRequest> decoded = decode_control_request(frame.payload);
            if (!decoded.ok()) {
                reject(decoded.error().code(), decoded.error().to_string());
                return;
            }
            Result<ControlResponse> response = execute(decoded.value());
            if (!response.ok()) {
                reject(response.error().code(), response.error().to_string());
                return;
            }
            const Result<std::vector<std::byte>> payload = encode_control_response(response.value());
            if (!payload.ok()) {
                reject(payload.error().code(), payload.error().to_string());
                return;
            }
            (void)socket.send_frame(MessageKind::CONTROL_RESPONSE, payload.value());
            return;
        }
        case MessageKind::HELLO_ACK:
        case MessageKind::WORKER_EVIDENCE_ACK:
        case MessageKind::QUERY_REQUEST:
        case MessageKind::QUERY_RESPONSE:
        case MessageKind::CONTROL_RESPONSE:
        case MessageKind::SHUTDOWN:
            reject(ErrorCode::FRAME_CORRUPT, "message kind is not valid in this direction");
            return;
        case MessageKind::REJECT:
        case MessageKind::ACTION_DISPATCH:
            reject(ErrorCode::FRAME_CORRUPT, "message kind is not valid from a peer");
            return;
    }
    reject(ErrorCode::FRAME_CORRUPT, "unknown mandatory message type");
}

void Coordinator::Impl::serve(Socket& socket) {
    WorkerId worker;
    WorkerBootId boot;
    bool hello_done = false;
    for (;;) {
        const Result<Frame> frame = socket.receive_frame();
        if (!frame.ok()) {
            break;
        }
        handle_frame(socket, frame.value(), worker, boot, hello_done);
    }

    {
        std::lock_guard<std::mutex> guard(connection_mutex);
        if (hello_done) {
            peer_sockets.erase(boot);
        }
        const auto it = std::find(live_sockets.begin(), live_sockets.end(), &socket);
        if (it != live_sockets.end()) {
            live_sockets.erase(it);
        }
        --active_connections;
    }
    connection_drained.notify_all();

    if (hello_done) {
        // A closed connection without a graceful retirement is an observed
        // authority loss for that exact incarnation.
        const Result<ContainmentRecord> containment = engine->worker_authority_lost(
            worker, boot, FaultKind::PROCESS_DEATH,
            "worker connection closed without graceful retirement", 0);
        if (containment.ok()) {
            dispatch_and_settle(containment.value().generation);
        }
    }
}

Result<std::unique_ptr<Coordinator>> Coordinator::start(Config config) {
    const Status ready = initialise_network();
    if (!ready.ok()) {
        return ready.error();
    }
    std::unique_ptr<Coordinator> coordinator(new Coordinator());
    coordinator->impl_ = std::make_shared<Impl>();
    Impl& impl = *coordinator->impl_;
    impl.config = std::move(config);
    impl.engine = std::make_unique<Engine>(impl.config.engine);
    if (impl.config.store != nullptr) {
        const Status attached = impl.engine->attach_store(impl.config.store);
        if (!attached.ok()) {
            return attached.error();
        }
        const Result<CoordinatorEpoch> recovered =
            impl.engine->recover_from_store(*impl.config.store, impl.config.now_ms);
        if (!recovered.ok()) {
            return recovered.error();
        }
    }
    Result<Listener> listener = Listener::bind(impl.config.host, impl.config.port);
    if (!listener.ok()) {
        return listener.error();
    }
    impl.listener = std::move(listener.value());
    coordinator->port_ = impl.listener.port();
    coordinator->engine_ = impl.engine.get();

    impl.acceptor = std::thread([&impl]() {
        for (;;) {
            Result<Socket> accepted = impl.listener.accept();
            if (!accepted.ok()) {
                return;
            }
            // The socket is owned by the connection thread through this shared_ptr,
            // and the registry points at that same live object so shutdown can close
            // exactly the socket the thread is blocked on.
            std::shared_ptr<Socket> socket = std::make_shared<Socket>(std::move(accepted.value()));
            {
                std::lock_guard<std::mutex> guard(impl.connection_mutex);
                if (impl.stopped.load() ||
                    impl.active_connections >= impl.config.max_connections) {
                    socket->close();
                    continue;
                }
                ++impl.active_connections;
                impl.live_sockets.push_back(socket.get());
            }
            std::thread([&impl, socket]() { impl.serve(*socket); }).detach();
        }
    });
    return coordinator;
}

Coordinator::~Coordinator() { stop(); }

void Coordinator::stop() {
    if (!impl_) {
        return;
    }
    Impl& impl = *impl_;
    if (impl.stopped.exchange(true)) {
        return;
    }
    impl.listener.close();
    {
        std::lock_guard<std::mutex> guard(impl.connection_mutex);
        for (Socket* socket : impl.live_sockets) {
            socket->close();
        }
    }
    impl.connection_drained.notify_all();
    {
        std::unique_lock<std::mutex> lock(impl.connection_mutex);
        impl.connection_drained.wait(lock, [&impl]() { return impl.active_connections == 0; });
    }
    if (impl.acceptor.joinable()) {
        impl.acceptor.join();
    }
    if (impl.engine) {
        impl.engine->shutdown();
    }
}

Result<ControlResponse> Coordinator::Impl::execute(const ControlRequest& request) {
    if (request.command == "shutdown") {
        ControlResponse response;
        response.ok = true;
        response.add("shutdown=accepted");
        {
            std::lock_guard<std::mutex> guard(shutdown_mutex);
            shutdown_requested = true;
        }
        shutdown_cv.notify_all();
        return response;
    }
    if (request.command == "poll-workers") {
        // Deterministic evidence pull: the coordinator asks every live peer for
        // fresh evidence instead of relying on timers.
        std::vector<Socket*> peers;
        {
            std::lock_guard<std::mutex> guard(connection_mutex);
            for (const auto& entry : peer_sockets) {
                peers.push_back(entry.second);
            }
        }
        ControlResponse response;
        response.ok = true;
        std::size_t sent = 0;
        for (Socket* peer : peers) {
            const Status status = peer->send_frame(MessageKind::QUERY_REQUEST, {});
            if (status.ok()) {
                ++sent;
            }
        }
        response.add("polled=" + std::to_string(sent));
        return response;
    }
    return execute_engine_control(*engine, request);
}

Result<ControlResponse> Coordinator::execute_control(const ControlRequest& request) {
    return impl_->execute(request);
}

void Coordinator::request_shutdown() {
    {
        std::lock_guard<std::mutex> guard(impl_->shutdown_mutex);
        impl_->shutdown_requested = true;
    }
    impl_->shutdown_cv.notify_all();
}

bool Coordinator::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(impl_->shutdown_mutex);
    impl_->shutdown_cv.wait(lock, [this]() { return impl_->shutdown_requested; });
    return true;
}

std::string Coordinator::capability_report() const {
    std::string out;
    out += "REAL: independent Windows processes over framed TCP (Winsock)\n";
    out += "REAL: coordinator epoch advance and durable journal on restart\n";
    out += "REAL: process termination observed as connection loss and authority revocation\n";
    out += "REAL: logical containment (authority revocation, admission denial, quarantine)\n";
    out += "REAL: process containment of a worker incarnation the coordinator owns\n";
    out += "REAL: versioned, CRC32C-checked snapshot plus write-ahead journal\n";
    out += "SYNTHETIC: multi-device and multi-rack failure domains (declared by the operator)\n";
    out += "UNSUPPORTED: hardware isolation primitives (GPU reset, MIG, NVLink, PCIe, RDMA)\n";
    return out;
}

}  // namespace fcf
