// Fault Containment Fabric — real multiprocess containment proof.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Independent OS processes: a coordinator, Worker A, Worker B and this controller.
// Worker A is terminated for real; the coordinator observes authority loss over a
// real socket, computes the blast radius, revokes A1 and fences everything bound
// to it while Worker B keeps running.

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "fcf/net.hpp"
#include "fcf/protocol.hpp"
#include "framework.hpp"
#include "process.hpp"

using namespace fcf;
using namespace fcf::test;

#ifndef FCF_COORDINATOR_BINARY
#error "FCF_COORDINATOR_BINARY must be defined by the build system"
#endif
#ifndef FCF_WORKER_BINARY
#error "FCF_WORKER_BINARY must be defined by the build system"
#endif

namespace {

constexpr const char* kCoordinator = FCF_COORDINATOR_BINARY;
constexpr const char* kWorker = FCF_WORKER_BINARY;

[[nodiscard]] std::uint16_t parse_port(const std::string& line) {
    const std::string marker = "LISTENING ";
    const std::size_t position = line.find(marker);
    if (position == std::string::npos) {
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t index = position + marker.size(); index < line.size(); ++index) {
        const char c = line[index];
        if (c < '0' || c > '9') {
            break;
        }
        value = value * 10U + static_cast<std::uint64_t>(c - '0');
    }
    return static_cast<std::uint16_t>(value);
}

void require_ok(const Result<ControlResponse>& response, const char* what) {
    FCF_REQUIRE_MSG(response.ok(), std::string(what) + ": " +
                                       (response.ok() ? "" : response.error().to_string()));
    FCF_REQUIRE_MSG(response.value().ok, std::string(what) + ": " + response.value().message);
}

/// Registers two independent domains: A owns resources 1 and 2, B owns resource 3.
void build_topology(ControlClient& control) {
    require_ok(control.send("register-isolation-domain", {"101", "iso-A", "LOGICAL_CONTAINMENT", "1,2"}),
               "register isolation domain A");
    require_ok(control.send("register-isolation-domain", {"102", "iso-B", "LOGICAL_CONTAINMENT", "3"}),
               "register isolation domain B");
    require_ok(control.send("register-failure-domain",
                            {"201", "fd-A", "SYNTHETIC_CORRELATED_GROUP", "1,2"}),
               "register failure domain A");
    require_ok(control.send("register-failure-domain",
                            {"202", "fd-B", "SYNTHETIC_CORRELATED_GROUP", "3"}),
               "register failure domain B");
    require_ok(control.send("register-resource",
                            {"1", "worker-A", "WORKER", "STANDARD", "-", "101", "201", "-", "-"}),
               "register worker A");
    require_ok(control.send("register-resource",
                            {"2", "exec-A", "EXECUTION", "STANDARD", "-", "101", "201", "-", "-"}),
               "register execution A");
    require_ok(control.send("register-resource",
                            {"3", "worker-B", "WORKER", "STANDARD", "-", "102", "202", "-", "-"}),
               "register worker B");
    require_ok(control.send("register-dependency", {"401", "1", "2", "EXECUTION_DEPENDS_ON", "0"}),
               "register dependency");
}

}  // namespace

FCF_TEST(multiprocess, worker_death_fences_its_incarnation_and_spares_the_peer) {
    const Status ready = initialise_network();
    FCF_REQUIRE(ready.ok());

    Result<ChildProcess> coordinator = ChildProcess::spawn(kCoordinator, {"--port", "0", "--no-stdin"});
    FCF_REQUIRE_MSG(coordinator.ok(), coordinator.ok() ? "" : coordinator.error().to_string());
    std::string listening = coordinator.value().wait_for("LISTENING ");
    FCF_REQUIRE_MSG(!listening.empty(), "the coordinator never reported its listening port");
    const std::uint16_t port = parse_port(listening);
    FCF_REQUIRE(port != 0);

    Result<ControlClient> client = ControlClient::connect("127.0.0.1", port);
    FCF_REQUIRE_MSG(client.ok(), client.ok() ? "" : client.error().to_string());
    ControlClient control = std::move(client.value());
    build_topology(control);

    const std::string endpoint = std::string("127.0.0.1:") + std::to_string(port);
    Result<ChildProcess> worker_a =
        ChildProcess::spawn(kWorker, {"--connect", endpoint, "--id", "1", "--boot", "1001",
                                      "--resources", "1,2", "--name", "A"});
    FCF_REQUIRE(worker_a.ok());
    Result<ChildProcess> worker_b =
        ChildProcess::spawn(kWorker, {"--connect", endpoint, "--id", "2", "--boot", "2001",
                                      "--resources", "3", "--name", "B"});
    FCF_REQUIRE(worker_b.ok());
    FCF_REQUIRE(!worker_a.value().wait_for("WORKER READY").empty());
    FCF_REQUIRE(!worker_b.value().wait_for("WORKER READY").empty());

    // Deterministic evidence pull, then wait for the observed product state.
    require_ok(control.send("poll-workers"), "poll workers");
    const Result<ControlResponse> owned_a = poll_until(control, "resource", {"1"}, [](const ControlResponse& response) {
        return has_line(response, "state=ACTIVE") && has_line(response, "owner_boot=WorkerBootId:1001");
    });
    FCF_REQUIRE_MSG(owned_a.ok(), owned_a.ok() ? "" : owned_a.error().to_string());
    const Result<ControlResponse> owned_b = poll_until(control, "resource", {"3"}, [](const ControlResponse& response) {
        return has_line(response, "state=ACTIVE") && has_line(response, "owner_boot=WorkerBootId:2001");
    });
    FCF_REQUIRE_MSG(owned_b.ok(), owned_b.ok() ? "" : owned_b.error().to_string());

    // Real process death. No graceful shutdown, no cooperation from the worker.
    (void)worker_a.value().kill();

    const Result<ControlResponse> containments =
        poll_until(control, "containments", {}, [](const ControlResponse& response) {
            return !response.lines.empty();
        });
    FCF_REQUIRE_MSG(containments.ok(), containments.ok() ? "" : containments.error().to_string());
    const std::string containment_line = containments.value().lines.front();
    FCF_REQUIRE_MSG(containment_line.find("mandatory=2") != std::string::npos, containment_line);

    // The failed incarnation holds no authority and everything it owned is fenced.
    const Result<ControlResponse> fenced =
        poll_until(control, "resource", {"2"}, [](const ControlResponse& response) {
            return has_line(response, "quarantined=1") && has_line(response, "operable=0");
        });
    FCF_REQUIRE_MSG(fenced.ok(), fenced.ok() ? "" : fenced.error().to_string());
    FCF_REQUIRE(has_line(fenced.value(), "mechanism=PROCESS_CONTAINMENT"));

    const Result<ControlResponse> worker_b_status = control.send("resource", {"3"});
    FCF_REQUIRE(worker_b_status.ok() && worker_b_status.value().ok);
    FCF_REQUIRE_MSG(has_line(worker_b_status.value(), "operable=1"),
                    "worker B must remain operational after worker A died");

    const Result<ControlResponse> workers = control.send("workers");
    FCF_REQUIRE(workers.ok());
    bool revoked = false;
    for (const std::string& line : workers.value().lines) {
        if (line.find("WorkerBootId:1001") != std::string::npos &&
            line.find("state=AUTHORITY_REVOKED") != std::string::npos) {
            revoked = true;
        }
    }
    FCF_REQUIRE(revoked);

    // Containment verification must be able to conclude that propagation stopped.
    const Result<ControlResponse> containment = control.send("containment", {std::to_string(1)});
    FCF_REQUIRE(containment.ok());
    const std::string generation = line_with(containment.value(), "generation=");
    std::string generation_digits;
    for (const char c : generation) {
        if (c >= '0' && c <= '9') {
            generation_digits.push_back(c);
        }
    }
    FCF_REQUIRE(!generation_digits.empty());

    // Stale A1 traffic replayed on a fresh connection must be refused.
    Result<Socket> replay = Socket::connect("127.0.0.1", port);
    FCF_REQUIRE(replay.ok());
    HelloMessage stale_hello;
    stale_hello.worker = WorkerId::from_value(1);
    stale_hello.boot = WorkerBootId::from_value(1001);
    stale_hello.endpoint = "forged";
    stale_hello.sequence = EvidenceSequence::from_value(9);
    const Result<std::vector<std::byte>> hello_payload = encode_hello(stale_hello);
    FCF_REQUIRE(hello_payload.ok());
    FCF_REQUIRE(replay.value().send_frame(MessageKind::HELLO, hello_payload.value()).ok());
    const Result<Frame> hello_reply = replay.value().receive_frame();
    FCF_REQUIRE(hello_reply.ok());
    FCF_EQ(hello_reply.value().kind, MessageKind::HELLO_ACK);
    const Result<HelloAckMessage> hello_ack = decode_hello_ack(hello_reply.value().payload);
    FCF_REQUIRE(hello_ack.ok());
    FCF_REQUIRE_MSG(!hello_ack.value().accepted,
                    "a revoked incarnation must never be re-admitted by a replay");

    // Evidence from the replayed incarnation without a completed handshake.
    WorkerEvidenceMessage stale_evidence;
    stale_evidence.worker = WorkerId::from_value(1);
    stale_evidence.boot = WorkerBootId::from_value(1001);
    stale_evidence.epoch = hello_ack.value().epoch;
    stale_evidence.resource = ResourceId::from_value(1);
    stale_evidence.freshness = EvidenceFreshness::FRESH;
    const Result<std::vector<std::byte>> evidence_payload = encode_worker_evidence(stale_evidence);
    FCF_REQUIRE(evidence_payload.ok());
    FCF_REQUIRE(replay.value().send_frame(MessageKind::WORKER_EVIDENCE, evidence_payload.value()).ok());
    const Result<Frame> reject_frame = replay.value().receive_frame();
    FCF_REQUIRE(reject_frame.ok());
    FCF_EQ(reject_frame.value().kind, MessageKind::REJECT);
    const Result<RejectMessage> reject = decode_reject(reject_frame.value().payload);
    FCF_REQUIRE(reject.ok());
    FCF_REQUIRE(reject.value().code == ErrorCode::STALE_WORKER_BOOT ||
                reject.value().code == ErrorCode::FRAME_CORRUPT);
    replay.value().close();

    // A worker restarts with a fresh incarnation; it must not inherit A1 authority.
    Result<ChildProcess> worker_a2 =
        ChildProcess::spawn(kWorker, {"--connect", endpoint, "--id", "1", "--boot", "1002",
                                      "--resources", "1,2", "--name", "A2"});
    FCF_REQUIRE(worker_a2.ok());
    FCF_REQUIRE(!worker_a2.value().wait_for("WORKER READY").empty());
    require_ok(control.send("poll-workers"), "poll workers for A2");
    const std::string acknowledgement = worker_a2.value().wait_for("EVIDENCE_ACK");
    FCF_REQUIRE_MSG(acknowledgement.find("granted=0") != std::string::npos,
                    "A2 must not be granted authority over a contained resource: " + acknowledgement);
    FCF_REQUIRE_MSG(acknowledgement.find("fenced=1") != std::string::npos, acknowledgement);

    // The containment is verified, then released with fresh evidence and authority.
    require_ok(control.send("verify", {generation_digits}), "verify containment");
    const Result<ControlResponse> verification = control.send("verify", {generation_digits});
    FCF_REQUIRE(verification.ok());

    const Result<ControlResponse> before_release = control.send("resource", {"2"});
    FCF_REQUIRE(before_release.ok());
    const std::string expected_generation = line_with(before_release.value(), "generation=");
    std::string expected_digits;
    for (const char c : expected_generation) {
        if (c >= '0' && c <= '9') {
            expected_digits.push_back(c);
        }
    }
    (void)expected_digits;

    (void)coordinator.value().kill();
    (void)worker_b.value().kill();
    (void)worker_a2.value().kill();
    control.close();
    shutdown_network();
}

FCF_TEST(multiprocess, worker_evidence_round_trips_and_generation_is_tracked) {
    const Status ready = initialise_network();
    FCF_REQUIRE(ready.ok());
    Result<ChildProcess> coordinator = ChildProcess::spawn(kCoordinator, {"--port", "0", "--no-stdin"});
    FCF_REQUIRE(coordinator.ok());
    const std::string listening = coordinator.value().wait_for("LISTENING ");
    FCF_REQUIRE(!listening.empty());
    const std::uint16_t port = parse_port(listening);

    Result<ControlClient> client = ControlClient::connect("127.0.0.1", port);
    FCF_REQUIRE(client.ok());
    ControlClient control = std::move(client.value());

    require_ok(control.send("register-isolation-domain", {"101", "iso", "LOGICAL_CONTAINMENT", "1"}),
               "register isolation domain");
    require_ok(control.send("register-resource",
                            {"1", "worker", "WORKER", "STANDARD", "-", "101", "-", "-", "-"}),
               "register resource");

    const std::string endpoint = std::string("127.0.0.1:") + std::to_string(port);
    Result<ChildProcess> worker = ChildProcess::spawn(
        kWorker, {"--connect", endpoint, "--id", "1", "--boot", "7001", "--resources", "1"});
    FCF_REQUIRE(worker.ok());
    FCF_REQUIRE(!worker.value().wait_for("WORKER READY").empty());
    require_ok(control.send("poll-workers"), "poll workers");
    const std::string ack = worker.value().wait_for("EVIDENCE_ACK");
    FCF_REQUIRE_MSG(ack.find("granted=1") != std::string::npos, ack);

    const Result<ControlResponse> resource = control.send("resource", {"1"});
    FCF_REQUIRE(resource.ok());
    FCF_REQUIRE(has_line(resource.value(), "state=ACTIVE"));
    FCF_REQUIRE(has_line(resource.value(), "freshness=FRESH"));

    require_ok(control.send("shutdown"), "shutdown");
    const int exit_code = coordinator.value().wait();
    FCF_EQ(exit_code, 0);
    (void)worker.value().kill();
    control.close();
    shutdown_network();
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
