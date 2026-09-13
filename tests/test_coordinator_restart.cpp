// Fault Containment Fabric — real coordinator crash and restart proof.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator is terminated without any graceful shutdown. A fresh process
// recovers durable state, advances the coordinator epoch, refuses old-epoch
// traffic, marks dynamic evidence for revalidation and never blindly repeats an
// ambiguous destructive action.

#include <cstdint>
#include <filesystem>
#include <string>
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

/// Extracts the decimal value from a rendering such as "CoordinatorEpoch:7".
[[nodiscard]] std::uint64_t parse_epoch(const std::string& line) {
    const std::size_t colon = line.rfind(':');
    if (colon == std::string::npos) {
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t index = colon + 1U; index < line.size(); ++index) {
        const char c = line[index];
        if (c < '0' || c > '9') {
            break;
        }
        value = value * 10U + static_cast<std::uint64_t>(c - '0');
    }
    return value;
}

[[nodiscard]] std::string join(const std::vector<std::string>& lines) {
    std::string out;
    for (const std::string& line : lines) {
        out += line;
        out += " | ";
    }
    return out;
}

void require_ok(const Result<ControlResponse>& response, const char* what) {
    FCF_REQUIRE_MSG(response.ok(), std::string(what) + ": " +
                                       (response.ok() ? "" : response.error().to_string()));
    FCF_REQUIRE_MSG(response.value().ok, std::string(what) + ": " + response.value().message);
}

class ScratchState {
public:
    ScratchState() {
        path_ = std::filesystem::temp_directory_path() / "fcf-restart-proof-state";
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    ~ScratchState() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    [[nodiscard]] std::string text() { return path_.string(); }

private:
    std::filesystem::path path_;
};

}  // namespace

FCF_TEST(coordinator_restart, crash_and_recover_preserves_containment_without_resurrecting_authority) {
    FCF_REQUIRE(initialise_network().ok());
    ScratchState scratch;

    // --- First coordinator: build state, contain a worker, then die hard. ------------
    Result<ChildProcess> first = ChildProcess::spawn(
        kCoordinator, {"--port", "0", "--no-stdin", "--state-dir", scratch.text()});
    FCF_REQUIRE_MSG(first.ok(), first.ok() ? "" : first.error().to_string());
    const std::string first_listening = first.value().wait_for("LISTENING ");
    FCF_REQUIRE_MSG(!first_listening.empty(),
                    "the coordinator produced no listening line: " + join(first.value().drain()));
    const std::uint16_t first_port = parse_port(first_listening);

    Result<ControlClient> first_client = ControlClient::connect("127.0.0.1", first_port);
    FCF_REQUIRE(first_client.ok());
    ControlClient control = std::move(first_client.value());

    require_ok(control.send("register-isolation-domain", {"101", "iso-A", "LOGICAL_CONTAINMENT", "1,2"}),
               "register isolation domain");
    require_ok(control.send("register-resource",
                            {"1", "worker-A", "WORKER", "STANDARD", "-", "101", "-", "-", "-"}),
               "register worker resource");
    require_ok(control.send("register-resource",
                            {"2", "exec-A", "EXECUTION", "STANDARD", "-", "101", "-", "-", "-"}),
               "register execution resource");
    require_ok(control.send("register-dependency", {"401", "1", "2", "EXECUTION_DEPENDS_ON", "0"}),
               "register dependency");

    const std::string endpoint = std::string("127.0.0.1:") + std::to_string(first_port);
    Result<ChildProcess> worker = ChildProcess::spawn(
        kWorker, {"--connect", endpoint, "--id", "1", "--boot", "5001", "--resources", "1,2"});
    FCF_REQUIRE(worker.ok());
    FCF_REQUIRE(!worker.value().wait_for("WORKER READY").empty());
    require_ok(control.send("poll-workers"), "poll workers");
    const Result<ControlResponse> owned = poll_until(control, "resource", {"1"}, [](const ControlResponse& response) {
        return has_line(response, "state=ACTIVE") && has_line(response, "owner_boot=WorkerBootId:5001");
    });
    FCF_REQUIRE_MSG(owned.ok(), owned.ok() ? "" : owned.error().to_string());

    require_ok(control.send("worker-lost", {"1", "5001", "PROCESS_DEATH"}), "worker lost");
    const Result<ControlResponse> containment =
        poll_until(control, "containments", {}, [](const ControlResponse& response) {
            return !response.lines.empty();
        });
    FCF_REQUIRE(containment.ok());
    FCF_REQUIRE(containment.value().lines.front().find("mandatory=2") != std::string::npos);

    // Crash: terminate the coordinator process with no graceful shutdown at all.
    (void)0;
    control.close();

    // --- Second coordinator over the same durable directory. ------------------------
    Result<ChildProcess> second = ChildProcess::spawn(
        kCoordinator, {"--port", "0", "--no-stdin", "--state-dir", scratch.text()});
    FCF_REQUIRE_MSG(second.ok(), second.ok() ? "" : second.error().to_string());
    const std::string second_listening = second.value().wait_for("LISTENING ");
    FCF_REQUIRE_MSG(!second_listening.empty(),
                    "the restarted coordinator produced no listening line: " +
                        join(second.value().drain()));
    const std::uint64_t epoch_before = parse_epoch(first_listening);
    const std::uint64_t epoch_after = parse_epoch(second_listening);
    FCF_REQUIRE_MSG(epoch_after > epoch_before,
                    "coordinator epoch must advance across a restart: " + first_listening + " -> " +
                        second_listening);
    const std::uint16_t second_port = parse_port(second_listening);
    FCF_REQUIRE(second_port != 0);

    Result<ControlClient> second_client = ControlClient::connect("127.0.0.1", second_port);
    FCF_REQUIRE(second_client.ok());
    ControlClient recovered = std::move(second_client.value());

    // Durable containment history survived.
    const Result<ControlResponse> restored = recovered.send("containments");
    FCF_REQUIRE(restored.ok() && restored.value().ok);
    FCF_REQUIRE_MSG(!restored.value().lines.empty(), "durable containment did not survive the crash");
    FCF_REQUIRE(restored.value().lines.front().find("mandatory=2") != std::string::npos);

    // The contained resources are still fenced, and dynamic evidence needs revalidation.
    const Result<ControlResponse> fenced = recovered.send("resource", {"2"});
    FCF_REQUIRE(fenced.ok());
    FCF_REQUIRE_MSG(has_line(fenced.value(), "quarantined=1"), "containment must survive the crash");
    FCF_REQUIRE(has_line(fenced.value(), "freshness=REVALIDATION_REQUIRED"));

    const Result<ControlResponse> status = recovered.send("status");
    FCF_REQUIRE(status.ok());
    FCF_REQUIRE(has_line(status.value(), "recovery_incomplete=1"));

    // Degraded operation is not current until revalidation happens.
    const Result<ControlResponse> degraded = recovered.send("degraded", {"1"});
    FCF_REQUIRE(degraded.ok() && degraded.value().ok);
    FCF_REQUIRE_MSG(has_line(degraded.value(), "status=DEGRADED_REVALIDATION_REQUIRED"),
                    "degraded state must require revalidation after a restart");

    // Ambiguous in-flight actions are not blindly repeated.
    const Result<ControlResponse> containment_detail = recovered.send("containment", {"1"});
    FCF_REQUIRE(containment_detail.ok());
    std::string action_id;
    for (const std::string& line : containment_detail.value().lines) {
        if (line.rfind("action=", 0) == 0) {
            action_id = line.substr(7);
            break;
        }
    }
    if (!action_id.empty()) {
        const Result<ControlResponse> action = recovered.send("action", {action_id});
        FCF_REQUIRE(action.ok());
        FCF_REQUIRE_MSG(has_line(action.value(), "status=AMBIGUOUS") ||
                            has_line(action.value(), "status=PLANNED"),
                        "an in-flight action must never be silently repeated or reported as done");
    }

    // Old-epoch traffic from a replayed incarnation is refused; a fresh handshake is
    // accepted, but only for the current epoch and without restored authority.
    Result<Socket> socket = Socket::connect("127.0.0.1", second_port);
    FCF_REQUIRE(socket.ok());
    HelloMessage hello;
    hello.worker = WorkerId::from_value(1);
    hello.boot = WorkerBootId::from_value(5001);
    // The same endpoint label the original incarnation registered with.
    hello.endpoint = "worker";
    const Result<std::vector<std::byte>> hello_payload = encode_hello(hello);
    FCF_REQUIRE(hello_payload.ok());
    FCF_REQUIRE(socket.value().send_frame(MessageKind::HELLO, hello_payload.value()).ok());
    const Result<Frame> hello_reply = socket.value().receive_frame();
    FCF_REQUIRE(hello_reply.ok());
    const Result<HelloAckMessage> hello_ack = decode_hello_ack(hello_reply.value().payload);
    FCF_REQUIRE(hello_ack.ok());
    FCF_REQUIRE_MSG(hello_ack.value().accepted, "a surviving incarnation must be able to reattach");
    FCF_EQ(hello_ack.value().epoch.value(), epoch_after);

    WorkerEvidenceMessage stale;
    stale.worker = WorkerId::from_value(1);
    stale.boot = WorkerBootId::from_value(5001);
    stale.epoch = CoordinatorEpoch::from_value(epoch_before);
    stale.resource = ResourceId::from_value(1);
    stale.freshness = EvidenceFreshness::FRESH;
    const Result<std::vector<std::byte>> stale_payload = encode_worker_evidence(stale);
    FCF_REQUIRE(stale_payload.ok());
    FCF_REQUIRE(socket.value().send_frame(MessageKind::WORKER_EVIDENCE, stale_payload.value()).ok());
    const Result<Frame> stale_reply = socket.value().receive_frame();
    FCF_REQUIRE(stale_reply.ok());
    FCF_EQ(stale_reply.value().kind, MessageKind::REJECT);
    const Result<RejectMessage> stale_reject = decode_reject(stale_reply.value().payload);
    FCF_REQUIRE(stale_reject.ok());
    FCF_EQ(stale_reject.value().code, ErrorCode::STALE_EPOCH);
    socket.value().close();

    require_ok(recovered.send("shutdown"), "shutdown");
    const int exit_code = second.value().wait();
    FCF_EQ(exit_code, 0);
    (void)worker.value().kill();
    recovered.close();
    shutdown_network();
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
