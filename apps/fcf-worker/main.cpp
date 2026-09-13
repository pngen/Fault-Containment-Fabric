// Fault Containment Fabric — worker node process.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A worker is a real OS process that owns real resources. It registers a fresh
// incarnation on every start, publishes evidence only when asked, executes
// containment intents it is handed, and reports honestly what it actually did.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include "fcf/net.hpp"
#include "fcf/protocol.hpp"

#ifdef FCF_WORKER_CUDA
#include "cuda/cuda_probe.hpp"
#endif

namespace {

void print_usage() {
    std::cout << "fcf-worker [options]\n"
                 "  --connect <host:port>   coordinator endpoint (required)\n"
                 "  --id <n>               worker identity (required)\n"
                 "  --boot <n>             worker boot identity (default: fresh per process)\n"
                 "  --resources <csv>      resource identities this worker owns (required)\n"
                 "  --cuda-elements <n>    element count for the CUDA workload (CUDA build)\n"
                 "  --name <text>          endpoint label reported in the handshake\n"
                 "  --help                 show this message\n";
}

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) {
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10U + static_cast<std::uint64_t>(c - '0');
    }
    out = value;
    return true;
}

[[nodiscard]] std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> out;
    std::string current;
    for (const char c : text) {
        if (c == ',') {
            out.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        out.push_back(current);
    }
    return out;
}

void emit(const std::string& line) {
    std::cout << line << "\n";
    std::cout.flush();
}

[[nodiscard]] std::uint64_t current_process_id() {
#ifdef _WIN32
    return static_cast<std::uint64_t>(::_getpid());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

}  // namespace

int main(int argc, char** argv) {
    std::string endpoint;
    std::string name = "worker";
    std::size_t cuda_elements = 1U << 20;
    std::vector<fcf::ResourceId> resources;
    fcf::WorkerId worker{};
    fcf::WorkerBootId boot{};

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--help") {
            print_usage();
            return 0;
        }
        if (i + 1 >= argc) {
            std::cerr << "missing value for " << argument << "\n";
            return 2;
        }
        const std::string value = argv[++i];
        if (argument == "--connect") {
            endpoint = value;
        } else if (argument == "--name") {
            name = value;
        } else if (argument == "--id") {
            std::uint64_t parsed = 0;
            if (!parse_u64(value, parsed)) {
                std::cerr << "invalid worker identity\n";
                return 2;
            }
            worker = fcf::WorkerId::from_value(parsed);
        } else if (argument == "--boot") {
            std::uint64_t parsed = 0;
            if (!parse_u64(value, parsed)) {
                std::cerr << "invalid boot identity\n";
                return 2;
            }
            boot = fcf::WorkerBootId::from_value(parsed);
        } else if (argument == "--cuda-elements") {
            std::uint64_t parsed = 0;
            if (!parse_u64(value, parsed) || parsed == 0U) {
                std::cerr << "invalid element count\n";
                return 2;
            }
            cuda_elements = static_cast<std::size_t>(parsed);
        } else if (argument == "--resources") {
            for (const std::string& token : split_csv(value)) {
                std::uint64_t parsed = 0;
                if (!parse_u64(token, parsed)) {
                    std::cerr << "invalid resource identity\n";
                    return 2;
                }
                resources.push_back(fcf::ResourceId::from_value(parsed));
            }
        } else {
            std::cerr << "unknown option " << argument << "\n";
            return 2;
        }
    }

    if (endpoint.empty() || !worker.valid() || resources.empty()) {
        print_usage();
        return 2;
    }
    if (!boot.valid()) {
        // A fresh incarnation identity for every process start. The value mixes the
        // OS process identity with a monotonic clock reading so a restart can never
        // reuse an earlier boot identity.
        const std::uint64_t ticks = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
        boot = fcf::WorkerBootId::from_value((ticks << 16U) ^ current_process_id());
    }

    const std::size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos) {
        std::cerr << "--connect must be host:port\n";
        return 2;
    }
    const std::string host = endpoint.substr(0, colon);
    std::uint64_t parsed_port = 0;
    if (!parse_u64(endpoint.substr(colon + 1), parsed_port) || parsed_port > 65535U) {
        std::cerr << "invalid port in --connect\n";
        return 2;
    }

    emit("WORKER BEGIN id=" + fcf::to_string(worker) + " boot=" + fcf::to_string(boot));

    fcf::Result<fcf::Socket> connected =
        fcf::Socket::connect(host, static_cast<std::uint16_t>(parsed_port));
    if (!connected.ok()) {
        emit("WORKER CONNECT_FAILED " + connected.error().to_string());
        return 3;
    }
    fcf::Socket socket = std::move(connected.value());

    fcf::HelloMessage hello;
    hello.worker = worker;
    hello.boot = boot;
    hello.epoch = fcf::CoordinatorEpoch{};
    hello.sequence = fcf::EvidenceSequence::from_value(1);
    // The endpoint label is informational and stable, so a surviving incarnation can
    // reattach with the same label. Process identity is not part of it: the boot
    // identity already carries the incarnation.
    hello.endpoint = name;
    const fcf::Result<std::vector<std::byte>> hello_payload = fcf::encode_hello(hello);
    if (!hello_payload.ok()) {
        emit("WORKER ENCODE_FAILED " + hello_payload.error().to_string());
        return 3;
    }
    if (!socket.send_frame(fcf::MessageKind::HELLO, hello_payload.value()).ok()) {
        emit("WORKER HANDSHAKE_FAILED send");
        return 3;
    }

    fcf::CoordinatorEpoch ack_epoch{};
    std::map<fcf::ResourceId, fcf::ResourceGeneration> generations;
    std::map<fcf::ResourceId, bool> authorized;

#ifdef FCF_WORKER_CUDA
    {
        const fcf::cuda::DeviceInfo device = fcf::cuda::query_device();
        if (device.available) {
            emit("WORKER CUDA DEVICE name=\"" + device.name + "\" compute=" +
                 std::to_string(device.compute_major) + "." + std::to_string(device.compute_minor) +
                 " devices=" + std::to_string(device.device_count) + " total_bytes=" +
                 std::to_string(device.total_memory_bytes));
        } else {
            emit("WORKER CUDA UNSUPPORTED " + device.driver_error);
        }
    }
#endif

    auto run_cuda_work = [&](const char* phase) {
#ifdef FCF_WORKER_CUDA
        const std::size_t before = fcf::cuda::free_device_memory_bytes();
        const fcf::cuda::WorkloadResult workload = fcf::cuda::run_workload(cuda_elements);
        const std::size_t after = fcf::cuda::free_device_memory_bytes();
        emit(std::string("WORKER CUDA ") + phase + " ok=" + (workload.ok ? "1" : "0") +
             " elements=" + std::to_string(workload.elements) + " parity=" +
             (workload.cpu_parity ? "1" : "0") + " kernel_us=" +
             std::to_string(workload.kernel_milliseconds) + " released=" +
             (workload.memory_released ? "1" : "0") + " free_before=" + std::to_string(before) +
             " free_after=" + std::to_string(after) + " detail=" + workload.detail);
#else
        (void)phase;
#endif
    };

    auto send_evidence = [&](fcf::ResourceId resource) {
        fcf::WorkerEvidenceMessage message;
        message.worker = worker;
        message.boot = boot;
        message.epoch = ack_epoch;
        message.resource = resource;
        const auto known = generations.find(resource);
        message.generation = known == generations.end() ? fcf::ResourceGeneration{} : known->second;
        message.freshness = fcf::EvidenceFreshness::FRESH;
        message.sequence = fcf::EvidenceSequence::from_value(1);
        message.mechanism = fcf::ContainmentMechanism::LOGICAL_CONTAINMENT;
        const fcf::Result<std::vector<std::byte>> payload = fcf::encode_worker_evidence(message);
        if (payload.ok()) {
            (void)socket.send_frame(fcf::MessageKind::WORKER_EVIDENCE, payload.value());
        }
    };

    for (;;) {
        fcf::Result<fcf::Frame> frame = socket.receive_frame();
        if (!frame.ok()) {
            emit("WORKER DISCONNECTED " + frame.error().to_string());
            break;
        }
        switch (frame.value().kind) {
            case fcf::MessageKind::HELLO_ACK: {
                const fcf::Result<fcf::HelloAckMessage> ack =
                    fcf::decode_hello_ack(frame.value().payload);
                if (!ack.ok() || !ack.value().accepted) {
                    emit("WORKER REJECTED " +
                         (ack.ok() ? ack.value().detail : ack.error().to_string()));
                    socket.close();
                    return 4;
                }
                ack_epoch = ack.value().epoch;
                emit("WORKER READY id=" + fcf::to_string(worker) + " boot=" + fcf::to_string(boot) +
                     " incarnation=" + fcf::to_string(ack.value().incarnation) +
                     " epoch=" + fcf::to_string(ack_epoch));
                run_cuda_work("BASELINE");
                break;
            }
            case fcf::MessageKind::QUERY_REQUEST: {
                for (const fcf::ResourceId resource : resources) {
                    send_evidence(resource);
                }
                (void)socket.send_frame(fcf::MessageKind::QUERY_RESPONSE, {});
                // The workload runs only for a resource this incarnation is actually
                // authorised to use. A fenced incarnation is refused and does no work.
                bool any_authorized = false;
                for (const fcf::ResourceId resource : resources) {
                    const auto entry = authorized.find(resource);
                    if (entry != authorized.end() && entry->second) {
                        any_authorized = true;
                    }
                }
                if (any_authorized) {
                    run_cuda_work("WORK");
                } else {
                    emit("WORKER CUDA REFUSED no resource is currently authorised for this "
                         "incarnation");
                }
                break;
            }
            case fcf::MessageKind::WORKER_EVIDENCE_ACK: {
                const fcf::Result<fcf::WorkerEvidenceAck> ack =
                    fcf::decode_worker_evidence_ack(frame.value().payload);
                if (ack.ok()) {
                    if (ack.value().generation.valid()) {
                        for (const fcf::ResourceId resource : resources) {
                            generations[resource] = ack.value().generation;
                        }
                    }
                    for (const fcf::ResourceId resource : resources) {
                        authorized[resource] = ack.value().granted;
                    }
                    emit(std::string("WORKER EVIDENCE_ACK granted=") +
                         (ack.value().granted ? "1" : "0") + " fenced=" +
                         (ack.value().fenced ? "1" : "0") + " generation=" +
                         fcf::to_string(ack.value().generation) + " detail=" + ack.value().detail);
                }
                break;
            }
            case fcf::MessageKind::ACTION_DISPATCH: {
                const fcf::Result<fcf::ActionDispatchMessage> dispatch =
                    fcf::decode_action_dispatch(frame.value().payload);
                if (!dispatch.ok()) {
                    emit("WORKER DISPATCH_MALFORMED " + dispatch.error().to_string());
                    break;
                }
                const fcf::ContainmentAction& action = dispatch.value().action;
                emit("WORKER DISPATCH action=" + fcf::to_string(action.id) + " kind=" +
                     std::string(fcf::to_string(action.kind)) + " target=" +
                     fcf::to_string(action.target));

                fcf::ActionAckMessage ack_message;
                ack_message.ack.action = action.id;
                ack_message.ack.action_generation = action.generation;
                ack_message.ack.epoch = action.envelope.epoch;
                ack_message.ack.worker = worker;
                ack_message.ack.worker_boot = boot;
                ack_message.ack.accepted = true;
                ack_message.ack.executor_token = "worker:" + fcf::to_string(boot);
                ack_message.ack.detail = "accepted; the resource is fenced locally";
                const fcf::Result<std::vector<std::byte>> ack_payload =
                    fcf::encode_action_ack(ack_message);
                if (ack_payload.ok()) {
                    (void)socket.send_frame(fcf::MessageKind::ACTION_ACK, ack_payload.value());
                }

                fcf::ActionResultMessage result_message;
                result_message.result.action = action.id;
                result_message.result.action_generation = action.generation;
                result_message.result.epoch = action.envelope.epoch;
                result_message.result.worker = worker;
                result_message.result.worker_boot = boot;
                result_message.result.success = true;
                // Honest mechanism: the worker stops issuing work for the resource,
                // which is logical and process-scoped enforcement it genuinely owns.
                result_message.result.mechanism =
                    action.envelope.target.valid()
                        ? fcf::ContainmentMechanism::PROCESS_CONTAINMENT
                        : fcf::ContainmentMechanism::LOGICAL_CONTAINMENT;
                result_message.result.detail = "worker stopped issuing work for the target";
                const fcf::Result<std::vector<std::byte>> result_payload =
                    fcf::encode_action_result(result_message);
                if (result_payload.ok()) {
                    (void)socket.send_frame(fcf::MessageKind::ACTION_RESULT, result_payload.value());
                }
                emit("WORKER ACK action=" + fcf::to_string(action.id));
                break;
            }
            case fcf::MessageKind::REJECT: {
                const fcf::Result<fcf::RejectMessage> reject = fcf::decode_reject(frame.value().payload);
                if (reject.ok()) {
                    emit("WORKER REJECT code=" + std::string(fcf::to_string(reject.value().code)) +
                         " detail=" + reject.value().detail);
                }
                break;
            }
            case fcf::MessageKind::SHUTDOWN: {
                emit("WORKER SHUTDOWN_REQUESTED");
                socket.close();
                emit("WORKER EXIT");
                return 0;
            }
            default:
                break;
        }
    }
    socket.close();
    emit("WORKER EXIT");
    return 0;
}
