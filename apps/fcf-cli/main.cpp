// Fault Containment Fabric — inspection and control client.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "fcf/coordinator.hpp"
#include "fcf/engine.hpp"
#include "fcf/net.hpp"
#include "fcf/persistence.hpp"
#include "fcf/protocol.hpp"

namespace {

void print_usage() {
    std::cout
        << "fcf-cli [--connect <host:port> | --state-dir <path>] <command> [arguments...]\n"
           "\n"
           "Connection:\n"
           "  --connect <host:port>  send the command to a running coordinator\n"
           "  --state-dir <path>     inspect durable state offline in this process\n"
           "\n"
           "Commands (identical for both modes):\n"
           "  status | faults | containments | workers | snapshot-info\n"
           "  resource <id> | action <id> | containment <generation> | explain <generation>\n"
           "  evaluate <fault> | contain <fault> | verify <containment> | degraded <containment>\n"
           "  release <resource> <containment> <authority>\n"
           "  history <from-sequence> [limit]\n"
           "  register-domain <id> <name> <co_isolate> [members]\n"
           "  register-isolation-domain <id> <name> <mechanism> [members]\n"
           "  register-failure-domain <id> <name> <kind> [members]\n"
           "  register-resource <id> <name> <class> <protection> <cd> <idom> <fdom> <worker> <boot>\n"
           "  register-dependency <id> <source> <destination> <kind> [conditional]\n"
           "  set-resource-owner <resource> <worker> <boot>\n"
           "  publish-fault <id> <kind> <subject> [details]\n"
           "  worker-lost <worker> <boot> <fault-kind>\n"
           "  poll-workers | shutdown\n";
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

void render(const fcf::ControlResponse& response) {
    std::cout << (response.ok ? "ok" : "err") << " " << fcf::to_string(response.code);
    if (!response.message.empty()) {
        std::cout << " " << response.message;
    }
    std::cout << "\n";
    for (const std::string& line : response.lines) {
        std::cout << line << "\n";
    }
    std::cout.flush();
}

}  // namespace

int main(int argc, char** argv) {
    std::string endpoint;
    std::string state_directory;
    fcf::ControlRequest request;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--help" || argument == "-h") {
            print_usage();
            return 0;
        }
        if (argument == "--connect" || argument == "--state-dir") {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << argument << "\n";
                return 2;
            }
            const std::string value = argv[++i];
            if (argument == "--connect") {
                endpoint = value;
            } else {
                state_directory = value;
            }
            continue;
        }
        if (request.command.empty()) {
            request.command = argument;
        } else {
            request.arguments.push_back(argument);
        }
    }

    if (request.command.empty()) {
        print_usage();
        return 2;
    }

    if (!endpoint.empty()) {
        const std::size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos) {
            std::cerr << "--connect must be host:port\n";
            return 2;
        }
        std::uint64_t port = 0;
        if (!parse_u64(endpoint.substr(colon + 1), port) || port > 65535U) {
            std::cerr << "invalid port\n";
            return 2;
        }
        fcf::Result<fcf::Socket> connected =
            fcf::Socket::connect(endpoint.substr(0, colon), static_cast<std::uint16_t>(port));
        if (!connected.ok()) {
            std::cerr << "connect: " << connected.error().to_string() << "\n";
            return 3;
        }
        fcf::Socket socket = std::move(connected.value());
        const fcf::Result<std::vector<std::byte>> payload = fcf::encode_control_request(request);
        if (!payload.ok()) {
            std::cerr << "encode: " << payload.error().to_string() << "\n";
            return 3;
        }
        const fcf::Status sent = socket.send_frame(fcf::MessageKind::CONTROL_REQUEST, payload.value());
        if (!sent.ok()) {
            std::cerr << "send: " << sent.error().to_string() << "\n";
            return 3;
        }
        fcf::Result<fcf::Frame> frame = socket.receive_frame();
        if (!frame.ok()) {
            std::cerr << "receive: " << frame.error().to_string() << "\n";
            return 3;
        }
        if (frame.value().kind == fcf::MessageKind::REJECT) {
            const fcf::Result<fcf::RejectMessage> reject = fcf::decode_reject(frame.value().payload);
            if (reject.ok()) {
                std::cout << "rejected " << fcf::to_string(reject.value().code) << " "
                          << reject.value().detail << "\n";
            }
            return 1;
        }
        const fcf::Result<fcf::ControlResponse> response =
            fcf::decode_control_response(frame.value().payload);
        if (!response.ok()) {
            std::cerr << "decode: " << response.error().to_string() << "\n";
            return 3;
        }
        render(response.value());
        return response.value().ok ? 0 : 1;
    }

    if (state_directory.empty()) {
        std::cerr << "either --connect or --state-dir is required\n";
        return 2;
    }
    fcf::DurableStore::Options options;
    options.directory = state_directory;
    fcf::Result<std::unique_ptr<fcf::DurableStore>> opened = fcf::DurableStore::open(options);
    if (!opened.ok()) {
        std::cerr << "state: " << opened.error().to_string() << "\n";
        return 3;
    }
    fcf::Engine::Config config;
    fcf::Engine engine(config);
    const fcf::Result<fcf::CoordinatorEpoch> recovered =
        engine.recover_from_store(*opened.value(), 0);
    if (!recovered.ok()) {
        std::cerr << "recover: " << recovered.error().to_string() << "\n";
        return 3;
    }
    const fcf::Result<fcf::ControlResponse> response = fcf::execute_engine_control(engine, request);
    if (!response.ok()) {
        std::cerr << "control: " << response.error().to_string() << "\n";
        return 3;
    }
    render(response.value());
    return response.value().ok ? 0 : 1;
}
