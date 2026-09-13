// Fault Containment Fabric — coordinator node process.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fcf/coordinator.hpp"
#include "fcf/persistence.hpp"

namespace {

void print_usage() {
    std::cout << "fcf-coordinator [options]\n"
                 "  --host <address>      bind address (default 127.0.0.1)\n"
                 "  --port <port>         bind port; 0 selects an ephemeral port (default 0)\n"
                 "  --state-dir <path>    enable the durable snapshot and write-ahead journal\n"
                 "  --capabilities        print the REAL/SYNTHETIC/UNSUPPORTED capability report\n"
                 "  --no-stdin            do not read control commands from standard input\n"
                 "  --help                show this message\n";
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

}  // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    std::string state_directory;
    bool read_stdin = true;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--help") {
            print_usage();
            return 0;
        }
        if (argument == "--no-stdin") {
            read_stdin = false;
            continue;
        }
        if (argument == "--capabilities") {
            std::cout << "REAL: Windows x64 processes, Winsock framed TCP, durable journal\n"
                         "REAL: coordinator epoch advance and conservative recovery\n"
                         "REAL: worker authority revocation on observed process death\n"
                         "REAL: logical containment and coordinator-owned process containment\n"
                         "SYNTHETIC: multi-device, multi-host and multi-rack failure domains declared "
                         "by an operator\n"
                         "UNSUPPORTED: GPU reset isolation, MIG isolation, NVLink/NVSwitch fault "
                         "containment, PCIe fault isolation, RDMA/DPU containment\n";
            return 0;
        }
        if (i + 1 >= argc) {
            std::cerr << "missing value for " << argument << "\n";
            return 2;
        }
        const std::string value = argv[++i];
        if (argument == "--host") {
            host = value;
        } else if (argument == "--port") {
            std::uint64_t parsed = 0;
            if (!parse_u64(value, parsed) || parsed > 65535U) {
                std::cerr << "invalid port\n";
                return 2;
            }
            port = static_cast<std::uint16_t>(parsed);
        } else if (argument == "--state-dir") {
            state_directory = value;
        } else {
            std::cerr << "unknown option " << argument << "\n";
            return 2;
        }
    }

    std::unique_ptr<fcf::DurableStore> store;
    if (!state_directory.empty()) {
        fcf::DurableStore::Options options;
        options.directory = state_directory;
        fcf::Result<std::unique_ptr<fcf::DurableStore>> opened = fcf::DurableStore::open(options);
        if (!opened.ok()) {
            std::cerr << "state: " << opened.error().to_string() << "\n";
            return 3;
        }
        store = std::move(opened.value());
    }

    fcf::Coordinator::Config config;
    config.host = host;
    config.port = port;
    config.store = store.get();
    config.now_ms = 0;
    fcf::Result<std::unique_ptr<fcf::Coordinator>> started = fcf::Coordinator::start(config);
    if (!started.ok()) {
        std::cerr << "start: " << started.error().to_string() << "\n";
        return 4;
    }
    std::unique_ptr<fcf::Coordinator> coordinator = std::move(started.value());

    std::cout << "LISTENING " << coordinator->port() << " epoch "
              << fcf::to_string(coordinator->engine().epoch()) << "\n";
    std::cout.flush();

    if (read_stdin) {
        std::thread reader([&coordinator]() {
            std::string line;
            while (std::getline(std::cin, line)) {
                if (line.empty()) {
                    continue;
                }
                fcf::ControlRequest request;
                std::size_t position = 0;
                while (position <= line.size()) {
                    const std::size_t space = line.find(' ', position);
                    const std::string token =
                        line.substr(position, space == std::string::npos ? std::string::npos
                                                                         : space - position);
                    if (request.command.empty()) {
                        request.command = token;
                    } else if (!token.empty()) {
                        request.arguments.push_back(token);
                    }
                    if (space == std::string::npos) {
                        break;
                    }
                    position = space + 1;
                }
                if (request.command.empty()) {
                    continue;
                }
                const fcf::Result<fcf::ControlResponse> response =
                    coordinator->execute_control(request);
                if (!response.ok()) {
                    std::cout << "err " << fcf::to_string(response.error().code()) << " "
                              << response.error().message() << "\n.\n";
                } else {
                    std::cout << (response.value().ok ? "ok" : "err") << " "
                              << fcf::to_string(response.value().code) << " "
                              << response.value().message << "\n";
                    for (const std::string& output : response.value().lines) {
                        std::cout << output << "\n";
                    }
                    std::cout << ".\n";
                }
                std::cout.flush();
            }
            coordinator->request_shutdown();
        });
        reader.detach();
    }

    coordinator->wait_for_shutdown();
    coordinator->stop();
    std::cout << "STOPPED\n";
    std::cout.flush();
    return 0;
}
