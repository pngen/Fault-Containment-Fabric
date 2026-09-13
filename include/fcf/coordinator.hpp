// Fault Containment Fabric — reference coordinator node.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator hosts one Engine and speaks the framed protocol over real TCP.
// Worker connections carry evidence, fault reports and action outcomes; a
// controller connection carries the closed control vocabulary.

#ifndef FCF_COORDINATOR_HPP
#define FCF_COORDINATOR_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "fcf/engine.hpp"
#include "fcf/protocol.hpp"
#include "fcf/result.hpp"

namespace fcf {

class Coordinator {
public:
    struct Config {
        Engine::Config engine;
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
        /// When set, durable state is recovered on start and journaled thereafter.
        DurableStore* store = nullptr;
        std::size_t max_connections = 64;
        std::uint64_t now_ms = 0;
    };

    /// Binds the listener, recovers durable state when configured, and starts
    /// accepting connections.
    [[nodiscard]] static Result<std::unique_ptr<Coordinator>> start(Config config);

    ~Coordinator();
    Coordinator(const Coordinator&) = delete;
    Coordinator& operator=(const Coordinator&) = delete;

    [[nodiscard]] Engine& engine() noexcept { return *engine_; }
    [[nodiscard]] const Engine& engine() const noexcept { return *engine_; }
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

    /// Stops accepting work, closes every connection, waits for in-flight
    /// handlers to drain, then flushes durable state.
    void stop();

    /// Asks the node to shut down without joining anything. Safe to call from a
    /// connection handler; the owner thread observes it through wait_for_shutdown().
    void request_shutdown();

    /// Blocks until request_shutdown() has been observed. Returns true when a
    /// shutdown was requested.
    bool wait_for_shutdown();

    /// The single control surface. The socket handler is a thin codec around this.
    [[nodiscard]] Result<ControlResponse> execute_control(const ControlRequest& request);

    /// REAL/SYNTHETIC/UNSUPPORTED labelled statement of what this deployment does.
    [[nodiscard]] std::string capability_report() const;

private:
    Coordinator() = default;

    struct Impl;
    std::shared_ptr<Impl> impl_;
    Engine* engine_ = nullptr;
    std::uint16_t port_ = 0;
};

/// Executes one control request against an engine. Used by the CLI in embedded
/// mode and by the coordinator's socket handler.
[[nodiscard]] Result<ControlResponse> execute_engine_control(Engine& engine,
                                                             const ControlRequest& request);

}  // namespace fcf

#endif  // FCF_COORDINATOR_HPP
