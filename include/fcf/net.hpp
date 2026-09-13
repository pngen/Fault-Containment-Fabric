// Fault Containment Fabric — real framed TCP transport.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// This is a genuine socket transport between independent OS processes. Every
// read is partial-read safe and every buffer is bounded, so a peer can neither
// overrun the frame ceiling nor make the runtime allocate on a claimed length.

#ifndef FCF_NET_HPP
#define FCF_NET_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "fcf/result.hpp"
#include "fcf/wire.hpp"

namespace fcf {

/// Winsock lifecycle. Reference counted so repeated start/stop is safe.
[[nodiscard]] Status initialise_network();
void shutdown_network();

/// Largest number of bytes buffered for one connection while reassembling frames.
inline constexpr std::size_t kMaxConnectionBufferBytes = 8U * 1024U * 1024U;

/// A connected, framed TCP socket. Movable, not copyable.
class Socket {
public:
    Socket() = default;
    ~Socket();
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    /// Connects to host:port. host may be a dotted IPv4 literal or a name.
    [[nodiscard]] static Result<Socket> connect(const std::string& host, std::uint16_t port);

    /// Writes one complete frame. Handles partial writes.
    [[nodiscard]] Status send_frame(MessageKind kind, std::span<const std::byte> payload);

    /// Reads exactly one frame. Blocks until a frame arrives, the peer closes, or
    /// the connection fails. Never assumes one read equals one frame.
    [[nodiscard]] Result<Frame> receive_frame();

    /// Closes the send side so the peer observes end-of-stream.
    void shutdown_send();
    /// Closes the connection. Idempotent and safe to call from another thread.
    void close();

    [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
    [[nodiscard]] std::string peer() const;

private:
    friend class Listener;
    static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ULL);
    std::uintptr_t handle_ = kInvalidHandle;
    std::vector<std::byte> residual_;
    std::string peer_;
};

/// A bound listening socket.
class Listener {
public:
    Listener() = default;
    ~Listener();
    Listener(Listener&& other) noexcept;
    Listener& operator=(Listener&& other) noexcept;
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    /// Binds to host:port. Port 0 selects an ephemeral port.
    [[nodiscard]] static Result<Listener> bind(const std::string& host, std::uint16_t port);

    /// Blocks until a peer connects. Fails once the listener is closed.
    [[nodiscard]] Result<Socket> accept();

    void close();
    [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

private:
    static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ULL);
    std::uintptr_t handle_ = kInvalidHandle;
    std::uint16_t port_ = 0;
};

}  // namespace fcf

#endif  // FCF_NET_HPP
