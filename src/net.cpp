// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/net.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#ifdef _WIN32
// The Windows SDK's ws2tcpip.h produces a C6101 diagnostic under /analyze for its own
// GetAdaptersAddresses glue. The suppression is scoped to this include and applies to no
// first-party code.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fcf {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

std::atomic<int> g_winsock_refs{0};
std::mutex g_winsock_mutex;

[[nodiscard]] Error socket_error(ErrorCode code, const char* stage, const std::string& what) {
    return make_error(code, stage, what, "wsa=" + std::to_string(WSAGetLastError()));
}

void close_native(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::closesocket(socket);
    }
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

std::atomic<int> g_winsock_refs{0};
std::mutex g_winsock_mutex;

[[nodiscard]] Error socket_error(ErrorCode code, const char* stage, const std::string& what) {
    return make_error(code, stage, what, std::string(std::strerror(errno)));
}

void close_native(NativeSocket socket) {
    if (socket != kInvalidSocket) {
        ::close(socket);
    }
}
#endif

}  // namespace

Status initialise_network() {
    std::lock_guard<std::mutex> guard(g_winsock_mutex);
    if (g_winsock_refs.fetch_add(1) == 0) {
#ifdef _WIN32
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc != 0) {
            g_winsock_refs.store(0);
            return fail(ErrorCode::INTERNAL, "net.init", "WSAStartup failed", std::to_string(rc));
        }
#endif
    }
    return ok_status();
}

void shutdown_network() {
    std::lock_guard<std::mutex> guard(g_winsock_mutex);
    if (g_winsock_refs.load() <= 0) {
        return;
    }
    if (g_winsock_refs.fetch_sub(1) == 1) {
#ifdef _WIN32
        WSACleanup();
#endif
    }
}

// --- Socket ----------------------------------------------------------------------------

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept
    : handle_(other.handle_), residual_(std::move(other.residual_)), peer_(std::move(other.peer_)) {
    other.handle_ = kInvalidHandle;
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        residual_ = std::move(other.residual_);
        peer_ = std::move(other.peer_);
        other.handle_ = kInvalidHandle;
    }
    return *this;
}

Result<Socket> Socket::connect(const std::string& host, std::uint16_t port) {
    const Status ready = initialise_network();
    if (!ready.ok()) {
        return ready.error();
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* results = nullptr;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.connect", "address resolution failed", host);
    }
    NativeSocket native = kInvalidSocket;
    for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
        native = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (native == kInvalidSocket) {
            continue;
        }
        if (::connect(native, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
            break;
        }
        close_native(native);
        native = kInvalidSocket;
    }
    ::freeaddrinfo(results);
    if (native == kInvalidSocket) {
        shutdown_network();
        return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "net.connect", "connection failed",
                          host + ":" + service);
    }
#ifdef _WIN32
    BOOL nodelay = TRUE;
    ::setsockopt(native, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                 sizeof(nodelay));
    DWORD send_buffer = 256U * 1024U;
    ::setsockopt(native, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&send_buffer),
                 sizeof(send_buffer));
#endif
    Socket socket;
    socket.handle_ = static_cast<std::uintptr_t>(native);
    socket.peer_ = host + ":" + service;
    return socket;
}

Status Socket::send_frame(MessageKind kind, std::span<const std::byte> payload) {
    Result<std::vector<std::byte>> encoded = encode_frame(kind, payload);
    if (!encoded.ok()) {
        return encoded.error();
    }
    const std::vector<std::byte>& bytes = encoded.value();
    if (handle_ == kInvalidHandle) {
        return fail(ErrorCode::EXECUTOR_UNAVAILABLE, "net.send", "socket is closed");
    }
    const NativeSocket native = static_cast<NativeSocket>(handle_);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const int chunk = static_cast<int>(
            std::min<std::size_t>(bytes.size() - offset, 1U << 20U));
        const int written = ::send(native, reinterpret_cast<const char*>(bytes.data() + offset), chunk, 0);
        if (written <= 0) {
            return fail(ErrorCode::EXECUTOR_UNAVAILABLE, "net.send", "send failed");
        }
        offset += static_cast<std::size_t>(written);
    }
    return ok_status();
}

Result<Frame> Socket::receive_frame() {
    if (handle_ == kInvalidHandle) {
        return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "net.receive", "socket is closed");
    }
    const NativeSocket native = static_cast<NativeSocket>(handle_);
    std::vector<std::byte> chunk(64U * 1024U);
    for (;;) {
        const FrameDecodeResult decoded =
            decode_frame_streaming(std::span<const std::byte>(residual_.data(), residual_.size()));
        if (decoded.state == FrameDecodeResult::State::COMPLETE) {
            residual_.erase(residual_.begin(),
                            residual_.begin() + static_cast<std::ptrdiff_t>(decoded.consumed));
            return decoded.frame;
        }
        if (decoded.state == FrameDecodeResult::State::FATAL) {
            return make_error(decoded.error, "net.receive", decoded.detail);
        }
        const int got = ::recv(native, reinterpret_cast<char*>(chunk.data()),
                               static_cast<int>(chunk.size()), 0);
        if (got == 0) {
            return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "net.receive",
                              "peer closed the connection");
        }
        if (got < 0) {
            return make_error(ErrorCode::EXECUTOR_UNAVAILABLE, "net.receive", "receive failed");
        }
        if (residual_.size() + static_cast<std::size_t>(got) > kMaxConnectionBufferBytes) {
            return make_error(ErrorCode::RESOURCE_EXHAUSTED, "net.receive",
                              "connection buffer ceiling exceeded");
        }
        residual_.insert(residual_.end(), chunk.begin(), chunk.begin() + got);
    }
}

void Socket::shutdown_send() {
    if (handle_ == kInvalidHandle) {
        return;
    }
#ifdef _WIN32
    ::shutdown(static_cast<NativeSocket>(handle_), SD_SEND);
#else
    ::shutdown(static_cast<NativeSocket>(handle_), SHUT_WR);
#endif
}

void Socket::close() {
    if (handle_ != kInvalidHandle) {
        const NativeSocket native = static_cast<NativeSocket>(handle_);
        handle_ = kInvalidHandle;
        close_native(native);
        shutdown_network();
    }
    residual_.clear();
}

std::string Socket::peer() const { return peer_; }

// --- Listener --------------------------------------------------------------------------

Listener::~Listener() { close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
    other.handle_ = kInvalidHandle;
}

Listener& Listener::operator=(Listener&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        port_ = other.port_;
        other.handle_ = kInvalidHandle;
    }
    return *this;
}

Result<Listener> Listener::bind(const std::string& host, std::uint16_t port) {
    const Status ready = initialise_network();
    if (!ready.ok()) {
        return ready.error();
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* results = nullptr;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &results) != 0 ||
        results == nullptr) {
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.bind", "address resolution failed", host);
    }
    NativeSocket native = ::socket(results->ai_family, results->ai_socktype, results->ai_protocol);
    if (native == kInvalidSocket) {
        ::freeaddrinfo(results);
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.bind", "socket creation failed");
    }
    int reuse = 1;
    ::setsockopt(native, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (::bind(native, results->ai_addr, static_cast<int>(results->ai_addrlen)) != 0) {
        ::freeaddrinfo(results);
        close_native(native);
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.bind", "bind failed",
                          host + ":" + service);
    }
    ::freeaddrinfo(results);
    if (::listen(native, SOMAXCONN) != 0) {
        close_native(native);
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.bind", "listen failed");
    }
    sockaddr_in bound{};
    int bound_length = static_cast<int>(sizeof(bound));
    if (::getsockname(native, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
        close_native(native);
        shutdown_network();
        return make_error(ErrorCode::INTERNAL, "net.bind", "getsockname failed");
    }
    Listener listener;
    listener.handle_ = static_cast<std::uintptr_t>(native);
    listener.port_ = ntohs(bound.sin_port);
    return listener;
}

Result<Socket> Listener::accept() {
    if (handle_ == kInvalidHandle) {
        return make_error(ErrorCode::SHUTTING_DOWN, "net.accept", "listener is closed");
    }
    sockaddr_storage address{};
    int address_length = static_cast<int>(sizeof(address));
    const NativeSocket native = ::accept(static_cast<NativeSocket>(handle_),
                                         reinterpret_cast<sockaddr*>(&address), &address_length);
    if (native == kInvalidSocket) {
        return make_error(ErrorCode::SHUTTING_DOWN, "net.accept", "accept failed");
    }
    char text[INET6_ADDRSTRLEN] = {0};
    std::uint16_t peer_port = 0;
    if (address.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
        ::inet_ntop(AF_INET, &v4->sin_addr, text, sizeof(text));
        peer_port = ntohs(v4->sin_port);
    } else if (address.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
        ::inet_ntop(AF_INET6, &v6->sin6_addr, text, sizeof(text));
        peer_port = ntohs(v6->sin6_port);
    }
    // An accepted socket is an independent Winsock user: it must take its own
    // reference so its close balances and the library is never torn down under a
    // socket that is still in use.
    const Status acquired = initialise_network();
    if (!acquired.ok()) {
        close_native(native);
        return acquired.error();
    }
    Socket socket;
    socket.handle_ = static_cast<std::uintptr_t>(native);
    socket.peer_ = std::string(text) + ":" + std::to_string(peer_port);
#ifdef _WIN32
    BOOL nodelay = TRUE;
    ::setsockopt(native, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                 sizeof(nodelay));
#endif
    return socket;
}

void Listener::close() {
    if (handle_ != kInvalidHandle) {
        const NativeSocket native = static_cast<NativeSocket>(handle_);
        handle_ = kInvalidHandle;
        close_native(native);
        shutdown_network();
    }
}

}  // namespace fcf
