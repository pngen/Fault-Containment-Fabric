// Fault Containment Fabric — real child process control for multiprocess proofs.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Real OS processes with hidden console windows. Output is read on a dedicated
// thread and delivered through a condition variable, so waiting on a child is
// driven by observed output rather than by sleeps.

#ifndef FCF_TESTS_PROCESS_HPP
#define FCF_TESTS_PROCESS_HPP

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "fcf/net.hpp"
#include "fcf/protocol.hpp"
#include "fcf/result.hpp"
#include "framework.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fcf::test {

/// A real child process with its standard output captured line by line.
class ChildProcess {
public:
    ChildProcess() = default;

    ChildProcess(ChildProcess&& other) noexcept
        : process_(other.process_), read_end_(other.read_end_), reader_(std::move(other.reader_)),
          shared_(std::move(other.shared_)) {
        other.process_ = 0;
        other.read_end_ = 0;
    }

    ChildProcess& operator=(ChildProcess&& other) noexcept {
        if (this != &other) {
            (void)kill();
            process_ = other.process_;
            read_end_ = other.read_end_;
            reader_ = std::move(other.reader_);
            shared_ = std::move(other.shared_);
            other.process_ = 0;
            other.read_end_ = 0;
        }
        return *this;
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    ~ChildProcess() { (void)kill(); }

    static Result<ChildProcess> spawn(const std::string& executable,
                                      const std::vector<std::string>& arguments) {
        ChildProcess child;
#ifdef _WIN32
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.bInheritHandle = TRUE;
        HANDLE read_end = nullptr;
        HANDLE write_end = nullptr;
        if (CreatePipe(&read_end, &write_end, &attributes, 0) == 0) {
            return make_error(ErrorCode::INTERNAL, "process.spawn", "CreatePipe failed");
        }
        SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

        std::string command = "\"" + executable + "\"";
        for (const std::string& argument : arguments) {
            command += " \"" + argument + "\"";
        }
        std::wstring wide(command.begin(), command.end());

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = write_end;
        startup.hStdError = write_end;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION information{};
        // CREATE_NO_WINDOW keeps helper processes from opening a visible console.
        const BOOL created = CreateProcessW(nullptr, wide.data(), nullptr, nullptr, TRUE,
                                            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
        CloseHandle(write_end);
        if (created == 0) {
            CloseHandle(read_end);
            return make_error(ErrorCode::INTERNAL, "process.spawn", "CreateProcess failed",
                              std::to_string(GetLastError()));
        }
        CloseHandle(information.hThread);
        child.process_ = reinterpret_cast<std::uintptr_t>(information.hProcess);
        child.read_end_ = reinterpret_cast<std::uintptr_t>(read_end);
#else
        int pipe_fds[2];
        if (pipe(pipe_fds) != 0) {
            return make_error(ErrorCode::INTERNAL, "process.spawn", "pipe failed");
        }
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(executable.c_str()));
        for (const std::string& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        const pid_t pid = fork();
        if (pid == 0) {
            dup2(pipe_fds[1], STDOUT_FILENO);
            dup2(pipe_fds[1], STDERR_FILENO);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            execv(executable.c_str(), argv.data());
            _exit(127);
        }
        close(pipe_fds[1]);
        child.process_ = static_cast<std::uintptr_t>(pid);
        child.read_end_ = static_cast<std::uintptr_t>(pipe_fds[0]);
#endif
        child.reader_ = std::thread(pump, child.read_end_, child.shared_);
        return child;
    }

    /// Blocks until a line containing the needle arrives and returns it.
    [[nodiscard]] std::string wait_for(const std::string& needle) {
        std::unique_lock<std::mutex> lock(shared_->mutex);
        shared_->condition.wait(lock, [this, &needle]() {
            for (const std::string& line : shared_->lines) {
                if (line.find(needle) != std::string::npos) {
                    return true;
                }
            }
            return shared_->eof;
        });
        for (const std::string& line : shared_->lines) {
            if (line.find(needle) != std::string::npos) {
                return line;
            }
        }
        return {};
    }

    [[nodiscard]] std::vector<std::string> drain() {
        std::lock_guard<std::mutex> guard(shared_->mutex);
        std::vector<std::string> out(shared_->lines.begin(), shared_->lines.end());
        shared_->lines.clear();
        return out;
    }

    [[nodiscard]] bool saw(const std::string& needle) {
        std::lock_guard<std::mutex> guard(shared_->mutex);
        for (const std::string& line : shared_->lines) {
            if (line.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    /// Terminates the process without any graceful shutdown: a real process death.
    [[nodiscard]] bool kill() {
#ifdef _WIN32
        if (process_ != 0) {
            HANDLE handle = reinterpret_cast<HANDLE>(process_);
            const BOOL killed = TerminateProcess(handle, 0xC000013A);
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
            process_ = 0;
            if (read_end_ != 0) {
                CloseHandle(reinterpret_cast<HANDLE>(read_end_));
                read_end_ = 0;
            }
            if (reader_.joinable()) {
                reader_.join();
            }
            return killed != 0;
        }
#else
        if (process_ != 0) {
            ::kill(static_cast<pid_t>(process_), SIGKILL);
            int status = 0;
            ::waitpid(static_cast<pid_t>(process_), &status, 0);
            process_ = 0;
            if (read_end_ != 0) {
                ::close(static_cast<int>(read_end_));
                read_end_ = 0;
            }
            if (reader_.joinable()) {
                reader_.join();
            }
            return true;
        }
#endif
        if (reader_.joinable()) {
            reader_.join();
        }
        return false;
    }

    /// Waits for a clean exit and returns the exit code.
    [[nodiscard]] int wait() {
#ifdef _WIN32
        if (process_ == 0) {
            return -1;
        }
        HANDLE handle = reinterpret_cast<HANDLE>(process_);
        WaitForSingleObject(handle, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(handle, &code);
        CloseHandle(handle);
        process_ = 0;
        if (read_end_ != 0) {
            CloseHandle(reinterpret_cast<HANDLE>(read_end_));
            read_end_ = 0;
        }
        if (reader_.joinable()) {
            reader_.join();
        }
        return static_cast<int>(code);
#else
        if (process_ == 0) {
            return -1;
        }
        int status = 0;
        ::waitpid(static_cast<pid_t>(process_), &status, 0);
        process_ = 0;
        if (read_end_ != 0) {
            ::close(static_cast<int>(read_end_));
            read_end_ = 0;
        }
        if (reader_.joinable()) {
            reader_.join();
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    }

private:
    struct Shared {
        std::mutex mutex;
        std::condition_variable condition;
        std::deque<std::string> lines;
        bool eof = false;
    };

    static void pump(std::uintptr_t read_end, std::shared_ptr<Shared> shared) {
        std::string buffer;
        char chunk[1024];
        for (;;) {
#ifdef _WIN32
            DWORD read = 0;
            if (read_end == 0 ||
                ReadFile(reinterpret_cast<HANDLE>(read_end), chunk, sizeof(chunk), &read, nullptr) == 0 ||
                read == 0) {
                break;
            }
#else
            const ssize_t read = ::read(static_cast<int>(read_end), chunk, sizeof(chunk));
            if (read <= 0) {
                break;
            }
#endif
            for (DWORD index = 0; index < read; ++index) {
                const char c = chunk[index];
                if (c == '\n') {
                    std::lock_guard<std::mutex> guard(shared->mutex);
                    shared->lines.push_back(buffer);
                    buffer.clear();
                } else if (c != '\r') {
                    buffer.push_back(c);
                }
            }
            shared->condition.notify_all();
        }
        std::lock_guard<std::mutex> guard(shared->mutex);
        if (!buffer.empty()) {
            shared->lines.push_back(buffer);
        }
        shared->eof = true;
        shared->condition.notify_all();
    }

    std::uintptr_t process_ = 0;
    std::uintptr_t read_end_ = 0;
    std::thread reader_;
    std::shared_ptr<Shared> shared_ = std::make_shared<Shared>();
};

/// A controller connection to a running coordinator.
class ControlClient {
public:
    [[nodiscard]] static Result<ControlClient> connect(const std::string& host, std::uint16_t port) {
        Result<Socket> socket = Socket::connect(host, port);
        if (!socket.ok()) {
            return socket.error();
        }
        ControlClient client;
        client.socket_ = std::move(socket.value());
        return client;
    }

    [[nodiscard]] Result<ControlResponse> send(const std::string& command,
                                               const std::vector<std::string>& arguments = {}) {
        ControlRequest request;
        request.command = command;
        request.arguments = arguments;
        const Result<std::vector<std::byte>> payload = encode_control_request(request);
        if (!payload.ok()) {
            return payload.error();
        }
        const Status sent = socket_.send_frame(MessageKind::CONTROL_REQUEST, payload.value());
        if (!sent.ok()) {
            return sent.error();
        }
        Result<Frame> frame = socket_.receive_frame();
        if (!frame.ok()) {
            return frame.error();
        }
        if (frame.value().kind == MessageKind::REJECT) {
            const Result<RejectMessage> reject = decode_reject(frame.value().payload);
            if (reject.ok()) {
                return make_error(reject.value().code, "control", reject.value().detail);
            }
            return make_error(ErrorCode::FRAME_CORRUPT, "control", "undecodable rejection");
        }
        return decode_control_response(frame.value().payload);
    }

    void close() { socket_.close(); }

private:
    Socket socket_;
};

/// Repeatedly issues a control command until the predicate accepts the response.
/// This is state-driven polling of an observed product state, not a sleep.
template <class Predicate>
[[nodiscard]] Result<ControlResponse> poll_until(ControlClient& client, const std::string& command,
                                                 const std::vector<std::string>& arguments,
                                                 Predicate&& accept) {
    for (int attempt = 0; attempt < 2000000; ++attempt) {
        Result<ControlResponse> response = client.send(command, arguments);
        if (!response.ok()) {
            return response.error();
        }
        if (accept(response.value())) {
            return response.value();
        }
        std::this_thread::yield();
    }
    return make_error(ErrorCode::INTERNAL, "control.poll", "the expected state never appeared",
                      command);
}

[[nodiscard]] inline bool has_line(const ControlResponse& response, const std::string& needle) {
    for (const std::string& line : response.lines) {
        if (line.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] inline std::string line_with(const ControlResponse& response, const std::string& prefix) {
    for (const std::string& line : response.lines) {
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.size());
        }
    }
    return {};
}

}  // namespace fcf::test

#endif  // FCF_TESTS_PROCESS_HPP
