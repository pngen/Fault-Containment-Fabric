// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/persistence.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

#include "fcf/detail/bytes.hpp"
#include "fcf/detail/crc32c.hpp"
#include "fcf/version.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fcf {
namespace {

// Snapshot container layout:
//   [0,8)    magic "FCFSNAP1"
//   [8,12)   format version (little endian)
//   [12,20)  payload length (little endian, u64)
//   [20,24)  header CRC32C over bytes [0,20) -- the checksum field itself is excluded
//   [24,28)  payload CRC32C
//   [28,..)  payload = sequence(u64) followed by the encoded state
// Anything after the payload is rejected: the format forbids trailing bytes.
constexpr const char kSnapshotMagic[8] = {'F', 'C', 'F', 'S', 'N', 'A', 'P', '1'};
constexpr std::size_t kSnapshotHeaderBytes = 28U;

// Journal record layout:
//   [0,4)   magic 0x314A4346 ('F','C','J','1')
//   [4,8)   payload length (little endian)
//   [8,12)  payload CRC32C
//   [12,..) payload = sequence(u64) followed by the encoded event
// A crash may leave the final record partially written. That torn tail is
// discarded and reported; a torn record followed by further valid records is
// treated as corruption.
constexpr std::uint32_t kJournalRecordMagic = 0x314A4346U;
constexpr std::size_t kJournalHeaderBytes = 12U;
constexpr std::uint64_t kMaxJournalFileBytes = 512ULL * 1024ULL * 1024ULL;

void put_u32(std::uint8_t* out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
}

void put_u64(std::uint8_t* out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
}

std::uint32_t get_u32(const std::uint8_t* in) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(in[i]) << (8U * static_cast<unsigned>(i));
    }
    return value;
}

std::uint64_t get_u64(const std::uint8_t* in) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(in[i]) << (8U * static_cast<unsigned>(i));
    }
    return value;
}

#ifdef _WIN32

[[nodiscard]] std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed);
    return out;
}

struct FileHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~FileHandle() {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
    FileHandle() = default;
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
};

[[nodiscard]] Error win_error(ErrorCode code, const char* stage, const std::string& what) {
    return make_error(code, stage, what + " failed", "win32=" + std::to_string(GetLastError()));
}

/// Reads a whole file with a hard ceiling, refusing reparse points so a substituted
/// link cannot redirect durable state outside the configured directory.
[[nodiscard]] Status read_file(const std::string& path, std::size_t ceiling, std::vector<std::byte>& out,
                               bool& exists) {
    exists = false;
    const std::wstring wide = widen(path);
    HANDLE probe = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL, nullptr);
    if (probe == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return ok_status();
        }
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "open failed",
                    "win32=" + std::to_string(error));
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileInformationByHandle(probe, &info) == 0) {
        CloseHandle(probe);
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "stat failed");
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
        CloseHandle(probe);
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read",
                    "durable state path is a reparse point; refusing substitution");
    }
    CloseHandle(probe);

    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "open failed",
                    "win32=" + std::to_string(GetLastError()));
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(handle, &size) == 0) {
        CloseHandle(handle);
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "size query failed");
    }
    if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > ceiling) {
        CloseHandle(handle);
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read", "durable file exceeds the size ceiling",
                    std::to_string(size.QuadPart));
    }
    exists = true;
    out.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < out.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - offset, 1U << 20U));
        DWORD read = 0;
        if (ReadFile(handle, out.data() + offset, chunk, &read, nullptr) == 0) {
            CloseHandle(handle);
            return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "read failed");
        }
        if (read == 0) {
            break;
        }
        offset += read;
    }
    CloseHandle(handle);
    if (offset != out.size()) {
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read", "short read");
    }
    return ok_status();
}

[[nodiscard]] Status write_file_atomic(const std::string& path, const std::string& temp_path,
                                       std::span<const std::byte> bytes) {
    const std::wstring wide_temp = widen(temp_path);
    HANDLE handle = CreateFileW(wide_temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp create failed",
                    "win32=" + std::to_string(GetLastError()));
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1U << 20U));
        DWORD written = 0;
        if (WriteFile(handle, bytes.data() + offset, chunk, &written, nullptr) == 0 || written == 0) {
            CloseHandle(handle);
            DeleteFileW(wide_temp.c_str());
            return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp write failed");
        }
        offset += written;
    }
    if (FlushFileBuffers(handle) == 0) {
        CloseHandle(handle);
        DeleteFileW(wide_temp.c_str());
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp flush failed");
    }
    CloseHandle(handle);

    const std::wstring wide_target = widen(path);
    // MoveFileEx with MOVEFILE_REPLACE_EXISTING is an atomic same-volume replace on NTFS.
    if (MoveFileExW(wide_temp.c_str(), wide_target.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        const DWORD error = GetLastError();
        DeleteFileW(wide_temp.c_str());
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "atomic replace failed",
                    "win32=" + std::to_string(error));
    }
    return ok_status();
}

#else  // POSIX implementation: implemented from the same contract, unvalidated in the
       // Windows x64 release environment. See README "Platform" for the honest label.

[[nodiscard]] Status read_file(const std::string& path, std::size_t ceiling, std::vector<std::byte>& out,
                               bool& exists) {
    exists = false;
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            return ok_status();
        }
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "stat failed", std::strerror(errno));
    }
    if (S_ISLNK(info.st_mode)) {
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read",
                    "durable state path is a symlink; refusing substitution");
    }
    if (!S_ISREG(info.st_mode)) {
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read", "durable state path is not a file");
    }
    if (static_cast<std::uint64_t>(info.st_size) > ceiling) {
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read", "durable file exceeds the size ceiling");
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "open failed", std::strerror(errno));
    }
    exists = true;
    out.resize(static_cast<std::size_t>(info.st_size));
    std::size_t offset = 0;
    while (offset < out.size()) {
        const ssize_t got = ::read(fd, out.data() + offset, out.size() - offset);
        if (got < 0) {
            ::close(fd);
            return fail(ErrorCode::PERSISTENCE_IO, "persist.read", "read failed", std::strerror(errno));
        }
        if (got == 0) {
            break;
        }
        offset += static_cast<std::size_t>(got);
    }
    ::close(fd);
    if (offset != out.size()) {
        return fail(ErrorCode::PERSISTENCE_CORRUPT, "persist.read", "short read");
    }
    return ok_status();
}

[[nodiscard]] Status write_file_atomic(const std::string& path, const std::string& temp_path,
                                       std::span<const std::byte> bytes) {
    const int fd = ::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp create failed", std::strerror(errno));
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t put = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (put <= 0) {
            ::close(fd);
            ::unlink(temp_path.c_str());
            return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp write failed");
        }
        offset += static_cast<std::size_t>(put);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        ::unlink(temp_path.c_str());
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "temp flush failed");
    }
    ::close(fd);
    if (::rename(temp_path.c_str(), path.c_str()) != 0) {
        ::unlink(temp_path.c_str());
        return fail(ErrorCode::PERSISTENCE_IO, "persist.write", "atomic replace failed");
    }
    return ok_status();
}

#endif

}  // namespace

std::string_view snapshot_magic() noexcept { return std::string_view(kSnapshotMagic, 8); }
std::string_view journal_magic() noexcept { return std::string_view("FCJ1", 4); }

Result<std::unique_ptr<DurableStore>> DurableStore::open(const Options& options) {
    if (options.directory.empty()) {
        return make_error(ErrorCode::INVALID_ARGUMENT, "persist.open", "state directory must not be empty");
    }
    std::error_code ec;
    if (options.create_directory) {
        std::filesystem::create_directories(std::filesystem::path(options.directory), ec);
        if (ec) {
            return make_error(ErrorCode::PERSISTENCE_IO, "persist.open", "cannot create state directory",
                              ec.message());
        }
    }
    if (!std::filesystem::is_directory(std::filesystem::path(options.directory), ec) || ec) {
        return make_error(ErrorCode::PERSISTENCE_IO, "persist.open", "state directory is not a directory",
                          options.directory);
    }
    std::unique_ptr<DurableStore> store(new DurableStore());
    store->directory_ = options.directory;
    const std::filesystem::path base(options.directory);
    store->snapshot_path_ = (base / "state.fcfsnap").string();
    store->journal_path_ = (base / "journal.fcf").string();
    store->flush_on_append_ = options.flush_on_append;
    const Status opened = store->open_files(true);
    if (!opened.ok()) {
        return opened.error();
    }
    return store;
}

DurableStore::~DurableStore() {
#ifdef _WIN32
    if (journal_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(journal_handle_));
        journal_handle_ = nullptr;
    }
#else
    if (journal_fd_ >= 0) {
        ::close(journal_fd_);
        journal_fd_ = -1;
    }
#endif
}

Status DurableStore::open_files(bool for_append) {
#ifdef _WIN32
    if (journal_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(journal_handle_));
        journal_handle_ = nullptr;
    }
    const std::wstring wide = widen(journal_path_);
    DWORD disposition = OPEN_ALWAYS;
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_WRITE | GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.open", "cannot open journal",
                    "win32=" + std::to_string(GetLastError()));
    }
    if (for_append) {
        LARGE_INTEGER zero{};
        if (SetFilePointerEx(handle, zero, nullptr, FILE_END) == 0) {
            CloseHandle(handle);
            return fail(ErrorCode::PERSISTENCE_IO, "persist.open", "cannot seek journal to end");
        }
    }
    journal_handle_ = handle;
    return ok_status();
#else
    (void)for_append;
    journal_fd_ = ::open(journal_path_.c_str(), O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (journal_fd_ < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.open", "cannot open journal", std::strerror(errno));
    }
    return ok_status();
#endif
}

Status DurableStore::append_record(std::uint64_t sequence, std::span<const std::byte> payload) {
    if (payload.size() > kMaxJournalRecordBytes) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "record exceeds the journal record ceiling",
                    std::to_string(payload.size()));
    }
    std::vector<std::byte> record(kJournalHeaderBytes + 8U + payload.size());
    auto* bytes = reinterpret_cast<std::uint8_t*>(record.data());
    put_u64(bytes + kJournalHeaderBytes, sequence);
    if (!payload.empty()) {
        std::memcpy(bytes + kJournalHeaderBytes + 8U, payload.data(), payload.size());
    }
    // The checksum covers the complete stored payload region, so the reader hashes
    // exactly the bytes the writer protected.
    const std::uint32_t crc = detail::Crc32c::compute(
        std::span<const std::byte>(record.data() + kJournalHeaderBytes, 8U + payload.size()));
    put_u32(bytes + 0, kJournalRecordMagic);
    put_u32(bytes + 4, static_cast<std::uint32_t>(8U + payload.size()));
    put_u32(bytes + 8, crc);

    const std::lock_guard<std::mutex> guard(mutex_);
#ifdef _WIN32
    if (journal_handle_ == nullptr) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal is not open");
    }
    HANDLE handle = static_cast<HANDLE>(journal_handle_);
    std::size_t offset = 0;
    while (offset < record.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(record.size() - offset, 1U << 20U));
        DWORD written = 0;
        if (WriteFile(handle, record.data() + offset, chunk, &written, nullptr) == 0 || written == 0) {
            return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal write failed",
                        "win32=" + std::to_string(GetLastError()));
        }
        offset += written;
    }
    if (flush_on_append_ && FlushFileBuffers(handle) == 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal flush failed",
                    "win32=" + std::to_string(GetLastError()));
    }
    return ok_status();
#else
    if (journal_fd_ < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal is not open");
    }
    std::size_t offset = 0;
    while (offset < record.size()) {
        const ssize_t put = ::write(journal_fd_, record.data() + offset, record.size() - offset);
        if (put <= 0) {
            return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal write failed");
        }
        offset += static_cast<std::size_t>(put);
    }
    if (flush_on_append_ && ::fsync(journal_fd_) != 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.append", "journal flush failed");
    }
    return ok_status();
#endif
}

Status DurableStore::save_snapshot(std::span<const std::byte> payload, std::uint64_t sequence) {
    if (payload.size() > kMaxSnapshotPayloadBytes) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.snapshot", "snapshot exceeds the payload ceiling",
                    std::to_string(payload.size()));
    }
    std::vector<std::byte> image(kSnapshotHeaderBytes + 8U + payload.size());
    auto* bytes = reinterpret_cast<std::uint8_t*>(image.data());
    std::memcpy(bytes, kSnapshotMagic, sizeof(kSnapshotMagic));
    put_u32(bytes + 8, kSnapshotFormatVersion);
    put_u64(bytes + 12, static_cast<std::uint64_t>(8U + payload.size()));
    put_u64(bytes + kSnapshotHeaderBytes, sequence);
    if (!payload.empty()) {
        std::memcpy(bytes + kSnapshotHeaderBytes + 8U, payload.data(), payload.size());
    }
    const std::uint32_t header_crc =
        detail::Crc32c::compute(std::span<const std::byte>(image.data(), kSnapshotHeaderBytes - 8U));
    put_u32(bytes + 20, header_crc);
    // The checksum covers the complete stored payload region, including the sequence.
    put_u32(bytes + 24,
            detail::Crc32c::compute(std::span<const std::byte>(image.data() + kSnapshotHeaderBytes,
                                                               8U + payload.size())));

    const std::lock_guard<std::mutex> guard(mutex_);
#ifdef _WIN32
    const std::string temp_path = snapshot_path_ + ".tmp." + std::to_string(GetCurrentProcessId());
    const Status written = write_file_atomic(snapshot_path_, temp_path,
                                             std::span<const std::byte>(image.data(), image.size()));
    if (!written.ok()) {
        return written;
    }
    return truncate_journal_locked();
#else
    (void)sequence;
    const std::string temp_path = snapshot_path_ + ".tmp." + std::to_string(::getpid());
    const Status written = write_file_atomic(snapshot_path_, temp_path,
                                             std::span<const std::byte>(image.data(), image.size()));
    if (!written.ok()) {
        return written;
    }
    return truncate_journal_locked();
#endif
}

Status DurableStore::truncate_journal_locked() {
#ifdef _WIN32
    if (journal_handle_ == nullptr) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal is not open");
    }
    HANDLE handle = static_cast<HANDLE>(journal_handle_);
    LARGE_INTEGER zero{};
    if (SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) == 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal rewind failed");
    }
    if (SetEndOfFile(handle) == 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal truncate failed");
    }
    if (FlushFileBuffers(handle) == 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal flush failed");
    }
    return ok_status();
#else
    if (journal_fd_ < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal is not open");
    }
    if (::ftruncate(journal_fd_, 0) != 0 || ::lseek(journal_fd_, 0, SEEK_SET) < 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal truncate failed");
    }
    if (::fsync(journal_fd_) != 0) {
        return fail(ErrorCode::PERSISTENCE_IO, "persist.truncate", "journal flush failed");
    }
    return ok_status();
#endif
}

Result<DurableStore::Recovery> DurableStore::recover() const {
    const std::lock_guard<std::mutex> guard(mutex_);
    Recovery recovery;

    std::vector<std::byte> snapshot_bytes;
    bool snapshot_exists = false;
    const std::size_t snapshot_ceiling =
        kSnapshotHeaderBytes + 8U + static_cast<std::size_t>(kMaxSnapshotPayloadBytes);
    Status read = read_file(snapshot_path_, snapshot_ceiling, snapshot_bytes, snapshot_exists);
    if (!read.ok()) {
        return read.error();
    }
    if (snapshot_exists) {
        if (snapshot_bytes.size() < kSnapshotHeaderBytes) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover", "snapshot header truncated",
                              std::to_string(snapshot_bytes.size()));
        }
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(snapshot_bytes.data());
        if (std::memcmp(bytes, kSnapshotMagic, sizeof(kSnapshotMagic)) != 0) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover", "snapshot magic mismatch");
        }
        const std::uint32_t version = get_u32(bytes + 8);
        if (version != kSnapshotFormatVersion) {
            return make_error(ErrorCode::PERSISTENCE_UNSUPPORTED_VERSION, "persist.recover",
                              "unsupported snapshot format version", std::to_string(version));
        }
        const std::uint64_t payload_len = get_u64(bytes + 12);
        if (payload_len > kMaxSnapshotPayloadBytes) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot declares an absurd payload length", std::to_string(payload_len));
        }
        const std::uint32_t expected_header_crc =
            detail::Crc32c::compute(std::span<const std::byte>(snapshot_bytes.data(),
                                                               kSnapshotHeaderBytes - 8U));
        if (get_u32(bytes + 20) != expected_header_crc) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot header checksum mismatch");
        }
        std::size_t expected_total = 0;
        if (!detail::checked_add(kSnapshotHeaderBytes, static_cast<std::size_t>(payload_len), expected_total)) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot length overflows the address space");
        }
        if (snapshot_bytes.size() != expected_total) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot length mismatch (truncated or trailing bytes)",
                              std::to_string(snapshot_bytes.size()) + " != " + std::to_string(expected_total));
        }
        const auto payload = std::span<const std::byte>(snapshot_bytes.data() + kSnapshotHeaderBytes,
                                                        static_cast<std::size_t>(payload_len));
        if (detail::Crc32c::compute(payload) != get_u32(bytes + 24)) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot payload checksum mismatch");
        }
        if (payload.size() < 8U) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "snapshot payload is shorter than its sequence header");
        }
        recovery.snapshot_sequence = get_u64(reinterpret_cast<const std::uint8_t*>(payload.data()));
        recovery.snapshot_payload.assign(payload.begin() + 8, payload.end());
        recovery.snapshot_present = true;
    }

    std::vector<std::byte> journal_bytes;
    bool journal_exists = false;
    read = read_file(journal_path_, static_cast<std::size_t>(kMaxJournalFileBytes), journal_bytes,
                     journal_exists);
    if (!read.ok()) {
        return read.error();
    }
    if (journal_exists) {
        std::size_t offset = 0;
        while (offset < journal_bytes.size()) {
            const std::size_t remaining = journal_bytes.size() - offset;
            if (remaining < kJournalHeaderBytes) {
                recovery.torn_tail_bytes = remaining;
                break;
            }
            const auto* header = reinterpret_cast<const std::uint8_t*>(journal_bytes.data() + offset);
            if (get_u32(header) != kJournalRecordMagic) {
                return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                                  "journal record magic mismatch",
                                  "offset=" + std::to_string(offset));
            }
            const std::uint32_t record_len = get_u32(header + 4);
            if (record_len > kMaxJournalRecordBytes) {
                return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                                  "journal record declares an absurd length",
                                  "offset=" + std::to_string(offset));
            }
            const std::size_t total = kJournalHeaderBytes + static_cast<std::size_t>(record_len);
            if (remaining < total) {
                recovery.torn_tail_bytes = remaining;
                break;
            }
            const auto payload = std::span<const std::byte>(journal_bytes.data() + offset + kJournalHeaderBytes,
                                                            record_len);
            if (detail::Crc32c::compute(payload) != get_u32(header + 8)) {
                return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                                  "journal record checksum mismatch", "offset=" + std::to_string(offset));
            }
            if (record_len < 8U) {
                return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                                  "journal record is shorter than its sequence header",
                                  "offset=" + std::to_string(offset));
            }
            const std::uint64_t sequence = get_u64(reinterpret_cast<const std::uint8_t*>(payload.data()));
            if (sequence <= recovery.snapshot_sequence) {
                ++recovery.journal_records_skipped;
            } else {
                recovery.journal_records.emplace_back(payload.begin() + 8, payload.end());
                recovery.journal_sequences.push_back(sequence);
            }
            offset += total;
        }
    }

    // Records may have been appended concurrently by more than one durable
    // mutation; order them by sequence so replay is deterministic.
    std::vector<std::size_t> order(recovery.journal_sequences.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::stable_sort(order.begin(), order.end(), [&recovery](std::size_t a, std::size_t b) {
        return recovery.journal_sequences[a] < recovery.journal_sequences[b];
    });
    std::vector<std::vector<std::byte>> ordered_records;
    ordered_records.reserve(order.size());
    std::vector<std::uint64_t> ordered_sequences;
    ordered_sequences.reserve(order.size());
    std::uint64_t previous = recovery.snapshot_sequence;
    for (const std::size_t index : order) {
        const std::uint64_t sequence = recovery.journal_sequences[index];
        if (previous != 0 && sequence != previous + 1U) {
            return make_error(ErrorCode::PERSISTENCE_CORRUPT, "persist.recover",
                              "journal sequence gap detected",
                              std::to_string(previous) + " -> " + std::to_string(sequence));
        }
        previous = sequence;
        ordered_records.push_back(std::move(recovery.journal_records[index]));
        ordered_sequences.push_back(sequence);
    }
    recovery.journal_records = std::move(ordered_records);
    recovery.journal_sequences = std::move(ordered_sequences);
    recovery.journal_records_applied = recovery.journal_records.size();
    return recovery;
}

}  // namespace fcf
