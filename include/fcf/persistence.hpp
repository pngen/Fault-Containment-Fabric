// Fault Containment Fabric — versioned, integrity-checked durable state.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Durable state is a full snapshot plus a write-ahead journal of ordered event
// records. The journal is flushed before a durable mutation is acknowledged, so
// a mutation is never reported as committed before it crossed the durability
// boundary. Snapshots are replaced atomically.

#ifndef FCF_PERSISTENCE_HPP
#define FCF_PERSISTENCE_HPP

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "fcf/result.hpp"

namespace fcf {

inline constexpr std::uint32_t kMaxJournalRecordBytes = 8U * 1024U * 1024U;
inline constexpr std::uint32_t kMaxSnapshotPayloadBytes = 128U * 1024U * 1024U;

/// A durable store rooted at one directory.
class DurableStore {
public:
    struct Options {
        std::string directory;
        /// fsync every appended record before returning (the durability boundary).
        bool flush_on_append = true;
        /// Refuse to open if the directory cannot be created.
        bool create_directory = true;
    };

    struct Recovery {
        bool snapshot_present = false;
        std::vector<std::byte> snapshot_payload;
        std::uint64_t snapshot_sequence = 0;
        /// Journal records that follow the snapshot, ordered by their sequence number.
        std::vector<std::vector<std::byte>> journal_records;
        std::vector<std::uint64_t> journal_sequences;
        /// Bytes discarded because the final record was torn by a crash mid-write.
        std::uint64_t torn_tail_bytes = 0;
        std::uint64_t journal_records_applied = 0;
        std::uint64_t journal_records_skipped = 0;
    };

    static Result<std::unique_ptr<DurableStore>> open(const Options& options);

    DurableStore(const DurableStore&) = delete;
    DurableStore& operator=(const DurableStore&) = delete;
    ~DurableStore();

    /// Appends one ordered record and flushes it past the durability boundary.
    Status append_record(std::uint64_t sequence, std::span<const std::byte> payload);

    /// Serializes the supplied payload to a temporary file, flushes it, then
    /// atomically replaces the authoritative snapshot. Only then is the journal
    /// truncated to the last sequence covered by the snapshot.
    Status save_snapshot(std::span<const std::byte> payload, std::uint64_t sequence);

    /// Reads and integrity-checks the durable state. Corruption is reported, never
    /// silently repaired.
    [[nodiscard]] Result<Recovery> recover() const;

    [[nodiscard]] const std::string& directory() const noexcept { return directory_; }
    [[nodiscard]] const std::string& snapshot_path() const noexcept { return snapshot_path_; }
    [[nodiscard]] const std::string& journal_path() const noexcept { return journal_path_; }

private:
    DurableStore() = default;

    Status open_files(bool for_append);
    Status truncate_journal_locked();

    std::string directory_;
    std::string snapshot_path_;
    std::string journal_path_;
    void* journal_handle_ = nullptr;  // HANDLE on Windows
    int journal_fd_ = -1;             // file descriptor on POSIX
    bool flush_on_append_ = true;
    mutable std::mutex mutex_;
};

/// Sequence/format helpers shared with the wire codec so both boundaries agree.
[[nodiscard]] std::string_view snapshot_magic() noexcept;
[[nodiscard]] std::string_view journal_magic() noexcept;

}  // namespace fcf

#endif  // FCF_PERSISTENCE_HPP
