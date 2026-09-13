// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "fcf/fault.hpp"

#include <span>

#include "fcf/detail/bytes.hpp"
#include "fcf/detail/sha256.hpp"

namespace fcf {

std::array<std::uint8_t, 32> compute_evidence_digest(const FaultEvidence& evidence) {
    // The fault identity itself is deliberately excluded: an identical observation
    // republished under a freshly allocated identity must still be recognised as a
    // duplicate rather than becoming a second fault.
    detail::ByteWriter writer;
    writer.u64(evidence.generation.value());
    writer.str(std::string(to_string(evidence.kind)));
    writer.u64(evidence.subject.value());
    writer.u64(evidence.subject_generation.value());
    writer.str(std::string(to_string(evidence.reporter_kind)));
    writer.u64(evidence.reporter_worker.value());
    writer.u64(evidence.reporter_boot.value());
    writer.u64(evidence.epoch.value());
    writer.str(std::string(to_string(evidence.provenance)));
    writer.u64(evidence.observation_sequence.value());
    writer.u64(evidence.publication_time_ms);
    writer.str(std::string(to_string(evidence.freshness)));
    writer.str(std::string(to_string(evidence.integrity)));
    writer.u16(evidence.confidence_permille);
    writer.str(evidence.details);
    if (!writer.ok()) {
        return {};
    }
    return detail::Sha256::compute(writer.span());
}

std::string evidence_digest_hex(const FaultRecord& record) {
    return detail::to_hex(std::span<const std::uint8_t>(record.evidence.digest.data(),
                                                        record.evidence.digest.size()));
}

}  // namespace fcf
