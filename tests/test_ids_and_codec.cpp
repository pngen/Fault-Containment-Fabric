// Fault Containment Fabric — identity, digest and codec proof obligations.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include "fcf/detail/bytes.hpp"
#include "fcf/detail/crc32c.hpp"
#include "fcf/detail/sha256.hpp"
#include "fcf/ids.hpp"
#include "framework.hpp"

namespace {

// Compile-time proof that identity domains cannot be interchanged.
static_assert(!std::is_convertible_v<fcf::WorkerId, fcf::ResourceId>);
static_assert(!std::is_convertible_v<fcf::ResourceId, fcf::ContainmentDomainId>);
static_assert(!std::is_convertible_v<fcf::FaultId, fcf::ActionId>);
static_assert(!std::is_convertible_v<fcf::TopologyGeneration, fcf::PolicyGeneration>);
static_assert(std::is_same_v<fcf::WorkerId, fcf::Id<fcf::detail::WorkerIdTag>>);

[[nodiscard]] std::vector<std::byte> from_text(const std::string& text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] std::string to_text(const std::array<std::uint8_t, 32>& digest) {
    return fcf::detail::to_hex(std::span<const std::uint8_t>(digest.data(), digest.size()));
}

}  // namespace

FCF_TEST(ids, invalid_sentinel_is_never_a_real_identity) {
    const fcf::WorkerId worker;
    FCF_REQUIRE(!worker.valid());
    FCF_EQ(worker.value(), 0U);
    FCF_EQ(fcf::to_string(worker), std::string("WorkerId:invalid"));
    const fcf::ResourceId resource = fcf::ResourceId::from_value(7);
    FCF_REQUIRE(resource.valid());
    FCF_EQ(fcf::to_string(resource), std::string("ResourceId:7"));
}

FCF_TEST(ids, parsing_rejects_malformed_and_overflowing_values) {
    fcf::ResourceId parsed;
    FCF_REQUIRE(fcf::parse_id<fcf::ResourceId>("ResourceId:42", parsed));
    FCF_EQ(parsed.value(), 42U);
    FCF_REQUIRE(fcf::parse_id<fcf::ResourceId>("42", parsed));
    FCF_EQ(parsed.value(), 42U);
    // Wrong domain name, empty, signed, whitespace, non-numeric and overflow.
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>("WorkerId:42", parsed));
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>("ResourceId:", parsed));
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>("-1", parsed));
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>(" 1", parsed));
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>("1x", parsed));
    FCF_REQUIRE(!fcf::parse_id<fcf::ResourceId>("99999999999999999999999", parsed));
}

FCF_TEST(ids, generation_advance_saturates_rather_than_wrapping) {
    fcf::TopologyGeneration generation = fcf::TopologyGeneration::from_value(UINT64_MAX - 1U);
    generation = fcf::next_generation(generation);
    FCF_EQ(generation.value(), UINT64_MAX);
    generation = fcf::next_generation(generation);
    FCF_EQ(generation.value(), UINT64_MAX);
}

FCF_TEST(codec, round_trip_preserves_values_and_rejects_trailing_bytes) {
    fcf::detail::ByteWriter writer;
    writer.u8(0x12U);
    writer.u16(0xBEEFU);
    writer.u32(0xDEADBEEFU);
    writer.u64(0x0123456789ABCDEFULL);
    writer.i64(-42);
    writer.boolean(true);
    writer.str("fault containment");
    FCF_REQUIRE(writer.ok());

    fcf::detail::ByteReader reader(writer.span());
    FCF_EQ(reader.u8(), 0x12U);
    FCF_EQ(reader.u16(), 0xBEEFU);
    FCF_EQ(reader.u32(), 0xDEADBEEFU);
    FCF_EQ(reader.u64(), 0x0123456789ABCDEFULL);
    FCF_EQ(reader.i64(), -42);
    FCF_EQ(reader.boolean(), true);
    FCF_EQ(reader.str(), std::string("fault containment"));
    FCF_REQUIRE(reader.ok());
    FCF_REQUIRE(reader.at_end());
}

FCF_TEST(codec, truncated_reads_latch_failure_instead_of_reading_past_the_end) {
    const std::vector<std::byte> bytes = from_text("abc");
    fcf::detail::ByteReader reader(std::span<const std::byte>(bytes.data(), bytes.size()));
    // A multi-byte read that cannot be satisfied yields zero and latches failure,
    // rather than returning a partially assembled value.
    FCF_EQ(reader.u32(), 0U);
    FCF_REQUIRE(!reader.ok());
    FCF_REQUIRE(!reader.at_end());
    // Once latched, every further read is inert rather than advancing.
    FCF_EQ(reader.u8(), 0U);
    FCF_REQUIRE(!reader.ok());
    FCF_EQ(reader.offset(), 0U);
}

FCF_TEST(codec, oversized_claims_are_rejected_before_any_allocation) {
    fcf::detail::ByteWriter writer;
    writer.u32(0xFFFFFFFFU);
    fcf::detail::ByteReader reader(writer.span());
    const std::string text = reader.str();
    FCF_REQUIRE(text.empty());
    FCF_REQUIRE(!reader.ok());

    fcf::detail::ByteWriter blob_writer;
    blob_writer.u32(0x7FFFFFFFU);
    fcf::detail::ByteReader blob_reader(blob_writer.span());
    const auto blob = blob_reader.blob();
    FCF_REQUIRE(blob.empty());
    FCF_REQUIRE(!blob_reader.ok());
}

FCF_TEST(codec, invalid_utf8_is_rejected_on_both_sides) {
    fcf::detail::ByteWriter writer;
    writer.str(std::string("\xC3\x28", 2));  // invalid two-byte sequence
    FCF_REQUIRE(!writer.ok());

    fcf::detail::ByteWriter raw;
    raw.u32(2U);
    raw.raw("\xC3\x28", 2);
    FCF_REQUIRE(raw.ok());
    fcf::detail::ByteReader reader(raw.span());
    FCF_REQUIRE(reader.str().empty());
    FCF_REQUIRE(!reader.ok());

    FCF_REQUIRE(fcf::detail::is_valid_utf8("plain ascii"));
    FCF_REQUIRE(fcf::detail::is_valid_utf8("\xE2\x82\xAC"));
    FCF_REQUIRE(!fcf::detail::is_valid_utf8("\xED\xA0\x80"));  // surrogate half
    FCF_REQUIRE(!fcf::detail::is_valid_utf8("\xC0\x80"));       // overlong
    FCF_REQUIRE(!fcf::detail::is_valid_utf8("\xF5\x80\x80\x80"));
}

FCF_TEST(integrity, crc32c_matches_published_test_vectors) {
    FCF_EQ(fcf::detail::Crc32c::compute("", 0), 0x00000000U);
    FCF_EQ(fcf::detail::Crc32c::compute("a", 1), 0xC1D04330U);
    FCF_EQ(fcf::detail::Crc32c::compute("123456789", 9), 0xE3069283U);
    const std::string sentence = "The quick brown fox jumps over the lazy dog";
    FCF_EQ(fcf::detail::Crc32c::compute(sentence.data(), sentence.size()), 0x22620404U);
}

FCF_TEST(integrity, sha256_matches_published_test_vectors) {
    FCF_EQ(to_text(fcf::detail::Sha256::compute("")),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    FCF_EQ(to_text(fcf::detail::Sha256::compute("abc")),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    FCF_EQ(to_text(fcf::detail::Sha256::compute(
               "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
           std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    // A message longer than one block exercises buffering and padding boundaries.
    std::string long_message(1000, 'a');
    FCF_EQ(to_text(fcf::detail::Sha256::compute(long_message)),
           std::string("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"));
    // Incremental use must equal one-shot use.
    fcf::detail::Sha256 incremental;
    incremental.update("ab");
    incremental.update("c");
    FCF_EQ(to_text(incremental.finish()),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
