//===----------------------------------------------------------------------===//
/// \file
/// Exercise secure memory behavior and failure paths.
//===----------------------------------------------------------------------===//

// Covers the process-level memory protections: OpenSSL secure heap, fail-closed
// strict mode, disabled core dumps, and wipe-on-free for secret containers.
#include "../src/secure_memory.h"
#include "../src/vault.h"
#include <catch_amalgamated.hpp>
#include <openssl/crypto.h>
#include <sys/resource.h>

using namespace alfie;

/// The protections are process-wide and idempotent. Every case that touches a
/// secret asks for them itself, so a case can be run alone by tag or by name
/// and still get the arena it needs.
static MemoryProtections protections() {
  return initProcessMemoryProtections(MemoryPolicy::BestEffort);
}

TEST_CASE("Process memory protections initialize", "[memory][process]") {
  const MemoryProtections status = protections();

  CHECK(status.secureHeap);
  CHECK(status.coreDumpsDisabled);
  CHECK(memoryProtections().secureHeap);
}

TEST_CASE("Core dumps are disabled", "[memory][process]") {
  protections();

  struct rlimit limit{};
  REQUIRE(getrlimit(RLIMIT_CORE, &limit) == 0);
  // A core file would write the master password to disk.
  CHECK(limit.rlim_cur == 0);
}

TEST_CASE("Strict mode is reported and does not degrade", "[memory][process]") {
  const MemoryProtections status =
      initProcessMemoryProtections(MemoryPolicy::Strict);

  CHECK(status.policy == MemoryPolicy::Strict);
  CHECK(strictMemory());
  // Strict mode only reaches this line because both protections are in place;
  // if either had failed, initProcessMemoryProtections would have thrown
  // instead of degrading.
  CHECK(status.secureHeap);
  CHECK(status.coreDumpsDisabled);

  protections(); // Leave the process as the other cases expect to find it.
}

TEST_CASE("Secrets are allocated from the secure heap", "[memory][arena]") {
  protections();

  const SecureBuffer secret("master password");

  CHECK(CRYPTO_secure_allocated(secret.data()) != 0);
}

TEST_CASE("Growth wipes the abandoned buffer", "[memory][arena]") {
  protections();

  // A plain std::vector leaves its old buffer readable after it grows;
  // SecureBytes must not, which is why the wipe belongs to the allocator and
  // not to a destructor.
  SecureBytes bytes;
  bytes.reserve(8);
  const unsigned char *first = bytes.data();
  for (int i = 0; i < 8; ++i)
    bytes.push_back(0xAB);
  const size_t oldCapacity = bytes.capacity();

  bytes.push_back(0xAB); // Forces reallocation, freeing `first`.

  REQUIRE(bytes.data() != first);
  // `first` is freed; the allocator must have cleansed it before release.
  const std::vector<unsigned char> abandoned(first, first + oldCapacity);
  CHECK_THAT(
      abandoned,
      Catch::Matchers::AllMatch(Catch::Matchers::Predicate<unsigned char>(
          [](unsigned char byte) { return byte == 0; }, "is zero")));
}

TEST_CASE("Truncate wipes the tail in place", "[memory][buffer]") {
  protections();

  SecureBuffer buf("SECRETVALUE");
  const unsigned char *tail = buf.data() + 6;

  buf.truncate(6);

  CHECK(buf.size() == 6);
  CHECK(buf.str() == "SECRET");
  const std::vector<unsigned char> wiped(tail, tail + 5);
  CHECK_THAT(
      wiped,
      Catch::Matchers::AllMatch(Catch::Matchers::Predicate<unsigned char>(
          [](unsigned char byte) { return byte == 0; }, "is zero")));
}
