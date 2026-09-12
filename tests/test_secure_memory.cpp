//===----------------------------------------------------------------------===//
/// \file
/// Exercise secure memory behavior and failure paths.
//===----------------------------------------------------------------------===//

// Covers the process-level memory protections: OpenSSL secure heap, fail-closed
// strict mode, disabled core dumps, and wipe-on-free for secret containers.
#include "../src/secure_memory.h"
#include "../src/vault.h"
#include <cassert>
#include <iostream>
#include <openssl/crypto.h>
#include <sys/resource.h>
#include <vector>

using namespace alfie;

static void testProtectionsInitialize() {
  const auto status = initProcessMemoryProtections(MemoryPolicy::BestEffort);
  assert(status.secureHeap && "OpenSSL secure heap should initialize");
  assert(status.coreDumpsDisabled && "core dumps should be disabled");
  assert(memoryProtections().secureHeap);
}

static void testCoreDumpLimitIsZero() {
  struct rlimit limit{};
  assert(getrlimit(RLIMIT_CORE, &limit) == 0);
  assert(limit.rlim_cur == 0 && "RLIMIT_CORE soft limit must be 0");
}

static void testSecretsLandInTheSecureHeap() {
  SecureBuffer secret("master password");
  assert(CRYPTO_secure_allocated(secret.data()) != 0 &&
         "secret bytes should come from the OpenSSL secure arena");
}

// A plain std::vector leaves its old buffer readable after it grows;
// SecureBytes must not.
static void testGrowthWipesTheAbandonedBuffer() {
  SecureBytes bytes;
  bytes.reserve(8);
  const unsigned char *first = bytes.data();
  for (int i = 0; i < 8; ++i)
    bytes.push_back(0xAB);
  const size_t oldCapacity = bytes.capacity();
  bytes.push_back(0xAB); // forces reallocation, freeing `first`
  assert(bytes.data() != first);
  // `first` is freed; the allocator must have cleansed it before release.
  bool anyNonzero = false;
  for (size_t i = 0; i < oldCapacity; ++i) {
    if (first[i] != 0)
      anyNonzero = true;
  }
  assert(!anyNonzero && "abandoned secret buffer was not wiped on free");
}

static void testStrictModeIsReported() {
  const auto status = initProcessMemoryProtections(MemoryPolicy::Strict);
  assert(status.policy == MemoryPolicy::Strict);
  assert(strictMemory());
  // Strict mode only reaches this line because both protections are in place;
  // if either had failed, init_process_memory_protections would have thrown
  // instead of degrading.
  assert(status.secureHeap && status.coreDumpsDisabled);
  initProcessMemoryProtections(MemoryPolicy::BestEffort);
}

static void testSecureBufferTruncateWipesTail() {
  SecureBuffer buf("SECRETVALUE");
  const unsigned char *tail = buf.data() + 6;
  buf.truncate(6);
  assert(buf.size() == 6);
  assert(buf.str() == "SECRET");
  for (size_t i = 0; i < 5; ++i)
    assert(tail[i] == 0 && "truncated tail must be wiped in place");
}

int main() {
  testProtectionsInitialize();
  testCoreDumpLimitIsZero();
  testSecretsLandInTheSecureHeap();
  testGrowthWipesTheAbandonedBuffer();
  testStrictModeIsReported();
  testSecureBufferTruncateWipesTail();
  std::cout << "secure memory tests passed\n";
  return 0;
}
