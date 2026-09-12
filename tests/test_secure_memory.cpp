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
  const auto Status = initProcessMemoryProtections(MemoryPolicy::BestEffort);
  assert(Status.SecureHeap && "OpenSSL secure heap should initialize");
  assert(Status.CoreDumpsDisabled && "core dumps should be disabled");
  assert(memoryProtections().SecureHeap);
}

static void testCoreDumpLimitIsZero() {
  struct rlimit Limit{};
  assert(getrlimit(RLIMIT_CORE, &Limit) == 0);
  assert(Limit.rlim_cur == 0 && "RLIMIT_CORE soft limit must be 0");
}

static void testSecretsLandInTheSecureHeap() {
  SecureBuffer Secret("master password");
  assert(CRYPTO_secure_allocated(Secret.data()) != 0 &&
         "secret bytes should come from the OpenSSL secure arena");
}

// A plain std::vector leaves its old buffer readable after it grows;
// SecureBytes must not.
static void testGrowthWipesTheAbandonedBuffer() {
  SecureBytes Bytes;
  Bytes.reserve(8);
  const unsigned char *First = Bytes.data();
  for (int I = 0; I < 8; ++I)
    Bytes.push_back(0xAB);
  const size_t OldCapacity = Bytes.capacity();
  Bytes.push_back(0xAB); // forces reallocation, freeing `first`
  assert(Bytes.data() != First);
  // `first` is freed; the allocator must have cleansed it before release.
  bool AnyNonzero = false;
  for (size_t I = 0; I < OldCapacity; ++I) {
    if (First[I] != 0)
      AnyNonzero = true;
  }
  assert(!AnyNonzero && "abandoned secret buffer was not wiped on free");
}

static void testStrictModeIsReported() {
  const auto Status = initProcessMemoryProtections(MemoryPolicy::Strict);
  assert(Status.Policy == MemoryPolicy::Strict);
  assert(strictMemory());
  // Strict mode only reaches this line because both protections are in place;
  // if either had failed, init_process_memory_protections would have thrown
  // instead of degrading.
  assert(Status.SecureHeap && Status.CoreDumpsDisabled);
  initProcessMemoryProtections(MemoryPolicy::BestEffort);
}

static void testSecureBufferTruncateWipesTail() {
  SecureBuffer Buf("SECRETVALUE");
  const unsigned char *Tail = Buf.data() + 6;
  Buf.truncate(6);
  assert(Buf.size() == 6);
  assert(Buf.str() == "SECRET");
  for (size_t I = 0; I < 5; ++I)
    assert(Tail[I] == 0 && "truncated tail must be wiped in place");
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
