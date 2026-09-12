// Covers the process-level memory protections: OpenSSL secure heap, fail-closed strict mode,
// disabled core dumps, and wipe-on-free for secret containers.
#include <openssl/crypto.h>
#include <sys/resource.h>

#include <cassert>
#include <iostream>
#include <vector>

#include "../src/secure_memory.hpp"
#include "../src/vault.hpp"

using namespace alfie;

static void test_protections_initialize() {
  const auto status = init_process_memory_protections(MemoryPolicy::BestEffort);
  assert(status.secure_heap && "OpenSSL secure heap should initialize");
  assert(status.core_dumps_disabled && "core dumps should be disabled");
  assert(memory_protections().secure_heap);
}

static void test_core_dump_limit_is_zero() {
  struct rlimit limit{};
  assert(getrlimit(RLIMIT_CORE, &limit) == 0);
  assert(limit.rlim_cur == 0 && "RLIMIT_CORE soft limit must be 0");
}

static void test_secrets_land_in_the_secure_heap() {
  SecureBuffer secret("master password");
  assert(CRYPTO_secure_allocated(secret.data()) != 0 &&
         "secret bytes should come from the OpenSSL secure arena");
}

// A plain std::vector leaves its old buffer readable after it grows; SecureBytes must not.
static void test_growth_wipes_the_abandoned_buffer() {
  SecureBytes bytes;
  bytes.reserve(8);
  const unsigned char* first = bytes.data();
  for (int i = 0; i < 8; ++i)
    bytes.push_back(0xAB);
  const size_t old_capacity = bytes.capacity();
  bytes.push_back(0xAB);  // forces reallocation, freeing `first`
  assert(bytes.data() != first);
  // `first` is freed; the allocator must have cleansed it before release.
  bool any_nonzero = false;
  for (size_t i = 0; i < old_capacity; ++i) {
    if (first[i] != 0)
      any_nonzero = true;
  }
  assert(!any_nonzero && "abandoned secret buffer was not wiped on free");
}

static void test_strict_mode_is_reported() {
  const auto status = init_process_memory_protections(MemoryPolicy::Strict);
  assert(status.policy == MemoryPolicy::Strict);
  assert(strict_memory());
  // Strict mode only reaches this line because both protections are in place; if either had
  // failed, init_process_memory_protections would have thrown instead of degrading.
  assert(status.secure_heap && status.core_dumps_disabled);
  init_process_memory_protections(MemoryPolicy::BestEffort);
}

static void test_secure_buffer_truncate_wipes_tail() {
  SecureBuffer buf("SECRETVALUE");
  const unsigned char* tail = buf.data() + 6;
  buf.truncate(6);
  assert(buf.size() == 6);
  assert(buf.str() == "SECRET");
  for (size_t i = 0; i < 5; ++i)
    assert(tail[i] == 0 && "truncated tail must be wiped in place");
}

int main() {
  test_protections_initialize();
  test_core_dump_limit_is_zero();
  test_secrets_land_in_the_secure_heap();
  test_growth_wipes_the_abandoned_buffer();
  test_strict_mode_is_reported();
  test_secure_buffer_truncate_wipes_tail();
  std::cout << "secure memory tests passed\n";
  return 0;
}
