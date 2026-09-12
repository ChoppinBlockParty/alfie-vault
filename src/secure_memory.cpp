//===----------------------------------------------------------------------===//
/// \file
/// Lock and wipe secret allocations and disable process core dumps.
//===----------------------------------------------------------------------===//

#include "secure_memory.h"
#include "vault.h"
#include <openssl/crypto.h>
#include <sys/mman.h>
#include <sys/resource.h>

using namespace alfie;

static constinit MemoryProtections gProtections;

// Locks `bytes` at `p` out of swap and out of core dumps. Returns false when
// the OS refuses, which is common under a small RLIMIT_MEMLOCK.
//
// Caveat that motivates the secure heap: mlock/munlock operate on whole pages,
// so two secrets that land on one page share a lock. Freeing one would munlock
// the other's page. Arena allocations from OpenSSL's secure heap are locked
// once, as a unit, and never hit this path.
static bool lockPages(void *p, size_t bytes) {
  if (p == nullptr || bytes == 0)
    return true;
#ifdef MADV_DONTDUMP
  madvise(p, bytes, MADV_DONTDUMP);
#endif
  return mlock(p, bytes) == 0;
}

static void unlockPages(void *p, size_t bytes) noexcept {
  if (p == nullptr || bytes == 0)
    return;
#ifdef MADV_DODUMP
  madvise(p, bytes, MADV_DODUMP);
#endif
  munlock(p, bytes);
}

MemoryProtections alfie::initProcessMemoryProtections(MemoryPolicy policy,
                                                      size_t secureHeapBytes) {
  gProtections.policy = policy;

  if (CRYPTO_secure_malloc_initialized() != 1) {
    // Second argument is the arena's minimum allocation unit; both it and the
    // arena size must be powers of two. The arena is mlock'd as a whole at
    // init.
    CRYPTO_secure_malloc_init(secureHeapBytes, 64);
  }
  gProtections.secureHeap = CRYPTO_secure_malloc_initialized() == 1;

  // A core dump of this process would contain whatever plaintext was live at
  // crash time.
  struct rlimit noCore = {0, 0};
  gProtections.coreDumpsDisabled = setrlimit(RLIMIT_CORE, &noCore) == 0;

  if (policy == MemoryPolicy::Strict) {
    if (!gProtections.secureHeap)
      throw CryptoError(
          "strict memory policy: OpenSSL secure heap unavailable");
    if (!gProtections.coreDumpsDisabled)
      throw CryptoError("strict memory policy: cannot disable core dumps");
  }
  return gProtections;
}

const MemoryProtections &alfie::memoryProtections() { return gProtections; }

bool alfie::strictMemory() {
  return gProtections.policy == MemoryPolicy::Strict;
}

void *alfie::secureAllocate(size_t bytes) {
  if (bytes == 0)
    return nullptr;

  // OPENSSL_secure_malloc serves from the secure arena when it is initialized
  // and has room, and otherwise falls back to OPENSSL_malloc.
  // OPENSSL_secure_clear_free mirrors that decision, so the pair stays
  // consistent whether or not the heap was ever initialized.
  void *p = OPENSSL_secure_malloc(bytes);
  if (p == nullptr)
    throw std::bad_alloc();

  if (CRYPTO_secure_allocated(p) != 0)
    return p; // arena memory: already locked and excluded from dumps.

  // Fell back to the normal heap: lock this allocation on its own.
  if (!lockPages(p, bytes)) {
    if (strictMemory()) {
      OPENSSL_secure_clear_free(p, bytes);
      throw CryptoError(
          "strict memory policy: cannot lock secret memory (mlock failed)");
    }
  }
  return p;
}

void alfie::secureDeallocate(void *p, size_t bytes) noexcept {
  if (p == nullptr)
    return;
  if (CRYPTO_secure_allocated(p) == 0 && bytes > 0) {
    // Wipe while the pages are still locked, then release the lock.
    OPENSSL_cleanse(p, bytes);
    unlockPages(p, bytes);
  }
  OPENSSL_secure_clear_free(p, bytes);
}
