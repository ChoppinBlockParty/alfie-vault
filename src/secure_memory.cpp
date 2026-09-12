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

static constinit MemoryProtections GProtections;

// Locks `bytes` at `p` out of swap and out of core dumps. Returns false when
// the OS refuses, which is common under a small RLIMIT_MEMLOCK.
//
// Caveat that motivates the secure heap: mlock/munlock operate on whole pages,
// so two secrets that land on one page share a lock. Freeing one would munlock
// the other's page. Arena allocations from OpenSSL's secure heap are locked
// once, as a unit, and never hit this path.
static bool lockPages(void *P, size_t Bytes) {
  if (P == nullptr || Bytes == 0)
    return true;
#ifdef MADV_DONTDUMP
  madvise(P, Bytes, MADV_DONTDUMP);
#endif
  return mlock(P, Bytes) == 0;
}

static void unlockPages(void *P, size_t Bytes) noexcept {
  if (P == nullptr || Bytes == 0)
    return;
#ifdef MADV_DODUMP
  madvise(P, Bytes, MADV_DODUMP);
#endif
  munlock(P, Bytes);
}

MemoryProtections alfie::initProcessMemoryProtections(MemoryPolicy Policy,
                                                      size_t SecureHeapBytes) {
  GProtections.Policy = Policy;

  if (CRYPTO_secure_malloc_initialized() != 1) {
    // Second argument is the arena's minimum allocation unit; both it and the
    // arena size must be powers of two. The arena is mlock'd as a whole at
    // init.
    CRYPTO_secure_malloc_init(SecureHeapBytes, 64);
  }
  GProtections.SecureHeap = CRYPTO_secure_malloc_initialized() == 1;

  // A core dump of this process would contain whatever plaintext was live at
  // crash time.
  struct rlimit NoCore = {0, 0};
  GProtections.CoreDumpsDisabled = setrlimit(RLIMIT_CORE, &NoCore) == 0;

  if (Policy == MemoryPolicy::Strict) {
    if (!GProtections.SecureHeap)
      throw CryptoError(
          "strict memory policy: OpenSSL secure heap unavailable");
    if (!GProtections.CoreDumpsDisabled)
      throw CryptoError("strict memory policy: cannot disable core dumps");
  }
  return GProtections;
}

const MemoryProtections &alfie::memoryProtections() { return GProtections; }

bool alfie::strictMemory() {
  return GProtections.Policy == MemoryPolicy::Strict;
}

void *alfie::secureAllocate(size_t Bytes) {
  if (Bytes == 0)
    return nullptr;

  // OPENSSL_secure_malloc serves from the secure arena when it is initialized
  // and has room, and otherwise falls back to OPENSSL_malloc.
  // OPENSSL_secure_clear_free mirrors that decision, so the pair stays
  // consistent whether or not the heap was ever initialized.
  void *P = OPENSSL_secure_malloc(Bytes);
  if (P == nullptr)
    throw std::bad_alloc();

  if (CRYPTO_secure_allocated(P) != 0)
    return P; // arena memory: already locked and excluded from dumps.

  // Fell back to the normal heap: lock this allocation on its own.
  if (!lockPages(P, Bytes)) {
    if (strictMemory()) {
      OPENSSL_secure_clear_free(P, Bytes);
      throw CryptoError(
          "strict memory policy: cannot lock secret memory (mlock failed)");
    }
  }
  return P;
}

void alfie::secureDeallocate(void *P, size_t Bytes) noexcept {
  if (P == nullptr)
    return;
  if (CRYPTO_secure_allocated(P) == 0 && Bytes > 0) {
    // Wipe while the pages are still locked, then release the lock.
    OPENSSL_cleanse(P, Bytes);
    unlockPages(P, Bytes);
  }
  OPENSSL_secure_clear_free(P, Bytes);
}
