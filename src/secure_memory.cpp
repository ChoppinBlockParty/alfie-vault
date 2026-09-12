#include "secure_memory.hpp"

#include <openssl/crypto.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "vault.hpp"

namespace alfie {
namespace {

MemoryProtections g_protections;

// Locks `bytes` at `p` out of swap and out of core dumps. Returns false when the OS refuses,
// which is common under a small RLIMIT_MEMLOCK.
//
// Caveat that motivates the secure heap: mlock/munlock operate on whole pages, so two secrets
// that land on one page share a lock. Freeing one would munlock the other's page. Arena
// allocations from OpenSSL's secure heap are locked once, as a unit, and never hit this path.
bool lock_pages(void* p, size_t bytes) {
  if (p == nullptr || bytes == 0)
    return true;
#ifdef MADV_DONTDUMP
  madvise(p, bytes, MADV_DONTDUMP);
#endif
  return mlock(p, bytes) == 0;
}

void unlock_pages(void* p, size_t bytes) noexcept {
  if (p == nullptr || bytes == 0)
    return;
#ifdef MADV_DODUMP
  madvise(p, bytes, MADV_DODUMP);
#endif
  munlock(p, bytes);
}

}  // namespace

MemoryProtections init_process_memory_protections(MemoryPolicy policy, size_t secure_heap_bytes) {
  g_protections.policy = policy;

  if (CRYPTO_secure_malloc_initialized() != 1) {
    // Second argument is the arena's minimum allocation unit; both it and the arena size must be
    // powers of two. The arena is mlock'd as a whole at init.
    CRYPTO_secure_malloc_init(secure_heap_bytes, 64);
  }
  g_protections.secure_heap = CRYPTO_secure_malloc_initialized() == 1;

  // A core dump of this process would contain whatever plaintext was live at crash time.
  struct rlimit no_core = {0, 0};
  g_protections.core_dumps_disabled = setrlimit(RLIMIT_CORE, &no_core) == 0;

  if (policy == MemoryPolicy::Strict) {
    if (!g_protections.secure_heap)
      throw CryptoError("strict memory policy: OpenSSL secure heap unavailable");
    if (!g_protections.core_dumps_disabled)
      throw CryptoError("strict memory policy: cannot disable core dumps");
  }
  return g_protections;
}

const MemoryProtections& memory_protections() {
  return g_protections;
}

bool strict_memory() {
  return g_protections.policy == MemoryPolicy::Strict;
}

void* secure_allocate(size_t bytes) {
  if (bytes == 0)
    return nullptr;

  // OPENSSL_secure_malloc serves from the secure arena when it is initialized and has room, and
  // otherwise falls back to OPENSSL_malloc. OPENSSL_secure_clear_free mirrors that decision, so
  // the pair stays consistent whether or not the heap was ever initialized.
  void* p = OPENSSL_secure_malloc(bytes);
  if (p == nullptr)
    throw std::bad_alloc();

  if (CRYPTO_secure_allocated(p) != 0)
    return p;  // arena memory: already locked and excluded from dumps.

  // Fell back to the normal heap: lock this allocation on its own.
  if (!lock_pages(p, bytes)) {
    if (strict_memory()) {
      OPENSSL_secure_clear_free(p, bytes);
      throw CryptoError("strict memory policy: cannot lock secret memory (mlock failed)");
    }
  }
  return p;
}

void secure_deallocate(void* p, size_t bytes) noexcept {
  if (p == nullptr)
    return;
  if (CRYPTO_secure_allocated(p) == 0 && bytes > 0) {
    // Wipe while the pages are still locked, then release the lock.
    OPENSSL_cleanse(p, bytes);
    unlock_pages(p, bytes);
  }
  OPENSSL_secure_clear_free(p, bytes);
}

}  // namespace alfie
