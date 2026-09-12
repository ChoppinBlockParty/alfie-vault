#pragma once

#include <cstddef>
#include <limits>
#include <new>

namespace alfie {

// How hard the process insists on its memory protections.
//
// BestEffort keeps the historical behaviour: try to lock secrets out of swap and out of core
// dumps, but carry on when the OS refuses. Strict fails closed instead -- a box that cannot
// guarantee the protections should not go on to hold a master password in memory.
enum class MemoryPolicy { BestEffort, Strict };

struct MemoryProtections {
  // OpenSSL's secure heap is initialized, so secret allocations come from one arena that is
  // mlock'd once as a whole. This is the wanted state: it also removes the page-sharing hazard
  // of per-buffer mlock (see secure_memory.cpp).
  bool secure_heap = false;
  // setrlimit(RLIMIT_CORE, 0) succeeded, so a crash cannot spill secrets into a core file.
  bool core_dumps_disabled = false;
  MemoryPolicy policy = MemoryPolicy::BestEffort;
};

// Call once at process start, before any secret is read. Initializes the OpenSSL secure heap and
// disables core dumps. Under MemoryPolicy::Strict a failure of either throws CryptoError rather
// than degrading silently.
//
// Not calling it is safe: allocations then fall back to malloc + per-buffer mlock, which is what
// this codebase did before the secure heap existed.
MemoryProtections init_process_memory_protections(MemoryPolicy policy,
                                                  size_t secure_heap_bytes = 2u << 20);

const MemoryProtections& memory_protections();
bool strict_memory();

// Raw secret allocation. Prefer SecureAllocator/SecureBuffer over calling these.
void* secure_allocate(size_t bytes);
void secure_deallocate(void* p, size_t bytes) noexcept;

// Allocator that keeps container storage in locked, dump-excluded, wipe-on-free memory.
template <typename T>
struct SecureAllocator {
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <typename U>
  SecureAllocator(const SecureAllocator<U>&) noexcept {}

  T* allocate(size_t n) {
    if (n > std::numeric_limits<size_t>::max() / sizeof(T))
      throw std::bad_alloc();
    return static_cast<T*>(secure_allocate(n * sizeof(T)));
  }

  void deallocate(T* p, size_t n) noexcept {
    secure_deallocate(p, n * sizeof(T));
  }

  template <typename U>
  bool operator==(const SecureAllocator<U>&) const noexcept {
    return true;
  }
  template <typename U>
  bool operator!=(const SecureAllocator<U>&) const noexcept {
    return false;
  }
};

}  // namespace alfie
