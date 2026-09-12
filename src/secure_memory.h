//===----------------------------------------------------------------------===//
/// \file
/// Lock and wipe secret allocations and disable process core dumps.
//===----------------------------------------------------------------------===//

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

namespace alfie {

/// How hard the process insists on its memory protections.
///
/// BestEffort keeps the historical behaviour: try to lock secrets out of swap
/// and out of core dumps, but carry on when the OS refuses. Strict fails closed
/// instead -- a box that cannot guarantee the protections should not go on to
/// hold a master password in memory.
enum class MemoryPolicy : std::uint8_t { BestEffort, Strict };

/// Report the protections actually established by process initialization.
struct MemoryProtections {
  /// OpenSSL's secure heap is initialized, so secret allocations come from one
  /// arena that is mlock'd once as a whole. This is the wanted state: it also
  /// removes the page-sharing hazard of per-buffer mlock (see
  /// secure_memory.cpp).
  bool SecureHeap = false;
  /// setrlimit(RLIMIT_CORE, 0) succeeded, so a crash cannot spill secrets into
  /// a core file.
  bool CoreDumpsDisabled = false;
  MemoryPolicy Policy = MemoryPolicy::BestEffort;
};

/// Call once at process start, before any secret is read. Initializes the
/// OpenSSL secure heap and disables core dumps. Under MemoryPolicy::Strict a
/// failure of either throws CryptoError rather than degrading silently.
///
/// Not calling it is safe: allocations then fall back to malloc + per-buffer
/// mlock, which is what this codebase did before the secure heap existed.
MemoryProtections initProcessMemoryProtections(MemoryPolicy Policy,
                                               size_t SecureHeapBytes = 2U
                                                                        << 20);

/// Return the last initialization result; this function does not initialize it.
const MemoryProtections &memoryProtections();
/// Return whether failures to establish memory protections must fail closed.
bool strictMemory();

/// Raw secret allocation. Prefer SecureAllocator/SecureBuffer over calling
/// these.
void *secureAllocate(size_t Bytes);
void secureDeallocate(void *P, size_t Bytes) noexcept;

/// Allocator that keeps container storage in locked, dump-excluded,
/// wipe-on-free memory.
template <typename T> struct SecureAllocator {
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <typename U>
  SecureAllocator(const SecureAllocator<U> & /*Other*/) noexcept {}

  T *allocate(size_t N) {
    if (N > std::numeric_limits<size_t>::max() / sizeof(T))
      throw std::bad_alloc();
    return static_cast<T *>(secureAllocate(N * sizeof(T)));
  }

  void deallocate(T *P, size_t N) noexcept {
    secureDeallocate(P, N * sizeof(T));
  }

  template <typename U>
  bool operator==(const SecureAllocator<U> & /*Other*/) const noexcept {
    return true;
  }
  template <typename U>
  bool operator!=(const SecureAllocator<U> & /*Other*/) const noexcept {
    return false;
  }
};

} // namespace alfie

#endif // SECURE_MEMORY_H
