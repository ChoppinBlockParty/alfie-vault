//===----------------------------------------------------------------------===//
/// \file
/// Close owned file descriptors on every exit path.
//===----------------------------------------------------------------------===//

#ifndef SCOPED_FD_H
#define SCOPED_FD_H

#include <unistd.h>
#include <utility>

namespace alfie {

/// Close owned descriptors on every exit path, including exceptions.
class ScopedFd {
public:
  explicit ScopedFd(int Fd) : Fd(Fd) {}
  ~ScopedFd() { reset(-1); }
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;

  int get() const { return this->Fd; }

  /// Transfer ownership to a caller that manages the descriptor lifetime.
  int release() { return std::exchange(this->Fd, -1); }

  /// Replace a directory descriptor while walking a validated path.
  void reset(int Fd) {
    if (this->Fd >= 0)
      close(this->Fd);
    this->Fd = Fd;
  }

private:
  int Fd;
};

} // namespace alfie

#endif // SCOPED_FD_H
