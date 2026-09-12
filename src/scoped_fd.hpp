#pragma once

#include <unistd.h>

#include <utility>

namespace alfie {

// Close owned descriptors on every exit path, including exceptions.
class ScopedFd {
 public:
  explicit ScopedFd(int fd) : fd_(fd) {}
  ~ScopedFd() {
    reset(-1);
  }
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;

  int get() const {
    return fd_;
  }

  // Transfer ownership to a caller that manages the descriptor lifetime.
  int release() {
    return std::exchange(fd_, -1);
  }

  // Replace a directory descriptor while walking a validated path.
  void reset(int fd) {
    if (fd_ >= 0)
      close(fd_);
    fd_ = fd;
  }

 private:
  int fd_;
};

}  // namespace alfie
