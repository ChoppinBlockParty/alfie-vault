//===----------------------------------------------------------------------===//
/// \file
/// Exercise ipc transport behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ipc_transport.h"
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

using namespace alfie;

static mode_t modeOf(const std::filesystem::path &p) {
  struct stat st{};
  assert(lstat(p.c_str(), &st) == 0);
  return st.st_mode & 0777;
}

// Assert fail-closed behavior for each deliberately unsafe operation.
template <typename F> static void rejects(F operation) {
  bool rejected = false;
  try {
    operation();
  } catch (const std::exception &) {
    rejected = true;
  }
  assert(rejected);
}

// Queue a real local peer to exercise the accept-time credential check.
static int connectTo(const std::filesystem::path &path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(fd >= 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strcpy(addr.sun_path, path.c_str());
  assert(connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  return fd;
}

// Creation must remain private even when the process umask permits public
// access.
static void testRuntimePermissions(const std::filesystem::path &dir) {
  mode_t oldMask = umask(0);
  makePrivateRuntimeDir(dir);
  umask(oldMask);
  assert(modeOf(dir) == 0700);
  makePrivateRuntimeDir(dir);
}

// Accepted peers must have the expected UID and safe descriptor flags.
static void testSocketCredentials(const std::filesystem::path &dir) {
  auto socketPath = dir / "vault.sock";
  int listener = bindSecureUnixSocket(socketPath);
  assert(modeOf(socketPath) == 0600);
  assert(fcntl(listener, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(listener, F_GETFL) & O_NONBLOCK);
  rejects([&] { peerUid(listener); });
  rejects([&] { acceptSecureUnixSocket(listener, geteuid()); });
  rejects([&] { bindSecureUnixSocket(socketPath); });
  int client = connectTo(socketPath);
  int accepted = acceptSecureUnixSocket(listener, geteuid());
  assert(peerUid(accepted) == geteuid());
  assert(fcntl(accepted, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(accepted, F_GETFL) & O_NONBLOCK);
  close(accepted);
  close(client);
  client = connectTo(socketPath);
  rejects([&] { acceptSecureUnixSocket(listener, geteuid() + 1); });
  char byte;
  assert(read(client, &byte, 1) == 0);
  close(client);
  close(listener);
  // Stale entries are not removed automatically either.
  rejects([&] { bindSecureUnixSocket(socketPath); });
}

// Reject unsafe paths without deleting entries or changing existing
// permissions.
static void testUnsafePaths(const std::filesystem::path &root,
                            const std::filesystem::path &dir) {
  // A failed bind must preserve regular files and symlinks.
  auto file = dir / "keep";
  std::ofstream(file) << "must survive";
  rejects([&] { bindSecureUnixSocket(file); });
  assert(std::filesystem::file_size(file) == 12);
  auto alias = root / "alias";
  std::filesystem::create_directory_symlink(dir, alias);
  rejects([&] { makePrivateRuntimeDir(alias); });
  rejects([&] { bindSecureUnixSocket(alias / "bad.sock"); });
  std::filesystem::create_symlink(file, dir / "link.sock");
  rejects([&] { bindSecureUnixSocket(dir / "link.sock"); });
  assert(std::filesystem::is_symlink(dir / "link.sock"));
  // Refuse public runtime directories instead of silently repairing them.
  chmod(dir.c_str(), 0777);
  rejects([&] { makePrivateRuntimeDir(dir); });
  assert(modeOf(dir) == 0777);
  rejects([&] { makePrivateRuntimeDir(dir / "child"); });
  chmod(dir.c_str(), 0700);
  // Reject traversal and pathname truncation before calling bind.
  rejects([&] { makePrivateRuntimeDir("relative"); });
  rejects([&] { makePrivateRuntimeDir(dir / ".." / "escape"); });
  rejects([&] { bindSecureUnixSocket(dir / std::string(200, 'x')); });
  rejects([&] { bindSecureUnixSocket(dir / std::string("bad\0suffix", 10)); });
  rejects([&] { peerUid(-1); });
}

int main() {
  // Resolve the OS-provided temp alias before selecting a fresh, privately
  // owned test root.
  auto pattern =
      (std::filesystem::canonical(std::filesystem::temp_directory_path()) /
       "alfie-ipc-XXXXXX")
          .string();
  assert(mkdtemp(pattern.data()));
  auto root = std::filesystem::path(pattern);
  auto dir = root / "runtime";
  testRuntimePermissions(dir);
  testSocketCredentials(dir);
  testUnsafePaths(root, dir);
  std::filesystem::remove_all(root);
  std::cout << "IPC transport tests passed\n";
}
