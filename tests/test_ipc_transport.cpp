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

static mode_t modeOf(const std::filesystem::path &P) {
  struct stat St{};
  assert(lstat(P.c_str(), &St) == 0);
  return St.st_mode & 0777;
}

// Assert fail-closed behavior for each deliberately unsafe operation.
template <typename F> static void rejects(F Operation) {
  bool Rejected = false;
  try {
    Operation();
  } catch (const std::exception &) {
    Rejected = true;
  }
  assert(Rejected);
}

// Queue a real local peer to exercise the accept-time credential check.
static int connectTo(const std::filesystem::path &Path) {
  int Fd = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(Fd >= 0);
  sockaddr_un Addr{};
  Addr.sun_family = AF_UNIX;
  std::strcpy(Addr.sun_path, Path.c_str());
  assert(connect(Fd, reinterpret_cast<sockaddr *>(&Addr), sizeof(Addr)) == 0);
  return Fd;
}

// Creation must remain private even when the process umask permits public
// access.
static void testRuntimePermissions(const std::filesystem::path &Dir) {
  mode_t OldMask = umask(0);
  makePrivateRuntimeDir(Dir);
  umask(OldMask);
  assert(modeOf(Dir) == 0700);
  makePrivateRuntimeDir(Dir);
}

// Accepted peers must have the expected UID and safe descriptor flags.
static void testSocketCredentials(const std::filesystem::path &Dir) {
  auto SocketPath = Dir / "vault.sock";
  int Listener = bindSecureUnixSocket(SocketPath);
  assert(modeOf(SocketPath) == 0600);
  assert(fcntl(Listener, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(Listener, F_GETFL) & O_NONBLOCK);
  rejects([&] { peerUid(Listener); });
  rejects([&] { acceptSecureUnixSocket(Listener, geteuid()); });
  rejects([&] { bindSecureUnixSocket(SocketPath); });
  int Client = connectTo(SocketPath);
  int Accepted = acceptSecureUnixSocket(Listener, geteuid());
  assert(peerUid(Accepted) == geteuid());
  assert(fcntl(Accepted, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(Accepted, F_GETFL) & O_NONBLOCK);
  close(Accepted);
  close(Client);
  Client = connectTo(SocketPath);
  rejects([&] { acceptSecureUnixSocket(Listener, geteuid() + 1); });
  char Byte;
  assert(read(Client, &Byte, 1) == 0);
  close(Client);
  close(Listener);
  // Stale entries are not removed automatically either.
  rejects([&] { bindSecureUnixSocket(SocketPath); });
}

// Reject unsafe paths without deleting entries or changing existing
// permissions.
static void testUnsafePaths(const std::filesystem::path &Root,
                            const std::filesystem::path &Dir) {
  // A failed bind must preserve regular files and symlinks.
  auto File = Dir / "keep";
  std::ofstream(File) << "must survive";
  rejects([&] { bindSecureUnixSocket(File); });
  assert(std::filesystem::file_size(File) == 12);
  auto Alias = Root / "alias";
  std::filesystem::create_directory_symlink(Dir, Alias);
  rejects([&] { makePrivateRuntimeDir(Alias); });
  rejects([&] { bindSecureUnixSocket(Alias / "bad.sock"); });
  std::filesystem::create_symlink(File, Dir / "link.sock");
  rejects([&] { bindSecureUnixSocket(Dir / "link.sock"); });
  assert(std::filesystem::is_symlink(Dir / "link.sock"));
  // Refuse public runtime directories instead of silently repairing them.
  chmod(Dir.c_str(), 0777);
  rejects([&] { makePrivateRuntimeDir(Dir); });
  assert(modeOf(Dir) == 0777);
  rejects([&] { makePrivateRuntimeDir(Dir / "child"); });
  chmod(Dir.c_str(), 0700);
  // Reject traversal and pathname truncation before calling bind.
  rejects([&] { makePrivateRuntimeDir("relative"); });
  rejects([&] { makePrivateRuntimeDir(Dir / ".." / "escape"); });
  rejects([&] { bindSecureUnixSocket(Dir / std::string(200, 'x')); });
  rejects([&] { bindSecureUnixSocket(Dir / std::string("bad\0suffix", 10)); });
  rejects([&] { peerUid(-1); });
}

int main() {
  // Resolve the OS-provided temp alias before selecting a fresh, privately
  // owned test root.
  auto Pattern =
      (std::filesystem::canonical(std::filesystem::temp_directory_path()) /
       "alfie-ipc-XXXXXX")
          .string();
  assert(mkdtemp(Pattern.data()));
  auto Root = std::filesystem::path(Pattern);
  auto Dir = Root / "runtime";
  testRuntimePermissions(Dir);
  testSocketCredentials(Dir);
  testUnsafePaths(Root, Dir);
  std::filesystem::remove_all(Root);
  std::cout << "IPC transport tests passed\n";
}
