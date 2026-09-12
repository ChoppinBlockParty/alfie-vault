//===----------------------------------------------------------------------===//
/// \file
/// Restrict Unix socket access to the expected local user.
//===----------------------------------------------------------------------===//

#include "ipc_transport.h"
#include "scoped_fd.h"
#include "vault.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

using namespace alfie;

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

static std::runtime_error sysError(const std::string &What) {
  return std::runtime_error(What + ": " + std::strerror(errno));
}

// Fail closed if the directory could be replaced or accessed by another user.
static void validateRuntimeDirectory(int Fd, bool IsRuntimeDir) {
  struct stat Info{};
  if (fstat(Fd, &Info) != 0)
    throw sysError("stat runtime component");
  if (IsRuntimeDir) {
    if (Info.st_uid != geteuid() || (Info.st_mode & 07777) != 0700)
      throw std::runtime_error(
          "runtime directory requires effective UID ownership and mode 0700");
    return;
  }

  // Root-owned sticky directories allow safe private children under /tmp.
  bool TrustedOwner = Info.st_uid == 0 || Info.st_uid == geteuid();
  bool PubliclyWritable = Info.st_mode & 0022;
  bool RootSticky = Info.st_uid == 0 && (Info.st_mode & S_ISVTX);
  if (!TrustedOwner || (PubliclyWritable && !RootSticky))
    throw std::runtime_error("untrusted runtime ancestor");
}

// Prevent descriptor inheritance and blocking IPC operations on all supported
// platforms.
static void configureUnixSocket(int Fd) {
  if (fcntl(Fd, F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(Fd, F_SETFL, O_NONBLOCK) != 0)
    throw sysError("configure unix socket");
}

// Walk through directory descriptors so symlinks cannot redirect runtime
// creation.
std::filesystem::path
alfie::makePrivateRuntimeDir(const std::filesystem::path &Dir) {
  if (!Dir.is_absolute() || Dir.string().find('\0') != std::string::npos ||
      Dir == Dir.root_path())
    throw std::runtime_error(
        "runtime directory must be an absolute non-root path");
  ScopedFd Current(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (Current.get() < 0)
    throw sysError("open runtime root");

  auto Relative = Dir.relative_path();
  for (auto It = Relative.begin(); It != Relative.end(); ++It) {
    const auto Name = It->string();
    if (Name.empty() || Name == "." || Name == "..")
      throw std::runtime_error("invalid runtime path component");
    // Restrict new directories at creation; never repair existing permissions.
    if (mkdirat(Current.get(), Name.c_str(), 0700) != 0 && errno != EEXIST)
      throw sysError("mkdir runtime component");
    int Next = openat(Current.get(), Name.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (Next < 0)
      throw sysError("open runtime component");
    Current.reset(Next);
    validateRuntimeDirectory(Current.get(), std::next(It) == Relative.end());
  }
  return Dir;
}

int alfie::bindSecureUnixSocket(const std::filesystem::path &SocketPath) {
  // Reject NUL truncation and pathname overflow before touching the filesystem.
  const std::string Path = SocketPath.string();
  sockaddr_un Addr{};
  if (Path.find('\0') != std::string::npos ||
      Path.size() >= sizeof(Addr.sun_path) || SocketPath.filename().empty())
    throw std::runtime_error("invalid socket path");
  makePrivateRuntimeDir(SocketPath.parent_path());
  // Binding fails on existing entries; never delete another listener or file.
  ScopedFd SocketFd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (SocketFd.get() < 0)
    throw sysError("socket");
  configureUnixSocket(SocketFd.get());
  Addr.sun_family = AF_UNIX;
  std::memcpy(Addr.sun_path, Path.c_str(), Path.size() + 1);
  if (bind(SocketFd.get(), reinterpret_cast<sockaddr *>(&Addr), sizeof(Addr)) !=
      0)
    throw sysError("bind");
  // The enclosing 0700 directory protects the socket before chmod completes.
  if (chmod(Path.c_str(), 0600) != 0)
    throw sysError("chmod socket");
  if (listen(SocketFd.get(), 16) != 0)
    throw sysError("listen");
  return SocketFd.release();
}

// Authenticate the peer before handing its connection to the caller.
int alfie::acceptSecureUnixSocket(int Listener, uid_t ExpectedUid) {
#ifdef __linux__
  ScopedFd Client(
      accept4(Listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
#else
  ScopedFd Client(accept(Listener, nullptr, nullptr));
#endif
  if (Client.get() < 0)
    throw sysError("accept unix socket");
  configureUnixSocket(Client.get());
  if (peerUid(Client.get()) != ExpectedUid)
    throw CryptoError("unauthorized Unix socket peer");
  return Client.release();
}

uid_t alfie::peerUid(int ConnectedUnixSocketFd) {
  // Reject listeners and non-Unix sockets before interpreting peer credentials.
  sockaddr_storage Address{};
  socklen_t AddressLen = sizeof(Address);
  int Type = 0;
  socklen_t TypeLen = sizeof(Type);
  if (getpeername(ConnectedUnixSocketFd, reinterpret_cast<sockaddr *>(&Address),
                  &AddressLen) != 0 ||
      getsockopt(ConnectedUnixSocketFd, SOL_SOCKET, SO_TYPE, &Type, &TypeLen) !=
          0)
    throw sysError("inspect unix peer");
  if (Address.ss_family != AF_UNIX || Type != SOCK_STREAM)
    throw CryptoError("peer must be a connected Unix stream socket");
#ifdef __linux__
  // Read identity from the kernel rather than trusting client-supplied data.
  ucred Cred{};
  socklen_t Len = sizeof(Cred);
  if (getsockopt(ConnectedUnixSocketFd, SOL_SOCKET, SO_PEERCRED, &Cred, &Len) !=
      0) {
    throw sysError("SO_PEERCRED");
  }
  if (Len != sizeof(Cred))
    throw std::runtime_error("invalid peer credential length");
  return Cred.uid;
#else
  // macOS/BSD have no SO_PEERCRED; getpeereid(3) is the equivalent.
  uid_t Uid = 0;
  gid_t Gid = 0;
  if (getpeereid(ConnectedUnixSocketFd, &Uid, &Gid) != 0) {
    throw sysError("getpeereid");
  }
  return Uid;
#endif
}
