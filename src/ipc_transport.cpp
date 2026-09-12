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

static std::runtime_error sysError(const std::string &what) {
  return std::runtime_error(what + ": " + std::strerror(errno));
}

// Fail closed if the directory could be replaced or accessed by another user.
static void validateRuntimeDirectory(int fd, bool isRuntimeDir) {
  struct stat info{};
  if (fstat(fd, &info) != 0)
    throw sysError("stat runtime component");
  if (isRuntimeDir) {
    if (info.st_uid != geteuid() || (info.st_mode & 07777) != 0700)
      throw std::runtime_error(
          "runtime directory requires effective UID ownership and mode 0700");
    return;
  }

  // Root-owned sticky directories allow safe private children under /tmp.
  bool trustedOwner = info.st_uid == 0 || info.st_uid == geteuid();
  bool publiclyWritable = info.st_mode & 0022;
  bool rootSticky = info.st_uid == 0 && (info.st_mode & S_ISVTX);
  if (!trustedOwner || (publiclyWritable && !rootSticky))
    throw std::runtime_error("untrusted runtime ancestor");
}

// Prevent descriptor inheritance and blocking IPC operations on all supported
// platforms.
static void configureUnixSocket(int fd) {
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(fd, F_SETFL, O_NONBLOCK) != 0)
    throw sysError("configure unix socket");
}

// Walk through directory descriptors so symlinks cannot redirect runtime
// creation.
std::filesystem::path
alfie::makePrivateRuntimeDir(const std::filesystem::path &dir) {
  if (!dir.is_absolute() || dir.string().find('\0') != std::string::npos ||
      dir == dir.root_path())
    throw std::runtime_error(
        "runtime directory must be an absolute non-root path");
  ScopedFd current(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (current.get() < 0)
    throw sysError("open runtime root");

  auto relative = dir.relative_path();
  for (auto it = relative.begin(); it != relative.end(); ++it) {
    const auto name = it->string();
    if (name.empty() || name == "." || name == "..")
      throw std::runtime_error("invalid runtime path component");
    // Restrict new directories at creation; never repair existing permissions.
    if (mkdirat(current.get(), name.c_str(), 0700) != 0 && errno != EEXIST)
      throw sysError("mkdir runtime component");
    int next = openat(current.get(), name.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0)
      throw sysError("open runtime component");
    current.reset(next);
    validateRuntimeDirectory(current.get(), std::next(it) == relative.end());
  }
  return dir;
}

int alfie::bindSecureUnixSocket(const std::filesystem::path &socketPath) {
  // Reject NUL truncation and pathname overflow before touching the filesystem.
  const std::string path = socketPath.string();
  sockaddr_un addr{};
  if (path.find('\0') != std::string::npos ||
      path.size() >= sizeof(addr.sun_path) || socketPath.filename().empty())
    throw std::runtime_error("invalid socket path");
  makePrivateRuntimeDir(socketPath.parent_path());
  // Binding fails on existing entries; never delete another listener or file.
  ScopedFd socketFd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (socketFd.get() < 0)
    throw sysError("socket");
  configureUnixSocket(socketFd.get());
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (bind(socketFd.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
      0)
    throw sysError("bind");
  // The enclosing 0700 directory protects the socket before chmod completes.
  if (chmod(path.c_str(), 0600) != 0)
    throw sysError("chmod socket");
  if (listen(socketFd.get(), 16) != 0)
    throw sysError("listen");
  return socketFd.release();
}

// Authenticate the peer before handing its connection to the caller.
int alfie::acceptSecureUnixSocket(int listener, uid_t expectedUid) {
#ifdef __linux__
  ScopedFd Client(
      accept4(Listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
#else
  ScopedFd client(accept(listener, nullptr, nullptr));
#endif
  if (client.get() < 0)
    throw sysError("accept unix socket");
  configureUnixSocket(client.get());
  if (peerUid(client.get()) != expectedUid)
    throw CryptoError("unauthorized Unix socket peer");
  return client.release();
}

uid_t alfie::peerUid(int connectedUnixSocketFd) {
  // Reject listeners and non-Unix sockets before interpreting peer credentials.
  sockaddr_storage address{};
  socklen_t addressLen = sizeof(address);
  int type = 0;
  socklen_t typeLen = sizeof(type);
  if (getpeername(connectedUnixSocketFd, reinterpret_cast<sockaddr *>(&address),
                  &addressLen) != 0 ||
      getsockopt(connectedUnixSocketFd, SOL_SOCKET, SO_TYPE, &type, &typeLen) !=
          0)
    throw sysError("inspect unix peer");
  if (address.ss_family != AF_UNIX || type != SOCK_STREAM)
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
  uid_t uid = 0;
  gid_t gid = 0;
  if (getpeereid(connectedUnixSocketFd, &uid, &gid) != 0) {
    throw sysError("getpeereid");
  }
  return uid;
#endif
}
