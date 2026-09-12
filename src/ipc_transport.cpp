#include "ipc_transport.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>

#include "scoped_fd.hpp"
#include "vault.hpp"

namespace alfie {

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

namespace {
std::runtime_error sys_error(const std::string& what) {
  return std::runtime_error(what + ": " + std::strerror(errno));
}

// Fail closed if the directory could be replaced or accessed by another user.
void validate_runtime_directory(int fd, bool is_runtime_dir) {
  struct stat info{};
  if (fstat(fd, &info) != 0)
    throw sys_error("stat runtime component");
  if (is_runtime_dir) {
    if (info.st_uid != geteuid() || (info.st_mode & 07777) != 0700)
      throw std::runtime_error("runtime directory requires effective UID ownership and mode 0700");
    return;
  }

  // Root-owned sticky directories allow safe private children under /tmp.
  bool trusted_owner = info.st_uid == 0 || info.st_uid == geteuid();
  bool publicly_writable = info.st_mode & 0022;
  bool root_sticky = info.st_uid == 0 && (info.st_mode & S_ISVTX);
  if (!trusted_owner || (publicly_writable && !root_sticky))
    throw std::runtime_error("untrusted runtime ancestor");
}

// Prevent descriptor inheritance and blocking IPC operations on all supported platforms.
void configure_unix_socket(int fd) {
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fcntl(fd, F_SETFL, O_NONBLOCK) != 0)
    throw sys_error("configure unix socket");
}
}  // namespace

// Walk through directory descriptors so symlinks cannot redirect runtime creation.
std::filesystem::path make_private_runtime_dir(const std::filesystem::path& dir) {
  if (!dir.is_absolute() || dir.string().find('\0') != std::string::npos || dir == dir.root_path())
    throw std::runtime_error("runtime directory must be an absolute non-root path");
  ScopedFd current(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (current.get() < 0)
    throw sys_error("open runtime root");

  auto relative = dir.relative_path();
  for (auto it = relative.begin(); it != relative.end(); ++it) {
    const auto name = it->string();
    if (name.empty() || name == "." || name == "..")
      throw std::runtime_error("invalid runtime path component");
    // Restrict new directories at creation; never repair existing permissions.
    if (mkdirat(current.get(), name.c_str(), 0700) != 0 && errno != EEXIST)
      throw sys_error("mkdir runtime component");
    int next = openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0)
      throw sys_error("open runtime component");
    current.reset(next);
    validate_runtime_directory(current.get(), std::next(it) == relative.end());
  }
  return dir;
}

int bind_secure_unix_socket(const std::filesystem::path& socket_path) {
  // Reject NUL truncation and pathname overflow before touching the filesystem.
  const std::string path = socket_path.string();
  sockaddr_un addr{};
  if (path.find('\0') != std::string::npos || path.size() >= sizeof(addr.sun_path) ||
      socket_path.filename().empty())
    throw std::runtime_error("invalid socket path");
  make_private_runtime_dir(socket_path.parent_path());
  // Binding fails on existing entries; never delete another listener or file.
  ScopedFd socket_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (socket_fd.get() < 0)
    throw sys_error("socket");
  configure_unix_socket(socket_fd.get());
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    throw sys_error("bind");
  // The enclosing 0700 directory protects the socket before chmod completes.
  if (chmod(path.c_str(), 0600) != 0)
    throw sys_error("chmod socket");
  if (listen(socket_fd.get(), 16) != 0)
    throw sys_error("listen");
  return socket_fd.release();
}

// Authenticate the peer before handing its connection to the caller.
int accept_secure_unix_socket(int listener, uid_t expected_uid) {
#ifdef __linux__
  ScopedFd client(accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
#else
  ScopedFd client(accept(listener, nullptr, nullptr));
#endif
  if (client.get() < 0)
    throw sys_error("accept unix socket");
  configure_unix_socket(client.get());
  if (peer_uid(client.get()) != expected_uid)
    throw CryptoError("unauthorized Unix socket peer");
  return client.release();
}

uid_t peer_uid(int connected_unix_socket_fd) {
  // Reject listeners and non-Unix sockets before interpreting peer credentials.
  sockaddr_storage address{};
  socklen_t address_len = sizeof(address);
  int type = 0;
  socklen_t type_len = sizeof(type);
  if (getpeername(connected_unix_socket_fd, reinterpret_cast<sockaddr*>(&address), &address_len) !=
          0 ||
      getsockopt(connected_unix_socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0)
    throw sys_error("inspect unix peer");
  if (address.ss_family != AF_UNIX || type != SOCK_STREAM)
    throw CryptoError("peer must be a connected Unix stream socket");
#ifdef __linux__
  // Read identity from the kernel rather than trusting client-supplied data.
  ucred cred{};
  socklen_t len = sizeof(cred);
  if (getsockopt(connected_unix_socket_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    throw sys_error("SO_PEERCRED");
  }
  if (len != sizeof(cred))
    throw std::runtime_error("invalid peer credential length");
  return cred.uid;
#else
  // macOS/BSD have no SO_PEERCRED; getpeereid(3) is the equivalent.
  uid_t uid = 0;
  gid_t gid = 0;
  if (getpeereid(connected_unix_socket_fd, &uid, &gid) != 0) {
    throw sys_error("getpeereid");
  }
  return uid;
#endif
}

}  // namespace alfie
