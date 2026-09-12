#include "ipc_transport.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

namespace alfie {

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

namespace {
std::runtime_error sys_error(const std::string& what) {
  return std::runtime_error(what + ": " + std::strerror(errno));
}
}  // namespace

std::filesystem::path make_private_runtime_dir(const std::filesystem::path& dir) {
  std::filesystem::create_directories(dir);
  if (chmod(dir.c_str(), 0700) != 0)
    throw sys_error("chmod runtime dir");
  return dir;
}

int bind_secure_unix_socket(const std::filesystem::path& socket_path) {
  make_private_runtime_dir(socket_path.parent_path());
  std::filesystem::remove(socket_path);

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd >= 0 && SOCK_CLOEXEC == 0)
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  if (fd < 0)
    throw sys_error("socket");

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::string path = socket_path.string();
  if (path.size() >= sizeof(addr.sun_path)) {
    close(fd);
    throw std::runtime_error("socket path too long");
  }
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    throw sys_error("bind");
  }
  if (chmod(socket_path.c_str(), 0600) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    throw sys_error("chmod socket");
  }
  if (listen(fd, 16) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    throw sys_error("listen");
  }
  return fd;
}

uid_t peer_uid(int connected_unix_socket_fd) {
#ifdef __linux__
  ucred cred{};
  socklen_t len = sizeof(cred);
  if (getsockopt(connected_unix_socket_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    throw sys_error("SO_PEERCRED");
  }
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
