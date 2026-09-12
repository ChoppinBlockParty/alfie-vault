#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "../src/ipc_transport.hpp"

using namespace alfie;

static mode_t mode_of(const std::filesystem::path& p) {
  struct stat st{};
  assert(lstat(p.c_str(), &st) == 0);
  return st.st_mode & 0777;
}

// Assert fail-closed behavior for each deliberately unsafe operation.
template <typename F>
static void rejects(F operation) {
  bool rejected = false;
  try {
    operation();
  } catch (const std::exception&) {
    rejected = true;
  }
  assert(rejected);
}

// Queue a real local peer to exercise the accept-time credential check.
static int connect_to(const std::filesystem::path& path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(fd >= 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strcpy(addr.sun_path, path.c_str());
  assert(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  return fd;
}

// Creation must remain private even when the process umask permits public access.
static void test_runtime_permissions(const std::filesystem::path& dir) {
  mode_t old_mask = umask(0);
  make_private_runtime_dir(dir);
  umask(old_mask);
  assert(mode_of(dir) == 0700);
  make_private_runtime_dir(dir);
}

// Accepted peers must have the expected UID and safe descriptor flags.
static void test_socket_credentials(const std::filesystem::path& dir) {
  auto socket_path = dir / "vault.sock";
  int listener = bind_secure_unix_socket(socket_path);
  assert(mode_of(socket_path) == 0600);
  assert(fcntl(listener, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(listener, F_GETFL) & O_NONBLOCK);
  rejects([&] { peer_uid(listener); });
  rejects([&] { accept_secure_unix_socket(listener, geteuid()); });
  rejects([&] { bind_secure_unix_socket(socket_path); });
  int client = connect_to(socket_path);
  int accepted = accept_secure_unix_socket(listener, geteuid());
  assert(peer_uid(accepted) == geteuid());
  assert(fcntl(accepted, F_GETFD) & FD_CLOEXEC);
  assert(fcntl(accepted, F_GETFL) & O_NONBLOCK);
  close(accepted);
  close(client);
  client = connect_to(socket_path);
  rejects([&] { accept_secure_unix_socket(listener, geteuid() + 1); });
  char byte;
  assert(read(client, &byte, 1) == 0);
  close(client);
  close(listener);
  // Stale entries are not removed automatically either.
  rejects([&] { bind_secure_unix_socket(socket_path); });
}

// Reject unsafe paths without deleting entries or changing existing permissions.
static void test_unsafe_paths(const std::filesystem::path& root, const std::filesystem::path& dir) {
  // A failed bind must preserve regular files and symlinks.
  auto file = dir / "keep";
  std::ofstream(file) << "must survive";
  rejects([&] { bind_secure_unix_socket(file); });
  assert(std::filesystem::file_size(file) == 12);
  auto alias = root / "alias";
  std::filesystem::create_directory_symlink(dir, alias);
  rejects([&] { make_private_runtime_dir(alias); });
  rejects([&] { bind_secure_unix_socket(alias / "bad.sock"); });
  std::filesystem::create_symlink(file, dir / "link.sock");
  rejects([&] { bind_secure_unix_socket(dir / "link.sock"); });
  assert(std::filesystem::is_symlink(dir / "link.sock"));
  // Refuse public runtime directories instead of silently repairing them.
  chmod(dir.c_str(), 0777);
  rejects([&] { make_private_runtime_dir(dir); });
  assert(mode_of(dir) == 0777);
  rejects([&] { make_private_runtime_dir(dir / "child"); });
  chmod(dir.c_str(), 0700);
  // Reject traversal and pathname truncation before calling bind.
  rejects([&] { make_private_runtime_dir("relative"); });
  rejects([&] { make_private_runtime_dir(dir / ".." / "escape"); });
  rejects([&] { bind_secure_unix_socket(dir / std::string(200, 'x')); });
  rejects([&] { bind_secure_unix_socket(dir / std::string("bad\0suffix", 10)); });
  rejects([&] { peer_uid(-1); });
}

int main() {
  // Resolve the OS-provided temp alias before selecting a fresh, privately owned test root.
  auto pattern =
      (std::filesystem::canonical(std::filesystem::temp_directory_path()) / "alfie-ipc-XXXXXX")
          .string();
  assert(mkdtemp(pattern.data()));
  auto root = std::filesystem::path(pattern);
  auto dir = root / "runtime";
  test_runtime_permissions(dir);
  test_socket_credentials(dir);
  test_unsafe_paths(root, dir);
  std::filesystem::remove_all(root);
  std::cout << "IPC transport tests passed\n";
}
