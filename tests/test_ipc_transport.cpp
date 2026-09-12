//===----------------------------------------------------------------------===//
/// \file
/// Exercise ipc transport behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ipc_transport.h"
#include <catch_amalgamated.hpp>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

using namespace alfie;

static mode_t modeOf(const std::filesystem::path &path) {
  struct stat st{};
  REQUIRE(lstat(path.c_str(), &st) == 0);
  return st.st_mode & 0777;
}

/// Queue a real local peer to exercise the accept-time credential check.
static int connectTo(const std::filesystem::path &path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strcpy(addr.sun_path, path.c_str());
  REQUIRE(connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  return fd;
}

/// A private test root per case, so no case inherits another's directory.
struct RuntimeRoot {
  std::filesystem::path root;
  std::filesystem::path dir;

  RuntimeRoot() {
    // Resolve the OS-provided temp alias before selecting a fresh, privately
    // owned test root.
    std::string pattern =
        (std::filesystem::canonical(std::filesystem::temp_directory_path()) /
         "alfie-ipc-XXXXXX")
            .string();
    REQUIRE(mkdtemp(pattern.data()) != nullptr);
    this->root = pattern;
    this->dir = this->root / "runtime";
  }

  ~RuntimeRoot() {
    std::error_code ec;
    std::filesystem::permissions(this->dir, std::filesystem::perms::owner_all,
                                 ec);
    std::filesystem::remove_all(this->root, ec);
  }

  RuntimeRoot(const RuntimeRoot &) = delete;
  RuntimeRoot &operator=(const RuntimeRoot &) = delete;
};

TEST_CASE_METHOD(RuntimeRoot, "The runtime directory is created private",
                 "[transport][permissions]") {
  // Creation must remain private even when the process umask permits public
  // access.
  const mode_t oldMask = umask(0);
  makePrivateRuntimeDir(this->dir);
  umask(oldMask);

  CHECK(modeOf(this->dir) == 0700);
  // Creating it again over an already-private directory is not an error.
  CHECK_NOTHROW(makePrivateRuntimeDir(this->dir));
}

TEST_CASE_METHOD(RuntimeRoot, "Accepted peers are checked and safe",
                 "[transport][credentials]") {
  makePrivateRuntimeDir(this->dir);
  const std::filesystem::path socketPath = this->dir / "vault.sock";

  const int listener = bindSecureUnixSocket(socketPath);

  SECTION("the listener is private, close-on-exec and non-blocking") {
    CHECK(modeOf(socketPath) == 0600);
    CHECK(fcntl(listener, F_GETFD) & FD_CLOEXEC);
    CHECK(fcntl(listener, F_GETFL) & O_NONBLOCK);
  }

  SECTION("a listener answers neither peerUid nor a bind over itself") {
    CHECK_THROWS(peerUid(listener));
    CHECK_THROWS(acceptSecureUnixSocket(listener, geteuid()));
    CHECK_THROWS(bindSecureUnixSocket(socketPath));
  }

  SECTION("a peer with the expected uid is accepted") {
    const int client = connectTo(socketPath);
    const int accepted = acceptSecureUnixSocket(listener, geteuid());

    CHECK(peerUid(accepted) == geteuid());
    CHECK(fcntl(accepted, F_GETFD) & FD_CLOEXEC);
    CHECK(fcntl(accepted, F_GETFL) & O_NONBLOCK);

    close(accepted);
    close(client);
  }

  SECTION("a peer with another uid is refused and disconnected") {
    const int client = connectTo(socketPath);

    CHECK_THROWS(acceptSecureUnixSocket(listener, geteuid() + 1));

    char byte = 0;
    CHECK(read(client, &byte, 1) == 0);
    close(client);
  }

  close(listener);
}

TEST_CASE_METHOD(RuntimeRoot, "A stale socket entry is not reused",
                 "[transport][paths]") {
  makePrivateRuntimeDir(this->dir);
  const std::filesystem::path socketPath = this->dir / "vault.sock";
  close(bindSecureUnixSocket(socketPath));

  // Removing it is the operator's decision, not something a bind does quietly.
  CHECK_THROWS(bindSecureUnixSocket(socketPath));
  CHECK(std::filesystem::exists(socketPath));
}

TEST_CASE_METHOD(RuntimeRoot, "A failed bind leaves the filesystem alone",
                 "[transport][paths]") {
  makePrivateRuntimeDir(this->dir);

  SECTION("a regular file is preserved") {
    const std::filesystem::path file = this->dir / "keep";
    std::ofstream(file) << "must survive";

    CHECK_THROWS(bindSecureUnixSocket(file));

    CHECK(std::filesystem::file_size(file) == 12);
  }

  SECTION("a symlinked socket path is refused and left in place") {
    const std::filesystem::path file = this->dir / "keep";
    std::ofstream(file) << "must survive";
    std::filesystem::create_symlink(file, this->dir / "link.sock");

    CHECK_THROWS(bindSecureUnixSocket(this->dir / "link.sock"));

    CHECK(std::filesystem::is_symlink(this->dir / "link.sock"));
  }

  SECTION("a symlinked directory is refused") {
    const std::filesystem::path alias = this->root / "alias";
    std::filesystem::create_directory_symlink(this->dir, alias);

    CHECK_THROWS(makePrivateRuntimeDir(alias));
    CHECK_THROWS(bindSecureUnixSocket(alias / "bad.sock"));
  }
}

TEST_CASE_METHOD(RuntimeRoot, "A public runtime directory is refused",
                 "[transport][permissions]") {
  makePrivateRuntimeDir(this->dir);
  chmod(this->dir.c_str(), 0777);

  // Refuse instead of silently repairing: the operator should learn that
  // something widened the directory.
  CHECK_THROWS(makePrivateRuntimeDir(this->dir));
  CHECK(modeOf(this->dir) == 0777);
  CHECK_THROWS(makePrivateRuntimeDir(this->dir / "child"));

  chmod(this->dir.c_str(), 0700);
}

TEST_CASE_METHOD(RuntimeRoot, "Unsafe path shapes are rejected before bind",
                 "[transport][paths]") {
  makePrivateRuntimeDir(this->dir);

  CHECK_THROWS(makePrivateRuntimeDir("relative"));
  CHECK_THROWS(makePrivateRuntimeDir(this->dir / ".." / "escape"));
  // sun_path is a fixed-size field: an over-long name would be truncated into
  // a different path than the caller asked for.
  CHECK_THROWS(bindSecureUnixSocket(this->dir / std::string(200, 'x')));
  CHECK_THROWS(
      bindSecureUnixSocket(this->dir / std::string("bad\0suffix", 10)));
  CHECK_THROWS(peerUid(-1));
}
