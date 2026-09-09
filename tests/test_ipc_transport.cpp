#include "../src/ipc_transport.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace alfie;

static mode_t mode_of(const std::filesystem::path& p) {
    struct stat st{};
    assert(stat(p.c_str(), &st) == 0);
    return st.st_mode & 0777;
}

static void test_runtime_dir_is_private() {
    auto dir = std::filesystem::temp_directory_path() / "alfie_ipc_runtime_test";
    std::filesystem::remove_all(dir);
    make_private_runtime_dir(dir);
    assert(std::filesystem::is_directory(dir));
    assert(mode_of(dir) == 0700);
    std::filesystem::remove_all(dir);
}

static void test_bound_socket_is_user_private() {
    auto dir = std::filesystem::temp_directory_path() / "alfie_ipc_socket_test";
    std::filesystem::remove_all(dir);
    make_private_runtime_dir(dir);
    auto socket_path = dir / "vault.sock";
    int fd = bind_secure_unix_socket(socket_path);
    assert(fd >= 0);
    assert(std::filesystem::exists(socket_path));
    assert(mode_of(socket_path) == 0600);
    close(fd);
    std::filesystem::remove_all(dir);
}

static void test_peer_uid_reads_unix_peer_credentials() {
    int fds[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    assert(peer_uid(fds[0]) == getuid());
    close(fds[0]);
    close(fds[1]);
}

int main() {
    test_runtime_dir_is_private();
    test_bound_socket_is_user_private();
    test_peer_uid_reads_unix_peer_credentials();
    std::cout << "IPC transport tests passed\n";
}
