#pragma once

#include <sys/types.h>

#include <filesystem>

namespace alfie {

// Unix-domain socket transport guard for vault IPC. Crypto lives in
// ipc_crypto.hpp; this layer keeps the socket private to Alfie's Unix user.
std::filesystem::path make_private_runtime_dir(const std::filesystem::path& dir);
int bind_secure_unix_socket(const std::filesystem::path& socket_path);
uid_t peer_uid(int connected_unix_socket_fd);

}  // namespace alfie
