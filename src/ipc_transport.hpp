#pragma once

#include <sys/types.h>

#include <filesystem>

namespace alfie {

// Unix-domain socket transport guard for vault IPC. Crypto lives in
// ipc_crypto.hpp; this layer keeps the socket private to Alfie's Unix user.
// Requires an absolute path without symlinks and trusted ancestors; existing mode must be 0700.
std::filesystem::path make_private_runtime_dir(const std::filesystem::path& dir);
// Returns a nonblocking, close-on-exec descriptor owned by the caller. Never replaces a path.
// Caller closes the descriptor and explicitly removes its socket after stopping the listener.
int bind_secure_unix_socket(const std::filesystem::path& socket_path);
// Accepted descriptors are nonblocking and close-on-exec; mismatched peers are closed.
int accept_secure_unix_socket(int listener, uid_t expected_uid);
uid_t peer_uid(int connected_unix_socket_fd);

}  // namespace alfie
