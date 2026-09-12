//===----------------------------------------------------------------------===//
/// \file
/// Restrict Unix socket access to the expected local user.
//===----------------------------------------------------------------------===//

#ifndef IPC_TRANSPORT_H
#define IPC_TRANSPORT_H

#include <filesystem>
#include <sys/types.h>

namespace alfie {

/// Unix-domain socket transport guard for vault IPC. Crypto lives in
/// ipc_crypto.h; this layer keeps the socket private to Alfie's Unix user.
/// Requires an absolute path without symlinks and trusted ancestors; existing
/// mode must be 0700.
std::filesystem::path makePrivateRuntimeDir(const std::filesystem::path &Dir);
/// Returns a nonblocking, close-on-exec descriptor owned by the caller. Never
/// replaces a path. Caller closes the descriptor and explicitly removes its
/// socket after stopping the listener.
int bindSecureUnixSocket(const std::filesystem::path &SocketPath);
/// Accepted descriptors are nonblocking and close-on-exec; mismatched peers are
/// closed.
int acceptSecureUnixSocket(int Listener, uid_t ExpectedUid);
/// Query kernel credentials, rejecting descriptors that are not Unix streams.
uid_t peerUid(int ConnectedUnixSocketFd);

} // namespace alfie

#endif // IPC_TRANSPORT_H
