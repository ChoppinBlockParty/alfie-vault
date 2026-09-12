//===----------------------------------------------------------------------===//
/// \file
/// Bind encrypted IPC envelopes to one authorized request.
//===----------------------------------------------------------------------===//

#ifndef IPC_CRYPTO_H
#define IPC_CRYPTO_H

#include "vault.h"
#include <set>
#include <string>
#include <vector>

namespace alfie {

/// A compact encrypted IPC layer for vault -> browser-worker handoff.
/// Transport is still a Unix domain socket; this layer adds per-request crypto
/// so payloads are not plaintext even inside that socket.
struct IpcKeyPair {
  SecureBuffer PrivateKey;
  std::vector<unsigned char> PublicKey;
};

/// Carry the nonce and authenticated ciphertext; no plaintext is stored here.
struct IpcFrame {
  std::vector<unsigned char> Nonce;
  std::vector<unsigned char> CiphertextAndTag;
};

/// Bind an envelope to its one-time token, domain and authorized action.
struct IpcRequestContext {
  std::string Token;
  std::string Domain;
  std::string Action;

  /// Serialize the context with separators for HKDF and GCM authentication.
  std::vector<unsigned char> aad() const;
};

/// Reject token/nonce pairs already accepted during this guard's lifetime.
class ReplayGuard {
public:
  /// Record a new pair, returning false when the pair was already seen.
  bool accept(const std::string &Token,
              const std::vector<unsigned char> &Nonce);

private:
  std::set<std::string> Seen;
};

/// Generate an ephemeral X25519 key pair; private bytes use secure storage.
IpcKeyPair generateIpcKeypair();
/// Derive a context-bound key from X25519 and HKDF-SHA256.
SecureBuffer
deriveIpcSessionKey(const SecureBuffer &PrivateKey,
                    const std::vector<unsigned char> &PeerPublicKey,
                    const IpcRequestContext &Context);
/// Encrypt a payload with a fresh nonce and authenticated request context.
IpcFrame encryptIpcMessage(const SecureBuffer &SessionKey,
                           const IpcRequestContext &Context,
                           const SecureBuffer &Plaintext);
/// Authenticate and decrypt a frame, rejecting malformed or replayed messages.
SecureBuffer decryptIpcMessage(const SecureBuffer &SessionKey,
                               const IpcRequestContext &Context,
                               const IpcFrame &Frame, ReplayGuard &ReplayGuard);

} // namespace alfie

#endif // IPC_CRYPTO_H
