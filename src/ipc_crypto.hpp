#pragma once

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "vault.hpp"

namespace alfie {

// A compact encrypted IPC layer for vault -> browser-worker handoff.
// Transport is still a Unix domain socket; this layer adds per-request crypto
// so payloads are not plaintext even inside that socket.
struct IpcKeyPair {
  SecureBuffer private_key;
  std::vector<unsigned char> public_key;
};

struct IpcFrame {
  std::vector<unsigned char> nonce;
  std::vector<unsigned char> ciphertext_and_tag;
};

struct IpcRequestContext {
  std::string token;
  std::string domain;
  std::string action;

  std::vector<unsigned char> aad() const;
};

class ReplayGuard {
 public:
  bool accept(const std::string& token, const std::vector<unsigned char>& nonce);

 private:
  std::set<std::string> seen_;
};

IpcKeyPair generate_ipc_keypair();
SecureBuffer derive_ipc_session_key(const SecureBuffer& private_key,
                                    const std::vector<unsigned char>& peer_public_key,
                                    const IpcRequestContext& context);
IpcFrame encrypt_ipc_message(const SecureBuffer& session_key, const IpcRequestContext& context,
                             const SecureBuffer& plaintext);
SecureBuffer decrypt_ipc_message(const SecureBuffer& session_key, const IpcRequestContext& context,
                                 const IpcFrame& frame, ReplayGuard& replay_guard);

}  // namespace alfie
