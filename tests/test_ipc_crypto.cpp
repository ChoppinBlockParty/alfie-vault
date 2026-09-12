//===----------------------------------------------------------------------===//
/// \file
/// Exercise ipc crypto behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ipc_crypto.h"
#include <catch_amalgamated.hpp>
#include <string>
#include <type_traits>

using namespace alfie;

namespace {

/// Both sides of one request: two key pairs and the context they agree on.
struct IpcPeers {
  IpcKeyPair server = generateIpcKeypair();
  IpcKeyPair client = generateIpcKeypair();
  IpcRequestContext context{"one-time-token", "example.com", "fill_password"};

  SecureBuffer senderKey() const {
    return deriveIpcSessionKey(this->server.privateKey, this->client.publicKey,
                               this->context);
  }

  SecureBuffer receiverKey() const {
    return deriveIpcSessionKey(this->client.privateKey, this->server.publicKey,
                               this->context);
  }
};

} // namespace

TEST_CASE("IPC key pairs are move-only and X25519 sized", "[ipc][keys]") {
  STATIC_REQUIRE(!std::is_copy_constructible_v<IpcKeyPair>);
  STATIC_REQUIRE(!std::is_copy_assignable_v<IpcKeyPair>);

  const IpcPeers peers;
  CHECK(peers.server.publicKey.size() == 32);
  CHECK(peers.client.publicKey.size() == 32);
  CHECK(peers.server.privateKey.size() == 32);
  CHECK(peers.client.privateKey.size() == 32);
}

TEST_CASE("X25519 and HKDF agree on one session key", "[ipc][keys]") {
  const IpcPeers peers;

  const SecureBuffer serverKey = peers.senderKey();
  const SecureBuffer clientKey = peers.receiverKey();

  CHECK(serverKey.size() == 32);
  CHECK(serverKey.str() == clientKey.str());
}

TEST_CASE("An IPC frame decrypts exactly once", "[ipc][replay]") {
  const IpcPeers peers;
  const std::string plaintext = R"({"secret":"VERY-SECRET-IPC"})";
  SecureBuffer secret(plaintext);

  const IpcFrame frame =
      encryptIpcMessage(peers.senderKey(), peers.context, secret);

  SECTION("the secret does not appear in the ciphertext") {
    const std::string raw(frame.ciphertextAndTag.begin(),
                          frame.ciphertextAndTag.end());
    REQUIRE_THAT(raw, !Catch::Matchers::ContainsSubstring("VERY-SECRET-IPC"));
  }

  SECTION("the first decryption returns the plaintext and the second throws") {
    ReplayGuard guard;
    const SecureBuffer decrypted =
        decryptIpcMessage(peers.receiverKey(), peers.context, frame, guard);
    REQUIRE(decrypted.str() == plaintext);

    REQUIRE_THROWS_AS(
        decryptIpcMessage(peers.receiverKey(), peers.context, frame, guard),
        CryptoError);
  }

  SECTION("a fresh guard does not carry the earlier acceptance") {
    ReplayGuard first;
    ReplayGuard second;
    REQUIRE_NOTHROW(
        decryptIpcMessage(peers.receiverKey(), peers.context, frame, first));
    REQUIRE_NOTHROW(
        decryptIpcMessage(peers.receiverKey(), peers.context, frame, second));
  }
}

TEST_CASE("A frame is bound to its token, domain and action", "[ipc][aad]") {
  const IpcPeers peers;
  SecureBuffer secret("secret");
  const IpcFrame frame =
      encryptIpcMessage(peers.senderKey(), peers.context, secret);

  // Each field of the context is bound as HKDF info and as GCM AAD, so
  // changing any one of them must fail the frame rather than return plaintext
  // meant for a different request.
  const IpcRequestContext tampered = GENERATE_COPY(
      IpcRequestContext{"other-token", "example.com", "fill_password"},
      IpcRequestContext{"one-time-token", "evil.example", "fill_password"},
      IpcRequestContext{"one-time-token", "example.com", "fill_card"});

  CAPTURE(tampered.token, tampered.domain, tampered.action);
  ReplayGuard guard;
  REQUIRE_THROWS_AS(
      decryptIpcMessage(deriveIpcSessionKey(peers.client.privateKey,
                                            peers.server.publicKey, tampered),
                        tampered, frame, guard),
      CryptoError);
}
