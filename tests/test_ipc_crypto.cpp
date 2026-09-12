//===----------------------------------------------------------------------===//
/// \file
/// Exercise ipc crypto behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ipc_crypto.h"
#include <cassert>
#include <iostream>
#include <string>
#include <type_traits>

using namespace alfie;

static void testKeypairsAreMoveOnlyAndPublicKeysAreX25519Size() {
  static_assert(!std::is_copy_constructible_v<IpcKeyPair>);
  static_assert(!std::is_copy_assignable_v<IpcKeyPair>);

  auto server = generateIpcKeypair();
  auto client = generateIpcKeypair();
  assert(server.publicKey.size() == 32);
  assert(client.publicKey.size() == 32);
  assert(server.privateKey.size() == 32);
  assert(client.privateKey.size() == 32);
}

static void testX25519HkdfSessionKeyMatchesOnBothSides() {
  auto server = generateIpcKeypair();
  auto client = generateIpcKeypair();
  IpcRequestContext ctx{"one-time-token", "example.com", "fill_password"};

  auto serverKey =
      deriveIpcSessionKey(server.privateKey, client.publicKey, ctx);
  auto clientKey =
      deriveIpcSessionKey(client.privateKey, server.publicKey, ctx);

  assert(serverKey.size() == 32);
  assert(serverKey.str() == clientKey.str());
}

static void testIpcEncryptsSecretAndDecryptsOnce() {
  auto server = generateIpcKeypair();
  auto client = generateIpcKeypair();
  IpcRequestContext ctx{"one-time-token", "example.com", "fill_password"};
  auto senderKey =
      deriveIpcSessionKey(server.privateKey, client.publicKey, ctx);
  auto receiverKey =
      deriveIpcSessionKey(client.privateKey, server.publicKey, ctx);
  SecureBuffer secret(R"({"secret":"VERY-SECRET-IPC"})");

  auto frame = encryptIpcMessage(senderKey, ctx, secret);
  std::string raw(frame.ciphertextAndTag.begin(), frame.ciphertextAndTag.end());
  assert(raw.find("VERY-SECRET-IPC") == std::string::npos);

  ReplayGuard guard;
  auto decrypted = decryptIpcMessage(receiverKey, ctx, frame, guard);
  assert(decrypted.str() == R"({"secret":"VERY-SECRET-IPC"})");

  bool replayRejected = false;
  try {
    (void)decryptIpcMessage(receiverKey, ctx, frame, guard);
  } catch (const CryptoError &) {
    replayRejected = true;
  }
  assert(replayRejected);
}

static void testIpcAadBindsTokenDomainAndAction() {
  auto server = generateIpcKeypair();
  auto client = generateIpcKeypair();
  IpcRequestContext ctx{"token-a", "example.com", "fill_password"};
  auto senderKey =
      deriveIpcSessionKey(server.privateKey, client.publicKey, ctx);
  auto receiverKey =
      deriveIpcSessionKey(client.privateKey, server.publicKey, ctx);
  SecureBuffer secret("secret");
  auto frame = encryptIpcMessage(senderKey, ctx, secret);

  ReplayGuard guard;
  bool failed = false;
  try {
    IpcRequestContext tampered{"token-a", "evil.example", "fill_password"};
    (void)decryptIpcMessage(receiverKey, tampered, frame, guard);
  } catch (const CryptoError &) {
    failed = true;
  }
  assert(failed);
}

int main() {
  testKeypairsAreMoveOnlyAndPublicKeysAreX25519Size();
  testX25519HkdfSessionKeyMatchesOnBothSides();
  testIpcEncryptsSecretAndDecryptsOnce();
  testIpcAadBindsTokenDomainAndAction();
  std::cout << "IPC crypto tests passed\n";
}
