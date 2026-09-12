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

  auto Server = generateIpcKeypair();
  auto Client = generateIpcKeypair();
  assert(Server.PublicKey.size() == 32);
  assert(Client.PublicKey.size() == 32);
  assert(Server.PrivateKey.size() == 32);
  assert(Client.PrivateKey.size() == 32);
}

static void testX25519HkdfSessionKeyMatchesOnBothSides() {
  auto Server = generateIpcKeypair();
  auto Client = generateIpcKeypair();
  IpcRequestContext Ctx{"one-time-token", "example.com", "fill_password"};

  auto ServerKey =
      deriveIpcSessionKey(Server.PrivateKey, Client.PublicKey, Ctx);
  auto ClientKey =
      deriveIpcSessionKey(Client.PrivateKey, Server.PublicKey, Ctx);

  assert(ServerKey.size() == 32);
  assert(ServerKey.str() == ClientKey.str());
}

static void testIpcEncryptsSecretAndDecryptsOnce() {
  auto Server = generateIpcKeypair();
  auto Client = generateIpcKeypair();
  IpcRequestContext Ctx{"one-time-token", "example.com", "fill_password"};
  auto SenderKey =
      deriveIpcSessionKey(Server.PrivateKey, Client.PublicKey, Ctx);
  auto ReceiverKey =
      deriveIpcSessionKey(Client.PrivateKey, Server.PublicKey, Ctx);
  SecureBuffer Secret(R"({"secret":"VERY-SECRET-IPC"})");

  auto Frame = encryptIpcMessage(SenderKey, Ctx, Secret);
  std::string Raw(Frame.CiphertextAndTag.begin(), Frame.CiphertextAndTag.end());
  assert(Raw.find("VERY-SECRET-IPC") == std::string::npos);

  ReplayGuard Guard;
  auto Decrypted = decryptIpcMessage(ReceiverKey, Ctx, Frame, Guard);
  assert(Decrypted.str() == R"({"secret":"VERY-SECRET-IPC"})");

  bool ReplayRejected = false;
  try {
    (void)decryptIpcMessage(ReceiverKey, Ctx, Frame, Guard);
  } catch (const CryptoError &) {
    ReplayRejected = true;
  }
  assert(ReplayRejected);
}

static void testIpcAadBindsTokenDomainAndAction() {
  auto Server = generateIpcKeypair();
  auto Client = generateIpcKeypair();
  IpcRequestContext Ctx{"token-a", "example.com", "fill_password"};
  auto SenderKey =
      deriveIpcSessionKey(Server.PrivateKey, Client.PublicKey, Ctx);
  auto ReceiverKey =
      deriveIpcSessionKey(Client.PrivateKey, Server.PublicKey, Ctx);
  SecureBuffer Secret("secret");
  auto Frame = encryptIpcMessage(SenderKey, Ctx, Secret);

  ReplayGuard Guard;
  bool Failed = false;
  try {
    IpcRequestContext Tampered{"token-a", "evil.example", "fill_password"};
    (void)decryptIpcMessage(ReceiverKey, Tampered, Frame, Guard);
  } catch (const CryptoError &) {
    Failed = true;
  }
  assert(Failed);
}

int main() {
  testKeypairsAreMoveOnlyAndPublicKeysAreX25519Size();
  testX25519HkdfSessionKeyMatchesOnBothSides();
  testIpcEncryptsSecretAndDecryptsOnce();
  testIpcAadBindsTokenDomainAndAction();
  std::cout << "IPC crypto tests passed\n";
}
