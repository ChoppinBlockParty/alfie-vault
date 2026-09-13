//===----------------------------------------------------------------------===//
/// \file
/// Bind encrypted IPC envelopes to one authorized request.
//===----------------------------------------------------------------------===//

#include "ipc_crypto.h"
#include <algorithm>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>

using namespace alfie;

static constexpr size_t kX25519KeyLen = 32;
static constexpr size_t kIpcKeyLen = 32;
static constexpr size_t kNonceLen = 12;
static constexpr size_t kTagLen = 16;

static std::string hexBytes(const std::vector<unsigned char> &bytes) {
  std::ostringstream out;
  for (auto b : bytes)
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  return out.str();
}

static std::vector<unsigned char> randomBytes(size_t n) {
  std::vector<unsigned char> out(n);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
    throw CryptoError("RAND_bytes failed");
  return out;
}

static std::vector<unsigned char>
hmacSha256(const std::vector<unsigned char> &key,
           const std::vector<unsigned char> &msg) {
  unsigned int len = 0;
  std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
  HMAC(EVP_sha256(), key.data(), key.size(), msg.data(), msg.size(), out.data(),
       &len);
  out.resize(len);
  return out;
}

static SecureBuffer hkdfSha256(const std::vector<unsigned char> &sharedSecret,
                               const std::vector<unsigned char> &info) {
  const std::vector<unsigned char> salt = {'a', 'l', 'f', 'i', 'e', '-',
                                           'i', 'p', 'c', '-', 'v', '1'};
  auto prk = hmacSha256(salt, sharedSecret);
  std::vector<unsigned char> expandInput = info;
  expandInput.push_back(1);
  auto okm = hmacSha256(prk, expandInput);
  OPENSSL_cleanse(prk.data(), prk.size());
  SecureBuffer key(kIpcKeyLen);
  std::copy_n(okm.data(), kIpcKeyLen, key.data());
  OPENSSL_cleanse(okm.data(), okm.size());
  return key;
}

static std::vector<unsigned char>
encryptGcm(const SecureBuffer &key, const std::vector<unsigned char> &nonce,
           const SecureBuffer &plaintext,
           const std::vector<unsigned char> &aad) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> out(plaintext.size() + kTagLen);
  int len = 0;
  bool ok =
      EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) ==
          1 &&
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) ==
          1 &&
      EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
      EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(),
                        plaintext.size()) == 1;
  int total = len;
  ok = ok && EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                 out.data() + plaintext.size()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("IPC AES-256-GCM encrypt failed");
  return out;
}

static SecureBuffer
decryptGcm(const SecureBuffer &key, const std::vector<unsigned char> &nonce,
           const std::vector<unsigned char> &ciphertextAndTag,
           const std::vector<unsigned char> &aad) {
  if (ciphertextAndTag.size() < kTagLen)
    throw CryptoError("bad IPC ciphertext");
  const size_t ctLen = ciphertextAndTag.size() - kTagLen;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  SecureBuffer plain(ctLen);
  int len = 0;
  bool ok =
      EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) ==
          1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) ==
          1 &&
      EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
      EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertextAndTag.data(),
                        ctLen) == 1;
  int total = len;
  ok = ok &&
       EVP_CIPHER_CTX_ctrl(
           ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
           const_cast<unsigned char *>(ciphertextAndTag.data() + ctLen)) == 1 &&
       EVP_DecryptFinal_ex(ctx, plain.data() + total, &len) == 1;
  total += len;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("IPC AES-256-GCM decrypt failed");
  plain.truncate(static_cast<size_t>(total));
  return plain;
}

std::vector<unsigned char> IpcRequestContext::aad() const {
  // Real NUL separators: `"lit\0" + token` would decay to a C string and drop
  // them, letting different (token, domain, action) triples produce the same
  // AAD.
  std::string packed = "alfie-ipc-v1";
  for (const auto *field : {&this->token, &this->domain, &this->action}) {
    packed.push_back('\0');
    packed += *field;
  }
  return {packed.begin(), packed.end()};
}

bool ReplayGuard::accept(const std::string &token,
                         const std::vector<unsigned char> &nonce) {
  std::string key = token + ":" + hexBytes(nonce);
  return this->seen_.insert(key).second;
}

IpcKeyPair alfie::generateIpcKeypair() {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx)
    throw CryptoError("EVP_PKEY_CTX_new_id failed");
  EVP_PKEY *pkey = nullptr;
  bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1;
  EVP_PKEY_CTX_free(ctx);
  if (!ok || !pkey)
    throw CryptoError("X25519 keygen failed");

  std::vector<unsigned char> pub(kX25519KeyLen);
  SecureBuffer priv(kX25519KeyLen);
  size_t pubLen = pub.size(), privLen = priv.size();
  ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen) == 1 &&
       EVP_PKEY_get_raw_private_key(pkey, priv.data(), &privLen) == 1;
  EVP_PKEY_free(pkey);
  if (!ok || pubLen != kX25519KeyLen || privLen != kX25519KeyLen)
    throw CryptoError("X25519 raw key export failed");
  return {std::move(priv), std::move(pub)};
}

SecureBuffer
alfie::deriveIpcSessionKey(const SecureBuffer &privateKey,
                           const std::vector<unsigned char> &peerPublicKey,
                           const IpcRequestContext &context) {
  if (privateKey.size() != kX25519KeyLen ||
      peerPublicKey.size() != kX25519KeyLen) {
    throw CryptoError("bad X25519 key size");
  }
  EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size());
  EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peerPublicKey.data(), peerPublicKey.size());
  if (!priv || !peer)
    throw CryptoError("X25519 raw key import failed");
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
  if (!ctx)
    throw CryptoError("EVP_PKEY_CTX_new failed");
  size_t secretLen = 0;
  bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
            EVP_PKEY_derive(ctx, nullptr, &secretLen) == 1;
  std::vector<unsigned char> shared(secretLen);
  ok = ok && EVP_PKEY_derive(ctx, shared.data(), &secretLen) == 1;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  EVP_PKEY_free(priv);
  if (!ok)
    throw CryptoError("X25519 derive failed");
  shared.resize(secretLen);
  auto key = hkdfSha256(shared, context.aad());
  OPENSSL_cleanse(shared.data(), shared.size());
  return key;
}

IpcFrame alfie::encryptIpcMessage(const SecureBuffer &sessionKey,
                                  const IpcRequestContext &context,
                                  const SecureBuffer &plaintext) {
  if (sessionKey.size() != kIpcKeyLen)
    throw CryptoError("bad IPC session key size");
  auto nonce = randomBytes(kNonceLen);
  auto ciphertext = encryptGcm(sessionKey, nonce, plaintext, context.aad());
  return {std::move(nonce), std::move(ciphertext)};
}

SecureBuffer alfie::decryptIpcMessage(const SecureBuffer &sessionKey,
                                      const IpcRequestContext &context,
                                      const IpcFrame &frame,
                                      ReplayGuard &replayGuard) {
  if (sessionKey.size() != kIpcKeyLen)
    throw CryptoError("bad IPC session key size");
  if (frame.nonce.size() != kNonceLen)
    throw CryptoError("bad IPC nonce size");
  // Authenticate before claiming the nonce. Recording it first lets an
  // unauthenticated frame burn a nonce of its choosing: the forgery still
  // fails the tag check, but the genuine frame carrying that nonce is then
  // refused as a replay and the delivery is silently lost.
  SecureBuffer plaintext = decryptGcm(sessionKey, frame.nonce,
                                      frame.ciphertextAndTag, context.aad());
  if (!replayGuard.accept(context.token, frame.nonce))
    throw CryptoError("replayed IPC frame");
  return plaintext;
}
