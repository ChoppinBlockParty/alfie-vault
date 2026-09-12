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

static constexpr size_t X25519KeyLen = 32;
static constexpr size_t IpcKeyLen = 32;
static constexpr size_t NonceLen = 12;
static constexpr size_t TagLen = 16;

static std::string hexBytes(const std::vector<unsigned char> &Bytes) {
  std::ostringstream Out;
  for (auto B : Bytes)
    Out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(B);
  return Out.str();
}

static std::vector<unsigned char> randomBytes(size_t N) {
  std::vector<unsigned char> Out(N);
  if (RAND_bytes(Out.data(), static_cast<int>(Out.size())) != 1)
    throw CryptoError("RAND_bytes failed");
  return Out;
}

static std::vector<unsigned char>
hmacSha256(const std::vector<unsigned char> &Key,
           const std::vector<unsigned char> &Msg) {
  unsigned int Len = 0;
  std::vector<unsigned char> Out(EVP_MAX_MD_SIZE);
  HMAC(EVP_sha256(), Key.data(), Key.size(), Msg.data(), Msg.size(), Out.data(),
       &Len);
  Out.resize(Len);
  return Out;
}

static SecureBuffer hkdfSha256(const std::vector<unsigned char> &SharedSecret,
                               const std::vector<unsigned char> &Info) {
  const std::vector<unsigned char> Salt = {'a', 'l', 'f', 'i', 'e', '-',
                                           'i', 'p', 'c', '-', 'v', '1'};
  auto Prk = hmacSha256(Salt, SharedSecret);
  std::vector<unsigned char> ExpandInput = Info;
  ExpandInput.push_back(1);
  auto Okm = hmacSha256(Prk, ExpandInput);
  OPENSSL_cleanse(Prk.data(), Prk.size());
  SecureBuffer Key(IpcKeyLen);
  std::copy_n(Okm.data(), IpcKeyLen, Key.data());
  OPENSSL_cleanse(Okm.data(), Okm.size());
  return Key;
}

static std::vector<unsigned char>
encryptGcm(const SecureBuffer &Key, const std::vector<unsigned char> &Nonce,
           const SecureBuffer &Plaintext,
           const std::vector<unsigned char> &Aad) {
  EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
  if (!Ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> Out(Plaintext.size() + TagLen);
  int Len = 0;
  bool Ok =
      EVP_EncryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, Nonce.size(), nullptr) ==
          1 &&
      EVP_EncryptInit_ex(Ctx, nullptr, nullptr, Key.data(), Nonce.data()) ==
          1 &&
      EVP_EncryptUpdate(Ctx, nullptr, &Len, Aad.data(), Aad.size()) == 1 &&
      EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plaintext.data(),
                        Plaintext.size()) == 1;
  int Total = Len;
  Ok = Ok && EVP_EncryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
  Ok = Ok && EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, TagLen,
                                 Out.data() + Plaintext.size()) == 1;
  EVP_CIPHER_CTX_free(Ctx);
  if (!Ok)
    throw CryptoError("IPC AES-256-GCM encrypt failed");
  return Out;
}

static SecureBuffer
decryptGcm(const SecureBuffer &Key, const std::vector<unsigned char> &Nonce,
           const std::vector<unsigned char> &CiphertextAndTag,
           const std::vector<unsigned char> &Aad) {
  if (CiphertextAndTag.size() < TagLen)
    throw CryptoError("bad IPC ciphertext");
  const size_t CtLen = CiphertextAndTag.size() - TagLen;
  EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
  if (!Ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  SecureBuffer Plain(CtLen);
  int Len = 0;
  bool Ok =
      EVP_DecryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, Nonce.size(), nullptr) ==
          1 &&
      EVP_DecryptInit_ex(Ctx, nullptr, nullptr, Key.data(), Nonce.data()) ==
          1 &&
      EVP_DecryptUpdate(Ctx, nullptr, &Len, Aad.data(), Aad.size()) == 1 &&
      EVP_DecryptUpdate(Ctx, Plain.data(), &Len, CiphertextAndTag.data(),
                        CtLen) == 1;
  int Total = Len;
  Ok = Ok &&
       EVP_CIPHER_CTX_ctrl(
           Ctx, EVP_CTRL_GCM_SET_TAG, TagLen,
           const_cast<unsigned char *>(CiphertextAndTag.data() + CtLen)) == 1 &&
       EVP_DecryptFinal_ex(Ctx, Plain.data() + Total, &Len) == 1;
  Total += Len;
  EVP_CIPHER_CTX_free(Ctx);
  if (!Ok)
    throw CryptoError("IPC AES-256-GCM decrypt failed");
  Plain.truncate(static_cast<size_t>(Total));
  return Plain;
}

std::vector<unsigned char> IpcRequestContext::aad() const {
  // Real NUL separators: `"lit\0" + token` would decay to a C string and drop
  // them, letting different (token, domain, action) triples produce the same
  // AAD.
  std::string Packed = "alfie-ipc-v1";
  for (const auto *Field : {&this->Token, &this->Domain, &this->Action}) {
    Packed.push_back('\0');
    Packed += *Field;
  }
  return {Packed.begin(), Packed.end()};
}

bool ReplayGuard::accept(const std::string &Token,
                         const std::vector<unsigned char> &Nonce) {
  std::string Key = Token + ":" + hexBytes(Nonce);
  return this->Seen.insert(Key).second;
}

IpcKeyPair alfie::generateIpcKeypair() {
  EVP_PKEY_CTX *Ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!Ctx)
    throw CryptoError("EVP_PKEY_CTX_new_id failed");
  EVP_PKEY *Pkey = nullptr;
  bool Ok = EVP_PKEY_keygen_init(Ctx) == 1 && EVP_PKEY_keygen(Ctx, &Pkey) == 1;
  EVP_PKEY_CTX_free(Ctx);
  if (!Ok || !Pkey)
    throw CryptoError("X25519 keygen failed");

  std::vector<unsigned char> Pub(X25519KeyLen);
  SecureBuffer Priv(X25519KeyLen);
  size_t PubLen = Pub.size(), PrivLen = Priv.size();
  Ok = EVP_PKEY_get_raw_public_key(Pkey, Pub.data(), &PubLen) == 1 &&
       EVP_PKEY_get_raw_private_key(Pkey, Priv.data(), &PrivLen) == 1;
  EVP_PKEY_free(Pkey);
  if (!Ok || PubLen != X25519KeyLen || PrivLen != X25519KeyLen)
    throw CryptoError("X25519 raw key export failed");
  return {std::move(Priv), std::move(Pub)};
}

SecureBuffer
alfie::deriveIpcSessionKey(const SecureBuffer &PrivateKey,
                           const std::vector<unsigned char> &PeerPublicKey,
                           const IpcRequestContext &Context) {
  if (PrivateKey.size() != X25519KeyLen ||
      PeerPublicKey.size() != X25519KeyLen) {
    throw CryptoError("bad X25519 key size");
  }
  EVP_PKEY *Priv = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, PrivateKey.data(), PrivateKey.size());
  EVP_PKEY *Peer = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, PeerPublicKey.data(), PeerPublicKey.size());
  if (!Priv || !Peer)
    throw CryptoError("X25519 raw key import failed");
  EVP_PKEY_CTX *Ctx = EVP_PKEY_CTX_new(Priv, nullptr);
  if (!Ctx)
    throw CryptoError("EVP_PKEY_CTX_new failed");
  size_t SecretLen = 0;
  bool Ok = EVP_PKEY_derive_init(Ctx) == 1 &&
            EVP_PKEY_derive_set_peer(Ctx, Peer) == 1 &&
            EVP_PKEY_derive(Ctx, nullptr, &SecretLen) == 1;
  std::vector<unsigned char> Shared(SecretLen);
  Ok = Ok && EVP_PKEY_derive(Ctx, Shared.data(), &SecretLen) == 1;
  EVP_PKEY_CTX_free(Ctx);
  EVP_PKEY_free(Peer);
  EVP_PKEY_free(Priv);
  if (!Ok)
    throw CryptoError("X25519 derive failed");
  Shared.resize(SecretLen);
  auto Key = hkdfSha256(Shared, Context.aad());
  OPENSSL_cleanse(Shared.data(), Shared.size());
  return Key;
}

IpcFrame alfie::encryptIpcMessage(const SecureBuffer &SessionKey,
                                  const IpcRequestContext &Context,
                                  const SecureBuffer &Plaintext) {
  if (SessionKey.size() != IpcKeyLen)
    throw CryptoError("bad IPC session key size");
  auto Nonce = randomBytes(NonceLen);
  auto Ciphertext = encryptGcm(SessionKey, Nonce, Plaintext, Context.aad());
  return {std::move(Nonce), std::move(Ciphertext)};
}

SecureBuffer alfie::decryptIpcMessage(const SecureBuffer &SessionKey,
                                      const IpcRequestContext &Context,
                                      const IpcFrame &Frame,
                                      ReplayGuard &ReplayGuard) {
  if (SessionKey.size() != IpcKeyLen)
    throw CryptoError("bad IPC session key size");
  if (Frame.Nonce.size() != NonceLen)
    throw CryptoError("bad IPC nonce size");
  if (!ReplayGuard.accept(Context.Token, Frame.Nonce))
    throw CryptoError("replayed IPC frame");
  return decryptGcm(SessionKey, Frame.Nonce, Frame.CiphertextAndTag,
                    Context.aad());
}
