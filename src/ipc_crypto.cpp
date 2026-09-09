#include "ipc_crypto.hpp"

#include <iomanip>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace alfie {
namespace {
constexpr size_t kX25519KeyLen = 32;
constexpr size_t kIpcKeyLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;

std::string hex_bytes(const std::vector<unsigned char>& bytes) {
    std::ostringstream out;
    for (auto b : bytes) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return out.str();
}

std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> out(n);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) throw CryptoError("RAND_bytes failed");
    return out;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& msg) {
    unsigned int len = 0;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), key.data(), key.size(), msg.data(), msg.size(), out.data(), &len);
    out.resize(len);
    return out;
}

SecureBuffer hkdf_sha256(const std::vector<unsigned char>& shared_secret,
                         const std::vector<unsigned char>& info) {
    const std::vector<unsigned char> salt = {'a','l','f','i','e','-','i','p','c','-','v','1'};
    auto prk = hmac_sha256(salt, shared_secret);
    std::vector<unsigned char> expand_input = info;
    expand_input.push_back(1);
    auto okm = hmac_sha256(prk, expand_input);
    okm.resize(kIpcKeyLen);
    OPENSSL_cleanse(prk.data(), prk.size());
    return SecureBuffer(std::move(okm));
}

std::vector<unsigned char> encrypt_gcm(const SecureBuffer& key,
                                       const std::vector<unsigned char>& nonce,
                                       const SecureBuffer& plaintext,
                                       const std::vector<unsigned char>& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> out(plaintext.size() + kTagLen);
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.bytes().data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.bytes().data(), plaintext.size()) == 1;
    int total = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, out.data() + plaintext.size()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw CryptoError("IPC AES-256-GCM encrypt failed");
    return out;
}

SecureBuffer decrypt_gcm(const SecureBuffer& key,
                         const std::vector<unsigned char>& nonce,
                         const std::vector<unsigned char>& ciphertext_and_tag,
                         const std::vector<unsigned char>& aad) {
    if (ciphertext_and_tag.size() < kTagLen) throw CryptoError("bad IPC ciphertext");
    const size_t ct_len = ciphertext_and_tag.size() - kTagLen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> plain(ct_len);
    int len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.bytes().data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext_and_tag.data(), ct_len) == 1;
    int total = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                                   const_cast<unsigned char*>(ciphertext_and_tag.data() + ct_len)) == 1 &&
              EVP_DecryptFinal_ex(ctx, plain.data() + total, &len) == 1;
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw CryptoError("IPC AES-256-GCM decrypt failed");
    plain.resize(total);
    return SecureBuffer(std::move(plain));
}
} // namespace

std::vector<unsigned char> IpcRequestContext::aad() const {
    std::string packed = "alfie-ipc-v1\0" + token + "\0" + domain + "\0" + action;
    return {packed.begin(), packed.end()};
}

bool ReplayGuard::accept(const std::string& token, const std::vector<unsigned char>& nonce) {
    std::string key = token + ":" + hex_bytes(nonce);
    return seen_.insert(key).second;
}

IpcKeyPair generate_ipc_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) throw CryptoError("EVP_PKEY_CTX_new_id failed");
    EVP_PKEY* pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1;
    EVP_PKEY_CTX_free(ctx);
    if (!ok || !pkey) throw CryptoError("X25519 keygen failed");

    std::vector<unsigned char> pub(kX25519KeyLen);
    std::vector<unsigned char> priv(kX25519KeyLen);
    size_t pub_len = pub.size(), priv_len = priv.size();
    ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) == 1 &&
         EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len) == 1;
    EVP_PKEY_free(pkey);
    if (!ok || pub_len != kX25519KeyLen || priv_len != kX25519KeyLen) throw CryptoError("X25519 raw key export failed");
    return {SecureBuffer(std::move(priv)), std::move(pub)};
}

SecureBuffer derive_ipc_session_key(const SecureBuffer& private_key,
                                    const std::vector<unsigned char>& peer_public_key,
                                    const IpcRequestContext& context) {
    if (private_key.size() != kX25519KeyLen || peer_public_key.size() != kX25519KeyLen) {
        throw CryptoError("bad X25519 key size");
    }
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                  private_key.bytes().data(), private_key.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                 peer_public_key.data(), peer_public_key.size());
    if (!priv || !peer) throw CryptoError("X25519 raw key import failed");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) throw CryptoError("EVP_PKEY_CTX_new failed");
    size_t secret_len = 0;
    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
              EVP_PKEY_derive(ctx, nullptr, &secret_len) == 1;
    std::vector<unsigned char> shared(secret_len);
    ok = ok && EVP_PKEY_derive(ctx, shared.data(), &secret_len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    if (!ok) throw CryptoError("X25519 derive failed");
    shared.resize(secret_len);
    auto key = hkdf_sha256(shared, context.aad());
    OPENSSL_cleanse(shared.data(), shared.size());
    return key;
}

IpcFrame encrypt_ipc_message(const SecureBuffer& session_key,
                             const IpcRequestContext& context,
                             const SecureBuffer& plaintext) {
    if (session_key.size() != kIpcKeyLen) throw CryptoError("bad IPC session key size");
    auto nonce = random_bytes(kNonceLen);
    auto ciphertext = encrypt_gcm(session_key, nonce, plaintext, context.aad());
    return {std::move(nonce), std::move(ciphertext)};
}

SecureBuffer decrypt_ipc_message(const SecureBuffer& session_key,
                                 const IpcRequestContext& context,
                                 const IpcFrame& frame,
                                 ReplayGuard& replay_guard) {
    if (session_key.size() != kIpcKeyLen) throw CryptoError("bad IPC session key size");
    if (frame.nonce.size() != kNonceLen) throw CryptoError("bad IPC nonce size");
    if (!replay_guard.accept(context.token, frame.nonce)) throw CryptoError("replayed IPC frame");
    return decrypt_gcm(session_key, frame.nonce, frame.ciphertext_and_tag, context.aad());
}

} // namespace alfie
