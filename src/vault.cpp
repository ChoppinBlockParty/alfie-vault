#include "vault.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef __linux__
#include <sys/mman.h>
#endif

namespace alfie {
namespace {
constexpr const char* kMagic = "ALFIECHUNK1\n";
constexpr size_t kSaltLen = 16;
constexpr size_t kVaultSaltLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kDerivedLen = 64;

std::string hex(const unsigned char* data, size_t len) {
    std::ostringstream out;
    for (size_t i = 0; i < len; ++i) out << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return out.str();
}

std::vector<unsigned char> sha256_bytes(const std::string& s) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest.data());
    return digest;
}

unsigned char from_hex(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(10 + c - 'A');
    throw CryptoError("bad hex");
}

std::vector<unsigned char> unhex(const std::string& s) {
    if (s.size() % 2 != 0) throw CryptoError("bad hex length");
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back(static_cast<unsigned char>((from_hex(s[i]) << 4) | from_hex(s[i + 1])));
    }
    return out;
}

std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> out(n);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) throw CryptoError("RAND_bytes failed");
    return out;
}

void write_file(const std::filesystem::path& p, const std::vector<unsigned char>& data) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::vector<unsigned char> read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw CryptoError("record not found");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::vector<unsigned char> encrypt_gcm(const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& nonce,
                                       const std::vector<unsigned char>& plaintext,
                                       const std::vector<unsigned char>& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> ciphertext(plaintext.size() + kTagLen);
    int len = 0, total = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) == 1;
    total = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) == 1;
    total += len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, ciphertext.data() + plaintext.size()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw CryptoError("AES-256-GCM encrypt failed");
    ciphertext.resize(plaintext.size() + kTagLen);
    return ciphertext;
}

std::vector<unsigned char> decrypt_gcm(const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& nonce,
                                       const std::vector<unsigned char>& ciphertext_and_tag,
                                       const std::vector<unsigned char>& aad) {
    if (ciphertext_and_tag.size() < kTagLen) throw CryptoError("bad ciphertext");
    const size_t ct_len = ciphertext_and_tag.size() - kTagLen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> plaintext(ct_len);
    int len = 0, total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext_and_tag.data(), ct_len) == 1;
    total = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                                   const_cast<unsigned char*>(ciphertext_and_tag.data() + ct_len)) == 1 &&
              EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) == 1;
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw CryptoError("AES-256-GCM decrypt failed");
    plaintext.resize(total);
    return plaintext;
}
} // namespace

SecureBuffer::SecureBuffer(const std::string& s) : data_(s.begin(), s.end()) { lock_memory(); }
SecureBuffer::SecureBuffer(std::vector<unsigned char> bytes) : data_(std::move(bytes)) { lock_memory(); }
SecureBuffer::~SecureBuffer() { wipe(); }

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)), locked_(false) {
    other.locked_ = false;
    lock_memory();
}
SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) { wipe(); data_ = std::move(other.data_); other.locked_ = false; lock_memory(); }
    return *this;
}

std::string SecureBuffer::str() const { return {data_.begin(), data_.end()}; }

void SecureBuffer::lock_memory() {
#ifdef __linux__
    if (!data_.empty()) {
        if (mlock(data_.data(), data_.size()) == 0) locked_ = true;
        madvise(data_.data(), data_.size(), MADV_DONTDUMP);
    }
#endif
}

void SecureBuffer::unlock_memory() {
#ifdef __linux__
    if (locked_ && !data_.empty()) munlock(data_.data(), data_.size());
#endif
    locked_ = false;
}

void SecureBuffer::wipe() {
    if (!data_.empty()) OPENSSL_cleanse(data_.data(), data_.size());
    unlock_memory();
}

VaultKeys derive_keys(SecureBuffer& passphrase, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> out(kDerivedLen);
    int rc = argon2id_hash_raw(/*t_cost*/3, /*m_cost KiB*/65536, /*parallelism*/1,
                               passphrase.bytes().data(), passphrase.bytes().size(),
                               salt.data(), salt.size(), out.data(), out.size());
    passphrase.wipe();
    if (rc != ARGON2_OK) throw CryptoError(argon2_error_message(rc));
    SecureBuffer index(std::vector<unsigned char>(out.begin(), out.begin() + 32));
    SecureBuffer record(std::vector<unsigned char>(out.begin() + 32, out.end()));
    OPENSSL_cleanse(out.data(), out.size());
    return VaultKeys(std::move(index), std::move(record));
}

VaultKeys derive_keys(SecureBuffer& passphrase, const std::string& context) {
    auto salt = sha256_bytes("alfie-vault-argon2id:" + context);
    return derive_keys(passphrase, salt);
}

VaultKeys derive_keys(const std::string& passphrase, const std::string& context) {
    SecureBuffer locked_passphrase(passphrase);
    return derive_keys(locked_passphrase, context);
}

std::string normalize_domain(const std::string& input) {
    std::string s = input;
    auto scheme = s.find("://");
    if (scheme != std::string::npos) s = s.substr(scheme + 3);
    auto slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    auto colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    if (s.rfind("www.", 0) == 0) s = s.substr(4);
    while (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

std::string record_id(const SecureBuffer& index_key, const std::string& purpose,
                      const std::string& domain_or_url, const std::string& account) {
    std::string msg = purpose + "\0" + normalize_domain(domain_or_url) + "\0" + account;
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), index_key.bytes().data(), index_key.bytes().size(),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), mac, &len);
    std::string id = hex(mac, len);
    OPENSSL_cleanse(mac, sizeof(mac));
    return id;
}

ChunkVault::ChunkVault(std::filesystem::path root) : root_(std::move(root)) {}

std::vector<unsigned char> ChunkVault::load_or_create_salt() const {
    const auto meta_path = root_ / "vault.meta";
    if (std::filesystem::exists(meta_path)) {
        std::ifstream in(meta_path, std::ios::binary);
        std::string magic, salt_hex;
        std::getline(in, magic);
        std::getline(in, salt_hex);
        if (magic != "ALFIEVAULT1") throw CryptoError("bad vault metadata");
        auto salt = unhex(salt_hex);
        if (salt.size() != kVaultSaltLen) throw CryptoError("bad vault salt");
        return salt;
    }

    auto salt = random_bytes(kVaultSaltLen);
    std::filesystem::create_directories(root_);
    std::ofstream out(meta_path, std::ios::binary | std::ios::trunc);
    out << "ALFIEVAULT1\n" << hex(salt.data(), salt.size()) << "\n"
        << "argon2id m=65536,t=3,p=1\n";
    return salt;
}

std::filesystem::path ChunkVault::path_for_id(const std::string& id) const {
    return root_ / "records" / id.substr(0, 2) / id.substr(2, 2) / (id + ".enc");
}

std::filesystem::path ChunkVault::put(const std::string& purpose, const std::string& domain_or_url,
                                      const std::string& account, const std::string& passphrase,
                                      const std::string& plaintext_json) {
    SecureBuffer locked_passphrase(passphrase);
    VaultKeys keys = derive_keys(locked_passphrase, load_or_create_salt());
    std::string id = record_id(keys.index_key, purpose, domain_or_url, account);
    auto salt = random_bytes(kSaltLen); // stored for future format agility; record key currently derived from Argon2id master.
    auto nonce = random_bytes(kNonceLen);
    std::vector<unsigned char> aad(kMagic, kMagic + std::char_traits<char>::length(kMagic));
    SecureBuffer plain(plaintext_json);
    auto enc = encrypt_gcm(keys.record_key.bytes(), nonce, plain.bytes(), aad);
    std::vector<unsigned char> file;
    file.insert(file.end(), kMagic, kMagic + std::char_traits<char>::length(kMagic));
    file.insert(file.end(), salt.begin(), salt.end());
    file.insert(file.end(), nonce.begin(), nonce.end());
    file.insert(file.end(), enc.begin(), enc.end());
    auto path = path_for_id(id);
    write_file(path, file);
    return path;
}

std::string ChunkVault::get(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, const std::string& passphrase) {
    std::string value;
    use(purpose, domain_or_url, account, passphrase, [&](const SecureBuffer& secret) {
        value = secret.str(); // Compatibility path. Production should prefer use().
    });
    return value;
}

void ChunkVault::use(const std::string& purpose, const std::string& domain_or_url,
                     const std::string& account, const std::string& passphrase,
                     const std::function<void(const SecureBuffer&)>& callback) {
    SecureBuffer locked_passphrase(passphrase);
    VaultKeys keys = derive_keys(locked_passphrase, load_or_create_salt());
    std::string id = record_id(keys.index_key, purpose, domain_or_url, account);
    auto file = read_file(path_for_id(id));
    const size_t magic_len = std::char_traits<char>::length(kMagic);
    if (file.size() < magic_len + kSaltLen + kNonceLen + kTagLen) throw CryptoError("bad record");
    std::string magic(reinterpret_cast<const char*>(file.data()), magic_len);
    if (magic != kMagic) throw CryptoError("bad record magic");
    std::vector<unsigned char> nonce(file.begin() + magic_len + kSaltLen, file.begin() + magic_len + kSaltLen + kNonceLen);
    std::vector<unsigned char> enc(file.begin() + magic_len + kSaltLen + kNonceLen, file.end());
    std::vector<unsigned char> aad(kMagic, kMagic + magic_len);
    auto plain = decrypt_gcm(keys.record_key.bytes(), nonce, enc, aad);
    SecureBuffer out(std::move(plain));
    callback(out);
}

} // namespace alfie
