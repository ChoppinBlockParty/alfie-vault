#include "vault.hpp"

#include <argon2.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

namespace alfie {
namespace {
// Record format. V1 authenticated only the magic, so the reserved salt field and the record's
// own identity were malleable: an attacker with write access to the vault directory could swap
// one record file for another and the vault would happily decrypt it under the wrong domain.
// V2 binds magic + record id + salt into the GCM AAD. V1 records stay readable so an existing
// vault keeps working; every write produces V2.
constexpr const char* kMagicV1 = "ALFIECHUNK1\n";
constexpr const char* kMagicV2 = "ALFIECHUNK2\n";
constexpr size_t kMagicLen = 12;
constexpr size_t kSaltLen = 16;
constexpr size_t kVaultSaltLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kDerivedLen = 64;
constexpr size_t kSubKeyLen = 32;

std::string hex(const unsigned char* data, size_t len) {
  std::ostringstream out;
  for (size_t i = 0; i < len; ++i)
    out << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  return out.str();
}

std::vector<unsigned char> sha256_bytes(const std::string& s) {
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest.data());
  return digest;
}

unsigned char from_hex(char c) {
  if (c >= '0' && c <= '9')
    return static_cast<unsigned char>(c - '0');
  if (c >= 'a' && c <= 'f')
    return static_cast<unsigned char>(10 + c - 'a');
  if (c >= 'A' && c <= 'F')
    return static_cast<unsigned char>(10 + c - 'A');
  throw CryptoError("bad hex");
}

std::vector<unsigned char> unhex(const std::string& s) {
  if (s.size() % 2 != 0)
    throw CryptoError("bad hex length");
  std::vector<unsigned char> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    out.push_back(static_cast<unsigned char>((from_hex(s[i]) << 4) | from_hex(s[i + 1])));
  }
  return out;
}

std::vector<unsigned char> random_bytes(size_t n) {
  std::vector<unsigned char> out(n);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
    throw CryptoError("RAND_bytes failed");
  return out;
}

// Joins fields with a real NUL separator. Writing `a + "\0" + b` looks like this but is not:
// the literal decays to a C string, strlen() stops at the NUL, and the separator vanishes --
// which would let ("acc", "ountX") and ("account", "X") hash to the same record id.
std::string nul_join(std::initializer_list<std::string> fields) {
  std::string out;
  bool first = true;
  for (const auto& field : fields) {
    if (!first)
      out.push_back('\0');
    out += field;
    first = false;
  }
  return out;
}

void write_file(const std::filesystem::path& p, const std::vector<unsigned char>& data) {
  std::filesystem::create_directories(p.parent_path());
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::vector<unsigned char> read_file(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in)
    throw CryptoError("record not found");
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Ciphertext is not secret, so it stays on the normal heap; the plaintext side is always
// addressed as raw bytes so callers can keep it in secure memory.
std::vector<unsigned char> encrypt_gcm(const unsigned char* key, const unsigned char* plaintext,
                                       size_t plaintext_len,
                                       const std::vector<unsigned char>& nonce,
                                       const std::vector<unsigned char>& aad) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> ciphertext(plaintext_len + kTagLen);
  int len = 0;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                                nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
  if (ok && !aad.empty())
    ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
  int total = 0;
  if (ok && plaintext_len > 0) {
    ok = EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext,
                           static_cast<int>(plaintext_len)) == 1;
    total = len;
  }
  ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                 ciphertext.data() + plaintext_len) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("AES-256-GCM encrypt failed");
  return ciphertext;
}

// Decrypts straight into secure memory: the plaintext never exists on the normal heap.
SecureBuffer decrypt_gcm(const unsigned char* key,
                         const std::vector<unsigned char>& ciphertext_and_tag,
                         const std::vector<unsigned char>& nonce,
                         const std::vector<unsigned char>& aad) {
  if (ciphertext_and_tag.size() < kTagLen)
    throw CryptoError("bad ciphertext");
  const size_t ct_len = ciphertext_and_tag.size() - kTagLen;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  SecureBuffer plaintext(ct_len);
  int len = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                                nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
  if (ok && !aad.empty())
    ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
  int total = 0;
  if (ok && ct_len > 0) {
    ok = EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext_and_tag.data(),
                           static_cast<int>(ct_len)) == 1;
    total = len;
  }
  ok = ok &&
       EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                           const_cast<unsigned char*>(ciphertext_and_tag.data() + ct_len)) == 1 &&
       EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) == 1;
  total += len;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("AES-256-GCM decrypt failed");
  plaintext.truncate(static_cast<size_t>(total));
  return plaintext;
}
}  // namespace

SecureBuffer::SecureBuffer(size_t size) : data_(size, 0) {}
SecureBuffer::SecureBuffer(const std::string& s) : data_(s.begin(), s.end()) {}
SecureBuffer::SecureBuffer(SecureBytes bytes) : data_(std::move(bytes)) {}

SecureBuffer::SecureBuffer(std::vector<unsigned char> bytes) : data_(bytes.begin(), bytes.end()) {
  if (!bytes.empty())
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

SecureBuffer::~SecureBuffer() {
  wipe();
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    wipe();
    data_ = std::move(other.data_);
  }
  return *this;
}

std::string SecureBuffer::str() const {
  return {data_.begin(), data_.end()};
}

void SecureBuffer::truncate(size_t size) {
  if (size >= data_.size())
    return;
  OPENSSL_cleanse(data_.data() + size, data_.size() - size);
  data_.resize(size);  // Shrinking never reallocates, so no copy is left behind.
}

void SecureBuffer::wipe() {
  if (!data_.empty())
    OPENSSL_cleanse(data_.data(), data_.size());
}

VaultKeys derive_keys(SecureBuffer& passphrase, const std::vector<unsigned char>& salt,
                      const Argon2Params& params) {
  SecureBuffer out(kDerivedLen);
  int rc =
      argon2id_hash_raw(params.t_cost, params.m_cost_kib, params.parallelism, passphrase.data(),
                        passphrase.size(), salt.data(), salt.size(), out.data(), out.size());
  passphrase.wipe();
  if (rc != ARGON2_OK)
    throw CryptoError(argon2_error_message(rc));
  SecureBuffer index(kSubKeyLen);
  SecureBuffer record(kSubKeyLen);
  std::copy_n(out.data(), kSubKeyLen, index.data());
  std::copy_n(out.data() + kSubKeyLen, kSubKeyLen, record.data());
  return VaultKeys(std::move(index), std::move(record));
}

VaultKeys derive_keys(SecureBuffer& passphrase, const std::string& context) {
  auto salt = sha256_bytes("alfie-vault-argon2id:" + context);
  return derive_keys(passphrase, salt);
}

std::string normalize_domain(const std::string& input) {
  std::string s = input;
  auto scheme = s.find("://");
  if (scheme != std::string::npos)
    s = s.substr(scheme + 3);
  auto slash = s.find('/');
  if (slash != std::string::npos)
    s = s.substr(0, slash);
  auto colon = s.find(':');
  if (colon != std::string::npos)
    s = s.substr(0, colon);
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  if (s.rfind("www.", 0) == 0)
    s = s.substr(4);
  while (!s.empty() && s.back() == '.')
    s.pop_back();
  return s;
}

std::string record_id(const SecureBuffer& index_key, const std::string& purpose,
                      const std::string& domain_or_url, const std::string& account) {
  const std::string msg = nul_join({purpose, normalize_domain(domain_or_url), account});
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), index_key.data(), static_cast<int>(index_key.size()),
       reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), mac, &len);
  std::string id = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return id;
}

namespace {

constexpr const char* kMetaV1 = "ALFIEVAULT1";
constexpr const char* kMetaV2 = "ALFIEVAULT2";
constexpr const char* kPasswordVerifierLabel = "alfie-vault-password-verifier";
constexpr const char* kLoginVerifierLabel = "alfie-vault-login:";

struct VaultMeta {
  std::vector<unsigned char> salt;
  Argon2Params params;
  bool has_credentials = false;
  std::string login_verifier;
  std::string password_verifier;
};

// Parses "argon2id m=65536,t=3,p=1". Anything unrecognised leaves the default in place, so a
// malformed line cannot silently weaken the cost below what this build would have used.
Argon2Params parse_argon2_params(const std::string& line) {
  Argon2Params params;
  if (line.rfind("argon2id ", 0) != 0)
    return params;
  std::istringstream fields(line.substr(9));
  std::string field;
  while (std::getline(fields, field, ',')) {
    const auto eq = field.find('=');
    if (eq == std::string::npos)
      continue;
    const auto key = field.substr(0, eq);
    unsigned long value = 0;
    try {
      value = std::stoul(field.substr(eq + 1));
    } catch (const std::exception&) {
      continue;
    }
    if (value == 0)
      continue;
    if (key == "m")
      params.m_cost_kib = static_cast<uint32_t>(value);
    else if (key == "t")
      params.t_cost = static_cast<uint32_t>(value);
    else if (key == "p")
      params.parallelism = static_cast<uint32_t>(value);
  }
  return params;
}

std::string hmac_hex(const SecureBuffer& key, const std::string& message) {
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(message.data()), message.size(), mac, &len);
  std::string out = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return out;
}

bool constant_time_equals(const std::string& a, const std::string& b) {
  if (a.size() != b.size())
    return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::filesystem::path meta_path_for(const std::filesystem::path& root) {
  return root / "vault.meta";
}

VaultMeta read_meta(const std::filesystem::path& root) {
  const auto meta_path = meta_path_for(root);
  if (!std::filesystem::exists(meta_path))
    throw CryptoError("vault is not initialized");

  std::ifstream in(meta_path, std::ios::binary);
  std::string magic, salt_hex, costs;
  std::getline(in, magic);
  std::getline(in, salt_hex);
  std::getline(in, costs);
  if (magic != kMetaV1 && magic != kMetaV2)
    throw CryptoError("bad vault metadata");

  VaultMeta meta;
  meta.params = parse_argon2_params(costs);
  meta.salt = unhex(salt_hex);
  if (meta.salt.size() != kVaultSaltLen)
    throw CryptoError("bad vault salt");
  if (magic == kMetaV1)
    return meta;

  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const auto space = line.find(' ');
    if (space == std::string::npos)
      continue;
    const auto key = line.substr(0, space);
    const auto value = line.substr(space + 1);
    if (key == "login_verifier")
      meta.login_verifier = value;
    else if (key == "password_verifier")
      meta.password_verifier = value;
  }
  if (meta.login_verifier.empty() || meta.password_verifier.empty())
    throw CryptoError("bad vault metadata: missing credential verifiers");
  meta.has_credentials = true;
  return meta;
}

// Reproduces the pre-fix record id, where `purpose + "\0" + domain + "\0" + account` silently
// dropped both separators. Kept only so records written before the fix can still be found.
std::string legacy_record_id(const SecureBuffer& index_key, const std::string& purpose,
                             const std::string& domain_or_url, const std::string& account) {
  const std::string msg = purpose + normalize_domain(domain_or_url) + account;
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), index_key.data(), static_cast<int>(index_key.size()),
       reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), mac, &len);
  std::string id = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return id;
}

// V2 AAD: magic || record id || reserved salt. Binding the id stops record files being swapped
// between records; binding the salt stops that reserved field being tampered with before a
// future format starts deriving keys from it.
std::vector<unsigned char> record_aad(const char* magic, const std::string& id,
                                      const unsigned char* salt, size_t salt_len) {
  std::vector<unsigned char> aad(magic, magic + kMagicLen);
  if (magic == std::string(kMagicV1))
    return aad;  // V1 authenticated the magic only.
  aad.insert(aad.end(), id.begin(), id.end());
  aad.insert(aad.end(), salt, salt + salt_len);
  return aad;
}

std::filesystem::path path_for_id(const std::filesystem::path& root, const std::string& id) {
  return root / "records" / id.substr(0, 2) / id.substr(2, 2) / (id + ".enc");
}

}  // namespace

bool vault_initialized(const std::filesystem::path& root) {
  return std::filesystem::exists(meta_path_for(root));
}

bool vault_has_credentials(const std::filesystem::path& root) {
  if (!vault_initialized(root))
    return false;
  return read_meta(root).has_credentials;
}

void init_vault(const std::filesystem::path& root, const std::string& login,
                SecureBuffer& passphrase) {
  if (login.empty())
    throw CryptoError("login must not be empty");
  if (passphrase.empty())
    throw CryptoError("master password must not be empty");
  if (vault_initialized(root))
    throw CryptoError("vault already initialized");

  auto salt = random_bytes(kVaultSaltLen);
  const Argon2Params params;
  VaultKeys keys = derive_keys(passphrase, salt, params);
  const auto password_verifier = hmac_hex(keys.index_key, kPasswordVerifierLabel);
  const auto login_verifier = hmac_hex(keys.index_key, kLoginVerifierLabel + login);

  std::filesystem::create_directories(root);
  const auto meta_path = meta_path_for(root);
  std::ofstream out(meta_path, std::ios::binary | std::ios::trunc);
  if (!out)
    throw CryptoError("cannot write vault metadata");
  out << kMetaV2 << "\n"
      << hex(salt.data(), salt.size()) << "\n"
      << "argon2id m=" << params.m_cost_kib << ",t=" << params.t_cost << ",p=" << params.parallelism
      << "\n"
      << "login_verifier " << login_verifier << "\n"
      << "password_verifier " << password_verifier << "\n";
  out.flush();
  if (!out)
    throw CryptoError("cannot write vault metadata");
  std::filesystem::permissions(
      meta_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
}

bool verify_credentials(const std::filesystem::path& root, const std::string& login,
                        SecureBuffer& passphrase) {
  const auto meta = read_meta(root);
  if (!meta.has_credentials) {
    passphrase.wipe();
    return false;
  }
  VaultKeys keys = derive_keys(passphrase, meta.salt, meta.params);
  const bool password_ok = constant_time_equals(hmac_hex(keys.index_key, kPasswordVerifierLabel),
                                                meta.password_verifier);
  const bool login_ok = constant_time_equals(hmac_hex(keys.index_key, kLoginVerifierLabel + login),
                                             meta.login_verifier);
  return password_ok && login_ok;
}

VaultSession VaultSession::open(const std::filesystem::path& root, const std::string& login,
                                SecureBuffer& passphrase) {
  const auto meta = read_meta(root);
  VaultKeys keys = derive_keys(passphrase, meta.salt, meta.params);
  if (!meta.has_credentials)
    throw CryptoError("vault has no credential verifiers");
  const bool password_ok = constant_time_equals(hmac_hex(keys.index_key, kPasswordVerifierLabel),
                                                meta.password_verifier);
  const bool login_ok = constant_time_equals(hmac_hex(keys.index_key, kLoginVerifierLabel + login),
                                             meta.login_verifier);
  if (!password_ok || !login_ok)
    throw CryptoError("bad login or master password");
  return VaultSession(root, std::move(keys));
}

VaultSession VaultSession::open_with_password(const std::filesystem::path& root,
                                              SecureBuffer& passphrase) {
  const auto meta = read_meta(root);
  VaultKeys keys = derive_keys(passphrase, meta.salt, meta.params);
  // Without this, a wrong master password derives a different index key, computes a record id
  // that happens to address nothing, and surfaces as "record not found" -- exactly the
  // confusion the stored verifiers exist to remove. Legacy V1 vaults carry no verifiers.
  if (meta.has_credentials &&
      !constant_time_equals(hmac_hex(keys.index_key, kPasswordVerifierLabel),
                            meta.password_verifier)) {
    throw CryptoError("bad master password");
  }
  return VaultSession(root, std::move(keys));
}

std::filesystem::path VaultSession::put(const std::string& purpose,
                                        const std::string& domain_or_url,
                                        const std::string& account, const SecureBuffer& plaintext) {
  const std::string id = record_id(keys_.index_key, purpose, domain_or_url, account);
  auto salt = random_bytes(kSaltLen);  // Reserved for future format agility; authenticated by
                                       // the V2 AAD so it cannot be altered in place.
  auto nonce = random_bytes(kNonceLen);
  const auto aad = record_aad(kMagicV2, id, salt.data(), salt.size());
  auto enc = encrypt_gcm(keys_.record_key.data(), plaintext.data(), plaintext.size(), nonce, aad);

  std::vector<unsigned char> file;
  file.reserve(kMagicLen + salt.size() + nonce.size() + enc.size());
  file.insert(file.end(), kMagicV2, kMagicV2 + kMagicLen);
  file.insert(file.end(), salt.begin(), salt.end());
  file.insert(file.end(), nonce.begin(), nonce.end());
  file.insert(file.end(), enc.begin(), enc.end());
  auto path = path_for_id(root_, id);
  write_file(path, file);

  // Drop any pre-fix copy of the same record, so a stale ciphertext of an old secret is not
  // left behind in the vault directory.
  const auto legacy =
      path_for_id(root_, legacy_record_id(keys_.index_key, purpose, domain_or_url, account));
  if (legacy != path) {
    std::error_code ec;
    std::filesystem::remove(legacy, ec);
  }
  return path;
}

void VaultSession::use(const std::string& purpose, const std::string& domain_or_url,
                       const std::string& account,
                       const std::function<void(const SecureBuffer&)>& callback) {
  std::string id = record_id(keys_.index_key, purpose, domain_or_url, account);
  auto path = path_for_id(root_, id);
  if (!std::filesystem::exists(path)) {
    // Fall back to the pre-fix id so vaults written before the separator fix still resolve.
    const std::string legacy_id =
        legacy_record_id(keys_.index_key, purpose, domain_or_url, account);
    const auto legacy_path = path_for_id(root_, legacy_id);
    if (!std::filesystem::exists(legacy_path))
      throw CryptoError("record not found");
    id = legacy_id;
    path = legacy_path;
  }

  auto file = read_file(path);
  if (file.size() < kMagicLen + kSaltLen + kNonceLen + kTagLen)
    throw CryptoError("bad record");

  const char* magic = nullptr;
  if (std::memcmp(file.data(), kMagicV2, kMagicLen) == 0)
    magic = kMagicV2;
  else if (std::memcmp(file.data(), kMagicV1, kMagicLen) == 0)
    magic = kMagicV1;
  else
    throw CryptoError("bad record magic");

  const unsigned char* salt = file.data() + kMagicLen;
  std::vector<unsigned char> nonce(file.begin() + kMagicLen + kSaltLen,
                                   file.begin() + kMagicLen + kSaltLen + kNonceLen);
  std::vector<unsigned char> enc(file.begin() + kMagicLen + kSaltLen + kNonceLen, file.end());
  const auto aad = record_aad(magic, id, salt, kSaltLen);
  SecureBuffer plain = decrypt_gcm(keys_.record_key.data(), enc, nonce, aad);
  callback(plain);
}

ChunkVault::ChunkVault(std::filesystem::path root) : root_(std::move(root)) {}

std::filesystem::path ChunkVault::put(const std::string& purpose, const std::string& domain_or_url,
                                      const std::string& account, SecureBuffer& passphrase,
                                      const SecureBuffer& plaintext) {
  return VaultSession::open_with_password(root_, passphrase)
      .put(purpose, domain_or_url, account, plaintext);
}

void ChunkVault::use(const std::string& purpose, const std::string& domain_or_url,
                     const std::string& account, SecureBuffer& passphrase,
                     const std::function<void(const SecureBuffer&)>& callback) {
  VaultSession::open_with_password(root_, passphrase)
      .use(purpose, domain_or_url, account, callback);
}

// --- Test-fixture overloads. See the warning in vault.hpp. ---------------------------------

std::filesystem::path ChunkVault::put(const std::string& purpose, const std::string& domain_or_url,
                                      const std::string& account, const std::string& passphrase,
                                      const std::string& plaintext_json) {
  SecureBuffer locked_passphrase(passphrase);
  SecureBuffer plaintext(plaintext_json);
  return put(purpose, domain_or_url, account, locked_passphrase, plaintext);
}

std::string ChunkVault::get(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, const std::string& passphrase) {
  std::string value;
  use(purpose, domain_or_url, account, passphrase,
      [&](const SecureBuffer& secret) { value = secret.str(); });
  return value;
}

void ChunkVault::use(const std::string& purpose, const std::string& domain_or_url,
                     const std::string& account, const std::string& passphrase,
                     const std::function<void(const SecureBuffer&)>& callback) {
  SecureBuffer locked_passphrase(passphrase);
  use(purpose, domain_or_url, account, locked_passphrase, callback);
}

void init_vault(const std::filesystem::path& root, const std::string& login,
                const std::string& passphrase) {
  SecureBuffer locked_passphrase(passphrase);
  init_vault(root, login, locked_passphrase);
}

bool verify_credentials(const std::filesystem::path& root, const std::string& login,
                        const std::string& passphrase) {
  SecureBuffer locked_passphrase(passphrase);
  return verify_credentials(root, login, locked_passphrase);
}

}  // namespace alfie
