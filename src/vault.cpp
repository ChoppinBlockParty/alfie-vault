//===----------------------------------------------------------------------===//
/// \file
/// Store independently encrypted records and scope keys to one unlock.
//===----------------------------------------------------------------------===//

#include "vault.h"
#include <algorithm>
#include <argon2.h>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>

using namespace alfie;

CryptoError::~CryptoError() = default;

// Record format. V1 authenticated only the magic, so the reserved salt field
// and the record's own identity were malleable: an attacker with write access
// to the vault directory could swap one record file for another and the vault
// would happily decrypt it under the wrong domain. V2 binds magic + record id +
// salt into the GCM AAD. V1 records stay readable so an existing vault keeps
// working; every write produces V2.
static constexpr char kMagicV1[] = "ALFIECHUNK1\n";
static constexpr char kMagicV2[] = "ALFIECHUNK2\n";
static constexpr size_t kMagicLen = 12;
static constexpr size_t kSaltLen = 16;
static constexpr size_t kVaultSaltLen = 32;
static constexpr size_t kNonceLen = 12;
static constexpr size_t kTagLen = 16;
static constexpr size_t kDerivedLen = 64;
static constexpr size_t kSubKeyLen = 32;

static std::string hex(const unsigned char *data, size_t len) {
  std::ostringstream out;
  for (size_t i = 0; i < len; ++i)
    out << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  return out.str();
}

static std::vector<unsigned char> sha256Bytes(const std::string &s) {
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char *>(s.data()), s.size(),
         digest.data());
  return digest;
}

static unsigned char fromHex(char c) {
  if (c >= '0' && c <= '9')
    return static_cast<unsigned char>(c - '0');
  if (c >= 'a' && c <= 'f')
    return static_cast<unsigned char>(10 + c - 'a');
  if (c >= 'A' && c <= 'F')
    return static_cast<unsigned char>(10 + c - 'A');
  throw CryptoError("bad hex");
}

static std::vector<unsigned char> unhex(const std::string &s) {
  if (s.size() % 2 != 0)
    throw CryptoError("bad hex length");
  std::vector<unsigned char> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    out.push_back(
        static_cast<unsigned char>((fromHex(s[i]) << 4) | fromHex(s[i + 1])));
  }
  return out;
}

static std::vector<unsigned char> randomBytes(size_t n) {
  std::vector<unsigned char> out(n);
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
    throw CryptoError("RAND_bytes failed");
  return out;
}

// Joins fields with a real NUL separator. Writing `a + "\0" + b` looks like
// this but is not: the literal decays to a C string, strlen() stops at the NUL,
// and the separator vanishes -- which would let ("acc", "ountX") and
// ("account", "X") hash to the same record id.
static std::string nulJoin(std::initializer_list<std::string> fields) {
  std::string out;
  bool first = true;
  for (const auto &field : fields) {
    if (!first)
      out.push_back('\0');
    out += field;
    first = false;
  }
  return out;
}

static void writeFile(const std::filesystem::path &p,
                      const std::vector<unsigned char> &data) {
  std::filesystem::create_directories(p.parent_path());
  for (auto dir = p.parent_path(); dir.has_relative_path();
       dir = dir.parent_path()) {
    std::error_code ec;
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (dir.filename() == "records")
      break;
  }
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
  out.flush();
  std::error_code ec;
  std::filesystem::permissions(p,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);
}

static std::vector<unsigned char> readFile(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in)
    throw CryptoError("record not found");
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Ciphertext is not secret, so it stays on the normal heap; the plaintext side
// is always addressed as raw bytes so callers can keep it in secure memory.
static std::vector<unsigned char>
encryptGcm(const unsigned char *key, const unsigned char *plaintext,
           size_t plaintextLen, const std::vector<unsigned char> &nonce,
           const std::vector<unsigned char> &aad) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> ciphertext(plaintextLen + kTagLen);
  int len = 0;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
  if (ok && !aad.empty())
    ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                           static_cast<int>(aad.size())) == 1;
  int total = 0;
  if (ok && plaintextLen > 0) {
    ok = EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext,
                           static_cast<int>(plaintextLen)) == 1;
    total = len;
  }
  ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                 ciphertext.data() + plaintextLen) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("AES-256-GCM encrypt failed");
  return ciphertext;
}

// Decrypts straight into secure memory: the plaintext never exists on the
// normal heap.
static SecureBuffer
decryptGcm(const unsigned char *key,
           const std::vector<unsigned char> &ciphertextAndTag,
           const std::vector<unsigned char> &nonce,
           const std::vector<unsigned char> &aad) {
  if (ciphertextAndTag.size() < kTagLen)
    throw CryptoError("bad ciphertext");
  const size_t ctLen = ciphertextAndTag.size() - kTagLen;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  SecureBuffer plaintext(ctLen);
  int len = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
  if (ok && !aad.empty())
    ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                           static_cast<int>(aad.size())) == 1;
  int total = 0;
  if (ok && ctLen > 0) {
    ok = EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertextAndTag.data(),
                           static_cast<int>(ctLen)) == 1;
    total = len;
  }
  ok = ok &&
       EVP_CIPHER_CTX_ctrl(
           ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
           const_cast<unsigned char *>(ciphertextAndTag.data() + ctLen)) == 1 &&
       EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) == 1;
  total += len;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw CryptoError("AES-256-GCM decrypt failed");
  plaintext.truncate(static_cast<size_t>(total));
  return plaintext;
}

SecureBuffer::SecureBuffer(size_t size) : data_(size, 0) {}
SecureBuffer::SecureBuffer(const std::string &s) : data_(s.begin(), s.end()) {}
SecureBuffer::SecureBuffer(SecureBytes bytes) : data_(std::move(bytes)) {}

SecureBuffer::SecureBuffer(std::vector<unsigned char> bytes)
    : data_(bytes.begin(), bytes.end()) {
  if (!bytes.empty())
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

SecureBuffer::~SecureBuffer() { wipe(); }

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
  if (this != &other) {
    wipe();
    this->data_ = std::move(other.data_);
  }
  return *this;
}

std::string SecureBuffer::str() const {
  return {this->data_.begin(), this->data_.end()};
}

void SecureBuffer::truncate(size_t size) {
  if (size >= this->data_.size())
    return;
  OPENSSL_cleanse(this->data_.data() + size, this->data_.size() - size);
  this->data_.resize(
      size); // Shrinking never reallocates, so no copy is left behind.
}

void SecureBuffer::wipe() {
  if (!this->data_.empty())
    OPENSSL_cleanse(this->data_.data(), this->data_.size());
}

VaultKeys alfie::deriveKeys(SecureBuffer &passphrase,
                            const std::vector<unsigned char> &salt,
                            const Argon2Params &params) {
  SecureBuffer out(kDerivedLen);
  int rc = argon2id_hash_raw(params.tCost, params.mCostKib, params.parallelism,
                             passphrase.data(), passphrase.size(), salt.data(),
                             salt.size(), out.data(), out.size());
  passphrase.wipe();
  if (rc != ARGON2_OK)
    throw CryptoError(argon2_error_message(rc));
  SecureBuffer index(kSubKeyLen);
  SecureBuffer record(kSubKeyLen);
  std::copy_n(out.data(), kSubKeyLen, index.data());
  std::copy_n(out.data() + kSubKeyLen, kSubKeyLen, record.data());
  return VaultKeys(std::move(index), std::move(record));
}

VaultKeys alfie::deriveKeys(SecureBuffer &passphrase,
                            const std::string &context) {
  auto salt = sha256Bytes("alfie-vault-argon2id:" + context);
  return deriveKeys(passphrase, salt);
}

std::string alfie::normalizeDomain(const std::string &input) {
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
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  if (s.rfind("www.", 0) == 0)
    s = s.substr(4);
  while (!s.empty() && s.back() == '.')
    s.pop_back();
  return s;
}

std::string alfie::recordId(const SecureBuffer &indexKey,
                            const std::string &purpose,
                            const std::string &domainOrUrl,
                            const std::string &account) {
  const std::string msg =
      nulJoin({purpose, normalizeDomain(domainOrUrl), account});
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), indexKey.data(), static_cast<int>(indexKey.size()),
       reinterpret_cast<const unsigned char *>(msg.data()), msg.size(), mac,
       &len);
  std::string id = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return id;
}

static constexpr char kMetaV1[] = "ALFIEVAULT1";
static constexpr char kMetaV2[] = "ALFIEVAULT2";
static constexpr char kPasswordVerifierLabel[] =
    "alfie-vault-password-verifier";
static constexpr char kLoginVerifierLabel[] = "alfie-vault-login:";

namespace {
struct VaultMeta {
  std::vector<unsigned char> salt;
  Argon2Params params;
  bool hasCredentials = false;
  std::string loginVerifier;
  std::string passwordVerifier;
};
} // namespace

// Parses "argon2id m=65536,t=3,p=1". Anything unrecognised leaves the default
// in place, so a malformed line cannot silently weaken the cost below what this
// build would have used.
static Argon2Params parseArgon2Params(const std::string &line) {
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
    } catch (const std::exception &) {
      continue;
    }
    if (value == 0)
      continue;
    if (key == "m")
      params.mCostKib = static_cast<uint32_t>(value);
    else if (key == "t")
      params.tCost = static_cast<uint32_t>(value);
    else if (key == "p")
      params.parallelism = static_cast<uint32_t>(value);
  }
  return params;
}

static std::string hmacHex(const SecureBuffer &key,
                           const std::string &message) {
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char *>(message.data()), message.size(),
       mac, &len);
  std::string out = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return out;
}

static bool constantTimeEquals(const std::string &a, const std::string &b) {
  if (a.size() != b.size())
    return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

static std::filesystem::path metaPathFor(const std::filesystem::path &root) {
  return root / "vault.meta";
}

static VaultMeta readMeta(const std::filesystem::path &root) {
  const auto metaPath = metaPathFor(root);
  if (!std::filesystem::exists(metaPath))
    throw CryptoError("vault is not initialized");

  std::ifstream in(metaPath, std::ios::binary);
  std::string magic, saltHex, costs;
  std::getline(in, magic);
  std::getline(in, saltHex);
  std::getline(in, costs);
  if (magic != kMetaV1 && magic != kMetaV2)
    throw CryptoError("bad vault metadata");

  VaultMeta meta;
  meta.params = parseArgon2Params(costs);
  meta.salt = unhex(saltHex);
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
      meta.loginVerifier = value;
    else if (key == "password_verifier")
      meta.passwordVerifier = value;
  }
  if (meta.loginVerifier.empty() || meta.passwordVerifier.empty())
    throw CryptoError("bad vault metadata: missing credential verifiers");
  meta.hasCredentials = true;
  return meta;
}

// Reproduces the pre-fix record id, where `purpose + "\0" + domain + "\0" +
// account` silently dropped both separators. Kept only so records written
// before the fix can still be found.
static std::string legacyRecordId(const SecureBuffer &indexKey,
                                  const std::string &purpose,
                                  const std::string &domainOrUrl,
                                  const std::string &account) {
  const std::string msg = purpose + normalizeDomain(domainOrUrl) + account;
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), indexKey.data(), static_cast<int>(indexKey.size()),
       reinterpret_cast<const unsigned char *>(msg.data()), msg.size(), mac,
       &len);
  std::string id = hex(mac, len);
  OPENSSL_cleanse(mac, sizeof(mac));
  return id;
}

// V2 AAD: magic || record id || reserved salt. Binding the id stops record
// files being swapped between records; binding the salt stops that reserved
// field being tampered with before a future format starts deriving keys from
// it.
static std::vector<unsigned char> recordAad(const char *magic,
                                            const std::string &id,
                                            const unsigned char *salt,
                                            size_t saltLen) {
  std::vector<unsigned char> aad(magic, magic + kMagicLen);
  if (magic == std::string(kMagicV1))
    return aad; // V1 authenticated the magic only.
  aad.insert(aad.end(), id.begin(), id.end());
  aad.insert(aad.end(), salt, salt + saltLen);
  return aad;
}

static std::filesystem::path pathForId(const std::filesystem::path &root,
                                       const std::string &id) {
  return root / "records" / id.substr(0, 2) / id.substr(2, 2) / (id + ".enc");
}

bool alfie::vaultInitialized(const std::filesystem::path &root) {
  return std::filesystem::exists(metaPathFor(root));
}

bool alfie::vaultHasCredentials(const std::filesystem::path &root) {
  if (!vaultInitialized(root))
    return false;
  return readMeta(root).hasCredentials;
}

void alfie::initVault(const std::filesystem::path &root,
                      const std::string &login, SecureBuffer &passphrase) {
  if (login.empty())
    throw CryptoError("login must not be empty");
  if (passphrase.empty())
    throw CryptoError("master password must not be empty");
  if (vaultInitialized(root))
    throw CryptoError("vault already initialized");

  auto salt = randomBytes(kVaultSaltLen);
  const Argon2Params params;
  VaultKeys keys = deriveKeys(passphrase, salt, params);
  const auto passwordVerifier = hmacHex(keys.indexKey, kPasswordVerifierLabel);
  const auto loginVerifier =
      hmacHex(keys.indexKey, kLoginVerifierLabel + login);

  std::filesystem::create_directories(root);
  // The vault directory is private to this user: record filenames are HMACs,
  // but their count, sizes and timestamps still leak how the vault is used.
  std::filesystem::permissions(root, std::filesystem::perms::owner_all);
  const auto metaPath = metaPathFor(root);
  std::ofstream out(metaPath, std::ios::binary | std::ios::trunc);
  if (!out)
    throw CryptoError("cannot write vault metadata");
  out << kMetaV2 << "\n"
      << hex(salt.data(), salt.size()) << "\n"
      << "argon2id m=" << params.mCostKib << ",t=" << params.tCost
      << ",p=" << params.parallelism << "\n"
      << "login_verifier " << loginVerifier << "\n"
      << "password_verifier " << passwordVerifier << "\n";
  out.flush();
  if (!out)
    throw CryptoError("cannot write vault metadata");
  std::filesystem::permissions(metaPath,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write);
}

bool alfie::verifyCredentials(const std::filesystem::path &root,
                              const std::string &login,
                              SecureBuffer &passphrase) {
  const auto meta = readMeta(root);
  if (!meta.hasCredentials) {
    passphrase.wipe();
    return false;
  }
  VaultKeys keys = deriveKeys(passphrase, meta.salt, meta.params);
  const bool passwordOk = constantTimeEquals(
      hmacHex(keys.indexKey, kPasswordVerifierLabel), meta.passwordVerifier);
  const bool loginOk = constantTimeEquals(
      hmacHex(keys.indexKey, kLoginVerifierLabel + login), meta.loginVerifier);
  return passwordOk && loginOk;
}

VaultSession VaultSession::open(const std::filesystem::path &root,
                                const std::string &login,
                                SecureBuffer &passphrase) {
  const auto meta = readMeta(root);
  VaultKeys keys = deriveKeys(passphrase, meta.salt, meta.params);
  if (!meta.hasCredentials)
    throw CryptoError("vault has no credential verifiers");
  const bool passwordOk = constantTimeEquals(
      hmacHex(keys.indexKey, kPasswordVerifierLabel), meta.passwordVerifier);
  const bool loginOk = constantTimeEquals(
      hmacHex(keys.indexKey, kLoginVerifierLabel + login), meta.loginVerifier);
  if (!passwordOk || !loginOk)
    throw CryptoError("bad login or master password");
  return VaultSession(root, std::move(keys));
}

VaultSession VaultSession::openWithPassword(const std::filesystem::path &root,
                                            SecureBuffer &passphrase) {
  const auto meta = readMeta(root);
  VaultKeys keys = deriveKeys(passphrase, meta.salt, meta.params);
  // Without this, a wrong master password derives a different index key,
  // computes a record id that happens to address nothing, and surfaces as
  // "record not found" -- exactly the confusion the stored verifiers exist to
  // remove. Legacy V1 vaults carry no verifiers.
  if (meta.hasCredentials &&
      !constantTimeEquals(hmacHex(keys.indexKey, kPasswordVerifierLabel),
                          meta.passwordVerifier)) {
    throw CryptoError("bad master password");
  }
  return VaultSession(root, std::move(keys));
}

std::filesystem::path VaultSession::put(const std::string &purpose,
                                        const std::string &domainOrUrl,
                                        const std::string &account,
                                        const SecureBuffer &plaintext) {
  const std::string id =
      recordId(this->keys_.indexKey, purpose, domainOrUrl, account);
  auto salt = randomBytes(
      kSaltLen); // Reserved for future format agility; authenticated
                 // by the V2 AAD so it cannot be altered in place.
  auto nonce = randomBytes(kNonceLen);
  const auto aad = recordAad(kMagicV2, id, salt.data(), salt.size());
  auto enc = encryptGcm(this->keys_.recordKey.data(), plaintext.data(),
                        plaintext.size(), nonce, aad);

  std::vector<unsigned char> file;
  file.reserve(kMagicLen + salt.size() + nonce.size() + enc.size());
  file.insert(file.end(), kMagicV2, kMagicV2 + kMagicLen);
  file.insert(file.end(), salt.begin(), salt.end());
  file.insert(file.end(), nonce.begin(), nonce.end());
  file.insert(file.end(), enc.begin(), enc.end());
  auto path = pathForId(this->root_, id);
  writeFile(path, file);

  // Drop any pre-fix copy of the same record, so a stale ciphertext of an old
  // secret is not left behind in the vault directory.
  const auto legacy =
      pathForId(this->root_, legacyRecordId(this->keys_.indexKey, purpose,
                                            domainOrUrl, account));
  if (legacy != path) {
    std::error_code ec;
    std::filesystem::remove(legacy, ec);
  }
  return path;
}

void VaultSession::use(
    const std::string &purpose, const std::string &domainOrUrl,
    const std::string &account,
    const std::function<void(const SecureBuffer &)> &callback) {
  std::string id =
      recordId(this->keys_.indexKey, purpose, domainOrUrl, account);
  auto path = pathForId(this->root_, id);
  if (!std::filesystem::exists(path)) {
    // Fall back to the pre-fix id so vaults written before the separator fix
    // still resolve.
    const std::string legacyId =
        legacyRecordId(this->keys_.indexKey, purpose, domainOrUrl, account);
    const auto legacyPath = pathForId(this->root_, legacyId);
    if (!std::filesystem::exists(legacyPath))
      throw CryptoError("record not found");
    id = legacyId;
    path = legacyPath;
  }

  auto file = readFile(path);
  if (file.size() < kMagicLen + kSaltLen + kNonceLen + kTagLen)
    throw CryptoError("bad record");

  const char *magic = nullptr;
  if (std::memcmp(file.data(), kMagicV2, kMagicLen) == 0)
    magic = kMagicV2;
  else if (std::memcmp(file.data(), kMagicV1, kMagicLen) == 0)
    magic = kMagicV1;
  else
    throw CryptoError("bad record magic");

  const unsigned char *salt = file.data() + kMagicLen;
  std::vector<unsigned char> nonce(file.begin() + kMagicLen + kSaltLen,
                                   file.begin() + kMagicLen + kSaltLen +
                                       kNonceLen);
  std::vector<unsigned char> enc(
      file.begin() + kMagicLen + kSaltLen + kNonceLen, file.end());
  const auto aad = recordAad(magic, id, salt, kSaltLen);
  SecureBuffer plain =
      decryptGcm(this->keys_.recordKey.data(), enc, nonce, aad);
  callback(plain);
}

ChunkVault::ChunkVault(std::filesystem::path root) : root_(std::move(root)) {}

std::filesystem::path ChunkVault::put(const std::string &purpose,
                                      const std::string &domainOrUrl,
                                      const std::string &account,
                                      SecureBuffer &passphrase,
                                      const SecureBuffer &plaintext) {
  return VaultSession::openWithPassword(this->root_, passphrase)
      .put(purpose, domainOrUrl, account, plaintext);
}

void ChunkVault::use(
    const std::string &purpose, const std::string &domainOrUrl,
    const std::string &account, SecureBuffer &passphrase,
    const std::function<void(const SecureBuffer &)> &callback) {
  VaultSession::openWithPassword(this->root_, passphrase)
      .use(purpose, domainOrUrl, account, callback);
}

// --- Test-fixture overloads. See the warning in vault.h.
// ---------------------------------

std::filesystem::path ChunkVault::put(const std::string &purpose,
                                      const std::string &domainOrUrl,
                                      const std::string &account,
                                      const std::string &passphrase,
                                      const std::string &plaintextJson) {
  SecureBuffer lockedPassphrase(passphrase);
  SecureBuffer plaintext(plaintextJson);
  return put(purpose, domainOrUrl, account, lockedPassphrase, plaintext);
}

std::string ChunkVault::get(const std::string &purpose,
                            const std::string &domainOrUrl,
                            const std::string &account,
                            const std::string &passphrase) {
  std::string value;
  use(purpose, domainOrUrl, account, passphrase,
      [&](const SecureBuffer &secret) { value = secret.str(); });
  return value;
}

void ChunkVault::use(
    const std::string &purpose, const std::string &domainOrUrl,
    const std::string &account, const std::string &passphrase,
    const std::function<void(const SecureBuffer &)> &callback) {
  SecureBuffer lockedPassphrase(passphrase);
  use(purpose, domainOrUrl, account, lockedPassphrase, callback);
}

void alfie::initVault(const std::filesystem::path &root,
                      const std::string &login, const std::string &passphrase) {
  SecureBuffer lockedPassphrase(passphrase);
  initVault(root, login, lockedPassphrase);
}

bool alfie::verifyCredentials(const std::filesystem::path &root,
                              const std::string &login,
                              const std::string &passphrase) {
  SecureBuffer lockedPassphrase(passphrase);
  return verifyCredentials(root, login, lockedPassphrase);
}
