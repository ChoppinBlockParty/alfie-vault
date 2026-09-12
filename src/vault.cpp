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
static constexpr char MagicV1[] = "ALFIECHUNK1\n";
static constexpr char MagicV2[] = "ALFIECHUNK2\n";
static constexpr size_t MagicLen = 12;
static constexpr size_t SaltLen = 16;
static constexpr size_t VaultSaltLen = 32;
static constexpr size_t NonceLen = 12;
static constexpr size_t TagLen = 16;
static constexpr size_t DerivedLen = 64;
static constexpr size_t SubKeyLen = 32;

static std::string hex(const unsigned char *Data, size_t Len) {
  std::ostringstream Out;
  for (size_t I = 0; I < Len; ++I)
    Out << std::hex << std::setw(2) << std::setfill('0') << (int)Data[I];
  return Out.str();
}

static std::vector<unsigned char> sha256Bytes(const std::string &S) {
  std::vector<unsigned char> Digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char *>(S.data()), S.size(),
         Digest.data());
  return Digest;
}

static unsigned char fromHex(char C) {
  if (C >= '0' && C <= '9')
    return static_cast<unsigned char>(C - '0');
  if (C >= 'a' && C <= 'f')
    return static_cast<unsigned char>(10 + C - 'a');
  if (C >= 'A' && C <= 'F')
    return static_cast<unsigned char>(10 + C - 'A');
  throw CryptoError("bad hex");
}

static std::vector<unsigned char> unhex(const std::string &S) {
  if (S.size() % 2 != 0)
    throw CryptoError("bad hex length");
  std::vector<unsigned char> Out;
  Out.reserve(S.size() / 2);
  for (size_t I = 0; I < S.size(); I += 2) {
    Out.push_back(
        static_cast<unsigned char>((fromHex(S[I]) << 4) | fromHex(S[I + 1])));
  }
  return Out;
}

static std::vector<unsigned char> randomBytes(size_t N) {
  std::vector<unsigned char> Out(N);
  if (RAND_bytes(Out.data(), static_cast<int>(Out.size())) != 1)
    throw CryptoError("RAND_bytes failed");
  return Out;
}

// Joins fields with a real NUL separator. Writing `a + "\0" + b` looks like
// this but is not: the literal decays to a C string, strlen() stops at the NUL,
// and the separator vanishes -- which would let ("acc", "ountX") and
// ("account", "X") hash to the same record id.
static std::string nulJoin(std::initializer_list<std::string> Fields) {
  std::string Out;
  bool First = true;
  for (const auto &Field : Fields) {
    if (!First)
      Out.push_back('\0');
    Out += Field;
    First = false;
  }
  return Out;
}

static void writeFile(const std::filesystem::path &P,
                      const std::vector<unsigned char> &Data) {
  std::filesystem::create_directories(P.parent_path());
  for (auto Dir = P.parent_path(); Dir.has_relative_path();
       Dir = Dir.parent_path()) {
    std::error_code Ec;
    std::filesystem::permissions(Dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, Ec);
    if (Dir.filename() == "records")
      break;
  }
  std::ofstream Out(P, std::ios::binary | std::ios::trunc);
  Out.write(reinterpret_cast<const char *>(Data.data()),
            static_cast<std::streamsize>(Data.size()));
  Out.flush();
  std::error_code Ec;
  std::filesystem::permissions(P,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, Ec);
}

static std::vector<unsigned char> readFile(const std::filesystem::path &P) {
  std::ifstream In(P, std::ios::binary);
  if (!In)
    throw CryptoError("record not found");
  return {std::istreambuf_iterator<char>(In), std::istreambuf_iterator<char>()};
}

// Ciphertext is not secret, so it stays on the normal heap; the plaintext side
// is always addressed as raw bytes so callers can keep it in secure memory.
static std::vector<unsigned char>
encryptGcm(const unsigned char *Key, const unsigned char *Plaintext,
           size_t PlaintextLen, const std::vector<unsigned char> &Nonce,
           const std::vector<unsigned char> &Aad) {
  EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
  if (!Ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> Ciphertext(PlaintextLen + TagLen);
  int Len = 0;
  bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(Nonce.size()), nullptr) == 1 &&
            EVP_EncryptInit_ex(Ctx, nullptr, nullptr, Key, Nonce.data()) == 1;
  if (Ok && !Aad.empty())
    Ok = EVP_EncryptUpdate(Ctx, nullptr, &Len, Aad.data(),
                           static_cast<int>(Aad.size())) == 1;
  int Total = 0;
  if (Ok && PlaintextLen > 0) {
    Ok = EVP_EncryptUpdate(Ctx, Ciphertext.data(), &Len, Plaintext,
                           static_cast<int>(PlaintextLen)) == 1;
    Total = Len;
  }
  Ok = Ok && EVP_EncryptFinal_ex(Ctx, Ciphertext.data() + Total, &Len) == 1;
  Ok = Ok && EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, TagLen,
                                 Ciphertext.data() + PlaintextLen) == 1;
  EVP_CIPHER_CTX_free(Ctx);
  if (!Ok)
    throw CryptoError("AES-256-GCM encrypt failed");
  return Ciphertext;
}

// Decrypts straight into secure memory: the plaintext never exists on the
// normal heap.
static SecureBuffer
decryptGcm(const unsigned char *Key,
           const std::vector<unsigned char> &CiphertextAndTag,
           const std::vector<unsigned char> &Nonce,
           const std::vector<unsigned char> &Aad) {
  if (CiphertextAndTag.size() < TagLen)
    throw CryptoError("bad ciphertext");
  const size_t CtLen = CiphertextAndTag.size() - TagLen;
  EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
  if (!Ctx)
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  SecureBuffer Plaintext(CtLen);
  int Len = 0;
  bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(Nonce.size()), nullptr) == 1 &&
            EVP_DecryptInit_ex(Ctx, nullptr, nullptr, Key, Nonce.data()) == 1;
  if (Ok && !Aad.empty())
    Ok = EVP_DecryptUpdate(Ctx, nullptr, &Len, Aad.data(),
                           static_cast<int>(Aad.size())) == 1;
  int Total = 0;
  if (Ok && CtLen > 0) {
    Ok = EVP_DecryptUpdate(Ctx, Plaintext.data(), &Len, CiphertextAndTag.data(),
                           static_cast<int>(CtLen)) == 1;
    Total = Len;
  }
  Ok = Ok &&
       EVP_CIPHER_CTX_ctrl(
           Ctx, EVP_CTRL_GCM_SET_TAG, TagLen,
           const_cast<unsigned char *>(CiphertextAndTag.data() + CtLen)) == 1 &&
       EVP_DecryptFinal_ex(Ctx, Plaintext.data() + Total, &Len) == 1;
  Total += Len;
  EVP_CIPHER_CTX_free(Ctx);
  if (!Ok)
    throw CryptoError("AES-256-GCM decrypt failed");
  Plaintext.truncate(static_cast<size_t>(Total));
  return Plaintext;
}

SecureBuffer::SecureBuffer(size_t Size) : Data(Size, 0) {}
SecureBuffer::SecureBuffer(const std::string &S) : Data(S.begin(), S.end()) {}
SecureBuffer::SecureBuffer(SecureBytes Bytes) : Data(std::move(Bytes)) {}

SecureBuffer::SecureBuffer(std::vector<unsigned char> Bytes)
    : Data(Bytes.begin(), Bytes.end()) {
  if (!Bytes.empty())
    OPENSSL_cleanse(Bytes.data(), Bytes.size());
}

SecureBuffer::~SecureBuffer() { wipe(); }

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&Other) noexcept {
  if (this != &Other) {
    wipe();
    this->Data = std::move(Other.Data);
  }
  return *this;
}

std::string SecureBuffer::str() const {
  return {this->Data.begin(), this->Data.end()};
}

void SecureBuffer::truncate(size_t Size) {
  if (Size >= this->Data.size())
    return;
  OPENSSL_cleanse(this->Data.data() + Size, this->Data.size() - Size);
  this->Data.resize(
      Size); // Shrinking never reallocates, so no copy is left behind.
}

void SecureBuffer::wipe() {
  if (!this->Data.empty())
    OPENSSL_cleanse(this->Data.data(), this->Data.size());
}

VaultKeys alfie::deriveKeys(SecureBuffer &Passphrase,
                            const std::vector<unsigned char> &Salt,
                            const Argon2Params &Params) {
  SecureBuffer Out(DerivedLen);
  int Rc = argon2id_hash_raw(Params.TCost, Params.MCostKib, Params.Parallelism,
                             Passphrase.data(), Passphrase.size(), Salt.data(),
                             Salt.size(), Out.data(), Out.size());
  Passphrase.wipe();
  if (Rc != ARGON2_OK)
    throw CryptoError(argon2_error_message(Rc));
  SecureBuffer Index(SubKeyLen);
  SecureBuffer Record(SubKeyLen);
  std::copy_n(Out.data(), SubKeyLen, Index.data());
  std::copy_n(Out.data() + SubKeyLen, SubKeyLen, Record.data());
  return VaultKeys(std::move(Index), std::move(Record));
}

VaultKeys alfie::deriveKeys(SecureBuffer &Passphrase,
                            const std::string &Context) {
  auto Salt = sha256Bytes("alfie-vault-argon2id:" + Context);
  return deriveKeys(Passphrase, Salt);
}

std::string alfie::normalizeDomain(const std::string &Input) {
  std::string S = Input;
  auto Scheme = S.find("://");
  if (Scheme != std::string::npos)
    S = S.substr(Scheme + 3);
  auto Slash = S.find('/');
  if (Slash != std::string::npos)
    S = S.substr(0, Slash);
  auto Colon = S.find(':');
  if (Colon != std::string::npos)
    S = S.substr(0, Colon);
  std::transform(S.begin(), S.end(), S.begin(),
                 [](unsigned char C) { return std::tolower(C); });
  if (S.rfind("www.", 0) == 0)
    S = S.substr(4);
  while (!S.empty() && S.back() == '.')
    S.pop_back();
  return S;
}

std::string alfie::recordId(const SecureBuffer &IndexKey,
                            const std::string &Purpose,
                            const std::string &DomainOrUrl,
                            const std::string &Account) {
  const std::string Msg =
      nulJoin({Purpose, normalizeDomain(DomainOrUrl), Account});
  unsigned int Len = 0;
  unsigned char Mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), IndexKey.data(), static_cast<int>(IndexKey.size()),
       reinterpret_cast<const unsigned char *>(Msg.data()), Msg.size(), Mac,
       &Len);
  std::string Id = hex(Mac, Len);
  OPENSSL_cleanse(Mac, sizeof(Mac));
  return Id;
}

static constexpr char MetaV1[] = "ALFIEVAULT1";
static constexpr char MetaV2[] = "ALFIEVAULT2";
static constexpr char PasswordVerifierLabel[] = "alfie-vault-password-verifier";
static constexpr char LoginVerifierLabel[] = "alfie-vault-login:";

namespace {
struct VaultMeta {
  std::vector<unsigned char> Salt;
  Argon2Params Params;
  bool HasCredentials = false;
  std::string LoginVerifier;
  std::string PasswordVerifier;
};
} // namespace

// Parses "argon2id m=65536,t=3,p=1". Anything unrecognised leaves the default
// in place, so a malformed line cannot silently weaken the cost below what this
// build would have used.
static Argon2Params parseArgon2Params(const std::string &Line) {
  Argon2Params Params;
  if (Line.rfind("argon2id ", 0) != 0)
    return Params;
  std::istringstream Fields(Line.substr(9));
  std::string Field;
  while (std::getline(Fields, Field, ',')) {
    const auto Eq = Field.find('=');
    if (Eq == std::string::npos)
      continue;
    const auto Key = Field.substr(0, Eq);
    unsigned long Value = 0;
    try {
      Value = std::stoul(Field.substr(Eq + 1));
    } catch (const std::exception &) {
      continue;
    }
    if (Value == 0)
      continue;
    if (Key == "m")
      Params.MCostKib = static_cast<uint32_t>(Value);
    else if (Key == "t")
      Params.TCost = static_cast<uint32_t>(Value);
    else if (Key == "p")
      Params.Parallelism = static_cast<uint32_t>(Value);
  }
  return Params;
}

static std::string hmacHex(const SecureBuffer &Key,
                           const std::string &Message) {
  unsigned int Len = 0;
  unsigned char Mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), Key.data(), static_cast<int>(Key.size()),
       reinterpret_cast<const unsigned char *>(Message.data()), Message.size(),
       Mac, &Len);
  std::string Out = hex(Mac, Len);
  OPENSSL_cleanse(Mac, sizeof(Mac));
  return Out;
}

static bool constantTimeEquals(const std::string &A, const std::string &B) {
  if (A.size() != B.size())
    return false;
  return CRYPTO_memcmp(A.data(), B.data(), A.size()) == 0;
}

static std::filesystem::path metaPathFor(const std::filesystem::path &Root) {
  return Root / "vault.meta";
}

static VaultMeta readMeta(const std::filesystem::path &Root) {
  const auto MetaPath = metaPathFor(Root);
  if (!std::filesystem::exists(MetaPath))
    throw CryptoError("vault is not initialized");

  std::ifstream In(MetaPath, std::ios::binary);
  std::string Magic, SaltHex, Costs;
  std::getline(In, Magic);
  std::getline(In, SaltHex);
  std::getline(In, Costs);
  if (Magic != MetaV1 && Magic != MetaV2)
    throw CryptoError("bad vault metadata");

  VaultMeta Meta;
  Meta.Params = parseArgon2Params(Costs);
  Meta.Salt = unhex(SaltHex);
  if (Meta.Salt.size() != VaultSaltLen)
    throw CryptoError("bad vault salt");
  if (Magic == MetaV1)
    return Meta;

  std::string Line;
  while (std::getline(In, Line)) {
    if (!Line.empty() && Line.back() == '\r')
      Line.pop_back();
    const auto Space = Line.find(' ');
    if (Space == std::string::npos)
      continue;
    const auto Key = Line.substr(0, Space);
    const auto Value = Line.substr(Space + 1);
    if (Key == "login_verifier")
      Meta.LoginVerifier = Value;
    else if (Key == "password_verifier")
      Meta.PasswordVerifier = Value;
  }
  if (Meta.LoginVerifier.empty() || Meta.PasswordVerifier.empty())
    throw CryptoError("bad vault metadata: missing credential verifiers");
  Meta.HasCredentials = true;
  return Meta;
}

// Reproduces the pre-fix record id, where `purpose + "\0" + domain + "\0" +
// account` silently dropped both separators. Kept only so records written
// before the fix can still be found.
static std::string legacyRecordId(const SecureBuffer &IndexKey,
                                  const std::string &Purpose,
                                  const std::string &DomainOrUrl,
                                  const std::string &Account) {
  const std::string Msg = Purpose + normalizeDomain(DomainOrUrl) + Account;
  unsigned int Len = 0;
  unsigned char Mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), IndexKey.data(), static_cast<int>(IndexKey.size()),
       reinterpret_cast<const unsigned char *>(Msg.data()), Msg.size(), Mac,
       &Len);
  std::string Id = hex(Mac, Len);
  OPENSSL_cleanse(Mac, sizeof(Mac));
  return Id;
}

// V2 AAD: magic || record id || reserved salt. Binding the id stops record
// files being swapped between records; binding the salt stops that reserved
// field being tampered with before a future format starts deriving keys from
// it.
static std::vector<unsigned char> recordAad(const char *Magic,
                                            const std::string &Id,
                                            const unsigned char *Salt,
                                            size_t SaltLen) {
  std::vector<unsigned char> Aad(Magic, Magic + MagicLen);
  if (Magic == std::string(MagicV1))
    return Aad; // V1 authenticated the magic only.
  Aad.insert(Aad.end(), Id.begin(), Id.end());
  Aad.insert(Aad.end(), Salt, Salt + SaltLen);
  return Aad;
}

static std::filesystem::path pathForId(const std::filesystem::path &Root,
                                       const std::string &Id) {
  return Root / "records" / Id.substr(0, 2) / Id.substr(2, 2) / (Id + ".enc");
}

bool alfie::vaultInitialized(const std::filesystem::path &Root) {
  return std::filesystem::exists(metaPathFor(Root));
}

bool alfie::vaultHasCredentials(const std::filesystem::path &Root) {
  if (!vaultInitialized(Root))
    return false;
  return readMeta(Root).HasCredentials;
}

void alfie::initVault(const std::filesystem::path &Root,
                      const std::string &Login, SecureBuffer &Passphrase) {
  if (Login.empty())
    throw CryptoError("login must not be empty");
  if (Passphrase.empty())
    throw CryptoError("master password must not be empty");
  if (vaultInitialized(Root))
    throw CryptoError("vault already initialized");

  auto Salt = randomBytes(VaultSaltLen);
  const Argon2Params Params;
  VaultKeys Keys = deriveKeys(Passphrase, Salt, Params);
  const auto PasswordVerifier = hmacHex(Keys.IndexKey, PasswordVerifierLabel);
  const auto LoginVerifier = hmacHex(Keys.IndexKey, LoginVerifierLabel + Login);

  std::filesystem::create_directories(Root);
  // The vault directory is private to this user: record filenames are HMACs,
  // but their count, sizes and timestamps still leak how the vault is used.
  std::filesystem::permissions(Root, std::filesystem::perms::owner_all);
  const auto MetaPath = metaPathFor(Root);
  std::ofstream Out(MetaPath, std::ios::binary | std::ios::trunc);
  if (!Out)
    throw CryptoError("cannot write vault metadata");
  Out << MetaV2 << "\n"
      << hex(Salt.data(), Salt.size()) << "\n"
      << "argon2id m=" << Params.MCostKib << ",t=" << Params.TCost
      << ",p=" << Params.Parallelism << "\n"
      << "login_verifier " << LoginVerifier << "\n"
      << "password_verifier " << PasswordVerifier << "\n";
  Out.flush();
  if (!Out)
    throw CryptoError("cannot write vault metadata");
  std::filesystem::permissions(MetaPath,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write);
}

bool alfie::verifyCredentials(const std::filesystem::path &Root,
                              const std::string &Login,
                              SecureBuffer &Passphrase) {
  const auto Meta = readMeta(Root);
  if (!Meta.HasCredentials) {
    Passphrase.wipe();
    return false;
  }
  VaultKeys Keys = deriveKeys(Passphrase, Meta.Salt, Meta.Params);
  const bool PasswordOk = constantTimeEquals(
      hmacHex(Keys.IndexKey, PasswordVerifierLabel), Meta.PasswordVerifier);
  const bool LoginOk = constantTimeEquals(
      hmacHex(Keys.IndexKey, LoginVerifierLabel + Login), Meta.LoginVerifier);
  return PasswordOk && LoginOk;
}

VaultSession VaultSession::open(const std::filesystem::path &Root,
                                const std::string &Login,
                                SecureBuffer &Passphrase) {
  const auto Meta = readMeta(Root);
  VaultKeys Keys = deriveKeys(Passphrase, Meta.Salt, Meta.Params);
  if (!Meta.HasCredentials)
    throw CryptoError("vault has no credential verifiers");
  const bool PasswordOk = constantTimeEquals(
      hmacHex(Keys.IndexKey, PasswordVerifierLabel), Meta.PasswordVerifier);
  const bool LoginOk = constantTimeEquals(
      hmacHex(Keys.IndexKey, LoginVerifierLabel + Login), Meta.LoginVerifier);
  if (!PasswordOk || !LoginOk)
    throw CryptoError("bad login or master password");
  return VaultSession(Root, std::move(Keys));
}

VaultSession VaultSession::openWithPassword(const std::filesystem::path &Root,
                                            SecureBuffer &Passphrase) {
  const auto Meta = readMeta(Root);
  VaultKeys Keys = deriveKeys(Passphrase, Meta.Salt, Meta.Params);
  // Without this, a wrong master password derives a different index key,
  // computes a record id that happens to address nothing, and surfaces as
  // "record not found" -- exactly the confusion the stored verifiers exist to
  // remove. Legacy V1 vaults carry no verifiers.
  if (Meta.HasCredentials &&
      !constantTimeEquals(hmacHex(Keys.IndexKey, PasswordVerifierLabel),
                          Meta.PasswordVerifier)) {
    throw CryptoError("bad master password");
  }
  return VaultSession(Root, std::move(Keys));
}

std::filesystem::path VaultSession::put(const std::string &Purpose,
                                        const std::string &DomainOrUrl,
                                        const std::string &Account,
                                        const SecureBuffer &Plaintext) {
  const std::string Id =
      recordId(this->Keys.IndexKey, Purpose, DomainOrUrl, Account);
  auto Salt =
      randomBytes(SaltLen); // Reserved for future format agility; authenticated
                            // by the V2 AAD so it cannot be altered in place.
  auto Nonce = randomBytes(NonceLen);
  const auto Aad = recordAad(MagicV2, Id, Salt.data(), Salt.size());
  auto Enc = encryptGcm(this->Keys.RecordKey.data(), Plaintext.data(),
                        Plaintext.size(), Nonce, Aad);

  std::vector<unsigned char> File;
  File.reserve(MagicLen + Salt.size() + Nonce.size() + Enc.size());
  File.insert(File.end(), MagicV2, MagicV2 + MagicLen);
  File.insert(File.end(), Salt.begin(), Salt.end());
  File.insert(File.end(), Nonce.begin(), Nonce.end());
  File.insert(File.end(), Enc.begin(), Enc.end());
  auto Path = pathForId(this->Root, Id);
  writeFile(Path, File);

  // Drop any pre-fix copy of the same record, so a stale ciphertext of an old
  // secret is not left behind in the vault directory.
  const auto Legacy =
      pathForId(this->Root, legacyRecordId(this->Keys.IndexKey, Purpose,
                                           DomainOrUrl, Account));
  if (Legacy != Path) {
    std::error_code Ec;
    std::filesystem::remove(Legacy, Ec);
  }
  return Path;
}

void VaultSession::use(
    const std::string &Purpose, const std::string &DomainOrUrl,
    const std::string &Account,
    const std::function<void(const SecureBuffer &)> &Callback) {
  std::string Id = recordId(this->Keys.IndexKey, Purpose, DomainOrUrl, Account);
  auto Path = pathForId(this->Root, Id);
  if (!std::filesystem::exists(Path)) {
    // Fall back to the pre-fix id so vaults written before the separator fix
    // still resolve.
    const std::string LegacyId =
        legacyRecordId(this->Keys.IndexKey, Purpose, DomainOrUrl, Account);
    const auto LegacyPath = pathForId(this->Root, LegacyId);
    if (!std::filesystem::exists(LegacyPath))
      throw CryptoError("record not found");
    Id = LegacyId;
    Path = LegacyPath;
  }

  auto File = readFile(Path);
  if (File.size() < MagicLen + SaltLen + NonceLen + TagLen)
    throw CryptoError("bad record");

  const char *Magic = nullptr;
  if (std::memcmp(File.data(), MagicV2, MagicLen) == 0)
    Magic = MagicV2;
  else if (std::memcmp(File.data(), MagicV1, MagicLen) == 0)
    Magic = MagicV1;
  else
    throw CryptoError("bad record magic");

  const unsigned char *Salt = File.data() + MagicLen;
  std::vector<unsigned char> Nonce(File.begin() + MagicLen + SaltLen,
                                   File.begin() + MagicLen + SaltLen +
                                       NonceLen);
  std::vector<unsigned char> Enc(File.begin() + MagicLen + SaltLen + NonceLen,
                                 File.end());
  const auto Aad = recordAad(Magic, Id, Salt, SaltLen);
  SecureBuffer Plain = decryptGcm(this->Keys.RecordKey.data(), Enc, Nonce, Aad);
  Callback(Plain);
}

ChunkVault::ChunkVault(std::filesystem::path Root) : Root(std::move(Root)) {}

std::filesystem::path ChunkVault::put(const std::string &Purpose,
                                      const std::string &DomainOrUrl,
                                      const std::string &Account,
                                      SecureBuffer &Passphrase,
                                      const SecureBuffer &Plaintext) {
  return VaultSession::openWithPassword(this->Root, Passphrase)
      .put(Purpose, DomainOrUrl, Account, Plaintext);
}

void ChunkVault::use(
    const std::string &Purpose, const std::string &DomainOrUrl,
    const std::string &Account, SecureBuffer &Passphrase,
    const std::function<void(const SecureBuffer &)> &Callback) {
  VaultSession::openWithPassword(this->Root, Passphrase)
      .use(Purpose, DomainOrUrl, Account, Callback);
}

// --- Test-fixture overloads. See the warning in vault.h.
// ---------------------------------

std::filesystem::path ChunkVault::put(const std::string &Purpose,
                                      const std::string &DomainOrUrl,
                                      const std::string &Account,
                                      const std::string &Passphrase,
                                      const std::string &PlaintextJson) {
  SecureBuffer LockedPassphrase(Passphrase);
  SecureBuffer Plaintext(PlaintextJson);
  return put(Purpose, DomainOrUrl, Account, LockedPassphrase, Plaintext);
}

std::string ChunkVault::get(const std::string &Purpose,
                            const std::string &DomainOrUrl,
                            const std::string &Account,
                            const std::string &Passphrase) {
  std::string Value;
  use(Purpose, DomainOrUrl, Account, Passphrase,
      [&](const SecureBuffer &Secret) { Value = Secret.str(); });
  return Value;
}

void ChunkVault::use(
    const std::string &Purpose, const std::string &DomainOrUrl,
    const std::string &Account, const std::string &Passphrase,
    const std::function<void(const SecureBuffer &)> &Callback) {
  SecureBuffer LockedPassphrase(Passphrase);
  use(Purpose, DomainOrUrl, Account, LockedPassphrase, Callback);
}

void alfie::initVault(const std::filesystem::path &Root,
                      const std::string &Login, const std::string &Passphrase) {
  SecureBuffer LockedPassphrase(Passphrase);
  initVault(Root, Login, LockedPassphrase);
}

bool alfie::verifyCredentials(const std::filesystem::path &Root,
                              const std::string &Login,
                              const std::string &Passphrase) {
  SecureBuffer LockedPassphrase(Passphrase);
  return verifyCredentials(Root, Login, LockedPassphrase);
}
