//===----------------------------------------------------------------------===//
/// \file
/// Exercise vault behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/vault.h"
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string>
#include <type_traits>

using namespace alfie;

static std::string readFile(const std::filesystem::path &P) {
  std::ifstream In(P, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(In)),
                     std::istreambuf_iterator<char>());
}

static std::filesystem::path firstRecordPath(const std::filesystem::path &Dir) {
  for (const auto &Entry :
       std::filesystem::recursive_directory_iterator(Dir / "records")) {
    if (Entry.path().extension() == ".enc")
      return Entry.path();
  }
  assert(false && "expected encrypted record");
  return {};
}

// --- Helpers that reproduce the pre-fix (ALFIECHUNK1) writer, for the
// compatibility test. ---

static std::vector<unsigned char> vaultSalt(const std::filesystem::path &Dir) {
  std::ifstream In(Dir / "vault.meta", std::ios::binary);
  std::string Magic, SaltHex;
  std::getline(In, Magic);
  std::getline(In, SaltHex);
  std::vector<unsigned char> Salt;
  for (size_t I = 0; I + 1 < SaltHex.size(); I += 2)
    Salt.push_back(static_cast<unsigned char>(
        std::stoi(SaltHex.substr(I, 2), nullptr, 16)));
  return Salt;
}

static VaultKeys deriveKeysForVault(const std::filesystem::path &Dir,
                                    SecureBuffer &Passphrase) {
  return deriveKeys(Passphrase, vaultSalt(Dir));
}

static std::string legacyIdFor(const SecureBuffer &IndexKey,
                               const std::string &Purpose,
                               const std::string &Domain,
                               const std::string &Account) {
  const std::string Msg =
      Purpose + normalizeDomain(Domain) + Account; // separators dropped
  unsigned int Len = 0;
  unsigned char Mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), IndexKey.data(), static_cast<int>(IndexKey.size()),
       reinterpret_cast<const unsigned char *>(Msg.data()), Msg.size(), Mac,
       &Len);
  std::string Out;
  char Buf[3];
  for (unsigned int I = 0; I < Len; ++I) {
    std::snprintf(Buf, sizeof(Buf), "%02x", Mac[I]);
    Out += Buf;
  }
  return Out;
}

static void writeLegacyV1Record(const std::filesystem::path &Path,
                                const SecureBuffer &RecordKey,
                                const std::string &Plaintext) {
  const std::string Magic = "ALFIECHUNK1\n";
  std::vector<unsigned char> Salt(16), Nonce(12);
  RAND_bytes(Salt.data(), static_cast<int>(Salt.size()));
  RAND_bytes(Nonce.data(), static_cast<int>(Nonce.size()));

  std::vector<unsigned char> Out(Plaintext.size() + 16);
  EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
  int Len = 0;
  EVP_EncryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN,
                      static_cast<int>(Nonce.size()), nullptr);
  EVP_EncryptInit_ex(Ctx, nullptr, nullptr, RecordKey.data(), Nonce.data());
  EVP_EncryptUpdate(Ctx, nullptr, &Len,
                    reinterpret_cast<const unsigned char *>(Magic.data()),
                    static_cast<int>(Magic.size())); // V1 AAD: the magic only
  EVP_EncryptUpdate(Ctx, Out.data(), &Len,
                    reinterpret_cast<const unsigned char *>(Plaintext.data()),
                    static_cast<int>(Plaintext.size()));
  int Total = Len;
  EVP_EncryptFinal_ex(Ctx, Out.data() + Total, &Len);
  EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16,
                      Out.data() + Plaintext.size());
  EVP_CIPHER_CTX_free(Ctx);

  std::filesystem::create_directories(Path.parent_path());
  std::ofstream F(Path, std::ios::binary | std::ios::trunc);
  F.write(Magic.data(), static_cast<std::streamsize>(Magic.size()));
  F.write(reinterpret_cast<const char *>(Salt.data()),
          static_cast<std::streamsize>(Salt.size()));
  F.write(reinterpret_cast<const char *>(Nonce.data()),
          static_cast<std::streamsize>(Nonce.size()));
  F.write(reinterpret_cast<const char *>(Out.data()),
          static_cast<std::streamsize>(Out.size()));
}

static void testSecureBufferWipes() {
  SecureBuffer Buf("SECRET");
  assert(Buf.str() == "SECRET");
  Buf.wipe();
  for (auto B : Buf.bytes())
    assert(B == 0);
}

static void testSecretTypesAreMoveOnly() {
  static_assert(!std::is_copy_constructible_v<SecureBuffer>);
  static_assert(!std::is_copy_assignable_v<SecureBuffer>);
  static_assert(!std::is_copy_constructible_v<VaultKeys>);
  static_assert(!std::is_copy_assignable_v<VaultKeys>);
}

static void testArgon2idDerivationWipesPassphraseBuffer() {
  SecureBuffer Passphrase("correct horse battery staple");
  auto Keys = deriveKeys(Passphrase, "wipe-test");
  assert(Keys.IndexKey.size() == 32);
  assert(Keys.RecordKey.size() == 32);
  for (auto B : Passphrase.bytes())
    assert(B == 0);
}

static void testRecordIdIsStableAndNotPlaintext() {
  SecureBuffer Passphrase("correct horse battery staple");
  VaultKeys Keys = deriveKeys(Passphrase, "alfie-v1");
  auto Id1 = recordId(Keys.IndexKey, "account", "https://www.example.com",
                      "yuki@example.com");
  auto Id2 =
      recordId(Keys.IndexKey, "account", "example.com", "yuki@example.com");
  assert(Id1 == Id2);
  assert(Id1.find("example") == std::string::npos);
  assert(Id1.find("yuki") == std::string::npos);
  assert(Id1.size() == 64);
}

static void testPutGetOneChunkWithoutPlaintextOnDisk() {
  std::filesystem::path Dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_test";
  std::filesystem::remove_all(Dir);
  std::string Passphrase = "correct horse battery staple";
  initVault(Dir, "yuki", Passphrase);
  ChunkVault Vault(Dir);
  std::string Json =
      R"({"login":"yuki@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

  auto Path =
      Vault.put("account", "example.com", "yuki@example.com", Passphrase, Json);
  assert(std::filesystem::exists(Path));
  assert(Path.string().find("example") == std::string::npos);

  std::string Raw = readFile(Path);
  assert(Raw.find("VERY-SECRET") == std::string::npos);
  assert(Raw.find("yuki@example.com") == std::string::npos);
  assert(Raw.rfind("ALFIECHUNK2\n", 0) == 0);

  auto Out =
      Vault.get("account", "example.com", "yuki@example.com", Passphrase);
  assert(Out == Json);
  std::filesystem::remove_all(Dir);
}

static void testWrongPassphraseFails() {
  std::filesystem::path Dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_wrong_pass";
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "right pass");
  ChunkVault Vault(Dir);
  Vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");
  bool Failed = false;
  try {
    (void)Vault.get("account", "example.com", "u", "wrong pass");
  } catch (const CryptoError &) {
    Failed = true;
  }
  assert(Failed);
  std::filesystem::remove_all(Dir);
}

static void testNewVaultsUseDifferentRandomSalts() {
  auto Base = std::filesystem::temp_directory_path();
  auto A = Base / "alfie_vault_cpp_salt_a";
  auto B = Base / "alfie_vault_cpp_salt_b";
  std::filesystem::remove_all(A);
  std::filesystem::remove_all(B);

  std::string Passphrase = "same passphrase";
  std::string Json = R"({"secret":"same"})";
  initVault(A, "yuki", Passphrase);
  initVault(B, "yuki", Passphrase);
  ChunkVault VaultA(A);
  ChunkVault VaultB(B);
  VaultA.put("account", "example.com", "u", Passphrase, Json);
  VaultB.put("account", "example.com", "u", Passphrase, Json);

  assert(std::filesystem::exists(A / "vault.meta"));
  assert(std::filesystem::exists(B / "vault.meta"));
  assert(readFile(A / "vault.meta") != readFile(B / "vault.meta"));
  assert(firstRecordPath(A).filename() != firstRecordPath(B).filename());
  assert(VaultA.get("account", "example.com", "u", Passphrase) == Json);
  assert(VaultB.get("account", "example.com", "u", Passphrase) == Json);

  std::filesystem::remove_all(A);
  std::filesystem::remove_all(B);
}

static void testRecordCanBeUsedWithoutReturningSecretString() {
  std::filesystem::path Dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_use_record";
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "right pass");
  ChunkVault Vault(Dir);
  Vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");

  size_t SeenSize = 0;
  Vault.use("account", "example.com", "u", "right pass",
            [&](const SecureBuffer &Secret) {
              SeenSize = Secret.size();
              assert(Secret.str() == R"({"secret":"s"})");
            });

  assert(SeenSize == 14);
  std::filesystem::remove_all(Dir);
}

static void testVaultMustBeInitializedBeforeUse() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_uninit";
  std::filesystem::remove_all(Dir);

  // Reading a vault that was never created must fail rather than quietly create
  // one: a typo'd vault path used to become a brand-new empty vault with a
  // fresh salt.
  ChunkVault Vault(Dir);
  bool Threw = false;
  try {
    Vault.get("account", "example.com", "u", "pass");
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw);
  assert(!std::filesystem::exists(Dir / "vault.meta"));
  assert(!vaultInitialized(Dir));

  Threw = false;
  try {
    Vault.put("account", "example.com", "u", "pass", R"({"secret":"s"})");
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw);
  assert(!std::filesystem::exists(Dir / "vault.meta"));
  std::filesystem::remove_all(Dir);
}

static void testInitVaultSetsCredentialsAndIsNotRepeatable() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_init";
  std::filesystem::remove_all(Dir);

  initVault(Dir, "yuki", "master pass");
  assert(vaultInitialized(Dir));
  assert(vaultHasCredentials(Dir));

  // A second init must never re-key a live vault.
  bool Threw = false;
  try {
    initVault(Dir, "someone-else", "other pass");
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw);

  assert(verifyCredentials(Dir, "yuki", "master pass"));
  assert(!verifyCredentials(Dir, "yuki", "wrong pass"));
  assert(!verifyCredentials(Dir, "wrong-login", "master pass"));

  // Neither the login nor the password is recoverable from vault.meta.
  std::string Meta = readFile(Dir / "vault.meta");
  assert(Meta.find("yuki") == std::string::npos);
  assert(Meta.find("master pass") == std::string::npos);
  assert(Meta.find("ALFIEVAULT2") != std::string::npos);

  std::filesystem::remove_all(Dir);
}

static void testInitVaultRejectsEmptyCredentials() {
  auto Base =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_init_empty";
  std::filesystem::remove_all(Base);

  bool Threw = false;
  try {
    initVault(Base / "a", "", "pass");
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw);

  Threw = false;
  try {
    initVault(Base / "b", "yuki", "");
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw);
  std::filesystem::remove_all(Base);
}

// A vault written before the record-format fix must stay readable: V1 records
// live at the old (separator-less) record id and authenticate only the magic.
// Rewriting one upgrades it to V2 at the new id and removes the stale V1 file.
static void testLegacyV1RecordsAreStillReadable() {
  std::filesystem::path Dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_legacy_v1";
  std::filesystem::remove_all(Dir);
  const std::string Passphrase = "correct horse battery staple";
  const std::string Json = R"({"secret":"legacy-value"})";
  initVault(Dir, "yuki", Passphrase);

  // Hand-build a V1 record the way the pre-fix code did: id over the
  // concatenated fields with no separators, AAD over the magic alone.
  SecureBuffer Locked(Passphrase);
  VaultKeys Keys = deriveKeysForVault(Dir, Locked);
  const std::string LegacyId =
      legacyIdFor(Keys.IndexKey, "account", "example.com", "u");
  const auto Path = Dir / "records" / LegacyId.substr(0, 2) /
                    LegacyId.substr(2, 2) / (LegacyId + ".enc");
  writeLegacyV1Record(Path, Keys.RecordKey, Json);

  ChunkVault Vault(Dir);
  assert(Vault.get("account", "example.com", "u", Passphrase) == Json);

  // Rewriting moves it to the V2 id and drops the V1 file.
  auto NewPath = Vault.put("account", "example.com", "u", Passphrase, Json);
  assert(NewPath != Path);
  assert(!std::filesystem::exists(Path));
  assert(readFile(NewPath).rfind("ALFIECHUNK2\n", 0) == 0);
  assert(Vault.get("account", "example.com", "u", Passphrase) == Json);
  std::filesystem::remove_all(Dir);
}

// Distinct (purpose, domain, account) triples must never collide. Before the
// fix the separators were dropped, so ("acc","ountX") and ("account","X")
// hashed to the same record id.
static void testRecordIdsAreDomainSeparated() {
  SecureBuffer Passphrase("correct horse battery staple");
  VaultKeys Keys = deriveKeys(Passphrase, "separator-test");
  auto A = recordId(Keys.IndexKey, "acc", "example.com", "ountX");
  auto B = recordId(Keys.IndexKey, "account", "example.com", "X");
  assert(A != B);
  auto C = recordId(Keys.IndexKey, "account", "example.com", "");
  auto D = recordId(Keys.IndexKey, "account", "example.co", "m");
  assert(C != D);
}

// The Argon2id cost line in vault.meta must be load-bearing, not decorative: if
// it were ignored, a future build that raised the cost would silently derive a
// different key for every existing vault. Changing the recorded cost must
// change the derived key.
static void testStoredArgon2ParamsAreUsed() {
  std::filesystem::path Dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_params";
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "master pass");
  assert(verifyCredentials(Dir, "yuki", "master pass"));

  // Rewrite only the cost line, leaving salt and verifiers intact.
  std::string Meta = readFile(Dir / "vault.meta");
  const auto Start = Meta.find("argon2id ");
  const auto End = Meta.find('\n', Start);
  assert(Start != std::string::npos && End != std::string::npos);
  Meta.replace(Start, End - Start, "argon2id m=32768,t=2,p=1");
  {
    std::ofstream Out(Dir / "vault.meta", std::ios::binary | std::ios::trunc);
    Out << Meta;
  }

  // A different cost derives a different key, so the verifiers no longer match.
  assert(!verifyCredentials(Dir, "yuki", "master pass"));
  std::filesystem::remove_all(Dir);
}

static void testVaultDirectoriesArePrivateToTheOwner() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_perms";
  std::filesystem::remove_all(Dir);
  SecureBuffer Passphrase("correct horse battery staple");
  initVault(Dir, "yuki", Passphrase);

  const auto OwnerOnly = [](const std::filesystem::path &P) {
    const auto Perms = std::filesystem::status(P).permissions();
    return (Perms & (std::filesystem::perms::group_all |
                     std::filesystem::perms::others_all)) ==
           std::filesystem::perms::none;
  };
  assert(OwnerOnly(Dir));
  assert(OwnerOnly(Dir / "vault.meta"));

  {
    SecureBuffer OpenPass("correct horse battery staple");
    VaultSession Session = VaultSession::open(Dir, "yuki", OpenPass);
    Session.put("account", "example.com", "u",
                SecureBuffer(std::string(R"({"secret":"s"})")));
  }
  for (const auto &Entry : std::filesystem::recursive_directory_iterator(Dir))
    assert(OwnerOnly(Entry.path()));

  std::filesystem::remove_all(Dir);
}

int main() {
  testVaultDirectoriesArePrivateToTheOwner();
  testVaultMustBeInitializedBeforeUse();
  testInitVaultSetsCredentialsAndIsNotRepeatable();
  testInitVaultRejectsEmptyCredentials();
  testSecureBufferWipes();
  testSecretTypesAreMoveOnly();
  testArgon2idDerivationWipesPassphraseBuffer();
  testRecordIdIsStableAndNotPlaintext();
  testPutGetOneChunkWithoutPlaintextOnDisk();
  testLegacyV1RecordsAreStillReadable();
  testRecordIdsAreDomainSeparated();
  testStoredArgon2ParamsAreUsed();
  testNewVaultsUseDifferentRandomSalts();
  testRecordCanBeUsedWithoutReturningSecretString();
  testWrongPassphraseFails();
  std::cout << "C++ vault tests passed\n";
}
