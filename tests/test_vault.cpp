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

static std::string readFile(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

static std::filesystem::path firstRecordPath(const std::filesystem::path &dir) {
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  assert(false && "expected encrypted record");
  return {};
}

// --- Helpers that reproduce the pre-fix (ALFIECHUNK1) writer, for the
// compatibility test. ---

static std::vector<unsigned char> vaultSalt(const std::filesystem::path &dir) {
  std::ifstream in(dir / "vault.meta", std::ios::binary);
  std::string magic, saltHex;
  std::getline(in, magic);
  std::getline(in, saltHex);
  std::vector<unsigned char> salt;
  for (size_t i = 0; i + 1 < saltHex.size(); i += 2)
    salt.push_back(static_cast<unsigned char>(
        std::stoi(saltHex.substr(i, 2), nullptr, 16)));
  return salt;
}

static VaultKeys deriveKeysForVault(const std::filesystem::path &dir,
                                    SecureBuffer &passphrase) {
  return deriveKeys(passphrase, vaultSalt(dir));
}

static std::string legacyIdFor(const SecureBuffer &indexKey,
                               const std::string &purpose,
                               const std::string &domain,
                               const std::string &account) {
  const std::string msg =
      purpose + normalizeDomain(domain) + account; // separators dropped
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), indexKey.data(), static_cast<int>(indexKey.size()),
       reinterpret_cast<const unsigned char *>(msg.data()), msg.size(), mac,
       &len);
  std::string out;
  char buf[3];
  for (unsigned int i = 0; i < len; ++i) {
    std::snprintf(buf, sizeof(buf), "%02x", mac[i]);
    out += buf;
  }
  return out;
}

static void writeLegacyV1Record(const std::filesystem::path &path,
                                const SecureBuffer &recordKey,
                                const std::string &plaintext) {
  const std::string magic = "ALFIECHUNK1\n";
  std::vector<unsigned char> salt(16), nonce(12);
  RAND_bytes(salt.data(), static_cast<int>(salt.size()));
  RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));

  std::vector<unsigned char> out(plaintext.size() + 16);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                      static_cast<int>(nonce.size()), nullptr);
  EVP_EncryptInit_ex(ctx, nullptr, nullptr, recordKey.data(), nonce.data());
  EVP_EncryptUpdate(ctx, nullptr, &len,
                    reinterpret_cast<const unsigned char *>(magic.data()),
                    static_cast<int>(magic.size())); // V1 AAD: the magic only
  EVP_EncryptUpdate(ctx, out.data(), &len,
                    reinterpret_cast<const unsigned char *>(plaintext.data()),
                    static_cast<int>(plaintext.size()));
  int total = len;
  EVP_EncryptFinal_ex(ctx, out.data() + total, &len);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                      out.data() + plaintext.size());
  EVP_CIPHER_CTX_free(ctx);

  std::filesystem::create_directories(path.parent_path());
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(magic.data(), static_cast<std::streamsize>(magic.size()));
  f.write(reinterpret_cast<const char *>(salt.data()),
          static_cast<std::streamsize>(salt.size()));
  f.write(reinterpret_cast<const char *>(nonce.data()),
          static_cast<std::streamsize>(nonce.size()));
  f.write(reinterpret_cast<const char *>(out.data()),
          static_cast<std::streamsize>(out.size()));
}

static void testSecureBufferWipes() {
  SecureBuffer buf("SECRET");
  assert(buf.str() == "SECRET");
  buf.wipe();
  for (auto b : buf.bytes())
    assert(b == 0);
}

static void testSecretTypesAreMoveOnly() {
  static_assert(!std::is_copy_constructible_v<SecureBuffer>);
  static_assert(!std::is_copy_assignable_v<SecureBuffer>);
  static_assert(!std::is_copy_constructible_v<VaultKeys>);
  static_assert(!std::is_copy_assignable_v<VaultKeys>);
}

static void testArgon2idDerivationWipesPassphraseBuffer() {
  SecureBuffer passphrase("correct horse battery staple");
  auto keys = deriveKeys(passphrase, "wipe-test");
  assert(keys.indexKey.size() == 32);
  assert(keys.recordKey.size() == 32);
  for (auto b : passphrase.bytes())
    assert(b == 0);
}

static void testRecordIdIsStableAndNotPlaintext() {
  SecureBuffer passphrase("correct horse battery staple");
  VaultKeys keys = deriveKeys(passphrase, "alfie-v1");
  auto id1 = recordId(keys.indexKey, "account", "https://www.example.com",
                      "yuki@example.com");
  auto id2 =
      recordId(keys.indexKey, "account", "example.com", "yuki@example.com");
  assert(id1 == id2);
  assert(id1.find("example") == std::string::npos);
  assert(id1.find("yuki") == std::string::npos);
  assert(id1.size() == 64);
}

static void testPutGetOneChunkWithoutPlaintextOnDisk() {
  std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_test";
  std::filesystem::remove_all(dir);
  std::string passphrase = "correct horse battery staple";
  initVault(dir, "yuki", passphrase);
  ChunkVault vault(dir);
  std::string json =
      R"({"login":"yuki@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

  auto path =
      vault.put("account", "example.com", "yuki@example.com", passphrase, json);
  assert(std::filesystem::exists(path));
  assert(path.string().find("example") == std::string::npos);

  std::string raw = readFile(path);
  assert(raw.find("VERY-SECRET") == std::string::npos);
  assert(raw.find("yuki@example.com") == std::string::npos);
  assert(raw.rfind("ALFIECHUNK2\n", 0) == 0);

  auto out =
      vault.get("account", "example.com", "yuki@example.com", passphrase);
  assert(out == json);
  std::filesystem::remove_all(dir);
}

static void testWrongPassphraseFails() {
  std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_wrong_pass";
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "right pass");
  ChunkVault vault(dir);
  vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");
  bool failed = false;
  try {
    (void)vault.get("account", "example.com", "u", "wrong pass");
  } catch (const CryptoError &) {
    failed = true;
  }
  assert(failed);
  std::filesystem::remove_all(dir);
}

static void testNewVaultsUseDifferentRandomSalts() {
  auto base = std::filesystem::temp_directory_path();
  auto a = base / "alfie_vault_cpp_salt_a";
  auto b = base / "alfie_vault_cpp_salt_b";
  std::filesystem::remove_all(a);
  std::filesystem::remove_all(b);

  std::string passphrase = "same passphrase";
  std::string json = R"({"secret":"same"})";
  initVault(a, "yuki", passphrase);
  initVault(b, "yuki", passphrase);
  ChunkVault vaultA(a);
  ChunkVault vaultB(b);
  vaultA.put("account", "example.com", "u", passphrase, json);
  vaultB.put("account", "example.com", "u", passphrase, json);

  assert(std::filesystem::exists(a / "vault.meta"));
  assert(std::filesystem::exists(b / "vault.meta"));
  assert(readFile(a / "vault.meta") != readFile(b / "vault.meta"));
  assert(firstRecordPath(a).filename() != firstRecordPath(b).filename());
  assert(vaultA.get("account", "example.com", "u", passphrase) == json);
  assert(vaultB.get("account", "example.com", "u", passphrase) == json);

  std::filesystem::remove_all(a);
  std::filesystem::remove_all(b);
}

static void testRecordCanBeUsedWithoutReturningSecretString() {
  std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_use_record";
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "right pass");
  ChunkVault vault(dir);
  vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");

  size_t seenSize = 0;
  vault.use("account", "example.com", "u", "right pass",
            [&](const SecureBuffer &secret) {
              seenSize = secret.size();
              assert(secret.str() == R"({"secret":"s"})");
            });

  assert(seenSize == 14);
  std::filesystem::remove_all(dir);
}

static void testVaultMustBeInitializedBeforeUse() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_uninit";
  std::filesystem::remove_all(dir);

  // Reading a vault that was never created must fail rather than quietly create
  // one: a typo'd vault path used to become a brand-new empty vault with a
  // fresh salt.
  ChunkVault vault(dir);
  bool threw = false;
  try {
    vault.get("account", "example.com", "u", "pass");
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw);
  assert(!std::filesystem::exists(dir / "vault.meta"));
  assert(!vaultInitialized(dir));

  threw = false;
  try {
    vault.put("account", "example.com", "u", "pass", R"({"secret":"s"})");
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw);
  assert(!std::filesystem::exists(dir / "vault.meta"));
  std::filesystem::remove_all(dir);
}

static void testInitVaultSetsCredentialsAndIsNotRepeatable() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_init";
  std::filesystem::remove_all(dir);

  initVault(dir, "yuki", "master pass");
  assert(vaultInitialized(dir));
  assert(vaultHasCredentials(dir));

  // A second init must never re-key a live vault.
  bool threw = false;
  try {
    initVault(dir, "someone-else", "other pass");
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw);

  assert(verifyCredentials(dir, "yuki", "master pass"));
  assert(!verifyCredentials(dir, "yuki", "wrong pass"));
  assert(!verifyCredentials(dir, "wrong-login", "master pass"));

  // Neither the login nor the password is recoverable from vault.meta.
  std::string meta = readFile(dir / "vault.meta");
  assert(meta.find("yuki") == std::string::npos);
  assert(meta.find("master pass") == std::string::npos);
  assert(meta.find("ALFIEVAULT2") != std::string::npos);

  std::filesystem::remove_all(dir);
}

static void testInitVaultRejectsEmptyCredentials() {
  auto base =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_init_empty";
  std::filesystem::remove_all(base);

  bool threw = false;
  try {
    initVault(base / "a", "", "pass");
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw);

  threw = false;
  try {
    initVault(base / "b", "yuki", "");
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw);
  std::filesystem::remove_all(base);
}

// A vault written before the record-format fix must stay readable: V1 records
// live at the old (separator-less) record id and authenticate only the magic.
// Rewriting one upgrades it to V2 at the new id and removes the stale V1 file.
static void testLegacyV1RecordsAreStillReadable() {
  std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_legacy_v1";
  std::filesystem::remove_all(dir);
  const std::string passphrase = "correct horse battery staple";
  const std::string json = R"({"secret":"legacy-value"})";
  initVault(dir, "yuki", passphrase);

  // Hand-build a V1 record the way the pre-fix code did: id over the
  // concatenated fields with no separators, AAD over the magic alone.
  SecureBuffer locked(passphrase);
  VaultKeys keys = deriveKeysForVault(dir, locked);
  const std::string legacyId =
      legacyIdFor(keys.indexKey, "account", "example.com", "u");
  const auto path = dir / "records" / legacyId.substr(0, 2) /
                    legacyId.substr(2, 2) / (legacyId + ".enc");
  writeLegacyV1Record(path, keys.recordKey, json);

  ChunkVault vault(dir);
  assert(vault.get("account", "example.com", "u", passphrase) == json);

  // Rewriting moves it to the V2 id and drops the V1 file.
  auto newPath = vault.put("account", "example.com", "u", passphrase, json);
  assert(newPath != path);
  assert(!std::filesystem::exists(path));
  assert(readFile(newPath).rfind("ALFIECHUNK2\n", 0) == 0);
  assert(vault.get("account", "example.com", "u", passphrase) == json);
  std::filesystem::remove_all(dir);
}

// Distinct (purpose, domain, account) triples must never collide. Before the
// fix the separators were dropped, so ("acc","ountX") and ("account","X")
// hashed to the same record id.
static void testRecordIdsAreDomainSeparated() {
  SecureBuffer passphrase("correct horse battery staple");
  VaultKeys keys = deriveKeys(passphrase, "separator-test");
  auto a = recordId(keys.indexKey, "acc", "example.com", "ountX");
  auto b = recordId(keys.indexKey, "account", "example.com", "X");
  assert(a != b);
  auto c = recordId(keys.indexKey, "account", "example.com", "");
  auto d = recordId(keys.indexKey, "account", "example.co", "m");
  assert(c != d);
}

// The Argon2id cost line in vault.meta must be load-bearing, not decorative: if
// it were ignored, a future build that raised the cost would silently derive a
// different key for every existing vault. Changing the recorded cost must
// change the derived key.
static void testStoredArgon2ParamsAreUsed() {
  std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "alfie_vault_cpp_params";
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "master pass");
  assert(verifyCredentials(dir, "yuki", "master pass"));

  // Rewrite only the cost line, leaving salt and verifiers intact.
  std::string meta = readFile(dir / "vault.meta");
  const auto start = meta.find("argon2id ");
  const auto end = meta.find('\n', start);
  assert(start != std::string::npos && end != std::string::npos);
  meta.replace(start, end - start, "argon2id m=32768,t=2,p=1");
  {
    std::ofstream out(dir / "vault.meta", std::ios::binary | std::ios::trunc);
    out << meta;
  }

  // A different cost derives a different key, so the verifiers no longer match.
  assert(!verifyCredentials(dir, "yuki", "master pass"));
  std::filesystem::remove_all(dir);
}

static void testVaultDirectoriesArePrivateToTheOwner() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_perms";
  std::filesystem::remove_all(dir);
  SecureBuffer passphrase("correct horse battery staple");
  initVault(dir, "yuki", passphrase);

  const auto ownerOnly = [](const std::filesystem::path &p) {
    const auto perms = std::filesystem::status(p).permissions();
    return (perms & (std::filesystem::perms::group_all |
                     std::filesystem::perms::others_all)) ==
           std::filesystem::perms::none;
  };
  assert(ownerOnly(dir));
  assert(ownerOnly(dir / "vault.meta"));

  {
    SecureBuffer openPass("correct horse battery staple");
    VaultSession session = VaultSession::open(dir, "yuki", openPass);
    session.put("account", "example.com", "u",
                SecureBuffer(std::string(R"({"secret":"s"})")));
  }
  for (const auto &entry : std::filesystem::recursive_directory_iterator(dir))
    assert(ownerOnly(entry.path()));

  std::filesystem::remove_all(dir);
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
