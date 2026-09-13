//===----------------------------------------------------------------------===//
/// \file
/// Exercise vault behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/vault.h"
#include <catch_amalgamated.hpp>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

using namespace alfie;

static const char *kPassphrase = "correct horse battery staple";

static std::string readFile(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

static std::filesystem::path firstRecordPath(const std::filesystem::path &dir) {
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  FAIL("expected an encrypted record under " << dir);
  return {};
}

static bool ownerOnly(const std::filesystem::path &path) {
  const std::filesystem::perms perms =
      std::filesystem::status(path).permissions();
  return (perms & (std::filesystem::perms::group_all |
                   std::filesystem::perms::others_all)) ==
         std::filesystem::perms::none;
}

/// A unique temp root per case. Unique rather than a fixed name under /tmp so
/// that a failed run cannot leave state that changes the next run's result.
struct VaultDir {
  std::filesystem::path root;
  std::filesystem::path path;

  VaultDir() {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "alfie-vault-XXXXXX")
            .string();
    REQUIRE(mkdtemp(pattern.data()) != nullptr);
    this->root = pattern;
    this->path = this->root / "vault";
  }

  ~VaultDir() {
    std::error_code ec;
    std::filesystem::remove_all(this->root, ec);
  }

  VaultDir(const VaultDir &) = delete;
  VaultDir &operator=(const VaultDir &) = delete;
};

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

TEST_CASE("A SecureBuffer wipes on demand", "[memory][buffer]") {
  SecureBuffer buf("SECRET");
  REQUIRE(buf.str() == "SECRET");

  buf.wipe();

  CHECK_THAT(
      buf.bytes(),
      Catch::Matchers::AllMatch(Catch::Matchers::Predicate<unsigned char>(
          [](unsigned char byte) { return byte == 0; }, "is zero")));
}

TEST_CASE("Secret types are move-only", "[memory][types]") {
  // A copy would put a second, unwiped image of a secret on the heap.
  STATIC_REQUIRE(!std::is_copy_constructible_v<SecureBuffer>);
  STATIC_REQUIRE(!std::is_copy_assignable_v<SecureBuffer>);
  STATIC_REQUIRE(!std::is_copy_constructible_v<VaultKeys>);
  STATIC_REQUIRE(!std::is_copy_assignable_v<VaultKeys>);
}

TEST_CASE("Argon2id derivation wipes the passphrase buffer", "[kdf]") {
  SecureBuffer passphrase(kPassphrase);

  const VaultKeys keys = deriveKeys(passphrase, "wipe-test");

  CHECK(keys.indexKey.size() == 32);
  CHECK(keys.recordKey.size() == 32);
  CHECK_THAT(
      passphrase.bytes(),
      Catch::Matchers::AllMatch(Catch::Matchers::Predicate<unsigned char>(
          [](unsigned char byte) { return byte == 0; }, "is zero")));
}

TEST_CASE("A record id is stable and reveals nothing", "[record][id]") {
  SecureBuffer passphrase(kPassphrase);
  const VaultKeys keys = deriveKeys(passphrase, "alfie-v1");

  const std::string fromUrl = recordId(
      keys.indexKey, "account", "https://www.example.com", "yuki@example.com");
  const std::string fromDomain =
      recordId(keys.indexKey, "account", "example.com", "yuki@example.com");

  CHECK(fromUrl == fromDomain);
  CHECK(fromUrl.size() == 64);
  CHECK_THAT(fromUrl, !Catch::Matchers::ContainsSubstring("example"));
  CHECK_THAT(fromUrl, !Catch::Matchers::ContainsSubstring("yuki"));
}

TEST_CASE("Record ids are domain-separated", "[record][id]") {
  SecureBuffer passphrase(kPassphrase);
  const VaultKeys keys = deriveKeys(passphrase, "separator-test");

  // Before the fix the separators were dropped, so ("acc", "ountX") and
  // ("account", "X") hashed to the same record id.
  CHECK(recordId(keys.indexKey, "acc", "example.com", "ountX") !=
        recordId(keys.indexKey, "account", "example.com", "X"));
  CHECK(recordId(keys.indexKey, "account", "example.com", "") !=
        recordId(keys.indexKey, "account", "example.co", "m"));
}

TEST_CASE_METHOD(VaultDir, "A record round-trips with no plaintext on disk",
                 "[record][roundtrip]") {
  initVault(this->path, "yuki", kPassphrase);
  ChunkVault vault(this->path);
  const std::string json =
      R"({"login":"yuki@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

  const std::filesystem::path record = vault.put(
      "account", "example.com", "yuki@example.com", kPassphrase, json);

  REQUIRE(std::filesystem::exists(record));
  CHECK_THAT(record.string(), !Catch::Matchers::ContainsSubstring("example"));

  const std::string raw = readFile(record);
  CHECK_THAT(raw, !Catch::Matchers::ContainsSubstring("VERY-SECRET"));
  CHECK_THAT(raw, !Catch::Matchers::ContainsSubstring("yuki@example.com"));
  CHECK_THAT(raw, Catch::Matchers::StartsWith("ALFIECHUNK2\n"));
  CHECK(vault.get("account", "example.com", "yuki@example.com", kPassphrase) ==
        json);
}

TEST_CASE_METHOD(VaultDir, "A wrong passphrase does not open a record",
                 "[record][auth]") {
  initVault(this->path, "yuki", "right passphrase");
  ChunkVault vault(this->path);
  vault.put("account", "example.com", "u", "right passphrase",
            R"({"secret":"s"})");

  CHECK_THROWS_AS(vault.get("account", "example.com", "u", "wrong pass"),
                  CryptoError);
}

TEST_CASE_METHOD(VaultDir, "A record can be used without returning a string",
                 "[record][use]") {
  initVault(this->path, "yuki", "right passphrase");
  ChunkVault vault(this->path);
  vault.put("account", "example.com", "u", "right passphrase",
            R"({"secret":"s"})");

  size_t seenSize = 0;
  vault.use("account", "example.com", "u", "right passphrase",
            [&](const SecureBuffer &secret) {
              seenSize = secret.size();
              CHECK(secret.str() == R"({"secret":"s"})");
            });

  CHECK(seenSize == 14);
}

TEST_CASE_METHOD(VaultDir, "Two vaults with one passphrase share nothing",
                 "[vault][salt]") {
  const std::filesystem::path a = this->root / "a";
  const std::filesystem::path b = this->root / "b";
  const std::string json = R"({"secret":"same"})";
  initVault(a, "yuki", kPassphrase);
  initVault(b, "yuki", kPassphrase);
  ChunkVault vaultA(a);
  ChunkVault vaultB(b);

  vaultA.put("account", "example.com", "u", kPassphrase, json);
  vaultB.put("account", "example.com", "u", kPassphrase, json);

  // Each vault has its own random salt, so the same passphrase and the same
  // record name still produce different keys and different record ids.
  CHECK(readFile(a / "vault.meta") != readFile(b / "vault.meta"));
  CHECK(firstRecordPath(a).filename() != firstRecordPath(b).filename());
  CHECK(vaultA.get("account", "example.com", "u", kPassphrase) == json);
  CHECK(vaultB.get("account", "example.com", "u", kPassphrase) == json);
}

TEST_CASE_METHOD(VaultDir, "A vault never springs into existence",
                 "[vault][init]") {
  // Reading a vault that was never created must fail rather than quietly
  // create one: a typo'd vault path used to become a brand-new empty vault
  // with a fresh salt.
  ChunkVault vault(this->path);

  SECTION("reading an absent vault throws") {
    CHECK_THROWS_AS(vault.get("account", "example.com", "u", "pass"),
                    CryptoError);
  }

  SECTION("writing to an absent vault throws") {
    CHECK_THROWS_AS(
        vault.put("account", "example.com", "u", "pass", R"({"secret":"s"})"),
        CryptoError);
  }

  CHECK_FALSE(std::filesystem::exists(this->path / "vault.meta"));
  CHECK_FALSE(vaultInitialized(this->path));
}

TEST_CASE_METHOD(VaultDir, "Init sets credentials and cannot be repeated",
                 "[vault][init]") {
  initVault(this->path, "yuki", "master passphrase");

  CHECK(vaultInitialized(this->path));
  CHECK(vaultHasCredentials(this->path));

  SECTION("a second init must never re-key a live vault") {
    CHECK_THROWS_AS(initVault(this->path, "someone-else", "other passphrase"),
                    CryptoError);
  }

  SECTION("both the login and the password are checked") {
    CHECK(verifyCredentials(this->path, "yuki", "master passphrase"));
    CHECK_FALSE(verifyCredentials(this->path, "yuki", "wrong pass"));
    CHECK_FALSE(
        verifyCredentials(this->path, "wrong-login", "master passphrase"));
  }

  SECTION("neither credential is recoverable from vault.meta") {
    const std::string meta = readFile(this->path / "vault.meta");
    CHECK_THAT(meta, !Catch::Matchers::ContainsSubstring("yuki"));
    CHECK_THAT(meta, !Catch::Matchers::ContainsSubstring("master passphrase"));
    CHECK_THAT(meta, Catch::Matchers::ContainsSubstring("ALFIEVAULT2"));
  }
}

TEST_CASE_METHOD(VaultDir, "Init rejects empty credentials", "[vault][init]") {
  CHECK_THROWS_AS(initVault(this->path / "a", "", "long enough passphrase"),
                  CryptoError);
  CHECK_THROWS_AS(initVault(this->path / "b", "yuki", ""), CryptoError);
}

TEST_CASE_METHOD(VaultDir, "Init refuses a master password below the floor",
                 "[vault][init]") {
  // The floor belongs here rather than beside the HTTPS form: the CLI creates
  // vaults too, and a vault's master password can never be changed afterwards,
  // so this is the only moment a hopeless one can be refused.
  const std::string tooShort(kMinimumMasterPasswordLength - 1, 'a');
  const std::string justLong(kMinimumMasterPasswordLength, 'a');

  CHECK_THROWS_AS(initVault(this->path / "short", "yuki", tooShort),
                  CryptoError);
  CHECK_FALSE(vaultInitialized(this->path / "short"));

  CHECK_NOTHROW(initVault(this->path / "ok", "yuki", justLong));
  CHECK(verifyCredentials(this->path / "ok", "yuki", justLong));
}

TEST_CASE_METHOD(VaultDir, "The stored Argon2id cost is used", "[vault][kdf]") {
  initVault(this->path, "yuki", "master passphrase");
  REQUIRE(verifyCredentials(this->path, "yuki", "master passphrase"));

  // The cost line in vault.meta must be load-bearing, not decorative: if it
  // were ignored, a future build that raised the cost would silently derive a
  // different key for every existing vault. Rewrite only the cost line,
  // leaving salt and verifiers intact.
  std::string meta = readFile(this->path / "vault.meta");
  const size_t start = meta.find("argon2id ");
  const size_t end = meta.find('\n', start);
  REQUIRE(start != std::string::npos);
  REQUIRE(end != std::string::npos);
  meta.replace(start, end - start, "argon2id m=32768,t=2,p=1");
  {
    std::ofstream out(this->path / "vault.meta",
                      std::ios::binary | std::ios::trunc);
    out << meta;
  }

  // A different cost derives a different key, so the verifiers no longer
  // match.
  CHECK_FALSE(verifyCredentials(this->path, "yuki", "master passphrase"));
}

TEST_CASE_METHOD(VaultDir, "Legacy V1 records stay readable and upgrade",
                 "[record][compat]") {
  const std::string json = R"({"secret":"legacy-value"})";
  initVault(this->path, "yuki", kPassphrase);

  // Hand-build a V1 record the way the pre-fix code did: id over the
  // concatenated fields with no separators, AAD over the magic alone.
  SecureBuffer locked(kPassphrase);
  const VaultKeys keys = deriveKeysForVault(this->path, locked);
  const std::string legacyId =
      legacyIdFor(keys.indexKey, "account", "example.com", "u");
  const std::filesystem::path legacyPath =
      this->path / "records" / legacyId.substr(0, 2) / legacyId.substr(2, 2) /
      (legacyId + ".enc");
  writeLegacyV1Record(legacyPath, keys.recordKey, json);

  ChunkVault vault(this->path);
  REQUIRE(vault.get("account", "example.com", "u", kPassphrase) == json);

  // Rewriting moves it to the V2 id and drops the V1 file.
  const std::filesystem::path upgraded =
      vault.put("account", "example.com", "u", kPassphrase, json);

  CHECK(upgraded != legacyPath);
  CHECK_FALSE(std::filesystem::exists(legacyPath));
  CHECK_THAT(readFile(upgraded), Catch::Matchers::StartsWith("ALFIECHUNK2\n"));
  CHECK(vault.get("account", "example.com", "u", kPassphrase) == json);
}

TEST_CASE_METHOD(VaultDir, "Every vault file is private to the owner",
                 "[vault][permissions]") {
  SecureBuffer passphrase(kPassphrase);
  initVault(this->path, "yuki", passphrase);

  CHECK(ownerOnly(this->path));
  CHECK(ownerOnly(this->path / "vault.meta"));

  {
    SecureBuffer openPass(kPassphrase);
    VaultSession session = VaultSession::open(this->path, "yuki", openPass);
    session.put("account", "example.com", "u",
                SecureBuffer(std::string(R"({"secret":"s"})")));
  }

  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(this->path)) {
    CAPTURE(entry.path().string());
    CHECK(ownerOnly(entry.path()));
  }
}

TEST_CASE_METHOD(VaultDir, "A record is replaced atomically, not truncated",
                 "[vault][durability]") {
  initVault(this->path, "yuki", kPassphrase);
  ChunkVault vault(this->path);
  const auto record = vault.put("account", "example.com", "u", kPassphrase,
                                R"({"secret":"first"})");

  struct stat before{};
  REQUIRE(::stat(record.c_str(), &before) == 0);

  // A record is the one thing in this vault that cannot be regenerated, so
  // re-storing one must publish the new ciphertext with rename(2) rather than
  // truncate the old one in place: a crash between the truncate and the last
  // write would destroy the only copy. A fresh inode is the evidence that the
  // replacement went through a temporary file.
  REQUIRE(vault.put("account", "example.com", "u", kPassphrase,
                    R"({"secret":"second"})") == record);
  struct stat after{};
  REQUIRE(::stat(record.c_str(), &after) == 0);
  CHECK(before.st_ino != after.st_ino);

  CHECK(vault.get("account", "example.com", "u", kPassphrase) ==
        R"({"secret":"second"})");

  // Nothing of the temporary survives the rename.
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(this->path))
    CHECK(entry.path().extension() != ".tmp");
}
