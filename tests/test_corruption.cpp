//===----------------------------------------------------------------------===//
/// \file
/// Exercise corruption behavior and failure paths.
//===----------------------------------------------------------------------===//

// Corruption and fuzz coverage for encrypted chunks.
//
// The rule under test is simple and absolute: a record that has been altered in
// any way must fail authentication. It must never decrypt to something other
// than what was stored, and it must never decrypt to a *different* record's
// contents.
#include "../src/vault.h"
#include <catch_amalgamated.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <unistd.h>
#include <vector>

using namespace alfie;

static constexpr size_t kMagicLen = 12;
static constexpr size_t kSaltLen = 16;
static constexpr size_t kNonceLen = 12;
static constexpr size_t kTagLen = 16;

static const char *kPassphrase = "correct horse battery staple";
static const char *kPayload =
    R"({"login":"yuki@example.com","secret":"hunter2-hunter2"})";

static std::filesystem::path onlyRecord(const std::filesystem::path &vaultDir) {
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(vaultDir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  FAIL("expected exactly one encrypted record");
  return {};
}

static std::vector<unsigned char> readBytes(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static void writeBytes(const std::filesystem::path &path,
                       const std::vector<unsigned char> &data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

/// What one attempt to read a record produced: whether the vault refused it,
/// and anything it handed back if it did not.
struct UseResult {
  bool refused = false;
  std::string recovered;
};

static UseResult tryUse(VaultSession &session, const std::string &account) {
  UseResult result;
  try {
    session.use(
        "account", "example.com", account,
        [&](const SecureBuffer &secret) { result.recovered = secret.str(); });
  } catch (const CryptoError &) {
    result.refused = true;
  }
  return result;
}

/// One vault holding one record, plus a pristine copy of the record bytes.
///
/// The session is opened once and reused: at 64 MiB / t=3 per Argon2id call,
/// re-deriving for every corruption case would make this test take minutes.
struct OneRecord {
  std::filesystem::path dir;
  std::filesystem::path record;
  std::vector<unsigned char> original;
  VaultSession session;

  OneRecord() : dir(makeDir()), session(openSession(this->dir)) {
    this->record = onlyRecord(this->dir);
    this->original = readBytes(this->record);
  }

  ~OneRecord() {
    std::error_code ec;
    std::filesystem::remove_all(this->dir, ec);
  }

  OneRecord(const OneRecord &) = delete;
  OneRecord &operator=(const OneRecord &) = delete;

  /// Put the untouched record back after a mutation.
  void restore() const { writeBytes(this->record, this->original); }

  UseResult use() { return tryUse(this->session, "u"); }

private:
  static std::filesystem::path makeDir() {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "alfie-corruption-XXXXXX")
            .string();
    REQUIRE(mkdtemp(pattern.data()) != nullptr);
    const std::filesystem::path dir = std::filesystem::path(pattern) / "vault";
    initVault(dir, "yuki", kPassphrase);
    ChunkVault vault(dir);
    vault.put("account", "example.com", "u", kPassphrase, kPayload);
    return dir;
  }

  static VaultSession openSession(const std::filesystem::path &dir) {
    SecureBuffer password(kPassphrase);
    return VaultSession::open(dir, "yuki", password);
  }
};

TEST_CASE_METHOD(OneRecord, "Every single-byte change is rejected",
                 "[corruption][sweep]") {
  // This covers the magic, the reserved salt, the nonce, the ciphertext and
  // the GCM tag in one sweep: under the V2 format all of them are
  // authenticated.
  REQUIRE(this->original.size() > kMagicLen + kSaltLen + kNonceLen);

  for (size_t i = 0; i < this->original.size(); ++i) {
    std::vector<unsigned char> mutated = this->original;
    mutated[i] = static_cast<unsigned char>(mutated[i] ^ 0x01);
    writeBytes(this->record, mutated);

    CAPTURE(i);
    CHECK(this->use().refused);

    this->restore();
  }

  // Sanity: the untouched record still works, so the sweep was not passing
  // because every read fails.
  const UseResult clean = this->use();
  CHECK_FALSE(clean.refused);
  CHECK(clean.recovered == kPayload);
}

TEST_CASE_METHOD(OneRecord, "Every tag bit flip is rejected",
                 "[corruption][tag]") {
  // The authenticator is the last line of defence, so it gets bit-level
  // coverage rather than the one flip per byte above.
  const size_t tagStart = this->original.size() - kTagLen;

  for (size_t byte = tagStart; byte < this->original.size(); ++byte) {
    for (unsigned bit = 0; bit < 8; ++bit) {
      std::vector<unsigned char> mutated = this->original;
      mutated[byte] = static_cast<unsigned char>(mutated[byte] ^ (1U << bit));
      writeBytes(this->record, mutated);

      CAPTURE(byte, bit);
      CHECK(this->use().refused);

      this->restore();
    }
  }
}

TEST_CASE_METHOD(OneRecord, "Truncation at every length is rejected",
                 "[corruption][length]") {
  for (size_t len = 0; len < this->original.size(); ++len) {
    writeBytes(this->record, {this->original.begin(),
                              this->original.begin() + static_cast<long>(len)});

    CAPTURE(len);
    CHECK(this->use().refused);

    this->restore();
  }
}

TEST_CASE_METHOD(OneRecord, "Appended bytes are rejected",
                 "[corruption][length]") {
  std::vector<unsigned char> mutated = this->original;
  mutated.push_back(0x00);
  writeBytes(this->record, mutated);

  CHECK(this->use().refused);
}

TEST_CASE_METHOD(OneRecord, "Empty and garbage records are rejected",
                 "[corruption][garbage]") {
  SECTION("an empty file") {
    writeBytes(this->record, {});
    CHECK(this->use().refused);
  }

  SECTION("a short run of garbage") {
    writeBytes(this->record, std::vector<unsigned char>(8, 0xFF));
    CHECK(this->use().refused);
  }

  SECTION("a record with the wrong magic") {
    std::vector<unsigned char> wrongMagic = this->original;
    wrongMagic[0] = 'X';
    writeBytes(this->record, wrongMagic);
    CHECK(this->use().refused);
  }
}

TEST_CASE_METHOD(OneRecord, "A wrong passphrase is rejected",
                 "[corruption][auth]") {
  SecureBuffer wrong("wrong pass");

  CHECK_THROWS_AS(
      [&] {
        VaultSession session = VaultSession::open(this->dir, "yuki", wrong);
        session.use("account", "example.com", "u", [](const SecureBuffer &) {});
      }(),
      CryptoError);
}

TEST_CASE_METHOD(OneRecord, "Random mutations never yield wrong plaintext",
                 "[corruption][fuzz]") {
  // The constant seed is the point: a failing sweep has to be replayable.
  // NOLINTNEXTLINE(bugprone-random-generator-seed)
  std::mt19937 rng(0xA1F1E);
  std::uniform_int_distribution<size_t> pick(0, this->original.size() - 1);
  std::uniform_int_distribution<int> byteValue(0, 255);
  std::uniform_int_distribution<size_t> mutationCount(1, 4);

  for (int iteration = 0; iteration < 400; ++iteration) {
    std::vector<unsigned char> mutated = this->original;
    bool changed = false;
    const size_t mutations = mutationCount(rng);
    for (size_t m = 0; m < mutations; ++m) {
      const size_t index = pick(rng);
      const auto replacement = static_cast<unsigned char>(byteValue(rng));
      if (replacement != mutated[index])
        changed = true;
      mutated[index] = replacement;
    }
    writeBytes(this->record, mutated);

    CAPTURE(iteration, changed);
    const UseResult result = this->use();
    if (changed) {
      CHECK(result.refused);
    } else if (!result.refused) {
      // An unchanged draw must still return exactly what was stored.
      CHECK(result.recovered == kPayload);
    }

    this->restore();
  }
}

TEST_CASE("Records cannot be swapped between accounts",
          "[corruption][binding]") {
  // Swapping two record files is the attack available to anyone who can write
  // to the vault directory but does not know the master password: it would
  // make the vault hand a task the wrong credential.
  std::string pattern =
      (std::filesystem::temp_directory_path() / "alfie-corruption-XXXXXX")
          .string();
  REQUIRE(mkdtemp(pattern.data()) != nullptr);
  const std::filesystem::path root(pattern);
  const std::filesystem::path dir = root / "vault";
  initVault(dir, "yuki", kPassphrase);
  {
    ChunkVault writer(dir);
    writer.put("account", "example.com", "alice", kPassphrase,
               R"({"secret":"alice-secret"})");
    writer.put("account", "example.com", "bob", kPassphrase,
               R"({"secret":"bob-secret"})");
  }

  std::vector<std::filesystem::path> records;
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() == ".enc")
      records.push_back(entry.path());
  }
  REQUIRE(records.size() == 2);

  const std::vector<unsigned char> first = readBytes(records[0]);
  const std::vector<unsigned char> second = readBytes(records[1]);
  writeBytes(records[0], second);
  writeBytes(records[1], first);

  SecureBuffer password(kPassphrase);
  VaultSession vault = VaultSession::open(dir, "yuki", password);
  const UseResult alice = tryUse(vault, "alice");
  const UseResult bob = tryUse(vault, "bob");

  // Both accounts must now fail, and neither may silently return the other's
  // secret. The record id is bound as GCM AAD, which is what stops this.
  CHECK_THAT(alice.recovered,
             !Catch::Matchers::ContainsSubstring("bob-secret"));
  CHECK_THAT(bob.recovered,
             !Catch::Matchers::ContainsSubstring("alice-secret"));
  CHECK(alice.refused);
  CHECK(bob.refused);

  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}
