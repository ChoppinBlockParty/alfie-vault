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
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <unistd.h>
#include <vector>

using namespace alfie;

static constexpr size_t kMagicLen = 12;
static constexpr size_t kSaltLen = 16;
static constexpr size_t kNonceLen = 12;

static const char *passphrase = "correct horse battery staple";
static const char *payload =
    R"({"login":"yuki@example.com","secret":"hunter2-hunter2"})";

static std::filesystem::path tempDir(const std::string &name) {
  auto dir = std::filesystem::temp_directory_path() /
             ("alfie-corruption-" + name + "-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  return dir;
}

static std::filesystem::path onlyRecord(const std::filesystem::path &vaultDir) {
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(vaultDir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  assert(false && "expected exactly one encrypted record");
  return {};
}

static std::vector<unsigned char> readBytes(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static void writeBytes(const std::filesystem::path &p,
                       const std::vector<unsigned char> &data) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

// One Argon2id derivation for the whole sweep: at 64 MiB / t=3 per call,
// re-deriving for every corruption case would make this test take minutes.
static VaultSession openSession(const std::filesystem::path &dir) {
  SecureBuffer password(passphrase);
  return VaultSession::open(dir, "yuki", password);
}

// Returns true when the vault refused the record.
static bool rejected(VaultSession &session, const std::string &account,
                     std::string *recovered = nullptr) {
  try {
    session.use("account", "example.com", account,
                [&](const SecureBuffer &secret) {
                  if (recovered != nullptr)
                    *recovered = secret.str();
                });
    return false;
  } catch (const CryptoError &) {
    return true;
  }
}

namespace {
struct Fixture {
  std::filesystem::path dir;
  std::filesystem::path record;
  std::vector<unsigned char> original;

  explicit Fixture(const std::string &name) : dir(tempDir(name)) {
    initVault(this->dir, "yuki", passphrase);
    ChunkVault vault(this->dir);
    vault.put("account", "example.com", "u", passphrase, payload);
    this->record = onlyRecord(this->dir);
    this->original = readBytes(this->record);
  }
  ~Fixture() { std::filesystem::remove_all(this->dir); }
  void restore() const { writeBytes(this->record, this->original); }
};
} // namespace

// Every single-byte change anywhere in the record must be caught. This covers
// the magic, the reserved salt, the nonce, the ciphertext and the GCM tag in
// one sweep -- under the V2 format all of them are authenticated.
static void testEverySingleByteCorruptionIsRejected() {
  Fixture fx("single-byte");
  VaultSession vault = openSession(fx.dir);
  assert(fx.original.size() > kMagicLen + kSaltLen + kNonceLen);

  for (size_t i = 0; i < fx.original.size(); ++i) {
    auto mutated = fx.original;
    mutated[i] = static_cast<unsigned char>(mutated[i] ^ 0x01);
    writeBytes(fx.record, mutated);
    std::string recovered;
    const bool refused = rejected(vault, "u", &recovered);
    if (!refused) {
      std::cerr << "byte " << i
                << " was corrupted but the record still decrypted\n";
      assert(false && "corrupted byte accepted");
    }
    fx.restore();
  }
  // Sanity: the untouched record still works.
  std::string recovered;
  assert(!rejected(vault, "u", &recovered));
  assert(recovered == payload);
}

// Every bit of the GCM tag specifically -- the authenticator is the last line
// of defence.
static void testEveryTagBitFlipIsRejected() {
  Fixture fx("tag-bits");
  VaultSession vault = openSession(fx.dir);
  const size_t tagStart = fx.original.size() - 16;

  for (size_t byte = tagStart; byte < fx.original.size(); ++byte) {
    for (int bit = 0; bit < 8; ++bit) {
      auto mutated = fx.original;
      mutated[byte] = static_cast<unsigned char>(mutated[byte] ^ (1U << bit));
      writeBytes(fx.record, mutated);
      assert(rejected(vault, "u") && "tag bit flip accepted");
      fx.restore();
    }
  }
}

static void testTruncationAtEveryLengthIsRejected() {
  Fixture fx("truncate");
  VaultSession vault = openSession(fx.dir);
  for (size_t len = 0; len < fx.original.size(); ++len) {
    writeBytes(fx.record, {fx.original.begin(),
                           fx.original.begin() + static_cast<long>(len)});
    assert(rejected(vault, "u") && "truncated record accepted");
    fx.restore();
  }
}

static void testAppendedBytesAreRejected() {
  Fixture fx("append");
  VaultSession vault = openSession(fx.dir);
  auto mutated = fx.original;
  mutated.push_back(0x00);
  writeBytes(fx.record, mutated);
  assert(rejected(vault, "u") && "appended byte accepted");
}

static void testEmptyAndGarbageRecordsAreRejected() {
  Fixture fx("garbage");
  VaultSession vault = openSession(fx.dir);

  writeBytes(fx.record, {});
  assert(rejected(vault, "u"));

  writeBytes(fx.record, std::vector<unsigned char>(8, 0xFF));
  assert(rejected(vault, "u"));

  std::vector<unsigned char> wrongMagic = fx.original;
  wrongMagic[0] = 'X';
  writeBytes(fx.record, wrongMagic);
  assert(rejected(vault, "u"));
}

// A record file must only decrypt at its own address. Swapping two record files
// is the attack available to anyone who can write to the vault directory but
// does not know the master password -- it would make the vault hand a task the
// wrong credential.
static void testRecordsCannotBeSwappedBetweenAccounts() {
  auto dir = tempDir("swap");
  initVault(dir, "yuki", passphrase);
  {
    ChunkVault writer(dir);
    writer.put("account", "example.com", "alice", passphrase,
               R"({"secret":"alice-secret"})");
    writer.put("account", "example.com", "bob", passphrase,
               R"({"secret":"bob-secret"})");
  }
  VaultSession vault = openSession(dir);

  std::filesystem::path alicePath, bobPath;
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() != ".enc")
      continue;
    if (alicePath.empty())
      alicePath = entry.path();
    else
      bobPath = entry.path();
  }
  assert(!alicePath.empty() && !bobPath.empty());

  auto a = readBytes(alicePath);
  auto b = readBytes(bobPath);
  writeBytes(alicePath, b);
  writeBytes(bobPath, a);

  // Both accounts must now fail; neither may silently return the other's
  // secret.
  std::string recoveredAlice, recoveredBob;
  const bool aliceRefused = rejected(vault, "alice", &recoveredAlice);
  const bool bobRefused = rejected(vault, "bob", &recoveredBob);
  assert(recoveredAlice.find("bob-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(recoveredBob.find("alice-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(aliceRefused && bobRefused &&
         "swapped record files must not authenticate");

  std::filesystem::remove_all(dir);
}

static void testWrongPassphraseIsRejected() {
  Fixture fx("wrong-pass");
  bool threw = false;
  try {
    SecureBuffer wrong("wrong pass");
    VaultSession session = VaultSession::open(fx.dir, "yuki", wrong);
    session.use("account", "example.com", "u", [](const SecureBuffer &) {});
  } catch (const CryptoError &) {
    threw = true;
  }
  assert(threw && "wrong passphrase accepted");
}

// Randomized sweep with a fixed seed, so a failure is reproducible.
static void testRandomMutationsNeverYieldWrongPlaintext() {
  Fixture fx("fuzz");
  VaultSession vault = openSession(fx.dir);
  // The constant seed is the point: a failing sweep has to be replayable.
  // NOLINTNEXTLINE(bugprone-random-generator-seed)
  std::mt19937 rng(0xA1F1E);
  std::uniform_int_distribution<size_t> pick(0, fx.original.size() - 1);
  std::uniform_int_distribution<int> byteValue(0, 255);
  std::uniform_int_distribution<size_t> mutationCount(1, 4);

  for (int iteration = 0; iteration < 400; ++iteration) {
    auto mutated = fx.original;
    const size_t mutations = mutationCount(rng);
    bool changed = false;
    for (size_t m = 0; m < mutations; ++m) {
      const size_t index = pick(rng);
      const auto replacement = static_cast<unsigned char>(byteValue(rng));
      if (replacement != mutated[index])
        changed = true;
      mutated[index] = replacement;
    }
    writeBytes(fx.record, mutated);

    std::string recovered;
    const bool refused = rejected(vault, "u", &recovered);
    if (changed) {
      assert(refused && "mutated record authenticated");
    } else if (!refused) {
      assert(recovered == payload);
    }
    fx.restore();
  }
}

int main() {
  testEverySingleByteCorruptionIsRejected();
  testEveryTagBitFlipIsRejected();
  testTruncationAtEveryLengthIsRejected();
  testAppendedBytesAreRejected();
  testEmptyAndGarbageRecordsAreRejected();
  testRecordsCannotBeSwappedBetweenAccounts();
  testWrongPassphraseIsRejected();
  testRandomMutationsNeverYieldWrongPlaintext();
  std::cout << "corruption tests passed\n";
  return 0;
}
