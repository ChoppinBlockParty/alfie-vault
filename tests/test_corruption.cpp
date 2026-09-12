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

static constexpr size_t MagicLen = 12;
static constexpr size_t SaltLen = 16;
static constexpr size_t NonceLen = 12;

static const char *Passphrase = "correct horse battery staple";
static const char *Payload =
    R"({"login":"yuki@example.com","secret":"hunter2-hunter2"})";

static std::filesystem::path tempDir(const std::string &Name) {
  auto Dir = std::filesystem::temp_directory_path() /
             ("alfie-corruption-" + Name + "-" + std::to_string(::getpid()));
  std::filesystem::remove_all(Dir);
  return Dir;
}

static std::filesystem::path onlyRecord(const std::filesystem::path &VaultDir) {
  for (const auto &Entry :
       std::filesystem::recursive_directory_iterator(VaultDir / "records")) {
    if (Entry.path().extension() == ".enc")
      return Entry.path();
  }
  assert(false && "expected exactly one encrypted record");
  return {};
}

static std::vector<unsigned char> readBytes(const std::filesystem::path &P) {
  std::ifstream In(P, std::ios::binary);
  return {std::istreambuf_iterator<char>(In), std::istreambuf_iterator<char>()};
}

static void writeBytes(const std::filesystem::path &P,
                       const std::vector<unsigned char> &Data) {
  std::ofstream Out(P, std::ios::binary | std::ios::trunc);
  Out.write(reinterpret_cast<const char *>(Data.data()),
            static_cast<std::streamsize>(Data.size()));
}

// One Argon2id derivation for the whole sweep: at 64 MiB / t=3 per call,
// re-deriving for every corruption case would make this test take minutes.
static VaultSession openSession(const std::filesystem::path &Dir) {
  SecureBuffer Password(Passphrase);
  return VaultSession::open(Dir, "yuki", Password);
}

// Returns true when the vault refused the record.
static bool rejected(VaultSession &Session, const std::string &Account,
                     std::string *Recovered = nullptr) {
  try {
    Session.use("account", "example.com", Account,
                [&](const SecureBuffer &Secret) {
                  if (Recovered != nullptr)
                    *Recovered = Secret.str();
                });
    return false;
  } catch (const CryptoError &) {
    return true;
  }
}

namespace {
struct Fixture {
  std::filesystem::path Dir;
  std::filesystem::path Record;
  std::vector<unsigned char> Original;

  explicit Fixture(const std::string &Name) : Dir(tempDir(Name)) {
    initVault(this->Dir, "yuki", Passphrase);
    ChunkVault Vault(this->Dir);
    Vault.put("account", "example.com", "u", Passphrase, Payload);
    this->Record = onlyRecord(this->Dir);
    this->Original = readBytes(this->Record);
  }
  ~Fixture() { std::filesystem::remove_all(this->Dir); }
  void restore() const { writeBytes(this->Record, this->Original); }
};
} // namespace

// Every single-byte change anywhere in the record must be caught. This covers
// the magic, the reserved salt, the nonce, the ciphertext and the GCM tag in
// one sweep -- under the V2 format all of them are authenticated.
static void testEverySingleByteCorruptionIsRejected() {
  Fixture Fx("single-byte");
  VaultSession Vault = openSession(Fx.Dir);
  assert(Fx.Original.size() > MagicLen + SaltLen + NonceLen);

  for (size_t I = 0; I < Fx.Original.size(); ++I) {
    auto Mutated = Fx.Original;
    Mutated[I] = static_cast<unsigned char>(Mutated[I] ^ 0x01);
    writeBytes(Fx.Record, Mutated);
    std::string Recovered;
    const bool Refused = rejected(Vault, "u", &Recovered);
    if (!Refused) {
      std::cerr << "byte " << I
                << " was corrupted but the record still decrypted\n";
      assert(false && "corrupted byte accepted");
    }
    Fx.restore();
  }
  // Sanity: the untouched record still works.
  std::string Recovered;
  assert(!rejected(Vault, "u", &Recovered));
  assert(Recovered == Payload);
}

// Every bit of the GCM tag specifically -- the authenticator is the last line
// of defence.
static void testEveryTagBitFlipIsRejected() {
  Fixture Fx("tag-bits");
  VaultSession Vault = openSession(Fx.Dir);
  const size_t TagStart = Fx.Original.size() - 16;

  for (size_t Byte = TagStart; Byte < Fx.Original.size(); ++Byte) {
    for (int Bit = 0; Bit < 8; ++Bit) {
      auto Mutated = Fx.Original;
      Mutated[Byte] = static_cast<unsigned char>(Mutated[Byte] ^ (1U << Bit));
      writeBytes(Fx.Record, Mutated);
      assert(rejected(Vault, "u") && "tag bit flip accepted");
      Fx.restore();
    }
  }
}

static void testTruncationAtEveryLengthIsRejected() {
  Fixture Fx("truncate");
  VaultSession Vault = openSession(Fx.Dir);
  for (size_t Len = 0; Len < Fx.Original.size(); ++Len) {
    writeBytes(Fx.Record, {Fx.Original.begin(),
                           Fx.Original.begin() + static_cast<long>(Len)});
    assert(rejected(Vault, "u") && "truncated record accepted");
    Fx.restore();
  }
}

static void testAppendedBytesAreRejected() {
  Fixture Fx("append");
  VaultSession Vault = openSession(Fx.Dir);
  auto Mutated = Fx.Original;
  Mutated.push_back(0x00);
  writeBytes(Fx.Record, Mutated);
  assert(rejected(Vault, "u") && "appended byte accepted");
}

static void testEmptyAndGarbageRecordsAreRejected() {
  Fixture Fx("garbage");
  VaultSession Vault = openSession(Fx.Dir);

  writeBytes(Fx.Record, {});
  assert(rejected(Vault, "u"));

  writeBytes(Fx.Record, std::vector<unsigned char>(8, 0xFF));
  assert(rejected(Vault, "u"));

  std::vector<unsigned char> WrongMagic = Fx.Original;
  WrongMagic[0] = 'X';
  writeBytes(Fx.Record, WrongMagic);
  assert(rejected(Vault, "u"));
}

// A record file must only decrypt at its own address. Swapping two record files
// is the attack available to anyone who can write to the vault directory but
// does not know the master password -- it would make the vault hand a task the
// wrong credential.
static void testRecordsCannotBeSwappedBetweenAccounts() {
  auto Dir = tempDir("swap");
  initVault(Dir, "yuki", Passphrase);
  {
    ChunkVault Writer(Dir);
    Writer.put("account", "example.com", "alice", Passphrase,
               R"({"secret":"alice-secret"})");
    Writer.put("account", "example.com", "bob", Passphrase,
               R"({"secret":"bob-secret"})");
  }
  VaultSession Vault = openSession(Dir);

  std::filesystem::path AlicePath, BobPath;
  for (const auto &Entry :
       std::filesystem::recursive_directory_iterator(Dir / "records")) {
    if (Entry.path().extension() != ".enc")
      continue;
    if (AlicePath.empty())
      AlicePath = Entry.path();
    else
      BobPath = Entry.path();
  }
  assert(!AlicePath.empty() && !BobPath.empty());

  auto A = readBytes(AlicePath);
  auto B = readBytes(BobPath);
  writeBytes(AlicePath, B);
  writeBytes(BobPath, A);

  // Both accounts must now fail; neither may silently return the other's
  // secret.
  std::string RecoveredAlice, RecoveredBob;
  const bool AliceRefused = rejected(Vault, "alice", &RecoveredAlice);
  const bool BobRefused = rejected(Vault, "bob", &RecoveredBob);
  assert(RecoveredAlice.find("bob-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(RecoveredBob.find("alice-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(AliceRefused && BobRefused &&
         "swapped record files must not authenticate");

  std::filesystem::remove_all(Dir);
}

static void testWrongPassphraseIsRejected() {
  Fixture Fx("wrong-pass");
  bool Threw = false;
  try {
    SecureBuffer Wrong("wrong pass");
    VaultSession Session = VaultSession::open(Fx.Dir, "yuki", Wrong);
    Session.use("account", "example.com", "u", [](const SecureBuffer &) {});
  } catch (const CryptoError &) {
    Threw = true;
  }
  assert(Threw && "wrong passphrase accepted");
}

// Randomized sweep with a fixed seed, so a failure is reproducible.
static void testRandomMutationsNeverYieldWrongPlaintext() {
  Fixture Fx("fuzz");
  VaultSession Vault = openSession(Fx.Dir);
  // The constant seed is the point: a failing sweep has to be replayable.
  // NOLINTNEXTLINE(bugprone-random-generator-seed)
  std::mt19937 Rng(0xA1F1E);
  std::uniform_int_distribution<size_t> Pick(0, Fx.Original.size() - 1);
  std::uniform_int_distribution<int> ByteValue(0, 255);
  std::uniform_int_distribution<size_t> MutationCount(1, 4);

  for (int Iteration = 0; Iteration < 400; ++Iteration) {
    auto Mutated = Fx.Original;
    const size_t Mutations = MutationCount(Rng);
    bool Changed = false;
    for (size_t M = 0; M < Mutations; ++M) {
      const size_t Index = Pick(Rng);
      const auto Replacement = static_cast<unsigned char>(ByteValue(Rng));
      if (Replacement != Mutated[Index])
        Changed = true;
      Mutated[Index] = Replacement;
    }
    writeBytes(Fx.Record, Mutated);

    std::string Recovered;
    const bool Refused = rejected(Vault, "u", &Recovered);
    if (Changed) {
      assert(Refused && "mutated record authenticated");
    } else if (!Refused) {
      assert(Recovered == Payload);
    }
    Fx.restore();
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
