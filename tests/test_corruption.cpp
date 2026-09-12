// Corruption and fuzz coverage for encrypted chunks.
//
// The rule under test is simple and absolute: a record that has been altered in any way must
// fail authentication. It must never decrypt to something other than what was stored, and it
// must never decrypt to a *different* record's contents.
#include <unistd.h>

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "../src/vault.hpp"

using namespace alfie;

namespace {

constexpr size_t kMagicLen = 12;
constexpr size_t kSaltLen = 16;
constexpr size_t kNonceLen = 12;

const char* kPassphrase = "correct horse battery staple";
const char* kPayload = R"({"login":"yuki@example.com","secret":"hunter2-hunter2"})";

std::filesystem::path temp_dir(const std::string& name) {
  auto dir = std::filesystem::temp_directory_path() /
             ("alfie-corruption-" + name + "-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  return dir;
}

std::filesystem::path only_record(const std::filesystem::path& vault_dir) {
  for (const auto& entry : std::filesystem::recursive_directory_iterator(vault_dir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  assert(false && "expected exactly one encrypted record");
  return {};
}

std::vector<unsigned char> read_bytes(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_bytes(const std::filesystem::path& p, const std::vector<unsigned char>& data) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

// One Argon2id derivation for the whole sweep: at 64 MiB / t=3 per call, re-deriving for every
// corruption case would make this test take minutes.
VaultSession open_session(const std::filesystem::path& dir) {
  SecureBuffer passphrase(kPassphrase);
  return VaultSession::open(dir, "yuki", passphrase);
}

// Returns true when the vault refused the record.
bool rejected(VaultSession& session, const std::string& account, std::string* recovered = nullptr) {
  try {
    session.use("account", "example.com", account, [&](const SecureBuffer& secret) {
      if (recovered != nullptr)
        *recovered = secret.str();
    });
    return false;
  } catch (const CryptoError&) {
    return true;
  }
}

struct Fixture {
  std::filesystem::path dir;
  std::filesystem::path record;
  std::vector<unsigned char> original;

  explicit Fixture(const std::string& name) : dir(temp_dir(name)) {
    init_vault(dir, "yuki", kPassphrase);
    ChunkVault vault(dir);
    vault.put("account", "example.com", "u", kPassphrase, kPayload);
    record = only_record(dir);
    original = read_bytes(record);
  }
  ~Fixture() {
    std::filesystem::remove_all(dir);
  }
  void restore() const {
    write_bytes(record, original);
  }
};

// Every single-byte change anywhere in the record must be caught. This covers the magic, the
// reserved salt, the nonce, the ciphertext and the GCM tag in one sweep -- under the V2 format
// all of them are authenticated.
void test_every_single_byte_corruption_is_rejected() {
  Fixture fx("single-byte");
  VaultSession vault = open_session(fx.dir);
  assert(fx.original.size() > kMagicLen + kSaltLen + kNonceLen);

  for (size_t i = 0; i < fx.original.size(); ++i) {
    auto mutated = fx.original;
    mutated[i] = static_cast<unsigned char>(mutated[i] ^ 0x01);
    write_bytes(fx.record, mutated);
    std::string recovered;
    const bool refused = rejected(vault, "u", &recovered);
    if (!refused) {
      std::cerr << "byte " << i << " was corrupted but the record still decrypted\n";
      assert(false && "corrupted byte accepted");
    }
    fx.restore();
  }
  // Sanity: the untouched record still works.
  std::string recovered;
  assert(!rejected(vault, "u", &recovered));
  assert(recovered == kPayload);
}

// Every bit of the GCM tag specifically -- the authenticator is the last line of defence.
void test_every_tag_bit_flip_is_rejected() {
  Fixture fx("tag-bits");
  VaultSession vault = open_session(fx.dir);
  const size_t tag_start = fx.original.size() - 16;

  for (size_t byte = tag_start; byte < fx.original.size(); ++byte) {
    for (int bit = 0; bit < 8; ++bit) {
      auto mutated = fx.original;
      mutated[byte] = static_cast<unsigned char>(mutated[byte] ^ (1u << bit));
      write_bytes(fx.record, mutated);
      assert(rejected(vault, "u") && "tag bit flip accepted");
      fx.restore();
    }
  }
}

void test_truncation_at_every_length_is_rejected() {
  Fixture fx("truncate");
  VaultSession vault = open_session(fx.dir);
  for (size_t len = 0; len < fx.original.size(); ++len) {
    write_bytes(fx.record, {fx.original.begin(), fx.original.begin() + static_cast<long>(len)});
    assert(rejected(vault, "u") && "truncated record accepted");
    fx.restore();
  }
}

void test_appended_bytes_are_rejected() {
  Fixture fx("append");
  VaultSession vault = open_session(fx.dir);
  auto mutated = fx.original;
  mutated.push_back(0x00);
  write_bytes(fx.record, mutated);
  assert(rejected(vault, "u") && "appended byte accepted");
}

void test_empty_and_garbage_records_are_rejected() {
  Fixture fx("garbage");
  VaultSession vault = open_session(fx.dir);

  write_bytes(fx.record, {});
  assert(rejected(vault, "u"));

  write_bytes(fx.record, std::vector<unsigned char>(8, 0xFF));
  assert(rejected(vault, "u"));

  std::vector<unsigned char> wrong_magic = fx.original;
  wrong_magic[0] = 'X';
  write_bytes(fx.record, wrong_magic);
  assert(rejected(vault, "u"));
}

// A record file must only decrypt at its own address. Swapping two record files is the attack
// available to anyone who can write to the vault directory but does not know the master
// password -- it would make the vault hand a task the wrong credential.
void test_records_cannot_be_swapped_between_accounts() {
  auto dir = temp_dir("swap");
  init_vault(dir, "yuki", kPassphrase);
  {
    ChunkVault writer(dir);
    writer.put("account", "example.com", "alice", kPassphrase, R"({"secret":"alice-secret"})");
    writer.put("account", "example.com", "bob", kPassphrase, R"({"secret":"bob-secret"})");
  }
  VaultSession vault = open_session(dir);

  std::filesystem::path alice_path, bob_path;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() != ".enc")
      continue;
    if (alice_path.empty())
      alice_path = entry.path();
    else
      bob_path = entry.path();
  }
  assert(!alice_path.empty() && !bob_path.empty());

  auto a = read_bytes(alice_path);
  auto b = read_bytes(bob_path);
  write_bytes(alice_path, b);
  write_bytes(bob_path, a);

  // Both accounts must now fail; neither may silently return the other's secret.
  std::string recovered_alice, recovered_bob;
  const bool alice_refused = rejected(vault, "alice", &recovered_alice);
  const bool bob_refused = rejected(vault, "bob", &recovered_bob);
  assert(recovered_alice.find("bob-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(recovered_bob.find("alice-secret") == std::string::npos &&
         "swapped record leaked another account's secret");
  assert(alice_refused && bob_refused && "swapped record files must not authenticate");

  std::filesystem::remove_all(dir);
}

void test_wrong_passphrase_is_rejected() {
  Fixture fx("wrong-pass");
  bool threw = false;
  try {
    SecureBuffer wrong("wrong pass");
    VaultSession session = VaultSession::open(fx.dir, "yuki", wrong);
    session.use("account", "example.com", "u", [](const SecureBuffer&) {});
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw && "wrong passphrase accepted");
}

// Randomized sweep with a fixed seed, so a failure is reproducible.
void test_random_mutations_never_yield_wrong_plaintext() {
  Fixture fx("fuzz");
  VaultSession vault = open_session(fx.dir);
  std::mt19937 rng(0xA1F1E);
  std::uniform_int_distribution<size_t> pick(0, fx.original.size() - 1);
  std::uniform_int_distribution<int> byte_value(0, 255);
  std::uniform_int_distribution<size_t> mutation_count(1, 4);

  for (int iteration = 0; iteration < 400; ++iteration) {
    auto mutated = fx.original;
    const size_t mutations = mutation_count(rng);
    bool changed = false;
    for (size_t m = 0; m < mutations; ++m) {
      const size_t index = pick(rng);
      const auto replacement = static_cast<unsigned char>(byte_value(rng));
      if (replacement != mutated[index])
        changed = true;
      mutated[index] = replacement;
    }
    write_bytes(fx.record, mutated);

    std::string recovered;
    const bool refused = rejected(vault, "u", &recovered);
    if (changed) {
      assert(refused && "mutated record authenticated");
    } else if (!refused) {
      assert(recovered == kPayload);
    }
    fx.restore();
  }
}

}  // namespace

int main() {
  test_every_single_byte_corruption_is_rejected();
  test_every_tag_bit_flip_is_rejected();
  test_truncation_at_every_length_is_rejected();
  test_appended_bytes_are_rejected();
  test_empty_and_garbage_records_are_rejected();
  test_records_cannot_be_swapped_between_accounts();
  test_wrong_passphrase_is_rejected();
  test_random_mutations_never_yield_wrong_plaintext();
  std::cout << "corruption tests passed\n";
  return 0;
}
