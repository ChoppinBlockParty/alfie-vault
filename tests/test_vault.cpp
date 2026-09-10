#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <type_traits>

#include "../src/vault.hpp"

using namespace alfie;

static std::string read_file(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static std::filesystem::path first_record_path(const std::filesystem::path& dir) {
  for (const auto& entry : std::filesystem::recursive_directory_iterator(dir / "records")) {
    if (entry.path().extension() == ".enc")
      return entry.path();
  }
  assert(false && "expected encrypted record");
  return {};
}

static void test_secure_buffer_wipes() {
  SecureBuffer buf("SECRET");
  assert(buf.str() == "SECRET");
  buf.wipe();
  for (auto b : buf.bytes())
    assert(b == 0);
}

static void test_secret_types_are_move_only() {
  static_assert(!std::is_copy_constructible_v<SecureBuffer>);
  static_assert(!std::is_copy_assignable_v<SecureBuffer>);
  static_assert(!std::is_copy_constructible_v<VaultKeys>);
  static_assert(!std::is_copy_assignable_v<VaultKeys>);
}

static void test_argon2id_derivation_wipes_passphrase_buffer() {
  SecureBuffer passphrase("correct horse battery staple");
  auto keys = derive_keys(passphrase, "wipe-test");
  assert(keys.index_key.size() == 32);
  assert(keys.record_key.size() == 32);
  for (auto b : passphrase.bytes())
    assert(b == 0);
}

static void test_record_id_is_stable_and_not_plaintext() {
  VaultKeys keys = derive_keys("correct horse battery staple", "alfie-v1");
  auto id1 = record_id(keys.index_key, "account", "https://www.example.com", "slava@example.com");
  auto id2 = record_id(keys.index_key, "account", "example.com", "slava@example.com");
  assert(id1 == id2);
  assert(id1.find("example") == std::string::npos);
  assert(id1.find("slava") == std::string::npos);
  assert(id1.size() == 64);
}

static void test_put_get_one_chunk_without_plaintext_on_disk() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_test";
  std::filesystem::remove_all(dir);
  ChunkVault vault(dir);
  std::string passphrase = "correct horse battery staple";
  std::string json =
      R"({"login":"slava@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

  auto path = vault.put("account", "example.com", "slava@example.com", passphrase, json);
  assert(std::filesystem::exists(path));
  assert(path.string().find("example") == std::string::npos);

  std::string raw = read_file(path);
  assert(raw.find("VERY-SECRET") == std::string::npos);
  assert(raw.find("slava@example.com") == std::string::npos);
  assert(raw.rfind("ALFIECHUNK1\n", 0) == 0);

  auto out = vault.get("account", "example.com", "slava@example.com", passphrase);
  assert(out == json);
  std::filesystem::remove_all(dir);
}

static void test_wrong_passphrase_fails() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_wrong_pass";
  std::filesystem::remove_all(dir);
  ChunkVault vault(dir);
  vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");
  bool failed = false;
  try {
    (void)vault.get("account", "example.com", "u", "wrong pass");
  } catch (const CryptoError&) {
    failed = true;
  }
  assert(failed);
  std::filesystem::remove_all(dir);
}

static void test_new_vaults_use_different_random_salts() {
  auto base = std::filesystem::temp_directory_path();
  auto a = base / "alfie_vault_cpp_salt_a";
  auto b = base / "alfie_vault_cpp_salt_b";
  std::filesystem::remove_all(a);
  std::filesystem::remove_all(b);

  ChunkVault vault_a(a);
  ChunkVault vault_b(b);
  std::string passphrase = "same passphrase";
  std::string json = R"({"secret":"same"})";
  vault_a.put("account", "example.com", "u", passphrase, json);
  vault_b.put("account", "example.com", "u", passphrase, json);

  assert(std::filesystem::exists(a / "vault.meta"));
  assert(std::filesystem::exists(b / "vault.meta"));
  assert(read_file(a / "vault.meta") != read_file(b / "vault.meta"));
  assert(first_record_path(a).filename() != first_record_path(b).filename());
  assert(vault_a.get("account", "example.com", "u", passphrase) == json);
  assert(vault_b.get("account", "example.com", "u", passphrase) == json);

  std::filesystem::remove_all(a);
  std::filesystem::remove_all(b);
}

static void test_record_can_be_used_without_returning_secret_string() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_use_record";
  std::filesystem::remove_all(dir);
  ChunkVault vault(dir);
  vault.put("account", "example.com", "u", "right pass", R"({"secret":"s"})");

  size_t seen_size = 0;
  vault.use("account", "example.com", "u", "right pass", [&](const SecureBuffer& secret) {
    seen_size = secret.size();
    assert(secret.str() == R"({"secret":"s"})");
  });

  assert(seen_size == 14);
  std::filesystem::remove_all(dir);
}

int main() {
  test_secure_buffer_wipes();
  test_secret_types_are_move_only();
  test_argon2id_derivation_wipes_passphrase_buffer();
  test_record_id_is_stable_and_not_plaintext();
  test_put_get_one_chunk_without_plaintext_on_disk();
  test_new_vaults_use_different_random_salts();
  test_record_can_be_used_without_returning_secret_string();
  test_wrong_passphrase_fails();
  std::cout << "C++ vault tests passed\n";
}
