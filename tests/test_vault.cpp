#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cassert>
#include <cstdio>
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

// --- Helpers that reproduce the pre-fix (ALFIECHUNK1) writer, for the compatibility test. ---

static std::vector<unsigned char> vault_salt(const std::filesystem::path& dir) {
  std::ifstream in(dir / "vault.meta", std::ios::binary);
  std::string magic, salt_hex;
  std::getline(in, magic);
  std::getline(in, salt_hex);
  std::vector<unsigned char> salt;
  for (size_t i = 0; i + 1 < salt_hex.size(); i += 2)
    salt.push_back(static_cast<unsigned char>(std::stoi(salt_hex.substr(i, 2), nullptr, 16)));
  return salt;
}

static VaultKeys derive_keys_for_vault(const std::filesystem::path& dir, SecureBuffer& passphrase) {
  return derive_keys(passphrase, vault_salt(dir));
}

static std::string legacy_id_for(const SecureBuffer& index_key, const std::string& purpose,
                                 const std::string& domain, const std::string& account) {
  const std::string msg = purpose + normalize_domain(domain) + account;  // separators dropped
  unsigned int len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), index_key.data(), static_cast<int>(index_key.size()),
       reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), mac, &len);
  std::string out;
  char buf[3];
  for (unsigned int i = 0; i < len; ++i) {
    std::snprintf(buf, sizeof(buf), "%02x", mac[i]);
    out += buf;
  }
  return out;
}

static void write_legacy_v1_record(const std::filesystem::path& path,
                                   const SecureBuffer& record_key, const std::string& plaintext) {
  const std::string magic = "ALFIECHUNK1\n";
  std::vector<unsigned char> salt(16), nonce(12);
  RAND_bytes(salt.data(), static_cast<int>(salt.size()));
  RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));

  std::vector<unsigned char> out(plaintext.size() + 16);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
  EVP_EncryptInit_ex(ctx, nullptr, nullptr, record_key.data(), nonce.data());
  EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(magic.data()),
                    static_cast<int>(magic.size()));  // V1 AAD: the magic only
  EVP_EncryptUpdate(ctx, out.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()),
                    static_cast<int>(plaintext.size()));
  int total = len;
  EVP_EncryptFinal_ex(ctx, out.data() + total, &len);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + plaintext.size());
  EVP_CIPHER_CTX_free(ctx);

  std::filesystem::create_directories(path.parent_path());
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(magic.data(), static_cast<std::streamsize>(magic.size()));
  f.write(reinterpret_cast<const char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
  f.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
  f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
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
  SecureBuffer passphrase("correct horse battery staple");
  VaultKeys keys = derive_keys(passphrase, "alfie-v1");
  auto id1 = record_id(keys.index_key, "account", "https://www.example.com", "yuki@example.com");
  auto id2 = record_id(keys.index_key, "account", "example.com", "yuki@example.com");
  assert(id1 == id2);
  assert(id1.find("example") == std::string::npos);
  assert(id1.find("yuki") == std::string::npos);
  assert(id1.size() == 64);
}

static void test_put_get_one_chunk_without_plaintext_on_disk() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_test";
  std::filesystem::remove_all(dir);
  std::string passphrase = "correct horse battery staple";
  init_vault(dir, "yuki", passphrase);
  ChunkVault vault(dir);
  std::string json =
      R"({"login":"yuki@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

  auto path = vault.put("account", "example.com", "yuki@example.com", passphrase, json);
  assert(std::filesystem::exists(path));
  assert(path.string().find("example") == std::string::npos);

  std::string raw = read_file(path);
  assert(raw.find("VERY-SECRET") == std::string::npos);
  assert(raw.find("yuki@example.com") == std::string::npos);
  assert(raw.rfind("ALFIECHUNK2\n", 0) == 0);

  auto out = vault.get("account", "example.com", "yuki@example.com", passphrase);
  assert(out == json);
  std::filesystem::remove_all(dir);
}

static void test_wrong_passphrase_fails() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_wrong_pass";
  std::filesystem::remove_all(dir);
  init_vault(dir, "yuki", "right pass");
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

  std::string passphrase = "same passphrase";
  std::string json = R"({"secret":"same"})";
  init_vault(a, "yuki", passphrase);
  init_vault(b, "yuki", passphrase);
  ChunkVault vault_a(a);
  ChunkVault vault_b(b);
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
  init_vault(dir, "yuki", "right pass");
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

static void test_vault_must_be_initialized_before_use() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_uninit";
  std::filesystem::remove_all(dir);

  // Reading a vault that was never created must fail rather than quietly create one: a typo'd
  // vault path used to become a brand-new empty vault with a fresh salt.
  ChunkVault vault(dir);
  bool threw = false;
  try {
    vault.get("account", "example.com", "u", "pass");
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw);
  assert(!std::filesystem::exists(dir / "vault.meta"));
  assert(!vault_initialized(dir));

  threw = false;
  try {
    vault.put("account", "example.com", "u", "pass", R"({"secret":"s"})");
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw);
  assert(!std::filesystem::exists(dir / "vault.meta"));
  std::filesystem::remove_all(dir);
}

static void test_init_vault_sets_credentials_and_is_not_repeatable() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_init";
  std::filesystem::remove_all(dir);

  init_vault(dir, "yuki", "master pass");
  assert(vault_initialized(dir));
  assert(vault_has_credentials(dir));

  // A second init must never re-key a live vault.
  bool threw = false;
  try {
    init_vault(dir, "someone-else", "other pass");
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw);

  assert(verify_credentials(dir, "yuki", "master pass"));
  assert(!verify_credentials(dir, "yuki", "wrong pass"));
  assert(!verify_credentials(dir, "wrong-login", "master pass"));

  // Neither the login nor the password is recoverable from vault.meta.
  std::string meta = read_file(dir / "vault.meta");
  assert(meta.find("yuki") == std::string::npos);
  assert(meta.find("master pass") == std::string::npos);
  assert(meta.find("ALFIEVAULT2") != std::string::npos);

  std::filesystem::remove_all(dir);
}

static void test_init_vault_rejects_empty_credentials() {
  auto base = std::filesystem::temp_directory_path() / "alfie_vault_cpp_init_empty";
  std::filesystem::remove_all(base);

  bool threw = false;
  try {
    init_vault(base / "a", "", "pass");
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw);

  threw = false;
  try {
    init_vault(base / "b", "yuki", "");
  } catch (const CryptoError&) {
    threw = true;
  }
  assert(threw);
  std::filesystem::remove_all(base);
}

// A vault written before the record-format fix must stay readable: V1 records live at the old
// (separator-less) record id and authenticate only the magic. Rewriting one upgrades it to V2
// at the new id and removes the stale V1 file.
static void test_legacy_v1_records_are_still_readable() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_legacy_v1";
  std::filesystem::remove_all(dir);
  const std::string passphrase = "correct horse battery staple";
  const std::string json = R"({"secret":"legacy-value"})";
  init_vault(dir, "yuki", passphrase);

  // Hand-build a V1 record the way the pre-fix code did: id over the concatenated fields with
  // no separators, AAD over the magic alone.
  SecureBuffer locked(passphrase);
  VaultKeys keys = derive_keys_for_vault(dir, locked);
  const std::string legacy_id = legacy_id_for(keys.index_key, "account", "example.com", "u");
  const auto path =
      dir / "records" / legacy_id.substr(0, 2) / legacy_id.substr(2, 2) / (legacy_id + ".enc");
  write_legacy_v1_record(path, keys.record_key, json);

  ChunkVault vault(dir);
  assert(vault.get("account", "example.com", "u", passphrase) == json);

  // Rewriting moves it to the V2 id and drops the V1 file.
  auto new_path = vault.put("account", "example.com", "u", passphrase, json);
  assert(new_path != path);
  assert(!std::filesystem::exists(path));
  assert(read_file(new_path).rfind("ALFIECHUNK2\n", 0) == 0);
  assert(vault.get("account", "example.com", "u", passphrase) == json);
  std::filesystem::remove_all(dir);
}

// Distinct (purpose, domain, account) triples must never collide. Before the fix the separators
// were dropped, so ("acc","ountX") and ("account","X") hashed to the same record id.
static void test_record_ids_are_domain_separated() {
  SecureBuffer passphrase("correct horse battery staple");
  VaultKeys keys = derive_keys(passphrase, "separator-test");
  auto a = record_id(keys.index_key, "acc", "example.com", "ountX");
  auto b = record_id(keys.index_key, "account", "example.com", "X");
  assert(a != b);
  auto c = record_id(keys.index_key, "account", "example.com", "");
  auto d = record_id(keys.index_key, "account", "example.co", "m");
  assert(c != d);
}

// The Argon2id cost line in vault.meta must be load-bearing, not decorative: if it were
// ignored, a future build that raised the cost would silently derive a different key for every
// existing vault. Changing the recorded cost must change the derived key.
static void test_stored_argon2_params_are_used() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "alfie_vault_cpp_params";
  std::filesystem::remove_all(dir);
  init_vault(dir, "yuki", "master pass");
  assert(verify_credentials(dir, "yuki", "master pass"));

  // Rewrite only the cost line, leaving salt and verifiers intact.
  std::string meta = read_file(dir / "vault.meta");
  const auto start = meta.find("argon2id ");
  const auto end = meta.find('\n', start);
  assert(start != std::string::npos && end != std::string::npos);
  meta.replace(start, end - start, "argon2id m=32768,t=2,p=1");
  {
    std::ofstream out(dir / "vault.meta", std::ios::binary | std::ios::trunc);
    out << meta;
  }

  // A different cost derives a different key, so the verifiers no longer match.
  assert(!verify_credentials(dir, "yuki", "master pass"));
  std::filesystem::remove_all(dir);
}

int main() {
  test_vault_must_be_initialized_before_use();
  test_init_vault_sets_credentials_and_is_not_repeatable();
  test_init_vault_rejects_empty_credentials();
  test_secure_buffer_wipes();
  test_secret_types_are_move_only();
  test_argon2id_derivation_wipes_passphrase_buffer();
  test_record_id_is_stable_and_not_plaintext();
  test_put_get_one_chunk_without_plaintext_on_disk();
  test_legacy_v1_records_are_still_readable();
  test_record_ids_are_domain_separated();
  test_stored_argon2_params_are_used();
  test_new_vaults_use_different_random_salts();
  test_record_can_be_used_without_returning_secret_string();
  test_wrong_passphrase_fails();
  std::cout << "C++ vault tests passed\n";
}
