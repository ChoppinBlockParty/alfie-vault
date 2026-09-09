#include "../src/vault.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace alfie;

static std::string read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void test_secure_buffer_wipes() {
    SecureBuffer buf("SECRET");
    assert(buf.str() == "SECRET");
    buf.wipe();
    for (auto b : buf.bytes()) assert(b == 0);
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
    std::string json = R"({"login":"slava@example.com","secret":"VERY-SECRET-123!","metadata":{"created_by":"test"}})";

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

int main() {
    test_secure_buffer_wipes();
    test_record_id_is_stable_and_not_plaintext();
    test_put_get_one_chunk_without_plaintext_on_disk();
    test_wrong_passphrase_fails();
    std::cout << "C++ vault tests passed\n";
}
