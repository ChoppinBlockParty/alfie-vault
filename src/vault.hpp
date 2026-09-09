#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace alfie {

// Thrown when authentication/decryption fails or OpenSSL reports a crypto error.
class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Mutable memory for secrets. It is locked out of swap where the OS allows it
// and wiped with OPENSSL_cleanse before release.
class SecureBuffer {
public:
    explicit SecureBuffer(const std::string& s);
    explicit SecureBuffer(std::vector<unsigned char> bytes);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    const std::vector<unsigned char>& bytes() const { return data_; }
    std::vector<unsigned char>& bytes() { return data_; }
    std::string str() const;
    void wipe();

private:
    void lock_memory();
    void unlock_memory();
    std::vector<unsigned char> data_;
    bool locked_ = false;
};

struct VaultKeys {
    std::vector<unsigned char> index_key;
    std::vector<unsigned char> record_key;
};

// Argon2id derives independent keys for indexing and record encryption.
VaultKeys derive_keys(const std::string& passphrase, const std::string& context);

std::string normalize_domain(const std::string& domain_or_url);
std::string record_id(const std::vector<unsigned char>& index_key,
                      const std::string& purpose,
                      const std::string& domain_or_url,
                      const std::string& account);

class ChunkVault {
public:
    explicit ChunkVault(std::filesystem::path root);

    std::filesystem::path put(const std::string& purpose,
                              const std::string& domain_or_url,
                              const std::string& account,
                              const std::string& passphrase,
                              const std::string& plaintext_json);

    std::string get(const std::string& purpose,
                    const std::string& domain_or_url,
                    const std::string& account,
                    const std::string& passphrase);

private:
    std::filesystem::path path_for_id(const std::string& id) const;
    std::filesystem::path root_;
};

} // namespace alfie
