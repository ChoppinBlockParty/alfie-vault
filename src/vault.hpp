#pragma once

#include <filesystem>
#include <functional>
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

  const std::vector<unsigned char>& bytes() const {
    return data_;
  }
  std::vector<unsigned char>& bytes() {
    return data_;
  }
  size_t size() const {
    return data_.size();
  }
  std::string str() const;
  void wipe();

 private:
  void lock_memory();
  void unlock_memory();
  std::vector<unsigned char> data_;
  bool locked_ = false;
};

struct VaultKeys {
  VaultKeys(SecureBuffer index, SecureBuffer record)
      : index_key(std::move(index)), record_key(std::move(record)) {}
  VaultKeys(const VaultKeys&) = delete;
  VaultKeys& operator=(const VaultKeys&) = delete;
  VaultKeys(VaultKeys&&) noexcept = default;
  VaultKeys& operator=(VaultKeys&&) noexcept = default;

  SecureBuffer index_key;
  SecureBuffer record_key;
};

// Argon2id derives independent keys for indexing and record encryption.
VaultKeys derive_keys(SecureBuffer& passphrase, const std::string& context);
VaultKeys derive_keys(const std::string& passphrase, const std::string& context);

std::string normalize_domain(const std::string& domain_or_url);
std::string record_id(const SecureBuffer& index_key, const std::string& purpose,
                      const std::string& domain_or_url, const std::string& account);

class ChunkVault {
 public:
  explicit ChunkVault(std::filesystem::path root);

  std::filesystem::path put(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, const std::string& passphrase,
                            const std::string& plaintext_json);

  std::string get(const std::string& purpose, const std::string& domain_or_url,
                  const std::string& account, const std::string& passphrase);

  void use(const std::string& purpose, const std::string& domain_or_url, const std::string& account,
           const std::string& passphrase, const std::function<void(const SecureBuffer&)>& callback);

 private:
  std::vector<unsigned char> load_or_create_salt() const;
  std::filesystem::path path_for_id(const std::string& id) const;
  std::filesystem::path root_;
};

}  // namespace alfie
