#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "secure_memory.hpp"

namespace alfie {

// Thrown when authentication/decryption fails or OpenSSL reports a crypto error.
class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Storage for secrets: locked out of swap, excluded from core dumps, wiped on free.
// See secure_memory.hpp for how the backing pages are obtained.
using SecureBytes = std::vector<unsigned char, SecureAllocator<unsigned char>>;

// Mutable memory for secrets. Move-only, and wiped with OPENSSL_cleanse before release.
class SecureBuffer {
 public:
  SecureBuffer() = default;
  // Zero-filled buffer of `size` bytes, for writing crypto output straight into secure memory
  // instead of staging it on the normal heap first.
  explicit SecureBuffer(size_t size);
  explicit SecureBuffer(const std::string& s);
  explicit SecureBuffer(SecureBytes bytes);
  // Copies into secure memory and wipes `bytes`. Only for adapting code that cannot allocate
  // secure storage up front; prefer the sized constructor.
  explicit SecureBuffer(std::vector<unsigned char> bytes);
  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept = default;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  const SecureBytes& bytes() const {
    return data_;
  }
  SecureBytes& bytes() {
    return data_;
  }
  const unsigned char* data() const {
    return data_.data();
  }
  unsigned char* data() {
    return data_.data();
  }
  size_t size() const {
    return data_.size();
  }
  bool empty() const {
    return data_.empty();
  }
  // Shrinks in place. Wipes the bytes being dropped, and never reallocates, so a truncation
  // cannot leave a plaintext copy behind in a freed block.
  void truncate(size_t size);
  // Copies the secret out into an ordinary std::string. Every caller widens the plaintext
  // window by doing this -- prefer reading bytes() in place.
  std::string str() const;
  void wipe();

 private:
  SecureBytes data_;
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

// Argon2id cost. Stored in vault.meta at init and read back on every unlock, so the cost can be
// raised for new vaults without making existing ones underivable (NIST SP 800-63B migration
// guidance). Defaults are well above the OWASP minimum of m=19 MiB, t=2, p=1.
struct Argon2Params {
  uint32_t t_cost = 3;
  uint32_t m_cost_kib = 65536;
  uint32_t parallelism = 1;
};

// Argon2id derives independent keys for indexing and record encryption. The passphrase is wiped
// as soon as Argon2id returns, so each of these consumes its argument.
VaultKeys derive_keys(SecureBuffer& passphrase, const std::vector<unsigned char>& salt,
                      const Argon2Params& params = {});
VaultKeys derive_keys(SecureBuffer& passphrase, const std::string& context);

std::string normalize_domain(const std::string& domain_or_url);
std::string record_id(const SecureBuffer& index_key, const std::string& purpose,
                      const std::string& domain_or_url, const std::string& account);

// First-time install. A vault must be created explicitly before any record can be stored or
// read: creating it is what fixes the master password and the login for that vault.
//
// `vault.meta` (format ALFIEVAULT2) holds the non-secret vault salt, the Argon2id cost
// parameters, and two HMAC verifiers derived from the master key. The verifiers let a later
// unlock tell "wrong master password" apart from "no such record" -- without them, a typo at
// store time silently writes a record that can never be found again. Neither the login nor the
// password is recoverable from the verifiers; they are keyed hashes, not ciphertext.
bool vault_initialized(const std::filesystem::path& root);

// Throws if the vault already exists, so an init link can never silently re-key a live vault.
void init_vault(const std::filesystem::path& root, const std::string& login,
                SecureBuffer& passphrase);

// Constant-time check of login + master password against the stored verifiers. Returns false
// for a legacy ALFIEVAULT1 vault, which predates the verifiers and cannot be checked.
bool verify_credentials(const std::filesystem::path& root, const std::string& login,
                        SecureBuffer& passphrase);

// True when the vault carries ALFIEVAULT2 credential verifiers.
bool vault_has_credentials(const std::filesystem::path& root);

// One authorized unlock window.
//
// Opening a session runs Argon2id exactly once and wipes the passphrase; the derived keys live
// only until the session is destroyed. This is the API the HTTPS unlock path uses, because
// checking credentials and then touching a record must not mean deriving the master key twice.
class VaultSession {
 public:
  // Derives the master key, wipes `passphrase`, and checks login + password against the stored
  // verifiers. Throws CryptoError if they do not match.
  static VaultSession open(const std::filesystem::path& root, const std::string& login,
                           SecureBuffer& passphrase);
  // Checks the master password but not the login, for callers that have no login to check
  // (the test-fixture CLI) and for legacy ALFIEVAULT1 vaults, which carry no verifiers at all.
  // A caller that knows the login should always prefer open().
  static VaultSession open_with_password(const std::filesystem::path& root,
                                         SecureBuffer& passphrase);

  VaultSession(const VaultSession&) = delete;
  VaultSession& operator=(const VaultSession&) = delete;
  VaultSession(VaultSession&&) noexcept = default;
  VaultSession& operator=(VaultSession&&) noexcept = default;

  std::filesystem::path put(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, const SecureBuffer& plaintext);

  void use(const std::string& purpose, const std::string& domain_or_url, const std::string& account,
           const std::function<void(const SecureBuffer&)>& callback);

 private:
  VaultSession(std::filesystem::path root, VaultKeys keys)
      : root_(std::move(root)), keys_(std::move(keys)) {}

  std::filesystem::path root_;
  VaultKeys keys_;
};

class ChunkVault {
 public:
  explicit ChunkVault(std::filesystem::path root);

  std::filesystem::path put(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, SecureBuffer& passphrase,
                            const SecureBuffer& plaintext);

  void use(const std::string& purpose, const std::string& domain_or_url, const std::string& account,
           SecureBuffer& passphrase, const std::function<void(const SecureBuffer&)>& callback);

  // ---------------------------------------------------------------------------------------
  // Test fixtures only. These take and return secrets as plain std::string, which keeps
  // plaintext on the normal heap for an unbounded lifetime and leaves copies behind on every
  // reallocation. No production path may call them; see docs/best-practices.md rule 1.
  // ---------------------------------------------------------------------------------------
  std::filesystem::path put(const std::string& purpose, const std::string& domain_or_url,
                            const std::string& account, const std::string& passphrase,
                            const std::string& plaintext_json);
  std::string get(const std::string& purpose, const std::string& domain_or_url,
                  const std::string& account, const std::string& passphrase);
  void use(const std::string& purpose, const std::string& domain_or_url, const std::string& account,
           const std::string& passphrase, const std::function<void(const SecureBuffer&)>& callback);

 private:
  std::filesystem::path root_;
};

// Test fixtures only, for the same reason as the ChunkVault string overloads above.
void init_vault(const std::filesystem::path& root, const std::string& login,
                const std::string& passphrase);
bool verify_credentials(const std::filesystem::path& root, const std::string& login,
                        const std::string& passphrase);

}  // namespace alfie
