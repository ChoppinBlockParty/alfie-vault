//===----------------------------------------------------------------------===//
/// \file
/// Store independently encrypted records and scope keys to one unlock.
//===----------------------------------------------------------------------===//

#ifndef VAULT_H
#define VAULT_H

#include "secure_memory.h"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace alfie {

/// Thrown when authentication/decryption fails or OpenSSL reports a crypto
/// error.
class CryptoError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
  ~CryptoError() override;
};

/// Storage for secrets: locked out of swap, excluded from core dumps, wiped on
/// free. See secure_memory.h for how the backing pages are obtained.
using SecureBytes = std::vector<unsigned char, SecureAllocator<unsigned char>>;

/// Mutable memory for secrets. Move-only, and wiped with OPENSSL_cleanse before
/// release.
class SecureBuffer {
public:
  SecureBuffer() = default;
  /// Zero-filled buffer of \p Size bytes, for writing crypto output straight
  /// into secure memory instead of staging it on the normal heap first.
  explicit SecureBuffer(size_t size);
  explicit SecureBuffer(const std::string &s);
  explicit SecureBuffer(SecureBytes bytes);
  /// Copies into secure memory and wipes \p Bytes. Only for adapting code that
  /// cannot allocate secure storage up front; prefer the sized constructor.
  explicit SecureBuffer(std::vector<unsigned char> bytes);
  ~SecureBuffer();

  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;
  SecureBuffer(SecureBuffer &&other) noexcept = default;
  SecureBuffer &operator=(SecureBuffer &&other) noexcept;

  const SecureBytes &bytes() const { return this->data_; }
  SecureBytes &bytes() { return this->data_; }
  const unsigned char *data() const { return this->data_.data(); }
  unsigned char *data() { return this->data_.data(); }
  size_t size() const { return this->data_.size(); }
  bool empty() const { return this->data_.empty(); }
  /// Shrinks in place. Wipes the bytes being dropped, and never reallocates, so
  /// a truncation cannot leave a plaintext copy behind in a freed block.
  void truncate(size_t size);
  /// Copies the secret out into an ordinary std::string. Every caller widens
  /// the plaintext window by doing this -- prefer reading bytes() in place.
  std::string str() const;
  /// Wipe all bytes and release this buffer's logical contents.
  void wipe();

private:
  SecureBytes data_;
};

/// Own the independent indexing and encryption keys for one unlock window.
struct VaultKeys {
  VaultKeys(SecureBuffer index, SecureBuffer record)
      : indexKey(std::move(index)), recordKey(std::move(record)) {}
  VaultKeys(const VaultKeys &) = delete;
  VaultKeys &operator=(const VaultKeys &) = delete;
  VaultKeys(VaultKeys &&) noexcept = default;
  VaultKeys &operator=(VaultKeys &&) noexcept = default;

  SecureBuffer indexKey;
  SecureBuffer recordKey;
};

/// Argon2id cost. Stored in vault.meta at init and read back on every unlock,
/// so the cost can be raised for new vaults without making existing ones
/// underivable (NIST SP 800-63B migration guidance). Defaults are well above
/// the OWASP minimum of m=19 MiB, t=2, p=1.
struct Argon2Params {
  uint32_t tCost = 3;
  uint32_t mCostKib = 65536;
  uint32_t parallelism = 1;
};

/// Argon2id derives independent keys for indexing and record encryption. The
/// passphrase is wiped as soon as Argon2id returns, so each of these consumes
/// its argument.
VaultKeys deriveKeys(SecureBuffer &passphrase,
                     const std::vector<unsigned char> &salt,
                     const Argon2Params &params = {});
VaultKeys deriveKeys(SecureBuffer &passphrase, const std::string &context);

/// Extract and lowercase the host, removing a leading www. and trailing dots.
std::string normalizeDomain(const std::string &domainOrUrl);
/// Compute an opaque HMAC identifier binding purpose, normalized host and
/// account.
std::string recordId(const SecureBuffer &indexKey, const std::string &purpose,
                     const std::string &domainOrUrl,
                     const std::string &account);

/// The master password protects everything and can never be changed, so a
/// length floor is enforced at the one moment it is chosen. It lives here
/// rather than beside the HTTPS form because initVault() is what fixes the
/// password, and every path that creates a vault goes through it.
inline constexpr size_t kMinimumMasterPasswordLength = 12;

/// First-time install. A vault must be created explicitly before any record can
/// be stored or read: creating it is what fixes the master password and the
/// login for that vault.
///
/// `vault.meta` (format ALFIEVAULT2) holds the non-secret vault salt, the
/// Argon2id cost parameters, and two HMAC verifiers derived from the master
/// key. The verifiers let a later unlock tell "wrong master password" apart
/// from "no such record" -- without them, a typo at store time silently writes
/// a record that can never be found again. Neither the login nor the password
/// is recoverable from the verifiers; they are keyed hashes, not ciphertext.
bool vaultInitialized(const std::filesystem::path &root);

/// Throws if the vault already exists, so an init link can never silently
/// re-key a live vault, and if the master password is shorter than
/// kMinimumMasterPasswordLength.
void initVault(const std::filesystem::path &root, const std::string &login,
               SecureBuffer &passphrase);

/// Constant-time check of login + master password against the stored verifiers.
/// Returns false for a legacy ALFIEVAULT1 vault, which predates the verifiers
/// and cannot be checked.
bool verifyCredentials(const std::filesystem::path &root,
                       const std::string &login, SecureBuffer &passphrase);

/// True when the vault carries ALFIEVAULT2 credential verifiers.
bool vaultHasCredentials(const std::filesystem::path &root);

/// One authorized unlock window.
///
/// Opening a session runs Argon2id exactly once and wipes the passphrase; the
/// derived keys live only until the session is destroyed. This is the API the
/// HTTPS unlock path uses, because checking credentials and then touching a
/// record must not mean deriving the master key twice.
class VaultSession {
public:
  /// Derives the master key, wipes \p passphrase, and checks login + password
  /// against the stored verifiers. Throws CryptoError if they do not match.
  static VaultSession open(const std::filesystem::path &root,
                           const std::string &login, SecureBuffer &passphrase);
  /// Checks the master password but not the login, for callers that have no
  /// login to check (the test-fixture CLI) and for legacy ALFIEVAULT1 vaults,
  /// which carry no verifiers at all. A caller that knows the login should
  /// always prefer open().
  static VaultSession openWithPassword(const std::filesystem::path &root,
                                       SecureBuffer &passphrase);

  VaultSession(const VaultSession &) = delete;
  VaultSession &operator=(const VaultSession &) = delete;
  VaultSession(VaultSession &&) noexcept = default;
  VaultSession &operator=(VaultSession &&) noexcept = default;

  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &purpose,
                            const std::string &domainOrUrl,
                            const std::string &account,
                            const SecureBuffer &plaintext);

  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &purpose, const std::string &domainOrUrl,
           const std::string &account,
           const std::function<void(const SecureBuffer &)> &callback);

private:
  VaultSession(std::filesystem::path root, VaultKeys keys)
      : root_(std::move(root)), keys_(std::move(keys)) {}

  std::filesystem::path root_;
  VaultKeys keys_;
};

/// Access one encrypted record at a time without checking a login.
/// Production HTTPS callers should use VaultSession for credential
/// verification.
class ChunkVault {
public:
  explicit ChunkVault(std::filesystem::path root);

  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &purpose,
                            const std::string &domainOrUrl,
                            const std::string &account,
                            SecureBuffer &passphrase,
                            const SecureBuffer &plaintext);

  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &purpose, const std::string &domainOrUrl,
           const std::string &account, SecureBuffer &passphrase,
           const std::function<void(const SecureBuffer &)> &callback);

  // -------------------------------------------------------------------------
  /// Test fixtures only. These take and return secrets as plain std::string,
  /// which keeps plaintext on the normal heap for an unbounded lifetime and
  /// leaves copies behind on every reallocation. No production path may call
  /// them; see docs/best-practices.md rule 1.
  // -------------------------------------------------------------------------
  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &purpose,
                            const std::string &domainOrUrl,
                            const std::string &account,
                            const std::string &passphrase,
                            const std::string &plaintextJson);
  std::string get(const std::string &purpose, const std::string &domainOrUrl,
                  const std::string &account, const std::string &passphrase);
  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &purpose, const std::string &domainOrUrl,
           const std::string &account, const std::string &passphrase,
           const std::function<void(const SecureBuffer &)> &callback);

private:
  std::filesystem::path root_;
};

/// Test fixtures only, for the same reason as the ChunkVault string overloads
/// above.
void initVault(const std::filesystem::path &root, const std::string &login,
               const std::string &passphrase);
bool verifyCredentials(const std::filesystem::path &root,
                       const std::string &login, const std::string &passphrase);

} // namespace alfie

#endif // VAULT_H
