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
  explicit SecureBuffer(size_t Size);
  explicit SecureBuffer(const std::string &S);
  explicit SecureBuffer(SecureBytes Bytes);
  /// Copies into secure memory and wipes \p Bytes. Only for adapting code that
  /// cannot allocate secure storage up front; prefer the sized constructor.
  explicit SecureBuffer(std::vector<unsigned char> Bytes);
  ~SecureBuffer();

  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;
  SecureBuffer(SecureBuffer &&Other) noexcept = default;
  SecureBuffer &operator=(SecureBuffer &&Other) noexcept;

  const SecureBytes &bytes() const { return this->Data; }
  SecureBytes &bytes() { return this->Data; }
  const unsigned char *data() const { return this->Data.data(); }
  unsigned char *data() { return this->Data.data(); }
  size_t size() const { return this->Data.size(); }
  bool empty() const { return this->Data.empty(); }
  /// Shrinks in place. Wipes the bytes being dropped, and never reallocates, so
  /// a truncation cannot leave a plaintext copy behind in a freed block.
  void truncate(size_t Size);
  /// Copies the secret out into an ordinary std::string. Every caller widens
  /// the plaintext window by doing this -- prefer reading bytes() in place.
  std::string str() const;
  /// Wipe all bytes and release this buffer's logical contents.
  void wipe();

private:
  SecureBytes Data;
};

/// Own the independent indexing and encryption keys for one unlock window.
struct VaultKeys {
  VaultKeys(SecureBuffer Index, SecureBuffer Record)
      : IndexKey(std::move(Index)), RecordKey(std::move(Record)) {}
  VaultKeys(const VaultKeys &) = delete;
  VaultKeys &operator=(const VaultKeys &) = delete;
  VaultKeys(VaultKeys &&) noexcept = default;
  VaultKeys &operator=(VaultKeys &&) noexcept = default;

  SecureBuffer IndexKey;
  SecureBuffer RecordKey;
};

/// Argon2id cost. Stored in vault.meta at init and read back on every unlock,
/// so the cost can be raised for new vaults without making existing ones
/// underivable (NIST SP 800-63B migration guidance). Defaults are well above
/// the OWASP minimum of m=19 MiB, t=2, p=1.
struct Argon2Params {
  uint32_t TCost = 3;
  uint32_t MCostKib = 65536;
  uint32_t Parallelism = 1;
};

/// Argon2id derives independent keys for indexing and record encryption. The
/// passphrase is wiped as soon as Argon2id returns, so each of these consumes
/// its argument.
VaultKeys deriveKeys(SecureBuffer &Passphrase,
                     const std::vector<unsigned char> &Salt,
                     const Argon2Params &Params = {});
VaultKeys deriveKeys(SecureBuffer &Passphrase, const std::string &Context);

/// Extract and lowercase the host, removing a leading www. and trailing dots.
std::string normalizeDomain(const std::string &DomainOrUrl);
/// Compute an opaque HMAC identifier binding purpose, normalized host and
/// account.
std::string recordId(const SecureBuffer &IndexKey, const std::string &Purpose,
                     const std::string &DomainOrUrl,
                     const std::string &Account);

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
bool vaultInitialized(const std::filesystem::path &Root);

/// Throws if the vault already exists, so an init link can never silently
/// re-key a live vault.
void initVault(const std::filesystem::path &Root, const std::string &Login,
               SecureBuffer &Passphrase);

/// Constant-time check of login + master password against the stored verifiers.
/// Returns false for a legacy ALFIEVAULT1 vault, which predates the verifiers
/// and cannot be checked.
bool verifyCredentials(const std::filesystem::path &Root,
                       const std::string &Login, SecureBuffer &Passphrase);

/// True when the vault carries ALFIEVAULT2 credential verifiers.
bool vaultHasCredentials(const std::filesystem::path &Root);

/// One authorized unlock window.
///
/// Opening a session runs Argon2id exactly once and wipes the passphrase; the
/// derived keys live only until the session is destroyed. This is the API the
/// HTTPS unlock path uses, because checking credentials and then touching a
/// record must not mean deriving the master key twice.
class VaultSession {
public:
  /// Derives the master key, wipes \p Passphrase, and checks login + password
  /// against the stored verifiers. Throws CryptoError if they do not match.
  static VaultSession open(const std::filesystem::path &Root,
                           const std::string &Login, SecureBuffer &Passphrase);
  /// Checks the master password but not the login, for callers that have no
  /// login to check (the test-fixture CLI) and for legacy ALFIEVAULT1 vaults,
  /// which carry no verifiers at all. A caller that knows the login should
  /// always prefer open().
  static VaultSession openWithPassword(const std::filesystem::path &Root,
                                       SecureBuffer &Passphrase);

  VaultSession(const VaultSession &) = delete;
  VaultSession &operator=(const VaultSession &) = delete;
  VaultSession(VaultSession &&) noexcept = default;
  VaultSession &operator=(VaultSession &&) noexcept = default;

  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &Purpose,
                            const std::string &DomainOrUrl,
                            const std::string &Account,
                            const SecureBuffer &Plaintext);

  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &Purpose, const std::string &DomainOrUrl,
           const std::string &Account,
           const std::function<void(const SecureBuffer &)> &Callback);

private:
  VaultSession(std::filesystem::path Root, VaultKeys Keys)
      : Root(std::move(Root)), Keys(std::move(Keys)) {}

  std::filesystem::path Root;
  VaultKeys Keys;
};

/// Access one encrypted record at a time without checking a login.
/// Production HTTPS callers should use VaultSession for credential
/// verification.
class ChunkVault {
public:
  explicit ChunkVault(std::filesystem::path Root);

  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &Purpose,
                            const std::string &DomainOrUrl,
                            const std::string &Account,
                            SecureBuffer &Passphrase,
                            const SecureBuffer &Plaintext);

  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &Purpose, const std::string &DomainOrUrl,
           const std::string &Account, SecureBuffer &Passphrase,
           const std::function<void(const SecureBuffer &)> &Callback);

  // -------------------------------------------------------------------------
  /// Test fixtures only. These take and return secrets as plain std::string,
  /// which keeps plaintext on the normal heap for an unbounded lifetime and
  /// leaves copies behind on every reallocation. No production path may call
  /// them; see docs/best-practices.md rule 1.
  // -------------------------------------------------------------------------
  /// Encrypt one record and return its opaque path; the vault must exist.
  std::filesystem::path put(const std::string &Purpose,
                            const std::string &DomainOrUrl,
                            const std::string &Account,
                            const std::string &Passphrase,
                            const std::string &PlaintextJson);
  std::string get(const std::string &Purpose, const std::string &DomainOrUrl,
                  const std::string &Account, const std::string &Passphrase);
  /// Decrypt one record for the callback and wipe plaintext on every exit path.
  void use(const std::string &Purpose, const std::string &DomainOrUrl,
           const std::string &Account, const std::string &Passphrase,
           const std::function<void(const SecureBuffer &)> &Callback);

private:
  std::filesystem::path Root;
};

/// Test fixtures only, for the same reason as the ChunkVault string overloads
/// above.
void initVault(const std::filesystem::path &Root, const std::string &Login,
               const std::string &Passphrase);
bool verifyCredentials(const std::filesystem::path &Root,
                       const std::string &Login, const std::string &Passphrase);

} // namespace alfie

#endif // VAULT_H
