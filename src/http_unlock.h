//===----------------------------------------------------------------------===//
/// \file
/// Authorize one-record vault operations through one-time HTTPS links.
//===----------------------------------------------------------------------===//

#ifndef HTTP_UNLOCK_H
#define HTTP_UNLOCK_H

#include "vault.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <utility>

namespace alfie {

/// Parsed request data; the handler borrows the body for one submission.
struct HttpRequest {
  std::string Method;
  std::string Target;
  std::string Body;
  std::map<std::string, std::string> Headers;
};

/// Public response content; unlock responses must never contain a secret.
struct HttpResponse {
  int Status = 200;
  std::string ContentType = "text/plain; charset=utf-8";
  std::string Body;
};

/// What a one-time link is allowed to do. A token is minted for exactly one
/// mode and is rejected if it arrives on any other path.
enum class UnlockMode : std::uint8_t {
  Unlock, // decrypt one record for one task
  Store,  // encrypt a pasted secret into one record
  Init,   // first-time install: fix this vault's login and master password
};

/// Everything the first-time install produces besides the vault itself. The CA
/// private key is generated in memory and goes straight into the vault; only
/// public certificates and the server key (0600) are written to \p OutputDir.
struct InitPlan {
  std::filesystem::path OutputDir;
  std::string ServerIp;
  std::string CaCommonName = "Alfie Local CA";
  int CaRsaBits = 4096;
  int ServerRsaBits = 2048;
};

/// Where the CA private key is filed inside the vault.
inline constexpr char CaKeyPurpose[] = "secret-file";
inline constexpr char CaKeyDomain[] = "alfie.local.ca";
inline constexpr char CaKeyAccount[] = "alfie-local-ca-key.pem";

/// The master password protects everything and can never be changed, so a
/// length floor is enforced at the one moment it is chosen.
inline constexpr size_t MinimumMasterPasswordLength = 12;

/// Scope a one-time authorization to one record, action and expiry interval.
struct UnlockRequestSpec {
  std::string Purpose;
  std::string Domain;
  std::string Account;
  std::string Action;
  std::chrono::seconds Ttl = std::chrono::seconds(300);
};

/// Keep delivery metadata only, without retaining the decrypted value.
struct DeliveredSecret {
  std::string Token;
  std::string Domain;
  std::string Account;
  std::string Action;
  size_t SecretSize = 0;
};

/// Manage single-use tokens and human-authorized vault submissions.
/// Every GET and POST validates the token's mode, expiry and consumption state.
class UnlockService {
public:
  UnlockService(std::filesystem::path VaultDir, std::string ExpectedLogin);

  /// Mint a token authorizing one record unlock within the requested TTL.
  std::string createToken(const UnlockRequestSpec &Spec);
  /// Mint a token authorizing one record write within the requested TTL.
  std::string createStoreToken(const UnlockRequestSpec &Spec);
  /// Initialization requires both the link token and a separate terminal-only
  /// code.
  std::string createInitToken(const UnlockRequestSpec &Spec, InitPlan Plan);
  /// Public visual identifier for matching a live request to the bot message.
  std::string requestCode(const std::string &Token) const;
  /// Trusted terminal output only; never include this code in an HTTP response.
  const SecureBuffer &setupCode(const std::string &Token) const;
  /// Validate and dispatch a request, reporting success without secret values.
  HttpResponse handle(const HttpRequest &Request);
  /// Return metadata from the last successful unlock, or no value before one.
  const std::optional<DeliveredSecret> &lastDelivery() const {
    return this->LastDelivery;
  }

  /// Fingerprint of the certificate this service is being served under. The
  /// setup page shows it so the human can compare it with the value printed on
  /// the box's own terminal; a phishing page cannot reproduce a fingerprint the
  /// operator printed over SSH.
  void setTransportFingerprint(std::string Fingerprint) {
    this->TransportFingerprint = std::move(Fingerprint);
  }

  /// True once a first-time install has completed. The setup server stops
  /// serving at that point: its certificate is one-off and must never carry a
  /// second request.
  bool finished() const { return this->Finished; }

private:
  struct TokenRecord {
    UnlockRequestSpec Spec;
    std::chrono::steady_clock::time_point ExpiresAt;
    bool Used = false;
    UnlockMode Mode = UnlockMode::Unlock;
    InitPlan Plan;
    std::string DisplayCode;
    SecureBuffer SetupCode;
    unsigned int SetupFailures = 0;
  };

  std::string createTokenFor(const UnlockRequestSpec &Spec, UnlockMode Mode,
                             InitPlan Plan = {});
  HttpResponse runFirstTimeInstall(TokenRecord &Record,
                                   const std::string &Login,
                                   SecureBuffer &Password);
  TokenRecord *liveToken(const std::string &Token, UnlockMode Mode);
  HttpResponse renderForm(const std::string &Token, UnlockMode Mode);
  HttpResponse handleSubmit(const std::string &Token,
                            const std::string &FormBody, UnlockMode Mode);

  std::filesystem::path VaultDir;
  std::string ExpectedLogin;
  std::map<std::string, TokenRecord> Tokens;
  std::optional<DeliveredSecret> LastDelivery;
  std::string TransportFingerprint;
  bool Finished = false;
};

/// Parse a bounded HTTP request, rejecting malformed framing.
HttpRequest parseHttpRequest(const std::string &Raw);
/// Serialize status, headers and the public response body.
std::string httpResponseText(const HttpResponse &Response);
/// HTTPS only by design: the unlock page carries a vault master password, so
/// there is deliberately no plaintext-HTTP server in this build.
int runHttpsUnlockServer(UnlockService &Service, const std::string &BindHost,
                         int Port, const std::filesystem::path &CertificatePath,
                         const std::filesystem::path &PrivateKeyPath,
                         int MaxRequests = -1);

/// Same server, but with certificate and key held only in memory. The
/// first-time setup session uses this so its one-off key never reaches the
/// filesystem.
int runHttpsUnlockServerInMemory(UnlockService &Service,
                                 const std::string &BindHost, int Port,
                                 const std::string &CertificatePem,
                                 const SecureBuffer &PrivateKeyPem,
                                 int MaxRequests = -1);

} // namespace alfie

#endif // HTTP_UNLOCK_H
