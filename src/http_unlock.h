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
  std::string method;
  std::string target;
  std::string body;
  std::map<std::string, std::string> headers;
};

/// Public response content; unlock responses must never contain a secret.
struct HttpResponse {
  int status = 200;
  std::string contentType = "text/plain; charset=utf-8";
  std::string body;
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
  std::filesystem::path outputDir;
  std::string serverIp;
  std::string caCommonName = "Alfie Local CA";
  int caRsaBits = 4096;
  int serverRsaBits = 2048;
};

/// Where the CA private key is filed inside the vault.
inline constexpr char kCaKeyPurpose[] = "secret-file";
inline constexpr char kCaKeyDomain[] = "alfie.local.ca";
inline constexpr char kCaKeyAccount[] = "alfie-local-ca-key.pem";

/// Scope a one-time authorization to one record, action and expiry interval.
struct UnlockRequestSpec {
  std::string purpose;
  std::string domain;
  std::string account;
  std::string action;
  std::chrono::seconds ttl = std::chrono::seconds(300);
};

/// Keep delivery metadata only, without retaining the decrypted value.
struct DeliveredSecret {
  std::string token;
  std::string domain;
  std::string account;
  std::string action;
  size_t secretSize = 0;
};

/// Manage single-use tokens and human-authorized vault submissions.
/// Every GET and POST validates the token's mode, expiry and consumption state.
class UnlockService {
public:
  UnlockService(std::filesystem::path vaultDir, std::string expectedLogin);

  /// Mint a token authorizing one record unlock within the requested TTL.
  std::string createToken(const UnlockRequestSpec &spec);
  /// Mint a token authorizing one record write within the requested TTL.
  std::string createStoreToken(const UnlockRequestSpec &spec);
  /// Initialization requires both the link token and a separate terminal-only
  /// code.
  std::string createInitToken(const UnlockRequestSpec &spec, InitPlan plan);
  /// Public visual identifier for matching a live request to the bot message.
  std::string requestCode(const std::string &token) const;
  /// Trusted terminal output only; never include this code in an HTTP response.
  const SecureBuffer &setupCode(const std::string &token) const;
  /// Validate and dispatch a request, reporting success without secret values.
  HttpResponse handle(const HttpRequest &request);
  /// Return metadata from the last successful unlock, or no value before one.
  const std::optional<DeliveredSecret> &lastDelivery() const {
    return this->lastDelivery_;
  }

  /// Fingerprint of the certificate this service is being served under. The
  /// setup page shows it so the human can compare it with the value printed on
  /// the box's own terminal; a phishing page cannot reproduce a fingerprint the
  /// operator printed over SSH.
  void setTransportFingerprint(std::string fingerprint) {
    this->transportFingerprint_ = std::move(fingerprint);
  }

  /// True once a first-time install has completed. The setup server stops
  /// serving at that point: its certificate is one-off and must never carry a
  /// second request.
  bool finished() const { return this->finished_; }

private:
  struct TokenRecord {
    UnlockRequestSpec spec;
    std::chrono::steady_clock::time_point expiresAt;
    bool used = false;
    UnlockMode mode = UnlockMode::Unlock;
    InitPlan plan;
    std::string displayCode;
    SecureBuffer setupCode;
    unsigned int setupFailures = 0;
  };

  std::string createTokenFor(const UnlockRequestSpec &spec, UnlockMode mode,
                             InitPlan plan = {});
  HttpResponse runFirstTimeInstall(TokenRecord &record,
                                   const std::string &login,
                                   SecureBuffer &password);
  TokenRecord *findLiveToken(const std::string &token, UnlockMode mode);
  HttpResponse renderForm(const std::string &token, UnlockMode mode);
  HttpResponse handleSubmit(const std::string &token,
                            const std::string &formBody, UnlockMode mode);

  std::filesystem::path vaultDir_;
  std::string expectedLogin_;
  std::map<std::string, TokenRecord> tokens_;
  std::optional<DeliveredSecret> lastDelivery_;
  std::string transportFingerprint_;
  bool finished_ = false;
};

/// Parse a bounded HTTP request, rejecting malformed framing.
HttpRequest parseHttpRequest(const std::string &raw);
/// Serialize status, headers and the public response body.
std::string httpResponseText(const HttpResponse &response);
/// HTTPS only by design: the unlock page carries a vault master password, so
/// there is deliberately no plaintext-HTTP server in this build.
int runHttpsUnlockServer(UnlockService &service, const std::string &bindHost,
                         int port, const std::filesystem::path &certificatePath,
                         const std::filesystem::path &privateKeyPath,
                         int maxRequests = -1);

/// Same server, but with certificate and key held only in memory. The
/// first-time setup session uses this so its one-off key never reaches the
/// filesystem.
int runHttpsUnlockServerInMemory(UnlockService &service,
                                 const std::string &bindHost, int port,
                                 const std::string &certificatePem,
                                 const SecureBuffer &privateKeyPem,
                                 int maxRequests = -1);

} // namespace alfie

#endif // HTTP_UNLOCK_H
