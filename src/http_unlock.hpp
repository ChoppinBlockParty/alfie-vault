#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>

#include "ca.hpp"
#include "vault.hpp"

namespace alfie {

struct HttpRequest {
  std::string method;
  std::string target;
  std::string body;
  std::map<std::string, std::string> headers;
};

struct HttpResponse {
  int status = 200;
  std::string content_type = "text/plain; charset=utf-8";
  std::string body;
};

// What a one-time link is allowed to do. A token is minted for exactly one mode and is
// rejected if it arrives on any other path.
enum class UnlockMode {
  Unlock,  // decrypt one record for one task
  Store,   // encrypt a pasted secret into one record
  Init,    // first-time install: fix this vault's login and master password
};

// Everything the first-time install produces besides the vault itself. The CA private key is
// generated in memory and goes straight into the vault; only public certificates and the
// server key (0600) are written to `output_dir`.
struct InitPlan {
  std::filesystem::path output_dir;
  std::string server_ip;
  std::string ca_common_name = "Alfie Local CA";
  int ca_rsa_bits = 4096;
  int server_rsa_bits = 2048;
};

// Where the CA private key is filed inside the vault.
inline constexpr const char* kCaKeyPurpose = "secret-file";
inline constexpr const char* kCaKeyDomain = "alfie.local.ca";
inline constexpr const char* kCaKeyAccount = "alfie-local-ca-key.pem";

// The master password protects everything and can never be changed, so a length floor is
// enforced at the one moment it is chosen.
inline constexpr size_t kMinimumMasterPasswordLength = 12;

struct UnlockRequestSpec {
  std::string purpose;
  std::string domain;
  std::string account;
  std::string action;
  std::chrono::seconds ttl{300};
};

struct DeliveredSecret {
  std::string token;
  std::string domain;
  std::string account;
  std::string action;
  size_t secret_size = 0;
};

class UnlockService {
 public:
  UnlockService(std::filesystem::path vault_dir, std::string expected_login);

  std::string create_token(const UnlockRequestSpec& spec);
  std::string create_store_token(const UnlockRequestSpec& spec);
  // Initialization requires both the link token and a separate terminal-only code.
  std::string create_init_token(const UnlockRequestSpec& spec, InitPlan plan);
  // Public visual identifier for matching a live request to the bot message.
  std::string request_code(const std::string& token) const;
  // Trusted terminal output only; never include this code in an HTTP response.
  const SecureBuffer& setup_code(const std::string& token) const;
  HttpResponse handle(const HttpRequest& request);
  const std::optional<DeliveredSecret>& last_delivery() const {
    return last_delivery_;
  }

  // Fingerprint of the certificate this service is being served under. The setup page shows
  // it so the human can compare it with the value printed on the box's own terminal; a
  // phishing page cannot reproduce a fingerprint the operator printed over SSH.
  void set_transport_fingerprint(std::string fingerprint) {
    transport_fingerprint_ = std::move(fingerprint);
  }

  // True once a first-time install has completed. The setup server stops serving at that
  // point: its certificate is one-off and must never carry a second request.
  bool finished() const {
    return finished_;
  }

 private:
  struct TokenRecord {
    UnlockRequestSpec spec;
    std::chrono::steady_clock::time_point expires_at;
    bool used = false;
    UnlockMode mode = UnlockMode::Unlock;
    InitPlan plan;
    std::string display_code;
    SecureBuffer setup_code;
    unsigned int setup_failures = 0;
  };

  std::string create_token_for(const UnlockRequestSpec& spec, UnlockMode mode, InitPlan plan = {});
  HttpResponse run_first_time_install(TokenRecord& record, const std::string& login,
                                      SecureBuffer& password);
  TokenRecord* live_token(const std::string& token, UnlockMode mode);
  HttpResponse render_form(const std::string& token, UnlockMode mode);
  HttpResponse handle_submit(const std::string& token, const std::string& form_body,
                             UnlockMode mode);

  std::filesystem::path vault_dir_;
  std::string expected_login_;
  std::map<std::string, TokenRecord> tokens_;
  std::optional<DeliveredSecret> last_delivery_;
  std::string transport_fingerprint_;
  bool finished_ = false;
};

HttpRequest parse_http_request(const std::string& raw);
std::string http_response_text(const HttpResponse& response);
// HTTPS only by design: the unlock page carries a vault master password, so there is
// deliberately no plaintext-HTTP server in this build.
int run_https_unlock_server(UnlockService& service, const std::string& bind_host, int port,
                            const std::filesystem::path& certificate_path,
                            const std::filesystem::path& private_key_path, int max_requests = -1);

// Same server, but with certificate and key held only in memory. The first-time setup session
// uses this so its one-off key never reaches the filesystem.
int run_https_unlock_server_in_memory(UnlockService& service, const std::string& bind_host,
                                      int port, const std::string& certificate_pem,
                                      const SecureBuffer& private_key_pem, int max_requests = -1);

}  // namespace alfie
