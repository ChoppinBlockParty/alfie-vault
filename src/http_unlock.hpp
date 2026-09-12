#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>

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
  Unlock,     // decrypt one record for one task
  Store,      // encrypt a pasted secret into one record
  StoreFile,  // encrypt a prepared file, then wipe it from disk
  Init,       // first-time install: fix this vault's login and master password
};

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
  std::string create_store_file_token(const UnlockRequestSpec& spec,
                                      std::filesystem::path source_file);
  // First-time install link. The token itself is the authorization: there are no vault
  // credentials to check yet, because this is what creates them.
  std::string create_init_token(const UnlockRequestSpec& spec);
  HttpResponse handle(const HttpRequest& request);
  const std::optional<DeliveredSecret>& last_delivery() const {
    return last_delivery_;
  }

 private:
  struct TokenRecord {
    UnlockRequestSpec spec;
    std::chrono::steady_clock::time_point expires_at;
    bool used = false;
    UnlockMode mode = UnlockMode::Unlock;
    std::filesystem::path source_file;
  };

  std::string create_token_for(const UnlockRequestSpec& spec, UnlockMode mode,
                               std::filesystem::path source_file = {});
  TokenRecord* live_token(const std::string& token, UnlockMode mode);
  HttpResponse render_form(const std::string& token, UnlockMode mode);
  HttpResponse handle_submit(const std::string& token, const std::string& form_body,
                             UnlockMode mode);

  std::filesystem::path vault_dir_;
  std::string expected_login_;
  std::map<std::string, TokenRecord> tokens_;
  std::optional<DeliveredSecret> last_delivery_;
};

HttpRequest parse_http_request(const std::string& raw);
std::string http_response_text(const HttpResponse& response);
// HTTPS only by design: the unlock page carries a vault master password, so there is
// deliberately no plaintext-HTTP server in this build.
int run_https_unlock_server(UnlockService& service, const std::string& bind_host, int port,
                            const std::filesystem::path& certificate_path,
                            const std::filesystem::path& private_key_path, int max_requests = -1);

}  // namespace alfie
