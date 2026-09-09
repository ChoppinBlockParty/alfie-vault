#pragma once

#include "vault.hpp"

#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>

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
    HttpResponse handle(const HttpRequest& request);
    const std::optional<DeliveredSecret>& last_delivery() const { return last_delivery_; }

private:
    struct TokenRecord {
        UnlockRequestSpec spec;
        std::chrono::steady_clock::time_point expires_at;
        bool used = false;
        bool store_mode = false;
    };

    HttpResponse render_form(const std::string& token, bool store_mode);
    HttpResponse handle_submit(const std::string& token, const std::string& form_body, bool store_mode);

    std::filesystem::path vault_dir_;
    std::string expected_login_;
    std::map<std::string, TokenRecord> tokens_;
    std::optional<DeliveredSecret> last_delivery_;
};

HttpRequest parse_http_request(const std::string& raw);
std::string http_response_text(const HttpResponse& response);
int run_http_unlock_server(UnlockService& service, const std::string& bind_host, int port, int max_requests = -1);

} // namespace alfie
