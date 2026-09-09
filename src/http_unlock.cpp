#include "http_unlock.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

namespace alfie {
namespace {
std::runtime_error sys_error(const std::string& what) {
    return std::runtime_error(what + ": " + std::strerror(errno));
}

std::string random_token() {
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw CryptoError("RAND_bytes failed");
    std::ostringstream out;
    for (auto b : bytes) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return out.str();
}

std::string html_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += c; break;
        }
    }
    return out;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

std::string url_decode(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '+') {
            out.push_back(' ');
        } else if (in[i] == '%' && i + 2 < in.size()) {
            int hi = hex_value(in[i + 1]);
            int lo = hex_value(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
            } else {
                out.push_back(in[i]);
            }
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

std::map<std::string, std::string> parse_form(const std::string& body) {
    std::map<std::string, std::string> fields;
    size_t start = 0;
    while (start <= body.size()) {
        size_t end = body.find('&', start);
        if (end == std::string::npos) end = body.size();
        auto part = body.substr(start, end - start);
        auto eq = part.find('=');
        if (eq != std::string::npos) fields[url_decode(part.substr(0, eq))] = url_decode(part.substr(eq + 1));
        if (end == body.size()) break;
        start = end + 1;
    }
    return fields;
}

std::string status_text(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 410: return "Gone";
        case 500: return "Internal Server Error";
        default: return "OK";
    }
}

std::string token_from_target(const std::string& target) {
    constexpr const char* prefix = "/unlock/";
    if (target.rfind(prefix, 0) != 0) return {};
    auto token = target.substr(std::char_traits<char>::length(prefix));
    auto q = token.find('?');
    if (q != std::string::npos) token.resize(q);
    return token;
}
} // namespace

UnlockService::UnlockService(std::filesystem::path vault_dir, std::string expected_login)
    : vault_dir_(std::move(vault_dir)), expected_login_(std::move(expected_login)) {}

std::string UnlockService::create_token(const UnlockRequestSpec& spec) {
    std::string token = random_token();
    tokens_[token] = TokenRecord{spec, std::chrono::steady_clock::now() + spec.ttl, false};
    return token;
}

HttpResponse UnlockService::handle(const HttpRequest& request) {
    std::string token = token_from_target(request.target);
    if (token.empty()) return {404, "text/plain; charset=utf-8", "Not found"};
    if (request.method == "GET") return render_form(token);
    if (request.method == "POST") return handle_submit(token, request.body);
    return {405, "text/plain; charset=utf-8", "Method not allowed"};
}

HttpResponse UnlockService::render_form(const std::string& token) {
    auto it = tokens_.find(token);
    if (it == tokens_.end() || it->second.used || std::chrono::steady_clock::now() > it->second.expires_at) {
        return {410, "text/plain; charset=utf-8", "Unlock link expired"};
    }
    const auto& spec = it->second.spec;
    std::string body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Alfie Vault Unlock</title></head>"
                       "<body><h1>Alfie Vault Unlock</h1>"
                       "<p>Domain: " + html_escape(spec.domain) + "</p>"
                       "<p>Action: " + html_escape(spec.action) + "</p>"
                       "<form method=\"post\" action=\"/unlock/" + html_escape(token) + "\">"
                       "<label>Login <input name=\"login\" autocomplete=\"username\"></label><br>"
                       "<label>Vault password <input name=\"password\" type=\"password\" autocomplete=\"current-password\"></label><br>"
                       "<button type=\"submit\">Unlock once</button>"
                       "</form></body></html>";
    return {200, "text/html; charset=utf-8", body};
}

HttpResponse UnlockService::handle_submit(const std::string& token, const std::string& form_body) {
    auto it = tokens_.find(token);
    if (it == tokens_.end() || it->second.used || std::chrono::steady_clock::now() > it->second.expires_at) {
        return {410, "text/plain; charset=utf-8", "Unlock link expired"};
    }
    auto fields = parse_form(form_body);
    auto login = fields.find("login");
    auto password = fields.find("password");
    if (login == fields.end() || password == fields.end()) return {400, "text/plain; charset=utf-8", "Missing login or password"};
    if (login->second != expected_login_) return {403, "text/plain; charset=utf-8", "Bad login"};

    const auto spec = it->second.spec;
    try {
        ChunkVault vault(vault_dir_);
        vault.use(spec.purpose, spec.domain, spec.account, password->second, [&](const SecureBuffer& secret) {
            // Real browser-worker delivery will use encrypted IPC. Until that integration,
            // store only metadata proving that one secret was unlocked; never store payload.
            last_delivery_ = DeliveredSecret{token, spec.domain, spec.account, spec.action, secret.size()};
        });
        it->second.used = true;
        password->second.assign(password->second.size(), '\0');
        return {200, "text/html; charset=utf-8", "<html><body>Unlocked. Credential delivered to local worker.</body></html>"};
    } catch (const std::exception&) {
        password->second.assign(password->second.size(), '\0');
        return {403, "text/plain; charset=utf-8", "Unlock failed"};
    }
}

HttpRequest parse_http_request(const std::string& raw) {
    HttpRequest req;
    auto header_end = raw.find("\r\n\r\n");
    std::string head = raw.substr(0, header_end == std::string::npos ? raw.size() : header_end);
    req.body = header_end == std::string::npos ? std::string{} : raw.substr(header_end + 4);
    std::istringstream in(head);
    std::string version;
    in >> req.method >> req.target >> version;
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c){ return std::tolower(c); });
        std::string value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        req.headers[name] = value;
    }
    return req;
}

std::string http_response_text(const HttpResponse& response) {
    std::ostringstream out;
    out << "HTTP/1.1 " << response.status << " " << status_text(response.status) << "\r\n"
        << "Content-Type: " << response.content_type << "\r\n"
        << "Content-Length: " << response.body.size() << "\r\n"
        << "Cache-Control: no-store\r\n"
        << "Connection: close\r\n\r\n"
        << response.body;
    return out.str();
}

int run_http_unlock_server(UnlockService& service, const std::string& bind_host, int port, int max_requests) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw sys_error("socket");
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, bind_host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        throw std::runtime_error("bind host must be IPv4 address");
    }
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        throw sys_error("bind");
    }
    if (listen(fd, 16) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        throw sys_error("listen");
    }

    int handled = 0;
    while (max_requests < 0 || handled < max_requests) {
        int client = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            close(fd);
            errno = saved;
            throw sys_error("accept");
        }
        std::string raw;
        char buf[8192];
        ssize_t n = read(client, buf, sizeof(buf));
        if (n > 0) raw.assign(buf, buf + n);
        auto response = http_response_text(service.handle(parse_http_request(raw)));
        (void)write(client, response.data(), response.size());
        close(client);
        ++handled;
    }
    close(fd);
    return handled;
}

} // namespace alfie
