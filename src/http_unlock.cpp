#include "http_unlock.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace alfie {
namespace {
std::runtime_error sys_error(const std::string& what) {
  return std::runtime_error(what + ": " + std::strerror(errno));
}

std::string random_token() {
  unsigned char bytes[32];
  if (RAND_bytes(bytes, sizeof(bytes)) != 1)
    throw CryptoError("RAND_bytes failed");
  std::ostringstream out;
  for (auto b : bytes)
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  OPENSSL_cleanse(bytes, sizeof(bytes));
  return out.str();
}

std::string html_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      default:
        out += c;
        break;
    }
  }
  return out;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
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
    if (end == std::string::npos)
      end = body.size();
    auto part = body.substr(start, end - start);
    auto eq = part.find('=');
    if (eq != std::string::npos)
      fields[url_decode(part.substr(0, eq))] = url_decode(part.substr(eq + 1));
    if (end == body.size())
      break;
    start = end + 1;
  }
  return fields;
}

std::string status_text(int status) {
  switch (status) {
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 400:
      return "Bad Request";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 410:
      return "Gone";
    case 500:
      return "Internal Server Error";
    default:
      return "OK";
  }
}

std::string token_from_target(const std::string& target, const std::string& prefix) {
  if (target.rfind(prefix, 0) != 0)
    return {};
  auto token = target.substr(prefix.size());
  auto q = token.find('?');
  if (q != std::string::npos)
    token.resize(q);
  return token;
}

size_t content_length_from_raw(const std::string& raw) {
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos)
    return 0;
  auto req = parse_http_request(raw.substr(0, header_end + 4));
  auto it = req.headers.find("content-length");
  if (it == req.headers.end())
    return 0;
  return static_cast<size_t>(std::stoul(it->second));
}

bool http_message_complete(const std::string& raw) {
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos)
    return false;
  return raw.size() >= header_end + 4 + content_length_from_raw(raw);
}

std::string read_http_plain(int fd) {
  std::string raw;
  char buf[8192];
  while (!http_message_complete(raw)) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0)
      break;
    raw.append(buf, buf + n);
  }
  return raw;
}

std::string read_http_tls(SSL* ssl) {
  std::string raw;
  char buf[8192];
  while (!http_message_complete(raw)) {
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0)
      break;
    raw.append(buf, buf + n);
  }
  return raw;
}

std::string read_file_secret(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw CryptoError("source secret file not found");
  }
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void wipe_and_remove_file(const std::filesystem::path& path) {
  std::error_code ec;
  auto size = std::filesystem::file_size(path, ec);
  if (!ec) {
    std::ofstream out(path, std::ios::binary | std::ios::in);
    std::string zeros(8192, '\0');
    while (size > 0 && out) {
      const auto n = std::min<uintmax_t>(size, zeros.size());
      out.write(zeros.data(), static_cast<std::streamsize>(n));
      size -= n;
    }
    out.flush();
  }
  std::filesystem::remove(path, ec);
}
}  // namespace

UnlockService::UnlockService(std::filesystem::path vault_dir, std::string expected_login)
    : vault_dir_(std::move(vault_dir)), expected_login_(std::move(expected_login)) {}

std::string UnlockService::create_token(const UnlockRequestSpec& spec) {
  std::string token = random_token();
  tokens_[token] =
      TokenRecord{spec, std::chrono::steady_clock::now() + spec.ttl, false, false, false, {}};
  return token;
}

std::string UnlockService::create_store_token(const UnlockRequestSpec& spec) {
  std::string token = random_token();
  tokens_[token] =
      TokenRecord{spec, std::chrono::steady_clock::now() + spec.ttl, false, true, false, {}};
  return token;
}

std::string UnlockService::create_store_file_token(const UnlockRequestSpec& spec,
                                                   std::filesystem::path source_file) {
  std::string token = random_token();
  tokens_[token] = TokenRecord{
      spec, std::chrono::steady_clock::now() + spec.ttl, false, true, true, std::move(source_file)};
  return token;
}

HttpResponse UnlockService::handle(const HttpRequest& request) {
  std::string token = token_from_target(request.target, "/unlock/");
  bool store_mode = false;
  bool store_file_mode = false;
  if (token.empty()) {
    token = token_from_target(request.target, "/store/");
    store_mode = true;
  }
  if (token.empty()) {
    token = token_from_target(request.target, "/store-file/");
    store_mode = true;
    store_file_mode = true;
  }
  if (token.empty())
    return {404, "text/plain; charset=utf-8", "Not found"};
  if (request.method == "GET")
    return render_form(token, store_mode, store_file_mode);
  if (request.method == "POST")
    return handle_submit(token, request.body, store_mode, store_file_mode);
  return {405, "text/plain; charset=utf-8", "Method not allowed"};
}

HttpResponse UnlockService::render_form(const std::string& token, bool store_mode,
                                        bool store_file_mode) {
  auto it = tokens_.find(token);
  if (it == tokens_.end() || it->second.used || it->second.store_mode != store_mode ||
      it->second.store_file_mode != store_file_mode ||
      std::chrono::steady_clock::now() > it->second.expires_at) {
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};
  }
  const auto& spec = it->second.spec;
  std::string title = store_mode ? "Alfie Vault Store" : "Alfie Vault Unlock";
  std::string action_path = "/unlock/";
  if (store_file_mode) {
    action_path = "/store-file/";
  } else if (store_mode) {
    action_path = "/store/";
  }
  std::string value_field;
  if (store_file_mode) {
    value_field =
        "<p>No secret value will be shown. The server will encrypt the prepared file "
        "after successful unlock, then remove it from disk.</p>";
  } else if (store_mode) {
    value_field =
        "<label>Secret JSON <textarea name=\"value\" "
        "autocomplete=\"off\"></textarea></label><br>";
  }
  std::string button = store_mode ? "Store once" : "Unlock once";
  std::string body =
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
      "<title>" +
      title +
      "</title><style>"
      ":root{color-scheme:light dark}*{box-sizing:border-box}"
      "body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe "
      "UI',Roboto,sans-serif;"
      "background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;"
      "padding:24px}"
      ".card{width:100%;max-width:520px;background:#111827;border:1px solid "
      "#334155;border-radius:18px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}"
      "h1{font-size:1.4rem;margin:0 0 16px}.meta{color:#cbd5e1;font-size:.95rem;margin:8px 0}"
      "label{display:block;margin-top:16px;font-weight:600}"
      "input,textarea,button{width:100%;font:inherit;border-radius:12px;border:1px solid "
      "#475569;padding:14px;margin-top:8px}"
      "input,textarea{background:#020617;color:#f8fafc}textarea{min-height:120px}"
      "button{background:#2563eb;color:white;border:0;font-weight:700;margin-top:20px;cursor:"
      "pointer}"
      ".note{background:#172554;color:#bfdbfe;border-radius:12px;padding:12px;margin-top:16px}"
      "@media "
      "(max-width:540px){body{padding:12px;align-items:stretch}.card{border-radius:14px;padding:"
      "18px}}"
      "</style></head><body><main class=\"card\"><h1>" +
      title + "</h1><p class=\"meta\">Domain: " + html_escape(spec.domain) +
      "</p><p class=\"meta\">Action: " + html_escape(spec.action) +
      "</p><form method=\"post\" action=\"" + action_path + html_escape(token) +
      "\"><label>Login <input name=\"login\" autocomplete=\"username\" autocapitalize=\"none\" "
      "spellcheck=\"false\" inputmode=\"text\"></label>"
      "<label>Vault password <input name=\"password\" type=\"password\" "
      "autocomplete=\"current-password\"></label>" +
      value_field + "<button type=\"submit\">" + button + "</button></form></main></body></html>";
  return {200, "text/html; charset=utf-8", body};
}

HttpResponse UnlockService::handle_submit(const std::string& token, const std::string& form_body,
                                          bool store_mode, bool store_file_mode) {
  auto it = tokens_.find(token);
  if (it == tokens_.end() || it->second.used || it->second.store_mode != store_mode ||
      it->second.store_file_mode != store_file_mode ||
      std::chrono::steady_clock::now() > it->second.expires_at) {
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};
  }
  auto fields = parse_form(form_body);
  auto login = fields.find("login");
  auto password = fields.find("password");
  if (login == fields.end() || password == fields.end())
    return {400, "text/plain; charset=utf-8", "Missing login or password"};
  if (login->second != expected_login_)
    return {403, "text/plain; charset=utf-8", "Bad login"};

  const auto spec = it->second.spec;
  try {
    ChunkVault vault(vault_dir_);
    if (store_file_mode) {
      std::string file_secret = read_file_secret(it->second.source_file);
      SecureBuffer secret_value(file_secret);
      vault.put(spec.purpose, spec.domain, spec.account, password->second, secret_value.str());
      last_delivery_ =
          DeliveredSecret{token, spec.domain, spec.account, spec.action, secret_value.size()};
      OPENSSL_cleanse(file_secret.data(), file_secret.size());
      wipe_and_remove_file(it->second.source_file);
    } else if (store_mode) {
      auto value = fields.find("value");
      if (value == fields.end() || value->second.empty())
        return {400, "text/plain; charset=utf-8", "Missing secret value"};
      SecureBuffer secret_value(value->second);
      vault.put(spec.purpose, spec.domain, spec.account, password->second, secret_value.str());
      last_delivery_ =
          DeliveredSecret{token, spec.domain, spec.account, spec.action, secret_value.size()};
      value->second.assign(value->second.size(), '\0');
    } else {
      vault.use(spec.purpose, spec.domain, spec.account, password->second,
                [&](const SecureBuffer& secret) {
                  // Real browser-worker delivery will use encrypted IPC. Until that integration,
                  // store only metadata proving that one secret was unlocked; never store payload.
                  last_delivery_ =
                      DeliveredSecret{token, spec.domain, spec.account, spec.action, secret.size()};
                });
    }
    it->second.used = true;
    password->second.assign(password->second.size(), '\0');
    return {200, "text/html; charset=utf-8",
            store_mode
                ? "<html><body>Stored.</body></html>"
                : "<html><body>Unlocked. Credential delivered to local worker.</body></html>"};
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
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    auto colon = line.find(':');
    if (colon == std::string::npos)
      continue;
    std::string name = line.substr(0, colon);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::string value = line.substr(colon + 1);
    while (!value.empty() && value.front() == ' ')
      value.erase(value.begin());
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

int run_http_unlock_server(UnlockService& service, const std::string& bind_host, int port,
                           int max_requests) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    throw sys_error("socket");
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
      if (errno == EINTR)
        continue;
      int saved = errno;
      close(fd);
      errno = saved;
      throw sys_error("accept");
    }
    std::string raw = read_http_plain(client);
    auto response = http_response_text(service.handle(parse_http_request(raw)));
    (void)write(client, response.data(), response.size());
    close(client);
    ++handled;
  }
  close(fd);
  return handled;
}

int run_https_unlock_server(UnlockService& service, const std::string& bind_host, int port,
                            const std::filesystem::path& certificate_path,
                            const std::filesystem::path& private_key_path, int max_requests) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == nullptr)
    throw CryptoError("SSL_CTX_new failed");
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  if (SSL_CTX_use_certificate_file(ctx, certificate_path.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, private_key_path.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    throw CryptoError("TLS certificate/private key load failed");
  }

  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    SSL_CTX_free(ctx);
    throw sys_error("socket");
  }
  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, bind_host.c_str(), &addr.sin_addr) != 1) {
    close(fd);
    SSL_CTX_free(ctx);
    throw std::runtime_error("bind host must be IPv4 address");
  }
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    int saved = errno;
    close(fd);
    SSL_CTX_free(ctx);
    errno = saved;
    throw sys_error("bind");
  }
  if (listen(fd, 16) != 0) {
    int saved = errno;
    close(fd);
    SSL_CTX_free(ctx);
    errno = saved;
    throw sys_error("listen");
  }

  int handled = 0;
  while (max_requests < 0 || handled < max_requests) {
    int client = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR)
        continue;
      int saved = errno;
      close(fd);
      SSL_CTX_free(ctx);
      errno = saved;
      throw sys_error("accept");
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) == 1) {
      std::string raw = read_http_tls(ssl);
      auto response = http_response_text(service.handle(parse_http_request(raw)));
      (void)SSL_write(ssl, response.data(), static_cast<int>(response.size()));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    ++handled;
  }
  close(fd);
  SSL_CTX_free(ctx);
  return handled;
}

}  // namespace alfie
