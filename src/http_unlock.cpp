#include "http_unlock.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include "scoped_fd.hpp"

namespace alfie {
namespace {
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

// accept4(2) is Linux-only; elsewhere fall back to accept(2) + FD_CLOEXEC.
int accept_cloexec(int listen_fd) {
#ifdef __linux__
  return accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
#else
  int fd = accept(listen_fd, nullptr, nullptr);
  if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
#endif
}

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

// Rejection sampling gives each six-digit visual identifier equal probability.
SecureBuffer random_six_digit_code() {
  unsigned char bytes[3];
  unsigned int value;
  do {
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
      throw CryptoError("request code generation failed");
    value = (static_cast<unsigned int>(bytes[0]) << 16) |
            (static_cast<unsigned int>(bytes[1]) << 8) | bytes[2];
  } while (value >= 16000000);
  SecureBuffer code(6);
  for (size_t i = code.size(); i > 0; --i) {
    code.data()[i - 1] = '0' + value % 10;
    value /= 10;
  }
  return code;
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

// Wipe all decoded fields on every exit, including invalid submissions.
struct FormFields {
  std::map<std::string, SecureBuffer> values;
};

// Decode directly into secure storage; views avoid intermediate plaintext strings.
SecureBuffer url_decode(std::string_view input) {
  SecureBuffer output(input.size());
  size_t written = 0;
  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == '+') {
      output.data()[written++] = ' ';
    } else if (input[i] == '%' && i + 2 < input.size() && hex_value(input[i + 1]) >= 0 &&
               hex_value(input[i + 2]) >= 0) {
      output.data()[written++] = (hex_value(input[i + 1]) << 4) | hex_value(input[i + 2]);
      i += 2;
    } else {
      output.data()[written++] = input[i];
    }
  }
  output.truncate(written);
  return output;
}

// Accept only known literal field names; never copy attacker-controlled names into plain strings.
FormFields parse_form(std::string_view body) {
  FormFields fields;
  while (!body.empty()) {
    auto end = body.find('&');
    auto part = body.substr(0, end);
    auto separator = part.find('=');
    if (separator != std::string_view::npos) {
      auto name = part.substr(0, separator);
      if (name == "login" || name == "password" || name == "confirm" || name == "value" ||
          name == "setup_code")
        fields.values[std::string(name)] = url_decode(part.substr(separator + 1));
    }
    if (end == std::string_view::npos)
      break;
    body.remove_prefix(end + 1);
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

using Deadline = std::chrono::steady_clock::time_point;

// Bound connection time and allocation before processing unauthenticated input.
constexpr auto kConnectionTimeout = std::chrono::seconds(10);
constexpr size_t kMaxHttpBytes = 1024 * 1024;
constexpr size_t kMaxHeaderBytes = 16 * 1024;

// Reuse an absolute deadline so trickled traffic cannot extend the connection lifetime.
int remaining_milliseconds(Deadline deadline) {
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                       deadline - std::chrono::steady_clock::now())
                       .count();
  if (remaining <= 0)
    throw std::runtime_error("TLS connection deadline exceeded");
  return static_cast<int>(remaining);
}

// Wait for the direction requested by OpenSSL without blocking past the deadline.
void wait_for_tls(SSL* ssl, int error, Deadline deadline) {
  short events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
  pollfd socket{SSL_get_fd(ssl), events, 0};
  for (;;) {
    int ready = poll(&socket, 1, remaining_milliseconds(deadline));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0 || (socket.revents & (POLLERR | POLLNVAL)))
      throw std::runtime_error("TLS socket unavailable");
    return;
  }
}

// Retry the same TLS operation on WANT_READ/WANT_WRITE, as required by OpenSSL.
template <typename Operation>
int tls_io(SSL* ssl, Deadline deadline, Operation operation) {
  for (;;) {
    remaining_milliseconds(deadline);
    ERR_clear_error();  // SSL_get_error must see only this operation's errors.
    int result = operation();
    if (result > 0)
      return result;
    int error = SSL_get_error(ssl, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
      throw std::runtime_error("TLS connection failed");
    wait_for_tls(ssl, error, deadline);
  }
}

// Suppress only this thread's new SIGPIPE, preserving the caller's signal state.
class BlockSigpipe {
 public:
  BlockSigpipe() {
    sigemptyset(&blocked_signals_);
    sigaddset(&blocked_signals_, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked_signals_, &previous_mask_) != 0)
      throw std::runtime_error("block SIGPIPE failed");
    sigset_t pending;
    sigpending(&pending);
    had_pending_sigpipe_ = sigismember(&pending, SIGPIPE);
  }
  ~BlockSigpipe() {
    sigset_t pending;
    sigpending(&pending);
    // Consume newly generated SIGPIPE before restoring the caller's mask.
    if (!had_pending_sigpipe_ && sigismember(&pending, SIGPIPE)) {
      int signal = 0;
      sigwait(&blocked_signals_, &signal);
    }
    pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
  }

 private:
  sigset_t blocked_signals_{}, previous_mask_{};
  bool had_pending_sigpipe_ = false;
};

// Erase request plaintext on both normal and exceptional exits.
struct WipeString {
  std::string& value;
  ~WipeString() {
    OPENSSL_cleanse(value.data(), value.size());
  }
};

// Reject signed, overflowing, or trailing-junk lengths before allocating a body.
size_t parse_content_length(std::string_view value) {
  auto first = value.find_first_not_of(" \t");
  auto last = value.find_last_not_of(" \t");
  if (first == std::string_view::npos)
    throw std::runtime_error("invalid content length");
  value = value.substr(first, last - first + 1);
  size_t length = 0;
  auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), length);
  if (error != std::errc{} || end != value.data() + value.size())
    throw std::runtime_error("invalid content length");
  return length;
}

// Accept one unambiguous fixed-length request; chunking and duplicate lengths are unsupported.
size_t http_request_size(std::string_view headers) {
  size_t body_size = 0;
  bool seen_length = false;
  size_t pos = headers.find("\r\n") + 2;
  while (pos < headers.size() - 2) {
    size_t next = headers.find("\r\n", pos);
    auto line = headers.substr(pos, next - pos);
    auto colon = line.find(':');
    if (colon == std::string_view::npos)
      throw std::runtime_error("invalid HTTP header");
    std::string name(line.substr(0, colon));
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (name == "transfer-encoding")
      throw std::runtime_error("transfer encoding unsupported");
    if (name == "content-length") {
      if (seen_length)
        throw std::runtime_error("duplicate content length");
      seen_length = true;
      body_size = parse_content_length(line.substr(colon + 1));
    }
    pos = next + 2;
  }
  if (body_size > kMaxHttpBytes - headers.size())
    throw std::runtime_error("HTTP request too large");
  return headers.size() + body_size;
}

// Read exactly one bounded HTTP message before passing it to the request handler.
void read_http_tls(SSL* ssl, Deadline deadline, std::string& raw) {
  // Wipe the temporary TLS plaintext even if reading or parsing throws.
  struct ReadBuffer {
    char data[8192];
    ~ReadBuffer() {
      OPENSSL_cleanse(data, sizeof(data));
    }
  } buffer;
  raw.reserve(kMaxHttpBytes);  // Avoid abandoned plaintext copies during string growth.
  size_t expected_size = 0;
  for (;;) {
    int count =
        tls_io(ssl, deadline, [&] { return SSL_read(ssl, buffer.data, sizeof(buffer.data)); });
    if (raw.size() + count > kMaxHttpBytes)
      throw std::runtime_error("HTTP request too large");
    raw.append(buffer.data, count);

    // Parse framing once, only after the complete bounded header has arrived.
    if (expected_size == 0) {
      auto header_end = raw.find("\r\n\r\n");
      if (header_end == std::string::npos) {
        if (raw.size() > kMaxHeaderBytes)
          throw std::runtime_error("HTTP headers too large");
        continue;
      }
      size_t header_size = header_end + 4;
      if (header_size > kMaxHeaderBytes)
        throw std::runtime_error("HTTP headers too large");
      expected_size = http_request_size(std::string_view(raw).substr(0, header_size));
    }
    if (raw.size() > expected_size)
      throw std::runtime_error("HTTP pipelining unsupported");
    if (raw.size() == expected_size)
      return;
  }
}

// Complete partial response writes using the connection's original deadline.
void write_http_tls(SSL* ssl, Deadline deadline, const std::string& response) {
  size_t sent = 0;
  while (sent < response.size()) {
    sent += tls_io(ssl, deadline, [&] {
      return SSL_write(ssl, response.data() + sent, static_cast<int>(response.size() - sent));
    });
  }
}

}  // namespace

UnlockService::UnlockService(std::filesystem::path vault_dir, std::string expected_login)
    : vault_dir_(std::move(vault_dir)), expected_login_(std::move(expected_login)) {}

std::string UnlockService::create_token_for(const UnlockRequestSpec& spec, UnlockMode mode,
                                            InitPlan plan) {
  std::string token = random_token();
  tokens_[token] = TokenRecord{spec,
                               std::chrono::steady_clock::now() + spec.ttl,
                               false,
                               mode,
                               std::move(plan),
                               random_six_digit_code().str(),
                               SecureBuffer{},
                               0};
  return token;
}

std::string UnlockService::create_token(const UnlockRequestSpec& spec) {
  return create_token_for(spec, UnlockMode::Unlock);
}

std::string UnlockService::create_store_token(const UnlockRequestSpec& spec) {
  return create_token_for(spec, UnlockMode::Store);
}

std::string UnlockService::create_init_token(const UnlockRequestSpec& spec, InitPlan plan) {
  auto token = create_token_for(spec, UnlockMode::Init, std::move(plan));
  auto& record = tokens_.at(token);
  // Keep the secret independent of, and distinct from, the public visual identifier.
  do {
    record.setup_code = random_six_digit_code();
  } while (CRYPTO_memcmp(record.setup_code.data(), record.display_code.data(), 6) == 0);
  return token;
}

// Do not expose an identifier for an expired or consumed request.
std::string UnlockService::request_code(const std::string& token) const {
  auto it = tokens_.find(token);
  if (it == tokens_.end() || it->second.used ||
      std::chrono::steady_clock::now() > it->second.expires_at)
    throw CryptoError("request is not active");
  return it->second.display_code;
}

// Only live initialization requests expose their secret to trusted local callers.
const SecureBuffer& UnlockService::setup_code(const std::string& token) const {
  auto it = tokens_.find(token);
  if (it == tokens_.end() || it->second.used || it->second.mode != UnlockMode::Init ||
      std::chrono::steady_clock::now() > it->second.expires_at)
    throw CryptoError("setup request is not active");
  return it->second.setup_code;
}

// One place that decides whether a token may act: it must exist, be unused, be presented on the
// path matching the mode it was minted for, and be inside its TTL.
UnlockService::TokenRecord* UnlockService::live_token(const std::string& token, UnlockMode mode) {
  auto it = tokens_.find(token);
  if (it == tokens_.end() || it->second.used || it->second.mode != mode ||
      std::chrono::steady_clock::now() > it->second.expires_at) {
    return nullptr;
  }
  return &it->second;
}

HttpResponse UnlockService::handle(const HttpRequest& request) {
  struct Route {
    const char* prefix;
    UnlockMode mode;
  };
  static constexpr Route kRoutes[] = {
      {"/unlock/", UnlockMode::Unlock},
      {"/store/", UnlockMode::Store},
      {"/init/", UnlockMode::Init},
  };

  for (const auto& route : kRoutes) {
    std::string token = token_from_target(request.target, route.prefix);
    if (token.empty())
      continue;
    if (request.method == "GET")
      return render_form(token, route.mode);
    if (request.method == "POST")
      return handle_submit(token, request.body, route.mode);
    return {405, "text/plain; charset=utf-8", "Method not allowed"};
  }
  return {404, "text/plain; charset=utf-8", "Not found"};
}

HttpResponse UnlockService::render_form(const std::string& token, UnlockMode mode) {
  const TokenRecord* record = live_token(token, mode);
  if (record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  const auto& spec = record->spec;
  const bool init_mode = mode == UnlockMode::Init;

  std::string title = "Alfie Vault Unlock";
  std::string action_path = "/unlock/";
  std::string button = "Unlock once";
  if (init_mode) {
    title = "FIRST-TIME VAULT SETUP";
    action_path = "/init/";
    button = "Create vault";
  } else if (mode == UnlockMode::Store) {
    title = "Alfie Vault Store";
    action_path = "/store/";
    button = "Store once";
  }

  // The setup page is the highest-value phishing target in the system: it is the one page that
  // asks for the password protecting everything, and the one page a user reaches by clicking
  // through a certificate warning. So it does not look like the routine pages -- red, not
  // slate -- and it says plainly what it is and when it should never appear.
  const char* surface = init_mode ? "#450a0a" : "#0f172a";
  const char* card = init_mode ? "#7f1d1d" : "#111827";
  const char* border = init_mode ? "#f87171" : "#334155";
  const char* accent = init_mode ? "#dc2626" : "#2563eb";
  const char* field = init_mode ? "#1c0606" : "#020617";

  std::string meta_lines;
  if (init_mode) {
    meta_lines =
        "<p class=\"warn\"><strong>You should see this page exactly once.</strong> "
        "It creates a brand-new vault and sets the login and master password it will use "
        "forever. If you have already set up Alfie, close this page now &mdash; someone may be "
        "trying to collect your master password.</p>"
        "<p class=\"meta\">There is no recovery. If the master password is lost, every record "
        "in the vault is unreadable.</p>";
    if (!transport_fingerprint_.empty()) {
      meta_lines +=
          "<p class=\"meta\">Check this against the fingerprint printed on the server's "
          "terminal before typing anything:</p><p class=\"fp\">" +
          html_escape(transport_fingerprint_) + "</p>";
    }
  } else {
    meta_lines = "<p class=\"meta\">Domain: " + html_escape(spec.domain) +
                 "</p><p class=\"meta\">Action: " + html_escape(spec.action) + "</p>";
  }

  // The bot and page share this identifier; it is not a password or authorization factor.
  meta_lines +=
      "<p class=\"meta\">Match this request code with the bot's message:</p>"
      "<p class=\"fp\" style=\"font-size:32px;letter-spacing:0.15em\">" +
      record->display_code + "</p>";

  std::string extra_field;
  if (init_mode) {
    extra_field =
        "<label>Confirm vault password <input name=\"confirm\" type=\"password\" "
        "autocomplete=\"new-password\"></label>"
        "<label>One-time setup code from the terminal "
        "<input name=\"setup_code\" type=\"password\" inputmode=\"numeric\" "
        "pattern=\"[0-9]{6}\" minlength=\"6\" maxlength=\"6\" "
        "autocomplete=\"off\" required></label>"
        "<p class=\"meta\">Two incorrect setup codes invalidate this link.</p>";
  } else if (mode == UnlockMode::Store) {
    extra_field =
        "<label>Secret JSON <textarea name=\"value\" "
        "autocomplete=\"off\"></textarea></label><br>";
  }
  const std::string password_autocomplete = init_mode ? "new-password" : "current-password";
  const std::string password_hint = init_mode ? " <span class=\"hint\">(at least " +
                                                    std::to_string(kMinimumMasterPasswordLength) +
                                                    " characters)</span>"
                                              : "";

  std::string body =
      std::string(
          "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<meta name=\"viewport\" "
          "content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
          "<title>") +
      title +
      "</title><style>"
      ":root{color-scheme:dark}*{box-sizing:border-box}"
      "body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe "
      "UI',Roboto,sans-serif;"
      "background:" +
      surface +
      ";color:#f8fafc;display:flex;align-items:center;justify-content:center;padding:24px}"
      ".card{width:100%;max-width:520px;background:" +
      card + ";border:2px solid " + border +
      ";border-radius:18px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.45)}"
      "h1{font-size:1.4rem;margin:0 0 16px;letter-spacing:.02em}"
      ".meta{color:#e2e8f0;font-size:.95rem;margin:8px 0}"
      ".warn{background:#1c0606;border:1px solid #f87171;border-radius:12px;padding:14px;"
      "margin:0 0 14px;color:#fecaca;font-size:.95rem;line-height:1.45}"
      ".fp{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;"
      "word-break:break-all;background:#1c0606;border-radius:10px;padding:10px;color:#fecaca}"
      ".hint{font-weight:400;color:#e2e8f0;font-size:.85rem}"
      "label{display:block;margin-top:16px;font-weight:600}"
      "input,textarea,button{width:100%;font:inherit;border-radius:12px;border:1px solid "
      "#475569;padding:14px;margin-top:8px}"
      "input,textarea{background:" +
      field +
      ";color:#f8fafc}textarea{min-height:120px}"
      "button{background:" +
      accent +
      ";color:white;border:0;font-weight:700;margin-top:20px;cursor:pointer}"
      "@media "
      "(max-width:540px){body{padding:12px;align-items:stretch}.card{border-radius:14px;padding:"
      "18px}}"
      "</style></head><body><main class=\"card\"><h1>" +
      title + "</h1>" + meta_lines + "<form method=\"post\" action=\"" + action_path +
      html_escape(token) +
      "\"><label>Login <input name=\"login\" autocomplete=\"username\" autocapitalize=\"none\" "
      "spellcheck=\"false\" inputmode=\"text\"></label>"
      "<label>Vault password" +
      password_hint + " <input name=\"password\" type=\"password\" autocomplete=\"" +
      password_autocomplete + "\"></label>" + extra_field + "<button type=\"submit\">" + button +
      "</button></form></main></body></html>";
  return {200, "text/html; charset=utf-8", body};
}

// Creates the vault, then the CA, in that order. The CA private key is generated in memory and
// stored in the vault it just created; it is never written to disk. Only public certificates
// and the server key (0600) reach the filesystem.
HttpResponse UnlockService::run_first_time_install(TokenRecord& record, const std::string& login,
                                                   SecureBuffer& password) {
  const InitPlan& plan = record.plan;
  try {
    // Copy directly between secure allocations; setup needs two separate derivations.
    SecureBuffer for_init(SecureBytes(password.bytes()));
    init_vault(vault_dir_, login, for_init);

    GeneratedCertificate ca = generate_ca_certificate(plan.ca_common_name, 3650, plan.ca_rsa_bits);

    {
      SecureBuffer for_session(SecureBytes(password.bytes()));
      VaultSession session = VaultSession::open(vault_dir_, login, for_session);
      session.put(kCaKeyPurpose, kCaKeyDomain, kCaKeyAccount, ca.private_key_pem);
    }

    const auto ca_cert_path = plan.output_dir / "alfie-local-ca-cert.pem";
    write_public_file(ca_cert_path, ca.certificate_pem);

    std::string server_cert_path;
    if (!plan.server_ip.empty()) {
      GeneratedCertificate server = issue_ip_certificate(
          plan.server_ip, ca.certificate_pem, ca.private_key_pem, 825, plan.server_rsa_bits);
      write_public_file(plan.output_dir / "alfie-ip-cert.pem", server.certificate_pem);
      write_private_file(plan.output_dir / "alfie-ip-key.pem", server.private_key_pem);
      server_cert_path = (plan.output_dir / "alfie-ip-cert.pem").string();
    }

    record.setup_code.truncate(0);  // Erase the one-time secret after successful setup.
    record.used = true;
    finished_ = true;

    const std::string ca_fingerprint = certificate_fingerprint_sha256(ca.certificate_pem);
    return {201, "text/html; charset=utf-8",
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Vault created</title></head><body "
            "style=\"font-family:-apple-system,sans-serif;background:#450a0a;color:#f8fafc;"
            "padding:24px\">"
            "<h1>Vault created</h1><p>The login and master password are set, and the local CA "
            "private key is stored inside the vault. This setup link is now dead.</p>"
            "<p>Install and trust this CA certificate on your devices:<br><code>" +
                html_escape(ca_cert_path.string()) + "</code></p><p>Request code: <strong>" +
                record.display_code +
                "</strong></p><p>Verify the full SHA-256 fingerprint before "
                "trusting the CA:<br><code style=\"word-break:break-all\">" +
                html_escape(ca_fingerprint) + "</code></p>" +
                (server_cert_path.empty()
                     ? std::string{}
                     : "<p>Server certificate for future unlock sessions:<br><code>" +
                           html_escape(server_cert_path) + "</code></p>") +
                "</body></html>"};
  } catch (const std::exception&) {
    return {409, "text/plain; charset=utf-8", "Vault setup failed"};
  }
}

HttpResponse UnlockService::handle_submit(const std::string& token, const std::string& form_body,
                                          UnlockMode mode) {
  TokenRecord* record = live_token(token, mode);
  if (record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  auto form = parse_form(form_body);
  auto& fields = form.values;
  // Check before credentials or KDF work; missing and malformed codes count as failures.
  if (mode == UnlockMode::Init) {
    auto code = fields.find("setup_code");
    bool matches = code != fields.end() && code->second.size() == 6 &&
                   record->setup_code.size() == 6 &&
                   CRYPTO_memcmp(code->second.data(), record->setup_code.data(), 6) == 0;
    if (!matches) {
      if (++record->setup_failures >= 2) {
        record->used = true;
        record->setup_code.truncate(0);
        return {410, "text/plain; charset=utf-8",
                "Setup link invalidated after two incorrect codes"};
      }
      return {403, "text/plain; charset=utf-8", "Incorrect setup code. One attempt remaining."};
    }
  }
  auto login = fields.find("login");
  auto password = fields.find("password");
  if (login == fields.end() || password == fields.end())
    return {400, "text/plain; charset=utf-8", "Missing login or password"};

  // Transfer the decoded password without leaving a second plaintext allocation.
  SecureBuffer master_password = std::move(password->second);
  const std::string login_name = login->second.str();

  if (mode == UnlockMode::Init) {
    auto confirm = fields.find("confirm");
    const bool matched =
        confirm != fields.end() && confirm->second.size() == master_password.size() &&
        CRYPTO_memcmp(confirm->second.data(), master_password.data(), master_password.size()) == 0;
    if (confirm != fields.end()) {
      confirm->second.truncate(0);
    }
    if (!matched)
      return {400, "text/plain; charset=utf-8", "Passwords do not match"};
    if (login->second.empty())
      return {400, "text/plain; charset=utf-8", "Login must not be empty"};
    // The master password can never be changed, so the one moment it is chosen is the only
    // chance to refuse a hopeless one.
    if (master_password.size() < kMinimumMasterPasswordLength) {
      return {400, "text/plain; charset=utf-8",
              "Master password must be at least " + std::to_string(kMinimumMasterPasswordLength) +
                  " characters"};
    }
    return run_first_time_install(*record, login_name, master_password);
  }

  if (!vault_initialized(vault_dir_))
    return {409, "text/plain; charset=utf-8", "Vault is not initialized"};

  // One Argon2id derivation covers both the credential check and the record operation: the
  // session verifies login + master password against the stored verifiers, then holds the
  // derived keys for exactly this request. Legacy ALFIEVAULT1 vaults have no verifiers and fall
  // back to the login supplied at server start.
  const bool has_verifiers = vault_has_credentials(vault_dir_);
  if (!has_verifiers && login_name != expected_login_)
    return {403, "text/plain; charset=utf-8", "Bad login"};

  std::optional<VaultSession> session;
  try {
    session.emplace(has_verifiers ? VaultSession::open(vault_dir_, login_name, master_password)
                                  : VaultSession::open_with_password(vault_dir_, master_password));
  } catch (const std::exception&) {
    return {403, "text/plain; charset=utf-8", "Bad login or password"};
  }

  const auto spec = record->spec;
  try {
    if (mode == UnlockMode::Store) {
      auto value = fields.find("value");
      if (value == fields.end() || value->second.empty())
        return {400, "text/plain; charset=utf-8", "Missing secret value"};
      // Move the submitted secret into its single-use storage operation.
      SecureBuffer secret_value = std::move(value->second);
      session->put(spec.purpose, spec.domain, spec.account, secret_value);
      last_delivery_ =
          DeliveredSecret{token, spec.domain, spec.account, spec.action, secret_value.size()};
    } else {
      session->use(spec.purpose, spec.domain, spec.account, [&](const SecureBuffer& secret) {
        // Real browser-worker delivery will use encrypted IPC. Until that integration, store
        // only metadata proving that one secret was unlocked; never store payload.
        last_delivery_ =
            DeliveredSecret{token, spec.domain, spec.account, spec.action, secret.size()};
      });
    }
    record->used = true;
    return {200, "text/html; charset=utf-8",
            mode == UnlockMode::Unlock
                ? "<html><body>Unlocked. Credential delivered to local worker.</body></html>"
                : "<html><body>Stored.</body></html>"};
  } catch (const std::exception&) {
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

namespace {

// Validate the endpoint and finish listener setup before accepting connections.
int bind_tls_listener(const std::string& host, int port) {
  if (port < 1 || port > 65535)
    throw std::runtime_error("invalid TCP port");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
    throw std::runtime_error("bind host must be IPv4 address");

  ScopedFd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (listener.get() < 0)
    throw sys_error("socket");
  // Check the portable CLOEXEC fallback and permit restart after TCP TIME_WAIT.
  int yes = 1;
  if (fcntl(listener.get(), F_SETFD, FD_CLOEXEC) != 0 ||
      setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
    throw sys_error("configure TLS listener");
  if (bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    throw sys_error("bind");
  if (listen(listener.get(), 16) != 0)
    throw sys_error("listen");
  return listener.release();
}

// Handle one TLS exchange with scoped plaintext and OpenSSL cleanup.
void serve_tls_client(SSL_CTX* context, int client, UnlockService& service) {
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context), SSL_free);
  if (!ssl || fcntl(client, F_SETFL, O_NONBLOCK) != 0 || SSL_set_fd(ssl.get(), client) != 1)
    throw std::runtime_error("configure TLS client failed");
  auto deadline = std::chrono::steady_clock::now() + kConnectionTimeout;
  tls_io(ssl.get(), deadline, [&] { return SSL_accept(ssl.get()); });

  std::string raw;
  WipeString wipe_raw{raw};
  read_http_tls(ssl.get(), deadline, raw);
  auto request = parse_http_request(raw);
  WipeString wipe_body{request.body};
  auto response = http_response_text(service.handle(request));
  write_http_tls(ssl.get(), deadline, response);
  // Send close_notify best-effort; never wait for the peer to acknowledge shutdown.
  SSL_shutdown(ssl.get());
}

// Isolate client failures while keeping the listener and its resources scoped.
int serve_tls(SSL_CTX* ctx, UnlockService& service, const std::string& bind_host, int port,
              int max_requests) {
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(ctx, SSL_CTX_free);
  BlockSigpipe block_sigpipe;
  ScopedFd listener(bind_tls_listener(bind_host, port));
  int handled = 0;
  while (max_requests < 0 || handled < max_requests) {
    ScopedFd client(accept_cloexec(listener.get()));
    if (client.get() < 0) {
      if (errno == EINTR)
        continue;
      throw sys_error("accept");
    }
    try {
      serve_tls_client(context.get(), client.get(), service);
    } catch (const std::exception&) {
      // Drop malformed or stalled clients without logging request plaintext.
    }
    ++handled;
    // Stop the bootstrap server immediately after its one-time setup completes.
    if (service.finished())
      break;
  }
  return handled;
}

SSL_CTX* new_server_context() {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == nullptr)
    throw CryptoError("SSL_CTX_new failed");
  // Fail closed rather than silently permitting an older TLS protocol.
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
    SSL_CTX_free(ctx);
    throw CryptoError("TLS minimum version failed");
  }
  // Keep each TLS connection fresh and disable replayable early data.
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(ctx, 0);
  SSL_CTX_set_max_early_data(ctx, 0);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  return ctx;
}

}  // namespace

int run_https_unlock_server(UnlockService& service, const std::string& bind_host, int port,
                            const std::filesystem::path& certificate_path,
                            const std::filesystem::path& private_key_path, int max_requests) {
  SSL_CTX* ctx = new_server_context();
  if (SSL_CTX_use_certificate_file(ctx, certificate_path.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, private_key_path.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    throw CryptoError("TLS certificate/private key load failed");
  }
  return serve_tls(ctx, service, bind_host, port, max_requests);
}

int run_https_unlock_server_in_memory(UnlockService& service, const std::string& bind_host,
                                      int port, const std::string& certificate_pem,
                                      const SecureBuffer& private_key_pem, int max_requests) {
  SSL_CTX* ctx = new_server_context();

  BIO* cert_bio = BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size()));
  X509* cert =
      cert_bio == nullptr ? nullptr : PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
  BIO* key_bio = BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size()));
  EVP_PKEY* key =
      key_bio == nullptr ? nullptr : PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);

  const bool loaded = cert != nullptr && key != nullptr &&
                      SSL_CTX_use_certificate(ctx, cert) == 1 &&
                      SSL_CTX_use_PrivateKey(ctx, key) == 1 && SSL_CTX_check_private_key(ctx) == 1;

  X509_free(cert);
  EVP_PKEY_free(key);
  BIO_free(cert_bio);
  BIO_free(key_bio);

  if (!loaded) {
    SSL_CTX_free(ctx);
    throw CryptoError("in-memory TLS certificate/private key load failed");
  }
  return serve_tls(ctx, service, bind_host, port, max_requests);
}

}  // namespace alfie
