//===----------------------------------------------------------------------===//
/// \file
/// Authorize one-record vault operations through one-time HTTPS links.
//===----------------------------------------------------------------------===//

#include "http_unlock.h"
#include "ca.h"
#include "scoped_fd.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <memory>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>

using namespace alfie;

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

// accept4(2) is Linux-only; elsewhere fall back to accept(2) + FD_CLOEXEC.
static int acceptCloexec(int listenFd) {
#ifdef __linux__
  return accept4(ListenFd, nullptr, nullptr, SOCK_CLOEXEC);
#else
  int fd = accept(listenFd, nullptr, nullptr);
  if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
#endif
}

static std::runtime_error sysError(const std::string &what) {
  return std::runtime_error(what + ": " + std::strerror(errno));
}

static std::string randomToken() {
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
static SecureBuffer randomSixDigitCode() {
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
    code.data()[i - 1] = '0' + (value % 10);
    value /= 10;
  }
  return code;
}

static std::string htmlEscape(const std::string &s) {
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

static int hexValue(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  return -1;
}

// Wipe all decoded fields on every exit, including invalid submissions.
namespace {
struct FormFields {
  std::map<std::string, SecureBuffer> values;
};
} // namespace

// Decode directly into secure storage; views avoid intermediate plaintext
// strings.
static SecureBuffer urlDecode(std::string_view input) {
  SecureBuffer output(input.size());
  size_t written = 0;
  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == '+') {
      output.data()[written++] = ' ';
    } else if (input[i] == '%' && i + 2 < input.size() &&
               hexValue(input[i + 1]) >= 0 && hexValue(input[i + 2]) >= 0) {
      output.data()[written++] =
          (hexValue(input[i + 1]) << 4) | hexValue(input[i + 2]);
      i += 2;
    } else {
      output.data()[written++] = input[i];
    }
  }
  output.truncate(written);
  return output;
}

// Accept only known literal field names; never copy attacker-controlled names
// into plain strings.
static FormFields parseForm(std::string_view body) {
  FormFields fields;
  while (!body.empty()) {
    auto end = body.find('&');
    auto part = body.substr(0, end);
    auto separator = part.find('=');
    if (separator != std::string_view::npos) {
      auto name = part.substr(0, separator);
      if (name == "login" || name == "password" || name == "confirm" ||
          name == "value" || name == "setup_code")
        fields.values[std::string(name)] =
            urlDecode(part.substr(separator + 1));
    }
    if (end == std::string_view::npos)
      break;
    body.remove_prefix(end + 1);
  }
  return fields;
}

static std::string statusText(int status) {
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

static std::string tokenFromTarget(const std::string &target,
                                   const std::string &prefix) {
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
static constexpr auto kConnectionTimeout = std::chrono::seconds(10);
static constexpr size_t kMaxHttpBytes = size_t{1024} * 1024;
static constexpr size_t kMaxHeaderBytes = size_t{16} * 1024;

// Reuse an absolute deadline so trickled traffic cannot extend the connection
// lifetime.
static int remainingMilliseconds(Deadline deadline) {
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                       deadline - std::chrono::steady_clock::now())
                       .count();
  if (remaining <= 0)
    throw std::runtime_error("TLS connection deadline exceeded");
  return static_cast<int>(remaining);
}

// Wait for the direction requested by OpenSSL without blocking past the
// deadline.
static void waitForTls(SSL *ssl, int error, Deadline deadline) {
  short events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
  pollfd socket{SSL_get_fd(ssl), events, 0};
  for (;;) {
    int ready = poll(&socket, 1, remainingMilliseconds(deadline));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0 || (socket.revents & (POLLERR | POLLNVAL)))
      throw std::runtime_error("TLS socket unavailable");
    return;
  }
}

// Retry the same TLS operation on WANT_READ/WANT_WRITE, as required by OpenSSL.
template <typename OperationT>
static int tlsIo(SSL *ssl, Deadline deadline, OperationT operation) {
  for (;;) {
    remainingMilliseconds(deadline);
    ERR_clear_error(); // SSL_get_error must see only this operation's errors.
    int result = operation();
    if (result > 0)
      return result;
    int error = SSL_get_error(ssl, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
      throw std::runtime_error("TLS connection failed");
    waitForTls(ssl, error, deadline);
  }
}

// Suppress only this thread's new SIGPIPE, preserving the caller's signal
// state.
namespace {
class BlockSigpipe {
public:
  BlockSigpipe() {
    sigemptyset(&blockedSignals_);
    sigaddset(&blockedSignals_, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &this->blockedSignals_,
                        &this->previousMask_) != 0)
      throw std::runtime_error("block SIGPIPE failed");
    sigset_t pending;
    sigpending(&pending);
    this->hadPendingSigpipe_ = sigismember(&pending, SIGPIPE);
  }
  ~BlockSigpipe() {
    sigset_t pending;
    sigpending(&pending);
    // Consume newly generated SIGPIPE before restoring the caller's mask.
    if (!this->hadPendingSigpipe_ && sigismember(&pending, SIGPIPE)) {
      int signal = 0;
      sigwait(&this->blockedSignals_, &signal);
    }
    pthread_sigmask(SIG_SETMASK, &this->previousMask_, nullptr);
  }

private:
  sigset_t blockedSignals_{}, previousMask_{};
  bool hadPendingSigpipe_ = false;
};
} // namespace

// Erase request plaintext on both normal and exceptional exits.
namespace {
struct WipeString {
  std::string &value;
  ~WipeString() { OPENSSL_cleanse(this->value.data(), this->value.size()); }
};
} // namespace

// Reject signed, overflowing, or trailing-junk lengths before allocating a
// body.
static size_t parseContentLength(std::string_view value) {
  auto first = value.find_first_not_of(" \t");
  auto last = value.find_last_not_of(" \t");
  if (first == std::string_view::npos)
    throw std::runtime_error("invalid content length");
  value = value.substr(first, last - first + 1);
  size_t length = 0;
  auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), length);
  if (error != std::errc{} || end != value.data() + value.size())
    throw std::runtime_error("invalid content length");
  return length;
}

// Accept one unambiguous fixed-length request; chunking and duplicate lengths
// are unsupported.
static size_t httpRequestSize(std::string_view headers) {
  size_t bodySize = 0;
  bool seenLength = false;
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
      if (seenLength)
        throw std::runtime_error("duplicate content length");
      seenLength = true;
      bodySize = parseContentLength(line.substr(colon + 1));
    }
    pos = next + 2;
  }
  if (bodySize > kMaxHttpBytes - headers.size())
    throw std::runtime_error("HTTP request too large");
  return headers.size() + bodySize;
}

// Read exactly one bounded HTTP message before passing it to the request
// handler.
static void readHttpTls(SSL *ssl, Deadline deadline, std::string &raw) {
  // Wipe the temporary TLS plaintext even if reading or parsing throws.
  struct ReadBuffer {
    char data[8192];
    ~ReadBuffer() { OPENSSL_cleanse(this->data, sizeof(this->data)); }
  } buffer;
  raw.reserve(
      kMaxHttpBytes); // Avoid abandoned plaintext copies during string growth.
  size_t expectedSize = 0;
  for (;;) {
    int count = tlsIo(ssl, deadline, [&] {
      return SSL_read(ssl, buffer.data, sizeof(buffer.data));
    });
    if (raw.size() + count > kMaxHttpBytes)
      throw std::runtime_error("HTTP request too large");
    raw.append(buffer.data, count);

    // Parse framing once, only after the complete bounded header has arrived.
    if (expectedSize == 0) {
      auto headerEnd = raw.find("\r\n\r\n");
      if (headerEnd == std::string::npos) {
        if (raw.size() > kMaxHeaderBytes)
          throw std::runtime_error("HTTP headers too large");
        continue;
      }
      size_t headerSize = headerEnd + 4;
      if (headerSize > kMaxHeaderBytes)
        throw std::runtime_error("HTTP headers too large");
      expectedSize =
          httpRequestSize(std::string_view(raw).substr(0, headerSize));
    }
    if (raw.size() > expectedSize)
      throw std::runtime_error("HTTP pipelining unsupported");
    if (raw.size() == expectedSize)
      return;
  }
}

// Complete partial response writes using the connection's original deadline.
static void writeHttpTls(SSL *ssl, Deadline deadline,
                         const std::string &response) {
  size_t sent = 0;
  while (sent < response.size()) {
    sent += tlsIo(ssl, deadline, [&] {
      return SSL_write(ssl, response.data() + sent,
                       static_cast<int>(response.size() - sent));
    });
  }
}

UnlockService::UnlockService(std::filesystem::path vaultDir,
                             std::string expectedLogin)
    : vaultDir_(std::move(vaultDir)), expectedLogin_(std::move(expectedLogin)) {
}

std::string UnlockService::createTokenFor(const UnlockRequestSpec &spec,
                                          UnlockMode mode, InitPlan plan) {
  std::string token = randomToken();
  this->tokens_[token] =
      TokenRecord{spec,
                  std::chrono::steady_clock::now() + spec.ttl,
                  false,
                  mode,
                  std::move(plan),
                  randomSixDigitCode().str(),
                  SecureBuffer{},
                  0};
  return token;
}

std::string UnlockService::createToken(const UnlockRequestSpec &spec) {
  return createTokenFor(spec, UnlockMode::Unlock);
}

std::string UnlockService::createStoreToken(const UnlockRequestSpec &spec) {
  return createTokenFor(spec, UnlockMode::Store);
}

std::string UnlockService::createInitToken(const UnlockRequestSpec &spec,
                                           InitPlan plan) {
  auto token = createTokenFor(spec, UnlockMode::Init, std::move(plan));
  auto &record = this->tokens_.at(token);
  // Keep the secret independent of, and distinct from, the public visual
  // identifier.
  do {
    record.setupCode = randomSixDigitCode();
  } while (CRYPTO_memcmp(record.setupCode.data(), record.displayCode.data(),
                         6) == 0);
  return token;
}

// Do not expose an identifier for an expired or consumed request.
std::string UnlockService::requestCode(const std::string &token) const {
  auto it = this->tokens_.find(token);
  if (it == this->tokens_.end() || it->second.used ||
      std::chrono::steady_clock::now() > it->second.expiresAt)
    throw CryptoError("request is not active");
  return it->second.displayCode;
}

// Only live initialization requests expose their secret to trusted local
// callers.
const SecureBuffer &UnlockService::setupCode(const std::string &token) const {
  auto it = this->tokens_.find(token);
  if (it == this->tokens_.end() || it->second.used ||
      it->second.mode != UnlockMode::Init ||
      std::chrono::steady_clock::now() > it->second.expiresAt)
    throw CryptoError("setup request is not active");
  return it->second.setupCode;
}

// One place that decides whether a token may act: it must exist, be unused, be
// presented on the path matching the mode it was minted for, and be inside its
// TTL.
UnlockService::TokenRecord *
UnlockService::findLiveToken(const std::string &token, UnlockMode mode) {
  auto it = this->tokens_.find(token);
  if (it == this->tokens_.end() || it->second.used || it->second.mode != mode ||
      std::chrono::steady_clock::now() > it->second.expiresAt) {
    return nullptr;
  }
  return &it->second;
}

HttpResponse UnlockService::handle(const HttpRequest &request) {
  struct Route {
    const char *prefix;
    UnlockMode mode;
  };
  static constexpr Route kRoutes[] = {
      {"/unlock/", UnlockMode::Unlock},
      {"/store/", UnlockMode::Store},
      {"/init/", UnlockMode::Init},
  };

  for (const auto &route : kRoutes) {
    std::string token = tokenFromTarget(request.target, route.prefix);
    if (token.empty())
      continue;
    if (request.method == "GET")
      return renderForm(token, route.mode);
    if (request.method == "POST")
      return handleSubmit(token, request.body, route.mode);
    return {405, "text/plain; charset=utf-8", "Method not allowed"};
  }
  return {404, "text/plain; charset=utf-8", "Not found"};
}

HttpResponse UnlockService::renderForm(const std::string &token,
                                       UnlockMode mode) {
  const TokenRecord *record = findLiveToken(token, mode);
  if (record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  const auto &spec = record->spec;
  const bool initMode = mode == UnlockMode::Init;

  std::string title = "Alfie Vault Unlock";
  std::string actionPath = "/unlock/";
  std::string button = "Unlock once";
  if (initMode) {
    title = "FIRST-TIME VAULT SETUP";
    actionPath = "/init/";
    button = "Create vault";
  } else if (mode == UnlockMode::Store) {
    title = "Alfie Vault Store";
    actionPath = "/store/";
    button = "Store once";
  }

  // The setup page is the highest-value phishing target in the system: it is
  // the one page that asks for the password protecting everything, and the one
  // page a user reaches by clicking through a certificate warning. So it does
  // not look like the routine pages -- red, not slate -- and it says plainly
  // what it is and when it should never appear.
  const char *surface = initMode ? "#450a0a" : "#0f172a";
  const char *card = initMode ? "#7f1d1d" : "#111827";
  const char *border = initMode ? "#f87171" : "#334155";
  const char *accent = initMode ? "#dc2626" : "#2563eb";
  const char *field = initMode ? "#1c0606" : "#020617";

  std::string metaLines;
  if (initMode) {
    metaLines = "<p class=\"warn\"><strong>You should see this page exactly "
                "once.</strong> "
                "It creates a brand-new vault and sets the login and master "
                "password it will use "
                "forever. If you have already set up Alfie, close this page "
                "now &mdash; someone may be "
                "trying to collect your master password.</p>"
                "<p class=\"meta\">There is no recovery. If the master "
                "password is lost, every record "
                "in the vault is unreadable.</p>";
    if (!this->transportFingerprint_.empty()) {
      metaLines += "<p class=\"meta\">Check this against the fingerprint "
                   "printed on the server's "
                   "terminal before typing anything:</p><p class=\"fp\">" +
                   htmlEscape(this->transportFingerprint_) + "</p>";
    }
  } else {
    metaLines = "<p class=\"meta\">Domain: " + htmlEscape(spec.domain) +
                "</p><p class=\"meta\">Action: " + htmlEscape(spec.action) +
                "</p>";
  }

  // The bot and page share this identifier; it is not a password or
  // authorization factor.
  metaLines +=
      "<p class=\"meta\">Match this request code with the bot's message:</p>"
      "<p class=\"fp\" style=\"font-size:32px;letter-spacing:0.15em\">" +
      record->displayCode + "</p>";

  std::string extraField;
  if (initMode) {
    extraField =
        "<label>Confirm vault password <input name=\"confirm\" "
        "type=\"password\" "
        "autocomplete=\"new-password\"></label>"
        "<label>One-time setup code from the terminal "
        "<input name=\"setup_code\" type=\"password\" inputmode=\"numeric\" "
        "pattern=\"[0-9]{6}\" minlength=\"6\" maxlength=\"6\" "
        "autocomplete=\"off\" required></label>"
        "<p class=\"meta\">Two incorrect setup codes invalidate this link.</p>";
  } else if (mode == UnlockMode::Store) {
    extraField = "<label>Secret JSON <textarea name=\"value\" "
                 "autocomplete=\"off\"></textarea></label><br>";
  }
  const std::string passwordAutocomplete =
      initMode ? "new-password" : "current-password";
  const std::string passwordHint =
      initMode ? " <span class=\"hint\">(at least " +
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
      "body{margin:0;min-height:100vh;font-family:-apple-system,"
      "BlinkMacSystemFont,'Segoe "
      "UI',Roboto,sans-serif;"
      "background:" +
      surface +
      ";color:#f8fafc;display:flex;align-items:center;justify-content:center;"
      "padding:24px}"
      ".card{width:100%;max-width:520px;background:" +
      card + ";border:2px solid " + border +
      ";border-radius:18px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.45)}"
      "h1{font-size:1.4rem;margin:0 0 16px;letter-spacing:.02em}"
      ".meta{color:#e2e8f0;font-size:.95rem;margin:8px 0}"
      ".warn{background:#1c0606;border:1px solid "
      "#f87171;border-radius:12px;padding:14px;"
      "margin:0 0 14px;color:#fecaca;font-size:.95rem;line-height:1.45}"
      ".fp{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:."
      "78rem;"
      "word-break:break-all;background:#1c0606;border-radius:10px;padding:10px;"
      "color:#fecaca}"
      ".hint{font-weight:400;color:#e2e8f0;font-size:.85rem}"
      "label{display:block;margin-top:16px;font-weight:600}"
      "input,textarea,button{width:100%;font:inherit;border-radius:12px;border:"
      "1px solid "
      "#475569;padding:14px;margin-top:8px}"
      "input,textarea{background:" +
      field +
      ";color:#f8fafc}textarea{min-height:120px}"
      "button{background:" +
      accent +
      ";color:white;border:0;font-weight:700;margin-top:20px;cursor:pointer}"
      "@media "
      "(max-width:540px){body{padding:12px;align-items:stretch}.card{border-"
      "radius:14px;padding:"
      "18px}}"
      "</style></head><body><main class=\"card\"><h1>" +
      title + "</h1>" + metaLines + "<form method=\"post\" action=\"" +
      actionPath + htmlEscape(token) +
      "\"><label>Login <input name=\"login\" autocomplete=\"username\" "
      "autocapitalize=\"none\" "
      "spellcheck=\"false\" inputmode=\"text\"></label>"
      "<label>Vault password" +
      passwordHint +
      " <input name=\"password\" type=\"password\" autocomplete=\"" +
      passwordAutocomplete + "\"></label>" + extraField +
      "<button type=\"submit\">" + button +
      "</button></form></main></body></html>";
  return {200, "text/html; charset=utf-8", body};
}

// Creates the vault, then the CA, in that order. The CA private key is
// generated in memory and stored in the vault it just created; it is never
// written to disk. Only public certificates and the server key (0600) reach the
// filesystem.
HttpResponse UnlockService::runFirstTimeInstall(TokenRecord &record,
                                                const std::string &login,
                                                SecureBuffer &password) {
  const InitPlan &plan = record.plan;
  try {
    // Copy directly between secure allocations; setup needs two separate
    // derivations.
    SecureBuffer forInit(SecureBytes(password.bytes()));
    initVault(this->vaultDir_, login, forInit);

    GeneratedCertificate ca =
        generateCaCertificate(plan.caCommonName, 3650, plan.caRsaBits);

    {
      SecureBuffer forSession(SecureBytes(password.bytes()));
      VaultSession session =
          VaultSession::open(this->vaultDir_, login, forSession);
      session.put(kCaKeyPurpose, kCaKeyDomain, kCaKeyAccount, ca.privateKeyPem);
    }

    const auto caCertPath = plan.outputDir / "alfie-local-ca-cert.pem";
    writePublicFile(caCertPath, ca.certificatePem);

    std::string serverCertPath;
    if (!plan.serverIp.empty()) {
      GeneratedCertificate server =
          issueIpCertificate(plan.serverIp, ca.certificatePem, ca.privateKeyPem,
                             825, plan.serverRsaBits);
      writePublicFile(plan.outputDir / "alfie-ip-cert.pem",
                      server.certificatePem);
      writePrivateFile(plan.outputDir / "alfie-ip-key.pem",
                       server.privateKeyPem);
      serverCertPath = (plan.outputDir / "alfie-ip-cert.pem").string();
    }

    record.setupCode.truncate(
        0); // Erase the one-time secret after successful setup.
    record.used = true;
    this->finished_ = true;

    const std::string caFingerprint =
        certificateFingerprintSha256(ca.certificatePem);
    return {
        201, "text/html; charset=utf-8",
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" "
        "content=\"width=device-width,initial-scale=1\">"
        "<title>Vault created</title></head><body "
        "style=\"font-family:-apple-system,sans-serif;background:#450a0a;color:"
        "#f8fafc;"
        "padding:24px\">"
        "<h1>Vault created</h1><p>The login and master password are set, and "
        "the local CA "
        "private key is stored inside the vault. This setup link is now "
        "dead.</p>"
        "<p>Install and trust this CA certificate on your devices:<br><code>" +
            htmlEscape(caCertPath.string()) +
            "</code></p><p>Request code: <strong>" + record.displayCode +
            "</strong></p><p>Verify the full SHA-256 fingerprint before "
            "trusting the CA:<br><code style=\"word-break:break-all\">" +
            htmlEscape(caFingerprint) + "</code></p>" +
            (serverCertPath.empty()
                 ? std::string{}
                 : "<p>Server certificate for future unlock "
                   "sessions:<br><code>" +
                       htmlEscape(serverCertPath) + "</code></p>") +
            "</body></html>"};
  } catch (const std::exception &) {
    return {409, "text/plain; charset=utf-8", "Vault setup failed"};
  }
}

HttpResponse UnlockService::handleSubmit(const std::string &token,
                                         const std::string &formBody,
                                         UnlockMode mode) {
  TokenRecord *record = findLiveToken(token, mode);
  if (record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  auto form = parseForm(formBody);
  auto &fields = form.values;
  // Check before credentials or KDF work; missing and malformed codes count as
  // failures.
  if (mode == UnlockMode::Init) {
    auto code = fields.find("setup_code");
    bool matches =
        code != fields.end() && code->second.size() == 6 &&
        record->setupCode.size() == 6 &&
        CRYPTO_memcmp(code->second.data(), record->setupCode.data(), 6) == 0;
    if (!matches) {
      if (++record->setupFailures >= 2) {
        record->used = true;
        record->setupCode.truncate(0);
        return {410, "text/plain; charset=utf-8",
                "Setup link invalidated after two incorrect codes"};
      }
      return {403, "text/plain; charset=utf-8",
              "Incorrect setup code. One attempt remaining."};
    }
  }
  auto login = fields.find("login");
  auto password = fields.find("password");
  if (login == fields.end() || password == fields.end())
    return {400, "text/plain; charset=utf-8", "Missing login or password"};

  // Transfer the decoded password without leaving a second plaintext
  // allocation.
  SecureBuffer masterPassword = std::move(password->second);
  const std::string loginName = login->second.str();

  if (mode == UnlockMode::Init) {
    auto confirm = fields.find("confirm");
    const bool matched =
        confirm != fields.end() &&
        confirm->second.size() == masterPassword.size() &&
        CRYPTO_memcmp(confirm->second.data(), masterPassword.data(),
                      masterPassword.size()) == 0;
    if (confirm != fields.end()) {
      confirm->second.truncate(0);
    }
    if (!matched)
      return {400, "text/plain; charset=utf-8", "Passwords do not match"};
    if (login->second.empty())
      return {400, "text/plain; charset=utf-8", "Login must not be empty"};
    // The master password can never be changed, so the one moment it is chosen
    // is the only chance to refuse a hopeless one.
    if (masterPassword.size() < kMinimumMasterPasswordLength) {
      return {400, "text/plain; charset=utf-8",
              "Master password must be at least " +
                  std::to_string(kMinimumMasterPasswordLength) + " characters"};
    }
    return runFirstTimeInstall(*record, loginName, masterPassword);
  }

  if (!vaultInitialized(this->vaultDir_))
    return {409, "text/plain; charset=utf-8", "Vault is not initialized"};

  // One Argon2id derivation covers both the credential check and the record
  // operation: the session verifies login + master password against the stored
  // verifiers, then holds the derived keys for exactly this request. Legacy
  // ALFIEVAULT1 vaults have no verifiers and fall back to the login supplied at
  // server start.
  const bool hasVerifiers = vaultHasCredentials(this->vaultDir_);
  if (!hasVerifiers && loginName != this->expectedLogin_)
    return {403, "text/plain; charset=utf-8", "Bad login"};

  std::optional<VaultSession> session;
  try {
    session.emplace(
        hasVerifiers
            ? VaultSession::open(this->vaultDir_, loginName, masterPassword)
            : VaultSession::openWithPassword(this->vaultDir_, masterPassword));
  } catch (const std::exception &) {
    return {403, "text/plain; charset=utf-8", "Bad login or password"};
  }

  const auto spec = record->spec;
  try {
    if (mode == UnlockMode::Store) {
      auto value = fields.find("value");
      if (value == fields.end() || value->second.empty())
        return {400, "text/plain; charset=utf-8", "Missing secret value"};
      // Move the submitted secret into its single-use storage operation.
      SecureBuffer secretValue = std::move(value->second);
      session->put(spec.purpose, spec.domain, spec.account, secretValue);
      this->lastDelivery_ = DeliveredSecret{token, spec.domain, spec.account,
                                            spec.action, secretValue.size()};
    } else {
      session->use(spec.purpose, spec.domain, spec.account,
                   [&](const SecureBuffer &secret) {
                     // Real browser-worker delivery will use encrypted IPC.
                     // Until that integration, store only metadata proving that
                     // one secret was unlocked; never store payload.
                     this->lastDelivery_ =
                         DeliveredSecret{token, spec.domain, spec.account,
                                         spec.action, secret.size()};
                   });
    }
    record->used = true;
    return {200, "text/html; charset=utf-8",
            mode == UnlockMode::Unlock
                ? "<html><body>Unlocked. Credential delivered to local "
                  "worker.</body></html>"
                : "<html><body>Stored.</body></html>"};
  } catch (const std::exception &) {
    return {403, "text/plain; charset=utf-8", "Unlock failed"};
  }
}

HttpRequest alfie::parseHttpRequest(const std::string &raw) {
  HttpRequest req;
  auto headerEnd = raw.find("\r\n\r\n");
  std::string head =
      raw.substr(0, headerEnd == std::string::npos ? raw.size() : headerEnd);
  req.body = headerEnd == std::string::npos ? std::string{}
                                            : raw.substr(headerEnd + 4);
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

std::string alfie::httpResponseText(const HttpResponse &response) {
  std::ostringstream out;
  out << "HTTP/1.1 " << response.status << " " << statusText(response.status)
      << "\r\n"
      << "Content-Type: " << response.contentType << "\r\n"
      << "Content-Length: " << response.body.size() << "\r\n"
      << "Cache-Control: no-store\r\n"
      << "Connection: close\r\n\r\n"
      << response.body;
  return out.str();
}

// Validate the endpoint and finish listener setup before accepting connections.
static int bindTlsListener(const std::string &host, int port) {
  if (port < 1 || port > 65535)
    throw std::runtime_error("invalid TCP port");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
    throw std::runtime_error("bind host must be IPv4 address");

  ScopedFd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (listener.get() < 0)
    throw sysError("socket");
  // Check the portable CLOEXEC fallback and permit restart after TCP TIME_WAIT.
  int yes = 1;
  if (fcntl(listener.get(), F_SETFD, FD_CLOEXEC) != 0 ||
      setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) !=
          0)
    throw sysError("configure TLS listener");
  if (bind(listener.get(), reinterpret_cast<sockaddr *>(&address),
           sizeof(address)) != 0)
    throw sysError("bind");
  if (listen(listener.get(), 16) != 0)
    throw sysError("listen");
  return listener.release();
}

// Handle one TLS exchange with scoped plaintext and OpenSSL cleanup.
static void serveTlsClient(SSL_CTX *context, int client,
                           UnlockService &service) {
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context), SSL_free);
  if (!ssl || fcntl(client, F_SETFL, O_NONBLOCK) != 0 ||
      SSL_set_fd(ssl.get(), client) != 1)
    throw std::runtime_error("configure TLS client failed");
  auto deadline = std::chrono::steady_clock::now() + kConnectionTimeout;
  tlsIo(ssl.get(), deadline, [&] { return SSL_accept(ssl.get()); });

  std::string raw;
  WipeString wipeRaw{raw};
  readHttpTls(ssl.get(), deadline, raw);
  auto request = parseHttpRequest(raw);
  WipeString wipeBody{request.body};
  auto response = httpResponseText(service.handle(request));
  writeHttpTls(ssl.get(), deadline, response);
  // Send close_notify best-effort; never wait for the peer to acknowledge
  // shutdown.
  SSL_shutdown(ssl.get());
}

// Isolate client failures while keeping the listener and its resources scoped.
static int serveTls(SSL_CTX *ctx, UnlockService &service,
                    const std::string &bindHost, int port, int maxRequests) {
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(ctx, SSL_CTX_free);
  BlockSigpipe blockSigpipe;
  ScopedFd listener(bindTlsListener(bindHost, port));
  int handled = 0;
  while (maxRequests < 0 || handled < maxRequests) {
    ScopedFd client(acceptCloexec(listener.get()));
    if (client.get() < 0) {
      if (errno == EINTR)
        continue;
      throw sysError("accept");
    }
    try {
      serveTlsClient(context.get(), client.get(), service);
      // A dropped client must not reveal why it was dropped, and the
      // request body may hold a master password, so nothing is logged.
      // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const std::exception &) {
    }
    ++handled;
    // Stop the bootstrap server immediately after its one-time setup completes.
    if (service.finished())
      break;
  }
  return handled;
}

static SSL_CTX *newServerContext() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
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

int alfie::runHttpsUnlockServer(UnlockService &service,
                                const std::string &bindHost, int port,
                                const std::filesystem::path &certificatePath,
                                const std::filesystem::path &privateKeyPath,
                                int maxRequests) {
  SSL_CTX *ctx = newServerContext();
  if (SSL_CTX_use_certificate_file(ctx, certificatePath.c_str(),
                                   SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, privateKeyPath.c_str(),
                                  SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    throw CryptoError("TLS certificate/private key load failed");
  }
  return serveTls(ctx, service, bindHost, port, maxRequests);
}

int alfie::runHttpsUnlockServerInMemory(UnlockService &service,
                                        const std::string &bindHost, int port,
                                        const std::string &certificatePem,
                                        const SecureBuffer &privateKeyPem,
                                        int maxRequests) {
  SSL_CTX *ctx = newServerContext();

  BIO *certBio = BIO_new_mem_buf(certificatePem.data(),
                                 static_cast<int>(certificatePem.size()));
  X509 *cert = certBio == nullptr
                   ? nullptr
                   : PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
  BIO *keyBio = BIO_new_mem_buf(privateKeyPem.data(),
                                static_cast<int>(privateKeyPem.size()));
  EVP_PKEY *key = keyBio == nullptr ? nullptr
                                    : PEM_read_bio_PrivateKey(keyBio, nullptr,
                                                              nullptr, nullptr);

  const bool loaded = cert != nullptr && key != nullptr &&
                      SSL_CTX_use_certificate(ctx, cert) == 1 &&
                      SSL_CTX_use_PrivateKey(ctx, key) == 1 &&
                      SSL_CTX_check_private_key(ctx) == 1;

  X509_free(cert);
  EVP_PKEY_free(key);
  BIO_free(certBio);
  BIO_free(keyBio);

  if (!loaded) {
    SSL_CTX_free(ctx);
    throw CryptoError("in-memory TLS certificate/private key load failed");
  }
  return serveTls(ctx, service, bindHost, port, maxRequests);
}
