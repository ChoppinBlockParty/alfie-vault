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
static int acceptCloexec(int ListenFd) {
#ifdef __linux__
  return accept4(ListenFd, nullptr, nullptr, SOCK_CLOEXEC);
#else
  int Fd = accept(ListenFd, nullptr, nullptr);
  if (Fd >= 0 && fcntl(Fd, F_SETFD, FD_CLOEXEC) != 0) {
    int Saved = errno;
    close(Fd);
    errno = Saved;
    return -1;
  }
  return Fd;
#endif
}

static std::runtime_error sysError(const std::string &What) {
  return std::runtime_error(What + ": " + std::strerror(errno));
}

static std::string randomToken() {
  unsigned char Bytes[32];
  if (RAND_bytes(Bytes, sizeof(Bytes)) != 1)
    throw CryptoError("RAND_bytes failed");
  std::ostringstream Out;
  for (auto B : Bytes)
    Out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(B);
  OPENSSL_cleanse(Bytes, sizeof(Bytes));
  return Out.str();
}

// Rejection sampling gives each six-digit visual identifier equal probability.
static SecureBuffer randomSixDigitCode() {
  unsigned char Bytes[3];
  unsigned int Value;
  do {
    if (RAND_bytes(Bytes, sizeof(Bytes)) != 1)
      throw CryptoError("request code generation failed");
    Value = (static_cast<unsigned int>(Bytes[0]) << 16) |
            (static_cast<unsigned int>(Bytes[1]) << 8) | Bytes[2];
  } while (Value >= 16000000);
  SecureBuffer Code(6);
  for (size_t I = Code.size(); I > 0; --I) {
    Code.data()[I - 1] = '0' + (Value % 10);
    Value /= 10;
  }
  return Code;
}

static std::string htmlEscape(const std::string &S) {
  std::string Out;
  for (char C : S) {
    switch (C) {
    case '&':
      Out += "&amp;";
      break;
    case '<':
      Out += "&lt;";
      break;
    case '>':
      Out += "&gt;";
      break;
    case '"':
      Out += "&quot;";
      break;
    default:
      Out += C;
      break;
    }
  }
  return Out;
}

static int hexValue(char C) {
  if (C >= '0' && C <= '9')
    return C - '0';
  if (C >= 'a' && C <= 'f')
    return 10 + C - 'a';
  if (C >= 'A' && C <= 'F')
    return 10 + C - 'A';
  return -1;
}

// Wipe all decoded fields on every exit, including invalid submissions.
namespace {
struct FormFields {
  std::map<std::string, SecureBuffer> Values;
};
} // namespace

// Decode directly into secure storage; views avoid intermediate plaintext
// strings.
static SecureBuffer urlDecode(std::string_view Input) {
  SecureBuffer Output(Input.size());
  size_t Written = 0;
  for (size_t I = 0; I < Input.size(); ++I) {
    if (Input[I] == '+') {
      Output.data()[Written++] = ' ';
    } else if (Input[I] == '%' && I + 2 < Input.size() &&
               hexValue(Input[I + 1]) >= 0 && hexValue(Input[I + 2]) >= 0) {
      Output.data()[Written++] =
          (hexValue(Input[I + 1]) << 4) | hexValue(Input[I + 2]);
      I += 2;
    } else {
      Output.data()[Written++] = Input[I];
    }
  }
  Output.truncate(Written);
  return Output;
}

// Accept only known literal field names; never copy attacker-controlled names
// into plain strings.
static FormFields parseForm(std::string_view Body) {
  FormFields Fields;
  while (!Body.empty()) {
    auto End = Body.find('&');
    auto Part = Body.substr(0, End);
    auto Separator = Part.find('=');
    if (Separator != std::string_view::npos) {
      auto Name = Part.substr(0, Separator);
      if (Name == "login" || Name == "password" || Name == "confirm" ||
          Name == "value" || Name == "setup_code")
        Fields.Values[std::string(Name)] =
            urlDecode(Part.substr(Separator + 1));
    }
    if (End == std::string_view::npos)
      break;
    Body.remove_prefix(End + 1);
  }
  return Fields;
}

static std::string statusText(int Status) {
  switch (Status) {
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

static std::string tokenFromTarget(const std::string &Target,
                                   const std::string &Prefix) {
  if (Target.rfind(Prefix, 0) != 0)
    return {};
  auto Token = Target.substr(Prefix.size());
  auto Q = Token.find('?');
  if (Q != std::string::npos)
    Token.resize(Q);
  return Token;
}

using Deadline = std::chrono::steady_clock::time_point;

// Bound connection time and allocation before processing unauthenticated input.
static constexpr auto ConnectionTimeout = std::chrono::seconds(10);
static constexpr size_t MaxHttpBytes = size_t{1024} * 1024;
static constexpr size_t MaxHeaderBytes = size_t{16} * 1024;

// Reuse an absolute deadline so trickled traffic cannot extend the connection
// lifetime.
static int remainingMilliseconds(Deadline Deadline) {
  auto Remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                       Deadline - std::chrono::steady_clock::now())
                       .count();
  if (Remaining <= 0)
    throw std::runtime_error("TLS connection deadline exceeded");
  return static_cast<int>(Remaining);
}

// Wait for the direction requested by OpenSSL without blocking past the
// deadline.
static void waitForTls(SSL *Ssl, int Error, Deadline Deadline) {
  short Events = Error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
  pollfd Socket{SSL_get_fd(Ssl), Events, 0};
  for (;;) {
    int Ready = poll(&Socket, 1, remainingMilliseconds(Deadline));
    if (Ready < 0 && errno == EINTR)
      continue;
    if (Ready <= 0 || (Socket.revents & (POLLERR | POLLNVAL)))
      throw std::runtime_error("TLS socket unavailable");
    return;
  }
}

// Retry the same TLS operation on WANT_READ/WANT_WRITE, as required by OpenSSL.
template <typename OperationT>
static int tlsIo(SSL *Ssl, Deadline Deadline, OperationT Operation) {
  for (;;) {
    remainingMilliseconds(Deadline);
    ERR_clear_error(); // SSL_get_error must see only this operation's errors.
    int Result = Operation();
    if (Result > 0)
      return Result;
    int Error = SSL_get_error(Ssl, Result);
    if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
      throw std::runtime_error("TLS connection failed");
    waitForTls(Ssl, Error, Deadline);
  }
}

// Suppress only this thread's new SIGPIPE, preserving the caller's signal
// state.
namespace {
class BlockSigpipe {
public:
  BlockSigpipe() {
    sigemptyset(&BlockedSignals);
    sigaddset(&BlockedSignals, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &this->BlockedSignals,
                        &this->PreviousMask) != 0)
      throw std::runtime_error("block SIGPIPE failed");
    sigset_t Pending;
    sigpending(&Pending);
    this->HadPendingSigpipe = sigismember(&Pending, SIGPIPE);
  }
  ~BlockSigpipe() {
    sigset_t Pending;
    sigpending(&Pending);
    // Consume newly generated SIGPIPE before restoring the caller's mask.
    if (!this->HadPendingSigpipe && sigismember(&Pending, SIGPIPE)) {
      int Signal = 0;
      sigwait(&this->BlockedSignals, &Signal);
    }
    pthread_sigmask(SIG_SETMASK, &this->PreviousMask, nullptr);
  }

private:
  sigset_t BlockedSignals{}, PreviousMask{};
  bool HadPendingSigpipe = false;
};
} // namespace

// Erase request plaintext on both normal and exceptional exits.
namespace {
struct WipeString {
  std::string &Value;
  ~WipeString() { OPENSSL_cleanse(this->Value.data(), this->Value.size()); }
};
} // namespace

// Reject signed, overflowing, or trailing-junk lengths before allocating a
// body.
static size_t parseContentLength(std::string_view Value) {
  auto First = Value.find_first_not_of(" \t");
  auto Last = Value.find_last_not_of(" \t");
  if (First == std::string_view::npos)
    throw std::runtime_error("invalid content length");
  Value = Value.substr(First, Last - First + 1);
  size_t Length = 0;
  auto [end, error] =
      std::from_chars(Value.data(), Value.data() + Value.size(), Length);
  if (error != std::errc{} || end != Value.data() + Value.size())
    throw std::runtime_error("invalid content length");
  return Length;
}

// Accept one unambiguous fixed-length request; chunking and duplicate lengths
// are unsupported.
static size_t httpRequestSize(std::string_view Headers) {
  size_t BodySize = 0;
  bool SeenLength = false;
  size_t Pos = Headers.find("\r\n") + 2;
  while (Pos < Headers.size() - 2) {
    size_t Next = Headers.find("\r\n", Pos);
    auto Line = Headers.substr(Pos, Next - Pos);
    auto Colon = Line.find(':');
    if (Colon == std::string_view::npos)
      throw std::runtime_error("invalid HTTP header");
    std::string Name(Line.substr(0, Colon));
    std::transform(Name.begin(), Name.end(), Name.begin(),
                   [](unsigned char C) { return std::tolower(C); });
    if (Name == "transfer-encoding")
      throw std::runtime_error("transfer encoding unsupported");
    if (Name == "content-length") {
      if (SeenLength)
        throw std::runtime_error("duplicate content length");
      SeenLength = true;
      BodySize = parseContentLength(Line.substr(Colon + 1));
    }
    Pos = Next + 2;
  }
  if (BodySize > MaxHttpBytes - Headers.size())
    throw std::runtime_error("HTTP request too large");
  return Headers.size() + BodySize;
}

// Read exactly one bounded HTTP message before passing it to the request
// handler.
static void readHttpTls(SSL *Ssl, Deadline Deadline, std::string &Raw) {
  // Wipe the temporary TLS plaintext even if reading or parsing throws.
  struct ReadBuffer {
    char Data[8192];
    ~ReadBuffer() { OPENSSL_cleanse(this->Data, sizeof(this->Data)); }
  } Buffer;
  Raw.reserve(
      MaxHttpBytes); // Avoid abandoned plaintext copies during string growth.
  size_t ExpectedSize = 0;
  for (;;) {
    int Count = tlsIo(Ssl, Deadline, [&] {
      return SSL_read(Ssl, Buffer.Data, sizeof(Buffer.Data));
    });
    if (Raw.size() + Count > MaxHttpBytes)
      throw std::runtime_error("HTTP request too large");
    Raw.append(Buffer.Data, Count);

    // Parse framing once, only after the complete bounded header has arrived.
    if (ExpectedSize == 0) {
      auto HeaderEnd = Raw.find("\r\n\r\n");
      if (HeaderEnd == std::string::npos) {
        if (Raw.size() > MaxHeaderBytes)
          throw std::runtime_error("HTTP headers too large");
        continue;
      }
      size_t HeaderSize = HeaderEnd + 4;
      if (HeaderSize > MaxHeaderBytes)
        throw std::runtime_error("HTTP headers too large");
      ExpectedSize =
          httpRequestSize(std::string_view(Raw).substr(0, HeaderSize));
    }
    if (Raw.size() > ExpectedSize)
      throw std::runtime_error("HTTP pipelining unsupported");
    if (Raw.size() == ExpectedSize)
      return;
  }
}

// Complete partial response writes using the connection's original deadline.
static void writeHttpTls(SSL *Ssl, Deadline Deadline,
                         const std::string &Response) {
  size_t Sent = 0;
  while (Sent < Response.size()) {
    Sent += tlsIo(Ssl, Deadline, [&] {
      return SSL_write(Ssl, Response.data() + Sent,
                       static_cast<int>(Response.size() - Sent));
    });
  }
}

UnlockService::UnlockService(std::filesystem::path VaultDir,
                             std::string ExpectedLogin)
    : VaultDir(std::move(VaultDir)), ExpectedLogin(std::move(ExpectedLogin)) {}

std::string UnlockService::createTokenFor(const UnlockRequestSpec &Spec,
                                          UnlockMode Mode, InitPlan Plan) {
  std::string Token = randomToken();
  this->Tokens[Token] = TokenRecord{Spec,
                                    std::chrono::steady_clock::now() + Spec.Ttl,
                                    false,
                                    Mode,
                                    std::move(Plan),
                                    randomSixDigitCode().str(),
                                    SecureBuffer{},
                                    0};
  return Token;
}

std::string UnlockService::createToken(const UnlockRequestSpec &Spec) {
  return createTokenFor(Spec, UnlockMode::Unlock);
}

std::string UnlockService::createStoreToken(const UnlockRequestSpec &Spec) {
  return createTokenFor(Spec, UnlockMode::Store);
}

std::string UnlockService::createInitToken(const UnlockRequestSpec &Spec,
                                           InitPlan Plan) {
  auto Token = createTokenFor(Spec, UnlockMode::Init, std::move(Plan));
  auto &Record = this->Tokens.at(Token);
  // Keep the secret independent of, and distinct from, the public visual
  // identifier.
  do {
    Record.SetupCode = randomSixDigitCode();
  } while (CRYPTO_memcmp(Record.SetupCode.data(), Record.DisplayCode.data(),
                         6) == 0);
  return Token;
}

// Do not expose an identifier for an expired or consumed request.
std::string UnlockService::requestCode(const std::string &Token) const {
  auto It = this->Tokens.find(Token);
  if (It == this->Tokens.end() || It->second.Used ||
      std::chrono::steady_clock::now() > It->second.ExpiresAt)
    throw CryptoError("request is not active");
  return It->second.DisplayCode;
}

// Only live initialization requests expose their secret to trusted local
// callers.
const SecureBuffer &UnlockService::setupCode(const std::string &Token) const {
  auto It = this->Tokens.find(Token);
  if (It == this->Tokens.end() || It->second.Used ||
      It->second.Mode != UnlockMode::Init ||
      std::chrono::steady_clock::now() > It->second.ExpiresAt)
    throw CryptoError("setup request is not active");
  return It->second.SetupCode;
}

// One place that decides whether a token may act: it must exist, be unused, be
// presented on the path matching the mode it was minted for, and be inside its
// TTL.
UnlockService::TokenRecord *UnlockService::liveToken(const std::string &Token,
                                                     UnlockMode Mode) {
  auto It = this->Tokens.find(Token);
  if (It == this->Tokens.end() || It->second.Used || It->second.Mode != Mode ||
      std::chrono::steady_clock::now() > It->second.ExpiresAt) {
    return nullptr;
  }
  return &It->second;
}

HttpResponse UnlockService::handle(const HttpRequest &Request) {
  struct Route {
    const char *Prefix;
    UnlockMode Mode;
  };
  static constexpr Route Routes[] = {
      {"/unlock/", UnlockMode::Unlock},
      {"/store/", UnlockMode::Store},
      {"/init/", UnlockMode::Init},
  };

  for (const auto &Route : Routes) {
    std::string Token = tokenFromTarget(Request.Target, Route.Prefix);
    if (Token.empty())
      continue;
    if (Request.Method == "GET")
      return renderForm(Token, Route.Mode);
    if (Request.Method == "POST")
      return handleSubmit(Token, Request.Body, Route.Mode);
    return {405, "text/plain; charset=utf-8", "Method not allowed"};
  }
  return {404, "text/plain; charset=utf-8", "Not found"};
}

HttpResponse UnlockService::renderForm(const std::string &Token,
                                       UnlockMode Mode) {
  const TokenRecord *Record = liveToken(Token, Mode);
  if (Record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  const auto &Spec = Record->Spec;
  const bool InitMode = Mode == UnlockMode::Init;

  std::string Title = "Alfie Vault Unlock";
  std::string ActionPath = "/unlock/";
  std::string Button = "Unlock once";
  if (InitMode) {
    Title = "FIRST-TIME VAULT SETUP";
    ActionPath = "/init/";
    Button = "Create vault";
  } else if (Mode == UnlockMode::Store) {
    Title = "Alfie Vault Store";
    ActionPath = "/store/";
    Button = "Store once";
  }

  // The setup page is the highest-value phishing target in the system: it is
  // the one page that asks for the password protecting everything, and the one
  // page a user reaches by clicking through a certificate warning. So it does
  // not look like the routine pages -- red, not slate -- and it says plainly
  // what it is and when it should never appear.
  const char *Surface = InitMode ? "#450a0a" : "#0f172a";
  const char *Card = InitMode ? "#7f1d1d" : "#111827";
  const char *Border = InitMode ? "#f87171" : "#334155";
  const char *Accent = InitMode ? "#dc2626" : "#2563eb";
  const char *Field = InitMode ? "#1c0606" : "#020617";

  std::string MetaLines;
  if (InitMode) {
    MetaLines = "<p class=\"warn\"><strong>You should see this page exactly "
                "once.</strong> "
                "It creates a brand-new vault and sets the login and master "
                "password it will use "
                "forever. If you have already set up Alfie, close this page "
                "now &mdash; someone may be "
                "trying to collect your master password.</p>"
                "<p class=\"meta\">There is no recovery. If the master "
                "password is lost, every record "
                "in the vault is unreadable.</p>";
    if (!this->TransportFingerprint.empty()) {
      MetaLines += "<p class=\"meta\">Check this against the fingerprint "
                   "printed on the server's "
                   "terminal before typing anything:</p><p class=\"fp\">" +
                   htmlEscape(this->TransportFingerprint) + "</p>";
    }
  } else {
    MetaLines = "<p class=\"meta\">Domain: " + htmlEscape(Spec.Domain) +
                "</p><p class=\"meta\">Action: " + htmlEscape(Spec.Action) +
                "</p>";
  }

  // The bot and page share this identifier; it is not a password or
  // authorization factor.
  MetaLines +=
      "<p class=\"meta\">Match this request code with the bot's message:</p>"
      "<p class=\"fp\" style=\"font-size:32px;letter-spacing:0.15em\">" +
      Record->DisplayCode + "</p>";

  std::string ExtraField;
  if (InitMode) {
    ExtraField =
        "<label>Confirm vault password <input name=\"confirm\" "
        "type=\"password\" "
        "autocomplete=\"new-password\"></label>"
        "<label>One-time setup code from the terminal "
        "<input name=\"setup_code\" type=\"password\" inputmode=\"numeric\" "
        "pattern=\"[0-9]{6}\" minlength=\"6\" maxlength=\"6\" "
        "autocomplete=\"off\" required></label>"
        "<p class=\"meta\">Two incorrect setup codes invalidate this link.</p>";
  } else if (Mode == UnlockMode::Store) {
    ExtraField = "<label>Secret JSON <textarea name=\"value\" "
                 "autocomplete=\"off\"></textarea></label><br>";
  }
  const std::string PasswordAutocomplete =
      InitMode ? "new-password" : "current-password";
  const std::string PasswordHint =
      InitMode ? " <span class=\"hint\">(at least " +
                     std::to_string(MinimumMasterPasswordLength) +
                     " characters)</span>"
               : "";

  std::string Body =
      std::string(
          "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<meta name=\"viewport\" "
          "content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
          "<title>") +
      Title +
      "</title><style>"
      ":root{color-scheme:dark}*{box-sizing:border-box}"
      "body{margin:0;min-height:100vh;font-family:-apple-system,"
      "BlinkMacSystemFont,'Segoe "
      "UI',Roboto,sans-serif;"
      "background:" +
      Surface +
      ";color:#f8fafc;display:flex;align-items:center;justify-content:center;"
      "padding:24px}"
      ".card{width:100%;max-width:520px;background:" +
      Card + ";border:2px solid " + Border +
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
      Field +
      ";color:#f8fafc}textarea{min-height:120px}"
      "button{background:" +
      Accent +
      ";color:white;border:0;font-weight:700;margin-top:20px;cursor:pointer}"
      "@media "
      "(max-width:540px){body{padding:12px;align-items:stretch}.card{border-"
      "radius:14px;padding:"
      "18px}}"
      "</style></head><body><main class=\"card\"><h1>" +
      Title + "</h1>" + MetaLines + "<form method=\"post\" action=\"" +
      ActionPath + htmlEscape(Token) +
      "\"><label>Login <input name=\"login\" autocomplete=\"username\" "
      "autocapitalize=\"none\" "
      "spellcheck=\"false\" inputmode=\"text\"></label>"
      "<label>Vault password" +
      PasswordHint +
      " <input name=\"password\" type=\"password\" autocomplete=\"" +
      PasswordAutocomplete + "\"></label>" + ExtraField +
      "<button type=\"submit\">" + Button +
      "</button></form></main></body></html>";
  return {200, "text/html; charset=utf-8", Body};
}

// Creates the vault, then the CA, in that order. The CA private key is
// generated in memory and stored in the vault it just created; it is never
// written to disk. Only public certificates and the server key (0600) reach the
// filesystem.
HttpResponse UnlockService::runFirstTimeInstall(TokenRecord &Record,
                                                const std::string &Login,
                                                SecureBuffer &Password) {
  const InitPlan &Plan = Record.Plan;
  try {
    // Copy directly between secure allocations; setup needs two separate
    // derivations.
    SecureBuffer ForInit(SecureBytes(Password.bytes()));
    initVault(this->VaultDir, Login, ForInit);

    GeneratedCertificate Ca =
        generateCaCertificate(Plan.CaCommonName, 3650, Plan.CaRsaBits);

    {
      SecureBuffer ForSession(SecureBytes(Password.bytes()));
      VaultSession Session =
          VaultSession::open(this->VaultDir, Login, ForSession);
      Session.put(CaKeyPurpose, CaKeyDomain, CaKeyAccount, Ca.PrivateKeyPem);
    }

    const auto CaCertPath = Plan.OutputDir / "alfie-local-ca-cert.pem";
    writePublicFile(CaCertPath, Ca.CertificatePem);

    std::string ServerCertPath;
    if (!Plan.ServerIp.empty()) {
      GeneratedCertificate Server =
          issueIpCertificate(Plan.ServerIp, Ca.CertificatePem, Ca.PrivateKeyPem,
                             825, Plan.ServerRsaBits);
      writePublicFile(Plan.OutputDir / "alfie-ip-cert.pem",
                      Server.CertificatePem);
      writePrivateFile(Plan.OutputDir / "alfie-ip-key.pem",
                       Server.PrivateKeyPem);
      ServerCertPath = (Plan.OutputDir / "alfie-ip-cert.pem").string();
    }

    Record.SetupCode.truncate(
        0); // Erase the one-time secret after successful setup.
    Record.Used = true;
    this->Finished = true;

    const std::string CaFingerprint =
        certificateFingerprintSha256(Ca.CertificatePem);
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
            htmlEscape(CaCertPath.string()) +
            "</code></p><p>Request code: <strong>" + Record.DisplayCode +
            "</strong></p><p>Verify the full SHA-256 fingerprint before "
            "trusting the CA:<br><code style=\"word-break:break-all\">" +
            htmlEscape(CaFingerprint) + "</code></p>" +
            (ServerCertPath.empty()
                 ? std::string{}
                 : "<p>Server certificate for future unlock "
                   "sessions:<br><code>" +
                       htmlEscape(ServerCertPath) + "</code></p>") +
            "</body></html>"};
  } catch (const std::exception &) {
    return {409, "text/plain; charset=utf-8", "Vault setup failed"};
  }
}

HttpResponse UnlockService::handleSubmit(const std::string &Token,
                                         const std::string &FormBody,
                                         UnlockMode Mode) {
  TokenRecord *Record = liveToken(Token, Mode);
  if (Record == nullptr)
    return {410, "text/plain; charset=utf-8", "Unlock link expired"};

  auto Form = parseForm(FormBody);
  auto &Fields = Form.Values;
  // Check before credentials or KDF work; missing and malformed codes count as
  // failures.
  if (Mode == UnlockMode::Init) {
    auto Code = Fields.find("setup_code");
    bool Matches =
        Code != Fields.end() && Code->second.size() == 6 &&
        Record->SetupCode.size() == 6 &&
        CRYPTO_memcmp(Code->second.data(), Record->SetupCode.data(), 6) == 0;
    if (!Matches) {
      if (++Record->SetupFailures >= 2) {
        Record->Used = true;
        Record->SetupCode.truncate(0);
        return {410, "text/plain; charset=utf-8",
                "Setup link invalidated after two incorrect codes"};
      }
      return {403, "text/plain; charset=utf-8",
              "Incorrect setup code. One attempt remaining."};
    }
  }
  auto Login = Fields.find("login");
  auto Password = Fields.find("password");
  if (Login == Fields.end() || Password == Fields.end())
    return {400, "text/plain; charset=utf-8", "Missing login or password"};

  // Transfer the decoded password without leaving a second plaintext
  // allocation.
  SecureBuffer MasterPassword = std::move(Password->second);
  const std::string LoginName = Login->second.str();

  if (Mode == UnlockMode::Init) {
    auto Confirm = Fields.find("confirm");
    const bool Matched =
        Confirm != Fields.end() &&
        Confirm->second.size() == MasterPassword.size() &&
        CRYPTO_memcmp(Confirm->second.data(), MasterPassword.data(),
                      MasterPassword.size()) == 0;
    if (Confirm != Fields.end()) {
      Confirm->second.truncate(0);
    }
    if (!Matched)
      return {400, "text/plain; charset=utf-8", "Passwords do not match"};
    if (Login->second.empty())
      return {400, "text/plain; charset=utf-8", "Login must not be empty"};
    // The master password can never be changed, so the one moment it is chosen
    // is the only chance to refuse a hopeless one.
    if (MasterPassword.size() < MinimumMasterPasswordLength) {
      return {400, "text/plain; charset=utf-8",
              "Master password must be at least " +
                  std::to_string(MinimumMasterPasswordLength) + " characters"};
    }
    return runFirstTimeInstall(*Record, LoginName, MasterPassword);
  }

  if (!vaultInitialized(this->VaultDir))
    return {409, "text/plain; charset=utf-8", "Vault is not initialized"};

  // One Argon2id derivation covers both the credential check and the record
  // operation: the session verifies login + master password against the stored
  // verifiers, then holds the derived keys for exactly this request. Legacy
  // ALFIEVAULT1 vaults have no verifiers and fall back to the login supplied at
  // server start.
  const bool HasVerifiers = vaultHasCredentials(this->VaultDir);
  if (!HasVerifiers && LoginName != this->ExpectedLogin)
    return {403, "text/plain; charset=utf-8", "Bad login"};

  std::optional<VaultSession> Session;
  try {
    Session.emplace(
        HasVerifiers
            ? VaultSession::open(this->VaultDir, LoginName, MasterPassword)
            : VaultSession::openWithPassword(this->VaultDir, MasterPassword));
  } catch (const std::exception &) {
    return {403, "text/plain; charset=utf-8", "Bad login or password"};
  }

  const auto Spec = Record->Spec;
  try {
    if (Mode == UnlockMode::Store) {
      auto Value = Fields.find("value");
      if (Value == Fields.end() || Value->second.empty())
        return {400, "text/plain; charset=utf-8", "Missing secret value"};
      // Move the submitted secret into its single-use storage operation.
      SecureBuffer SecretValue = std::move(Value->second);
      Session->put(Spec.Purpose, Spec.Domain, Spec.Account, SecretValue);
      this->LastDelivery = DeliveredSecret{Token, Spec.Domain, Spec.Account,
                                           Spec.Action, SecretValue.size()};
    } else {
      Session->use(Spec.Purpose, Spec.Domain, Spec.Account,
                   [&](const SecureBuffer &Secret) {
                     // Real browser-worker delivery will use encrypted IPC.
                     // Until that integration, store only metadata proving that
                     // one secret was unlocked; never store payload.
                     this->LastDelivery =
                         DeliveredSecret{Token, Spec.Domain, Spec.Account,
                                         Spec.Action, Secret.size()};
                   });
    }
    Record->Used = true;
    return {200, "text/html; charset=utf-8",
            Mode == UnlockMode::Unlock
                ? "<html><body>Unlocked. Credential delivered to local "
                  "worker.</body></html>"
                : "<html><body>Stored.</body></html>"};
  } catch (const std::exception &) {
    return {403, "text/plain; charset=utf-8", "Unlock failed"};
  }
}

HttpRequest alfie::parseHttpRequest(const std::string &Raw) {
  HttpRequest Req;
  auto HeaderEnd = Raw.find("\r\n\r\n");
  std::string Head =
      Raw.substr(0, HeaderEnd == std::string::npos ? Raw.size() : HeaderEnd);
  Req.Body = HeaderEnd == std::string::npos ? std::string{}
                                            : Raw.substr(HeaderEnd + 4);
  std::istringstream In(Head);
  std::string Version;
  In >> Req.Method >> Req.Target >> Version;
  std::string Line;
  std::getline(In, Line);
  while (std::getline(In, Line)) {
    if (!Line.empty() && Line.back() == '\r')
      Line.pop_back();
    auto Colon = Line.find(':');
    if (Colon == std::string::npos)
      continue;
    std::string Name = Line.substr(0, Colon);
    std::transform(Name.begin(), Name.end(), Name.begin(),
                   [](unsigned char C) { return std::tolower(C); });
    std::string Value = Line.substr(Colon + 1);
    while (!Value.empty() && Value.front() == ' ')
      Value.erase(Value.begin());
    Req.Headers[Name] = Value;
  }
  return Req;
}

std::string alfie::httpResponseText(const HttpResponse &Response) {
  std::ostringstream Out;
  Out << "HTTP/1.1 " << Response.Status << " " << statusText(Response.Status)
      << "\r\n"
      << "Content-Type: " << Response.ContentType << "\r\n"
      << "Content-Length: " << Response.Body.size() << "\r\n"
      << "Cache-Control: no-store\r\n"
      << "Connection: close\r\n\r\n"
      << Response.Body;
  return Out.str();
}

// Validate the endpoint and finish listener setup before accepting connections.
static int bindTlsListener(const std::string &Host, int Port) {
  if (Port < 1 || Port > 65535)
    throw std::runtime_error("invalid TCP port");
  sockaddr_in Address{};
  Address.sin_family = AF_INET;
  Address.sin_port = htons(static_cast<uint16_t>(Port));
  if (inet_pton(AF_INET, Host.c_str(), &Address.sin_addr) != 1)
    throw std::runtime_error("bind host must be IPv4 address");

  ScopedFd Listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (Listener.get() < 0)
    throw sysError("socket");
  // Check the portable CLOEXEC fallback and permit restart after TCP TIME_WAIT.
  int Yes = 1;
  if (fcntl(Listener.get(), F_SETFD, FD_CLOEXEC) != 0 ||
      setsockopt(Listener.get(), SOL_SOCKET, SO_REUSEADDR, &Yes, sizeof(Yes)) !=
          0)
    throw sysError("configure TLS listener");
  if (bind(Listener.get(), reinterpret_cast<sockaddr *>(&Address),
           sizeof(Address)) != 0)
    throw sysError("bind");
  if (listen(Listener.get(), 16) != 0)
    throw sysError("listen");
  return Listener.release();
}

// Handle one TLS exchange with scoped plaintext and OpenSSL cleanup.
static void serveTlsClient(SSL_CTX *Context, int Client,
                           UnlockService &Service) {
  std::unique_ptr<SSL, decltype(&SSL_free)> Ssl(SSL_new(Context), SSL_free);
  if (!Ssl || fcntl(Client, F_SETFL, O_NONBLOCK) != 0 ||
      SSL_set_fd(Ssl.get(), Client) != 1)
    throw std::runtime_error("configure TLS client failed");
  auto Deadline = std::chrono::steady_clock::now() + ConnectionTimeout;
  tlsIo(Ssl.get(), Deadline, [&] { return SSL_accept(Ssl.get()); });

  std::string Raw;
  WipeString WipeRaw{Raw};
  readHttpTls(Ssl.get(), Deadline, Raw);
  auto Request = parseHttpRequest(Raw);
  WipeString WipeBody{Request.Body};
  auto Response = httpResponseText(Service.handle(Request));
  writeHttpTls(Ssl.get(), Deadline, Response);
  // Send close_notify best-effort; never wait for the peer to acknowledge
  // shutdown.
  SSL_shutdown(Ssl.get());
}

// Isolate client failures while keeping the listener and its resources scoped.
static int serveTls(SSL_CTX *Ctx, UnlockService &Service,
                    const std::string &BindHost, int Port, int MaxRequests) {
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> Context(Ctx, SSL_CTX_free);
  BlockSigpipe BlockSigpipe;
  ScopedFd Listener(bindTlsListener(BindHost, Port));
  int Handled = 0;
  while (MaxRequests < 0 || Handled < MaxRequests) {
    ScopedFd Client(acceptCloexec(Listener.get()));
    if (Client.get() < 0) {
      if (errno == EINTR)
        continue;
      throw sysError("accept");
    }
    try {
      serveTlsClient(Context.get(), Client.get(), Service);
      // A dropped client must not reveal why it was dropped, and the
      // request body may hold a master password, so nothing is logged.
      // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const std::exception &) {
    }
    ++Handled;
    // Stop the bootstrap server immediately after its one-time setup completes.
    if (Service.finished())
      break;
  }
  return Handled;
}

static SSL_CTX *newServerContext() {
  SSL_CTX *Ctx = SSL_CTX_new(TLS_server_method());
  if (Ctx == nullptr)
    throw CryptoError("SSL_CTX_new failed");
  // Fail closed rather than silently permitting an older TLS protocol.
  if (SSL_CTX_set_min_proto_version(Ctx, TLS1_3_VERSION) != 1) {
    SSL_CTX_free(Ctx);
    throw CryptoError("TLS minimum version failed");
  }
  // Keep each TLS connection fresh and disable replayable early data.
  SSL_CTX_set_session_cache_mode(Ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(Ctx, 0);
  SSL_CTX_set_max_early_data(Ctx, 0);
  SSL_CTX_set_options(Ctx, SSL_OP_NO_COMPRESSION);
  return Ctx;
}

int alfie::runHttpsUnlockServer(UnlockService &Service,
                                const std::string &BindHost, int Port,
                                const std::filesystem::path &CertificatePath,
                                const std::filesystem::path &PrivateKeyPath,
                                int MaxRequests) {
  SSL_CTX *Ctx = newServerContext();
  if (SSL_CTX_use_certificate_file(Ctx, CertificatePath.c_str(),
                                   SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(Ctx, PrivateKeyPath.c_str(),
                                  SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(Ctx) != 1) {
    SSL_CTX_free(Ctx);
    throw CryptoError("TLS certificate/private key load failed");
  }
  return serveTls(Ctx, Service, BindHost, Port, MaxRequests);
}

int alfie::runHttpsUnlockServerInMemory(UnlockService &Service,
                                        const std::string &BindHost, int Port,
                                        const std::string &CertificatePem,
                                        const SecureBuffer &PrivateKeyPem,
                                        int MaxRequests) {
  SSL_CTX *Ctx = newServerContext();

  BIO *CertBio = BIO_new_mem_buf(CertificatePem.data(),
                                 static_cast<int>(CertificatePem.size()));
  X509 *Cert = CertBio == nullptr
                   ? nullptr
                   : PEM_read_bio_X509(CertBio, nullptr, nullptr, nullptr);
  BIO *KeyBio = BIO_new_mem_buf(PrivateKeyPem.data(),
                                static_cast<int>(PrivateKeyPem.size()));
  EVP_PKEY *Key = KeyBio == nullptr ? nullptr
                                    : PEM_read_bio_PrivateKey(KeyBio, nullptr,
                                                              nullptr, nullptr);

  const bool Loaded = Cert != nullptr && Key != nullptr &&
                      SSL_CTX_use_certificate(Ctx, Cert) == 1 &&
                      SSL_CTX_use_PrivateKey(Ctx, Key) == 1 &&
                      SSL_CTX_check_private_key(Ctx) == 1;

  X509_free(Cert);
  EVP_PKEY_free(Key);
  BIO_free(CertBio);
  BIO_free(KeyBio);

  if (!Loaded) {
    SSL_CTX_free(Ctx);
    throw CryptoError("in-memory TLS certificate/private key load failed");
  }
  return serveTls(Ctx, Service, BindHost, Port, MaxRequests);
}
