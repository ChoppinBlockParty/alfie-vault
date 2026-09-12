//===----------------------------------------------------------------------===//
/// \file
/// Exercise http unlock behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/http_unlock.h"
#include <catch_amalgamated.hpp>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace alfie;

static const char *kFormEncoded = "application/x-www-form-urlencoded";

static HttpRequest get(const std::string &target) {
  return {"GET", target, "", {}};
}

static HttpRequest post(const std::string &target, const std::string &body) {
  return {"POST", target, body, {{"content-type", kFormEncoded}}};
}

/// A unique temp root per case, holding a vault directory and an output
/// directory for anything a setup run writes.
struct TempRoot {
  std::filesystem::path root;
  std::filesystem::path dir;
  std::filesystem::path out;

  TempRoot() {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "alfie-http-XXXXXX").string();
    REQUIRE(mkdtemp(pattern.data()) != nullptr);
    this->root = pattern;
    this->dir = this->root / "vault";
    this->out = this->root / "certs";
  }

  ~TempRoot() {
    std::error_code ec;
    std::filesystem::remove_all(this->root, ec);
  }

  TempRoot(const TempRoot &) = delete;
  TempRoot &operator=(const TempRoot &) = delete;

  /// A vault with one record in it, ready to unlock.
  void prepareVault() const {
    initVault(this->dir, "yuki", "master pass");
    ChunkVault vault(this->dir);
    vault.put("account", "example.com", "yuki@example.com", "master pass",
              R"({"secret":"VERY-SECRET-HTTP"})");
  }

  InitPlan plan() const {
    InitPlan plan;
    plan.outputDir = this->out;
    plan.serverIp = "127.0.0.1";
    // Small keys: these tests exercise the plumbing, not RSA.
    plan.caRsaBits = 2048;
    plan.serverRsaBits = 2048;
    return plan;
  }
};

static UnlockRequestSpec unlockSpec() {
  return {"account", "example.com", "yuki@example.com", "fill_password"};
}

static std::string readFile(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

TEST_CASE("An HTTP request round-trips through parse and render",
          "[http][protocol]") {
  const HttpRequest request =
      parseHttpRequest("POST /unlock/abc HTTP/1.1\r\nHost: "
                       "local\r\nContent-Length: 7\r\n\r\na=b+c+d");

  CHECK(request.method == "POST");
  CHECK(request.target == "/unlock/abc");
  CHECK(request.body == "a=b+c+d");

  const std::string text = httpResponseText({201, "text/plain", "created"});

  CHECK_THAT(text, Catch::Matchers::StartsWith("HTTP/1.1 201"));
  CHECK_THAT(text, Catch::Matchers::ContainsSubstring("Content-Length: 7"));
}

TEST_CASE_METHOD(TempRoot, "The unlock form never carries the secret",
                 "[http][unlock]") {
  this->prepareVault();
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createToken(unlockSpec());

  const HttpResponse response = service.handle(get("/unlock/" + token));

  CHECK(response.status == 200);
  CHECK_THAT(response.body, Catch::Matchers::ContainsSubstring("<form"));
  CHECK_THAT(response.body, Catch::Matchers::ContainsSubstring("example.com"));
  CHECK_THAT(response.body,
             !Catch::Matchers::ContainsSubstring("VERY-SECRET-HTTP"));
}

TEST_CASE_METHOD(TempRoot, "Request metadata is escaped into the page",
                 "[http][unlock][escaping]") {
  // The page carries the master password field, so anything interpolated into
  // it must not be able to introduce markup of its own.
  this->prepareVault();
  UnlockService service(this->dir, "yuki");
  UnlockRequestSpec spec = unlockSpec();
  spec.action = R"(<script>alert("xss")</script>)";
  const std::string token = service.createToken(spec);

  const std::string page = service.handle(get("/unlock/" + token)).body;

  CHECK_THAT(page, !Catch::Matchers::ContainsSubstring("<script>"));
  CHECK_THAT(page, Catch::Matchers::ContainsSubstring("&lt;script&gt;"));
}

TEST_CASE_METHOD(TempRoot, "A submitted unlock happens once",
                 "[http][unlock][token]") {
  this->prepareVault();
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createToken(unlockSpec());
  const std::string body = "login=yuki&password=master+pass";

  const HttpResponse response = service.handle(post("/unlock/" + token, body));

  CHECK(response.status == 200);
  CHECK_THAT(response.body, Catch::Matchers::ContainsSubstring("Unlocked"));
  CHECK_THAT(response.body,
             !Catch::Matchers::ContainsSubstring("VERY-SECRET-HTTP"));

  // Only metadata is retained, never the value.
  REQUIRE(service.lastDelivery().has_value());
  CHECK(service.lastDelivery()->secretSize == 29);

  // The token is consumed, so the same link cannot unlock a second time.
  CHECK(service.handle(post("/unlock/" + token, body)).status == 410);
}

TEST_CASE_METHOD(TempRoot, "A bad login does not consume the token",
                 "[http][unlock][token]") {
  this->prepareVault();
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createToken(unlockSpec());

  const HttpResponse bad = service.handle(
      post("/unlock/" + token, "login=wrong&password=master+pass"));

  CHECK(bad.status == 403);
  CHECK_FALSE(service.lastDelivery().has_value());

  // A typo must not cost the person their link.
  CHECK(service
            .handle(post("/unlock/" + token, "login=yuki&password=master+pass"))
            .status == 200);
}

TEST_CASE_METHOD(TempRoot, "The vault's own verifier decides the credentials",
                 "[http][unlock][auth]") {
  initVault(this->dir, "yuki", "master pass");
  {
    ChunkVault vault(this->dir);
    vault.put("account", "example.com", "yuki@example.com", "master pass",
              R"({"secret":"CRED-CHECK"})");
  }

  // The service was started with the wrong login hint; the vault decides.
  UnlockService service(this->dir, "not-the-login");

  CHECK(service
            .handle(post("/unlock/" + service.createToken(unlockSpec()),
                         "login=yuki&password=master+pass"))
            .status == 200);
  CHECK(service
            .handle(post("/unlock/" + service.createToken(unlockSpec()),
                         "login=attacker&password=master+pass"))
            .status == 403);
  CHECK(service
            .handle(post("/unlock/" + service.createToken(unlockSpec()),
                         "login=yuki&password=wrong+pass"))
            .status == 403);
}

TEST_CASE_METHOD(TempRoot, "A store link adds a secret without echoing it",
                 "[http][store]") {
  initVault(this->dir, "yuki", "master pass");
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});

  const HttpResponse form = service.handle(get("/store/" + token));
  CHECK(form.status == 200);
  CHECK_THAT(form.body, Catch::Matchers::ContainsSubstring("textarea"));
  CHECK_THAT(form.body, Catch::Matchers::ContainsSubstring("name=\"value\""));

  const std::string body =
      "login=yuki&password=master+pass&value=%7B%22secret%22%3A%"
      "22NEW-SECRET-HTTP%22%7D";
  const HttpResponse response = service.handle(post("/store/" + token, body));

  CHECK(response.status == 200);
  CHECK_THAT(response.body, Catch::Matchers::ContainsSubstring("Stored"));
  CHECK_THAT(response.body,
             !Catch::Matchers::ContainsSubstring("NEW-SECRET-HTTP"));

  ChunkVault vault(this->dir);
  CHECK(vault.get("account", "new.example", "new-login", "master pass") ==
        R"({"secret":"NEW-SECRET-HTTP"})");
  CHECK(service.handle(post("/store/" + token, body)).status == 410);
}

TEST_CASE_METHOD(TempRoot,
                 "Storing into a vault that does not exist is refused",
                 "[http][store]") {
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});

  const HttpResponse response = service.handle(
      post("/store/" + token, "login=yuki&password=master+pass&value=%7B%7D"));

  CHECK(response.status == 409);
  CHECK_FALSE(vaultInitialized(this->dir));
}

TEST_CASE_METHOD(TempRoot, "A setup link creates the vault, CA and credentials",
                 "[http][init]") {
  // No vault credentials exist yet; the terminal setup code authorizes
  // creation.
  UnlockService service(this->dir, "");
  const std::string token =
      service.createInitToken({"init", "", "", "init_vault"}, this->plan());

  const HttpResponse form = service.handle(get("/init/" + token));
  CHECK(form.status == 200);
  CHECK_THAT(form.body, Catch::Matchers::ContainsSubstring("name=\"confirm\""));

  SECTION("a mismatched confirmation creates nothing") {
    const HttpResponse mismatch = service.handle(
        post("/init/" + token, "setup_code=" + service.setupCode(token).str() +
                                   "&login=yuki&password=Zorb7-Quilm-Xy"
                                   "&confirm=typo"));

    CHECK(mismatch.status == 400);
    CHECK_FALSE(vaultInitialized(this->dir));
  }

  SECTION("a password below the floor is refused while it can still change") {
    const HttpResponse tooShort = service.handle(
        post("/init/" + token, "setup_code=" + service.setupCode(token).str() +
                                   "&login=yuki&password=short&confirm=short"));

    CHECK(tooShort.status == 400);
    CHECK_FALSE(vaultInitialized(this->dir));
  }

  SECTION("a completed setup leaves a vault, a CA and a dead link") {
    const HttpResponse created = service.handle(
        post("/init/" + token,
             "setup_code=" + service.setupCode(token).str() +
                 "&login=yuki&password=Zorb7-Quilm-Xy&confirm=Zorb7-Quilm-Xy"));

    REQUIRE(created.status == 201);
    CHECK(vaultInitialized(this->dir));
    CHECK(vaultHasCredentials(this->dir));
    CHECK_THAT(created.body,
               !Catch::Matchers::ContainsSubstring("Zorb7-Quilm-Xy"));

    // The CA certificate is public and written out; the CA private key is not
    // on disk anywhere.
    CHECK(std::filesystem::exists(this->out / "alfie-local-ca-cert.pem"));
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(this->out)) {
      if (!entry.is_regular_file() ||
          entry.path().filename() == "alfie-ip-key.pem")
        continue;
      CAPTURE(entry.path().string());
      CHECK_THAT(readFile(entry.path()),
                 !Catch::Matchers::ContainsSubstring("PRIVATE KEY"));
    }

    // The CA private key lives in the vault, reachable only with the master
    // password.
    SecureBuffer password("Zorb7-Quilm-Xy");
    VaultSession session = VaultSession::open(this->dir, "yuki", password);
    bool sawKey = false;
    session.use(kCaKeyPurpose, kCaKeyDomain, kCaKeyAccount,
                [&](const SecureBuffer &secret) {
                  sawKey =
                      secret.str().find("PRIVATE KEY") != std::string::npos;
                });
    CHECK(sawKey);

    // The server key is issued for the planned IP and stays 0600.
    const std::filesystem::path serverKey = this->out / "alfie-ip-key.pem";
    REQUIRE(std::filesystem::exists(serverKey));
    CHECK((std::filesystem::status(serverKey).permissions() &
           (std::filesystem::perms::group_all |
            std::filesystem::perms::others_all)) ==
          std::filesystem::perms::none);

    // The setup link is one-time, and the service reports that it is done
    // serving.
    CHECK(service.finished());
    CHECK(service
              .handle(post("/init/" + token,
                           "login=yuki&password=Other-Password-1"
                           "&confirm=Other-Password-1"))
              .status == 410);
  }
}

TEST_CASE_METHOD(TempRoot, "The setup page is unmistakable", "[http][init]") {
  UnlockService service(this->dir, "");
  service.setTransportFingerprint("AA:BB:CC:DD");
  const std::string token =
      service.createInitToken({"init", "", "", "init_vault"}, this->plan());

  const std::string page = service.handle(get("/init/" + token)).body;

  SECTION("it is red, not the slate of the routine pages") {
    CHECK_THAT(page, Catch::Matchers::ContainsSubstring("#450a0a"));
    CHECK_THAT(page, !Catch::Matchers::ContainsSubstring("#0f172a"));
  }

  SECTION("it says what it is and warns about the phishing case") {
    CHECK_THAT(page,
               Catch::Matchers::ContainsSubstring("FIRST-TIME VAULT SETUP"));
    CHECK_THAT(page, Catch::Matchers::ContainsSubstring("exactly once"));
    CHECK_THAT(page, Catch::Matchers::ContainsSubstring("master password"));
  }

  SECTION("it echoes the fingerprint for out-of-band comparison") {
    // No CA is trusted yet, so this comparison against the terminal is the
    // only real defence against a convincing imitation of this page.
    CHECK_THAT(page, Catch::Matchers::ContainsSubstring("AA:BB:CC:DD"));
    CHECK_THAT(page,
               Catch::Matchers::ContainsSubstring(service.requestCode(token)));
  }
}

TEST_CASE_METHOD(TempRoot, "A routine unlock page cannot be confused for setup",
                 "[http][init]") {
  this->prepareVault();
  UnlockService service(this->dir, "yuki");
  const std::string token = service.createToken(unlockSpec());

  const std::string page = service.handle(get("/unlock/" + token)).body;

  CHECK_THAT(page, !Catch::Matchers::ContainsSubstring("#450a0a"));
  CHECK_THAT(page, !Catch::Matchers::ContainsSubstring("FIRST-TIME"));
}

TEST_CASE_METHOD(TempRoot, "Setup is refused once a vault exists",
                 "[http][init]") {
  initVault(this->dir, "yuki", "master pass");
  UnlockService service(this->dir, "");
  const std::string token =
      service.createInitToken({"init", "", "", "init_vault"}, this->plan());

  const HttpResponse response = service.handle(
      post("/init/" + token, "setup_code=" + service.setupCode(token).str() +
                                 "&login=attacker&password=Attacker-Pass-1"
                                 "&confirm=Attacker-Pass-1"));

  CHECK(response.status == 409);
  // The original credentials still stand.
  CHECK(verifyCredentials(this->dir, "yuki", "master pass"));
  CHECK_FALSE(verifyCredentials(this->dir, "attacker", "Attacker-Pass-1"));
}

TEST_CASE_METHOD(TempRoot, "Request codes are visual only", "[http][codes]") {
  UnlockService service(this->dir, "yuki");
  UnlockRequestSpec spec{"account", "example.com", "yuki", "fill_password"};
  const std::string unlock = service.createToken(spec);
  const std::string store = service.createStoreToken(spec);
  const std::string init = service.createInitToken(spec, this->plan());

  for (const auto &[prefix, token] :
       {std::pair{"/unlock/", unlock}, std::pair{"/store/", store},
        std::pair{"/init/", init}}) {
    CAPTURE(prefix);
    const std::string code = service.requestCode(token);

    CHECK(code.size() == 6);
    CHECK(code.find_first_not_of("0123456789") == std::string::npos);
    CHECK(service.requestCode(token) == code);

    const HttpResponse page = service.handle(get(prefix + token));
    CHECK(page.status == 200);
    CHECK_THAT(page.body, Catch::Matchers::ContainsSubstring(code));
    // The code identifies the request; it does not authorize it.
    CHECK(service.handle(get(prefix + code)).status == 410);
  }

  SECTION("an expired token has no usable code lookup") {
    spec.ttl = std::chrono::seconds(-1);
    const std::string expired = service.createToken(spec);

    CHECK_THROWS_AS(service.requestCode(expired), CryptoError);
  }
}

TEST_CASE_METHOD(TempRoot, "The setup code is separate and attempt-limited",
                 "[http][init][codes]") {
  UnlockService service(this->dir, "");
  const std::string token =
      service.createInitToken({"init", "", "", "init_vault"}, this->plan());
  const std::string secret = service.setupCode(token).str();

  CHECK(secret.size() == 6);
  CHECK(secret.find_first_not_of("0123456789") == std::string::npos);
  // The setup code comes from the terminal, so it must not be the code the
  // page already shows.
  CHECK(secret != service.requestCode(token));

  const HttpResponse page = service.handle(get("/init/" + token));
  CHECK_THAT(page.body, !Catch::Matchers::ContainsSubstring(secret));
  CHECK_THAT(page.body,
             Catch::Matchers::ContainsSubstring("name=\"setup_code\""));

  SECTION("two wrong codes consume the link") {
    CHECK(service.handle(post("/init/" + token, "")).status == 403);
    CHECK(service.handle(get("/init/" + token)).status == 200);

    CHECK(service
              .handle(post("/init/" + token,
                           "setup_code=" + service.requestCode(token)))
              .status == 410);
    CHECK(service.handle(get("/init/" + token)).status == 410);
    // Even the correct code cannot revive it.
    CHECK(
        service.handle(post("/init/" + token, "setup_code=" + secret)).status ==
        410);
    CHECK_FALSE(vaultInitialized(this->dir));
  }

  SECTION("one failure does not consume a valid second submission") {
    CHECK(service.handle(post("/init/" + token, "setup_code=invalid")).status ==
          403);

    const std::string body =
        "setup_code=" + secret +
        "&login=yuki&password=Correct-Horse-9&confirm=Correct-Horse-9";
    CHECK(service.handle(post("/init/" + token, body)).status == 201);
    CHECK(service.handle(post("/init/" + token, body)).status == 410);
  }
}
