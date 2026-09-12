//===----------------------------------------------------------------------===//
/// \file
/// Exercise http unlock behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/http_unlock.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace alfie;

static void prepareVault(const std::filesystem::path &Dir) {
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "master pass");
  ChunkVault Vault(Dir);
  Vault.put("account", "example.com", "yuki@example.com", "master pass",
            R"({"secret":"VERY-SECRET-HTTP"})");
}

static void testTokenFormDoesNotExposeSecret() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_unlock_form";
  prepareVault(Dir);
  UnlockService Service(Dir, "yuki");
  auto Token = Service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  auto Response = Service.handle({"GET", "/unlock/" + Token, "", {}});
  assert(Response.Status == 200);
  assert(Response.Body.find("<form") != std::string::npos);
  assert(Response.Body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(Response.Body.find("example.com") != std::string::npos);
  std::filesystem::remove_all(Dir);
}

static void testSubmitUnlocksOnceWithoutReturningSecret() {
  auto Dir =
      std::filesystem::temp_directory_path() / "alfie_http_unlock_submit";
  prepareVault(Dir);
  UnlockService Service(Dir, "yuki");
  auto Token = Service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  std::string Body = "login=yuki&password=master+pass";
  auto Response =
      Service.handle({"POST",
                      "/unlock/" + Token,
                      Body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(Response.Status == 200);
  assert(Response.Body.find("Unlocked") != std::string::npos);
  assert(Response.Body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(Service.lastDelivery().has_value());
  assert(Service.lastDelivery()->SecretSize == 29);

  auto Replay =
      Service.handle({"POST",
                      "/unlock/" + Token,
                      Body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(Replay.Status == 410);
  std::filesystem::remove_all(Dir);
}

static void testStoreTokenAddsNewSecretWithoutEchoingValue() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_store_secret";
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "master pass");
  UnlockService Service(Dir, "yuki");
  auto Token = Service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});

  auto Form = Service.handle({"GET", "/store/" + Token, "", {}});
  assert(Form.Status == 200);
  assert(Form.Body.find("textarea") != std::string::npos);
  assert(Form.Body.find("name=\"value\"") != std::string::npos);

  std::string Body = "login=yuki&password=master+pass&value=%7B%22secret%22%3A%"
                     "22NEW-SECRET-HTTP%22%7D";
  auto Response =
      Service.handle({"POST",
                      "/store/" + Token,
                      Body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(Response.Status == 200);
  assert(Response.Body.find("Stored") != std::string::npos);
  assert(Response.Body.find("NEW-SECRET-HTTP") == std::string::npos);

  ChunkVault Vault(Dir);
  assert(Vault.get("account", "new.example", "new-login", "master pass") ==
         R"({"secret":"NEW-SECRET-HTTP"})");

  auto Replay =
      Service.handle({"POST",
                      "/store/" + Token,
                      Body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(Replay.Status == 410);
  std::filesystem::remove_all(Dir);
}

static void testBadLoginDoesNotConsumeToken() {
  auto Dir =
      std::filesystem::temp_directory_path() / "alfie_http_unlock_bad_login";
  prepareVault(Dir);
  UnlockService Service(Dir, "yuki");
  auto Token = Service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  auto Bad = Service.handle(
      {"POST", "/unlock/" + Token, "login=wrong&password=master+pass", {}});
  assert(Bad.Status == 403);
  assert(!Service.lastDelivery().has_value());

  auto Good = Service.handle(
      {"POST", "/unlock/" + Token, "login=yuki&password=master+pass", {}});
  assert(Good.Status == 200);
  std::filesystem::remove_all(Dir);
}

static void testHttpParseAndRender() {
  auto Req = parseHttpRequest("POST /unlock/abc HTTP/1.1\r\nHost: "
                              "local\r\nContent-Length: 7\r\n\r\na=b+c+d");
  assert(Req.Method == "POST");
  assert(Req.Target == "/unlock/abc");
  assert(Req.Body == "a=b+c+d");
  auto Text = httpResponseText({201, "text/plain", "created"});
  assert(Text.find("HTTP/1.1 201") == 0);
  assert(Text.find("Content-Length: 7") != std::string::npos);
}

static InitPlan testPlan(const std::filesystem::path &OutputDir) {
  InitPlan Plan;
  Plan.OutputDir = OutputDir;
  Plan.ServerIp = "127.0.0.1";
  // Small keys: these tests exercise the plumbing, not RSA.
  Plan.CaRsaBits = 2048;
  Plan.ServerRsaBits = 2048;
  return Plan;
}

static void testInitLinkCreatesVaultCaAndCredentials() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_init";
  auto Out = std::filesystem::temp_directory_path() / "alfie_http_init_out";
  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);

  // No vault credentials exist yet; the terminal setup code authorizes
  // creation.
  UnlockService Service(Dir, "");
  auto Token =
      Service.createInitToken({"init", "", "", "init_vault"}, testPlan(Out));

  auto Form = Service.handle({"GET", "/init/" + Token, "", {}});
  assert(Form.Status == 200);
  assert(Form.Body.find("name=\"confirm\"") != std::string::npos);

  // Mismatched confirmation must not create anything.
  auto Mismatch =
      Service.handle({"POST",
                      "/init/" + Token,
                      "setup_code=" + Service.setupCode(Token).str() +
                          "&login=yuki&password=Zorb7-Quilm-Xy&confirm=typo",
                      {}});
  assert(Mismatch.Status == 400);
  assert(!vaultInitialized(Dir));

  // A password below the floor is refused while it can still be changed.
  auto TooShort =
      Service.handle({"POST",
                      "/init/" + Token,
                      "setup_code=" + Service.setupCode(Token).str() +
                          "&login=yuki&password=short&confirm=short",
                      {}});
  assert(TooShort.Status == 400);
  assert(!vaultInitialized(Dir));

  auto Created = Service.handle(
      {"POST",
       "/init/" + Token,
       "setup_code=" + Service.setupCode(Token).str() +
           "&login=yuki&password=Zorb7-Quilm-Xy&confirm=Zorb7-Quilm-Xy",
       {}});
  assert(Created.Status == 201);
  assert(vaultInitialized(Dir));
  assert(vaultHasCredentials(Dir));
  assert(Created.Body.find("Zorb7-Quilm-Xy") == std::string::npos);

  // The CA certificate is public and written out; the CA private key is not on
  // disk anywhere.
  const auto CaCert = Out / "alfie-local-ca-cert.pem";
  assert(std::filesystem::exists(CaCert));
  for (const auto &Entry : std::filesystem::recursive_directory_iterator(Out)) {
    if (!Entry.is_regular_file())
      continue;
    std::ifstream In(Entry.path(), std::ios::binary);
    std::string Contents((std::istreambuf_iterator<char>(In)),
                         std::istreambuf_iterator<char>());
    const bool IsServerKey = Entry.path().filename() == "alfie-ip-key.pem";
    if (!IsServerKey)
      assert(Contents.find("PRIVATE KEY") == std::string::npos);
  }

  // The CA private key lives in the vault, reachable only with the master
  // password.
  {
    SecureBuffer Password("Zorb7-Quilm-Xy");
    VaultSession Session = VaultSession::open(Dir, "yuki", Password);
    bool SawKey = false;
    Session.use(CaKeyPurpose, CaKeyDomain, CaKeyAccount,
                [&](const SecureBuffer &Secret) {
                  SawKey =
                      Secret.str().find("PRIVATE KEY") != std::string::npos;
                });
    assert(SawKey);
  }

  // The server certificate is issued for the planned IP and its key is 0600.
  const auto ServerKey = Out / "alfie-ip-key.pem";
  assert(std::filesystem::exists(ServerKey));
  assert((std::filesystem::status(ServerKey).permissions() &
          (std::filesystem::perms::group_all |
           std::filesystem::perms::others_all)) ==
         std::filesystem::perms::none);

  // The setup link is one-time, and the service reports that it is done
  // serving.
  assert(Service.finished());
  auto Replay = Service.handle(
      {"POST",
       "/init/" + Token,
       "login=yuki&password=Other-Password-1&confirm=Other-Password-1",
       {}});
  assert(Replay.Status == 410);

  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);
}

static void testSetupPageIsVisuallyDistinctAndShowsFingerprint() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_init_look";
  auto Out =
      std::filesystem::temp_directory_path() / "alfie_http_init_look_out";
  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);

  UnlockService Service(Dir, "");
  Service.setTransportFingerprint("AA:BB:CC:DD");
  auto Token =
      Service.createInitToken({"init", "", "", "init_vault"}, testPlan(Out));
  auto Page = Service.handle({"GET", "/init/" + Token, "", {}}).Body;

  // Red surface, not the slate used by the routine pages.
  assert(Page.find("#450a0a") != std::string::npos);
  assert(Page.find("#0f172a") == std::string::npos);
  // Says what it is and warns about the phishing case.
  assert(Page.find("FIRST-TIME VAULT SETUP") != std::string::npos);
  assert(Page.find("exactly once") != std::string::npos);
  assert(Page.find("master password") != std::string::npos);
  // Echoes the transport fingerprint for out-of-band comparison.
  assert(Page.find("AA:BB:CC:DD") != std::string::npos);

  // Setup retains certificate verification alongside the request identifier.
  assert(Page.find(Service.requestCode(Token)) != std::string::npos);

  // A routine unlock page must not be red, so the two can never be confused.
  auto VaultDir =
      std::filesystem::temp_directory_path() / "alfie_http_init_look_vault";
  std::filesystem::remove_all(VaultDir);
  prepareVault(VaultDir);
  UnlockService UnlockService(VaultDir, "yuki");
  auto UnlockToken = UnlockService.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto UnlockPage =
      UnlockService.handle({"GET", "/unlock/" + UnlockToken, "", {}}).Body;
  assert(UnlockPage.find("#450a0a") == std::string::npos);
  assert(UnlockPage.find("FIRST-TIME") == std::string::npos);

  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);
  std::filesystem::remove_all(VaultDir);
}

static void testInitIsRefusedOnceAVaultExists() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_init_twice";
  auto Out =
      std::filesystem::temp_directory_path() / "alfie_http_init_twice_out";
  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);
  initVault(Dir, "yuki", "master pass");

  UnlockService Service(Dir, "");
  auto Token =
      Service.createInitToken({"init", "", "", "init_vault"}, testPlan(Out));
  auto Response = Service.handle(
      {"POST",
       "/init/" + Token,
       "setup_code=" + Service.setupCode(Token).str() +
           "&login=attacker&password=Attacker-Pass-1&confirm=Attacker-Pass-1",
       {}});
  assert(Response.Status == 409);
  // The original credentials still stand.
  assert(verifyCredentials(Dir, "yuki", "master pass"));
  assert(!verifyCredentials(Dir, "attacker", "Attacker-Pass-1"));

  std::filesystem::remove_all(Dir);
  std::filesystem::remove_all(Out);
}

static void testUnlockChecksCredentialsStoredInVault() {
  auto Dir =
      std::filesystem::temp_directory_path() / "alfie_http_vault_credentials";
  std::filesystem::remove_all(Dir);
  initVault(Dir, "yuki", "master pass");
  {
    ChunkVault Vault(Dir);
    Vault.put("account", "example.com", "yuki@example.com", "master pass",
              R"({"secret":"CRED-CHECK"})");
  }

  // The service was started with the wrong login hint; the vault's own verifier
  // decides.
  UnlockService Service(Dir, "not-the-login");
  auto Token = Service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto Ok = Service.handle(
      {"POST", "/unlock/" + Token, "login=yuki&password=master+pass", {}});
  assert(Ok.Status == 200);

  auto Token2 = Service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto BadLogin = Service.handle(
      {"POST", "/unlock/" + Token2, "login=attacker&password=master+pass", {}});
  assert(BadLogin.Status == 403);

  auto BadPassword = Service.handle(
      {"POST", "/unlock/" + Token2, "login=yuki&password=wrong+pass", {}});
  assert(BadPassword.Status == 403);

  std::filesystem::remove_all(Dir);
}

static void testStoreIntoUninitializedVaultIsRefused() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_http_store_uninit";
  std::filesystem::remove_all(Dir);
  UnlockService Service(Dir, "yuki");
  auto Token = Service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});
  auto Response =
      Service.handle({"POST",
                      "/store/" + Token,
                      "login=yuki&password=master+pass&value=%7B%7D",
                      {}});
  assert(Response.Status == 409);
  assert(!vaultInitialized(Dir));
  std::filesystem::remove_all(Dir);
}

// Every mode has a stable visual code; the code itself grants no access.
static void testRequestCodesAreVisualOnly() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_request_codes";
  std::filesystem::remove_all(Dir);
  UnlockService Service(Dir, "yuki");
  UnlockRequestSpec Spec{"account", "example.com", "yuki", "fill_password"};
  const auto Unlock = Service.createToken(Spec);
  const auto Store = Service.createStoreToken(Spec);
  const auto Init = Service.createInitToken(Spec, testPlan(Dir / "certs"));
  for (const auto &[prefix, token] :
       {std::pair{"/unlock/", Unlock}, std::pair{"/store/", Store},
        std::pair{"/init/", Init}}) {
    const auto Code = Service.requestCode(token);
    assert(Code.size() == 6);
    assert(Code.find_first_not_of("0123456789") == std::string::npos);
    const auto Page = Service.handle({"GET", prefix + token, "", {}});
    assert(Page.Status == 200);
    assert(Page.Body.find(Code) != std::string::npos);
    assert(Service.requestCode(token) == Code);
    assert(Service.handle({"GET", prefix + Code, "", {}}).Status == 410);
  }

  // Expired tokens must not retain a usable display-code lookup.
  Spec.Ttl = std::chrono::seconds(-1);
  auto Expired = Service.createToken(Spec);
  bool Rejected = false;
  try {
    Service.requestCode(Expired);
  } catch (const CryptoError &) {
    Rejected = true;
  }
  assert(Rejected);
}

// Two failures consume the link, even if the correct code is supplied
// afterward.
static void testSetupCodeAttemptLimit() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_setup_attempts";
  std::filesystem::remove_all(Dir);
  UnlockService Service(Dir, "");
  auto Token = Service.createInitToken({"init", "", "", "init_vault"},
                                       testPlan(Dir / "certs"));
  const auto Secret = Service.setupCode(Token).str();
  assert(Secret.size() == 6);
  assert(Secret.find_first_not_of("0123456789") == std::string::npos);
  assert(Secret != Service.requestCode(Token));
  const auto Page = Service.handle({"GET", "/init/" + Token, "", {}});
  assert(Page.Body.find(Secret) == std::string::npos);
  assert(Page.Body.find("name=\"setup_code\"") != std::string::npos);
  assert(Service.handle({"POST", "/init/" + Token, "", {}}).Status == 403);
  assert(Service.handle({"GET", "/init/" + Token, "", {}}).Status == 200);
  const auto Wrong = "setup_code=" + Service.requestCode(Token);
  assert(Service.handle({"POST", "/init/" + Token, Wrong, {}}).Status == 410);
  assert(Service.handle({"GET", "/init/" + Token, "", {}}).Status == 410);
  assert(Service.handle({"POST", "/init/" + Token, "setup_code=" + Secret, {}})
             .Status == 410);
  assert(!vaultInitialized(Dir));

  // One failure does not consume a valid second submission.
  auto Retry = Service.createInitToken({"init", "", "", "init_vault"},
                                       testPlan(Dir / "certs"));
  assert(Service.handle({"POST", "/init/" + Retry, "setup_code=invalid", {}})
             .Status == 403);
  auto Body = "setup_code=" + Service.setupCode(Retry).str() +
              "&login=yuki&password=Correct-Horse-9&confirm=Correct-Horse-9";
  assert(Service.handle({"POST", "/init/" + Retry, Body, {}}).Status == 201);
  assert(Service.handle({"POST", "/init/" + Retry, Body, {}}).Status == 410);
  std::filesystem::remove_all(Dir);
}

int main() {
  testSetupCodeAttemptLimit();
  testRequestCodesAreVisualOnly();
  testInitLinkCreatesVaultCaAndCredentials();
  testSetupPageIsVisuallyDistinctAndShowsFingerprint();
  testInitIsRefusedOnceAVaultExists();
  testUnlockChecksCredentialsStoredInVault();
  testStoreIntoUninitializedVaultIsRefused();
  testTokenFormDoesNotExposeSecret();
  testSubmitUnlocksOnceWithoutReturningSecret();
  testStoreTokenAddsNewSecretWithoutEchoingValue();
  testBadLoginDoesNotConsumeToken();
  testHttpParseAndRender();
  std::cout << "HTTP unlock tests passed\n";
}
