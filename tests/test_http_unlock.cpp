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

static void prepareVault(const std::filesystem::path &dir) {
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "master pass");
  ChunkVault vault(dir);
  vault.put("account", "example.com", "yuki@example.com", "master pass",
            R"({"secret":"VERY-SECRET-HTTP"})");
}

static void testTokenFormDoesNotExposeSecret() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_unlock_form";
  prepareVault(dir);
  UnlockService service(dir, "yuki");
  auto token = service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  auto response = service.handle({"GET", "/unlock/" + token, "", {}});
  assert(response.status == 200);
  assert(response.body.find("<form") != std::string::npos);
  assert(response.body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(response.body.find("example.com") != std::string::npos);
  std::filesystem::remove_all(dir);
}

static void testSubmitUnlocksOnceWithoutReturningSecret() {
  auto dir =
      std::filesystem::temp_directory_path() / "alfie_http_unlock_submit";
  prepareVault(dir);
  UnlockService service(dir, "yuki");
  auto token = service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  std::string body = "login=yuki&password=master+pass";
  auto response =
      service.handle({"POST",
                      "/unlock/" + token,
                      body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(response.status == 200);
  assert(response.body.find("Unlocked") != std::string::npos);
  assert(response.body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(service.lastDelivery().has_value());
  assert(service.lastDelivery()->secretSize == 29);

  auto replay =
      service.handle({"POST",
                      "/unlock/" + token,
                      body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(replay.status == 410);
  std::filesystem::remove_all(dir);
}

static void testStoreTokenAddsNewSecretWithoutEchoingValue() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_store_secret";
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "master pass");
  UnlockService service(dir, "yuki");
  auto token = service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});

  auto form = service.handle({"GET", "/store/" + token, "", {}});
  assert(form.status == 200);
  assert(form.body.find("textarea") != std::string::npos);
  assert(form.body.find("name=\"value\"") != std::string::npos);

  std::string body = "login=yuki&password=master+pass&value=%7B%22secret%22%3A%"
                     "22NEW-SECRET-HTTP%22%7D";
  auto response =
      service.handle({"POST",
                      "/store/" + token,
                      body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(response.status == 200);
  assert(response.body.find("Stored") != std::string::npos);
  assert(response.body.find("NEW-SECRET-HTTP") == std::string::npos);

  ChunkVault vault(dir);
  assert(vault.get("account", "new.example", "new-login", "master pass") ==
         R"({"secret":"NEW-SECRET-HTTP"})");

  auto replay =
      service.handle({"POST",
                      "/store/" + token,
                      body,
                      {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(replay.status == 410);
  std::filesystem::remove_all(dir);
}

static void testBadLoginDoesNotConsumeToken() {
  auto dir =
      std::filesystem::temp_directory_path() / "alfie_http_unlock_bad_login";
  prepareVault(dir);
  UnlockService service(dir, "yuki");
  auto token = service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});

  auto bad = service.handle(
      {"POST", "/unlock/" + token, "login=wrong&password=master+pass", {}});
  assert(bad.status == 403);
  assert(!service.lastDelivery().has_value());

  auto good = service.handle(
      {"POST", "/unlock/" + token, "login=yuki&password=master+pass", {}});
  assert(good.status == 200);
  std::filesystem::remove_all(dir);
}

static void testHttpParseAndRender() {
  auto req = parseHttpRequest("POST /unlock/abc HTTP/1.1\r\nHost: "
                              "local\r\nContent-Length: 7\r\n\r\na=b+c+d");
  assert(req.method == "POST");
  assert(req.target == "/unlock/abc");
  assert(req.body == "a=b+c+d");
  auto text = httpResponseText({201, "text/plain", "created"});
  assert(text.find("HTTP/1.1 201") == 0);
  assert(text.find("Content-Length: 7") != std::string::npos);
}

static InitPlan testPlan(const std::filesystem::path &outputDir) {
  InitPlan plan;
  plan.outputDir = outputDir;
  plan.serverIp = "127.0.0.1";
  // Small keys: these tests exercise the plumbing, not RSA.
  plan.caRsaBits = 2048;
  plan.serverRsaBits = 2048;
  return plan;
}

static void testInitLinkCreatesVaultCaAndCredentials() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_init";
  auto out = std::filesystem::temp_directory_path() / "alfie_http_init_out";
  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);

  // No vault credentials exist yet; the terminal setup code authorizes
  // creation.
  UnlockService service(dir, "");
  auto token =
      service.createInitToken({"init", "", "", "init_vault"}, testPlan(out));

  auto form = service.handle({"GET", "/init/" + token, "", {}});
  assert(form.status == 200);
  assert(form.body.find("name=\"confirm\"") != std::string::npos);

  // Mismatched confirmation must not create anything.
  auto mismatch =
      service.handle({"POST",
                      "/init/" + token,
                      "setup_code=" + service.setupCode(token).str() +
                          "&login=yuki&password=Zorb7-Quilm-Xy&confirm=typo",
                      {}});
  assert(mismatch.status == 400);
  assert(!vaultInitialized(dir));

  // A password below the floor is refused while it can still be changed.
  auto tooShort =
      service.handle({"POST",
                      "/init/" + token,
                      "setup_code=" + service.setupCode(token).str() +
                          "&login=yuki&password=short&confirm=short",
                      {}});
  assert(tooShort.status == 400);
  assert(!vaultInitialized(dir));

  auto created = service.handle(
      {"POST",
       "/init/" + token,
       "setup_code=" + service.setupCode(token).str() +
           "&login=yuki&password=Zorb7-Quilm-Xy&confirm=Zorb7-Quilm-Xy",
       {}});
  assert(created.status == 201);
  assert(vaultInitialized(dir));
  assert(vaultHasCredentials(dir));
  assert(created.body.find("Zorb7-Quilm-Xy") == std::string::npos);

  // The CA certificate is public and written out; the CA private key is not on
  // disk anywhere.
  const auto caCert = out / "alfie-local-ca-cert.pem";
  assert(std::filesystem::exists(caCert));
  for (const auto &entry : std::filesystem::recursive_directory_iterator(out)) {
    if (!entry.is_regular_file())
      continue;
    std::ifstream in(entry.path(), std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    const bool isServerKey = entry.path().filename() == "alfie-ip-key.pem";
    if (!isServerKey)
      assert(contents.find("PRIVATE KEY") == std::string::npos);
  }

  // The CA private key lives in the vault, reachable only with the master
  // password.
  {
    SecureBuffer password("Zorb7-Quilm-Xy");
    VaultSession session = VaultSession::open(dir, "yuki", password);
    bool sawKey = false;
    session.use(kCaKeyPurpose, kCaKeyDomain, kCaKeyAccount,
                [&](const SecureBuffer &secret) {
                  sawKey =
                      secret.str().find("PRIVATE KEY") != std::string::npos;
                });
    assert(sawKey);
  }

  // The server certificate is issued for the planned IP and its key is 0600.
  const auto serverKey = out / "alfie-ip-key.pem";
  assert(std::filesystem::exists(serverKey));
  assert((std::filesystem::status(serverKey).permissions() &
          (std::filesystem::perms::group_all |
           std::filesystem::perms::others_all)) ==
         std::filesystem::perms::none);

  // The setup link is one-time, and the service reports that it is done
  // serving.
  assert(service.finished());
  auto replay = service.handle(
      {"POST",
       "/init/" + token,
       "login=yuki&password=Other-Password-1&confirm=Other-Password-1",
       {}});
  assert(replay.status == 410);

  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);
}

static void testSetupPageIsVisuallyDistinctAndShowsFingerprint() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_init_look";
  auto out =
      std::filesystem::temp_directory_path() / "alfie_http_init_look_out";
  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);

  UnlockService service(dir, "");
  service.setTransportFingerprint("AA:BB:CC:DD");
  auto token =
      service.createInitToken({"init", "", "", "init_vault"}, testPlan(out));
  auto page = service.handle({"GET", "/init/" + token, "", {}}).body;

  // Red surface, not the slate used by the routine pages.
  assert(page.find("#450a0a") != std::string::npos);
  assert(page.find("#0f172a") == std::string::npos);
  // Says what it is and warns about the phishing case.
  assert(page.find("FIRST-TIME VAULT SETUP") != std::string::npos);
  assert(page.find("exactly once") != std::string::npos);
  assert(page.find("master password") != std::string::npos);
  // Echoes the transport fingerprint for out-of-band comparison.
  assert(page.find("AA:BB:CC:DD") != std::string::npos);

  // Setup retains certificate verification alongside the request identifier.
  assert(page.find(service.requestCode(token)) != std::string::npos);

  // A routine unlock page must not be red, so the two can never be confused.
  auto vaultDir =
      std::filesystem::temp_directory_path() / "alfie_http_init_look_vault";
  std::filesystem::remove_all(vaultDir);
  prepareVault(vaultDir);
  UnlockService unlockService(vaultDir, "yuki");
  auto unlockToken = unlockService.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto unlockPage =
      unlockService.handle({"GET", "/unlock/" + unlockToken, "", {}}).body;
  assert(unlockPage.find("#450a0a") == std::string::npos);
  assert(unlockPage.find("FIRST-TIME") == std::string::npos);

  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);
  std::filesystem::remove_all(vaultDir);
}

static void testInitIsRefusedOnceAVaultExists() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_init_twice";
  auto out =
      std::filesystem::temp_directory_path() / "alfie_http_init_twice_out";
  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);
  initVault(dir, "yuki", "master pass");

  UnlockService service(dir, "");
  auto token =
      service.createInitToken({"init", "", "", "init_vault"}, testPlan(out));
  auto response = service.handle(
      {"POST",
       "/init/" + token,
       "setup_code=" + service.setupCode(token).str() +
           "&login=attacker&password=Attacker-Pass-1&confirm=Attacker-Pass-1",
       {}});
  assert(response.status == 409);
  // The original credentials still stand.
  assert(verifyCredentials(dir, "yuki", "master pass"));
  assert(!verifyCredentials(dir, "attacker", "Attacker-Pass-1"));

  std::filesystem::remove_all(dir);
  std::filesystem::remove_all(out);
}

static void testUnlockChecksCredentialsStoredInVault() {
  auto dir =
      std::filesystem::temp_directory_path() / "alfie_http_vault_credentials";
  std::filesystem::remove_all(dir);
  initVault(dir, "yuki", "master pass");
  {
    ChunkVault vault(dir);
    vault.put("account", "example.com", "yuki@example.com", "master pass",
              R"({"secret":"CRED-CHECK"})");
  }

  // The service was started with the wrong login hint; the vault's own verifier
  // decides.
  UnlockService service(dir, "not-the-login");
  auto token = service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto ok = service.handle(
      {"POST", "/unlock/" + token, "login=yuki&password=master+pass", {}});
  assert(ok.status == 200);

  auto token2 = service.createToken(
      {"account", "example.com", "yuki@example.com", "fill_password"});
  auto badLogin = service.handle(
      {"POST", "/unlock/" + token2, "login=attacker&password=master+pass", {}});
  assert(badLogin.status == 403);

  auto badPassword = service.handle(
      {"POST", "/unlock/" + token2, "login=yuki&password=wrong+pass", {}});
  assert(badPassword.status == 403);

  std::filesystem::remove_all(dir);
}

static void testStoreIntoUninitializedVaultIsRefused() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_store_uninit";
  std::filesystem::remove_all(dir);
  UnlockService service(dir, "yuki");
  auto token = service.createStoreToken(
      {"account", "new.example", "new-login", "store_secret"});
  auto response =
      service.handle({"POST",
                      "/store/" + token,
                      "login=yuki&password=master+pass&value=%7B%7D",
                      {}});
  assert(response.status == 409);
  assert(!vaultInitialized(dir));
  std::filesystem::remove_all(dir);
}

// Every mode has a stable visual code; the code itself grants no access.
static void testRequestCodesAreVisualOnly() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_request_codes";
  std::filesystem::remove_all(dir);
  UnlockService service(dir, "yuki");
  UnlockRequestSpec spec{"account", "example.com", "yuki", "fill_password"};
  const auto unlock = service.createToken(spec);
  const auto store = service.createStoreToken(spec);
  const auto init = service.createInitToken(spec, testPlan(dir / "certs"));
  for (const auto &[prefix, token] :
       {std::pair{"/unlock/", unlock}, std::pair{"/store/", store},
        std::pair{"/init/", init}}) {
    const auto code = service.requestCode(token);
    assert(code.size() == 6);
    assert(code.find_first_not_of("0123456789") == std::string::npos);
    const auto page = service.handle({"GET", prefix + token, "", {}});
    assert(page.status == 200);
    assert(page.body.find(code) != std::string::npos);
    assert(service.requestCode(token) == code);
    assert(service.handle({"GET", prefix + code, "", {}}).status == 410);
  }

  // Expired tokens must not retain a usable display-code lookup.
  spec.ttl = std::chrono::seconds(-1);
  auto expired = service.createToken(spec);
  bool rejected = false;
  try {
    service.requestCode(expired);
  } catch (const CryptoError &) {
    rejected = true;
  }
  assert(rejected);
}

// Two failures consume the link, even if the correct code is supplied
// afterward.
static void testSetupCodeAttemptLimit() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_setup_attempts";
  std::filesystem::remove_all(dir);
  UnlockService service(dir, "");
  auto token = service.createInitToken({"init", "", "", "init_vault"},
                                       testPlan(dir / "certs"));
  const auto secret = service.setupCode(token).str();
  assert(secret.size() == 6);
  assert(secret.find_first_not_of("0123456789") == std::string::npos);
  assert(secret != service.requestCode(token));
  const auto page = service.handle({"GET", "/init/" + token, "", {}});
  assert(page.body.find(secret) == std::string::npos);
  assert(page.body.find("name=\"setup_code\"") != std::string::npos);
  assert(service.handle({"POST", "/init/" + token, "", {}}).status == 403);
  assert(service.handle({"GET", "/init/" + token, "", {}}).status == 200);
  const auto wrong = "setup_code=" + service.requestCode(token);
  assert(service.handle({"POST", "/init/" + token, wrong, {}}).status == 410);
  assert(service.handle({"GET", "/init/" + token, "", {}}).status == 410);
  assert(service.handle({"POST", "/init/" + token, "setup_code=" + secret, {}})
             .status == 410);
  assert(!vaultInitialized(dir));

  // One failure does not consume a valid second submission.
  auto retry = service.createInitToken({"init", "", "", "init_vault"},
                                       testPlan(dir / "certs"));
  assert(service.handle({"POST", "/init/" + retry, "setup_code=invalid", {}})
             .status == 403);
  auto body = "setup_code=" + service.setupCode(retry).str() +
              "&login=yuki&password=Correct-Horse-9&confirm=Correct-Horse-9";
  assert(service.handle({"POST", "/init/" + retry, body, {}}).status == 201);
  assert(service.handle({"POST", "/init/" + retry, body, {}}).status == 410);
  std::filesystem::remove_all(dir);
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
