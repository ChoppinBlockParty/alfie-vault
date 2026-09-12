#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "../src/http_unlock.hpp"

using namespace alfie;

static void prepare_vault(const std::filesystem::path& dir) {
  std::filesystem::remove_all(dir);
  init_vault(dir, "yuki", "master pass");
  ChunkVault vault(dir);
  vault.put("account", "example.com", "yuki@example.com", "master pass",
            R"({"secret":"VERY-SECRET-HTTP"})");
}

static void test_token_form_does_not_expose_secret() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_unlock_form";
  prepare_vault(dir);
  UnlockService service(dir, "yuki");
  auto token =
      service.create_token({"account", "example.com", "yuki@example.com", "fill_password"});

  auto response = service.handle({"GET", "/unlock/" + token, "", {}});
  assert(response.status == 200);
  assert(response.body.find("<form") != std::string::npos);
  assert(response.body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(response.body.find("example.com") != std::string::npos);
  std::filesystem::remove_all(dir);
}

static void test_submit_unlocks_once_without_returning_secret() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_unlock_submit";
  prepare_vault(dir);
  UnlockService service(dir, "yuki");
  auto token =
      service.create_token({"account", "example.com", "yuki@example.com", "fill_password"});

  std::string body = "login=yuki&password=master+pass";
  auto response = service.handle(
      {"POST", "/unlock/" + token, body, {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(response.status == 200);
  assert(response.body.find("Unlocked") != std::string::npos);
  assert(response.body.find("VERY-SECRET-HTTP") == std::string::npos);
  assert(service.last_delivery().has_value());
  assert(service.last_delivery()->secret_size == 29);

  auto replay = service.handle(
      {"POST", "/unlock/" + token, body, {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(replay.status == 410);
  std::filesystem::remove_all(dir);
}

static void test_store_token_adds_new_secret_without_echoing_value() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_store_secret";
  std::filesystem::remove_all(dir);
  init_vault(dir, "yuki", "master pass");
  UnlockService service(dir, "yuki");
  auto token = service.create_store_token({"account", "new.example", "new-login", "store_secret"});

  auto form = service.handle({"GET", "/store/" + token, "", {}});
  assert(form.status == 200);
  assert(form.body.find("textarea") != std::string::npos);
  assert(form.body.find("name=\"value\"") != std::string::npos);

  std::string body =
      "login=yuki&password=master+pass&value=%7B%22secret%22%3A%22NEW-SECRET-HTTP%22%7D";
  auto response = service.handle(
      {"POST", "/store/" + token, body, {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(response.status == 200);
  assert(response.body.find("Stored") != std::string::npos);
  assert(response.body.find("NEW-SECRET-HTTP") == std::string::npos);

  ChunkVault vault(dir);
  assert(vault.get("account", "new.example", "new-login", "master pass") ==
         R"({"secret":"NEW-SECRET-HTTP"})");

  auto replay = service.handle(
      {"POST", "/store/" + token, body, {{"content-type", "application/x-www-form-urlencoded"}}});
  assert(replay.status == 410);
  std::filesystem::remove_all(dir);
}

static void test_store_file_token_encrypts_file_and_removes_source() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_store_file_secret";
  auto source = std::filesystem::temp_directory_path() / "alfie_ca_key_source.pem";
  std::filesystem::remove_all(dir);
  std::filesystem::remove(source);
  {
    std::ofstream out(source, std::ios::binary);
    out << "PRIVATE-CA-KEY-MATERIAL";
  }
  init_vault(dir, "yuki", "master pass");
  UnlockService service(dir, "yuki");
  auto token = service.create_store_file_token(
      {"secret-file", "alfie.local.ca", "alfie-local-ca-key.pem", "store_ca_key"}, source);

  auto form = service.handle({"GET", "/store-file/" + token, "", {}});
  assert(form.status == 200);
  assert(form.body.find("name=\"viewport\"") != std::string::npos);
  assert(form.body.find("inputmode=\"text\"") != std::string::npos);
  assert(form.body.find("min-height:100vh") != std::string::npos);
  assert(form.body.find("font-family") != std::string::npos);
  assert(form.body.find("PRIVATE-CA-KEY-MATERIAL") == std::string::npos);
  assert(form.body.find("No secret value will be shown") != std::string::npos);

  auto response =
      service.handle({"POST", "/store-file/" + token, "login=yuki&password=master+pass", {}});
  assert(response.status == 200);
  assert(response.body.find("Stored") != std::string::npos);
  assert(response.body.find("PRIVATE-CA-KEY-MATERIAL") == std::string::npos);
  assert(!std::filesystem::exists(source));

  ChunkVault vault(dir);
  assert(vault.get("secret-file", "alfie.local.ca", "alfie-local-ca-key.pem", "master pass") ==
         "PRIVATE-CA-KEY-MATERIAL");
  std::filesystem::remove_all(dir);
}

static void test_bad_login_does_not_consume_token() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_unlock_bad_login";
  prepare_vault(dir);
  UnlockService service(dir, "yuki");
  auto token =
      service.create_token({"account", "example.com", "yuki@example.com", "fill_password"});

  auto bad = service.handle({"POST", "/unlock/" + token, "login=wrong&password=master+pass", {}});
  assert(bad.status == 403);
  assert(!service.last_delivery().has_value());

  auto good = service.handle({"POST", "/unlock/" + token, "login=yuki&password=master+pass", {}});
  assert(good.status == 200);
  std::filesystem::remove_all(dir);
}

static void test_http_parse_and_render() {
  auto req = parse_http_request(
      "POST /unlock/abc HTTP/1.1\r\nHost: local\r\nContent-Length: 7\r\n\r\na=b+c+d");
  assert(req.method == "POST");
  assert(req.target == "/unlock/abc");
  assert(req.body == "a=b+c+d");
  auto text = http_response_text({201, "text/plain", "created"});
  assert(text.find("HTTP/1.1 201") == 0);
  assert(text.find("Content-Length: 7") != std::string::npos);
}

static void test_init_link_creates_vault_and_sets_credentials() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_init";
  std::filesystem::remove_all(dir);

  // No vault yet, and no login known to the service: the one-time token is the authorization.
  UnlockService service(dir, "");
  auto token = service.create_init_token({"init", "", "", "init_vault"});

  auto form = service.handle({"GET", "/init/" + token, "", {}});
  assert(form.status == 200);
  assert(form.body.find("name=\"confirm\"") != std::string::npos);

  // Mismatched confirmation must not create anything.
  auto mismatch = service.handle(
      {"POST", "/init/" + token, "login=yuki&password=Zorb7-Quilm&confirm=typo", {}});
  assert(mismatch.status == 400);
  assert(!vault_initialized(dir));

  auto created = service.handle(
      {"POST", "/init/" + token, "login=yuki&password=Zorb7-Quilm&confirm=Zorb7-Quilm", {}});
  assert(created.status == 201);
  assert(vault_initialized(dir));
  assert(vault_has_credentials(dir));
  assert(created.body.find("Zorb7-Quilm") == std::string::npos);

  // The init link is one-time, like every other link.
  auto replay = service.handle(
      {"POST", "/init/" + token, "login=yuki&password=other+pass&confirm=other+pass", {}});
  assert(replay.status == 410);
  assert(verify_credentials(dir, "yuki", "Zorb7-Quilm"));

  std::filesystem::remove_all(dir);
}

static void test_unlock_checks_credentials_stored_in_vault() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_vault_credentials";
  std::filesystem::remove_all(dir);
  init_vault(dir, "yuki", "master pass");
  {
    ChunkVault vault(dir);
    vault.put("account", "example.com", "yuki@example.com", "master pass",
              R"({"secret":"CRED-CHECK"})");
  }

  // The service was started with the wrong login hint; the vault's own verifier decides.
  UnlockService service(dir, "not-the-login");
  auto token =
      service.create_token({"account", "example.com", "yuki@example.com", "fill_password"});
  auto ok = service.handle({"POST", "/unlock/" + token, "login=yuki&password=master+pass", {}});
  assert(ok.status == 200);

  auto token2 =
      service.create_token({"account", "example.com", "yuki@example.com", "fill_password"});
  auto bad_login =
      service.handle({"POST", "/unlock/" + token2, "login=attacker&password=master+pass", {}});
  assert(bad_login.status == 403);

  auto bad_password =
      service.handle({"POST", "/unlock/" + token2, "login=yuki&password=wrong+pass", {}});
  assert(bad_password.status == 403);

  std::filesystem::remove_all(dir);
}

static void test_store_into_uninitialized_vault_is_refused() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_http_store_uninit";
  std::filesystem::remove_all(dir);
  UnlockService service(dir, "yuki");
  auto token = service.create_store_token({"account", "new.example", "new-login", "store_secret"});
  auto response = service.handle(
      {"POST", "/store/" + token, "login=yuki&password=master+pass&value=%7B%7D", {}});
  assert(response.status == 409);
  assert(!vault_initialized(dir));
  std::filesystem::remove_all(dir);
}

int main() {
  test_init_link_creates_vault_and_sets_credentials();
  test_unlock_checks_credentials_stored_in_vault();
  test_store_into_uninitialized_vault_is_refused();
  test_token_form_does_not_expose_secret();
  test_submit_unlocks_once_without_returning_secret();
  test_store_token_adds_new_secret_without_echoing_value();
  test_store_file_token_encrypts_file_and_removes_source();
  test_bad_login_does_not_consume_token();
  test_http_parse_and_render();
  std::cout << "HTTP unlock tests passed\n";
}
