#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "../src/http_unlock.hpp"

using namespace alfie;

static void prepare_vault(const std::filesystem::path& dir) {
  std::filesystem::remove_all(dir);
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

int main() {
  test_token_form_does_not_expose_secret();
  test_submit_unlocks_once_without_returning_secret();
  test_store_token_adds_new_secret_without_echoing_value();
  test_store_file_token_encrypts_file_and_removes_source();
  test_bad_login_does_not_consume_token();
  test_http_parse_and_render();
  std::cout << "HTTP unlock tests passed\n";
}
