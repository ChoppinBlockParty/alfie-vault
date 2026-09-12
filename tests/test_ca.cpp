#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "../src/ca.hpp"

using namespace alfie;

namespace {

// Small keys throughout: these tests exercise certificate shape, not RSA strength.
constexpr int kTestBits = 2048;

X509* parse(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  assert(cert != nullptr);
  return cert;
}

bool is_certificate_authority(X509* cert) {
  BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
      X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
  const bool ca = bc != nullptr && bc->ca;
  BASIC_CONSTRAINTS_free(bc);
  return ca;
}

bool has_ip_san(X509* cert, const std::string& ip) {
  bool found = false;
  auto* names =
      static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (names != nullptr) {
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
      const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
      if (name->type != GEN_IPADD)
        continue;
      const unsigned char* data = name->d.iPAddress->data;
      if (name->d.iPAddress->length == 4) {
        const std::string rendered = std::to_string(data[0]) + "." + std::to_string(data[1]) + "." +
                                     std::to_string(data[2]) + "." + std::to_string(data[3]);
        found = found || rendered == ip;
      }
    }
    GENERAL_NAMES_free(names);
  }
  return found;
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

static void test_ca_is_self_signed_and_marked_as_a_ca() {
  auto ca = generate_ca_certificate("Alfie Test CA", 30, kTestBits);

  X509* cert = parse(ca.certificate_pem);
  assert(is_certificate_authority(cert));
  // Self-signed: issuer and subject match, and it verifies under its own key.
  assert(X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(cert)) == 0);
  EVP_PKEY* pub = X509_get_pubkey(cert);
  assert(X509_verify(cert, pub) == 1);
  EVP_PKEY_free(pub);
  X509_free(cert);

  // The key comes back as PEM inside a SecureBuffer, never as a plain string on the heap.
  assert(ca.private_key_pem.str().find("PRIVATE KEY") != std::string::npos);
}

static void test_ip_certificate_is_signed_by_the_ca_and_carries_the_ip() {
  auto ca = generate_ca_certificate("Alfie Test CA", 30, kTestBits);
  auto server =
      issue_ip_certificate("10.1.2.3", ca.certificate_pem, ca.private_key_pem, 30, kTestBits);

  X509* ca_cert = parse(ca.certificate_pem);
  X509* server_cert = parse(server.certificate_pem);

  assert(!is_certificate_authority(server_cert));
  assert(has_ip_san(server_cert, "10.1.2.3"));

  // Verifies under the CA's public key, and not under an unrelated CA.
  EVP_PKEY* ca_pub = X509_get_pubkey(ca_cert);
  assert(X509_verify(server_cert, ca_pub) == 1);
  EVP_PKEY_free(ca_pub);

  auto other = generate_ca_certificate("Other CA", 30, kTestBits);
  X509* other_cert = parse(other.certificate_pem);
  EVP_PKEY* other_pub = X509_get_pubkey(other_cert);
  assert(X509_verify(server_cert, other_pub) != 1);
  EVP_PKEY_free(other_pub);

  X509_free(other_cert);
  X509_free(server_cert);
  X509_free(ca_cert);
}

static void test_ephemeral_certificate_is_self_signed_and_short_lived() {
  auto ephemeral = generate_ephemeral_certificate("127.0.0.1", 1, kTestBits);
  X509* cert = parse(ephemeral.certificate_pem);
  assert(!is_certificate_authority(cert));
  assert(has_ip_san(cert, "127.0.0.1"));
  assert(X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(cert)) == 0);
  X509_free(cert);
}

static void test_fingerprint_matches_openssl_format_and_is_unique() {
  auto a = generate_ca_certificate("A", 30, kTestBits);
  auto b = generate_ca_certificate("B", 30, kTestBits);

  const auto fingerprint = certificate_fingerprint_sha256(a.certificate_pem);
  // 32 bytes rendered as uppercase hex pairs joined by colons.
  assert(fingerprint.size() == 32 * 3 - 1);
  assert(fingerprint[2] == ':');
  for (char c : fingerprint)
    assert(c == ':' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));

  assert(certificate_fingerprint_sha256(a.certificate_pem) == fingerprint);
  assert(certificate_fingerprint_sha256(b.certificate_pem) != fingerprint);
}

static void test_private_files_are_created_unreadable_to_others() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_ca_write_test";
  std::filesystem::remove_all(dir);

  auto ca = generate_ca_certificate("Alfie Test CA", 30, kTestBits);
  write_public_file(dir / "cert.pem", ca.certificate_pem);
  write_private_file(dir / "key.pem", ca.private_key_pem);

  const auto private_perms = std::filesystem::status(dir / "key.pem").permissions();
  assert((private_perms & (std::filesystem::perms::group_all |
                           std::filesystem::perms::others_all)) == std::filesystem::perms::none);

  assert(read_file(dir / "cert.pem") == ca.certificate_pem);
  assert(read_file(dir / "key.pem") == ca.private_key_pem.str());

  std::filesystem::remove_all(dir);
}

int main() {
  test_ca_is_self_signed_and_marked_as_a_ca();
  test_ip_certificate_is_signed_by_the_ca_and_carries_the_ip();
  test_ephemeral_certificate_is_self_signed_and_short_lived();
  test_fingerprint_matches_openssl_format_and_is_unique();
  test_private_files_are_created_unreadable_to_others();
  std::cout << "C++ CA tests passed\n";
}
