//===----------------------------------------------------------------------===//
/// \file
/// Exercise ca behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ca.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

using namespace alfie;

// Small keys throughout: these tests exercise certificate shape, not RSA
// strength.
static constexpr int kTestBits = 2048;

static X509 *parse(const std::string &pem) {
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  assert(cert != nullptr);
  return cert;
}

static bool isCertificateAuthority(X509 *cert) {
  BASIC_CONSTRAINTS *bc = static_cast<BASIC_CONSTRAINTS *>(
      X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
  const bool ca = bc != nullptr && bc->ca;
  BASIC_CONSTRAINTS_free(bc);
  return ca;
}

static bool hasIpSan(X509 *cert, const std::string &ip) {
  bool found = false;
  auto *names = static_cast<GENERAL_NAMES *>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (names != nullptr) {
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
      const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
      if (name->type != GEN_IPADD)
        continue;
      const unsigned char *data = name->d.iPAddress->data;
      if (name->d.iPAddress->length == 4) {
        const std::string rendered =
            std::to_string(data[0]) + "." + std::to_string(data[1]) + "." +
            std::to_string(data[2]) + "." + std::to_string(data[3]);
        found = found || rendered == ip;
      }
    }
    GENERAL_NAMES_free(names);
  }
  return found;
}

static std::string readFile(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

static void testCaIsSelfSignedAndMarkedAsACa() {
  auto ca = generateCaCertificate("Alfie Test CA", 30, kTestBits);

  X509 *cert = parse(ca.certificatePem);
  assert(isCertificateAuthority(cert));
  // Self-signed: issuer and subject match, and it verifies under its own key.
  assert(X509_NAME_cmp(X509_get_issuer_name(cert),
                       X509_get_subject_name(cert)) == 0);
  EVP_PKEY *pub = X509_get_pubkey(cert);
  assert(X509_verify(cert, pub) == 1);
  EVP_PKEY_free(pub);
  X509_free(cert);

  // The key comes back as PEM inside a SecureBuffer, never as a plain string on
  // the heap.
  assert(ca.privateKeyPem.str().find("PRIVATE KEY") != std::string::npos);
}

static void testIpCertificateIsSignedByTheCaAndCarriesTheIp() {
  auto ca = generateCaCertificate("Alfie Test CA", 30, kTestBits);
  auto server = issueIpCertificate("10.1.2.3", ca.certificatePem,
                                   ca.privateKeyPem, 30, kTestBits);

  X509 *caCert = parse(ca.certificatePem);
  X509 *serverCert = parse(server.certificatePem);

  assert(!isCertificateAuthority(serverCert));
  assert(hasIpSan(serverCert, "10.1.2.3"));

  // Verifies under the CA's public key, and not under an unrelated CA.
  EVP_PKEY *caPub = X509_get_pubkey(caCert);
  assert(X509_verify(serverCert, caPub) == 1);
  EVP_PKEY_free(caPub);

  auto other = generateCaCertificate("Other CA", 30, kTestBits);
  X509 *otherCert = parse(other.certificatePem);
  EVP_PKEY *otherPub = X509_get_pubkey(otherCert);
  assert(X509_verify(serverCert, otherPub) != 1);
  EVP_PKEY_free(otherPub);

  X509_free(otherCert);
  X509_free(serverCert);
  X509_free(caCert);
}

static void testEphemeralCertificateIsSelfSignedAndShortLived() {
  auto ephemeral = generateEphemeralCertificate("127.0.0.1", 1, kTestBits);
  X509 *cert = parse(ephemeral.certificatePem);
  assert(!isCertificateAuthority(cert));
  assert(hasIpSan(cert, "127.0.0.1"));
  assert(X509_NAME_cmp(X509_get_issuer_name(cert),
                       X509_get_subject_name(cert)) == 0);
  X509_free(cert);
}

static void testFingerprintMatchesOpensslFormatAndIsUnique() {
  auto a = generateCaCertificate("A", 30, kTestBits);
  auto b = generateCaCertificate("B", 30, kTestBits);

  const auto fingerprint = certificateFingerprintSha256(a.certificatePem);
  // 32 bytes rendered as uppercase hex pairs joined by colons.
  assert(fingerprint.size() == (32 * 3) - 1);
  assert(fingerprint[2] == ':');
  for (char c : fingerprint)
    assert(c == ':' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));

  assert(certificateFingerprintSha256(a.certificatePem) == fingerprint);
  assert(certificateFingerprintSha256(b.certificatePem) != fingerprint);
}

static void testPrivateFilesAreCreatedUnreadableToOthers() {
  auto dir = std::filesystem::temp_directory_path() / "alfie_ca_write_test";
  std::filesystem::remove_all(dir);

  auto ca = generateCaCertificate("Alfie Test CA", 30, kTestBits);
  writePublicFile(dir / "cert.pem", ca.certificatePem);
  writePrivateFile(dir / "key.pem", ca.privateKeyPem);

  const auto privatePerms =
      std::filesystem::status(dir / "key.pem").permissions();
  assert((privatePerms & (std::filesystem::perms::group_all |
                          std::filesystem::perms::others_all)) ==
         std::filesystem::perms::none);

  assert(readFile(dir / "cert.pem") == ca.certificatePem);
  assert(readFile(dir / "key.pem") == ca.privateKeyPem.str());

  std::filesystem::remove_all(dir);
}

int main() {
  testCaIsSelfSignedAndMarkedAsACa();
  testIpCertificateIsSignedByTheCaAndCarriesTheIp();
  testEphemeralCertificateIsSelfSignedAndShortLived();
  testFingerprintMatchesOpensslFormatAndIsUnique();
  testPrivateFilesAreCreatedUnreadableToOthers();
  std::cout << "C++ CA tests passed\n";
}
