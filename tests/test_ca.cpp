//===----------------------------------------------------------------------===//
/// \file
/// Exercise ca behavior and failure paths.
//===----------------------------------------------------------------------===//

#include "../src/ca.h"
#include <catch_amalgamated.hpp>
#include <filesystem>
#include <fstream>
#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

using namespace alfie;

/// Small keys throughout: these tests exercise certificate shape, not RSA
/// strength.
static constexpr int kTestBits = 2048;

struct X509Deleter {
  void operator()(X509 *cert) const { X509_free(cert); }
};
struct PkeyDeleter {
  void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
};
using CertPtr = std::unique_ptr<X509, X509Deleter>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

static CertPtr parse(const std::string &pem) {
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  CertPtr cert(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr));
  BIO_free(bio);
  REQUIRE(cert != nullptr);
  return cert;
}

static bool isCertificateAuthority(X509 *cert) {
  auto *bc = static_cast<BASIC_CONSTRAINTS *>(
      X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
  const bool ca = bc != nullptr && bc->ca;
  BASIC_CONSTRAINTS_free(bc);
  return ca;
}

static bool isSelfSigned(X509 *cert) {
  return X509_NAME_cmp(X509_get_issuer_name(cert),
                       X509_get_subject_name(cert)) == 0;
}

/// True when `cert` carries `ip` as an IP subject alternative name.
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

/// True when `cert` carries a signature made by `issuer`'s key.
static bool verifiesUnder(X509 *cert, X509 *issuer) {
  PkeyPtr issuerKey(X509_get_pubkey(issuer));
  return X509_verify(cert, issuerKey.get()) == 1;
}

static std::string readFile(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

struct TempDir {
  std::filesystem::path path;

  TempDir() {
    this->path = std::filesystem::temp_directory_path() / "alfie_ca_write_test";
    std::filesystem::remove_all(this->path);
  }

  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(this->path, ec);
  }

  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

TEST_CASE("The CA is self-signed and marked as a CA", "[ca][shape]") {
  const GeneratedCertificate ca =
      generateCaCertificate("Alfie Test CA", 30, kTestBits);
  const CertPtr cert = parse(ca.certificatePem);

  CHECK(isCertificateAuthority(cert.get()));
  CHECK(isSelfSigned(cert.get()));
  CHECK(verifiesUnder(cert.get(), cert.get()));
  // The key comes back as PEM inside a SecureBuffer, never as a plain string
  // on the heap.
  CHECK_THAT(ca.privateKeyPem.str(),
             Catch::Matchers::ContainsSubstring("PRIVATE KEY"));
}

TEST_CASE("An IP certificate is signed by the CA and carries the IP",
          "[ca][ip]") {
  const GeneratedCertificate ca =
      generateCaCertificate("Alfie Test CA", 30, kTestBits);
  const GeneratedCertificate server = issueIpCertificate(
      "10.1.2.3", ca.certificatePem, ca.privateKeyPem, 30, kTestBits);

  const CertPtr caCert = parse(ca.certificatePem);
  const CertPtr serverCert = parse(server.certificatePem);

  CHECK_FALSE(isCertificateAuthority(serverCert.get()));
  CHECK(hasIpSan(serverCert.get(), "10.1.2.3"));
  CHECK(verifiesUnder(serverCert.get(), caCert.get()));

  SECTION("and not by an unrelated CA") {
    const GeneratedCertificate other =
        generateCaCertificate("Other CA", 30, kTestBits);
    const CertPtr otherCert = parse(other.certificatePem);

    CHECK_FALSE(verifiesUnder(serverCert.get(), otherCert.get()));
  }
}

TEST_CASE("The setup certificate is self-signed and not a CA",
          "[ca][ephemeral]") {
  const GeneratedCertificate ephemeral =
      generateEphemeralCertificate("127.0.0.1", 1, kTestBits);
  const CertPtr cert = parse(ephemeral.certificatePem);

  CHECK_FALSE(isCertificateAuthority(cert.get()));
  CHECK(hasIpSan(cert.get(), "127.0.0.1"));
  CHECK(isSelfSigned(cert.get()));
}

TEST_CASE("The fingerprint matches the openssl rendering",
          "[ca][fingerprint]") {
  const GeneratedCertificate a = generateCaCertificate("A", 30, kTestBits);
  const GeneratedCertificate b = generateCaCertificate("B", 30, kTestBits);

  const std::string fingerprint =
      certificateFingerprintSha256(a.certificatePem);

  // 32 bytes as uppercase hex pairs joined by colons: the exact shape the
  // operator compares against the terminal, so it is asserted literally.
  CHECK_THAT(fingerprint,
             Catch::Matchers::Matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"));
  CHECK(fingerprint.size() == (32 * 3) - 1);
  CHECK(certificateFingerprintSha256(a.certificatePem) == fingerprint);
  CHECK(certificateFingerprintSha256(b.certificatePem) != fingerprint);
}

TEST_CASE_METHOD(TempDir, "Private files are unreadable to others",
                 "[ca][files]") {
  const GeneratedCertificate ca =
      generateCaCertificate("Alfie Test CA", 30, kTestBits);

  writePublicFile(this->path / "cert.pem", ca.certificatePem);
  writePrivateFile(this->path / "key.pem", ca.privateKeyPem);

  const std::filesystem::perms privatePerms =
      std::filesystem::status(this->path / "key.pem").permissions();
  CHECK((privatePerms & (std::filesystem::perms::group_all |
                         std::filesystem::perms::others_all)) ==
        std::filesystem::perms::none);
  CHECK(readFile(this->path / "cert.pem") == ca.certificatePem);
  CHECK(readFile(this->path / "key.pem") == ca.privateKeyPem.str());
}
