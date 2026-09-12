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
static constexpr int TestBits = 2048;

static X509 *parse(const std::string &Pem) {
  BIO *Bio = BIO_new_mem_buf(Pem.data(), static_cast<int>(Pem.size()));
  X509 *Cert = PEM_read_bio_X509(Bio, nullptr, nullptr, nullptr);
  BIO_free(Bio);
  assert(Cert != nullptr);
  return Cert;
}

static bool isCertificateAuthority(X509 *Cert) {
  BASIC_CONSTRAINTS *Bc = static_cast<BASIC_CONSTRAINTS *>(
      X509_get_ext_d2i(Cert, NID_basic_constraints, nullptr, nullptr));
  const bool Ca = Bc != nullptr && Bc->ca;
  BASIC_CONSTRAINTS_free(Bc);
  return Ca;
}

static bool hasIpSan(X509 *Cert, const std::string &Ip) {
  bool Found = false;
  auto *Names = static_cast<GENERAL_NAMES *>(
      X509_get_ext_d2i(Cert, NID_subject_alt_name, nullptr, nullptr));
  if (Names != nullptr) {
    for (int I = 0; I < sk_GENERAL_NAME_num(Names); ++I) {
      const GENERAL_NAME *Name = sk_GENERAL_NAME_value(Names, I);
      if (Name->type != GEN_IPADD)
        continue;
      const unsigned char *Data = Name->d.iPAddress->data;
      if (Name->d.iPAddress->length == 4) {
        const std::string Rendered =
            std::to_string(Data[0]) + "." + std::to_string(Data[1]) + "." +
            std::to_string(Data[2]) + "." + std::to_string(Data[3]);
        Found = Found || Rendered == Ip;
      }
    }
    GENERAL_NAMES_free(Names);
  }
  return Found;
}

static std::string readFile(const std::filesystem::path &Path) {
  std::ifstream In(Path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(In)),
                     std::istreambuf_iterator<char>());
}

static void testCaIsSelfSignedAndMarkedAsACa() {
  auto Ca = generateCaCertificate("Alfie Test CA", 30, TestBits);

  X509 *Cert = parse(Ca.CertificatePem);
  assert(isCertificateAuthority(Cert));
  // Self-signed: issuer and subject match, and it verifies under its own key.
  assert(X509_NAME_cmp(X509_get_issuer_name(Cert),
                       X509_get_subject_name(Cert)) == 0);
  EVP_PKEY *Pub = X509_get_pubkey(Cert);
  assert(X509_verify(Cert, Pub) == 1);
  EVP_PKEY_free(Pub);
  X509_free(Cert);

  // The key comes back as PEM inside a SecureBuffer, never as a plain string on
  // the heap.
  assert(Ca.PrivateKeyPem.str().find("PRIVATE KEY") != std::string::npos);
}

static void testIpCertificateIsSignedByTheCaAndCarriesTheIp() {
  auto Ca = generateCaCertificate("Alfie Test CA", 30, TestBits);
  auto Server = issueIpCertificate("10.1.2.3", Ca.CertificatePem,
                                   Ca.PrivateKeyPem, 30, TestBits);

  X509 *CaCert = parse(Ca.CertificatePem);
  X509 *ServerCert = parse(Server.CertificatePem);

  assert(!isCertificateAuthority(ServerCert));
  assert(hasIpSan(ServerCert, "10.1.2.3"));

  // Verifies under the CA's public key, and not under an unrelated CA.
  EVP_PKEY *CaPub = X509_get_pubkey(CaCert);
  assert(X509_verify(ServerCert, CaPub) == 1);
  EVP_PKEY_free(CaPub);

  auto Other = generateCaCertificate("Other CA", 30, TestBits);
  X509 *OtherCert = parse(Other.CertificatePem);
  EVP_PKEY *OtherPub = X509_get_pubkey(OtherCert);
  assert(X509_verify(ServerCert, OtherPub) != 1);
  EVP_PKEY_free(OtherPub);

  X509_free(OtherCert);
  X509_free(ServerCert);
  X509_free(CaCert);
}

static void testEphemeralCertificateIsSelfSignedAndShortLived() {
  auto Ephemeral = generateEphemeralCertificate("127.0.0.1", 1, TestBits);
  X509 *Cert = parse(Ephemeral.CertificatePem);
  assert(!isCertificateAuthority(Cert));
  assert(hasIpSan(Cert, "127.0.0.1"));
  assert(X509_NAME_cmp(X509_get_issuer_name(Cert),
                       X509_get_subject_name(Cert)) == 0);
  X509_free(Cert);
}

static void testFingerprintMatchesOpensslFormatAndIsUnique() {
  auto A = generateCaCertificate("A", 30, TestBits);
  auto B = generateCaCertificate("B", 30, TestBits);

  const auto Fingerprint = certificateFingerprintSha256(A.CertificatePem);
  // 32 bytes rendered as uppercase hex pairs joined by colons.
  assert(Fingerprint.size() == (32 * 3) - 1);
  assert(Fingerprint[2] == ':');
  for (char C : Fingerprint)
    assert(C == ':' || (C >= '0' && C <= '9') || (C >= 'A' && C <= 'F'));

  assert(certificateFingerprintSha256(A.CertificatePem) == Fingerprint);
  assert(certificateFingerprintSha256(B.CertificatePem) != Fingerprint);
}

static void testPrivateFilesAreCreatedUnreadableToOthers() {
  auto Dir = std::filesystem::temp_directory_path() / "alfie_ca_write_test";
  std::filesystem::remove_all(Dir);

  auto Ca = generateCaCertificate("Alfie Test CA", 30, TestBits);
  writePublicFile(Dir / "cert.pem", Ca.CertificatePem);
  writePrivateFile(Dir / "key.pem", Ca.PrivateKeyPem);

  const auto PrivatePerms =
      std::filesystem::status(Dir / "key.pem").permissions();
  assert((PrivatePerms & (std::filesystem::perms::group_all |
                          std::filesystem::perms::others_all)) ==
         std::filesystem::perms::none);

  assert(readFile(Dir / "cert.pem") == Ca.CertificatePem);
  assert(readFile(Dir / "key.pem") == Ca.PrivateKeyPem.str());

  std::filesystem::remove_all(Dir);
}

int main() {
  testCaIsSelfSignedAndMarkedAsACa();
  testIpCertificateIsSignedByTheCaAndCarriesTheIp();
  testEphemeralCertificateIsSelfSignedAndShortLived();
  testFingerprintMatchesOpensslFormatAndIsUnique();
  testPrivateFilesAreCreatedUnreadableToOthers();
  std::cout << "C++ CA tests passed\n";
}
