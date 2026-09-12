//===----------------------------------------------------------------------===//
/// \file
/// Generate X.509 certificates and keep private keys in secure memory.
//===----------------------------------------------------------------------===//

#ifndef CA_H
#define CA_H

#include "vault.h"
#include <filesystem>
#include <string>

namespace alfie {

/// In-memory X.509 generation.
///
/// Private keys produced here are never serialized to disk by this module: they
/// exist as an EVP_PKEY inside the call and leave only as PEM bytes in a
/// SecureBuffer, so the caller can put them straight into the vault.
/// Certificates are public and are returned as plain strings.
struct GeneratedCertificate {
  std::string certificatePem;
  SecureBuffer privateKeyPem;
};

/// Self-signed CA, suitable for installing as a trusted root on a phone or
/// laptop.
GeneratedCertificate generateCaCertificate(const std::string &commonName,
                                           int days = 3650, int rsaBits = 4096);

/// Leaf server certificate carrying an IP subjectAltName, signed by the given
/// CA.
GeneratedCertificate issueIpCertificate(const std::string &ipAddress,
                                        const std::string &caCertificatePem,
                                        const SecureBuffer &caPrivateKeyPem,
                                        int days = 825, int rsaBits = 2048);

/// Short-lived self-signed certificate for the first-time setup session only.
/// It is never written to disk and is discarded when the process exits.
GeneratedCertificate generateEphemeralCertificate(const std::string &ipAddress,
                                                  int days = 1,
                                                  int rsaBits = 2048);

/// Colon-separated uppercase SHA-256 of the DER certificate -- the same value
/// browsers and `openssl x509 -fingerprint -sha256` show, so a human can
/// compare them out of band.
std::string certificateFingerprintSha256(const std::string &certificatePem);

/// Writes a public file (0644) or a private one (0600, created with restrictive
/// permissions rather than widened afterwards).
void writePublicFile(const std::filesystem::path &path,
                     const std::string &contents);
void writePrivateFile(const std::filesystem::path &path,
                      const SecureBuffer &contents);

} // namespace alfie

#endif // CA_H
