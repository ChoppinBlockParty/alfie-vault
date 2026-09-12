#pragma once

#include <filesystem>
#include <string>

#include "vault.hpp"

namespace alfie {

// In-memory X.509 generation.
//
// Private keys produced here are never serialized to disk by this module: they exist as an
// EVP_PKEY inside the call and leave only as PEM bytes in a SecureBuffer, so the caller can put
// them straight into the vault. Certificates are public and are returned as plain strings.
struct GeneratedCertificate {
  std::string certificate_pem;
  SecureBuffer private_key_pem;
};

// Self-signed CA, suitable for installing as a trusted root on a phone or laptop.
GeneratedCertificate generate_ca_certificate(const std::string& common_name, int days = 3650,
                                             int rsa_bits = 4096);

// Leaf server certificate carrying an IP subjectAltName, signed by the given CA.
GeneratedCertificate issue_ip_certificate(const std::string& ip_address,
                                          const std::string& ca_certificate_pem,
                                          const SecureBuffer& ca_private_key_pem, int days = 825,
                                          int rsa_bits = 2048);

// Short-lived self-signed certificate for the first-time setup session only. It is never
// written to disk and is discarded when the process exits.
GeneratedCertificate generate_ephemeral_certificate(const std::string& ip_address, int days = 1,
                                                    int rsa_bits = 2048);

// Colon-separated uppercase SHA-256 of the DER certificate -- the same value browsers and
// `openssl x509 -fingerprint -sha256` show, so a human can compare them out of band.
std::string certificate_fingerprint_sha256(const std::string& certificate_pem);

// Writes a public file (0644) or a private one (0600, created with restrictive permissions
// rather than widened afterwards).
void write_public_file(const std::filesystem::path& path, const std::string& contents);
void write_private_file(const std::filesystem::path& path, const SecureBuffer& contents);

}  // namespace alfie
