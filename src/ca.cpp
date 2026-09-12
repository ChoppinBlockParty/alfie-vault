#include "ca.hpp"

#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>

namespace alfie {
namespace {

struct X509Deleter {
  void operator()(X509* p) const {
    X509_free(p);
  }
};
struct PkeyDeleter {
  void operator()(EVP_PKEY* p) const {
    EVP_PKEY_free(p);
  }
};
struct BioDeleter {
  void operator()(BIO* p) const {
    BIO_free(p);
  }
};
struct NameDeleter {
  void operator()(X509_NAME* p) const {
    X509_NAME_free(p);
  }
};

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

PkeyPtr generate_rsa_key(int bits) {
  PkeyPtr key(EVP_RSA_gen(static_cast<unsigned int>(bits)));
  if (!key)
    throw CryptoError("RSA key generation failed");
  return key;
}

void set_random_serial(X509* cert) {
  unsigned char bytes[16];
  if (RAND_bytes(bytes, sizeof(bytes)) != 1)
    throw CryptoError("RAND_bytes failed");
  bytes[0] &= 0x7F;  // keep the serial positive
  std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bn(BN_bin2bn(bytes, sizeof(bytes), nullptr),
                                                [](BIGNUM* p) { BN_free(p); });
  if (!bn)
    throw CryptoError("serial generation failed");
  if (BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert)) == nullptr)
    throw CryptoError("serial conversion failed");
}

void set_common_name(X509_NAME* name, const std::string& common_name) {
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(common_name.c_str()), -1,
                                 -1, 0) != 1) {
    throw CryptoError("cannot set certificate common name");
  }
}

void add_extension(X509* cert, X509* issuer, int nid, const std::string& value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
  if (ext == nullptr)
    throw CryptoError("cannot build certificate extension");
  const int rc = X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
  if (rc != 1)
    throw CryptoError("cannot add certificate extension");
}

std::string pem_from_certificate(X509* cert) {
  BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1)
    throw CryptoError("cannot encode certificate");
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio.get(), &data);
  return std::string(data, static_cast<size_t>(len));
}

// The private key leaves OpenSSL only as bytes inside a SecureBuffer, and the BIO that held the
// PEM is cleansed before it is freed.
SecureBuffer secure_pem_from_key(EVP_PKEY* key) {
  BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    throw CryptoError("cannot encode private key");
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio.get(), &data);
  SecureBuffer out(std::vector<unsigned char>(data, data + len));
  OPENSSL_cleanse(data, static_cast<size_t>(len));
  return out;
}

X509Ptr certificate_from_pem(const std::string& pem) {
  BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio)
    throw CryptoError("cannot read certificate");
  X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!cert)
    throw CryptoError("cannot parse certificate");
  return cert;
}

PkeyPtr key_from_secure_pem(const SecureBuffer& pem) {
  BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio)
    throw CryptoError("cannot read private key");
  PkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!key)
    throw CryptoError("cannot parse private key");
  return key;
}

X509Ptr new_certificate(EVP_PKEY* subject_key, const std::string& common_name, int days) {
  X509Ptr cert(X509_new());
  if (!cert)
    throw CryptoError("X509_new failed");
  if (X509_set_version(cert.get(), 2) != 1)  // v3
    throw CryptoError("cannot set certificate version");
  set_random_serial(cert.get());
  if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60L * 24L * days) == nullptr) {
    throw CryptoError("cannot set certificate validity");
  }
  if (X509_set_pubkey(cert.get(), subject_key) != 1)
    throw CryptoError("cannot set certificate public key");
  set_common_name(X509_get_subject_name(cert.get()), common_name);
  return cert;
}

}  // namespace

GeneratedCertificate generate_ca_certificate(const std::string& common_name, int days,
                                             int rsa_bits) {
  PkeyPtr key = generate_rsa_key(rsa_bits);
  X509Ptr cert = new_certificate(key.get(), common_name, days);

  // Self-signed: issuer is its own subject.
  if (X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get())) != 1)
    throw CryptoError("cannot set CA issuer");
  add_extension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE");
  add_extension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(cert.get(), cert.get(), NID_subject_key_identifier, "hash");

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot self-sign CA certificate");

  return GeneratedCertificate{pem_from_certificate(cert.get()), secure_pem_from_key(key.get())};
}

GeneratedCertificate issue_ip_certificate(const std::string& ip_address,
                                          const std::string& ca_certificate_pem,
                                          const SecureBuffer& ca_private_key_pem, int days,
                                          int rsa_bits) {
  X509Ptr ca_cert = certificate_from_pem(ca_certificate_pem);
  PkeyPtr ca_key = key_from_secure_pem(ca_private_key_pem);

  PkeyPtr key = generate_rsa_key(rsa_bits);
  X509Ptr cert = new_certificate(key.get(), ip_address, days);

  if (X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert.get())) != 1)
    throw CryptoError("cannot set server certificate issuer");
  add_extension(cert.get(), ca_cert.get(), NID_basic_constraints, "critical,CA:FALSE");
  add_extension(cert.get(), ca_cert.get(), NID_key_usage,
                "critical,digitalSignature,keyEncipherment");
  add_extension(cert.get(), ca_cert.get(), NID_ext_key_usage, "serverAuth");
  add_extension(cert.get(), ca_cert.get(), NID_subject_alt_name, "IP:" + ip_address);
  add_extension(cert.get(), ca_cert.get(), NID_subject_key_identifier, "hash");

  if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot sign server certificate");

  return GeneratedCertificate{pem_from_certificate(cert.get()), secure_pem_from_key(key.get())};
}

GeneratedCertificate generate_ephemeral_certificate(const std::string& ip_address, int days,
                                                    int rsa_bits) {
  PkeyPtr key = generate_rsa_key(rsa_bits);
  X509Ptr cert = new_certificate(key.get(), "Alfie Vault first-time setup", days);

  if (X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get())) != 1)
    throw CryptoError("cannot set issuer");
  add_extension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:FALSE");
  add_extension(cert.get(), cert.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment");
  add_extension(cert.get(), cert.get(), NID_ext_key_usage, "serverAuth");
  add_extension(cert.get(), cert.get(), NID_subject_alt_name, "IP:" + ip_address);

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot sign ephemeral certificate");

  return GeneratedCertificate{pem_from_certificate(cert.get()), secure_pem_from_key(key.get())};
}

std::string certificate_fingerprint_sha256(const std::string& certificate_pem) {
  X509Ptr cert = certificate_from_pem(certificate_pem);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (X509_digest(cert.get(), EVP_sha256(), digest, &len) != 1)
    throw CryptoError("cannot compute certificate fingerprint");

  std::ostringstream out;
  for (unsigned int i = 0; i < len; ++i) {
    if (i > 0)
      out << ':';
    out << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(digest[i]);
  }
  return out.str();
}

void write_public_file(const std::filesystem::path& path, const std::string& contents) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out)
    throw CryptoError("cannot write " + path.string());
  out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  out.flush();
  if (!out)
    throw CryptoError("cannot write " + path.string());
}

void write_private_file(const std::filesystem::path& path, const SecureBuffer& contents) {
  std::filesystem::create_directories(path.parent_path());
  // Created 0600 from the start: never write key material and widen permissions afterwards.
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    throw CryptoError("cannot create " + path.string());
  const unsigned char* data = contents.data();
  size_t remaining = contents.size();
  while (remaining > 0) {
    const ssize_t written = ::write(fd, data, remaining);
    if (written <= 0) {
      ::close(fd);
      throw CryptoError("cannot write " + path.string());
    }
    data += written;
    remaining -= static_cast<size_t>(written);
  }
  ::fsync(fd);
  ::close(fd);
}

}  // namespace alfie
