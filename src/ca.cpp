//===----------------------------------------------------------------------===//
/// \file
/// Generate X.509 certificates and keep private keys in secure memory.
//===----------------------------------------------------------------------===//

#include "ca.h"
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <memory>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <unistd.h>

using namespace alfie;

namespace {
struct X509Deleter {
  void operator()(X509 *P) const { X509_free(P); }
};
struct PkeyDeleter {
  void operator()(EVP_PKEY *P) const { EVP_PKEY_free(P); }
};
struct BioDeleter {
  void operator()(BIO *P) const { BIO_free(P); }
};
struct NameDeleter {
  void operator()(X509_NAME *P) const { X509_NAME_free(P); }
};
} // namespace

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

static PkeyPtr generateRsaKey(int Bits) {
  PkeyPtr Key(EVP_RSA_gen(static_cast<unsigned int>(Bits)));
  if (!Key)
    throw CryptoError("RSA key generation failed");
  return Key;
}

static void setRandomSerial(X509 *Cert) {
  unsigned char Bytes[16];
  if (RAND_bytes(Bytes, sizeof(Bytes)) != 1)
    throw CryptoError("RAND_bytes failed");
  Bytes[0] &= 0x7F; // keep the serial positive
  std::unique_ptr<BIGNUM, void (*)(BIGNUM *)> Bn(
      BN_bin2bn(Bytes, sizeof(Bytes), nullptr), [](BIGNUM *P) { BN_free(P); });
  if (!Bn)
    throw CryptoError("serial generation failed");
  if (BN_to_ASN1_INTEGER(Bn.get(), X509_get_serialNumber(Cert)) == nullptr)
    throw CryptoError("serial conversion failed");
}

static void setCommonName(X509_NAME *Name, const std::string &CommonName) {
  if (X509_NAME_add_entry_by_txt(
          Name, "CN", MBSTRING_ASC,
          reinterpret_cast<const unsigned char *>(CommonName.c_str()), -1, -1,
          0) != 1) {
    throw CryptoError("cannot set certificate common name");
  }
}

static void addExtension(X509 *Cert, X509 *Issuer, int Nid,
                         const std::string &Value) {
  X509V3_CTX Ctx;
  X509V3_set_ctx_nodb(&Ctx);
  X509V3_set_ctx(&Ctx, Issuer, Cert, nullptr, nullptr, 0);
  X509_EXTENSION *Ext = X509V3_EXT_conf_nid(nullptr, &Ctx, Nid, Value.c_str());
  if (Ext == nullptr)
    throw CryptoError("cannot build certificate extension");
  const int Rc = X509_add_ext(Cert, Ext, -1);
  X509_EXTENSION_free(Ext);
  if (Rc != 1)
    throw CryptoError("cannot add certificate extension");
}

static std::string pemFromCertificate(X509 *Cert) {
  BioPtr Bio(BIO_new(BIO_s_mem()));
  if (!Bio || PEM_write_bio_X509(Bio.get(), Cert) != 1)
    throw CryptoError("cannot encode certificate");
  char *Data = nullptr;
  const long Len = BIO_get_mem_data(Bio.get(), &Data);
  return std::string(Data, static_cast<size_t>(Len));
}

// The private key leaves OpenSSL only as bytes inside a SecureBuffer, and the
// BIO that held the PEM is cleansed before it is freed.
static SecureBuffer securePemFromKey(EVP_PKEY *Key) {
  BioPtr Bio(BIO_new(BIO_s_mem()));
  if (!Bio || PEM_write_bio_PrivateKey(Bio.get(), Key, nullptr, nullptr, 0,
                                       nullptr, nullptr) != 1)
    throw CryptoError("cannot encode private key");
  char *Data = nullptr;
  const long Len = BIO_get_mem_data(Bio.get(), &Data);
  SecureBuffer Out(std::vector<unsigned char>(Data, Data + Len));
  OPENSSL_cleanse(Data, static_cast<size_t>(Len));
  return Out;
}

static X509Ptr certificateFromPem(const std::string &Pem) {
  BioPtr Bio(BIO_new_mem_buf(Pem.data(), static_cast<int>(Pem.size())));
  if (!Bio)
    throw CryptoError("cannot read certificate");
  X509Ptr Cert(PEM_read_bio_X509(Bio.get(), nullptr, nullptr, nullptr));
  if (!Cert)
    throw CryptoError("cannot parse certificate");
  return Cert;
}

static PkeyPtr keyFromSecurePem(const SecureBuffer &Pem) {
  BioPtr Bio(BIO_new_mem_buf(Pem.data(), static_cast<int>(Pem.size())));
  if (!Bio)
    throw CryptoError("cannot read private key");
  PkeyPtr Key(PEM_read_bio_PrivateKey(Bio.get(), nullptr, nullptr, nullptr));
  if (!Key)
    throw CryptoError("cannot parse private key");
  return Key;
}

static X509Ptr newCertificate(EVP_PKEY *SubjectKey,
                              const std::string &CommonName, int Days) {
  X509Ptr Cert(X509_new());
  if (!Cert)
    throw CryptoError("X509_new failed");
  if (X509_set_version(Cert.get(), 2) != 1) // v3
    throw CryptoError("cannot set certificate version");
  setRandomSerial(Cert.get());
  if (X509_gmtime_adj(X509_getm_notBefore(Cert.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(Cert.get()), 60L * 60L * 24L * Days) ==
          nullptr) {
    throw CryptoError("cannot set certificate validity");
  }
  if (X509_set_pubkey(Cert.get(), SubjectKey) != 1)
    throw CryptoError("cannot set certificate public key");
  setCommonName(X509_get_subject_name(Cert.get()), CommonName);
  return Cert;
}

GeneratedCertificate alfie::generateCaCertificate(const std::string &CommonName,
                                                  int Days, int RsaBits) {
  PkeyPtr Key = generateRsaKey(RsaBits);
  X509Ptr Cert = newCertificate(Key.get(), CommonName, Days);

  // Self-signed: issuer is its own subject.
  if (X509_set_issuer_name(Cert.get(), X509_get_subject_name(Cert.get())) != 1)
    throw CryptoError("cannot set CA issuer");
  addExtension(Cert.get(), Cert.get(), NID_basic_constraints,
               "critical,CA:TRUE");
  addExtension(Cert.get(), Cert.get(), NID_key_usage,
               "critical,keyCertSign,cRLSign");
  addExtension(Cert.get(), Cert.get(), NID_subject_key_identifier, "hash");

  if (X509_sign(Cert.get(), Key.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot self-sign CA certificate");

  return GeneratedCertificate{pemFromCertificate(Cert.get()),
                              securePemFromKey(Key.get())};
}

GeneratedCertificate alfie::issueIpCertificate(
    const std::string &IpAddress, const std::string &CaCertificatePem,
    const SecureBuffer &CaPrivateKeyPem, int Days, int RsaBits) {
  X509Ptr CaCert = certificateFromPem(CaCertificatePem);
  PkeyPtr CaKey = keyFromSecurePem(CaPrivateKeyPem);

  PkeyPtr Key = generateRsaKey(RsaBits);
  X509Ptr Cert = newCertificate(Key.get(), IpAddress, Days);

  if (X509_set_issuer_name(Cert.get(), X509_get_subject_name(CaCert.get())) !=
      1)
    throw CryptoError("cannot set server certificate issuer");
  addExtension(Cert.get(), CaCert.get(), NID_basic_constraints,
               "critical,CA:FALSE");
  addExtension(Cert.get(), CaCert.get(), NID_key_usage,
               "critical,digitalSignature,keyEncipherment");
  addExtension(Cert.get(), CaCert.get(), NID_ext_key_usage, "serverAuth");
  addExtension(Cert.get(), CaCert.get(), NID_subject_alt_name,
               "IP:" + IpAddress);
  addExtension(Cert.get(), CaCert.get(), NID_subject_key_identifier, "hash");

  if (X509_sign(Cert.get(), CaKey.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot sign server certificate");

  return GeneratedCertificate{pemFromCertificate(Cert.get()),
                              securePemFromKey(Key.get())};
}

GeneratedCertificate
alfie::generateEphemeralCertificate(const std::string &IpAddress, int Days,
                                    int RsaBits) {
  PkeyPtr Key = generateRsaKey(RsaBits);
  X509Ptr Cert =
      newCertificate(Key.get(), "Alfie Vault first-time setup", Days);

  if (X509_set_issuer_name(Cert.get(), X509_get_subject_name(Cert.get())) != 1)
    throw CryptoError("cannot set issuer");
  addExtension(Cert.get(), Cert.get(), NID_basic_constraints,
               "critical,CA:FALSE");
  addExtension(Cert.get(), Cert.get(), NID_key_usage,
               "critical,digitalSignature,keyEncipherment");
  addExtension(Cert.get(), Cert.get(), NID_ext_key_usage, "serverAuth");
  addExtension(Cert.get(), Cert.get(), NID_subject_alt_name, "IP:" + IpAddress);

  if (X509_sign(Cert.get(), Key.get(), EVP_sha256()) == 0)
    throw CryptoError("cannot sign ephemeral certificate");

  return GeneratedCertificate{pemFromCertificate(Cert.get()),
                              securePemFromKey(Key.get())};
}

std::string
alfie::certificateFingerprintSha256(const std::string &CertificatePem) {
  X509Ptr Cert = certificateFromPem(CertificatePem);
  unsigned char Digest[EVP_MAX_MD_SIZE];
  unsigned int Len = 0;
  if (X509_digest(Cert.get(), EVP_sha256(), Digest, &Len) != 1)
    throw CryptoError("cannot compute certificate fingerprint");

  std::ostringstream Out;
  for (unsigned int I = 0; I < Len; ++I) {
    if (I > 0)
      Out << ':';
    Out << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(Digest[I]);
  }
  return Out.str();
}

void alfie::writePublicFile(const std::filesystem::path &Path,
                            const std::string &Contents) {
  std::filesystem::create_directories(Path.parent_path());
  std::ofstream Out(Path, std::ios::binary | std::ios::trunc);
  if (!Out)
    throw CryptoError("cannot write " + Path.string());
  Out.write(Contents.data(), static_cast<std::streamsize>(Contents.size()));
  Out.flush();
  if (!Out)
    throw CryptoError("cannot write " + Path.string());
}

void alfie::writePrivateFile(const std::filesystem::path &Path,
                             const SecureBuffer &Contents) {
  std::filesystem::create_directories(Path.parent_path());
  // Created 0600 from the start: never write key material and widen permissions
  // afterwards.
  const int Fd =
      ::open(Path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (Fd < 0)
    throw CryptoError("cannot create " + Path.string());
  const unsigned char *Data = Contents.data();
  size_t Remaining = Contents.size();
  while (Remaining > 0) {
    const ssize_t Written = ::write(Fd, Data, Remaining);
    if (Written <= 0) {
      ::close(Fd);
      throw CryptoError("cannot write " + Path.string());
    }
    Data += Written;
    Remaining -= static_cast<size_t>(Written);
  }
  ::fsync(Fd);
  ::close(Fd);
}
