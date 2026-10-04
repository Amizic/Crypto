// Crypto - src/Rsa4096.cpp
// RSA-4096: OAEP-SHA256 encryption and PSS-SHA256 signatures.

#include "Rsa4096.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "OpensslRaii.hpp"

namespace Crypto {
namespace {

/// Shared OAEP configuration for encryption and decryption: OAEP padding
/// with SHA-256 as both the OAEP digest and the MGF1 digest.
int configureOaep(EVP_PKEY_CTX* keyContext) noexcept {
    if (EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(keyContext, EVP_sha256()) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(keyContext, EVP_sha256()) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    return Rsa4096::kOk;
}

/// Shared PSS configuration for signing and verification: PSS padding with
/// SHA-256 and a salt as long as the digest.
int configurePss(EVP_PKEY_CTX* keyContext) noexcept {
    if (EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_signature_md(keyContext, EVP_sha256()) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(keyContext, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    return Rsa4096::kOk;
}

/// Read the current contents of a memory BIO into out (as text).
int bioMemoryToString(BIO* bio, std::string& out) noexcept {
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    if (length <= 0 || data == nullptr) {
        return Rsa4096::kErrOpenSsl;
    }
    out.assign(data, static_cast<std::size_t>(length));
    return Rsa4096::kOk;
}

/// Encode key as DER into out.
int exportDer(EVP_PKEY* key, bool privateKey, std::vector<uint8_t>& out) noexcept {
    const int length = privateKey ? i2d_PrivateKey(key, nullptr)
                                  : i2d_PUBKEY(key, nullptr);
    if (length <= 0) {
        return Rsa4096::kErrOpenSsl;
    }
    out.resize(static_cast<std::size_t>(length));
    unsigned char* cursor = out.data();
    const int written = privateKey ? i2d_PrivateKey(key, &cursor)
                                   : i2d_PUBKEY(key, &cursor);
    if (written != length) {
        out.clear();
        return Rsa4096::kErrOpenSsl;
    }
    return Rsa4096::kOk;
}

} // namespace

const char* Rsa4096::algorithmName() const noexcept {
    return "RSA-4096 (OAEP-SHA256 / PSS-SHA256)";
}

int Rsa4096::generateKeyPair(EVP_PKEY** outputKey) noexcept {
    ERR_clear_error();
    if (outputKey == nullptr) {
        return kErrInvalidArgument;
    }
    *outputKey = nullptr;

    EvpPkeyCtxPtr keyContext = makePkeyCtxFromId(EVP_PKEY_RSA);
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_keygen_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), kBits) <= 0) {
        return kErrOpenSsl;
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(keyContext.get(), &rawKey) <= 0) {
        return kErrOpenSsl;
    }

    // Ownership is transferred to the caller.
    *outputKey = rawKey;
    return kOk;
}

int Rsa4096::encrypt(EVP_PKEY* publicKey,
                     const std::vector<uint8_t>& plaintext,
                     std::vector<uint8_t>& ciphertext) noexcept {
    ERR_clear_error();
    ciphertext.clear();

    if (publicKey == nullptr) {
        return kErrInvalidArgument;
    }
    if (plaintext.empty()) {
        return kErrInvalidArgument;
    }
    if (plaintext.size() > static_cast<std::size_t>(INT_MAX)) {
        return kErrInvalidArgument;
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(publicKey);
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_encrypt_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }
    const int configurationResult = configureOaep(keyContext.get());
    if (configurationResult != kOk) {
        return configurationResult;
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_encrypt(keyContext.get(), nullptr, &outputLength,
                         plaintext.data(), plaintext.size()) <= 0) {
        return kErrOpenSsl;
    }
    ciphertext.resize(outputLength);
    if (EVP_PKEY_encrypt(keyContext.get(), ciphertext.data(), &outputLength,
                         plaintext.data(), plaintext.size()) <= 0) {
        return kErrOpenSsl;
    }
    ciphertext.resize(outputLength);
    return kOk;
}

int Rsa4096::decrypt(EVP_PKEY* privateKey,
                     const std::vector<uint8_t>& ciphertext,
                     std::vector<uint8_t>& plaintext) noexcept {
    ERR_clear_error();
    plaintext.clear();

    if (privateKey == nullptr) {
        return kErrInvalidArgument;
    }
    if (ciphertext.empty()) {
        return kErrInvalidArgument;
    }
    if (ciphertext.size() > static_cast<std::size_t>(INT_MAX)) {
        return kErrInvalidArgument;
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(privateKey);
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_decrypt_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }
    const int configurationResult = configureOaep(keyContext.get());
    if (configurationResult != kOk) {
        return configurationResult;
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_decrypt(keyContext.get(), nullptr, &outputLength,
                         ciphertext.data(), ciphertext.size()) <= 0) {
        return kErrOpenSsl;
    }
    plaintext.resize(outputLength);
    if (EVP_PKEY_decrypt(keyContext.get(), plaintext.data(), &outputLength,
                         ciphertext.data(), ciphertext.size()) <= 0) {
        return kErrOpenSsl;
    }
    plaintext.resize(outputLength);
    return kOk;
}

int Rsa4096::sign(EVP_PKEY* privateKey,
                  const std::vector<uint8_t>& digest,
                  std::vector<uint8_t>& signature) noexcept {
    ERR_clear_error();
    signature.clear();

    if (privateKey == nullptr) {
        return kErrInvalidArgument;
    }
    if (digest.empty()) {
        return kErrInvalidArgument;
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(privateKey);
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_sign_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }
    const int configurationResult = configurePss(keyContext.get());
    if (configurationResult != kOk) {
        return configurationResult;
    }

    std::size_t signatureLength = 0;
    if (EVP_PKEY_sign(keyContext.get(), nullptr, &signatureLength,
                      digest.data(), digest.size()) <= 0) {
        return kErrOpenSsl;
    }
    signature.resize(signatureLength);
    if (EVP_PKEY_sign(keyContext.get(), signature.data(), &signatureLength,
                      digest.data(), digest.size()) <= 0) {
        return kErrOpenSsl;
    }
    signature.resize(signatureLength);
    return kOk;
}

int Rsa4096::verify(EVP_PKEY* publicKey,
                    const std::vector<uint8_t>& digest,
                    const std::vector<uint8_t>& signature) noexcept {
    ERR_clear_error();

    if (publicKey == nullptr) {
        return kErrInvalidArgument;
    }
    if (digest.empty()) {
        return kErrInvalidArgument;
    }
    if (signature.empty()) {
        return kErrInvalidArgument;
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(publicKey);
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_verify_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }
    const int configurationResult = configurePss(keyContext.get());
    if (configurationResult != kOk) {
        return configurationResult;
    }

    const int verificationResult = EVP_PKEY_verify(keyContext.get(),
                                                   signature.data(), signature.size(),
                                                   digest.data(), digest.size());
    if (verificationResult == 1) {
        return kOk;
    }
    // 0 = the signature does not match (tampering); < 0 = an OpenSSL error.
    if (verificationResult == 0) {
        return kErrAuth;
    }
    return kErrOpenSsl;
}

// ---------------------------------------------------------------------------
// Key persistence (PEM / DER, in memory)
// ---------------------------------------------------------------------------
int Rsa4096::savePublicKeyPem(EVP_PKEY* key, std::string& pem) noexcept {
    ERR_clear_error();
    pem.clear();
    if (key == nullptr) {
        return kErrInvalidArgument;
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return kErrOpenSsl;
    }
    const int rc = PEM_write_bio_PUBKEY(bio, key);
    const int result = rc == 1 ? bioMemoryToString(bio, pem) : kErrOpenSsl;
    BIO_free(bio);
    return result;
}

int Rsa4096::loadPublicKeyPem(const std::string& pem, EVP_PKEY** outputKey) noexcept {
    ERR_clear_error();
    if (outputKey == nullptr) {
        return kErrInvalidArgument;
    }
    *outputKey = nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) {
        return kErrOpenSsl;
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        return kErrOpenSsl;
    }
    *outputKey = key;
    return kOk;
}

int Rsa4096::savePrivateKeyPem(EVP_PKEY* key, std::string& pem) noexcept {
    ERR_clear_error();
    pem.clear();
    if (key == nullptr) {
        return kErrInvalidArgument;
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return kErrOpenSsl;
    }
    const int rc = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    const int result = rc == 1 ? bioMemoryToString(bio, pem) : kErrOpenSsl;
    BIO_free(bio);
    return result;
}

int Rsa4096::loadPrivateKeyPem(const std::string& pem, EVP_PKEY** outputKey) noexcept {
    ERR_clear_error();
    if (outputKey == nullptr) {
        return kErrInvalidArgument;
    }
    *outputKey = nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) {
        return kErrOpenSsl;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        return kErrOpenSsl;
    }
    *outputKey = key;
    return kOk;
}

int Rsa4096::savePublicKeyDer(EVP_PKEY* key, std::vector<uint8_t>& der) noexcept {
    ERR_clear_error();
    der.clear();
    if (key == nullptr) {
        return kErrInvalidArgument;
    }
    return exportDer(key, false, der);
}

int Rsa4096::loadPublicKeyDer(const std::vector<uint8_t>& der,
                              EVP_PKEY** outputKey) noexcept {
    ERR_clear_error();
    if (outputKey == nullptr) {
        return kErrInvalidArgument;
    }
    *outputKey = nullptr;
    if (der.empty() || der.size() > static_cast<std::size_t>(LONG_MAX)) {
        return kErrInvalidArgument;
    }
    const unsigned char* cursor = der.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size()));
    if (key == nullptr) {
        return kErrOpenSsl;
    }
    *outputKey = key;
    return kOk;
}

int Rsa4096::savePrivateKeyDer(EVP_PKEY* key, std::vector<uint8_t>& der) noexcept {
    ERR_clear_error();
    der.clear();
    if (key == nullptr) {
        return kErrInvalidArgument;
    }
    return exportDer(key, true, der);
}

int Rsa4096::loadPrivateKeyDer(const std::vector<uint8_t>& der,
                               EVP_PKEY** outputKey) noexcept {
    ERR_clear_error();
    if (outputKey == nullptr) {
        return kErrInvalidArgument;
    }
    *outputKey = nullptr;
    if (der.empty() || der.size() > static_cast<std::size_t>(LONG_MAX)) {
        return kErrInvalidArgument;
    }
    const unsigned char* cursor = der.data();
    EVP_PKEY* key = d2i_PrivateKey(EVP_PKEY_NONE, nullptr, &cursor,
                                   static_cast<long>(der.size()));
    if (key == nullptr) {
        return kErrOpenSsl;
    }
    *outputKey = key;
    return kOk;
}

} // namespace Crypto
