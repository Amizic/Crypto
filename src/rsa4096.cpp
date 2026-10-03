// ObsidianGuard - src/rsa4096.cpp
// RSA-4096: OAEP-SHA256 encryption and PSS-SHA256 signatures.

#include "rsa4096.hpp"

#include <openssl/err.h>
#include <openssl/rsa.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "error_utils.hpp"
#include "openssl_raii.hpp"

namespace ObsidianGuard {
namespace {

constexpr int kKeyBits = 4096;

/// Shared OAEP configuration for encryption and decryption: OAEP padding
/// with SHA-256 as both the OAEP digest and the MGF1 digest.
CryptoResult configureOaep(EVP_PKEY_CTX* keyContext, std::string* lastError) noexcept {
    if (EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return detail::openSslFailure("RSA-4096: setting OAEP padding failed", lastError);
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(keyContext, EVP_sha256()) <= 0) {
        return detail::openSslFailure("RSA-4096: setting OAEP digest failed", lastError);
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(keyContext, EVP_sha256()) <= 0) {
        return detail::openSslFailure("RSA-4096: setting OAEP MGF1 digest failed", lastError);
    }
    return CryptoResult::success();
}

/// Shared PSS configuration for signing and verification: PSS padding with
/// SHA-256 and a salt as long as the digest.
CryptoResult configurePss(EVP_PKEY_CTX* keyContext, std::string* lastError) noexcept {
    if (EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING) <= 0) {
        return detail::openSslFailure("RSA-4096: setting PSS padding failed", lastError);
    }
    if (EVP_PKEY_CTX_set_signature_md(keyContext, EVP_sha256()) <= 0) {
        return detail::openSslFailure("RSA-4096: setting PSS digest failed", lastError);
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(keyContext, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        return detail::openSslFailure("RSA-4096: setting PSS salt length failed", lastError);
    }
    return CryptoResult::success();
}

} // namespace

const char* Rsa4096Module::algorithmName() const noexcept {
    return "RSA-4096 (OAEP-SHA256 / PSS-SHA256)";
}

const std::string& Rsa4096Module::getLastError() const noexcept {
    return lastError_;
}

void Rsa4096Module::clearError() noexcept {
    lastError_.clear();
    ERR_clear_error();
}

CryptoResult Rsa4096Module::generateKeyPair(EVP_PKEY** outputKey) noexcept {
    clearError();
    if (outputKey == nullptr) {
        return detail::paramFailure("RSA-4096: outputKey must not be null", &lastError_);
    }
    *outputKey = nullptr;

    EvpPkeyCtxPtr keyContext = makePkeyCtxFromId(EVP_PKEY_RSA);
    if (!keyContext) {
        return detail::openSslFailure("RSA-4096: EVP_PKEY_CTX_new_id failed", &lastError_);
    }
    if (EVP_PKEY_keygen_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("RSA-4096: key generation initialization failed",
                                      &lastError_);
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), kKeyBits) <= 0) {
        return detail::openSslFailure("RSA-4096: setting key size failed", &lastError_);
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(keyContext.get(), &rawKey) <= 0) {
        return detail::openSslFailure("RSA-4096: key generation failed", &lastError_);
    }

    // Ownership is transferred to the caller.
    *outputKey = rawKey;
    return CryptoResult::success();
}

CryptoResult Rsa4096Module::encrypt(EVP_PKEY* publicKey,
                                    const std::vector<uint8_t>& plaintext,
                                    std::vector<uint8_t>& ciphertext) noexcept {
    clearError();
    ciphertext.clear();

    if (publicKey == nullptr) {
        return detail::paramFailure("RSA-4096: public key must not be null", &lastError_);
    }
    if (plaintext.empty()) {
        return detail::paramFailure("RSA-4096: plaintext must not be empty", &lastError_);
    }
    if (plaintext.size() > static_cast<std::size_t>(INT_MAX)) {
        return detail::paramFailure("RSA-4096: plaintext too large for a single call",
                                    &lastError_);
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(publicKey);
    if (!keyContext) {
        return detail::openSslFailure("RSA-4096: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_encrypt_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("RSA-4096: encryption initialization failed", &lastError_);
    }
    const CryptoResult configurationResult = configureOaep(keyContext.get(), &lastError_);
    if (!configurationResult.ok()) {
        return configurationResult;
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_encrypt(keyContext.get(), nullptr, &outputLength,
                         plaintext.data(), plaintext.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: determining ciphertext size failed",
                                      &lastError_);
    }
    ciphertext.resize(outputLength);
    if (EVP_PKEY_encrypt(keyContext.get(), ciphertext.data(), &outputLength,
                         plaintext.data(), plaintext.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: encryption failed", &lastError_);
    }
    ciphertext.resize(outputLength);
    return CryptoResult::success();
}

CryptoResult Rsa4096Module::decrypt(EVP_PKEY* privateKey,
                                    const std::vector<uint8_t>& ciphertext,
                                    std::vector<uint8_t>& plaintext) noexcept {
    clearError();
    plaintext.clear();

    if (privateKey == nullptr) {
        return detail::paramFailure("RSA-4096: private key must not be null", &lastError_);
    }
    if (ciphertext.empty()) {
        return detail::paramFailure("RSA-4096: ciphertext must not be empty", &lastError_);
    }
    if (ciphertext.size() > static_cast<std::size_t>(INT_MAX)) {
        return detail::paramFailure("RSA-4096: ciphertext too large for a single call",
                                    &lastError_);
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(privateKey);
    if (!keyContext) {
        return detail::openSslFailure("RSA-4096: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_decrypt_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("RSA-4096: decryption initialization failed", &lastError_);
    }
    const CryptoResult configurationResult = configureOaep(keyContext.get(), &lastError_);
    if (!configurationResult.ok()) {
        return configurationResult;
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_decrypt(keyContext.get(), nullptr, &outputLength,
                         ciphertext.data(), ciphertext.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: determining plaintext size failed",
                                      &lastError_);
    }
    plaintext.resize(outputLength);
    if (EVP_PKEY_decrypt(keyContext.get(), plaintext.data(), &outputLength,
                         ciphertext.data(), ciphertext.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: decryption failed", &lastError_);
    }
    plaintext.resize(outputLength);
    return CryptoResult::success();
}

CryptoResult Rsa4096Module::sign(EVP_PKEY* privateKey,
                                 const std::vector<uint8_t>& digest,
                                 std::vector<uint8_t>& signature) noexcept {
    clearError();
    signature.clear();

    if (privateKey == nullptr) {
        return detail::paramFailure("RSA-4096: private key must not be null", &lastError_);
    }
    if (digest.empty()) {
        return detail::paramFailure("RSA-4096: digest must not be empty", &lastError_);
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(privateKey);
    if (!keyContext) {
        return detail::openSslFailure("RSA-4096: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_sign_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("RSA-4096: signature initialization failed", &lastError_);
    }
    const CryptoResult configurationResult = configurePss(keyContext.get(), &lastError_);
    if (!configurationResult.ok()) {
        return configurationResult;
    }

    std::size_t signatureLength = 0;
    if (EVP_PKEY_sign(keyContext.get(), nullptr, &signatureLength,
                      digest.data(), digest.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: determining signature size failed",
                                      &lastError_);
    }
    signature.resize(signatureLength);
    if (EVP_PKEY_sign(keyContext.get(), signature.data(), &signatureLength,
                      digest.data(), digest.size()) <= 0) {
        return detail::openSslFailure("RSA-4096: signing failed", &lastError_);
    }
    signature.resize(signatureLength);
    return CryptoResult::success();
}

CryptoResult Rsa4096Module::verify(EVP_PKEY* publicKey,
                                   const std::vector<uint8_t>& digest,
                                   const std::vector<uint8_t>& signature) noexcept {
    clearError();

    if (publicKey == nullptr) {
        return detail::paramFailure("RSA-4096: public key must not be null", &lastError_);
    }
    if (digest.empty()) {
        return detail::paramFailure("RSA-4096: digest must not be empty", &lastError_);
    }
    if (signature.empty()) {
        return detail::paramFailure("RSA-4096: signature must not be empty", &lastError_);
    }

    EvpPkeyCtxPtr keyContext = makePkeyCtx(publicKey);
    if (!keyContext) {
        return detail::openSslFailure("RSA-4096: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_verify_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("RSA-4096: verification initialization failed",
                                      &lastError_);
    }
    const CryptoResult configurationResult = configurePss(keyContext.get(), &lastError_);
    if (!configurationResult.ok()) {
        return configurationResult;
    }

    const int verificationResult = EVP_PKEY_verify(keyContext.get(),
                                                   signature.data(), signature.size(),
                                                   digest.data(), digest.size());
    if (verificationResult == 1) {
        return CryptoResult::success();
    }
    return detail::openSslFailure("RSA-4096: signature verification failed", &lastError_);
}

} // namespace ObsidianGuard
