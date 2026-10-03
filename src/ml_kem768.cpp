// ObsidianGuard - src/ml_kem768.cpp
// ML-KEM-768 (FIPS 203) post-quantum key encapsulation.
// Requires OpenSSL 3.5 or newer with ML-KEM support.

#include "ml_kem768.hpp"

#include <openssl/err.h>
#include <openssl/x509.h>

#include <climits>
#include <cstdint>
#include <string>
#include <vector>

#include "error_utils.hpp"
#include "openssl_raii.hpp"

namespace ObsidianGuard {
namespace {

constexpr const char* kAlgorithmName = "ML-KEM-768";
constexpr const char* kUnavailableMessage = "ML-KEM not available. Requires OpenSSL 3.5+.";

CryptoResult unavailable(std::string* lastError) noexcept {
    *lastError = kUnavailableMessage;
    return CryptoResult::failure(detail::kErrorCode, kUnavailableMessage);
}

/// Encode a key as DER into out. False on failure.
bool exportPublicDer(EVP_PKEY* key, std::vector<uint8_t>& out) noexcept {
    const int length = i2d_PUBKEY(key, nullptr);
    if (length <= 0) {
        return false;
    }
    out.resize(static_cast<std::size_t>(length));
    unsigned char* cursor = out.data();
    if (i2d_PUBKEY(key, &cursor) != length) {
        out.clear();
        return false;
    }
    return true;
}

/// Encode a key as DER into out. False on failure.
bool exportPrivateDer(EVP_PKEY* key, std::vector<uint8_t>& out) noexcept {
    const int length = i2d_PrivateKey(key, nullptr);
    if (length <= 0) {
        return false;
    }
    out.resize(static_cast<std::size_t>(length));
    unsigned char* cursor = out.data();
    if (i2d_PrivateKey(key, &cursor) != length) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace

const char* MlKem768Module::algorithmName() const noexcept {
    return "ML-KEM-768 (FIPS 203)";
}

const std::string& MlKem768Module::getLastError() const noexcept {
    return lastError_;
}

void MlKem768Module::clearError() noexcept {
    lastError_.clear();
    ERR_clear_error();
}

CryptoResult MlKem768Module::generateKeyPair(std::vector<uint8_t>& publicKey,
                                             std::vector<uint8_t>& secretKey) noexcept {
    clearError();
    publicKey.clear();
    secretKey.clear();

    // Creating the context by name is also the availability probe: it fails
    // when this OpenSSL build has no ML-KEM support.
    EvpPkeyCtxPtr keyContext = makePkeyCtxFromName(kAlgorithmName);
    if (!keyContext) {
        return unavailable(&lastError_);
    }
    if (EVP_PKEY_keygen_init(keyContext.get()) <= 0) {
        return detail::openSslFailure("ML-KEM-768: key generation initialization failed",
                                      &lastError_);
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(keyContext.get(), &rawKey) <= 0) {
        return detail::openSslFailure("ML-KEM-768: key generation failed", &lastError_);
    }
    EvpPkeyPtr keyPair = wrapPkey(rawKey);

    if (!exportPublicDer(keyPair.get(), publicKey)) {
        return detail::openSslFailure("ML-KEM-768: public key export failed", &lastError_);
    }
    if (!exportPrivateDer(keyPair.get(), secretKey)) {
        return detail::openSslFailure("ML-KEM-768: secret key export failed", &lastError_);
    }
    return CryptoResult::success();
}

CryptoResult MlKem768Module::encapsulate(const std::vector<uint8_t>& publicKey,
                                         std::vector<uint8_t>& ciphertext,
                                         std::vector<uint8_t>& sharedSecret) noexcept {
    clearError();
    ciphertext.clear();
    sharedSecret.clear();

    if (publicKey.empty()) {
        return detail::paramFailure("ML-KEM-768: public key must not be empty", &lastError_);
    }
    if (publicKey.size() > static_cast<std::size_t>(LONG_MAX)) {
        return detail::paramFailure("ML-KEM-768: public key too large", &lastError_);
    }

    const unsigned char* cursor = publicKey.data();
    EVP_PKEY* rawKey = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(publicKey.size()));
    if (rawKey == nullptr) {
        return detail::openSslFailure("ML-KEM-768: failed to parse public key", &lastError_);
    }
    EvpPkeyPtr parsedPublicKey = wrapPkey(rawKey);

    EvpPkeyCtxPtr keyContext = makePkeyCtx(parsedPublicKey.get());
    if (!keyContext) {
        return detail::openSslFailure("ML-KEM-768: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_encapsulate_init(keyContext.get(), nullptr) != 1) {
        return detail::openSslFailure("ML-KEM-768: encapsulation initialization failed",
                                      &lastError_);
    }

    std::size_t ciphertextLength = 0;
    std::size_t sharedSecretLength = 0;
    if (EVP_PKEY_encapsulate(keyContext.get(), nullptr, &ciphertextLength,
                             nullptr, &sharedSecretLength) != 1) {
        return detail::openSslFailure("ML-KEM-768: determining output sizes failed",
                                      &lastError_);
    }
    ciphertext.resize(ciphertextLength);
    sharedSecret.resize(sharedSecretLength);
    if (EVP_PKEY_encapsulate(keyContext.get(), ciphertext.data(), &ciphertextLength,
                             sharedSecret.data(), &sharedSecretLength) != 1) {
        return detail::openSslFailure("ML-KEM-768: encapsulation failed", &lastError_);
    }
    ciphertext.resize(ciphertextLength);
    sharedSecret.resize(sharedSecretLength);
    return CryptoResult::success();
}

CryptoResult MlKem768Module::decapsulate(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& secretKey,
                                         std::vector<uint8_t>& sharedSecret) noexcept {
    clearError();
    sharedSecret.clear();

    if (ciphertext.empty()) {
        return detail::paramFailure("ML-KEM-768: ciphertext must not be empty", &lastError_);
    }
    if (secretKey.empty()) {
        return detail::paramFailure("ML-KEM-768: secret key must not be empty", &lastError_);
    }
    if (secretKey.size() > static_cast<std::size_t>(LONG_MAX)) {
        return detail::paramFailure("ML-KEM-768: secret key too large", &lastError_);
    }

    const unsigned char* cursor = secretKey.data();
    EVP_PKEY* rawKey = d2i_PrivateKey(EVP_PKEY_NONE, nullptr, &cursor,
                                      static_cast<long>(secretKey.size()));
    if (rawKey == nullptr) {
        return detail::openSslFailure("ML-KEM-768: failed to parse secret key", &lastError_);
    }
    EvpPkeyPtr parsedSecretKey = wrapPkey(rawKey);

    EvpPkeyCtxPtr keyContext = makePkeyCtx(parsedSecretKey.get());
    if (!keyContext) {
        return detail::openSslFailure("ML-KEM-768: EVP_PKEY_CTX_new failed", &lastError_);
    }
    if (EVP_PKEY_decapsulate_init(keyContext.get(), nullptr) != 1) {
        return detail::openSslFailure("ML-KEM-768: decapsulation initialization failed",
                                      &lastError_);
    }

    std::size_t sharedSecretLength = 0;
    if (EVP_PKEY_decapsulate(keyContext.get(), nullptr, &sharedSecretLength,
                             ciphertext.data(), ciphertext.size()) != 1) {
        return detail::openSslFailure("ML-KEM-768: determining secret size failed",
                                      &lastError_);
    }
    sharedSecret.resize(sharedSecretLength);
    if (EVP_PKEY_decapsulate(keyContext.get(), sharedSecret.data(), &sharedSecretLength,
                             ciphertext.data(), ciphertext.size()) != 1) {
        return detail::openSslFailure("ML-KEM-768: decapsulation failed", &lastError_);
    }
    sharedSecret.resize(sharedSecretLength);
    return CryptoResult::success();
}

} // namespace ObsidianGuard
