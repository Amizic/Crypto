// Crypto - src/MlKem768.cpp
// ML-KEM-768 (FIPS 203) post-quantum key encapsulation.
// Requires OpenSSL 3.5 or newer with ML-KEM support.

#include "MlKem768.hpp"

#include <openssl/err.h>
#include <openssl/x509.h>

#include <climits>
#include <cstdint>
#include <vector>

#include "OpensslRaii.hpp"

namespace Crypto {
namespace {

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

const char* MlKem768::algorithmName() const noexcept {
    return "ML-KEM-768 (FIPS 203)";
}

int MlKem768::generateKeyPair(std::vector<uint8_t>& publicKey,
                              std::vector<uint8_t>& secretKey) noexcept {
    ERR_clear_error();
    publicKey.clear();
    secretKey.clear();

    // Creating the context by name is also the availability probe: it fails
    // when this OpenSSL build has no ML-KEM support.
    EvpPkeyCtxPtr keyContext = makePkeyCtxFromName(kAlgorithm);
    if (!keyContext) {
        return kErrUnavailable;
    }
    if (EVP_PKEY_keygen_init(keyContext.get()) <= 0) {
        return kErrOpenSsl;
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(keyContext.get(), &rawKey) <= 0) {
        return kErrOpenSsl;
    }
    EvpPkeyPtr keyPair = wrapPkey(rawKey);

    if (!exportPublicDer(keyPair.get(), publicKey)) {
        return kErrOpenSsl;
    }
    if (!exportPrivateDer(keyPair.get(), secretKey)) {
        return kErrOpenSsl;
    }
    return kOk;
}

int MlKem768::encapsulate(const std::vector<uint8_t>& publicKey,
                          std::vector<uint8_t>& ciphertext,
                          std::vector<uint8_t>& sharedSecret) noexcept {
    ERR_clear_error();
    ciphertext.clear();
    sharedSecret.clear();

    if (publicKey.empty()) {
        return kErrInvalidArgument;
    }
    if (publicKey.size() > static_cast<std::size_t>(LONG_MAX)) {
        return kErrInvalidArgument;
    }

    const unsigned char* cursor = publicKey.data();
    EVP_PKEY* rawKey = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(publicKey.size()));
    if (rawKey == nullptr) {
        return kErrOpenSsl;
    }
    EvpPkeyPtr parsedPublicKey = wrapPkey(rawKey);

    EvpPkeyCtxPtr keyContext = makePkeyCtx(parsedPublicKey.get());
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_encapsulate_init(keyContext.get(), nullptr) != 1) {
        return kErrOpenSsl;
    }

    std::size_t ciphertextLength = 0;
    std::size_t sharedSecretLength = 0;
    if (EVP_PKEY_encapsulate(keyContext.get(), nullptr, &ciphertextLength,
                             nullptr, &sharedSecretLength) != 1) {
        return kErrOpenSsl;
    }
    ciphertext.resize(ciphertextLength);
    sharedSecret.resize(sharedSecretLength);
    if (EVP_PKEY_encapsulate(keyContext.get(), ciphertext.data(), &ciphertextLength,
                             sharedSecret.data(), &sharedSecretLength) != 1) {
        return kErrOpenSsl;
    }
    ciphertext.resize(ciphertextLength);
    sharedSecret.resize(sharedSecretLength);
    return kOk;
}

int MlKem768::decapsulate(const std::vector<uint8_t>& ciphertext,
                          const std::vector<uint8_t>& secretKey,
                          std::vector<uint8_t>& sharedSecret) noexcept {
    ERR_clear_error();
    sharedSecret.clear();

    if (ciphertext.empty()) {
        return kErrInvalidArgument;
    }
    if (secretKey.empty()) {
        return kErrInvalidArgument;
    }
    if (secretKey.size() > static_cast<std::size_t>(LONG_MAX)) {
        return kErrInvalidArgument;
    }

    const unsigned char* cursor = secretKey.data();
    EVP_PKEY* rawKey = d2i_PrivateKey(EVP_PKEY_NONE, nullptr, &cursor,
                                      static_cast<long>(secretKey.size()));
    if (rawKey == nullptr) {
        return kErrOpenSsl;
    }
    EvpPkeyPtr parsedSecretKey = wrapPkey(rawKey);

    EvpPkeyCtxPtr keyContext = makePkeyCtx(parsedSecretKey.get());
    if (!keyContext) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_decapsulate_init(keyContext.get(), nullptr) != 1) {
        return kErrOpenSsl;
    }

    std::size_t sharedSecretLength = 0;
    if (EVP_PKEY_decapsulate(keyContext.get(), nullptr, &sharedSecretLength,
                             ciphertext.data(), ciphertext.size()) != 1) {
        return kErrOpenSsl;
    }
    sharedSecret.resize(sharedSecretLength);
    if (EVP_PKEY_decapsulate(keyContext.get(), sharedSecret.data(), &sharedSecretLength,
                             ciphertext.data(), ciphertext.size()) != 1) {
        return kErrOpenSsl;
    }
    sharedSecret.resize(sharedSecretLength);
    return kOk;
}

} // namespace Crypto
