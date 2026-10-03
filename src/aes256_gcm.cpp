// ObsidianGuard - src/aes256_gcm.cpp
// AES-256-GCM authenticated encryption (EVP_aes_256_gcm).

#include "aes256_gcm.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "error_utils.hpp"
#include "openssl_raii.hpp"

namespace ObsidianGuard {
namespace {

constexpr std::size_t kKeySize = 32;    // AES-256 key
constexpr std::size_t kNonceSize = 12;  // recommended GCM nonce (IV) length
constexpr int kTagSize = 16;            // full 128-bit authentication tag

} // namespace

const char* Aes256GcmModule::algorithmName() const noexcept {
    return "AES-256-GCM";
}

const std::string& Aes256GcmModule::getLastError() const noexcept {
    return lastError_;
}

void Aes256GcmModule::clearError() noexcept {
    lastError_.clear();
    ERR_clear_error();
}

CryptoResult Aes256GcmModule::generateKey(std::vector<uint8_t>& key) noexcept {
    clearError();
    key.assign(kKeySize, 0);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        return detail::openSslFailure("AES-256-GCM: RAND_bytes (key generation) failed",
                                      &lastError_);
    }
    return CryptoResult::success();
}

CryptoResult Aes256GcmModule::generateIv(std::vector<uint8_t>& nonce) noexcept {
    clearError();
    nonce.assign(kNonceSize, 0);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        return detail::openSslFailure("AES-256-GCM: RAND_bytes (nonce generation) failed",
                                      &lastError_);
    }
    return CryptoResult::success();
}

CryptoResult Aes256GcmModule::encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& nonce,
                                      std::vector<uint8_t>& ciphertext,
                                      std::array<uint8_t, 16>& tag) noexcept {
    clearError();
    ciphertext.clear();
    tag.fill(0);

    if (key.size() != kKeySize) {
        return detail::paramFailure("AES-256-GCM: key must be exactly 32 bytes", &lastError_);
    }
    if (nonce.size() != kNonceSize) {
        return detail::paramFailure("AES-256-GCM: nonce (IV) must be exactly 12 bytes",
                                    &lastError_);
    }
    if (plaintext.size() > static_cast<std::size_t>(INT_MAX)) {
        return detail::paramFailure("AES-256-GCM: plaintext too large for a single call",
                                    &lastError_);
    }

    EvpCipherCtxPtr cipherContext = makeCipherCtx();
    if (!cipherContext) {
        return detail::openSslFailure("AES-256-GCM: EVP_CIPHER_CTX_new failed", &lastError_);
    }
    if (EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        return detail::openSslFailure("AES-256-GCM: EVP_EncryptInit_ex failed", &lastError_);
    }
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        return detail::openSslFailure("AES-256-GCM: setting IV length failed", &lastError_);
    }
    if (EVP_EncryptInit_ex(cipherContext.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1) {
        return detail::openSslFailure("AES-256-GCM: key/IV initialization failed", &lastError_);
    }

    // GCM is a stream cipher: the ciphertext has the same size as the
    // plaintext. The extra headroom keeps the final-call pointer valid even
    // for empty input; it is trimmed away at the end.
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outputLength = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(cipherContext.get(), ciphertext.data(), &outputLength,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        return detail::openSslFailure("AES-256-GCM: encryption failed", &lastError_);
    }

    int finalLength = 0;
    if (EVP_EncryptFinal_ex(cipherContext.get(),
                            ciphertext.data() + outputLength, &finalLength) != 1) {
        return detail::openSslFailure("AES-256-GCM: finalizing encryption failed", &lastError_);
    }
    ciphertext.resize(static_cast<std::size_t>(outputLength) +
                      static_cast<std::size_t>(finalLength));

    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_GET_TAG,
                            kTagSize, tag.data()) != 1) {
        return detail::openSslFailure("AES-256-GCM: reading the authentication tag failed",
                                      &lastError_);
    }
    return CryptoResult::success();
}

CryptoResult Aes256GcmModule::decrypt(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& nonce,
                                      const std::vector<uint8_t>& tag,
                                      std::vector<uint8_t>& plaintext) noexcept {
    clearError();
    plaintext.clear();

    if (key.size() != kKeySize) {
        return detail::paramFailure("AES-256-GCM: key must be exactly 32 bytes", &lastError_);
    }
    if (nonce.size() != kNonceSize) {
        return detail::paramFailure("AES-256-GCM: nonce (IV) must be exactly 12 bytes",
                                    &lastError_);
    }
    if (tag.size() != kTagSize) {
        return detail::paramFailure("AES-256-GCM: tag must be exactly 16 bytes", &lastError_);
    }
    if (ciphertext.size() > static_cast<std::size_t>(INT_MAX)) {
        return detail::paramFailure("AES-256-GCM: ciphertext too large for a single call",
                                    &lastError_);
    }

    EvpCipherCtxPtr cipherContext = makeCipherCtx();
    if (!cipherContext) {
        return detail::openSslFailure("AES-256-GCM: EVP_CIPHER_CTX_new failed", &lastError_);
    }
    if (EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        return detail::openSslFailure("AES-256-GCM: EVP_DecryptInit_ex failed", &lastError_);
    }
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        return detail::openSslFailure("AES-256-GCM: setting IV length failed", &lastError_);
    }
    if (EVP_DecryptInit_ex(cipherContext.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1) {
        return detail::openSslFailure("AES-256-GCM: key/IV initialization failed", &lastError_);
    }

    // The expected tag must be supplied before the final step; only then is
    // the authentication checked.
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_TAG, kTagSize,
                            const_cast<uint8_t*>(tag.data())) != 1) {
        return detail::openSslFailure("AES-256-GCM: setting the authentication tag failed",
                                      &lastError_);
    }

    plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outputLength = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(cipherContext.get(), plaintext.data(), &outputLength,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        return detail::openSslFailure("AES-256-GCM: decryption failed", &lastError_);
    }

    int finalLength = 0;
    if (EVP_DecryptFinal_ex(cipherContext.get(),
                            plaintext.data() + outputLength, &finalLength) != 1) {
        // The most common cause is a wrong key, nonce (IV) or tag.
        return detail::openSslFailure(
            "AES-256-GCM: authentication failed (wrong key, nonce (IV) or tag)", &lastError_);
    }
    plaintext.resize(static_cast<std::size_t>(outputLength) +
                     static_cast<std::size_t>(finalLength));
    return CryptoResult::success();
}

} // namespace ObsidianGuard
