// ObsidianGuard - src/Aes256.cpp
// AES-256-GCM authenticated encryption (EVP_aes_256_gcm).

#include "Aes256.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "OpensslRaii.hpp"

namespace ObsidianGuard {

const char* Aes256::algorithmName() const noexcept {
    return "AES-256-GCM";
}

int Aes256::generateKey(std::vector<uint8_t>& key) noexcept {
    ERR_clear_error();  // keep the calling thread's OpenSSL error queue clean
    key.assign(kKeySize, 0);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        return kErrOpenSsl;
    }
    return kOk;
}

int Aes256::generateIv(std::vector<uint8_t>& nonce) noexcept {
    ERR_clear_error();
    nonce.assign(kIvSize, 0);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        return kErrOpenSsl;
    }
    return kOk;
}

int Aes256::encrypt(const std::vector<uint8_t>& plaintext,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& nonce,
                    std::vector<uint8_t>& ciphertext,
                    std::array<uint8_t, 16>& tag) noexcept {
    return encrypt(plaintext, key, nonce, std::vector<uint8_t>(), ciphertext, tag);
}

int Aes256::encrypt(const std::vector<uint8_t>& plaintext,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& nonce,
                    const std::vector<uint8_t>& aad,
                    std::vector<uint8_t>& ciphertext,
                    std::array<uint8_t, 16>& tag) noexcept {
    ERR_clear_error();
    ciphertext.clear();
    tag.fill(0);

    if (key.size() != kKeySize) {
        return kErrInvalidArgument;
    }
    if (nonce.size() != kIvSize) {
        return kErrInvalidArgument;
    }
    if (plaintext.size() > static_cast<std::size_t>(INT_MAX) ||
        aad.size() > static_cast<std::size_t>(INT_MAX)) {
        return kErrInvalidArgument;
    }

    EvpCipherCtxPtr cipherContext = makeCipherCtx();
    if (!cipherContext) {
        return kErrOpenSsl;
    }
    if (EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_EncryptInit_ex(cipherContext.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1) {
        return kErrOpenSsl;
    }

    // Associated data is authenticated but not encrypted; it must be fed
    // before any plaintext.
    if (!aad.empty()) {
        int aadLength = 0;
        if (EVP_EncryptUpdate(cipherContext.get(), nullptr, &aadLength,
                              aad.data(), static_cast<int>(aad.size())) != 1) {
            return kErrOpenSsl;
        }
    }

    // GCM is a stream cipher: the ciphertext has the same size as the
    // plaintext. The extra headroom keeps the final-call pointer valid even
    // for empty input; it is trimmed away at the end.
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outputLength = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(cipherContext.get(), ciphertext.data(), &outputLength,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        ciphertext.clear();
        return kErrOpenSsl;
    }

    int finalLength = 0;
    if (EVP_EncryptFinal_ex(cipherContext.get(),
                            ciphertext.data() + outputLength, &finalLength) != 1) {
        ciphertext.clear();
        return kErrOpenSsl;
    }
    ciphertext.resize(static_cast<std::size_t>(outputLength) +
                      static_cast<std::size_t>(finalLength));

    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(kTagSize), tag.data()) != 1) {
        ciphertext.clear();
        return kErrOpenSsl;
    }
    return kOk;
}

int Aes256::decrypt(const std::vector<uint8_t>& ciphertext,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& nonce,
                    const std::vector<uint8_t>& tag,
                    std::vector<uint8_t>& plaintext) noexcept {
    return decrypt(ciphertext, key, nonce, std::vector<uint8_t>(), tag, plaintext);
}

int Aes256::decrypt(const std::vector<uint8_t>& ciphertext,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& nonce,
                    const std::vector<uint8_t>& aad,
                    const std::vector<uint8_t>& tag,
                    std::vector<uint8_t>& plaintext) noexcept {
    ERR_clear_error();
    plaintext.clear();

    if (key.size() != kKeySize) {
        return kErrInvalidArgument;
    }
    if (nonce.size() != kIvSize) {
        return kErrInvalidArgument;
    }
    if (tag.size() != kTagSize) {
        return kErrInvalidArgument;
    }
    if (ciphertext.size() > static_cast<std::size_t>(INT_MAX) ||
        aad.size() > static_cast<std::size_t>(INT_MAX)) {
        return kErrInvalidArgument;
    }

    EvpCipherCtxPtr cipherContext = makeCipherCtx();
    if (!cipherContext) {
        return kErrOpenSsl;
    }
    if (EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_DecryptInit_ex(cipherContext.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1) {
        return kErrOpenSsl;
    }

    // Feed the same associated data that was bound at encryption.
    if (!aad.empty()) {
        int aadLength = 0;
        if (EVP_DecryptUpdate(cipherContext.get(), nullptr, &aadLength,
                              aad.data(), static_cast<int>(aad.size())) != 1) {
            plaintext.clear();
            return kErrOpenSsl;
        }
    }

    // The expected tag must be supplied before the final step; only then is
    // the authentication checked.
    if (EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(kTagSize),
                            const_cast<uint8_t*>(tag.data())) != 1) {
        return kErrOpenSsl;
    }

    plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outputLength = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(cipherContext.get(), plaintext.data(), &outputLength,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        plaintext.clear();
        return kErrOpenSsl;
    }

    int finalLength = 0;
    if (EVP_DecryptFinal_ex(cipherContext.get(),
                            plaintext.data() + outputLength, &finalLength) != 1) {
        // The most common cause is a wrong key, nonce (IV), tag or AAD.
        // Clear the partial output so no plaintext-derived bytes escape on
        // failure.
        plaintext.clear();
        return kErrAuth;
    }
    plaintext.resize(static_cast<std::size_t>(outputLength) +
                     static_cast<std::size_t>(finalLength));
    return kOk;
}

int Aes256::encrypt(const std::vector<uint8_t>& plaintext,
                    const std::vector<uint8_t>& key,
                    std::vector<uint8_t>& ciphertext) noexcept {
    ERR_clear_error();
    ciphertext.clear();

    std::vector<uint8_t> iv;
    int rc = generateIv(iv);
    if (rc != kOk) {
        return rc;
    }

    std::vector<uint8_t> body;
    std::array<uint8_t, 16> tag{};
    rc = encrypt(plaintext, key, iv, body, tag);
    if (rc != kOk) {
        return rc;
    }

    // Output layout: [12-byte IV][ciphertext][16-byte tag].
    ciphertext.reserve(iv.size() + body.size() + tag.size());
    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());
    ciphertext.insert(ciphertext.end(), body.begin(), body.end());
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return kOk;
}

int Aes256::decrypt(const std::vector<uint8_t>& ciphertext,
                    const std::vector<uint8_t>& key,
                    std::vector<uint8_t>& plaintext) noexcept {
    ERR_clear_error();
    plaintext.clear();

    if (ciphertext.size() < kIvSize + kTagSize) {
        return kErrInvalidArgument;
    }
    const std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + kIvSize);
    const std::vector<uint8_t> tag(ciphertext.end() - kTagSize, ciphertext.end());
    const std::vector<uint8_t> body(ciphertext.begin() + kIvSize,
                                    ciphertext.end() - kTagSize);
    return decrypt(body, key, iv, tag, plaintext);
}

} // namespace ObsidianGuard
