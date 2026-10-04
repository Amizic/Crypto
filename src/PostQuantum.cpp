// ObsidianGuard - src/PostQuantum.cpp
// Post-quantum hybrid encryption: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.

#include "PostQuantum.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Aes256.hpp"
#include "Hkdf.hpp"
#include "MlKem768.hpp"

namespace ObsidianGuard {
namespace {

constexpr const char* kInfoLabel = "ObsidianGuard post-quantum envelope v1";

constexpr std::size_t kKemLengthFieldSize = 4;
constexpr std::size_t kAesKeySize = 32;

std::vector<uint8_t> infoBytes() {
    const std::string label(kInfoLabel);
    return std::vector<uint8_t>(label.begin(), label.end());
}

} // namespace

const char* PostQuantum::algorithmName() const noexcept {
    return "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM";
}

int PostQuantum::encrypt(const std::vector<uint8_t>& recipientPublicKey,
                         const std::vector<uint8_t>& plaintext,
                         std::vector<uint8_t>& envelope) noexcept {
    ERR_clear_error();
    envelope.clear();
    if (recipientPublicKey.empty()) {
        return kErrInvalidArgument;
    }

    MlKem768 kem;
    Hkdf hkdf;
    Aes256 aes;

    // 1. Encapsulate a fresh shared secret to the recipient's public key.
    std::vector<uint8_t> kemCiphertext;
    std::vector<uint8_t> sharedSecret;
    int rc = kem.encapsulate(recipientPublicKey, kemCiphertext, sharedSecret);
    if (rc != kOk) {
        return rc;
    }

    // 2. Derive a dedicated AES-256 key from the shared secret.
    std::vector<uint8_t> aesKey;
    rc = hkdf.derive(sharedSecret, std::vector<uint8_t>(), infoBytes(),
                     kAesKeySize, aesKey);
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());
    if (rc != kOk) {
        return rc;
    }

    // 3. Encrypt with AES-256-GCM, binding the KEM ciphertext as AAD so the
    //    whole envelope is authenticated.
    std::vector<uint8_t> iv;
    rc = aes.generateIv(iv);
    if (rc != kOk) {
        OPENSSL_cleanse(aesKey.data(), aesKey.size());
        return rc;
    }

    std::vector<uint8_t> symCiphertext;
    std::array<uint8_t, 16> tag{};
    rc = aes.encrypt(plaintext, aesKey, iv, kemCiphertext, symCiphertext, tag);
    OPENSSL_cleanse(aesKey.data(), aesKey.size());
    if (rc != kOk) {
        return rc;
    }

    // 4. Assemble: [4-byte KEM length][KEM ciphertext][IV][ciphertext][tag].
    const std::uint32_t kemLength = static_cast<std::uint32_t>(kemCiphertext.size());
    envelope.reserve(kKemLengthFieldSize + kemCiphertext.size() +
                     iv.size() + symCiphertext.size() + tag.size());
    for (std::size_t i = 0; i < kKemLengthFieldSize; ++i) {
        envelope.push_back(static_cast<uint8_t>((kemLength >> (8 * i)) & 0xFFu));
    }
    envelope.insert(envelope.end(), kemCiphertext.begin(), kemCiphertext.end());
    envelope.insert(envelope.end(), iv.begin(), iv.end());
    envelope.insert(envelope.end(), symCiphertext.begin(), symCiphertext.end());
    envelope.insert(envelope.end(), tag.begin(), tag.end());
    return kOk;
}

int PostQuantum::decrypt(const std::vector<uint8_t>& recipientSecretKey,
                         const std::vector<uint8_t>& envelope,
                         std::vector<uint8_t>& plaintext) noexcept {
    ERR_clear_error();
    plaintext.clear();
    if (recipientSecretKey.empty()) {
        return kErrInvalidArgument;
    }

    // 1. Parse: [4-byte KEM length][KEM ciphertext][IV][ciphertext][tag].
    if (envelope.size() < kKemLengthFieldSize + Aes256::kIvSize + Aes256::kTagSize) {
        return kErrInvalidArgument;
    }
    std::uint32_t kemLength = 0;
    for (std::size_t i = 0; i < kKemLengthFieldSize; ++i) {
        kemLength |= static_cast<std::uint32_t>(envelope[i]) << (8 * i);
    }
    if (kemLength == 0 ||
        envelope.size() < kKemLengthFieldSize + kemLength +
                              Aes256::kIvSize + Aes256::kTagSize) {
        return kErrInvalidArgument;
    }
    const std::vector<uint8_t> kemCiphertext(
        envelope.begin() + kKemLengthFieldSize,
        envelope.begin() + kKemLengthFieldSize + kemLength);
    const std::size_t symOffset = kKemLengthFieldSize + kemLength;
    const std::vector<uint8_t> iv(envelope.begin() + symOffset,
                                  envelope.begin() + symOffset + Aes256::kIvSize);
    const std::size_t tagOffset = envelope.size() - Aes256::kTagSize;
    const std::vector<uint8_t> tag(envelope.begin() + tagOffset,
                                   envelope.end());
    const std::vector<uint8_t> symCiphertext(envelope.begin() + symOffset + Aes256::kIvSize,
                                             envelope.begin() + tagOffset);

    // 2. Decapsulate the shared secret (implicit rejection on tampering).
    MlKem768 kem;
    Hkdf hkdf;
    Aes256 aes;

    std::vector<uint8_t> sharedSecret;
    int rc = kem.decapsulate(kemCiphertext, recipientSecretKey, sharedSecret);
    if (rc != kOk) {
        return rc;
    }

    // 3. Derive the same AES-256 key.
    std::vector<uint8_t> aesKey;
    rc = hkdf.derive(sharedSecret, std::vector<uint8_t>(), infoBytes(),
                     kAesKeySize, aesKey);
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());
    if (rc != kOk) {
        return rc;
    }

    // 4. Decrypt with AES-256-GCM, checking the AAD bound at encryption.
    rc = aes.decrypt(symCiphertext, aesKey, iv, kemCiphertext, tag, plaintext);
    OPENSSL_cleanse(aesKey.data(), aesKey.size());
    return rc;  // kErrAuth on any tampering, including of the KEM part
}

} // namespace ObsidianGuard
