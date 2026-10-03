#pragma once

// ObsidianGuard - aes256_gcm.hpp
// AES-256-GCM authenticated encryption (EVP_aes_256_gcm).

#include <array>
#include <cstdint>
#include <vector>

#include "crypto_module.hpp"

namespace ObsidianGuard {

/// AES-256 in GCM mode: 32-byte keys, 12-byte nonces (IVs), 16-byte
/// authentication tags. Decryption verifies the tag and fails on any
/// tampering.
class OBSIDIAN_GUARD_API Aes256GcmModule final : public ICryptoModule {
public:
    Aes256GcmModule() noexcept = default;

    const char* algorithmName() const noexcept override;
    const std::string& getLastError() const noexcept override;
    void clearError() noexcept override;

    /// Generate a random 32-byte AES-256 key.
    CryptoResult generateKey(std::vector<uint8_t>& key) noexcept;

    /// Generate a random 12-byte GCM nonce (IV).
    CryptoResult generateIv(std::vector<uint8_t>& nonce) noexcept;

    /// Encrypt with AES-256-GCM. On success the ciphertext has the same size
    /// as the plaintext and tag receives the 16-byte authentication tag.
    CryptoResult encrypt(const std::vector<uint8_t>& plaintext,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& nonce,
                         std::vector<uint8_t>& ciphertext,
                         std::array<uint8_t, 16>& tag) noexcept;

    /// Decrypt and authenticate with AES-256-GCM. Fails (without output) if
    /// the key, nonce (IV) or tag does not match the ciphertext.
    CryptoResult decrypt(const std::vector<uint8_t>& ciphertext,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& nonce,
                         const std::vector<uint8_t>& tag,
                         std::vector<uint8_t>& plaintext) noexcept;
};

} // namespace ObsidianGuard
