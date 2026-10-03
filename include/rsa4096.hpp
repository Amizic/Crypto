#pragma once

// ObsidianGuard - rsa4096.hpp
// RSA-4096: OAEP-SHA256 encryption and PSS-SHA256 signatures.

#include <openssl/evp.h>

#include <cstdint>
#include <vector>

#include "crypto_module.hpp"

namespace ObsidianGuard {

/// RSA with 4096-bit keys.
///  * encryption/decryption use RSA-OAEP with SHA-256 (and MGF1-SHA-256),
///  * signing/verification use RSA-PSS with SHA-256 and a digest-length salt.
class OBSIDIAN_GUARD_API Rsa4096Module final : public ICryptoModule {
public:
    Rsa4096Module() noexcept = default;

    const char* algorithmName() const noexcept override;
    const std::string& getLastError() const noexcept override;
    void clearError() noexcept override;

    /// Generate a 4096-bit RSA key pair.
    /// On success *outputKey points to a new EVP_PKEY; the caller takes
    /// ownership and must release it with EVP_PKEY_free() (or
    /// ObsidianGuard::wrapPkey() from openssl_raii.hpp).
    CryptoResult generateKeyPair(EVP_PKEY** outputKey) noexcept;

    /// Encrypt with the public key (OAEP, SHA-256).
    CryptoResult encrypt(EVP_PKEY* publicKey,
                         const std::vector<uint8_t>& plaintext,
                         std::vector<uint8_t>& ciphertext) noexcept;

    /// Decrypt with the private key (OAEP, SHA-256).
    CryptoResult decrypt(EVP_PKEY* privateKey,
                         const std::vector<uint8_t>& ciphertext,
                         std::vector<uint8_t>& plaintext) noexcept;

    /// Sign a SHA-256 digest with the private key (PSS, SHA-256).
    CryptoResult sign(EVP_PKEY* privateKey,
                      const std::vector<uint8_t>& digest,
                      std::vector<uint8_t>& signature) noexcept;

    /// Verify an RSA-PSS signature over a SHA-256 digest (public key).
    CryptoResult verify(EVP_PKEY* publicKey,
                        const std::vector<uint8_t>& digest,
                        const std::vector<uint8_t>& signature) noexcept;
};

} // namespace ObsidianGuard
