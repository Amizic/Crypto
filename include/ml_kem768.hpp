#pragma once

// ObsidianGuard - ml_kem768.hpp
// ML-KEM-768 (FIPS 203) post-quantum key encapsulation.
// Requires OpenSSL 3.5 or newer built with ML-KEM support.

#include <cstdint>
#include <vector>

#include "crypto_module.hpp"

namespace ObsidianGuard {

/// ML-KEM-768 post-quantum key encapsulation mechanism.
///
/// generateKeyPair() produces a DER-encoded X.509 SubjectPublicKeyInfo
/// public key and a DER-encoded PKCS#8 secret key. encapsulate() creates a
/// fresh 32-byte shared secret wrapped to the public key; decapsulate()
/// recovers it with the secret key. If the OpenSSL build has no ML-KEM
/// support every method fails with the message
/// "ML-KEM not available. Requires OpenSSL 3.5+."
class OBSIDIAN_GUARD_API MlKem768Module final : public ICryptoModule {
public:
    MlKem768Module() noexcept = default;

    const char* algorithmName() const noexcept override;
    const std::string& getLastError() const noexcept override;
    void clearError() noexcept override;

    /// Generate an ML-KEM-768 key pair.
    CryptoResult generateKeyPair(std::vector<uint8_t>& publicKey,
                                 std::vector<uint8_t>& secretKey) noexcept;

    /// Encapsulate a fresh shared secret to the given public key.
    CryptoResult encapsulate(const std::vector<uint8_t>& publicKey,
                             std::vector<uint8_t>& ciphertext,
                             std::vector<uint8_t>& sharedSecret) noexcept;

    /// Decapsulate the shared secret with the matching secret key.
    CryptoResult decapsulate(const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& secretKey,
                             std::vector<uint8_t>& sharedSecret) noexcept;
};

} // namespace ObsidianGuard
