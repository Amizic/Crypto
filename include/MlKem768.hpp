// ML-KEM-768 (FIPS 203) post-quantum key encapsulation.
// Requires OpenSSL 3.5 or newer built with ML-KEM support.
//
// generateKeyPair() produces a DER-encoded X.509 SubjectPublicKeyInfo
// public key and a DER-encoded PKCS#8 secret key. encapsulate() creates a
// fresh 32-byte shared secret wrapped to the public key; decapsulate()
// recovers it with the secret key.
//
// The class is stateless, so it is trivially thread-safe: any number of
// threads may share one instance concurrently. Every method returns 0 on
// success or a negative return code on failure. If the OpenSSL build has no
// ML-KEM support every method fails with kErrUnavailable.
#ifndef OBSIDIAN_GUARD_MLKEM768_HPP
#define OBSIDIAN_GUARD_MLKEM768_HPP

// DLL import/export macro (Windows).
#ifndef OBSIDIAN_GUARD_API
    #ifdef OBSIDIAN_GUARD_STATIC
        #define OBSIDIAN_GUARD_API
    #elif defined(OBSIDIAN_GUARD_EXPORTS)
        #define OBSIDIAN_GUARD_API __declspec(dllexport)
    #else
        #define OBSIDIAN_GUARD_API __declspec(dllimport)
    #endif
#endif

#include <cstdint>
#include <vector>

namespace ObsidianGuard {

class OBSIDIAN_GUARD_API MlKem768 {
public:
    // The ML-KEM parameter set (NIST security category 3).
    static constexpr const char* kAlgorithm = "ML-KEM-768";

    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with ObsidianGuardLite)

    /// Human readable algorithm identifier ("ML-KEM-768 (FIPS 203)").
    const char* algorithmName() const noexcept;

    /// Generate an ML-KEM-768 key pair.
    int generateKeyPair(std::vector<uint8_t>& publicKey,
                        std::vector<uint8_t>& secretKey) noexcept;

    /// Encapsulate a fresh shared secret to the given public key.
    int encapsulate(const std::vector<uint8_t>& publicKey,
                    std::vector<uint8_t>& ciphertext,
                    std::vector<uint8_t>& sharedSecret) noexcept;

    /// Decapsulate the shared secret with the matching secret key.
    int decapsulate(const std::vector<uint8_t>& ciphertext,
                    const std::vector<uint8_t>& secretKey,
                    std::vector<uint8_t>& sharedSecret) noexcept;
};

} // namespace ObsidianGuard

#endif // OBSIDIAN_GUARD_MLKEM768_HPP
