// HKDF-SHA256 key derivation (RFC 5869).
//
// Derives cryptographically independent keys from input key material
// (e.g. a KEM shared secret or a master key). The salt and info parameters
// are optional (empty = not used).
//
// The class is stateless, so it is trivially thread-safe: any number of
// threads may share one instance concurrently. Every method returns 0 on
// success or a negative return code on failure.
#ifndef CRYPTO_HKDF_HPP
#define CRYPTO_HKDF_HPP

// DLL import/export macro (Windows).
#ifndef CRYPTO_API
    #ifdef CRYPTO_STATIC
        #define CRYPTO_API
    #elif defined(CRYPTO_EXPORTS)
        #define CRYPTO_API __declspec(dllexport)
    #else
        #define CRYPTO_API __declspec(dllimport)
    #endif
#endif

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Crypto {

class CRYPTO_API Hkdf {
public:
    /// Maximum output length per RFC 5869 (255 * hash length for SHA-256).
    static constexpr std::size_t kMaxOutputLength = 255 * 32;

    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with CryptoLite)

    /// Human readable algorithm identifier ("HKDF-SHA256 (RFC 5869)").
    const char* algorithmName() const noexcept;

    /// Derive outputLength bytes of key material from the input key
    /// material, using the optional salt and info. Returns 0 on success.
    /// Fails with kErrInvalidArgument for empty input key material or an
    /// outputLength of 0 or more than kMaxOutputLength.
    int derive(const std::vector<uint8_t>& inputKeyMaterial,
               const std::vector<uint8_t>& salt,
               const std::vector<uint8_t>& info,
               std::size_t outputLength,
               std::vector<uint8_t>& output) noexcept;
};

} // namespace Crypto

#endif // CRYPTO_HKDF_HPP
