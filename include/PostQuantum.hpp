// Post-quantum hybrid encryption: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.
//
// encrypt() encapsulates a fresh ML-KEM-768 shared secret to the recipient's
// public key, derives an AES-256 key from it with HKDF-SHA256, and encrypts
// the message with AES-256-GCM — binding the KEM ciphertext as associated
// data, so the whole envelope is authenticated. decrypt() reverses the
// process.
//
// Envelope layout (binary):
//   [ 4-byte little-endian KEM ciphertext length ][ KEM ciphertext ]
//   [ AES-256-GCM: 12-byte IV ][ ciphertext ][ 16-byte tag ]
//
// The class is stateless, so it is trivially thread-safe: any number of
// threads may share one instance concurrently. Every method returns 0 on
// success or a negative return code on failure.
#ifndef CRYPTO_POSTQUANTUM_HPP
#define CRYPTO_POSTQUANTUM_HPP

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

#include <cstdint>
#include <vector>

namespace Crypto {

class CRYPTO_API PostQuantum {
public:
    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with CryptoLite)

    /// Human readable algorithm identifier ("ML-KEM-768 + HKDF-SHA256 + AES-256-GCM").
    const char* algorithmName() const noexcept;

    /// Seal plaintext to the recipient's DER-encoded ML-KEM-768 public key
    /// (from MlKem768::generateKeyPair). Returns 0 on success.
    int encrypt(const std::vector<uint8_t>& recipientPublicKey,
                const std::vector<uint8_t>& plaintext,
                std::vector<uint8_t>& envelope) noexcept;

    /// Open an envelope with the recipient's DER-encoded ML-KEM-768 secret
    /// key. Fails with kErrAuth if the envelope was tampered with or was
    /// sealed to a different key.
    int decrypt(const std::vector<uint8_t>& recipientSecretKey,
                const std::vector<uint8_t>& envelope,
                std::vector<uint8_t>& plaintext) noexcept;
};

} // namespace Crypto

#endif // CRYPTO_POSTQUANTUM_HPP
