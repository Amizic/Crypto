// AES-256-GCM authenticated encryption, with optional associated data (AAD).
//
// 32-byte keys, 12-byte nonces (IVs), 16-byte authentication tags. Decryption
// verifies the tag (and the AAD) and fails on any tampering.
//
// The class is stateless, so it is trivially thread-safe: any number of
// threads may share one instance (or use separate instances) concurrently.
// Every method returns 0 on success or a negative return code on failure
// (see the kErr* constants).
#ifndef CRYPTO_AES256_HPP
#define CRYPTO_AES256_HPP

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

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Crypto {

class CRYPTO_API Aes256 {
public:
    static constexpr std::size_t kKeySize = 32; // bytes = 256 bits
    static constexpr std::size_t kIvSize  = 12; // bytes = 96 bits (GCM)
    static constexpr std::size_t kTagSize = 16; // bytes = 128 bits

    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with CryptoLite)

    /// Human readable algorithm identifier ("AES-256-GCM").
    const char* algorithmName() const noexcept;

    /// Generate a random 32-byte AES-256 key.
    int generateKey(std::vector<uint8_t>& key) noexcept;

    /// Generate a random 12-byte GCM nonce (IV).
    int generateIv(std::vector<uint8_t>& nonce) noexcept;

    /// Encrypt with AES-256-GCM. On success the ciphertext has the same size
    /// as the plaintext and tag receives the 16-byte authentication tag.
    int encrypt(const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& nonce,
                std::vector<uint8_t>& ciphertext,
                std::array<uint8_t, 16>& tag) noexcept;

    /// Encrypt with AES-256-GCM and bind associated data into the
    /// authentication tag. AAD (headers, IDs, metadata) is authenticated but
    /// not encrypted; tampering with either the ciphertext or the AAD is
    /// detected at decryption. May be empty (equivalent to the overload
    /// above).
    int encrypt(const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& nonce,
                const std::vector<uint8_t>& aad,
                std::vector<uint8_t>& ciphertext,
                std::array<uint8_t, 16>& tag) noexcept;

    /// Decrypt and authenticate with AES-256-GCM. Fails with kErrAuth
    /// (without output) if the key, nonce (IV) or tag does not match the
    /// ciphertext.
    int decrypt(const std::vector<uint8_t>& ciphertext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& nonce,
                const std::vector<uint8_t>& tag,
                std::vector<uint8_t>& plaintext) noexcept;

    /// Decrypt with AES-256-GCM using the same associated data that was
    /// bound into the tag at encryption. Fails with kErrAuth if the AAD,
    /// key, nonce (IV) or tag does not match.
    int decrypt(const std::vector<uint8_t>& ciphertext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& nonce,
                const std::vector<uint8_t>& aad,
                const std::vector<uint8_t>& tag,
                std::vector<uint8_t>& plaintext) noexcept;

    // ---- convenience overloads (auto nonce) ------------------------------
    /// Encrypt with a freshly generated random nonce (IV) and prepend it to
    /// the output: [IV][ciphertext][tag]. The IV is generated internally, so
    /// it can never be accidentally reused; decrypt() parses it back out.
    int encrypt(const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& key,
                std::vector<uint8_t>& ciphertext) noexcept;

    /// Decrypt the [IV][ciphertext][tag] layout produced by the auto-nonce
    /// encrypt() overload above.
    int decrypt(const std::vector<uint8_t>& ciphertext,
                const std::vector<uint8_t>& key,
                std::vector<uint8_t>& plaintext) noexcept;
};

} // namespace Crypto

#endif // CRYPTO_AES256_HPP
