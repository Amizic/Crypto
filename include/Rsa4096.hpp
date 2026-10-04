// RSA-4096 asymmetric encryption (OAEP-SHA256) and signatures (PSS-SHA256).
//
// Encrypt with the public key, decrypt with the private key. Sign with the
// private key, verify with the public key. Keys are stored in standard PEM
// format or as DER bytes (in memory, so they can be sent over a wire).
// A 4096-bit key encrypts at most 446 bytes per call (OAEP-SHA256 overhead),
// so use RSA to wrap a symmetric key, not bulk data.
//
// The class is stateless (keys are passed in per call), so it is trivially
// thread-safe: any number of threads may share one instance concurrently.
// Every method returns 0 on success or a negative return code on failure.
#ifndef OBSIDIAN_GUARD_RSA4096_HPP
#define OBSIDIAN_GUARD_RSA4096_HPP

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

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "OpensslRaii.hpp"

namespace ObsidianGuard {

class OBSIDIAN_GUARD_API Rsa4096 {
public:
    static constexpr int kBits = 4096;
    static constexpr std::size_t kModulusSize = kBits / 8;                  // 512 bytes
    static constexpr std::size_t kMaxPlaintext = kModulusSize - 2 * 32 - 2; // 446 bytes

    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with ObsidianGuardLite)

    /// Human readable algorithm identifier ("RSA-4096 (OAEP-SHA256 / PSS-SHA256)").
    const char* algorithmName() const noexcept;

    /// Generate a 4096-bit RSA key pair.
    /// On success *outputKey points to a new EVP_PKEY; the caller takes
    /// ownership and must release it with EVP_PKEY_free() — easiest via
    /// ObsidianGuard::wrapPkey() (OpensslRaii.hpp).
    int generateKeyPair(EVP_PKEY** outputKey) noexcept;

    /// Encrypt with the public key (OAEP, SHA-256).
    int encrypt(EVP_PKEY* publicKey,
                const std::vector<uint8_t>& plaintext,
                std::vector<uint8_t>& ciphertext) noexcept;

    /// Decrypt with the private key (OAEP, SHA-256).
    int decrypt(EVP_PKEY* privateKey,
                const std::vector<uint8_t>& ciphertext,
                std::vector<uint8_t>& plaintext) noexcept;

    /// Sign a SHA-256 digest with the private key (PSS, SHA-256).
    int sign(EVP_PKEY* privateKey,
             const std::vector<uint8_t>& digest,
             std::vector<uint8_t>& signature) noexcept;

    /// Verify an RSA-PSS signature over a SHA-256 digest (public key).
    /// Returns kErrAuth when the signature does not match the digest.
    int verify(EVP_PKEY* publicKey,
               const std::vector<uint8_t>& digest,
               const std::vector<uint8_t>& signature) noexcept;

    // ---- key persistence (PEM / DER, in memory) ---------------------------
    // Save/load keys so they can be stored to disk or sent over a wire.
    // Loaded keys are returned as a new EVP_PKEY* owned by the caller
    // (wrap with ObsidianGuard::wrapPkey()).
    int savePublicKeyPem(EVP_PKEY* key, std::string& pem) noexcept;
    int loadPublicKeyPem(const std::string& pem, EVP_PKEY** outputKey) noexcept;
    int savePrivateKeyPem(EVP_PKEY* key, std::string& pem) noexcept;
    int loadPrivateKeyPem(const std::string& pem, EVP_PKEY** outputKey) noexcept;
    int savePublicKeyDer(EVP_PKEY* key, std::vector<uint8_t>& der) noexcept;
    int loadPublicKeyDer(const std::vector<uint8_t>& der, EVP_PKEY** outputKey) noexcept;
    int savePrivateKeyDer(EVP_PKEY* key, std::vector<uint8_t>& der) noexcept;
    int loadPrivateKeyDer(const std::vector<uint8_t>& der, EVP_PKEY** outputKey) noexcept;
};

} // namespace ObsidianGuard

#endif // OBSIDIAN_GUARD_RSA4096_HPP
