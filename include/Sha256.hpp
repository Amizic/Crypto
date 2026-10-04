// One-shot SHA-256 / SHA-512 hashing.
//
// The class is stateless, so it is trivially thread-safe: any number of
// threads may share one instance concurrently. Every method returns 0 on
// success or a negative return code on failure.
#ifndef OBSIDIAN_GUARD_SHA256_HPP
#define OBSIDIAN_GUARD_SHA256_HPP

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

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ObsidianGuard {

class OBSIDIAN_GUARD_API Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;    // SHA-256 digest
    static constexpr std::size_t kDigest512Size = 64; // SHA-512 digest

    // Return codes (see README for the full table).
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input (wrong size, ...)
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (parity with ObsidianGuardLite)

    /// Human readable algorithm identifier ("SHA-256 / SHA-512").
    const char* algorithmName() const noexcept;

    /// SHA-256 of message into digest (32 bytes). Empty input is valid
    /// (returns the well-known digest of the empty string).
    int hash(const std::vector<uint8_t>& message,
             std::vector<uint8_t>& digest) noexcept;

    /// SHA-512 of message into digest (64 bytes). Empty input is valid.
    int hash512(const std::vector<uint8_t>& message,
                std::vector<uint8_t>& digest) noexcept;
};

} // namespace ObsidianGuard

#endif // OBSIDIAN_GUARD_SHA256_HPP
