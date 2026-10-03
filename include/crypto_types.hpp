#pragma once

// ObsidianGuard - crypto_types.hpp
// ---------------------------------------------------------------------------
// Common result type, the standard error code categories, and the library
// import/export macro.
//
// OBSIDIAN_GUARD_API
//   * building ObsidianGuard as a shared library: OBSIDIAN_GUARD_EXPORTS is defined
//     for the library's own translation units  -> __declspec(dllexport)
//   * consuming ObsidianGuard as a shared library: OBSIDIAN_GUARD_SHARED is defined
//     (public compile definition)              -> __declspec(dllimport)
//   * static builds define neither             -> plain symbols
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <utility>

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(OBSIDIAN_GUARD_SHARED)
#    if defined(OBSIDIAN_GUARD_EXPORTS)
#      define OBSIDIAN_GUARD_API __declspec(dllexport)
#    else
#      define OBSIDIAN_GUARD_API __declspec(dllimport)
#    endif
#  else
#    define OBSIDIAN_GUARD_API
#  endif
#else
#  define OBSIDIAN_GUARD_API __attribute__((visibility("default")))
#endif

namespace ObsidianGuard {

/// Standard failure categories used as CryptoResult::code.
///
/// Every failure reported by the library carries one of these negative
/// values, so callers can distinguish "the input was wrong" from "the
/// ciphertext was tampered with" without parsing the message text.
/// 0 (Success) is the only non-negative value the library ever returns.
enum class CryptoErrorCode : int {
    Success         = 0,   ///< no error
    InvalidArgument = -1,  ///< bad input (wrong size, null key, empty buffer, ...)
    OpenSslFailure  = -2,  ///< the underlying OpenSSL call failed
    AuthFailed      = -3,  ///< authentication/verification failed (wrong key, nonce, tag or signature)
    Unavailable     = -4,  ///< the algorithm is not available in this OpenSSL build
    Internal        = -5,  ///< unexpected internal failure
};

/// Result of every crypto operation.
/// code == 0 means success, a negative code means failure. Failure codes are
/// the CryptoErrorCode categories above (compare with e.g.
/// `result.code == static_cast<int>(CryptoErrorCode::AuthFailed)`).
struct OBSIDIAN_GUARD_API CryptoResult {
    int code = 0;        ///< 0 on success, a negative CryptoErrorCode on error.
    std::string message; ///< human readable error description.

    bool ok() const noexcept { return code == 0; }

    static CryptoResult success() noexcept { return CryptoResult{0, std::string()}; }

    static CryptoResult failure(int code, std::string message) {
        return CryptoResult{code, std::move(message)};
    }
};

} // namespace ObsidianGuard
