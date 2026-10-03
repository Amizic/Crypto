#pragma once

// ObsidianGuard - crypto_types.hpp
// ---------------------------------------------------------------------------
// Common result type and the library import/export macro.
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

/// Result of every crypto operation.
/// code == 0 means success, a negative code means failure.
struct OBSIDIAN_GUARD_API CryptoResult {
    int code = 0;        ///< 0 on success, negative on error.
    std::string message; ///< human readable error description.

    bool ok() const noexcept { return code == 0; }

    static CryptoResult success() noexcept { return CryptoResult{0, std::string()}; }

    static CryptoResult failure(int code, std::string message) {
        return CryptoResult{code, std::move(message)};
    }
};

} // namespace ObsidianGuard
