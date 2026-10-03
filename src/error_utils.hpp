#pragma once

// ObsidianGuard - src/error_utils.hpp
// Internal error helpers shared by the module implementations. This header is
// private to the library and is not installed.

#include <openssl/err.h>

#include <string>
#include <utility>

#include "crypto_types.hpp"

namespace ObsidianGuard {
namespace detail {

constexpr int kErrorCode = -1;

/// Build a CryptoResult::failure from the OpenSSL error queue.
/// The human readable description comes from
/// ERR_error_string(ERR_get_error(), nullptr); if the queue is empty the
/// supplied context string is used on its own. The queue is drained and the
/// description is stored in *lastError so getLastError() reports it as well.
inline CryptoResult openSslFailure(std::string context, std::string* lastError) noexcept {
    const unsigned long errorCode = ERR_get_error();
    if (errorCode != 0UL) {
        context += ": ";
        context += ERR_error_string(errorCode, nullptr);
    }
    while (ERR_get_error() != 0UL) {
        // drain anything else left in the error queue
    }
    *lastError = context;
    return CryptoResult::failure(kErrorCode, std::move(context));
}

/// Build a failure for an invalid argument (no OpenSSL error involved).
inline CryptoResult paramFailure(std::string message, std::string* lastError) noexcept {
    *lastError = message;
    return CryptoResult::failure(kErrorCode, std::move(message));
}

} // namespace detail
} // namespace ObsidianGuard
