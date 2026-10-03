#pragma once

// ObsidianGuard - src/error_utils.hpp
// Internal error helpers shared by the module implementations. This header is
// private to the library and is not installed.
//
// Every helper returns a CryptoResult whose code is one of the standard
// CryptoErrorCode categories; the distinct negative codes are the public
// contract that lets callers tell failure classes apart.

#include <openssl/err.h>

#include <string>
#include <utility>

#include "crypto_types.hpp"

namespace ObsidianGuard {
namespace detail {

/// Append the human readable text of the OpenSSL error queue to context and
/// drain the queue. The queue is thread-local (OpenSSL >= 1.1.0), so this
/// only ever touches the calling thread's errors.
inline void appendOpenSslQueue(std::string& context) noexcept {
    const unsigned long errorCode = ERR_get_error();
    if (errorCode != 0UL) {
        context += ": ";
        context += ERR_error_string(errorCode, nullptr);
    }
    while (ERR_get_error() != 0UL) {
        // drain anything else left in the error queue
    }
}

/// Failure caused by an invalid argument (no OpenSSL error involved).
inline CryptoResult paramFailure(std::string message) noexcept {
    return CryptoResult::failure(static_cast<int>(CryptoErrorCode::InvalidArgument),
                                 std::move(message));
}

/// Failure reported by OpenSSL; the queue text is appended when available.
inline CryptoResult openSslFailure(std::string context) noexcept {
    appendOpenSslQueue(context);
    return CryptoResult::failure(static_cast<int>(CryptoErrorCode::OpenSslFailure),
                                 std::move(context));
}

/// Authentication or verification failure: a wrong key, nonce (IV), tag or
/// signature. The OpenSSL queue is drained as well, so a queue entry left by
/// the failed check still lands in the description.
inline CryptoResult authFailure(std::string context) noexcept {
    appendOpenSslQueue(context);
    return CryptoResult::failure(static_cast<int>(CryptoErrorCode::AuthFailed),
                                 std::move(context));
}

/// The requested algorithm is not available in this OpenSSL build.
inline CryptoResult unavailableFailure(std::string message) noexcept {
    return CryptoResult::failure(static_cast<int>(CryptoErrorCode::Unavailable),
                                 std::move(message));
}

/// Unexpected internal failure (reserved for future use).
inline CryptoResult internalFailure(std::string message) noexcept {
    return CryptoResult::failure(static_cast<int>(CryptoErrorCode::Internal),
                                 std::move(message));
}

} // namespace detail
} // namespace ObsidianGuard
