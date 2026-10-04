#pragma once

// ObsidianGuard - OpensslRaii.hpp
// Centralized RAII wrappers for every OpenSSL resource used by ObsidianGuard.
// All OpenSSL pointers are owned by std::unique_ptr with the matching
// *_free() function as deleter; no manual frees exist anywhere in the
// library. Use these factories (or wrapPkey for keys returned by
// Rsa4096::generateKeyPair) instead of raw OpenSSL pointers.

#include <memory>

#include <openssl/evp.h>

namespace ObsidianGuard {

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using EvpMdCtxPtr     = std::unique_ptr<EVP_MD_CTX,     decltype(&EVP_MD_CTX_free)>;
using EvpPkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX,   decltype(&EVP_PKEY_CTX_free)>;
using EvpPkeyPtr      = std::unique_ptr<EVP_PKEY,       decltype(&EVP_PKEY_free)>;

/// New cipher context (EVP_CIPHER_CTX_new / EVP_CIPHER_CTX_free).
inline EvpCipherCtxPtr makeCipherCtx() noexcept {
    return EvpCipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
}

/// New digest context (EVP_MD_CTX_new / EVP_MD_CTX_free).
inline EvpMdCtxPtr makeMdCtx() noexcept {
    return EvpMdCtxPtr(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
}

/// Key context for operations with an existing key (EVP_PKEY_CTX_new).
inline EvpPkeyCtxPtr makePkeyCtx(EVP_PKEY* key) noexcept {
    return EvpPkeyCtxPtr(EVP_PKEY_CTX_new(key, nullptr), &EVP_PKEY_CTX_free);
}

/// Key context for key generation from an algorithm name (e.g. "ML-KEM-768").
inline EvpPkeyCtxPtr makePkeyCtxFromName(const char* name) noexcept {
    return EvpPkeyCtxPtr(EVP_PKEY_CTX_new_from_name(nullptr, name, nullptr),
                         &EVP_PKEY_CTX_free);
}

/// Key context for key generation from an algorithm id (e.g. EVP_PKEY_RSA).
inline EvpPkeyCtxPtr makePkeyCtxFromId(int id) noexcept {
    return EvpPkeyCtxPtr(EVP_PKEY_CTX_new_id(id, nullptr), &EVP_PKEY_CTX_free);
}

/// Take ownership of a raw EVP_PKEY produced by e.g.
/// Rsa4096::generateKeyPair(); releases it with EVP_PKEY_free().
inline EvpPkeyPtr wrapPkey(EVP_PKEY* key) noexcept {
    return EvpPkeyPtr(key, &EVP_PKEY_free);
}

} // namespace ObsidianGuard
