// Crypto - src/Hkdf.cpp
// HKDF-SHA256 key derivation (RFC 5869).

#include "Hkdf.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <climits>
#include <cstddef>
#include <vector>

#include "OpensslRaii.hpp"

namespace Crypto {

const char* Hkdf::algorithmName() const noexcept {
    return "HKDF-SHA256 (RFC 5869)";
}

int Hkdf::derive(const std::vector<uint8_t>& inputKeyMaterial,
                 const std::vector<uint8_t>& salt,
                 const std::vector<uint8_t>& info,
                 std::size_t outputLength,
                 std::vector<uint8_t>& output) noexcept {
    ERR_clear_error();
    output.clear();

    if (inputKeyMaterial.empty()) {
        return kErrInvalidArgument;
    }
    if (inputKeyMaterial.size() > static_cast<std::size_t>(INT_MAX) ||
        salt.size() > static_cast<std::size_t>(INT_MAX) ||
        info.size() > static_cast<std::size_t>(INT_MAX)) {
        return kErrInvalidArgument;
    }
    if (outputLength == 0 || outputLength > kMaxOutputLength) {
        return kErrInvalidArgument;
    }

    EvpPkeyCtxPtr context = makePkeyCtxFromId(EVP_PKEY_HKDF);
    if (!context) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_derive_init(context.get()) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha256()) != 1) {
        return kErrOpenSsl;
    }
    if (!salt.empty() &&
        EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt.data(),
                                    static_cast<int>(salt.size())) != 1) {
        return kErrOpenSsl;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(context.get(), inputKeyMaterial.data(),
                                   static_cast<int>(inputKeyMaterial.size())) != 1) {
        return kErrOpenSsl;
    }
    if (!info.empty() &&
        EVP_PKEY_CTX_add1_hkdf_info(context.get(), info.data(),
                                    static_cast<int>(info.size())) != 1) {
        return kErrOpenSsl;
    }

    output.resize(outputLength);
    std::size_t derivedLength = outputLength;
    if (EVP_PKEY_derive(context.get(), output.data(), &derivedLength) != 1) {
        output.clear();
        return kErrOpenSsl;
    }
    output.resize(derivedLength);
    return kOk;
}

} // namespace Crypto
