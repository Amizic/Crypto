// ObsidianGuard - src/Sha256.cpp
// One-shot SHA-256 / SHA-512 hashing.

#include "Sha256.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <vector>

#include "OpensslRaii.hpp"

namespace ObsidianGuard {
namespace {

int digestMessage(const std::vector<uint8_t>& message, const EVP_MD* algorithm,
                  std::vector<uint8_t>& digest) noexcept {
    ERR_clear_error();
    digest.clear();

    EvpMdCtxPtr context = makeMdCtx();
    if (!context) {
        return Sha256::kErrOpenSsl;
    }
    if (EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1) {
        return Sha256::kErrOpenSsl;
    }
    if (!message.empty() &&
        EVP_DigestUpdate(context.get(), message.data(), message.size()) != 1) {
        return Sha256::kErrOpenSsl;
    }
    digest.resize(EVP_MAX_MD_SIZE);
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestLength) != 1) {
        return Sha256::kErrOpenSsl;
    }
    digest.resize(digestLength);
    return Sha256::kOk;
}

} // namespace

const char* Sha256::algorithmName() const noexcept {
    return "SHA-256 / SHA-512";
}

int Sha256::hash(const std::vector<uint8_t>& message,
                 std::vector<uint8_t>& digest) noexcept {
    return digestMessage(message, EVP_sha256(), digest);
}

int Sha256::hash512(const std::vector<uint8_t>& message,
                    std::vector<uint8_t>& digest) noexcept {
    return digestMessage(message, EVP_sha512(), digest);
}

} // namespace ObsidianGuard
