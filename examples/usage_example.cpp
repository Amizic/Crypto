// ObsidianGuard - examples/usage_example.cpp
//
// End-to-end demonstration of every ObsidianGuard module:
//   * Aes256GcmModule : key/nonce generation, encrypt, decrypt, tag tampering
//   * Rsa4096Module   : key pair, OAEP encrypt/decrypt, PSS sign/verify
//   * MlKem768Module  : key pair, KEM encapsulate/decapsulate
//
// Every call is checked through CryptoResult and, on failure, the stored
// description is shown through getLastError().

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "aes256_gcm.hpp"
#include "crypto_module.hpp"
#include "crypto_types.hpp"
#include "ml_kem768.hpp"
#include "openssl_raii.hpp"
#include "rsa4096.hpp"

namespace {

int gFailureCount = 0;

void report(const char* label, const ObsidianGuard::CryptoResult& result) {
    std::cout << "  [";
    if (result.ok()) {
        std::cout << " OK ] ";
    } else {
        ++gFailureCount;
        std::cout << "FAIL] ";
    }
    std::cout << label;
    if (!result.ok()) {
        std::cout << " -> code " << result.code << ": " << result.message;
    }
    std::cout << '\n';
}

void showLastError(const ObsidianGuard::ICryptoModule& module) {
    std::cout << "        getLastError(): \"" << module.getLastError() << "\"\n";
}

void printHex(const char* label, const std::vector<uint8_t>& bytes,
              std::size_t maxBytes = 16) {
    static const char* kHex = "0123456789abcdef";
    std::cout << "    " << label << " (" << bytes.size() << " bytes): ";
    const std::size_t count = bytes.size() < maxBytes ? bytes.size() : maxBytes;
    for (std::size_t i = 0; i < count; ++i) {
        std::cout << kHex[bytes[i] >> 4] << kHex[bytes[i] & 0x0Fu];
    }
    if (count < bytes.size()) {
        std::cout << "...";
    }
    std::cout << '\n';
}

bool sha256(const std::vector<uint8_t>& message, std::vector<uint8_t>& digest) {
    ObsidianGuard::EvpMdCtxPtr digestContext = ObsidianGuard::makeMdCtx();
    if (!digestContext) {
        return false;
    }
    unsigned int digestLength = 0;
    digest.resize(32);
    if (EVP_DigestInit_ex(digestContext.get(), EVP_sha256(), nullptr) != 1) {
        return false;
    }
    if (EVP_DigestUpdate(digestContext.get(), message.data(), message.size()) != 1) {
        return false;
    }
    if (EVP_DigestFinal_ex(digestContext.get(), digest.data(), &digestLength) != 1) {
        return false;
    }
    digest.resize(digestLength);
    return true;
}

void testAes256Gcm() {
    std::cout << "== Module 1: AES-256-GCM ==\n";
    ObsidianGuard::Aes256GcmModule module;
    std::cout << "  algorithmName(): " << module.algorithmName() << "\n";

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    report("generateKey (32 bytes)", module.generateKey(key));
    report("generateIv  (12-byte nonce)", module.generateIv(nonce));

    const std::string message = "The quick brown fox jumps over the lazy dog";
    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    std::array<uint8_t, 16> tag{};

    report("encrypt", module.encrypt(plaintext, key, nonce, ciphertext, tag));
    printHex("ciphertext", ciphertext);
    printHex("auth tag", std::vector<uint8_t>(tag.begin(), tag.end()));

    report("decrypt", module.decrypt(ciphertext, key, nonce,
                                     std::vector<uint8_t>(tag.begin(), tag.end()),
                                     decrypted));
    if (decrypted == plaintext) {
        std::cout << "  [ OK ] AES round-trip: plaintext recovered exactly\n";
    } else {
        ++gFailureCount;
        std::cout << "  [FAIL] AES round-trip: plaintext mismatch\n";
    }

    // Negative test: corrupt one byte of the tag -> decryption must fail.
    std::cout << "  Negative test (corrupted tag, failure expected):\n";
    std::vector<uint8_t> corruptedTag(tag.begin(), tag.end());
    corruptedTag[0] ^= 0xFFu;
    const ObsidianGuard::CryptoResult result =
        module.decrypt(ciphertext, key, nonce, corruptedTag, decrypted);
    if (result.ok()) {
        ++gFailureCount;
        std::cout << "  [FAIL] decryption accepted a corrupted tag\n";
    } else {
        std::cout << "  [ OK ] decryption correctly rejected, code " << result.code
                  << ": " << result.message << "\n";
        showLastError(module);
    }
    module.clearError();
    std::cout << "  after clearError(): getLastError() -> \""
              << module.getLastError() << "\"\n";
}

void testRsa4096() {
    std::cout << "\n== Module 2: RSA-4096 ==\n";
    ObsidianGuard::Rsa4096Module module;
    std::cout << "  algorithmName(): " << module.algorithmName() << "\n";

    EVP_PKEY* rawKey = nullptr;
    report("generateKeyPair", module.generateKeyPair(&rawKey));
    if (rawKey == nullptr) {
        std::cout << "  (skipping the remaining RSA tests: no key material)\n";
        return;
    }
    // RAII: ownership of the OpenSSL key is transferred to a unique_ptr.
    ObsidianGuard::EvpPkeyPtr keyPair = ObsidianGuard::wrapPkey(rawKey);

    // --- OAEP encryption ---
    const std::string message = "RSA-4096 OAEP test message (64 bytes of payload data)!!!";
    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    report("encrypt (OAEP-SHA256)", module.encrypt(keyPair.get(), plaintext, ciphertext));
    report("decrypt (OAEP-SHA256)", module.decrypt(keyPair.get(), ciphertext, decrypted));
    if (decrypted == plaintext) {
        std::cout << "  [ OK ] RSA round-trip: plaintext recovered exactly\n";
    } else {
        ++gFailureCount;
        std::cout << "  [FAIL] RSA round-trip: plaintext mismatch\n";
    }

    // --- PSS signatures ---
    std::vector<uint8_t> digest;
    std::vector<uint8_t> signature;
    if (!sha256(plaintext, digest)) {
        ++gFailureCount;
        std::cout << "  [FAIL] SHA-256 digest computation failed\n";
        return;
    }
    printHex("SHA-256 digest", digest);
    report("sign   (PSS-SHA256)", module.sign(keyPair.get(), digest, signature));
    printHex("signature", signature, 32);
    report("verify (PSS-SHA256)", module.verify(keyPair.get(), digest, signature));

    // Negative test: corrupt one byte of the signature -> verify must fail.
    std::cout << "  Negative test (corrupted signature, failure expected):\n";
    std::vector<uint8_t> corruptedSignature = signature;
    corruptedSignature[corruptedSignature.size() / 2] ^= 0x01u;
    const ObsidianGuard::CryptoResult result =
        module.verify(keyPair.get(), digest, corruptedSignature);
    if (result.ok()) {
        ++gFailureCount;
        std::cout << "  [FAIL] verification accepted a corrupted signature\n";
    } else {
        std::cout << "  [ OK ] verification correctly rejected, code " << result.code
                  << ": " << result.message << "\n";
        showLastError(module);
    }
    module.clearError();
}

void testMlKem768() {
    std::cout << "\n== Module 3: ML-KEM-768 (post-quantum KEM) ==\n";
    ObsidianGuard::MlKem768Module module;
    std::cout << "  algorithmName(): " << module.algorithmName() << "\n";

    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecretA;
    std::vector<uint8_t> sharedSecretB;

    report("generateKeyPair", module.generateKeyPair(publicKey, secretKey));
    if (publicKey.empty()) {
        std::cout << "  (skipping the remaining ML-KEM tests: no key material)\n";
        if (!module.getLastError().empty()) {
            showLastError(module);
        }
        return;
    }
    std::cout << "    public key: " << publicKey.size()
              << " bytes, secret key: " << secretKey.size() << " bytes\n";

    report("encapsulate", module.encapsulate(publicKey, ciphertext, sharedSecretA));
    printHex("KEM ciphertext", ciphertext);
    report("decapsulate", module.decapsulate(ciphertext, secretKey, sharedSecretB));

    if (!sharedSecretA.empty() && sharedSecretA == sharedSecretB) {
        std::cout << "  [ OK ] KEM round-trip: both sides derived the same shared secret\n";
        printHex("shared secret", sharedSecretA);
    } else {
        ++gFailureCount;
        std::cout << "  [FAIL] KEM shared secrets differ\n";
    }

    // ML-KEM property: decapsulating a corrupted ciphertext still "succeeds"
    // (implicit rejection) but yields a different, pseudorandom secret.
    std::cout << "  Tampered ciphertext (implicit rejection, secret must differ):\n";
    std::vector<uint8_t> corruptedCiphertext = ciphertext;
    corruptedCiphertext[0] ^= 0xFFu;
    std::vector<uint8_t> rejectedSecret;
    const ObsidianGuard::CryptoResult result =
        module.decapsulate(corruptedCiphertext, secretKey, rejectedSecret);
    if (!result.ok()) {
        std::cout << "  [ OK ] decapsulation rejected the ciphertext, code "
                  << result.code << ": " << result.message << "\n";
    } else if (rejectedSecret == sharedSecretA) {
        ++gFailureCount;
        std::cout << "  [FAIL] tampered ciphertext yielded the original shared secret\n";
    } else {
        std::cout << "  [ OK ] implicit rejection: different secret, no error surfaced\n";
    }
}

} // namespace

int main() {
    std::cout << "============================================================\n";
    std::cout << " ObsidianGuard usage example (C++17 + OpenSSL)\n";
    std::cout << " OpenSSL runtime version: " << OpenSSL_version(OPENSSL_VERSION) << "\n";
    std::cout << "============================================================\n\n";

    testAes256Gcm();
    testRsa4096();
    testMlKem768();

    std::cout << "\n============================================================\n";
    if (gFailureCount == 0) {
        std::cout << " ALL TESTS PASSED\n";
    } else {
        std::cout << " " << gFailureCount << " TEST(S) FAILED\n";
    }
    std::cout << "============================================================\n";

#if defined(_WIN32)
    std::system("pause");
#else
    std::cout << "Press Enter to continue...";
    std::cin.get();
#endif
    return gFailureCount == 0 ? 0 : 1;
}
