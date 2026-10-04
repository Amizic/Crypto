// ObsidianGuard - examples/usage_example.cpp
//
// End-to-end demonstration of every ObsidianGuard class:
//   * Aes256      : key/nonce generation, encrypt, decrypt, tag tampering, AAD
//   * Rsa4096     : key pair, OAEP encrypt/decrypt, PSS sign/verify, PEM keys
//   * MlKem768    : key pair, KEM encapsulate/decapsulate
//   * Hkdf/Sha256 : key derivation and hashing
//   * PostQuantum : one-call hybrid encryption envelope
//
// The API is intentionally minimal: one header (obsidianguard.hpp), plain
// int return codes (0 = ok, negative = kErr*), and negative tests that show
// how each failure class surfaces as a distinct code.

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "obsidianguard.hpp"

namespace {

int gFailureCount = 0;

const char* codeName(int code) {
    switch (code) {
        case 0:  return "Ok";
        case -1: return "InvalidArgument";
        case -2: return "OpenSslFailure";
        case -3: return "AuthFailed";
        case -4: return "Unavailable";
        case -5: return "Internal";
        case -6: return "ErrFile";
    }
    return "Unknown";
}

void report(const char* label, int rc) {
    std::cout << "  [";
    if (rc == 0) {
        std::cout << " OK ] ";
    } else {
        ++gFailureCount;
        std::cout << "FAIL] ";
    }
    std::cout << label;
    if (rc != 0) {
        std::cout << " -> code " << rc << " (" << codeName(rc) << ")";
    }
    std::cout << '\n';
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
    std::cout << "== Class 1: AES-256-GCM ==\n";
    ObsidianGuard::Aes256 module;
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
    const int rc = module.decrypt(ciphertext, key, nonce, corruptedTag, decrypted);
    if (rc == 0) {
        ++gFailureCount;
        std::cout << "  [FAIL] decryption accepted a corrupted tag\n";
    } else {
        std::cout << "  [ OK ] decryption correctly rejected, code " << rc << " ("
                  << codeName(rc) << ")\n";
    }
}

void testRsa4096() {
    std::cout << "\n== Class 2: RSA-4096 ==\n";
    ObsidianGuard::Rsa4096 module;
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
    const int rc = module.verify(keyPair.get(), digest, corruptedSignature);
    if (rc == 0) {
        ++gFailureCount;
        std::cout << "  [FAIL] verification accepted a corrupted signature\n";
    } else {
        std::cout << "  [ OK ] verification correctly rejected, code " << rc << " ("
                  << codeName(rc) << ")\n";
    }

    // --- key persistence (PEM) ---
    std::string publicPem;
    std::string privatePem;
    report("savePublicKeyPem", module.savePublicKeyPem(keyPair.get(), publicPem));
    report("savePrivateKeyPem", module.savePrivateKeyPem(keyPair.get(), privatePem));
    EVP_PKEY* loadedRaw = nullptr;
    report("loadPublicKeyPem", module.loadPublicKeyPem(publicPem, &loadedRaw));
    ObsidianGuard::EvpPkeyPtr loadedKey = ObsidianGuard::wrapPkey(loadedRaw);
    std::cout << "    public PEM: " << publicPem.size() << " chars\n";
    loadedRaw = nullptr;
    report("loadPrivateKeyPem", module.loadPrivateKeyPem(privatePem, &loadedRaw));
    loadedKey = ObsidianGuard::wrapPkey(loadedRaw);
    std::cout << "    private PEM: " << privatePem.size() << " chars\n";
}

void testMlKem768() {
    std::cout << "\n== Class 3: ML-KEM-768 (post-quantum KEM) ==\n";
    ObsidianGuard::MlKem768 module;
    std::cout << "  algorithmName(): " << module.algorithmName() << "\n";

    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecretA;
    std::vector<uint8_t> sharedSecretB;

    report("generateKeyPair", module.generateKeyPair(publicKey, secretKey));
    if (publicKey.empty()) {
        std::cout << "  (skipping the remaining ML-KEM tests: no key material)\n";
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
    const int rc = module.decapsulate(corruptedCiphertext, secretKey, rejectedSecret);
    if (rc != 0) {
        std::cout << "  [ OK ] decapsulation rejected the ciphertext, code "
                  << rc << " (" << codeName(rc) << ")\n";
    } else if (rejectedSecret == sharedSecretA) {
        ++gFailureCount;
        std::cout << "  [FAIL] tampered ciphertext yielded the original shared secret\n";
    } else {
        std::cout << "  [ OK ] implicit rejection: different secret, no error surfaced\n";
    }
}

void testHkdfAndSha() {
    std::cout << "\n== Class 4: HKDF + SHA-256 ==\n";
    ObsidianGuard::Hkdf hkdf;
    ObsidianGuard::Sha256 sha;
    std::cout << "  algorithmName(): " << hkdf.algorithmName() << "\n";
    std::cout << "  algorithmName(): " << sha.algorithmName() << "\n";

    const std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> digest;
    report("sha256(\"hello\")", sha.hash(message, digest));
    printHex("digest", digest);

    std::vector<uint8_t> derived;
    report("hkdf.derive(32 bytes)", hkdf.derive(message, std::vector<uint8_t>(),
                                                std::vector<uint8_t>(), 32, derived));
    printHex("derived key", derived);
}

void testHybridEnvelope() {
    std::cout << "\n== Class 5: PostQuantum hybrid envelope ==\n";
    ObsidianGuard::PostQuantum module;
    ObsidianGuard::MlKem768 kem;
    std::cout << "  algorithmName(): " << module.algorithmName() << "\n";

    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    report("generateKeyPair", kem.generateKeyPair(publicKey, secretKey));
    if (publicKey.empty()) {
        std::cout << "  (skipping the hybrid tests: no key material)\n";
        return;
    }

    const std::string message = "A hybrid-encrypted message, one call";
    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> envelope;
    std::vector<uint8_t> decrypted;
    report("encrypt (seal)", module.encrypt(publicKey, plaintext, envelope));
    printHex("envelope", envelope, 24);
    report("decrypt (open)", module.decrypt(secretKey, envelope, decrypted));
    if (decrypted == plaintext) {
        std::cout << "  [ OK ] hybrid round-trip: message recovered exactly\n";
    } else {
        ++gFailureCount;
        std::cout << "  [FAIL] hybrid round-trip: message mismatch\n";
    }

    // Negative test: tamper one byte of the envelope -> decryption must fail.
    std::cout << "  Negative test (tampered envelope, failure expected):\n";
    std::vector<uint8_t> tampered = envelope;
    tampered[tampered.size() - 1] ^= 0xFFu;
    const int rc = module.decrypt(secretKey, tampered, decrypted);
    if (rc == 0) {
        ++gFailureCount;
        std::cout << "  [FAIL] decryption accepted a tampered envelope\n";
    } else {
        std::cout << "  [ OK ] decryption correctly rejected, code " << rc << " ("
                  << codeName(rc) << ")\n";
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
    testHkdfAndSha();
    testHybridEnvelope();

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
