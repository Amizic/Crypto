// Crypto - tests/test_main.cpp
//
// Dependency-free test suite for Crypto (no GoogleTest/Catch2; plain
// assertions wired into CTest).
//
// Coverage:
//   * error model          : 0 = success, distinct negative kErr* return
//                            codes shared by every class
//   * AES-256-GCM          : round trips (0..64 KiB), determinism, AAD, and
//                            every negative path with its exact error code
//   * RSA-4096             : OAEP/PSS round trips, param failures,
//                            padding error (-2) vs signature mismatch (-3)
//   * ML-KEM-768           : KEM round trip, implicit rejection, parse
//                            failures, unavailable-build behavior
//   * thread safety        : one shared (stateless) instance hammered by many
//                            threads
//
// Every check inside a worker thread goes through a per-thread atomic
// failure counter so the reporting counters stay single-threaded.

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  include <io.h>  // _isatty / _fileno: pause only for an interactive console
#endif

#include "Crypto.hpp"

namespace {

// ---------------------------------------------------------------------------
// Error code constants (public contract; compile-time checked as well).
// CryptoLite convention: every class exposes the same kOk / kErr*
// static constexpr int members.
// ---------------------------------------------------------------------------
constexpr int kOk              = Crypto::Aes256::kOk;
constexpr int kInvalidArgument = Crypto::Aes256::kErrInvalidArgument;
constexpr int kOpenSslFailure  = Crypto::Aes256::kErrOpenSsl;
constexpr int kAuthFailed      = Crypto::Aes256::kErrAuth;
constexpr int kUnavailable     = Crypto::Aes256::kErrUnavailable;
constexpr int kInternal        = Crypto::Aes256::kErrInternal;

static_assert(Crypto::Aes256::kOk == 0, "kOk must be 0");
static_assert(Crypto::Aes256::kErrInvalidArgument == -1,
              "kErrInvalidArgument must be -1");
static_assert(Crypto::Aes256::kErrOpenSsl == -2, "kErrOpenSsl must be -2");
static_assert(Crypto::Aes256::kErrAuth == -3, "kErrAuth must be -3");
static_assert(Crypto::Aes256::kErrUnavailable == -4, "kErrUnavailable must be -4");
static_assert(Crypto::Aes256::kErrInternal == -5, "kErrInternal must be -5");
static_assert(Crypto::Aes256::kErrFile == -6, "kErrFile must be -6");
// The same values must be exposed by every class.
static_assert(Crypto::Rsa4096::kErrAuth == Crypto::Aes256::kErrAuth,
              "Rsa4096 and Aes256 must share the codes");
static_assert(Crypto::MlKem768::kErrUnavailable ==
                  Crypto::Aes256::kErrUnavailable,
              "MlKem768 and Aes256 must share the codes");
static_assert(Crypto::Hkdf::kErrOpenSsl == Crypto::Aes256::kErrOpenSsl,
              "Hkdf and Aes256 must share the codes");
static_assert(Crypto::Sha256::kErrOpenSsl == Crypto::Aes256::kErrOpenSsl,
              "Sha256 and Aes256 must share the codes");
static_assert(Crypto::PostQuantum::kErrAuth == Crypto::Aes256::kErrAuth,
              "PostQuantum and Aes256 must share the codes");

// ---------------------------------------------------------------------------
// Minimal reporting harness
// ---------------------------------------------------------------------------
int gChecks = 0;
int gFailures = 0;
std::mutex gReportMutex;

void reportFailure(const char* file, int line, const std::string& message) {
    std::lock_guard<std::mutex> guard(gReportMutex);
    ++gFailures;
    std::cout << "  [FAIL] " << file << ":" << line << ": " << message << "\n";
}

void runSection(const char* name, void (*test)()) {
    std::cout << "== " << name << " ==\n";
    const int failuresBefore = gFailures;
    try {
        test();
    } catch (const std::exception& e) {
        reportFailure(name, 0, std::string("unexpected exception: ") + e.what());
    } catch (...) {
        reportFailure(name, 0, "unexpected non-standard exception");
    }
    if (gFailures == failuresBefore) {
        std::cout << "  [PASS]\n";
    }
}

} // namespace

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++gChecks;                                                             \
        if (!(cond)) {                                                         \
            ::reportFailure(__FILE__, __LINE__, std::string("CHECK(" #cond ")")); \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        ++gChecks;                                                             \
        const auto checkEqLhs = (a);                                           \
        const auto checkEqRhs = (b);                                           \
        if (!(checkEqLhs == checkEqRhs)) {                                     \
            std::ostringstream checkEqOs;                                      \
            checkEqOs << "CHECK_EQ(" #a ", " #b ") -> " << checkEqLhs          \
                      << " vs " << checkEqRhs;                                 \
            ::reportFailure(__FILE__, __LINE__, checkEqOs.str());              \
        }                                                                      \
    } while (0)

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
bool bytesEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a == b;
}

/// Deterministic xorshift64: reproducible test data without RAND_bytes.
uint64_t xorshift(uint64_t& state) noexcept {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

std::vector<uint8_t> pseudoRandomBytes(std::size_t count, uint64_t& state) {
    std::vector<uint8_t> out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = static_cast<uint8_t>(xorshift(state));
    }
    return out;
}

bool sha256Bytes(const std::vector<uint8_t>& message, std::vector<uint8_t>& digest) {
    Crypto::EvpMdCtxPtr context = Crypto::makeMdCtx();
    if (!context) {
        return false;
    }
    unsigned int digestLength = 0;
    digest.resize(32);
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        return false;
    }
    if (EVP_DigestUpdate(context.get(), message.data(), message.size()) != 1) {
        return false;
    }
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestLength) != 1) {
        return false;
    }
    digest.resize(digestLength);
    return true;
}

/// True when the test should wait for a keypress before exiting: only for an
/// interactive console (double-click or a terminal window). Piped/redirected
/// runs (CTest, CI) skip the pause, and CRYPTO_NO_PAUSE forces it off.
bool pauseRequested() {
#if defined(_WIN32)
    if (std::getenv("CRYPTO_NO_PAUSE") != nullptr) {
        return false;
    }
    return _isatty(_fileno(stdin)) != 0;
#else
    return std::getenv("CRYPTO_NO_PAUSE") == nullptr;
#endif
}

// ---------------------------------------------------------------------------
// 1. Error model
// ---------------------------------------------------------------------------
void testErrorModel() {
    Crypto::Aes256 module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("AES-256-GCM"));

    // A successful call returns exactly 0.
    std::vector<uint8_t> key;
    CHECK_EQ(module.generateKey(key), 0);
    CHECK_EQ(key.size(), std::size_t(32));

    // A failing call returns the exact negative category, never anything else.
    std::vector<uint8_t> plaintext{1, 2, 3};
    std::vector<uint8_t> badKey(31, 0x42);  // must be 32 bytes
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag{};
    const int rc = module.encrypt(plaintext, badKey, nonce, ciphertext, tag);
    CHECK(rc != 0);
    CHECK_EQ(rc, kInvalidArgument);

    // 0 means success, anything negative is a failure.
    CHECK_EQ(0, kOk);
    CHECK(kAuthFailed != 0);
}

// ---------------------------------------------------------------------------
// 2. AES-256-GCM round trips
// ---------------------------------------------------------------------------
void testAesRoundTrips() {
    Crypto::Aes256 module;

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    CHECK_EQ(module.generateKey(key), 0);
    CHECK_EQ(key.size(), std::size_t(32));
    CHECK_EQ(module.generateIv(nonce), 0);
    CHECK_EQ(nonce.size(), std::size_t(12));

    const std::size_t sizes[] = {0, 1, 16, 255, 1024, 65536};
    uint64_t state = 0x9E3779B97F4A7C15ull;
    for (const std::size_t size : sizes) {
        const std::vector<uint8_t> plaintext = pseudoRandomBytes(size, state);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;
        std::array<uint8_t, 16> tag{};

        CHECK_EQ(module.encrypt(plaintext, key, nonce, ciphertext, tag), 0);
        CHECK_EQ(ciphertext.size(), plaintext.size());
        CHECK_EQ(module.decrypt(ciphertext, key, nonce,
                                std::vector<uint8_t>(tag.begin(), tag.end()), decrypted),
                 0);
        CHECK(bytesEqual(decrypted, plaintext));
    }

    // GCM is deterministic for a fixed key/nonce: identical input must give
    // identical ciphertext and tag.
    const std::vector<uint8_t> plaintext(64, 0x5A);
    std::vector<uint8_t> ciphertextA;
    std::vector<uint8_t> ciphertextB;
    std::array<uint8_t, 16> tagA{};
    std::array<uint8_t, 16> tagB{};
    CHECK_EQ(module.encrypt(plaintext, key, nonce, ciphertextA, tagA), 0);
    CHECK_EQ(module.encrypt(plaintext, key, nonce, ciphertextB, tagB), 0);
    CHECK(ciphertextA == ciphertextB);
    CHECK(tagA == tagB);
}

// ---------------------------------------------------------------------------
// 3. AES-256-GCM error codes
// ---------------------------------------------------------------------------
void testAesErrorCodes() {
    Crypto::Aes256 module;

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    CHECK_EQ(module.generateKey(key), 0);
    CHECK_EQ(module.generateIv(nonce), 0);

    std::vector<uint8_t> plaintext(100, 0x11);
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag{};
    CHECK_EQ(module.encrypt(plaintext, key, nonce, ciphertext, tag), 0);
    const std::vector<uint8_t> goodTag(tag.begin(), tag.end());

    std::vector<uint8_t> out;
    std::array<uint8_t, 16> dummyTag{};

    // --- InvalidArgument (-1): wrong sizes --------------------------------
    const std::vector<uint8_t> key31(31, 0);
    const std::vector<uint8_t> key33(33, 0);
    const std::vector<uint8_t> nonce11(11, 0);
    const std::vector<uint8_t> nonce13(13, 0);
    CHECK_EQ(module.encrypt(plaintext, key31, nonce, out, dummyTag), kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key33, nonce, out, dummyTag), kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key, nonce11, out, dummyTag), kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key, nonce13, out, dummyTag), kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key31, nonce, goodTag, out), kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key, nonce11, goodTag, out), kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key, nonce, {0x01}, out), kInvalidArgument);

    // --- AuthFailed (-3): tampering ---------------------------------------
    std::vector<uint8_t> badTag = goodTag;
    badTag[0] ^= 0xFFu;
    int rc = module.decrypt(ciphertext, key, nonce, badTag, out);
    CHECK_EQ(rc, kAuthFailed);
    CHECK(out.empty());  // no plaintext-derived bytes escape on auth failure

    std::vector<uint8_t> badCiphertext = ciphertext;
    badCiphertext[3] ^= 0x80u;
    rc = module.decrypt(badCiphertext, key, nonce, goodTag, out);
    CHECK_EQ(rc, kAuthFailed);
    CHECK(out.empty());

    const std::vector<uint8_t> wrongKey(32, 0x77);
    rc = module.decrypt(ciphertext, wrongKey, nonce, goodTag, out);
    CHECK_EQ(rc, kAuthFailed);
    CHECK(out.empty());

    std::vector<uint8_t> wrongNonce = nonce;
    wrongNonce[0] ^= 0x01u;
    rc = module.decrypt(ciphertext, key, wrongNonce, goodTag, out);
    CHECK_EQ(rc, kAuthFailed);
    CHECK(out.empty());
}

// ---------------------------------------------------------------------------
// 4. RSA-4096
// ---------------------------------------------------------------------------
void testRsa() {
    Crypto::Rsa4096 module;
    CHECK_EQ(std::string(module.algorithmName()),
             std::string("RSA-4096 (OAEP-SHA256 / PSS-SHA256)"));

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    std::vector<uint8_t> signature;

    // --- InvalidArgument (-1): null/empty inputs, before any key exists ----
    CHECK_EQ(module.generateKeyPair(nullptr), kInvalidArgument);
    CHECK_EQ(module.encrypt(nullptr, std::vector<uint8_t>{1}, ciphertext),
             kInvalidArgument);
    CHECK_EQ(module.decrypt(nullptr, std::vector<uint8_t>{1}, decrypted),
             kInvalidArgument);
    CHECK_EQ(module.sign(nullptr, std::vector<uint8_t>{1}, signature),
             kInvalidArgument);
    CHECK_EQ(module.verify(nullptr, std::vector<uint8_t>{1},
                           std::vector<uint8_t>{1}),
             kInvalidArgument);

    EVP_PKEY* rawKey = nullptr;
    CHECK_EQ(module.generateKeyPair(&rawKey), 0);
    if (rawKey == nullptr) {
        std::cout << "  (skipping the remaining RSA tests: no key material)\n";
        return;
    }
    Crypto::EvpPkeyPtr key = Crypto::wrapPkey(rawKey);

    // --- InvalidArgument (-1): empty buffers with a valid key -------------
    CHECK_EQ(module.encrypt(key.get(), std::vector<uint8_t>(), ciphertext),
             kInvalidArgument);
    CHECK_EQ(module.decrypt(key.get(), std::vector<uint8_t>(), decrypted),
             kInvalidArgument);
    CHECK_EQ(module.sign(key.get(), std::vector<uint8_t>(), signature),
             kInvalidArgument);
    CHECK_EQ(module.verify(key.get(), std::vector<uint8_t>(),
                           std::vector<uint8_t>{0x01}),
             kInvalidArgument);
    CHECK_EQ(module.verify(key.get(), std::vector<uint8_t>{0x01},
                           std::vector<uint8_t>()),
             kInvalidArgument);

    // --- OAEP-SHA256 round trips (446 bytes is the maximum payload) -------
    uint64_t state = 0x12345678ull;
    const std::size_t payloadSizes[] = {1, 64, 446};
    for (const std::size_t size : payloadSizes) {
        const std::vector<uint8_t> plaintext = pseudoRandomBytes(size, state);
        CHECK_EQ(module.encrypt(key.get(), plaintext, ciphertext), 0);
        CHECK(!ciphertext.empty());
        CHECK_EQ(module.decrypt(key.get(), ciphertext, decrypted), 0);
        CHECK(bytesEqual(decrypted, plaintext));
    }

    // Corrupted OAEP ciphertext -> OpenSSL padding error (-2), NOT -3: the
    // library can tell "unparseable ciphertext" from "signature mismatch".
    const std::vector<uint8_t> plaintext(64, 0x33);
    CHECK_EQ(module.encrypt(key.get(), plaintext, ciphertext), 0);
    std::vector<uint8_t> corrupted = ciphertext;
    corrupted[corrupted.size() / 2] ^= 0xFFu;
    CHECK_EQ(module.decrypt(key.get(), corrupted, decrypted), kOpenSslFailure);

    // --- PSS-SHA256 sign/verify round trip --------------------------------
    std::vector<uint8_t> digest;
    CHECK(sha256Bytes(plaintext, digest));
    CHECK_EQ(module.sign(key.get(), digest, signature), 0);
    CHECK_EQ(signature.size(), std::size_t(512));  // RSA-4096 PSS signature
    CHECK_EQ(module.verify(key.get(), digest, signature), 0);

    // --- AuthFailed (-3): tampered digest and signature -------------------
    std::vector<uint8_t> wrongDigest = digest;
    wrongDigest[0] ^= 0x01u;
    CHECK_EQ(module.verify(key.get(), wrongDigest, signature), kAuthFailed);

    std::vector<uint8_t> badSignature = signature;
    badSignature[badSignature.size() / 2] ^= 0x01u;
    CHECK_EQ(module.verify(key.get(), digest, badSignature), kAuthFailed);
}

// ---------------------------------------------------------------------------
// 5. ML-KEM-768
// ---------------------------------------------------------------------------
void testMlKem() {
    Crypto::MlKem768 module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("ML-KEM-768 (FIPS 203)"));

    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> secretA;
    std::vector<uint8_t> secretB;
    const int rc = module.generateKeyPair(publicKey, secretKey);

    if (rc != 0 && rc == kUnavailable) {
        std::cout << "  (ML-KEM not available in this OpenSSL build;"
                     " checking the unavailable-code contract)\n";
        CHECK_EQ(rc, kUnavailable);

        // The failure classes below need no ML-KEM support at all.
        CHECK_EQ(module.encapsulate(std::vector<uint8_t>(), ciphertext, secretA),
                 kInvalidArgument);
        CHECK_EQ(module.decapsulate(std::vector<uint8_t>(), std::vector<uint8_t>(),
                                    secretB),
                 kInvalidArgument);
        const std::vector<uint8_t> garbage(64, 0xAA);
        CHECK_EQ(module.encapsulate(garbage, ciphertext, secretA), kOpenSslFailure);
        return;
    }

    CHECK_EQ(rc, 0);
    CHECK(!publicKey.empty());
    CHECK(!secretKey.empty());

    // --- InvalidArgument (-1): empty inputs ---------------------------------
    CHECK_EQ(module.encapsulate(std::vector<uint8_t>(), ciphertext, secretA),
             kInvalidArgument);
    CHECK_EQ(module.decapsulate(std::vector<uint8_t>(), secretKey, secretB),
             kInvalidArgument);
    CHECK_EQ(module.decapsulate(ciphertext, std::vector<uint8_t>(), secretB),
             kInvalidArgument);

    // --- OpenSslFailure (-2): unparseable key material ----------------------
    const std::vector<uint8_t> garbage(64, 0xAA);
    CHECK_EQ(module.encapsulate(garbage, ciphertext, secretA), kOpenSslFailure);
    CHECK_EQ(module.decapsulate(std::vector<uint8_t>{0x01, 0x02}, garbage, secretB),
             kOpenSslFailure);

    // --- KEM round trip ------------------------------------------------------
    CHECK_EQ(module.encapsulate(publicKey, ciphertext, secretA), 0);
    CHECK_EQ(secretA.size(), std::size_t(32));  // ML-KEM-768 shared secret
    CHECK(!ciphertext.empty());
    CHECK_EQ(module.decapsulate(ciphertext, secretKey, secretB), 0);
    CHECK(bytesEqual(secretA, secretB));

    // --- Implicit rejection: a tampered ciphertext still decapsulates, but
    // to a DIFFERENT pseudorandom secret (FIPS 203 property) ------------------
    std::vector<uint8_t> tampered = ciphertext;
    tampered[0] ^= 0xFFu;
    CHECK_EQ(module.decapsulate(tampered, secretKey, secretB), 0);
    CHECK(!bytesEqual(secretB, secretA));
}

// ---------------------------------------------------------------------------
// 5b. AES-256-GCM auto-nonce convenience overloads
// ---------------------------------------------------------------------------
void testAesAutoIv() {
    Crypto::Aes256 module;

    std::vector<uint8_t> key;
    CHECK_EQ(module.generateKey(key), 0);

    uint64_t state = 0xABCDEF0123456789ull;
    const std::vector<uint8_t> plaintext = pseudoRandomBytes(64, state);
    std::vector<uint8_t> cipherA;
    std::vector<uint8_t> cipherB;
    std::vector<uint8_t> recovered;

    // Round trip: output layout is [IV][ciphertext][tag].
    CHECK_EQ(module.encrypt(plaintext, key, cipherA), 0);
    CHECK_EQ(cipherA.size(), plaintext.size() + Crypto::Aes256::kIvSize +
                                  Crypto::Aes256::kTagSize);
    CHECK_EQ(module.decrypt(cipherA, key, recovered), 0);
    CHECK(bytesEqual(recovered, plaintext));

    // A fresh random IV is generated internally for every call: encrypting
    // the same plaintext twice must give different ciphertext.
    CHECK_EQ(module.encrypt(plaintext, key, cipherB), 0);
    CHECK(cipherA != cipherB);

    // Truncated auto-IV ciphertext -> InvalidArgument.
    recovered.clear();
    CHECK_EQ(module.decrypt(std::vector<uint8_t>{0x01, 0x02}, key, recovered),
             kInvalidArgument);

    // Tampered auto-IV ciphertext -> AuthFailed, no output.
    std::vector<uint8_t> tampered = cipherA;
    tampered[tampered.size() / 2] ^= 0xFFu;
    recovered.clear();
    CHECK_EQ(module.decrypt(tampered, key, recovered), kAuthFailed);
    CHECK(recovered.empty());
}

// ---------------------------------------------------------------------------
// 6. AES-256-GCM with associated data (AAD)
// ---------------------------------------------------------------------------
void testAad() {
    Crypto::Aes256 module;

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    CHECK_EQ(module.generateKey(key), 0);
    CHECK_EQ(module.generateIv(nonce), 0);

    const std::vector<uint8_t> plaintext(64, 0x42);
    const std::vector<uint8_t> aad = {'h', 'e', 'a', 'd', 'e', 'r', 0x00, 0x01, 0x02};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    std::array<uint8_t, 16> tag{};

    // Round trip with AAD.
    CHECK_EQ(module.encrypt(plaintext, key, nonce, aad, ciphertext, tag), 0);
    CHECK_EQ(module.decrypt(ciphertext, key, nonce, aad,
                            std::vector<uint8_t>(tag.begin(), tag.end()), decrypted),
             0);
    CHECK(bytesEqual(decrypted, plaintext));

    // Wrong AAD -> AuthFailed, no output.
    std::vector<uint8_t> wrongAad = aad;
    wrongAad[0] ^= 0x01u;
    decrypted.clear();
    CHECK_EQ(module.decrypt(ciphertext, key, nonce, wrongAad,
                            std::vector<uint8_t>(tag.begin(), tag.end()), decrypted),
             kAuthFailed);
    CHECK(decrypted.empty());

    // Missing AAD -> AuthFailed.
    decrypted.clear();
    CHECK_EQ(module.decrypt(ciphertext, key, nonce, std::vector<uint8_t>(),
                            std::vector<uint8_t>(tag.begin(), tag.end()), decrypted),
             kAuthFailed);
    CHECK(decrypted.empty());

    // Empty AAD behaves exactly like the no-AAD overload (same ciphertext).
    std::vector<uint8_t> ctA;
    std::vector<uint8_t> ctB;
    std::array<uint8_t, 16> tagA{};
    std::array<uint8_t, 16> tagB{};
    CHECK_EQ(module.encrypt(plaintext, key, nonce, std::vector<uint8_t>(), ctA, tagA), 0);
    CHECK_EQ(module.encrypt(plaintext, key, nonce, ctB, tagB), 0);
    CHECK(ctA == ctB);
    CHECK(tagA == tagB);
}

// ---------------------------------------------------------------------------
// 7. HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------
void testHkdf() {
    Crypto::Hkdf module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("HKDF-SHA256 (RFC 5869)"));

    // RFC 5869 Appendix A.1 test case 1 (SHA-256, L = 42): known-answer test.
    const std::vector<uint8_t> ikm(22, 0x0b);
    const std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                       0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    const std::vector<uint8_t> expectedOkm = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    std::vector<uint8_t> okm;
    CHECK_EQ(module.derive(ikm, salt, info, 42, okm), 0);
    CHECK(bytesEqual(okm, expectedOkm));

    // Empty salt/info is allowed and deterministic.
    std::vector<uint8_t> a;
    std::vector<uint8_t> b;
    CHECK_EQ(module.derive(ikm, std::vector<uint8_t>(), std::vector<uint8_t>(),
                           32, a),
             0);
    CHECK_EQ(module.derive(ikm, std::vector<uint8_t>(), std::vector<uint8_t>(),
                           32, b),
             0);
    CHECK_EQ(a.size(), std::size_t(32));
    CHECK(a == b);

    // Invalid arguments -> InvalidArgument.
    std::vector<uint8_t> out;
    CHECK_EQ(module.derive(std::vector<uint8_t>(), salt, info, 32, out),
             kInvalidArgument);
    CHECK_EQ(module.derive(ikm, salt, info, 0, out), kInvalidArgument);
    CHECK_EQ(module.derive(ikm, salt, info,
                           Crypto::Hkdf::kMaxOutputLength + 1, out),
             kInvalidArgument);
}

// ---------------------------------------------------------------------------
// 8. SHA-256 / SHA-512
// ---------------------------------------------------------------------------
void testSha() {
    Crypto::Sha256 module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("SHA-256 / SHA-512"));

    const std::vector<uint8_t> abc = {'a', 'b', 'c'};
    const std::vector<uint8_t> sha256Abc = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    const std::vector<uint8_t> sha512Abc = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
        0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
        0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
        0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
        0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
        0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};

    std::vector<uint8_t> digest;
    CHECK_EQ(module.hash(abc, digest), 0);
    CHECK_EQ(digest.size(), std::size_t(32));
    CHECK(bytesEqual(digest, sha256Abc));

    CHECK_EQ(module.hash512(abc, digest), 0);
    CHECK_EQ(digest.size(), std::size_t(64));
    CHECK(bytesEqual(digest, sha512Abc));

    // Empty input is valid.
    CHECK_EQ(module.hash(std::vector<uint8_t>(), digest), 0);
    CHECK_EQ(digest.size(), std::size_t(32));
    CHECK_EQ(module.hash512(std::vector<uint8_t>(), digest), 0);
    CHECK_EQ(digest.size(), std::size_t(64));
}

// ---------------------------------------------------------------------------
// 9. RSA key persistence (PEM / DER)
// ---------------------------------------------------------------------------
void testRsaKeys() {
    Crypto::Rsa4096 module;
    EVP_PKEY* rawKey = nullptr;
    CHECK_EQ(module.generateKeyPair(&rawKey), 0);
    if (rawKey == nullptr) {
        std::cout << "  (skipping the RSA persistence tests: no key material)\n";
        return;
    }
    Crypto::EvpPkeyPtr key = Crypto::wrapPkey(rawKey);

    // PEM round trips.
    std::string pubPem;
    std::string privPem;
    CHECK_EQ(module.savePublicKeyPem(key.get(), pubPem), 0);
    CHECK(!pubPem.empty());
    CHECK_EQ(module.savePrivateKeyPem(key.get(), privPem), 0);
    CHECK(!privPem.empty());

    rawKey = nullptr;
    CHECK_EQ(module.loadPublicKeyPem(pubPem, &rawKey), 0);
    Crypto::EvpPkeyPtr loadedPub = Crypto::wrapPkey(rawKey);
    rawKey = nullptr;
    CHECK_EQ(module.loadPrivateKeyPem(privPem, &rawKey), 0);
    Crypto::EvpPkeyPtr loadedPriv = Crypto::wrapPkey(rawKey);

    const std::vector<uint8_t> plaintext(100, 0x5C);
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    CHECK_EQ(module.encrypt(loadedPub.get(), plaintext, ciphertext), 0);
    CHECK_EQ(module.decrypt(loadedPriv.get(), ciphertext, decrypted), 0);
    CHECK(bytesEqual(decrypted, plaintext));

    // DER round trips.
    std::vector<uint8_t> pubDer;
    std::vector<uint8_t> privDer;
    CHECK_EQ(module.savePublicKeyDer(key.get(), pubDer), 0);
    CHECK(!pubDer.empty());
    CHECK_EQ(module.savePrivateKeyDer(key.get(), privDer), 0);
    CHECK(!privDer.empty());

    rawKey = nullptr;
    CHECK_EQ(module.loadPublicKeyDer(pubDer, &rawKey), 0);
    loadedPub = Crypto::wrapPkey(rawKey);
    rawKey = nullptr;
    CHECK_EQ(module.loadPrivateKeyDer(privDer, &rawKey), 0);
    loadedPriv = Crypto::wrapPkey(rawKey);
    ciphertext.clear();
    decrypted.clear();
    CHECK_EQ(module.encrypt(loadedPub.get(), plaintext, ciphertext), 0);
    CHECK_EQ(module.decrypt(loadedPriv.get(), ciphertext, decrypted), 0);
    CHECK(bytesEqual(decrypted, plaintext));

    // Null / garbage inputs.
    std::string pemOut;
    CHECK_EQ(module.savePublicKeyPem(nullptr, pemOut), kInvalidArgument);
    CHECK_EQ(module.loadPublicKeyPem("not a pem", &rawKey), kOpenSslFailure);
    CHECK_EQ(module.loadPublicKeyDer(std::vector<uint8_t>{0x01, 0x02}, &rawKey),
             kOpenSslFailure);
    CHECK_EQ(module.loadPublicKeyDer(std::vector<uint8_t>(), &rawKey),
             kInvalidArgument);
    CHECK_EQ(module.loadPublicKeyPem("", nullptr), kInvalidArgument);
}

// ---------------------------------------------------------------------------
// 10. Hybrid envelope (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM)
// ---------------------------------------------------------------------------
void testHybrid() {
    Crypto::PostQuantum module;
    CHECK_EQ(std::string(module.algorithmName()),
             std::string("ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"));

    Crypto::MlKem768 kem;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    const int rc = kem.generateKeyPair(publicKey, secretKey);
    if (rc != 0 && rc == kUnavailable) {
        std::cout << "  (ML-KEM not available; skipping the hybrid tests)\n";
        return;
    }
    CHECK_EQ(rc, 0);

    // Empty inputs -> InvalidArgument.
    std::vector<uint8_t> envelope;
    std::vector<uint8_t> plaintext;
    CHECK_EQ(module.encrypt(std::vector<uint8_t>(), plaintext, envelope),
             kInvalidArgument);
    CHECK_EQ(module.decrypt(std::vector<uint8_t>(), envelope, plaintext),
             kInvalidArgument);
    CHECK_EQ(module.decrypt(secretKey, std::vector<uint8_t>{0x01, 0x02}, plaintext),
             kInvalidArgument);

    // Round trip.
    const std::vector<uint8_t> message(200, 0x7B);
    CHECK_EQ(module.encrypt(publicKey, message, envelope), 0);
    CHECK(!envelope.empty());
    CHECK_EQ(module.decrypt(secretKey, envelope, plaintext), 0);
    CHECK(bytesEqual(plaintext, message));

    // Tampered tag (last byte) -> AuthFailed, no output.
    std::vector<uint8_t> tampered = envelope;
    tampered[tampered.size() - 1] ^= 0xFFu;
    plaintext.clear();
    CHECK_EQ(module.decrypt(secretKey, tampered, plaintext), kAuthFailed);
    CHECK(plaintext.empty());

    // Tampered KEM ciphertext -> different shared secret -> AuthFailed.
    tampered = envelope;
    tampered[4 + 16] ^= 0xFFu;
    plaintext.clear();
    CHECK_EQ(module.decrypt(secretKey, tampered, plaintext), kAuthFailed);
    CHECK(plaintext.empty());

    // Wrong secret key -> AuthFailed.
    std::vector<uint8_t> otherPublic;
    std::vector<uint8_t> otherSecret;
    CHECK_EQ(kem.generateKeyPair(otherPublic, otherSecret), 0);
    plaintext.clear();
    CHECK_EQ(module.decrypt(otherSecret, envelope, plaintext), kAuthFailed);
    CHECK(plaintext.empty());
}

void testHybridThreadSafety() {
    Crypto::PostQuantum shared;
    Crypto::MlKem768 kem;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    const int rc = kem.generateKeyPair(publicKey, secretKey);
    if (rc != 0 && rc == kUnavailable) {
        std::cout << "  (ML-KEM not available; skipping the hybrid thread test)\n";
        return;
    }
    CHECK_EQ(rc, 0);

    constexpr int kThreads = 4;
    constexpr int kIterations = 10;
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&shared, &publicKey, &secretKey, &failures, t]() {
            std::vector<uint8_t> message(96);
            for (std::size_t i = 0; i < message.size(); ++i) {
                message[i] = static_cast<uint8_t>(t * 17 + static_cast<int>(i));
            }
            for (int i = 0; i < kIterations; ++i) {
                std::vector<uint8_t> envelope;
                std::vector<uint8_t> plaintext;
                if (shared.encrypt(publicKey, message, envelope) != 0 ||
                    shared.decrypt(secretKey, envelope, plaintext) != 0 ||
                    !bytesEqual(plaintext, message)) {
                    ++failures;
                    return;
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    CHECK_EQ(failures.load(), 0);
}

// ---------------------------------------------------------------------------
// 11. Thread safety: one shared (stateless) instance, many threads
// ---------------------------------------------------------------------------
void testAesThreadSafety() {
    Crypto::Aes256 shared;
    constexpr int kThreads = 8;
    constexpr int kIterations = 25;
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&shared, t, &failures]() {
            uint64_t state = 0xDEADBEEFull ^ (static_cast<uint64_t>(t) << 32);
            for (int i = 0; i < kIterations; ++i) {
                std::vector<uint8_t> key;
                std::vector<uint8_t> nonce;
                if (shared.generateKey(key) != 0 || shared.generateIv(nonce) != 0) {
                    ++failures;
                    continue;
                }
                const std::vector<uint8_t> plaintext =
                    pseudoRandomBytes(512 + static_cast<std::size_t>(i) * 7, state);
                std::vector<uint8_t> ciphertext;
                std::array<uint8_t, 16> tag{};
                if (shared.encrypt(plaintext, key, nonce, ciphertext, tag) != 0 ||
                    ciphertext.size() != plaintext.size()) {
                    ++failures;
                    continue;
                }
                std::vector<uint8_t> decrypted;
                if (shared.decrypt(ciphertext, key, nonce,
                                   std::vector<uint8_t>(tag.begin(), tag.end()),
                                   decrypted) != 0 ||
                    !bytesEqual(decrypted, plaintext)) {
                    ++failures;
                    continue;
                }

                // Periodically force failures to exercise error paths under
                // contention.
                if (i % 4 == 0) {
                    std::vector<uint8_t> badTag(tag.begin(), tag.end());
                    badTag[0] ^= 0xFFu;
                    const int rc = shared.decrypt(ciphertext, key, nonce, badTag,
                                                  decrypted);
                    if (rc != kAuthFailed || !decrypted.empty()) {
                        ++failures;
                        continue;
                    }
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    CHECK_EQ(failures.load(), 0);
}

void testRsaThreadSafety() {
    Crypto::Rsa4096 shared;
    EVP_PKEY* rawKey = nullptr;
    if (shared.generateKeyPair(&rawKey) != 0 || rawKey == nullptr) {
        std::cout << "  (skipping the RSA thread test: no key material)\n";
        return;
    }
    Crypto::EvpPkeyPtr key = Crypto::wrapPkey(rawKey);

    constexpr int kThreads = 4;
    constexpr int kIterations = 8;
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&shared, keyPtr = key.get(), t, &failures]() {
            for (int i = 0; i < kIterations; ++i) {
                std::vector<uint8_t> message(32);
                for (std::size_t b = 0; b < message.size(); ++b) {
                    message[b] = static_cast<uint8_t>(t * 31 + i * 7 + static_cast<int>(b));
                }
                std::vector<uint8_t> digest;
                std::vector<uint8_t> signature;
                if (!sha256Bytes(message, digest)) {
                    ++failures;
                    continue;
                }
                if (shared.sign(keyPtr, digest, signature) != 0) {
                    ++failures;
                    continue;
                }
                if (shared.verify(keyPtr, digest, signature) != 0) {
                    ++failures;
                    continue;
                }
                std::vector<uint8_t> badSignature = signature;
                badSignature[0] ^= 0x01u;
                if (shared.verify(keyPtr, digest, badSignature) != kAuthFailed) {
                    ++failures;
                    continue;
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    CHECK_EQ(failures.load(), 0);
}

void testMlKemThreadSafety() {
    Crypto::MlKem768 shared;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    const int rc = shared.generateKeyPair(publicKey, secretKey);
    if (rc != 0 && rc == kUnavailable) {
        std::cout << "  (ML-KEM not available; skipping the KEM thread test)\n";
        return;
    }
    CHECK_EQ(rc, 0);

    constexpr int kThreads = 4;
    constexpr int kIterations = 10;
    std::atomic<int> failures{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&shared, &publicKey, &secretKey, &failures]() {
            for (int i = 0; i < kIterations; ++i) {
                std::vector<uint8_t> ciphertext;
                std::vector<uint8_t> secretA;
                std::vector<uint8_t> secretB;
                if (shared.encapsulate(publicKey, ciphertext, secretA) != 0) {
                    ++failures;
                    continue;
                }
                if (shared.decapsulate(ciphertext, secretKey, secretB) != 0 ||
                    !bytesEqual(secretA, secretB)) {
                    ++failures;
                    continue;
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    CHECK_EQ(failures.load(), 0);
}

} // namespace

int main() {
    std::cout << "============================================================\n";
    std::cout << " Crypto test suite\n";
    std::cout << " OpenSSL runtime version: " << OpenSSL_version(OPENSSL_VERSION) << "\n";
    std::cout << "============================================================\n\n";

    runSection("error model", testErrorModel);
    runSection("AES-256-GCM round trips", testAesRoundTrips);
    runSection("AES-256-GCM error codes", testAesErrorCodes);
    runSection("AES-256-GCM auto-nonce convenience", testAesAutoIv);
    runSection("RSA-4096", testRsa);
    runSection("ML-KEM-768", testMlKem);
    runSection("AES-256-GCM with AAD", testAad);
    runSection("HKDF-SHA256", testHkdf);
    runSection("SHA-256 / SHA-512", testSha);
    runSection("RSA key persistence", testRsaKeys);
    runSection("Hybrid envelope", testHybrid);
    runSection("Hybrid thread safety (one shared instance)", testHybridThreadSafety);
    runSection("AES thread safety (one shared instance)", testAesThreadSafety);
    runSection("RSA thread safety (one shared instance)", testRsaThreadSafety);
    runSection("ML-KEM thread safety (one shared instance)", testMlKemThreadSafety);

    std::cout << "\n============================================================\n";
    std::cout << " " << gChecks << " check(s), " << gFailures << " failure(s)\n";
    if (gFailures == 0) {
        std::cout << " ALL TESTS PASSED\n";
    } else {
        std::cout << " TESTS FAILED\n";
    }
    std::cout << "============================================================\n";

    if (pauseRequested()) {
#if defined(_WIN32)
        std::system("pause");  // keeps the console window open for reading
#else
        std::cout << "Press Enter to continue..." << std::flush;
        std::cin.get();
#endif
    }
    return gFailures == 0 ? 0 : 1;
}
