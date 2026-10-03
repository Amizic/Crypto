// ObsidianGuard - tests/test_main.cpp
//
// Dependency-free test suite for ObsidianGuard (no GoogleTest/Catch2; plain
// assertions wired into CTest).
//
// Coverage:
//   * error model          : 0 = success, distinct negative CryptoErrorCode
//                            categories, last-error bookkeeping
//   * AES-256-GCM          : round trips (0..64 KiB), determinism, and every
//                            negative path with its exact error code
//   * RSA-4096             : OAEP/PSS round trips, param failures,
//                            padding error (-2) vs signature mismatch (-3)
//   * ML-KEM-768           : KEM round trip, implicit rejection, parse
//                            failures, unavailable-build behavior
//   * thread safety        : one shared module instance hammered by many
//                            threads (round trips + forced failures)
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

#include "aes256_gcm.hpp"
#include "crypto_module.hpp"
#include "crypto_types.hpp"
#include "ml_kem768.hpp"
#include "openssl_raii.hpp"
#include "rsa4096.hpp"

namespace {

// ---------------------------------------------------------------------------
// Error code constants (public contract; compile-time checked as well)
// ---------------------------------------------------------------------------
using ObsidianGuard::CryptoErrorCode;

constexpr int kInvalidArgument = static_cast<int>(CryptoErrorCode::InvalidArgument);
constexpr int kOpenSslFailure  = static_cast<int>(CryptoErrorCode::OpenSslFailure);
constexpr int kAuthFailed      = static_cast<int>(CryptoErrorCode::AuthFailed);
constexpr int kUnavailable     = static_cast<int>(CryptoErrorCode::Unavailable);
constexpr int kInternal        = static_cast<int>(CryptoErrorCode::Internal);

static_assert(static_cast<int>(CryptoErrorCode::Success) == 0, "success must be 0");
static_assert(kInvalidArgument == -1, "InvalidArgument must be -1");
static_assert(kOpenSslFailure == -2, "OpenSslFailure must be -2");
static_assert(kAuthFailed == -3, "AuthFailed must be -3");
static_assert(kUnavailable == -4, "Unavailable must be -4");
static_assert(kInternal == -5, "Internal must be -5");

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
    ObsidianGuard::EvpMdCtxPtr context = ObsidianGuard::makeMdCtx();
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
/// runs (CTest, CI, `... | obsidianguard_tests.exe`) skip the pause, and the
/// OBSIDIAN_GUARD_NO_PAUSE environment variable forces it off.
bool pauseRequested() {
#if defined(_WIN32)
    if (std::getenv("OBSIDIAN_GUARD_NO_PAUSE") != nullptr) {
        return false;
    }
    return _isatty(_fileno(stdin)) != 0;
#else
    return std::getenv("OBSIDIAN_GUARD_NO_PAUSE") == nullptr;
#endif
}

// ---------------------------------------------------------------------------
// 1. Error model
// ---------------------------------------------------------------------------
void testErrorModel() {
    const ObsidianGuard::CryptoResult okResult = ObsidianGuard::CryptoResult::success();
    CHECK(okResult.ok());
    CHECK_EQ(okResult.code, 0);
    CHECK(okResult.message.empty());

    const ObsidianGuard::CryptoResult failure =
        ObsidianGuard::CryptoResult::failure(kAuthFailed, "boom");
    CHECK(!failure.ok());
    CHECK_EQ(failure.code, -3);
    CHECK_EQ(failure.message, std::string("boom"));

    // Last-error bookkeeping on a fresh module instance.
    ObsidianGuard::Aes256GcmModule module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("AES-256-GCM"));
    CHECK(module.getLastError().empty());

    std::vector<uint8_t> plaintext{1, 2, 3};
    std::vector<uint8_t> badKey(31, 0x42);  // must be 32 bytes
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag{};

    const ObsidianGuard::CryptoResult result =
        module.encrypt(plaintext, badKey, nonce, ciphertext, tag);
    CHECK(!result.ok());
    CHECK_EQ(result.code, kInvalidArgument);
    CHECK(!result.message.empty());
    CHECK(!module.getLastError().empty());

    module.clearError();
    CHECK(module.getLastError().empty());

    // A successful call clears the stored error as well.
    std::vector<uint8_t> key;
    CHECK(module.generateKey(key).ok());
    CHECK(module.getLastError().empty());
}

// ---------------------------------------------------------------------------
// 2. AES-256-GCM round trips
// ---------------------------------------------------------------------------
void testAesRoundTrips() {
    ObsidianGuard::Aes256GcmModule module;

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    CHECK(module.generateKey(key).ok());
    CHECK_EQ(key.size(), std::size_t(32));
    CHECK(module.generateIv(nonce).ok());
    CHECK_EQ(nonce.size(), std::size_t(12));

    const std::size_t sizes[] = {0, 1, 16, 255, 1024, 65536};
    uint64_t state = 0x9E3779B97F4A7C15ull;
    for (const std::size_t size : sizes) {
        const std::vector<uint8_t> plaintext = pseudoRandomBytes(size, state);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;
        std::array<uint8_t, 16> tag{};

        CHECK(module.encrypt(plaintext, key, nonce, ciphertext, tag).ok());
        CHECK_EQ(ciphertext.size(), plaintext.size());
        CHECK(module.decrypt(ciphertext, key, nonce,
                             std::vector<uint8_t>(tag.begin(), tag.end()), decrypted).ok());
        CHECK(bytesEqual(decrypted, plaintext));
    }

    // GCM is deterministic for a fixed key/nonce: identical input must give
    // identical ciphertext and tag.
    const std::vector<uint8_t> plaintext(64, 0x5A);
    std::vector<uint8_t> ciphertextA;
    std::vector<uint8_t> ciphertextB;
    std::array<uint8_t, 16> tagA{};
    std::array<uint8_t, 16> tagB{};
    CHECK(module.encrypt(plaintext, key, nonce, ciphertextA, tagA).ok());
    CHECK(module.encrypt(plaintext, key, nonce, ciphertextB, tagB).ok());
    CHECK(ciphertextA == ciphertextB);
    CHECK(tagA == tagB);
}

// ---------------------------------------------------------------------------
// 3. AES-256-GCM error codes
// ---------------------------------------------------------------------------
void testAesErrorCodes() {
    ObsidianGuard::Aes256GcmModule module;

    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    CHECK(module.generateKey(key).ok());
    CHECK(module.generateIv(nonce).ok());

    std::vector<uint8_t> plaintext(100, 0x11);
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag{};
    CHECK(module.encrypt(plaintext, key, nonce, ciphertext, tag).ok());
    const std::vector<uint8_t> goodTag(tag.begin(), tag.end());

    std::vector<uint8_t> out;
    std::array<uint8_t, 16> dummyTag{};

    // --- InvalidArgument (-1): wrong sizes --------------------------------
    const std::vector<uint8_t> key31(31, 0);
    const std::vector<uint8_t> key33(33, 0);
    const std::vector<uint8_t> nonce11(11, 0);
    const std::vector<uint8_t> nonce13(13, 0);
    CHECK_EQ(module.encrypt(plaintext, key31, nonce, out, dummyTag).code, kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key33, nonce, out, dummyTag).code, kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key, nonce11, out, dummyTag).code, kInvalidArgument);
    CHECK_EQ(module.encrypt(plaintext, key, nonce13, out, dummyTag).code, kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key31, nonce, goodTag, out).code, kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key, nonce11, goodTag, out).code, kInvalidArgument);
    CHECK_EQ(module.decrypt(ciphertext, key, nonce, {0x01}, out).code, kInvalidArgument);

    // --- AuthFailed (-3): tampering ---------------------------------------
    std::vector<uint8_t> badTag = goodTag;
    badTag[0] ^= 0xFFu;
    ObsidianGuard::CryptoResult result =
        module.decrypt(ciphertext, key, nonce, badTag, out);
    CHECK(!result.ok());
    CHECK_EQ(result.code, kAuthFailed);
    CHECK(out.empty());  // no plaintext-derived bytes escape on auth failure
    CHECK(!module.getLastError().empty());

    std::vector<uint8_t> badCiphertext = ciphertext;
    badCiphertext[3] ^= 0x80u;
    result = module.decrypt(badCiphertext, key, nonce, goodTag, out);
    CHECK_EQ(result.code, kAuthFailed);
    CHECK(out.empty());

    const std::vector<uint8_t> wrongKey(32, 0x77);
    result = module.decrypt(ciphertext, wrongKey, nonce, goodTag, out);
    CHECK_EQ(result.code, kAuthFailed);
    CHECK(out.empty());

    std::vector<uint8_t> wrongNonce = nonce;
    wrongNonce[0] ^= 0x01u;
    result = module.decrypt(ciphertext, key, wrongNonce, goodTag, out);
    CHECK_EQ(result.code, kAuthFailed);
    CHECK(out.empty());
}

// ---------------------------------------------------------------------------
// 4. RSA-4096
// ---------------------------------------------------------------------------
void testRsa() {
    ObsidianGuard::Rsa4096Module module;
    CHECK_EQ(std::string(module.algorithmName()),
             std::string("RSA-4096 (OAEP-SHA256 / PSS-SHA256)"));

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;
    std::vector<uint8_t> signature;
    ObsidianGuard::CryptoResult result;

    // --- InvalidArgument (-1): null/empty inputs, before any key exists ----
    CHECK_EQ(module.generateKeyPair(nullptr).code, kInvalidArgument);
    CHECK_EQ(module.encrypt(nullptr, std::vector<uint8_t>{1}, ciphertext).code,
             kInvalidArgument);
    CHECK_EQ(module.decrypt(nullptr, std::vector<uint8_t>{1}, decrypted).code,
             kInvalidArgument);
    CHECK_EQ(module.sign(nullptr, std::vector<uint8_t>{1}, signature).code,
             kInvalidArgument);
    CHECK_EQ(module.verify(nullptr, std::vector<uint8_t>{1},
                           std::vector<uint8_t>{1}).code,
             kInvalidArgument);

    EVP_PKEY* rawKey = nullptr;
    result = module.generateKeyPair(&rawKey);
    CHECK(result.ok());
    if (!result.ok()) {
        std::cout << "  (skipping the remaining RSA tests: no key material)\n";
        return;
    }
    ObsidianGuard::EvpPkeyPtr key = ObsidianGuard::wrapPkey(rawKey);

    // --- InvalidArgument (-1): empty buffers with a valid key -------------
    CHECK_EQ(module.encrypt(key.get(), std::vector<uint8_t>(), ciphertext).code,
             kInvalidArgument);
    CHECK_EQ(module.decrypt(key.get(), std::vector<uint8_t>(), decrypted).code,
             kInvalidArgument);
    CHECK_EQ(module.sign(key.get(), std::vector<uint8_t>(), signature).code,
             kInvalidArgument);
    CHECK_EQ(module.verify(key.get(), std::vector<uint8_t>(),
                           std::vector<uint8_t>{0x01}).code,
             kInvalidArgument);
    CHECK_EQ(module.verify(key.get(), std::vector<uint8_t>{0x01},
                           std::vector<uint8_t>()).code,
             kInvalidArgument);

    // --- OAEP-SHA256 round trips (446 bytes is the maximum payload) -------
    uint64_t state = 0x12345678ull;
    const std::size_t payloadSizes[] = {1, 64, 446};
    for (const std::size_t size : payloadSizes) {
        const std::vector<uint8_t> plaintext = pseudoRandomBytes(size, state);
        CHECK(module.encrypt(key.get(), plaintext, ciphertext).ok());
        CHECK(!ciphertext.empty());
        CHECK(module.decrypt(key.get(), ciphertext, decrypted).ok());
        CHECK(bytesEqual(decrypted, plaintext));
    }

    // Corrupted OAEP ciphertext -> OpenSSL padding error (-2), NOT -3: the
    // library can tell "unparseable ciphertext" from "signature mismatch".
    const std::vector<uint8_t> plaintext(64, 0x33);
    CHECK(module.encrypt(key.get(), plaintext, ciphertext).ok());
    std::vector<uint8_t> corrupted = ciphertext;
    corrupted[corrupted.size() / 2] ^= 0xFFu;
    result = module.decrypt(key.get(), corrupted, decrypted);
    CHECK(!result.ok());
    CHECK_EQ(result.code, kOpenSslFailure);

    // --- PSS-SHA256 sign/verify round trip --------------------------------
    std::vector<uint8_t> digest;
    CHECK(sha256Bytes(plaintext, digest));
    CHECK(module.sign(key.get(), digest, signature).ok());
    CHECK_EQ(signature.size(), std::size_t(512));  // RSA-4096 PSS signature
    CHECK(module.verify(key.get(), digest, signature).ok());

    // --- AuthFailed (-3): tampered digest and signature -------------------
    std::vector<uint8_t> wrongDigest = digest;
    wrongDigest[0] ^= 0x01u;
    result = module.verify(key.get(), wrongDigest, signature);
    CHECK_EQ(result.code, kAuthFailed);

    std::vector<uint8_t> badSignature = signature;
    badSignature[badSignature.size() / 2] ^= 0x01u;
    result = module.verify(key.get(), digest, badSignature);
    CHECK_EQ(result.code, kAuthFailed);
}

// ---------------------------------------------------------------------------
// 5. ML-KEM-768
// ---------------------------------------------------------------------------
void testMlKem() {
    ObsidianGuard::MlKem768Module module;
    CHECK_EQ(std::string(module.algorithmName()), std::string("ML-KEM-768 (FIPS 203)"));

    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> secretA;
    std::vector<uint8_t> secretB;
    ObsidianGuard::CryptoResult result = module.generateKeyPair(publicKey, secretKey);

    if (!result.ok() && result.code == kUnavailable) {
        std::cout << "  (ML-KEM not available in this OpenSSL build;"
                     " checking the unavailable-code contract)\n";
        CHECK_EQ(result.code, kUnavailable);
        CHECK(!result.message.empty());
        CHECK(!module.getLastError().empty());

        // The failure classes below need no ML-KEM support at all.
        CHECK_EQ(module.encapsulate(std::vector<uint8_t>(), ciphertext, secretA).code,
                 kInvalidArgument);
        CHECK_EQ(module.decapsulate(std::vector<uint8_t>(), std::vector<uint8_t>(),
                                    secretB).code,
                 kInvalidArgument);
        const std::vector<uint8_t> garbage(64, 0xAA);
        CHECK_EQ(module.encapsulate(garbage, ciphertext, secretA).code, kOpenSslFailure);
        return;
    }

    CHECK(result.ok());
    CHECK(!publicKey.empty());
    CHECK(!secretKey.empty());

    // --- InvalidArgument (-1): empty inputs ---------------------------------
    CHECK_EQ(module.encapsulate(std::vector<uint8_t>(), ciphertext, secretA).code,
             kInvalidArgument);
    CHECK_EQ(module.decapsulate(std::vector<uint8_t>(), secretKey, secretB).code,
             kInvalidArgument);
    CHECK_EQ(module.decapsulate(ciphertext, std::vector<uint8_t>(), secretB).code,
             kInvalidArgument);

    // --- OpenSslFailure (-2): unparseable key material ----------------------
    const std::vector<uint8_t> garbage(64, 0xAA);
    result = module.encapsulate(garbage, ciphertext, secretA);
    CHECK_EQ(result.code, kOpenSslFailure);
    result = module.decapsulate(std::vector<uint8_t>{0x01, 0x02}, garbage, secretB);
    CHECK_EQ(result.code, kOpenSslFailure);

    // --- KEM round trip ------------------------------------------------------
    result = module.encapsulate(publicKey, ciphertext, secretA);
    CHECK(result.ok());
    CHECK_EQ(secretA.size(), std::size_t(32));  // ML-KEM-768 shared secret
    CHECK(!ciphertext.empty());
    result = module.decapsulate(ciphertext, secretKey, secretB);
    CHECK(result.ok());
    CHECK(bytesEqual(secretA, secretB));

    // --- Implicit rejection: a tampered ciphertext still decapsulates, but
    // to a DIFFERENT pseudorandom secret (FIPS 203 property) ------------------
    std::vector<uint8_t> tampered = ciphertext;
    tampered[0] ^= 0xFFu;
    result = module.decapsulate(tampered, secretKey, secretB);
    CHECK(result.ok());
    CHECK(!bytesEqual(secretB, secretA));
}

// ---------------------------------------------------------------------------
// 6. Thread safety: one shared module instance, many threads
// ---------------------------------------------------------------------------
void testAesThreadSafety() {
    ObsidianGuard::Aes256GcmModule shared;
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
                if (!shared.generateKey(key).ok() || !shared.generateIv(nonce).ok()) {
                    ++failures;
                    continue;
                }
                const std::vector<uint8_t> plaintext =
                    pseudoRandomBytes(512 + static_cast<std::size_t>(i) * 7, state);
                std::vector<uint8_t> ciphertext;
                std::array<uint8_t, 16> tag{};
                ObsidianGuard::CryptoResult result =
                    shared.encrypt(plaintext, key, nonce, ciphertext, tag);
                if (!result.ok() || ciphertext.size() != plaintext.size()) {
                    ++failures;
                    continue;
                }
                std::vector<uint8_t> decrypted;
                result = shared.decrypt(ciphertext, key, nonce,
                                        std::vector<uint8_t>(tag.begin(), tag.end()),
                                        decrypted);
                if (!result.ok() || !bytesEqual(decrypted, plaintext)) {
                    ++failures;
                    continue;
                }

                // Periodically force failures to exercise the shared
                // last-error state under contention.
                if (i % 4 == 0) {
                    std::vector<uint8_t> badTag(tag.begin(), tag.end());
                    badTag[0] ^= 0xFFu;
                    result = shared.decrypt(ciphertext, key, nonce, badTag, decrypted);
                    if (result.ok() || result.code != kAuthFailed) {
                        ++failures;
                        continue;
                    }
                    (void)shared.getLastError();  // consistent snapshot under load
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
    ObsidianGuard::Rsa4096Module shared;
    EVP_PKEY* rawKey = nullptr;
    ObsidianGuard::CryptoResult result = shared.generateKeyPair(&rawKey);
    CHECK(result.ok());
    if (!result.ok()) {
        std::cout << "  (skipping the RSA thread test: no key material)\n";
        return;
    }
    ObsidianGuard::EvpPkeyPtr key = ObsidianGuard::wrapPkey(rawKey);

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
                ObsidianGuard::CryptoResult result = shared.sign(keyPtr, digest, signature);
                if (!result.ok()) {
                    ++failures;
                    continue;
                }
                result = shared.verify(keyPtr, digest, signature);
                if (!result.ok()) {
                    ++failures;
                    continue;
                }
                std::vector<uint8_t> badSignature = signature;
                badSignature[0] ^= 0x01u;
                result = shared.verify(keyPtr, digest, badSignature);
                if (result.ok() || result.code != kAuthFailed) {
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
    ObsidianGuard::MlKem768Module shared;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    ObsidianGuard::CryptoResult result = shared.generateKeyPair(publicKey, secretKey);
    if (!result.ok() && result.code == kUnavailable) {
        std::cout << "  (ML-KEM not available; skipping the KEM thread test)\n";
        return;
    }
    CHECK(result.ok());
    if (!result.ok()) {
        return;
    }

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
                ObsidianGuard::CryptoResult result =
                    shared.encapsulate(publicKey, ciphertext, secretA);
                if (!result.ok()) {
                    ++failures;
                    continue;
                }
                result = shared.decapsulate(ciphertext, secretKey, secretB);
                if (!result.ok() || !bytesEqual(secretA, secretB)) {
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
    std::cout << " ObsidianGuard test suite\n";
    std::cout << " OpenSSL runtime version: " << OpenSSL_version(OPENSSL_VERSION) << "\n";
    std::cout << "============================================================\n\n";

    runSection("error model", testErrorModel);
    runSection("AES-256-GCM round trips", testAesRoundTrips);
    runSection("AES-256-GCM error codes", testAesErrorCodes);
    runSection("RSA-4096", testRsa);
    runSection("ML-KEM-768", testMlKem);
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
