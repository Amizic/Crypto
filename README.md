# Crypto

> **Disclaimer:** This project was developed with the help of AI. All code
> has been tested and verified by me.

A small, stateless, C++17 cryptography library built on OpenSSL. Six
classes, one error model. One include brings in everything:

```cpp
#include "Crypto.hpp"   // namespace Crypto
```

| Class | Algorithm | Typical use |
|---|---|---|
| `Aes256` | AES-256-GCM (`EVP_aes_256_gcm`), optional AAD | Authenticated symmetric encryption |
| `Rsa4096` | RSA-4096, OAEP-SHA256 / PSS-SHA256, PEM/DER key persistence | Asymmetric encryption and digital signatures |
| `MlKem768` | ML-KEM-768 (FIPS 203, post-quantum) | Key encapsulation (requires OpenSSL 3.5+) |
| `Hkdf` | HKDF-SHA256 (RFC 5869) | Key derivation from shared secrets / master keys |
| `Sha256` | SHA-256 / SHA-512 | One-shot hashing |
| `PostQuantum` | ML-KEM-768 + HKDF-SHA256 + AES-256-GCM | One-call hybrid encryption |

## Crypto vs CryptoLite

This workspace ships two related libraries with the same algorithms and
aligned return codes, but different key-ownership models — pick per project:

| | **Crypto (this one)** | **CryptoLite** |
|---|---|---|
| Model | **Stateless engine** — classes hold nothing; keys are byte vectors / `EVP_PKEY*` you pass per call | **Key-owning objects** — each object stores its key inside itself |
| Locks | none — thread-safe by construction | internal mutex per object |
| Key storage | wherever *your* code keeps it (e.g. a per-client session struct) | inside the object (non-copyable); PEM save/load to files |
| Best for | servers with many clients/threads, custom session management, maximum throughput | small tools and apps that want self-contained per-client objects |

## Design

* **Plain `int` return codes, nothing else** — every public method returns
  `0` on success or a negative error code on failure. No result structs, no
  message strings; the code *is* the error. The same constants are exposed
  as `static constexpr int` members on **every class**, so you can write
  readable checks like `if (rc == Crypto::Aes256::kErrAuth)`.

  | Constant | Value | Meaning |
  |---|---|---|
  | `kOk` | `0` | success |
  | `kErrInvalidArgument` | `-1` | bad input (wrong size, null key, empty buffer, ...) |
  | `kErrOpenSsl` | `-2` | the underlying OpenSSL call failed |
  | `kErrAuth` | `-3` | authentication/verification failed (wrong key, nonce, tag or signature) |
  | `kErrUnavailable` | `-4` | the algorithm is not available in this OpenSSL build |
  | `kErrInternal` | `-5` | unexpected internal failure (reserved) |
  | `kErrFile` | `-6` | file I/O error (parity with CryptoLite; unused here) |

* **Stateless classes, trivially thread-safe** — classes hold no state (keys
  are passed in per call), so any number of threads may share one instance
  with zero locking.
* **No exceptions, no printing, no abort** — every method is `noexcept` and
  reports everything through its return code.
* **AAD support** — `Aes256` can bind associated data (headers, IDs,
  metadata) into the GCM tag: authenticated but not encrypted; any tampering
  with it is detected at decryption.
* **C++17** — `const std::vector<uint8_t>&` buffers everywhere, RAII via
  `unique_ptr` wrappers (`include/OpensslRaii.hpp`), no manual frees.

## API reference

### Aes256

AES-256-GCM authenticated encryption with optional associated data (AAD).
Constants: `kKeySize = 32` bytes, `kIvSize = 12` bytes (GCM nonce),
`kTagSize = 16` bytes (authentication tag).

#### `Aes256::algorithmName()`
- **Returns:** `"AES-256-GCM"` (for logging).

#### `Aes256::generateKey(key)`
Generates a random 32-byte AES-256 key.
- **Out:** `key` — `std::vector<uint8_t>`, 32 bytes.
- **Returns:** `kOk` (0) or a negative code.

#### `Aes256::generateIv(nonce)`
Generates a random 12-byte GCM nonce (IV). Generate a fresh one per message
under the same key — never reuse an IV.
- **Out:** `nonce` — `std::vector<uint8_t>`, 12 bytes.
- **Returns:** `kOk` (0) or a negative code.

#### `Aes256::encrypt(plaintext, key, nonce, ciphertext, tag)`
Encrypts with AES-256-GCM. Ciphertext has the same size as the plaintext;
the 16-byte tag authenticates it.
- **In:** `plaintext` — the message; `key` — 32 bytes; `nonce` — 12 bytes.
- **Out:** `ciphertext` — same size as plaintext; `tag` — `std::array<uint8_t, 16>`.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2).

#### `Aes256::encrypt(plaintext, key, nonce, aad, ciphertext, tag)`
Same, but also binds associated data into the tag. `aad` (headers, IDs,
metadata) is authenticated but **not** encrypted; tampering with either the
ciphertext or the AAD is detected at decryption. May be empty.
- **In:** as above + `aad` — `std::vector<uint8_t>`, any size (may be empty).
- **Out / Returns:** as above.

#### `Aes256::encrypt(plaintext, key, ciphertext)` *(auto nonce)*
Convenience overload: generates a fresh random nonce internally (so it can
never be reused by accident) and prepends it to the output:
`[IV][ciphertext][tag]`. Use `decrypt(ciphertext, key, plaintext)` to read
it back.
- **In:** `plaintext`, `key` — 32 bytes.
- **Out:** `ciphertext` — plaintext + 28 bytes.
- **Returns:** `kOk` (0) or a negative code.

#### `Aes256::decrypt(ciphertext, key, nonce, tag, plaintext)`
Decrypts and authenticates with AES-256-GCM. Fails with `kErrAuth` (and no
output) if the key, nonce or tag does not match the ciphertext.
- **In:** `ciphertext`; `key` — 32 bytes; `nonce` — 12 bytes; `tag` — 16 bytes.
- **Out:** `plaintext` — the original message.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2), `kErrAuth` (-3).

#### `Aes256::decrypt(ciphertext, key, nonce, aad, tag, plaintext)`
Same, using the same associated data that was bound into the tag at
encryption. Fails with `kErrAuth` if the AAD, key, nonce or tag does not
match.
- **In:** as above + `aad` — exactly the bytes used at encryption.
- **Out / Returns:** as above.

#### `Aes256::decrypt(ciphertext, key, plaintext)` *(auto nonce)*
Decrypts the `[IV][ciphertext][tag]` layout produced by the auto-nonce
`encrypt()` overload; the IV is parsed back out automatically.
- **In:** `ciphertext`, `key` — 32 bytes.
- **Out:** `plaintext`.
- **Returns:** `kOk` (0) or a negative code.

### Rsa4096

RSA-4096 asymmetric encryption (OAEP-SHA256) and signatures (PSS-SHA256).
Constants: `kBits = 4096`, `kModulusSize = 512` bytes,
`kMaxPlaintext = 446` bytes per `encrypt()` call — use RSA to wrap a
symmetric key, not bulk data.

#### `Rsa4096::algorithmName()`
- **Returns:** `"RSA-4096 (OAEP-SHA256 / PSS-SHA256)"`.

#### `Rsa4096::generateKeyPair(outputKey)`
Generates a 4096-bit RSA key pair (slow — takes seconds).
- **Out:** `outputKey` — `EVP_PKEY**`; you own the new key and must free it
  with `EVP_PKEY_free()` — easiest via `Crypto::wrapPkey()`
  (`include/OpensslRaii.hpp`).
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2).

#### `Rsa4096::encrypt(publicKey, plaintext, ciphertext)`
Encrypts with the public key (OAEP, SHA-256). Maximum 446 bytes of
plaintext per call.
- **In:** `publicKey` — `EVP_PKEY*`; `plaintext` — max 446 bytes.
- **Out:** `ciphertext` — 512 bytes.
- **Returns:** `kOk` (0) or a negative code (`kErrInvalidArgument` if too large).

#### `Rsa4096::decrypt(privateKey, ciphertext, plaintext)`
Decrypts with the private key (OAEP, SHA-256).
- **In:** `privateKey` — `EVP_PKEY*`; `ciphertext` — 512 bytes.
- **Out:** `plaintext`.
- **Returns:** `kOk` (0) or a negative code.

#### `Rsa4096::sign(privateKey, digest, signature)`
Signs a SHA-256 digest with the private key (PSS, SHA-256).
- **In:** `privateKey` — `EVP_PKEY*`; `digest` — 32 bytes (e.g. from `Sha256::hash`).
- **Out:** `signature` — 512 bytes.
- **Returns:** `kOk` (0) or a negative code.

#### `Rsa4096::verify(publicKey, digest, signature)`
Verifies an RSA-PSS signature over a SHA-256 digest with the public key.
- **In:** `publicKey` — `EVP_PKEY*`; `digest` — 32 bytes; `signature` — 512 bytes.
- **Returns:** `kOk` (0) when valid, `kErrAuth` (-3) when it does not match, other negative codes on error.

#### `Rsa4096::savePublicKeyPem(key, pem)` / `savePrivateKeyPem(key, pem)`
Serializes the key to standard PEM text (in memory — store it to a file or
send it over a wire).
- **In:** `key` — `EVP_PKEY*`.
- **Out:** `pem` — `std::string`.
- **Returns:** `kOk` (0) or a negative code.

#### `Rsa4096::loadPublicKeyPem(pem, outputKey)` / `loadPrivateKeyPem(pem, outputKey)`
Parses PEM text back into a key.
- **In:** `pem` — `std::string`.
- **Out:** `outputKey` — `EVP_PKEY**`, owned by the caller (`Crypto::wrapPkey()`).
- **Returns:** `kOk` (0) or a negative code.

#### `Rsa4096::savePublicKeyDer(key, der)` / `savePrivateKeyDer(key, der)`
Same as the PEM pair but as DER bytes (`std::vector<uint8_t>`) — the
compact binary form.

#### `Rsa4096::loadPublicKeyDer(der, outputKey)` / `loadPrivateKeyDer(der, outputKey)`
Parses DER bytes back into a key.
- **In:** `der` — `std::vector<uint8_t>`.
- **Out:** `outputKey` — `EVP_PKEY**`, owned by the caller.
- **Returns:** `kOk` (0) or a negative code.

### MlKem768

ML-KEM-768 (FIPS 203) post-quantum key encapsulation. Requires OpenSSL 3.5+
with ML-KEM support; without it every call fails with `kErrUnavailable`
(-4) but the library still builds.

#### `MlKem768::algorithmName()`
- **Returns:** `"ML-KEM-768 (FIPS 203)"`.

#### `MlKem768::generateKeyPair(publicKey, secretKey)`
Generates a key pair as **DER bytes** (no OpenSSL pointers cross the API
boundary).
- **Out:** `publicKey` — DER X.509 SubjectPublicKeyInfo; `secretKey` — DER PKCS#8.
- **Returns:** `kOk` (0) or a negative code (`kErrUnavailable` without ML-KEM).

#### `MlKem768::encapsulate(publicKey, ciphertext, sharedSecret)`
Encapsulates a fresh 32-byte shared secret to the given public key. The
ciphertext is sent to the key owner; only they can recover the secret.
- **In:** `publicKey` — the recipient's DER public key.
- **Out:** `ciphertext` — send this to the recipient; `sharedSecret` — 32 bytes, known only to you and them.
- **Returns:** `kOk` (0) or a negative code.

#### `MlKem768::decapsulate(ciphertext, secretKey, sharedSecret)`
Recovers the shared secret from the ciphertext with the matching secret key.
- **In:** `ciphertext` — from `encapsulate()`; `secretKey` — your DER secret key.
- **Out:** `sharedSecret` — the same 32 bytes the sender derived.
- **Returns:** `kOk` (0) or a negative code.

### Hkdf

HKDF-SHA256 key derivation (RFC 5869). Derives cryptographically
independent keys from input key material (e.g. a KEM shared secret).
Constant: `kMaxOutputLength = 255 * 32` bytes.

#### `Hkdf::algorithmName()`
- **Returns:** `"HKDF-SHA256 (RFC 5869)"`.

#### `Hkdf::derive(inputKeyMaterial, salt, info, outputLength, output)`
Derives `outputLength` bytes of key material.
- **In:** `inputKeyMaterial` — the secret (non-empty); `salt` — optional, may be empty; `info` — optional context label (e.g. `"client->server"`), may be empty; `outputLength` — how many bytes you need (max `kMaxOutputLength`).
- **Out:** `output` — `std::vector<uint8_t>`, `outputLength` bytes.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2).

### Sha256

One-shot SHA-256 / SHA-512 hashing. Constants: `kDigestSize = 32`
(SHA-256), `kDigest512Size = 64` (SHA-512).

#### `Sha256::algorithmName()`
- **Returns:** `"SHA-256 / SHA-512"`.

#### `Sha256::hash(message, digest)`
SHA-256 of the message. Empty input is valid (returns the well-known digest
of the empty string).
- **In:** `message` — any bytes.
- **Out:** `digest` — 32 bytes.
- **Returns:** `kOk` (0) or a negative code.

#### `Sha256::hash512(message, digest)`
SHA-512 of the message.
- **In:** `message` — any bytes.
- **Out:** `digest` — 64 bytes.
- **Returns:** `kOk` (0) or a negative code.

### PostQuantum

One-call post-quantum hybrid encryption: ML-KEM-768 + HKDF-SHA256 +
AES-256-GCM. Envelope layout (binary):
`[4-byte LE KEM ciphertext length][KEM ciphertext][AES-GCM: 12B IV][ciphertext][16B tag]`.
The KEM ciphertext is bound as AAD, so the whole envelope is authenticated.

#### `PostQuantum::algorithmName()`
- **Returns:** `"ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"`.

#### `PostQuantum::encrypt(recipientPublicKey, plaintext, envelope)`
Seals plaintext to the recipient's ML-KEM-768 public key.
- **In:** `recipientPublicKey` — DER public key (from `MlKem768::generateKeyPair`); `plaintext` — the message.
- **Out:** `envelope` — everything needed to decrypt, as one byte vector.
- **Returns:** `kOk` (0) or a negative code.

#### `PostQuantum::decrypt(recipientSecretKey, envelope, plaintext)`
Opens an envelope with the recipient's secret key.
- **In:** `recipientSecretKey` — DER secret key; `envelope` — from `encrypt()`.
- **Out:** `plaintext` — the original message.
- **Returns:** `kOk` (0), or `kErrAuth` (-3) if the envelope was tampered with or sealed to a different key.

## Typical call

```cpp
#include "Crypto.hpp"

Crypto::Aes256 aes;
std::vector<uint8_t> key, iv, ciphertext, plaintext;
std::array<uint8_t, 16> tag;

int rc = aes.generateKey(key);                   // 0 = ok
rc = aes.generateIv(iv);
rc = aes.encrypt(plaintext, key, iv, ciphertext, tag);
rc = aes.decrypt(ciphertext, key, iv,
                 std::vector<uint8_t>(tag.begin(), tag.end()), plaintext);
```

## Building

Requirements:

* CMake >= 3.20, Ninja (or Make), a C++17 compiler (MinGW-w64 GCC or MSVC)
* OpenSSL >= 3.5 (ML-KEM-768 requires 3.5+)

```bash
# shared library (DLL on Windows) — the default
cmake -S . -B build-shared -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-shared

# static library — same sources, one switch
cmake -S . -B build-static -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build build-static
```

The `scripts/build.ps1` helper builds with the in-workspace toolchain and
can run the tests right after: `pwsh -ExecutionPolicy Bypass -File
scripts/build.ps1 -Linkage shared -Test`.

The example executables (`examples/usage_example.cpp` and
`examples/quickstart.cpp`) are built automatically and land in `build-*/bin/`
next to the library. They exercise every class: key generation, encrypt,
decrypt, sign, verify, KEM encapsulate/decapsulate, HKDF/SHA-256, RSA key
persistence, the hybrid envelope, and a simulated handshake +
5-message session, plus negative tests that show how each failure class
surfaces as a distinct code.

The test suite (`tests/test_main.cpp`, no external test framework) is
registered with CTest:

```bash
ctest --test-dir build-shared --output-on-failure     # shared build
ctest --test-dir build-static --output-on-failure     # static build
```

It covers round trips, every negative path with its exact error code, the
error-model contract, known-answer vectors (RFC 5869 HKDF, SHA-256/512),
and multithreaded stress tests that hammer a single shared instance from
several threads. When you run `Crypto_tests.exe` directly in a terminal it
pauses at the end so the window stays open; CTest and redirected runs skip
the pause automatically, and `CRYPTO_NO_PAUSE=1` forces it off.

## Getting OpenSSL 3.5+

### vcpkg (recommended)

```bash
git clone https://github.com/microsoft/vcpkg
./vcpkg/bootstrap-vcpkg.bat
./vcpkg/vcpkg.exe install openssl --triplet x64-mingw-static   # or your triplet

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \
      -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
      -DVCPKG_INSTALLED_DIR=<vcpkg>/installed
```

### From source

```bash
tar -xzf openssl-3.5.9.tar.gz && cd openssl-3.5.9
perl Configure mingw64 no-shared no-tests --prefix=<install-dir> --openssldir=<install-dir>/ssl
mingw32-make -j
mingw32-make install_sw

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=<install-dir>
```

## CMake options

| Option | Default | Meaning |
|---|---|---|
| `BUILD_SHARED_LIBS` | `ON` | Shared library (`OFF` = static library) |
| `CRYPTO_BUILD_EXAMPLES` | `ON` | Build `examples/usage_example.cpp` and `examples/quickstart.cpp` |
| `CRYPTO_BUILD_TESTS` | `ON` | Build `tests/test_main.cpp` and register it with CTest |
| `CRYPTO_OPENSSL_STATIC` | `ON` | Define `OPENSSL_STATIC` (needed when OpenSSL is a static library, e.g. vcpkg static triplets) |

## Notes

* **Nonce discipline** — generate a fresh IV per message with `generateIv()`
  (or use the auto-nonce overloads). Never reuse an IV with the same key.
  With random 96-bit IVs the collision risk becomes meaningful only after
  ~2³² messages under one key — rotate keys at extreme volume.
* ML-KEM-768 requires OpenSSL 3.5+; without it every `MlKem768` call fails
  with `kErrUnavailable` (-4) — the library still builds and runs on older
  OpenSSL.
* Keys from `Rsa4096::generateKeyPair()` are returned as `EVP_PKEY*` owned by
  the caller; wrap them with `Crypto::wrapPkey()`
  (`include/OpensslRaii.hpp`) for automatic cleanup with `EVP_PKEY_free()`.
* ML-KEM key material is exchanged as DER (`i2d_PUBKEY` / `i2d_PrivateKey`),
  so no OpenSSL pointer ever crosses the API boundary.
* `PostQuantum::encrypt()` / `decrypt()` is the one-call version of the
  classic hybrid handshake: ML-KEM encapsulate → HKDF → AES-GCM with the KEM
  ciphertext bound as AAD, so the whole envelope is authenticated.

## Project layout

```
Crypto/
├── CMakeLists.txt
├── include/
│   ├── Crypto.hpp   # single-include convenience header
│   ├── Aes256.hpp
│   ├── Rsa4096.hpp
│   ├── MlKem768.hpp
│   ├── Hkdf.hpp
│   ├── Sha256.hpp
│   ├── PostQuantum.hpp
│   └── OpensslRaii.hpp     # RAII wrappers for OpenSSL resources
├── src/
├── examples/
├── tests/
├── cmake/
└── scripts/
```
