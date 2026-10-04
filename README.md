# ObsidianGuard

A small, stateless, C++17 cryptography library built on OpenSSL. Six
classes, one error model:

| Class | Algorithm | Typical use |
|---|---|---|
| `Aes256` | AES-256-GCM (`EVP_aes_256_gcm`), optional AAD | Authenticated symmetric encryption |
| `Rsa4096` | RSA-4096, OAEP-SHA256 / PSS-SHA256, PEM/DER key persistence | Asymmetric encryption and digital signatures |
| `MlKem768` | ML-KEM-768 (FIPS 203, post-quantum) | Key encapsulation (requires OpenSSL 3.5+) |
| `Hkdf` | HKDF-SHA256 (RFC 5869) | Key derivation from shared secrets / master keys |
| `Sha256` | SHA-256 / SHA-512 | One-shot hashing |
| `PostQuantum` | ML-KEM-768 + HKDF-SHA256 + AES-256-GCM | One-call hybrid encryption |

## ObsidianGuard vs ObsidianGuardLite

This workspace ships two related libraries. Both implement the same
algorithms (AES-256-GCM, RSA-4096, ML-KEM-768) with aligned return codes and
naming, but with different key-ownership models — pick per project:

| | **ObsidianGuard (this one)** | **ObsidianGuardLite** |
|---|---|---|
| Model | **Stateless engine** — classes hold nothing; keys are byte vectors / `EVP_PKEY*` you pass per call | **Key-owning objects** — each object stores its key inside itself |
| Locks | none — thread-safe by construction | internal mutex per object (uncontended in per-client use) |
| Key storage | wherever *your* code keeps it (e.g. a per-client session struct) | inside the object (non-copyable); PEM save/load to files |
| Best for | servers with many clients/threads, pinned cores, custom session management, maximum throughput | small tools and apps that want self-contained per-client objects |

Use **ObsidianGuard** when your application owns the key lifecycle and wants
a zero-lock, zero-state engine; use **ObsidianGuardLite** when you prefer
each object to carry its key and save/load itself. Both are thread-safe and
covered by the same style of test suites.

## Design

* **Plain `int` return codes, nothing else** — every public method returns
  `0` on success or a negative error code on failure. No result structs, no
  message strings; the code *is* the error. The same constants are exposed
  as `static constexpr int` members on **every class** (ObsidianGuardLite
  convention), so you can write readable checks:

  | Constant | Value | Meaning |
  |---|---|---|
  | `kOk` | `0` | success |
  | `kErrInvalidArgument` | `-1` | bad input (wrong size, null key, empty buffer, ...) |
  | `kErrOpenSsl` | `-2` | the underlying OpenSSL call failed |
  | `kErrAuth` | `-3` | authentication/verification failed (wrong key, nonce (IV), tag or signature) |
  | `kErrUnavailable` | `-4` | the algorithm is not available in this OpenSSL build |
  | `kErrInternal` | `-5` | unexpected internal failure (reserved) |
  | `kErrFile` | `-6` | file I/O error (parity with ObsidianGuardLite; unused here) |

  ```cpp
  int rc = aes.decrypt(cipher, key, iv, tag, plain);
  if (rc != 0) { /* failed */ }
  if (rc == ObsidianGuard::Aes256::kErrAuth) { /* tampered data */ }
  ```

  For example, AES-GCM decryption reports `kErrInvalidArgument` for a wrong
  key *size*, `kErrAuth` when the tag/ciphertext/AAD was tampered with, and
  RSA verification reports `kErrAuth` for a bad signature while unparseable
  ciphertext yields `kErrOpenSsl` — different causes, different codes.
* **Stateless classes, trivially thread-safe** — the classes hold no state
  at all (keys are passed in per call), so any number of threads may share
  one instance — or use one instance per client/core — with zero locking and
  zero contention. All crypto work happens on per-call, thread-local OpenSSL
  state.
* **No exceptions, no printing, no abort** — every method is `noexcept` and
  reports everything through its return code.
* **One include** — `#include "obsidianguard.hpp"` brings in all six classes.
* **AAD support** — `Aes256` has encrypt/decrypt overloads that bind
  associated data (headers, IDs, metadata) into the GCM tag: it is
  authenticated but not encrypted, and any tampering with it is detected.
* **RAII** — internally, `EVP_CIPHER_CTX`, `EVP_MD_CTX`, `EVP_PKEY_CTX` and
  `EVP_PKEY` are owned by `std::unique_ptr` wrappers centralized in
  [`include/OpensslRaii.hpp`](include/OpensslRaii.hpp); no manual frees
  exist anywhere.
* **C++17** — `const std::vector<uint8_t>&` buffers everywhere (no
  `std::span`), `noexcept`, no `goto`.

Typical call:

```cpp
#include "obsidianguard.hpp"

ObsidianGuard::Aes256 aes;
std::vector<uint8_t> key, iv, ciphertext, plaintext;
std::array<uint8_t, 16> tag;

int rc = aes.generateKey(key);                       // 0 = ok
if (rc != 0) { /* handle failure */ }

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

The `scripts/build.ps1` helper builds with the in-workspace toolchain and can
run the tests right after: `pwsh -ExecutionPolicy Bypass -File scripts/build.ps1
-Linkage shared -Test`.

`add_library(ObsidianGuard ...)` is declared without an explicit type, so the
standard `BUILD_SHARED_LIBS` variable (ON by default) selects shared vs
static linking.

The example executables are built automatically (`examples/usage_example.cpp`
and `examples/quickstart.cpp`) and land in `build-*/bin/` next to the
library. Run them to exercise every class: key generation, encrypt, decrypt,
sign, verify, KEM encapsulate/decapsulate, HKDF/SHA-256, RSA key
persistence, the hybrid envelope, and a simulated handshake + 5-message
session, plus negative tests that show how each failure class surfaces as a
distinct code.

The test suite (`tests/test_main.cpp`, no external test framework) is built
and registered with CTest as well:

```bash
ctest --test-dir build-shared --output-on-failure     # shared build
ctest --test-dir build-static --output-on-failure     # static build
```

It covers round trips, every negative path with its exact error code, the
error-model contract, known-answer vectors (RFC 5869 HKDF, SHA-256/512), and
multithreaded stress tests that hammer a single shared instance from several
threads. When you run `ObsidianGuard_tests.exe` directly in a terminal (or
double-click it), it pauses at the end so the window stays open while you
read the results; CTest and redirected runs skip the pause automatically,
and setting `OBSIDIAN_GUARD_NO_PAUSE=1` forces it off.

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
| `OBSIDIAN_GUARD_BUILD_EXAMPLES` | `ON` | Build `examples/usage_example.cpp` and `examples/quickstart.cpp` |
| `OBSIDIAN_GUARD_BUILD_TESTS` | `ON` | Build `tests/test_main.cpp` and register it with CTest |
| `OBSIDIAN_GUARD_OPENSSL_STATIC` | `ON` | Define `OPENSSL_STATIC` (needed when OpenSSL is a static library, e.g. vcpkg static triplets) |

## Project layout

```
ObsidianGuard/
├── CMakeLists.txt
├── include/
│   ├── obsidianguard.hpp   # single-include convenience header
│   ├── Aes256.hpp
│   ├── Rsa4096.hpp
│   ├── MlKem768.hpp
│   ├── Hkdf.hpp
│   ├── Sha256.hpp
│   ├── PostQuantum.hpp
│   └── OpensslRaii.hpp     # RAII wrappers for OpenSSL resources
├── src/
│   ├── Aes256.cpp
│   ├── Rsa4096.cpp
│   ├── MlKem768.cpp
│   ├── Hkdf.cpp
│   ├── Sha256.cpp
│   └── PostQuantum.cpp
├── examples/
│   ├── usage_example.cpp
│   └── quickstart.cpp
├── tests/
│   └── test_main.cpp        # dependency-free test suite (CTest)
├── cmake/
│   └── ObsidianGuardConfig.cmake.in
└── scripts/
    ├── build.ps1           # one-command build (shared/static)
    └── run_example.ps1     # one-command test run
```

## Notes

* **Nonce discipline** — `Aes256` takes the nonce (IV) as a parameter:
  generate a fresh one per message with `generateIv()`. The auto-nonce
  convenience overloads `encrypt(plaintext, key, ciphertext)` /
  `decrypt(ciphertext, key, plaintext)` generate the IV internally (output
  layout `[IV][ciphertext][tag]`), so it can never be reused. Never reuse an
  IV with the same key. With random 96-bit IVs the collision risk becomes
  meaningful only after ~2³² messages under one key — rotate keys at extreme
  volume.
* ML-KEM-768 requires OpenSSL 3.5+; without it every `MlKem768` call fails
  with `kErrUnavailable` (`-4`) — the library still builds and runs on older
  OpenSSL.
* Keys from `Rsa4096::generateKeyPair()` are returned as `EVP_PKEY*` owned by
  the caller; wrap them with `ObsidianGuard::wrapPkey()`
  (`include/OpensslRaii.hpp`) for automatic cleanup with `EVP_PKEY_free()`.
* ML-KEM key material is exchanged as DER (`i2d_PUBKEY` / `i2d_PrivateKey`),
  so no OpenSSL pointer ever crosses the API boundary.
* `PostQuantum::encrypt()` / `decrypt()` is the one-call version of the
  classic hybrid handshake: ML-KEM encapsulate → HKDF → AES-GCM with the KEM
  ciphertext bound as AAD, so the whole envelope is authenticated.
