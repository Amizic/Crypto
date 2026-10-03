# Obsidian Guard Library

A professional, modular C++17 cryptography library built on OpenSSL.
Three modules share one interface and one error model:

| Module | Algorithm | Typical use |
|---|---|---|
| `Aes256GcmModule` | AES-256-GCM (`EVP_aes_256_gcm`) | Authenticated symmetric encryption |
| `Rsa4096Module` | RSA-4096, OAEP-SHA256 / PSS-SHA256 | Asymmetric encryption and digital signatures |
| `MlKem768Module` | ML-KEM-768 (FIPS 203, post-quantum) | Key encapsulation (requires OpenSSL 3.5+) |

## Design

* **Common interface** — every module implements `ICryptoModule`:
  `algorithmName()`, `getLastError()`, `clearError()`.
* **No exceptions, no printing, no abort** — every public method returns
  `CryptoResult { int code; std::string message; bool ok(); }` where `0`
  means success and negative values mean failure.
* **OpenSSL errors** — every OpenSSL failure is translated into
  `CryptoResult::failure` with the human readable description from
  `ERR_error_string(ERR_get_error(), nullptr)` and is also stored in the
  module's `lastError_` (visible via `getLastError()`).
* **RAII everywhere** — `EVP_CIPHER_CTX`, `EVP_MD_CTX`, `EVP_PKEY_CTX` and
  `EVP_PKEY` are owned by `std::unique_ptr` wrappers centralized in
  [`include/openssl_raii.hpp`](include/openssl_raii.hpp).
* **C++17** — `const std::vector<uint8_t>&` buffers everywhere (no
  `std::span`), all methods `noexcept` where possible, no `goto`.

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

`add_library(ObsidianGuard ...)` is declared without an explicit type, so the
standard `BUILD_SHARED_LIBS` variable (ON by default) selects shared vs
static linking.

The example executable is built automatically
(`examples/usage_example.cpp`) and lands in `build-*/bin/` next to the
library. Run it to exercise all three modules: key generation, encrypt,
decrypt, sign, verify, KEM encapsulate/decapsulate, plus negative tests that
show how failures surface through `CryptoResult` and `getLastError()`. It
ends with `system("pause")` on Windows so the output stays visible.

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
| `OBSIDIAN_GUARD_BUILD_EXAMPLES` | `ON` | Build `examples/usage_example.cpp` |
| `OBSIDIAN_GUARD_OPENSSL_STATIC` | `ON` | Define `OPENSSL_STATIC` (needed when OpenSSL is a static library, e.g. vcpkg static triplets) |

## Project layout

```
ObsidianGuard/
├── CMakeLists.txt
├── include/
│   ├── crypto_types.hpp    # CryptoResult + OBSIDIAN_GUARD_API export macro
│   ├── crypto_module.hpp   # ICryptoModule interface
│   ├── openssl_raii.hpp    # centralized RAII wrappers for OpenSSL resources
│   ├── aes256_gcm.hpp
│   ├── rsa4096.hpp
│   └── ml_kem768.hpp
├── src/
│   ├── error_utils.hpp     # internal error translation helpers (not installed)
│   ├── aes256_gcm.cpp
│   ├── rsa4096.cpp
│   └── ml_kem768.cpp
├── examples/
│   └── usage_example.cpp
├── cmake/
│   └── ObsidianGuardConfig.cmake.in
└── scripts/
    ├── build.ps1           # one-command build (shared/static)
    └── run_example.ps1     # one-command test run
```

## Notes

* ML-KEM-768 requires OpenSSL 3.5+; without it every `MlKem768Module` call
  fails with `CryptoResult::failure(-1, "ML-KEM not available. Requires
  OpenSSL 3.5+.")` — the library still builds and runs on older OpenSSL.
* Keys exchanged with `Rsa4096Module::generateKeyPair()` are returned as
  `EVP_PKEY*` owned by the caller; wrap them with
  `ObsidianGuard::wrapPkey()` (`include/openssl_raii.hpp`) for automatic
  cleanup with `EVP_PKEY_free()`.
* ML-KEM key material is exchanged as DER (`i2d_PUBKEY` /
  `i2d_PrivateKey`), so no OpenSSL pointer ever crosses the API boundary.
