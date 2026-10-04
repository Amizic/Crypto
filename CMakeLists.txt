cmake_minimum_required(VERSION 3.20)

project(Crypto
    VERSION 1.0.0
    DESCRIPTION "Modular C++17 cryptography library (AES-256-GCM, RSA-4096, ML-KEM-768) built on OpenSSL"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
# BUILD_SHARED_LIBS is the standard CMake variable: ON builds Crypto as
# a shared library (DLL on Windows), OFF builds a static library. The library
# itself is declared with add_library(Crypto ...) without an explicit
# type, so this single switch selects between both variants.
option(BUILD_SHARED_LIBS "Build Crypto as a shared library (ON) or static library (OFF)" ON)
option(CRYPTO_BUILD_EXAMPLES "Build the usage example executable" ON)
option(CRYPTO_BUILD_TESTS "Build the Crypto test suite (CTest)" ON)
option(CRYPTO_OPENSSL_STATIC "Define OPENSSL_STATIC. Required when OpenSSL is available as a static library (e.g. vcpkg x64-*-static triplets)" ON)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(OpenSSL 3.5 REQUIRED)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(Crypto
    src/Aes256.cpp
    src/Rsa4096.cpp
    src/MlKem768.cpp
    src/Hkdf.cpp
    src/Sha256.cpp
    src/PostQuantum.cpp
)

target_include_directories(Crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(Crypto PUBLIC OpenSSL::Crypto)

if(MINGW)
    # A static MinGW OpenSSL links against these Windows system libraries
    # (visible in the OpenSSL build log as LDLIBS).
    target_link_libraries(Crypto PUBLIC ws2_32 gdi32 crypt32)
endif()

# Import/export semantics (CryptoLite convention):
#   * shared build  -> the library's own TUs export (CRYPTO_EXPORTS),
#                      consumers implicitly dllimport
#   * static build  -> CRYPTO_STATIC is public, so no declspec at all
if(BUILD_SHARED_LIBS)
    target_compile_definitions(Crypto PRIVATE CRYPTO_EXPORTS)
else()
    target_compile_definitions(Crypto PUBLIC CRYPTO_STATIC)
endif()
if(CRYPTO_OPENSSL_STATIC)
    target_compile_definitions(Crypto PUBLIC OPENSSL_STATIC)
endif()

set_target_properties(Crypto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

if(NOT WIN32)
    set_target_properties(Crypto PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# When OpenSSL is statically linked into the DLL, do not re-export its symbols.
if(MINGW AND BUILD_SHARED_LIBS)
    target_link_options(Crypto PRIVATE "LINKER:--exclude-libs,ALL")
endif()

# Copy the MinGW runtime DLLs next to an executable so it runs without extra
# PATH configuration.
function(crypto_copy_mingw_runtime target)
    if(NOT MINGW)
        return()
    endif()
    get_filename_component(_CRYPTO_MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(_CRYPTO_MINGW_RUNTIME_DLLS)
    foreach(_runtimeDll IN ITEMS libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
        if(EXISTS "${_CRYPTO_MINGW_BIN_DIR}/${_runtimeDll}")
            list(APPEND _CRYPTO_MINGW_RUNTIME_DLLS "${_CRYPTO_MINGW_BIN_DIR}/${_runtimeDll}")
        endif()
    endforeach()
    if(_CRYPTO_MINGW_RUNTIME_DLLS)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_CRYPTO_MINGW_RUNTIME_DLLS}
                    $<TARGET_FILE_DIR:${target}>
            COMMENT "Copying MinGW runtime DLLs next to ${target}")
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Example
# ---------------------------------------------------------------------------
if(CRYPTO_BUILD_EXAMPLES)
    add_executable(usage_example examples/usage_example.cpp)
    target_link_libraries(usage_example PRIVATE Crypto)
    set_target_properties(usage_example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    crypto_copy_mingw_runtime(usage_example)

    add_executable(quickstart examples/quickstart.cpp)
    target_link_libraries(quickstart PRIVATE Crypto)
    set_target_properties(quickstart PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    crypto_copy_mingw_runtime(quickstart)
endif()

# ---------------------------------------------------------------------------
# Tests (CTest)
# ---------------------------------------------------------------------------
include(CTest)
if(CRYPTO_BUILD_TESTS AND BUILD_TESTING)
    add_executable(Crypto_tests tests/test_main.cpp)
    target_link_libraries(Crypto_tests PRIVATE Crypto)
    set_target_properties(Crypto_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    crypto_copy_mingw_runtime(Crypto_tests)

    add_test(NAME Crypto_tests COMMAND Crypto_tests)
    # RSA-4096 key generation is intentionally slow; be generous on CI.
    # The test binary pauses at the end when run interactively; disable the
    # pause under CTest so automated runs never wait for a keypress.
    set_tests_properties(Crypto_tests PROPERTIES
        TIMEOUT 600
        ENVIRONMENT "CRYPTO_NO_PAUSE=1"
    )
endif()

# ---------------------------------------------------------------------------
# Install / package rules
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS Crypto EXPORT CryptoTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT CryptoTargets
    FILE CryptoTargets.cmake
    NAMESPACE Crypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto
)

configure_package_config_file(
    cmake/CryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto
)
