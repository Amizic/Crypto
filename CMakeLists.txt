cmake_minimum_required(VERSION 3.20)

project(ObsidianGuard
    VERSION 1.0.0
    DESCRIPTION "Modular C++17 cryptography library (AES-256-GCM, RSA-4096, ML-KEM-768) built on OpenSSL"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
# BUILD_SHARED_LIBS is the standard CMake variable: ON builds ObsidianGuard as
# a shared library (DLL on Windows), OFF builds a static library. The library
# itself is declared with add_library(ObsidianGuard ...) without an explicit
# type, so this single switch selects between both variants.
option(BUILD_SHARED_LIBS "Build ObsidianGuard as a shared library (ON) or static library (OFF)" ON)
option(OBSIDIAN_GUARD_BUILD_EXAMPLES "Build the usage example executable" ON)
option(OBSIDIAN_GUARD_OPENSSL_STATIC "Define OPENSSL_STATIC. Required when OpenSSL is available as a static library (e.g. vcpkg x64-*-static triplets)" ON)

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
add_library(ObsidianGuard
    src/aes256_gcm.cpp
    src/rsa4096.cpp
    src/ml_kem768.cpp
)

target_include_directories(ObsidianGuard PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(ObsidianGuard PUBLIC OpenSSL::Crypto)

if(MINGW)
    # A static MinGW OpenSSL links against these Windows system libraries
    # (visible in the OpenSSL build log as LDLIBS).
    target_link_libraries(ObsidianGuard PUBLIC ws2_32 gdi32 crypt32)
endif()

target_compile_definitions(ObsidianGuard PRIVATE OBSIDIAN_GUARD_EXPORTS)
if(BUILD_SHARED_LIBS)
    target_compile_definitions(ObsidianGuard PUBLIC OBSIDIAN_GUARD_SHARED)
endif()
if(OBSIDIAN_GUARD_OPENSSL_STATIC)
    target_compile_definitions(ObsidianGuard PUBLIC OPENSSL_STATIC)
endif()

set_target_properties(ObsidianGuard PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

if(NOT WIN32)
    set_target_properties(ObsidianGuard PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# When OpenSSL is statically linked into the DLL, do not re-export its symbols.
if(MINGW AND BUILD_SHARED_LIBS)
    target_link_options(ObsidianGuard PRIVATE "LINKER:--exclude-libs,ALL")
endif()

# ---------------------------------------------------------------------------
# Example
# ---------------------------------------------------------------------------
if(OBSIDIAN_GUARD_BUILD_EXAMPLES)
    add_executable(usage_example examples/usage_example.cpp)
    target_link_libraries(usage_example PRIVATE ObsidianGuard)
    set_target_properties(usage_example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    if(MINGW)
        # Copy the MinGW runtime DLLs next to the executable so it runs
        # without extra PATH configuration.
        get_filename_component(_OBSIDIAN_GUARD_MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set(_OBSIDIAN_GUARD_MINGW_RUNTIME_DLLS)
        foreach(_runtimeDll IN ITEMS libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
            if(EXISTS "${_OBSIDIAN_GUARD_MINGW_BIN_DIR}/${_runtimeDll}")
                list(APPEND _OBSIDIAN_GUARD_MINGW_RUNTIME_DLLS "${_OBSIDIAN_GUARD_MINGW_BIN_DIR}/${_runtimeDll}")
            endif()
        endforeach()
        if(_OBSIDIAN_GUARD_MINGW_RUNTIME_DLLS)
            add_custom_command(TARGET usage_example POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_OBSIDIAN_GUARD_MINGW_RUNTIME_DLLS}
                        $<TARGET_FILE_DIR:usage_example>
                COMMENT "Copying MinGW runtime DLLs next to usage_example.exe")
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# Install / package rules
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS ObsidianGuard EXPORT ObsidianGuardTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ObsidianGuardTargets
    FILE ObsidianGuardTargets.cmake
    NAMESPACE ObsidianGuard::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ObsidianGuard
)

configure_package_config_file(
    cmake/ObsidianGuardConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ObsidianGuardConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ObsidianGuard
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ObsidianGuardConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ObsidianGuardConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ObsidianGuardConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ObsidianGuard
)
