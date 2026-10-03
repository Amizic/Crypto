#pragma once

// ObsidianGuard - crypto_module.hpp
// Common interface implemented by every crypto module.

#include <string>

#include "crypto_types.hpp"

namespace ObsidianGuard {

/// Base class for all crypto modules.
///
/// Every module exposes the name of its algorithm and the description of the
/// last error that occurred inside it. None of the implementations print to
/// the console, throw exceptions, or terminate the process; every failure is
/// reported through CryptoResult and mirrored in the stored last error.
class OBSIDIAN_GUARD_API ICryptoModule {
public:
    virtual ~ICryptoModule() noexcept = default;

    /// Human readable algorithm identifier (e.g. "AES-256-GCM").
    virtual const char* algorithmName() const noexcept = 0;

    /// Description of the last error that occurred in this module instance.
    /// Empty if no error has occurred (or after clearError()).
    virtual const std::string& getLastError() const noexcept = 0;

    /// Reset the stored last error (both the text and the OpenSSL error queue).
    virtual void clearError() noexcept = 0;

protected:
    ICryptoModule() noexcept = default;
    ICryptoModule(const ICryptoModule&) = delete;
    ICryptoModule& operator=(const ICryptoModule&) = delete;

    /// Store the description of the most recent failure.
    void setLastError(const std::string& message) noexcept { lastError_ = message; }

    std::string lastError_;
};

} // namespace ObsidianGuard
