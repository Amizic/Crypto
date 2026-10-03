#pragma once

// ObsidianGuard - crypto_module.hpp
// Common interface implemented by every crypto module.

#include <atomic>
#include <string>
#include <thread>

#include "crypto_types.hpp"

namespace ObsidianGuard {
namespace detail {

/// Tiny non-throwing spinlock used to guard a module's shared last-error
/// text. The critical sections are short string copies, so spinning (with a
/// yield backoff) is cheap; unlike std::mutex, locking cannot throw, which
/// keeps the ICryptoModule accessors noexcept.
class SpinLock {
public:
    SpinLock() noexcept = default;
    SpinLock(const SpinLock&) = delete;
    SpinLock& operator=(const SpinLock&) = delete;

    void lock() noexcept {
        // Fast path: uncontended acquire in one atomic operation.
        if (!flag_.test_and_set(std::memory_order_acquire)) {
            return;
        }
        int spins = 0;
        while (flag_.test_and_set(std::memory_order_acquire)) {
            if (++spins >= 64) {
                spins = 0;
                std::this_thread::yield();
            }
        }
    }

    void unlock() noexcept { flag_.clear(std::memory_order_release); }

    class ScopedLock {
    public:
        explicit ScopedLock(SpinLock& lock) noexcept : lock_(lock) { lock_.lock(); }
        ~ScopedLock() { lock_.unlock(); }
        ScopedLock(const ScopedLock&) = delete;
        ScopedLock& operator=(const ScopedLock&) = delete;

    private:
        SpinLock& lock_;
    };

private:
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

} // namespace detail

/// Base class for all crypto modules.
///
/// Every module exposes the name of its algorithm and the description of the
/// last error that occurred inside it. None of the implementations print to
/// the console, throw exceptions, or terminate the process; every failure is
/// reported through CryptoResult and mirrored in the stored last error.
///
/// Thread safety: all crypto work happens on per-call, thread-local state
/// (OpenSSL contexts owned by the call, thread-local OpenSSL error queue), so
/// a single module instance may be shared between threads. The only shared
/// state is the stored last error, which is guarded internally: every
/// accessor returns a consistent snapshot, and concurrent failures are
/// resolved last-writer-wins. The CryptoResult returned by a call is always
/// the exact result of that call.
class OBSIDIAN_GUARD_API ICryptoModule {
public:
    virtual ~ICryptoModule() noexcept = default;

    /// Human readable algorithm identifier (e.g. "AES-256-GCM").
    virtual const char* algorithmName() const noexcept = 0;

    /// Thread-safe snapshot of the last error that occurred in this module
    /// instance, returned by value. Empty if no error has occurred (or after
    /// clearError()).
    virtual std::string getLastError() const noexcept = 0;

    /// Reset the stored last error. Also clears the OpenSSL error queue of
    /// the CALLING thread (OpenSSL keeps that queue per-thread).
    virtual void clearError() noexcept = 0;

protected:
    ICryptoModule() noexcept = default;
    ICryptoModule(const ICryptoModule&) = delete;
    ICryptoModule& operator=(const ICryptoModule&) = delete;

    /// Record the most recent failure description (thread-safe).
    void setLastError(std::string message) noexcept {
        detail::SpinLock::ScopedLock guard(errorLock_);
        lastError_ = std::move(message);
    }

    /// Thread-safe snapshot of the stored last error.
    std::string lastErrorSnapshot() const noexcept {
        detail::SpinLock::ScopedLock guard(errorLock_);
        return lastError_;
    }

    /// Clear the stored last error (thread-safe).
    void clearLastError() noexcept {
        detail::SpinLock::ScopedLock guard(errorLock_);
        lastError_.clear();
    }

    /// Store result.message as the last error and return the result
    /// unchanged, so every failure path can end in a single call:
    ///     return storeFailure(detail::paramFailure("..."));
    CryptoResult storeFailure(const CryptoResult& result) noexcept {
        setLastError(result.message);
        return result;
    }

private:
    mutable detail::SpinLock errorLock_; ///< guards lastError_
    std::string lastError_;              ///< shared state; touch only via the accessors above
};

} // namespace ObsidianGuard
