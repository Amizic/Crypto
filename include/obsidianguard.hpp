#pragma once

// ObsidianGuard - obsidianguard.hpp
// Single-include convenience header: everything the library exposes.
//   #include "obsidianguard.hpp"
// brings in all six classes (and their kErr* return-code constants).

#include "Aes256.hpp"
#include "Rsa4096.hpp"
#include "MlKem768.hpp"
#include "Hkdf.hpp"
#include "Sha256.hpp"
#include "PostQuantum.hpp"
