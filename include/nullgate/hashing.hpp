#pragma once

#include <cstdint>

namespace nullgate {

inline consteval uint64_t fnv1Const(const char *str) {
  const uint64_t fnvOffsetBasis = 14695981039346656037;
  const uint64_t fnvPrime = 1099511628211;
  uint64_t hash = fnvOffsetBasis;
  char c{};
  while ((c = *str++)) {
    hash *= fnvPrime;
    hash ^= c;
  }
  return hash;
}

// Don't use for hardcoded strings, the string won't be obfuscated
uint64_t fnv1Runtime(const char *str);

} // namespace nullgate
