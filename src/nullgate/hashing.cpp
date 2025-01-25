#include <nullgate/hashing.hpp>

namespace nullgate {

uint64_t fnv1Runtime(const char *str) {
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

} // namespace nullgate
