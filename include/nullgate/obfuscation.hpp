#pragma once

#include <cstdint>
#include <string>
#include <vector>

inline const std::string KEY = "FfqO3ZQ6XJ+SICAp";

namespace nullgate {

class obfuscation {
  static std::string base64Encode(const std::string &in);

  static std::string base64Decode(const std::string &in);

  static std::string xorHash(const std::string &str);

  static uint8_t char2int(char c);

public:
  static inline consteval uint64_t fnv1Const(const char *str) {
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
  static uint64_t fnv1Runtime(const char *str);

  static std::string xorEncode(const std::string &in);

  static std::string xorDecode(const std::string &in);

  static std::vector<unsigned char> hex2bin(const std::string &hexString);
};

} // namespace nullgate
