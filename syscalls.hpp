#pragma once

#include <cstdint>
#include <map>
#include <minwindef.h>
#include <ntdef.h>
#include <string>
#include <unordered_map>

namespace spi {

class syscalls {
  std::map<PDWORD, std::string> stubMap;
  std::unordered_map<std::string, DWORD> syscallNoMap;
  void populateStubs();
  void populateSyscalls();

public:
  explicit syscalls();
  DWORD getSyscallNumber(const std::string &func);
  uintptr_t getSyscallInstrAddr();

  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args...);
};

} // namespace spi
