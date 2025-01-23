#pragma once

#include <cstdint>
#include <map>
#include <minwindef.h>
#include <ntdef.h>
#include <string>
#include <unordered_map>

extern "C" NTSTATUS NTAPI trampoline(DWORD syscallNo,
                                     uintptr_t syscallInstrAddr, ...);

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
  NTSTATUS Call(const std::string &funcName, Args... args) {
    return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                      args...);
  }
};

} // namespace spi
