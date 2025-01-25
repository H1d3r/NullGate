#pragma once

#include <cstdint>
#include <map>
#include <minwindef.h>
#include <ntdef.h>
#include <string>
#include <unordered_map>

extern "C" NTSTATUS NTAPI trampoline(size_t syscallNo, uintptr_t syscallAddr,
                                     size_t ArgumentsSize, ...);
namespace nullgate {

class syscalls {
  std::map<PDWORD, std::string> stubMap;
  std::unordered_map<std::string, DWORD> syscallNoMap;
  void populateStubs();
  void populateSyscalls();
  DWORD getSyscallNumber(const std::string &func);
  uintptr_t getSyscallInstrAddr();

public:
  explicit syscalls();

  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args... args) {
    // We don't care that are right know there could be more on the stack, this
    // is supposed to represent the number of args on the stack disregarding the
    // added arguments
    constexpr size_t argStackSize =
        sizeof...(args) <= 4 ? 0 : sizeof...(args) - 4;
    return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                      argStackSize, std::forward<Args>(args)...);
  }
};

} // namespace nullgate
