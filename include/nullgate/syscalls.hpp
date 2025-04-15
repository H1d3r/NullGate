#pragma once

#include <cstdint>
#include <map>
#include <minwindef.h>
#include <ntdef.h>
#include <string>
#include <type_traits>
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
  DWORD getSyscallNumber(uint64_t funcNameHash);
  uintptr_t getSyscallInstrAddr();

  // We don't care that are right know there could be more on the stack, this
  // is supposed to represent the number of args on the stack disregarding the
  // added arguments
  template <typename... Args> constexpr size_t getArgStackSize(Args &&...args) {
    return sizeof...(args) <= 4 ? 0 : sizeof...(args) - 4;
  }

public:
  explicit syscalls();

  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args... args) {
    return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                      getArgStackSize(args...), std::forward<Args>(args)...);
  }

  template <typename... Args>
  NTSTATUS Call(uint64_t funcNameHash, Args... args) {
    return trampoline(getSyscallNumber(funcNameHash), getSyscallInstrAddr(),
                      getArgStackSize(args...), std::forward<Args>(args)...);
  }

  template <typename func, typename... Ts>
    requires std::invocable<func, Ts...>
  NTSTATUS SCall(const std::string &funcName, Ts &&...args) {
    return [&]<typename R, typename... Args>(std::type_identity<R(Args...)>) {
      return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                        getArgStackSize(args...), std::forward<Args>(args)...);
    }(std::type_identity<func>{});
  }

  template <typename func, typename... Ts>
    requires std::invocable<func, Ts &&...>
  NTSTATUS SCall(uint64_t funcNameHash, Ts &&...args) {
    return [&]<typename R, typename... Args>(std::type_identity<R(Args...)>) {
      return trampoline(getSyscallNumber(funcNameHash), getSyscallInstrAddr(),
                        getArgStackSize(args...), std::forward<Args>(args)...);
    }(std::type_identity<func>{});
  }
};

} // namespace nullgate
