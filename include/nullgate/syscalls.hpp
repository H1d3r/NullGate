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

  // Either forwards args perferctly or if they're not compatible casts them to
  // the right type
  template <typename To, typename T> decltype(auto) forwardCast(T &&t) {
    if constexpr (std::is_same_v<std::decay_t<To>, std::decay_t<T>>) {
      return std::forward<To>(t);
    } else {
      return static_cast<To>(t);
    }
  }

public:
  explicit syscalls();

  // WARNING: this function does not cast parameters to the right type. Meaning
  // if the function being called expects `size_t` and `int` is passed there
  // could be serious issues. It is recommended to use SCall.
  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args... args) {
    return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                      getArgStackSize(args...), std::forward<Args>(args)...);
  }

  // WARNING: this function does not cast parameters to the right type. Meaning
  // if the function being called expects `size_t` and `int` is passed there
  // could be serious issues. It is recommended to use SCall.
  template <typename... Args>
  NTSTATUS Call(uint64_t funcNameHash, Args... args) {
    return trampoline(getSyscallNumber(funcNameHash), getSyscallInstrAddr(),
                      getArgStackSize(args...), std::forward<Args>(args)...);
  }

  /// @brief Checks if function is callable with the passed arguments, cast the
  /// arguments to an accepted type. If you get a long as hell template error
  /// that's probably because you used wrong arguments for the function you
  /// specified. If not please report.
  /// @param func Typedef of a function needs to be called
  /// @param funcName name of the nt function
  /// @param args arguments of the nt function
  template <typename func, typename... Ts>
    requires std::invocable<func, Ts...>
  NTSTATUS SCall(const std::string &funcName, Ts &&...args) {
    return [&]<typename R, typename... Args>(
               std::type_identity<R(Args...)>,
               auto &&...forwardedArgs) { // auto&& because cannot inject other
                                          // templated types into a templated
                                          // lambda
      return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                        getArgStackSize(forwardedArgs...),
                        forwardCast<Args>(std::forward<Ts>(forwardedArgs))...);
    }(std::type_identity<func>{}, std::forward<Ts>(args)...);
  }

  /// @brief Checks if function is callable with the passed arguments, cast the
  /// arguments to an accepted type. If you get a long as hell template error
  /// that's probably because you used wrong arguments for the function you
  /// specified. If not please report.
  /// @param func Typedef of a function needs to be called
  /// @param funcNameHash fnv1 hash of the name of the nt function
  /// @param args arguments of the nt function
  template <typename func, typename... Ts>
    requires std::invocable<func, Ts &&...>
  NTSTATUS SCall(uint64_t funcNameHash, Ts &&...args) {
    return [&]<typename R, typename... Args>(
               std::type_identity<R(Args...)>,
               auto &&...forwardedArgs) { // auto&& because cannot inject other
                                          // templated types into a templated
                                          // lambda
      return trampoline(getSyscallNumber(funcNameHash), getSyscallInstrAddr(),
                        getArgStackSize(forwardedArgs...),
                        forwardCast<Args>(std::forward<Ts>(forwardedArgs))...);
    }(std::type_identity<func>{}, std::forward<Ts>(args)...);
  }
};

} // namespace nullgate
