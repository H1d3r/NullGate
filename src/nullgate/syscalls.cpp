#include <cstdint>
#include <cstdio>
#include <ctime>
#include <libloaderapi.h>
#include <minwindef.h>
#include <ntdef.h>
#include <nullgate/hashing.hpp>
#include <nullgate/syscalls.hpp>
#include <stdexcept>
#include <string>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

namespace nullgate {

syscalls::syscalls() {
  populateStubs();
  populateSyscalls();
}

void syscalls::populateStubs() {
  PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
  // ntdll is always the first module after the executable to be loaded
  const auto ntdllLdrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
      // NIGHTMARE NIGHTMARE NIGHTMARE
      CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink,
                        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
  const auto ntdllBase = reinterpret_cast<PBYTE>(ntdllLdrEntry->DllBase);
  const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllBase);

  // e_lfanew points to ntheaders(microsoft's great naming)
  const auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(ntdllBase + dosHeaders->e_lfanew);
  const auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      ntdllBase +
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);

  const auto functionsTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfFunctions);
  const auto namesTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfNames);
  const auto ordinalsTable =
      reinterpret_cast<PWORD>(ntdllBase + exportDir->AddressOfNameOrdinals);

  for (DWORD i{}; i < exportDir->NumberOfNames; i++) {
    std::string funcName =
        reinterpret_cast<const char *>(ntdllBase + namesTable[i]);
    if (funcName.starts_with("Zw")) {
      auto funcAddr = reinterpret_cast<PDWORD>(
          ntdllBase + functionsTable[ordinalsTable[i]]);
      stubMap.emplace(funcAddr, "Nt" + funcName.substr(2));
    }
  }
}

void syscalls::populateSyscalls() {
  unsigned int syscallNo{};
  for (const auto &stub : stubMap)
    syscallNoMap.emplace(stub.second, syscallNo++);
}

DWORD syscalls::getSyscallNumber(const std::string &funcName) {
  if (!syscallNoMap.contains(funcName))
    throw std::runtime_error("Function not found: " + funcName);

  return syscallNoMap.at(funcName);
}

DWORD syscalls::getSyscallNumber(uint64_t funcNameHash) {
  for (const auto &ntFuncPair : syscallNoMap) {
    if (fnv1Runtime(ntFuncPair.first.c_str()) == funcNameHash)
      return ntFuncPair.second;
  }

  throw std::runtime_error("Function hash not found: " +
                           std::to_string(funcNameHash));
}

uintptr_t syscalls::getSyscallInstrAddr() {
  auto stubBase = reinterpret_cast<PBYTE>((*stubMap.begin()).first);
  const int maxStubSize = 32; // I have no idea if it can be larger
  const BYTE syscallOpcode[] = {0x0F, 0x05, 0xC3}; // syscall; ret
  for (int i{}; i < maxStubSize; i++) {
    if (memcmp(syscallOpcode, stubBase + i, sizeof(syscallOpcode)) == 0)
      return reinterpret_cast<uintptr_t>(stubBase + i);
  }
  throw std::runtime_error("Couldn't find a syscall instruction");
}

} // namespace nullgate
