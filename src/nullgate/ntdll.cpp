#include <minwindef.h>
#include <ntdef.h>
#include <nullgate/ntdll.hpp>
#include <stdexcept>
#include <string>
#include <winnt.h>
#include <winscard.h>
#include <winternl.h>

namespace nullgate {

HMODULE ntdll::GetNtdllHandle() {
  PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
  // ntdll is always the first module after the executable to be loaded
  const auto ntdllLdrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
      // NIGHTMARE NIGHTMARE NIGHTMARE
      CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink,
                        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
  return reinterpret_cast<HMODULE>(ntdllLdrEntry->DllBase);
}

FARPROC ntdll::GetProcAddress(HMODULE moduleHandle, LPCSTR procName) {
  const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleHandle);
  const auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(moduleHandle + dosHeaders->e_lfanew);
  const auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      moduleHandle +
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);

  const auto functionsTable =
      reinterpret_cast<PDWORD>(moduleHandle + exportDir->AddressOfFunctions);
  const auto namesTable =
      reinterpret_cast<PDWORD>(moduleHandle + exportDir->AddressOfNames);
  const auto ordinalsTable =
      reinterpret_cast<PWORD>(moduleHandle + exportDir->AddressOfNameOrdinals);

  for (DWORD i{}; i < exportDir->NumberOfNames; i++) {
    std::string funcName =
        reinterpret_cast<const char *>(moduleHandle + namesTable[i]);
    if (funcName == procName) {
      return reinterpret_cast<FARPROC>(moduleHandle +
                                       functionsTable[ordinalsTable[i]]);
    }
  }

  throw std::runtime_error("Procedure not found:" + std::string(procName));
}

typedef NTSTATUS(NTAPI *LdrLoadDll)(_In_opt_ PCWSTR DllPath,
                                    _In_opt_ PULONG DllCharacteristics,
                                    _In_ PUNICODE_STRING DllName,
                                    _Out_ PVOID *DllHandle);

HMODULE ntdll::LoadLibraryW(LPCWSTR dllName) {
  auto ntdllHandle = ntdll::GetNtdllHandle();

  UNICODE_STRING unicodeStrModule;

  // RtlInitUnicodeString
  if (dllName)
    unicodeStrModule.MaximumLength =
        (unicodeStrModule.Length = (USHORT)(wcslen(dllName) * sizeof(WCHAR))) +
        sizeof(UNICODE_NULL);
  else
    unicodeStrModule.MaximumLength = unicodeStrModule.Length = 0;

  unicodeStrModule.Buffer = (PWCH)dllName;

  LdrLoadDll LdrLoadDllF = reinterpret_cast<LdrLoadDll>(
      ntdll::GetProcAddress(ntdllHandle, "LdrLoadLibrary"));

  HANDLE dllHandle = NULL;
  auto status = LdrLoadDllF(NULL, 0, &unicodeStrModule, &dllHandle);
  if (!NT_SUCCESS(status))
    throw std::runtime_error("LdrLoadDll failed with error: " +
                             std::to_string(status));
  return reinterpret_cast<HMODULE>(dllHandle);
}

} // namespace nullgate
