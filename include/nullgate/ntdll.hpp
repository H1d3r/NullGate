#pragma once

#include <minwindef.h>
#include <windows.h>
#include <winnt.h>

namespace nullgate {

class ntdll {
public:
  static HMODULE GetNtdllHandle();
  static FARPROC GetProcAddress(HMODULE moduleHandle, LPCSTR procName);
  static HMODULE LoadLibraryW(LPCWSTR filename);
};

} // namespace nullgate
