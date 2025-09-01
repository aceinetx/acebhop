// clang-format off
#include <windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <string>
#include <string_view>
#include <tchar.h>
#include <vector>
// clang-format on

int *in_air = nullptr;
int *jumping = nullptr;
bool active = false;

wchar_t *GetWC(const char *c) {
  const size_t cSize = strlen(c) + 1;
  wchar_t *wc = new wchar_t[cSize];
  mbstowcs(wc, c, cSize);

  return wc;
}

DWORD GetProcId(const char *processname) {
  std::wstring processName;
  processName.append(GetWC(processname));
  PROCESSENTRY32 processInfo;
  processInfo.dwSize = sizeof(processInfo);

  HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (processesSnapshot == INVALID_HANDLE_VALUE)
    return 0;

  Process32First(processesSnapshot, &processInfo);

  // if (!processName.compare(processInfo.szExeFile))
  if (!processName.compare(GetWC(processInfo.szExeFile))) {
    CloseHandle(processesSnapshot);
    return processInfo.th32ProcessID;
  }

  while (Process32Next(processesSnapshot, &processInfo)) {
    // if (!processName.compare(processInfo.szExeFile))
    if (!processName.compare(GetWC(processInfo.szExeFile))) {
      CloseHandle(processesSnapshot);
      return processInfo.th32ProcessID;
    }
  }

  CloseHandle(processesSnapshot);
  return 0;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const char *modName) {
  uintptr_t modBaseAddr = 0;
  HANDLE hSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
  if (hSnap != INVALID_HANDLE_VALUE) {
    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(modEntry);
    if (Module32First(hSnap, &modEntry)) {
      do {
        _bstr_t x(modEntry.szModule);
        if (!_stricmp(x, modName)) {
          modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
          break;
        }
      } while (Module32Next(hSnap, &modEntry));
    }
  }
  CloseHandle(hSnap);
  return modBaseAddr;
}

DWORD WINAPI MainThread(LPVOID lpThreadParameter) {
  while (true) {
    if (GetAsyncKeyState(VK_LMENU) & 0x1) {
      active = !active;
    }
    if (GetAsyncKeyState(VK_SPACE) && active) {
      if (*in_air == 0) {
        *jumping = 5;
        Sleep(10);
        *jumping = 4;
      }
    }
  }
  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  static_assert(sizeof(long) == 4, "you shall build w/ x86 kit");
  switch (dwReason) {
  case DLL_PROCESS_ATTACH: {
    DWORD pid = GetProcId("hl2.exe");
    uintptr_t client = GetModuleBaseAddress(pid, "client.dll");
    in_air = (int *)(client + 0x39D540);
    jumping = (int *)(client + 0x3E71E4);

    CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
  } break;
  case DLL_PROCESS_DETACH:
    FreeLibraryAndExitThread(hModule, TRUE);
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  default:
    break;
  }
  return TRUE;
}