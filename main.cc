// clang-format off
#include <windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <string>
#include <string_view>
#include <tchar.h>
#include <vector>
#include <type_traits>
// clang-format on
#ifndef _M_IX86
#error "you shall build w/ x86 kit"
#endif

int *in_air = nullptr;
int *jumping = nullptr;
bool active = false;

DWORD GetProcId(std::string processName) {
  PROCESSENTRY32 processInfo;
  processInfo.dwSize = sizeof(processInfo);

  HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (processesSnapshot == INVALID_HANDLE_VALUE)
    return 0;

  Process32First(processesSnapshot, &processInfo);

  if (!processName.compare(processInfo.szExeFile)) {
    CloseHandle(processesSnapshot);
    return processInfo.th32ProcessID;
  }

  while (Process32Next(processesSnapshot, &processInfo)) {
    if (!processName.compare(processInfo.szExeFile)) {
      CloseHandle(processesSnapshot);
      return processInfo.th32ProcessID;
    }
  }

  CloseHandle(processesSnapshot);
  return 0;
}

uintptr_t GetModuleBaseAddress(DWORD procId, std::string modName) {
  uintptr_t modBaseAddr = 0;
  HANDLE hSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
  if (hSnap != INVALID_HANDLE_VALUE) {
    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(modEntry);
    if (Module32First(hSnap, &modEntry)) {
      do {
        if (!modName.compare(modEntry.szModule)) {
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
    if (GetAsyncKeyState(VK_LMENU) & 0x1) { // toggle bhop
      active = !active;
    }
    if (GetAsyncKeyState(VK_SPACE) && active) { // jump
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
  switch (dwReason) {
  case DLL_PROCESS_ATTACH: {
    DWORD pid = GetProcId("hl2.exe");
    assert(pid != 0); // ensure process is found
    uintptr_t client = GetModuleBaseAddress(pid, "client.dll");
    assert(client != (uintptr_t)0); // ensure client.dll is found
    //DebugBreak();
    in_air = reinterpret_cast<int*>(client + 0x39D540);
    jumping = reinterpret_cast<int*>(client + 0x3E71E4);

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