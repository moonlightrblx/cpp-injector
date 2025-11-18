#pragma once

#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <vector>
using NtCreateThreadEx_t = NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using NtAllocateVirtualMemory_t = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );
using NtFreeVirtualMemory_t = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );
using NtReadVirtualMemory_t = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

inline NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
inline NtFreeVirtualMemory_t NtFreeVirtualMemory;
inline NtReadVirtualMemory_t NtReadVirtualMemory;
inline NtCreateThreadEx_t NtCreateThreadEx;
class CInjector {
public:
    bool ManualMap(HANDLE Process, const std::string& DllPath);

    using LoadLibraryFunc = HINSTANCE(WINAPI*)(const char* LibFileName);
    using GetProcAddressFunc = FARPROC(WINAPI*)(HMODULE Module, const char* ProcName);
    using DllEntryPointFunc = BOOL(WINAPI*)(void* Module, DWORD Reason, void* Reserved);
    // todo: add more syscalls also show the addresses of the syscalls <3

    struct MappingData {
        LoadLibraryFunc LoadLibraryA;
        GetProcAddressFunc GetProcAddress;
        HINSTANCE ModuleHandle;
    };
    __forceinline bool ApplyStealth(HANDLE Process, BYTE* RemoteBase, void* RemoteShellcode, uintptr_t DllBase);
private:
    static void WINAPI Shellcode(LPVOID DataPtr);
    bool Stealth = true;
};

inline auto Injector = std::make_unique<CInjector>();