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

//todo: clean this up :)
enum e_injection_method {
    INJ_METHOD_LOADLIBRARY,
    INJ_METHOD_MANUALMAP
};
class c_injector {
public:
    bool inject(HANDLE Proccess, const std::string& DllPath, e_injection_method inj_type);
	// might eventually make these private and just have a single inject function that takes in e_injection_method
    bool manual_map(HANDLE Process, const std::string& DllPath);
    bool loadlibrary(HANDLE Process, const std::string& DllPath);

    using LoadLibraryFunc = HINSTANCE(WINAPI*)(const char* LibFileName);
    using GetProcAddressFunc = FARPROC(WINAPI*)(HMODULE Module, const char* ProcName);
    using DllEntryPointFunc = BOOL(WINAPI*)(void* Module, DWORD Reason, void* Reserved);

    struct MappingData {
        LoadLibraryFunc LoadLibraryA;
        GetProcAddressFunc GetProcAddress;
        HINSTANCE ModuleHandle;
    };

private:
    __forceinline bool apply_stealth(HANDLE Process, BYTE* RemoteBase, void* RemoteShellcode, uintptr_t DllBase);
    static void WINAPI shellcode(LPVOID DataPtr);
    bool Stealth = true;
};

inline auto injector = std::make_unique<c_injector>();