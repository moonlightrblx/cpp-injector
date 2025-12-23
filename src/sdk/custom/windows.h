#pragma once
#include <TlHelp32.h>

namespace windows {
    __forceinline DWORD get_pid(LPCTSTR processName) {
        DWORD pid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 procEntry;
            procEntry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(snap, &procEntry)) {
                do {
                    if (custom::strcmp(procEntry.szExeFile, processName, true)) {
                        pid = procEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snap, &procEntry));
            }
            CloseHandle(snap);
        }
        return pid;
    }

    typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);

    __forceinline HANDLE OpenHandle(DWORD pid) {
        NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
        // might make this a direct syscall soon idk 🤷‍
        if (!NtOpenProcess) {
            std::cout << "[-] failed to get NtOpenProcess!";
            return nullptr;
        }
        HANDLE handle = nullptr;
        CLIENT_ID cid;
        cid.UniqueProcess = (HANDLE)pid;
        cid.UniqueThread = nullptr;

        OBJECT_ATTRIBUTES objAttr = {};
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        NtOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &cid);

        return handle;
    }

}