#define _CRT_SECURE_NO_WARNINGS
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include "injector/Injection.hpp"
#include <sdk/includes.h>
#include <TlHelp32.h>
/*
//! injector created by ellii <3
//! based on https://github.com/TheCruZ/Simple-Manual-Map-Injector/blob/master/Manual%20Map%20Injector/injector.cpp
//! with lots of changes and additions by me
//! this is way more secure than thecruz's injector but still not perfect

credits:
- thecruz for the original manual map injector
- conspiracy for help with the asm parts and some of the shellcode
- https://ntdoc.m417z.com/ best syscall docs site huge thx to the creator m417z :D
- myself for spending the time on actually creating this injector
- all the people who helped test and debug this injector <3
*/

namespace windows{
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
    __forceinline HANDLE OpenHandle(DWORD pid) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

}
//? note: this strings are not encrypted on purpose, they aren't needed to be encrypted or hidden :3
int main(int argc, char* argv[]) {
    std::string dllPath;
    // might want to xor this and add some protection later <3
    if (argc > 1) {
        dllPath = argv[1];
    }
    else {
        dllPath = "c:\\dll.dll"; //! when called from loader use dll.dll <3
    }

    c_console con;

    con.init();

    con.set_title("elli private injector <3 | " + custom::random_string(15));
    // yes this used to be a private injector lol thats why protection is barely present 
    // (no one had access to it except a few friends)
    // i wouldn't recomend using this protection in a public injector 
    // it was meant only to bypass simple anticheats

    con.print("welcome to the injector!");

    if (!std::filesystem::exists(dllPath)) {
        con.print("dll path does not exist.", 1);
        con.print("usage : injector.exe <full path to dll> <process>", 1);
        system("pause > nul");
        exit(1);
    }

    LPCTSTR targetProcess;

    if (argc > 2) {
        targetProcess = argv[2];
    }
    else {
        targetProcess = "cs2.exe"; //! temporary process name
    }

    DWORD pid = windows::get_pid(targetProcess);

    if (pid == 0) {
        con.print("couldn't find process.", 1);
        system("pause > nul");
        exit(1);
    }

    con.printf("found process pid : %d", 0, pid);

    auto handle = windows::OpenHandle(pid);

    con.printf("cs2.exe handle : 0x%p", 0, handle);

    if (!Injector->ManualMap(handle, dllPath.c_str()))
        con.print("injection failed.", 1);

    std::cout << "press any key to exit..." << std::endl;
    system("pause > nul");


}