#include "inject.hpp"
#include <iostream>
#include <sdk/custom/custom.h>
#include <thread>
#include <sdk/custom/prot/xor.h>

#define RELOC_FLAG(RelInfo) ((RelInfo >> 12) == IMAGE_REL_BASED_DIR64)

__forceinline void log(const char* format, ...)
{
    if (custom::is_dev()) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        std::cout << buffer;
    }
}

bool c_injector::inject(HANDLE Proccess, const std::string& DllPath, e_injection_method inj_type)
{
    if (inj_type == INJ_METHOD_LOADLIBRARY) {
        return loadlibrary(Proccess, DllPath);
    }
    else if (inj_type == INJ_METHOD_MANUALMAP) {
        return manual_map(Proccess, DllPath);
	}
    else {
        log("[-] invalid injection method!\n");
		return false;
    }
    // should never reach this?
    // if it does theres some serious issues.

    return false;
}

bool c_injector::manual_map(HANDLE Process, const std::string& DllPath) {
    std::ifstream dllfile(DllPath, std::ios::binary | std::ios::ate);

    if (!dllfile.is_open()) {
        log("[-] failed to open dll file!\n");
        return false;
    }

    auto FileSize = dllfile.tellg();
    if (FileSize < 4096) {
        log("[-] invalid dll file!\n");
        return false;
    }

    std::vector<BYTE> DllData(static_cast<size_t>(FileSize));
    dllfile.seekg(0, std::ios::beg);
    dllfile.read(reinterpret_cast<char*>(DllData.data()), FileSize);
    dllfile.close();

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(DllData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* ntheaders = reinterpret_cast<IMAGE_NT_HEADERS*>(DllData.data() + dos->e_lfanew);
    auto* opthead = &ntheaders->OptionalHeader;

    log("======== PE Headers ==========\n");
    log("OptHeader->ImageBase           @ 0x%llx\n", opthead->ImageBase);
    log("OptHeader->SizeOfImage         @ 0x%x\n", opthead->SizeOfImage);
    log("OptHeader->AddressOfEntryPoint @ 0x%x\n", opthead->AddressOfEntryPoint);
    log("=============================\n\n");

    if (ntheaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        log("[-] only x64 dlls are supported!\n");
        return false;
    }

    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (!Ntdll) return false;

    NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(GetProcAddress(Ntdll, "NtAllocateVirtualMemory"));
    NtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(GetProcAddress(Ntdll, "NtFreeVirtualMemory"));
    NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(Ntdll, "NtReadVirtualMemory"));
    NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(GetProcAddress(Ntdll, "NtCreateThreadEx"));
    
    log("======== syscalls =============\n");
    log("NtCreateThreadEx           @ 0x%p\n", NtCreateThreadEx);
    log("NtAllocateVirtualMemory    @ 0x%p\n", NtAllocateVirtualMemory);
    log("NtFreeVirtualMemory        @ 0x%p\n", NtFreeVirtualMemory);
    log("NtReadVirtualMemory        @ 0x%p\n", NtReadVirtualMemory);
    log("================================\n\n");

    BYTE* RemoteBase = reinterpret_cast<BYTE*>(VirtualAllocEx(Process, nullptr, opthead->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!RemoteBase) return false;

    MappingData mapdata{ LoadLibraryA, GetProcAddress, nullptr };
    auto* secheader = IMAGE_FIRST_SECTION(ntheaders);

    log("======= mapping sections =======\n");

    for (UINT i = 0; i < ntheaders->FileHeader.NumberOfSections; ++i, ++secheader) {
        if (secheader->SizeOfRawData) {
            if (!WriteProcessMemory(Process, RemoteBase + secheader->VirtualAddress,
                DllData.data() + secheader->PointerToRawData,
                secheader->SizeOfRawData, nullptr)) {
                NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
                return false;
            }
        }

        log("section : %.*s @ 0x%p\n", 8, secheader->Name, RemoteBase + secheader->VirtualAddress);
    }

    log("================================\n\n");

    memcpy(DllData.data(), &mapdata, sizeof(mapdata));
    if (!WriteProcessMemory(Process, RemoteBase, DllData.data(), 0x1000, nullptr)) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        return false;
    }

    auto RemoteShellcode = VirtualAllocEx(Process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!RemoteShellcode) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        return false;
    }

    // fire method trust
    if (!WriteProcessMemory(Process, RemoteShellcode, shellcode, 0x1000, nullptr)) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
        return false;
    }

    if (!NtCreateThreadEx) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
        return false;
    }

  

    HANDLE RemoteThread = nullptr;
    NTSTATUS Status = NtCreateThreadEx(&RemoteThread, THREAD_ALL_ACCESS, nullptr, Process, RemoteShellcode, RemoteBase, 0, 0, 0, 0, nullptr);

    if (Status != 0 || !RemoteThread) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
        log("[-] failed to create remote thread! NTSTATUS: 0x%x\n", Status);
        return false;
    }

    CloseHandle(RemoteThread);

    HINSTANCE CheckModule = nullptr;
    while (!CheckModule) {
        MappingData Data{ 0 };
        NtReadVirtualMemory(Process, RemoteBase, &Data, sizeof(Data), nullptr);
        CheckModule = Data.ModuleHandle;
        Sleep(10);
    }

    log("====== injected module =======\n");
    log("dll base address     @ 0x%p\n", CheckModule);
    log("entry point          @ 0x%p\n", reinterpret_cast<uintptr_t>(CheckModule) + opthead->AddressOfEntryPoint);
    log("size of image        @ 0x%x\n", opthead->SizeOfImage);
    log("==============================\n\n");

    if (Stealth) {
        uintptr_t CheckModuleAddr = reinterpret_cast<uintptr_t>(CheckModule);
        apply_stealth(Process, RemoteBase, RemoteShellcode, CheckModuleAddr);
    }

    log("injection successful!\n");
    NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
    return true;
}

bool c_injector::loadlibrary(HANDLE Process, const std::string& DllPath) {
    // todo: switch to dynamic syscalls and add stealth :)
    std::ifstream file(DllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        log("[-] Failed to open DLL: %s\n", DllPath.c_str());
        return false;
    }

    SIZE_T dllSize = static_cast<SIZE_T>(file.tellg());
    if (dllSize < 4096) {
        log("[-] DLL too small\n");
        return false;
    }

    std::vector<BYTE> dllBuffer(dllSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(dllBuffer.data()), dllSize);
    file.close();

    log("[+] DLL loaded into injector: %zu bytes\n", dllSize);

    LPVOID pRemoteDll = VirtualAllocEx(Process, nullptr, dllSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemoteDll) {
        log("[-] VirtualAllocEx failed: %d\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(Process, pRemoteDll, dllBuffer.data(), dllSize, nullptr)) {
        log("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
        return false;
    }

    log("[+] DLL copied to target process @ 0x%p\n", pRemoteDll);


    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(Process, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemoteDll,                          
        0, nullptr);

    if (!hThread) {
        log("[-] CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode); 
    CloseHandle(hThread);

    if (!exitCode) {
        log("[-] LoadLibrary failed in remote process\n");
        VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
        return false;
    }

    log("[+] Success! DLL loaded at 0x%p\n", (HMODULE)exitCode);
    VirtualFreeEx(Process, pRemoteDll, 0, MEM_RELEASE);
    return true;
}

bool c_injector::apply_stealth(HANDLE Process, BYTE* RemoteBase, void* RemoteShellcode, uintptr_t DllBase) {
    if (!Process || !RemoteBase || !RemoteShellcode) return false;

    log("=========== stealth ===========\n");

    BYTE garbage[0x600] = { 0 };
    for (int i = 0; i < sizeof(garbage); i++) garbage[i] = (BYTE)rand();
    WriteProcessMemory(Process, RemoteBase, garbage, sizeof(garbage), nullptr);
    log("garbage wrote to the first 0x600 bytes\n");

    log("cleanup complete!\n");
    log("==============================\n\n");

    return true;
}
void WINAPI c_injector::shellcode(LPVOID dataptr) {
	// we cant use our syscalls here since we dont have their addresses
    // i might just add them later tho
 
	// we have to do all the stuff the windows loader would do for us normally
	// we have the dll mapped at this point, we just need to fix relocations, imports, tls and call entry point
	// we get passed a pointer to our MappingData struct at the start of the mapped dll
	// which is nice since we can use that to get LoadLibraryA and GetProcAddress

    auto* data = static_cast<MappingData*>(dataptr);
    if (!data) return;

    auto* base = reinterpret_cast<BYTE*>(data);
    auto* OptHeader = 
        &reinterpret_cast<IMAGE_NT_HEADERS*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(data)->e_lfanew)->OptionalHeader;
	
    // now we can do the manual mapping steps
    
    auto LoadLibraryA = data->LoadLibraryA;
    auto GetProcAddress = data->GetProcAddress;

    auto DllMain = reinterpret_cast<DllEntryPointFunc>(base + OptHeader->AddressOfEntryPoint);

	// relocations
    BYTE* LocationDelta = base - OptHeader->ImageBase;
    if (LocationDelta) {
        if (!OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

        auto* RelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (RelocData->VirtualAddress) {
            UINT EntriesCount = (RelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* RelativeInfo = reinterpret_cast<WORD*>(RelocData + 1);

            for (UINT i = 0; i < EntriesCount; ++i, ++RelativeInfo) {
                if (RELOC_FLAG(*RelativeInfo)) {
                    auto* PatchAddr = reinterpret_cast<UINT_PTR*>(base + RelocData->VirtualAddress + ((*RelativeInfo) & 0xFFF));
                    *PatchAddr += reinterpret_cast<UINT_PTR>(LocationDelta);
                }
            }

            RelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocData) + RelocData->SizeOfBlock);
        }
    }
	
    // imports
    if (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* ImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (ImportDesc->Name) {
            char* ModuleName = reinterpret_cast<char*>(base + ImportDesc->Name);
            HINSTANCE Dll = LoadLibraryA(ModuleName);

            ULONG_PTR* ThunkRef = reinterpret_cast<ULONG_PTR*>(base + ImportDesc->OriginalFirstThunk);
            ULONG_PTR* FuncRef = reinterpret_cast<ULONG_PTR*>(base + ImportDesc->FirstThunk);

            if (!ThunkRef) ThunkRef = FuncRef;

            for (; *ThunkRef; ++ThunkRef, ++FuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*ThunkRef)) {
					*FuncRef = reinterpret_cast<ULONG_PTR>(GetProcAddress(Dll, reinterpret_cast<char*>(*ThunkRef & 0xFFFF))); 
                    // get the proc address using the ordinal
                }
                else {
					auto* Import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*ThunkRef)); // get the import by name
					*FuncRef = reinterpret_cast<ULONG_PTR>(GetProcAddress(Dll, Import->Name));  // get the proc address using the name
                }
            }
            ++ImportDesc;
        }
    }
	
    // tls 
    // if im being honest the only reason i added this is because my packer uses tls callbacks to hide the entry point 🤑
    if (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* TLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* Callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TLS->AddressOfCallBacks);

        while (Callback && *Callback) {
			(*Callback)(base, DLL_PROCESS_ATTACH, nullptr); 
            ++Callback;
        }
    }
	
    // call entry point
    // might eventually spoof the call to this so the process doesn't get a huge flag
    // just as a quick notice this does NOT create a new thread so the injector waits for this function to return. 
    // if you do not create a thread inside of dllmain then i would immediately do that (unless its a detection on the AC (very possible))

    DllMain(base, DLL_PROCESS_ATTACH, nullptr);
	data->ModuleHandle = reinterpret_cast<HINSTANCE>(base);
}