#include "Injection.hpp"
#include <iostream>
#include <sdk/custom/custom.h>
#include <thread>
#include <sdk/custom/prot/xor.h>

#define RELOC_FLAG(RelInfo) ((RelInfo >> 12) == IMAGE_REL_BASED_DIR64)


//__forceinline std::string random_syscall_name() {
//    // generate random syscall name
//      was used for testing imports but no longer needed <3
//    const std::vector<std::string> syscall_names_enc = {
//		_("NtCreateFile"), _("NtReadFile"), _("NtWriteFile"), _("NtClose"), _("NtOpenProcess"),
//		_("NtAllocateVirtualMemory"), _("NtFreeVirtualMemory"), _("NtProtectVirtualMemory"),
//		_("NtCreateThreadEx"), _("NtWaitForSingleObject"), _("NtQueryInformationProcess"),
//		_("NtSetInformationProcess"), _("NtQuerySystemInformation"), _("NtOpenThread"),
//		_("NtSuspendThread"), _("NtResumeThread"), _("NtTerminateThread")
//    };
//
//    std::random_device rd;
//    std::mt19937 eng(rd());
//    std::uniform_int_distribution<size_t> distr(0, syscall_names_enc.size() - 1);
//    return syscall_names_enc[distr(eng)];
//}

bool CInjector::ManualMap(HANDLE Process, const std::string& DllPath) {
    std::ifstream dllfile(DllPath, std::ios::binary | std::ios::ate);
    
	if (!dllfile.is_open()) // file not found or couldn't be opened
        return false;

	auto FileSize = dllfile.tellg(); // get file size
	if (FileSize < 4096)  // if file size is less than 4kb, invalid dll
		// even the smallest dlls are larger than 4kb
        return false;
	
    std::vector<BYTE> DllData(static_cast<size_t>(FileSize));
    
    dllfile.seekg(0, std::ios::beg);
    dllfile.read(reinterpret_cast<char*>(DllData.data()), FileSize);
    dllfile.close();


    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(DllData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* ntheaders = reinterpret_cast<IMAGE_NT_HEADERS*>(DllData.data() + dos->e_lfanew);
    auto* opthead = &ntheaders->OptionalHeader;
	std::cout << "======== PE Headers ==========" << std::endl;
	std::cout << "OptHeader->ImageBase            \t @ 0x" << std::hex << opthead->ImageBase << std::endl;
	std::cout << "OptHeader->SizeOfImage          \t @ 0x" << std::hex << opthead->SizeOfImage << std::endl;
	std::cout << "OptHeader->AddressOfEntryPoint  \t @ 0x" << std::hex << opthead->AddressOfEntryPoint << std::endl;
	std::cout << "=============================\n" << std::endl;

    if (ntheaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "[-] only x64 dlls are supported!" << std::endl;
        return false; 
    };
    
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (!Ntdll) return false;

     NtAllocateVirtualMemory = 
         reinterpret_cast<NtAllocateVirtualMemory_t>(GetProcAddress(Ntdll, "NtAllocateVirtualMemory"));
     NtFreeVirtualMemory = 
         reinterpret_cast<NtFreeVirtualMemory_t>(GetProcAddress(Ntdll, "NtFreeVirtualMemory"));
     NtReadVirtualMemory = 
         reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(Ntdll, "NtReadVirtualMemory"));
     NtCreateThreadEx = 
         reinterpret_cast<NtCreateThreadEx_t>(GetProcAddress(Ntdll, "NtCreateThreadEx"));
   
    BYTE* RemoteBase = reinterpret_cast<BYTE*>(VirtualAllocEx(Process, nullptr, opthead->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!RemoteBase) return false;

    MappingData mapdata{
        LoadLibraryA,
        GetProcAddress,
        nullptr
    };
  
    auto* secheader = IMAGE_FIRST_SECTION(ntheaders);
    
    if (custom::is_dev) {
        std::cout << "======= mapping sections =====" << std::endl;
    }
    
    
    for (UINT i = 0; i < ntheaders->FileHeader.NumberOfSections; ++i, ++secheader) {
        if (secheader->SizeOfRawData && 
            !WriteProcessMemory(
                Process, RemoteBase + secheader->VirtualAddress,
                DllData.data() + secheader->PointerToRawData, 
                secheader->SizeOfRawData, nullptr)
            ) 
        {
            NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
            return false;
        }
        if (custom::is_dev()) {
            std::cout << "section : " 
                << std::string(reinterpret_cast<char*>(secheader->Name), 8)
                << " @ 0x" 
                << std::hex 
                << reinterpret_cast<uintptr_t>(RemoteBase + secheader->VirtualAddress)
                << "\n"; // faster than flushing the output each time :D
        }
    }
    if (custom::is_dev()) 
		std::cout << "==============================\n" << std::endl;

	memcpy(DllData.data(), &mapdata, sizeof(mapdata)); 
    // copy the buffer data into the dll data so the shellcode gets access to it

    if (!WriteProcessMemory(Process, RemoteBase, DllData.data(), 0x1000, nullptr)) {
        // VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        return false;
    }

    auto RemoteShellcode = VirtualAllocEx(Process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// allocate memory for shellcode
    if (!RemoteShellcode) {
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        return false;
    }
 
    if (!WriteProcessMemory(Process, RemoteShellcode, Shellcode, 0x1000, nullptr)) {
        //VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        //VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
        return false;
    }
   /* HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (!Ntdll) {
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
        return false;
    }*/
    
    if (!NtCreateThreadEx) {
        //VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
        //VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
        NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
        return false;
    }
    if (custom::is_dev()) {
        std::cout << "======== syscalls ============" << std::endl;
        std::cout << "syscall : NtCreateThreadEx        @ 0x" << std::hex << reinterpret_cast<uintptr_t>(NtCreateThreadEx) << std::endl;
        std::cout << "syscall : NtAllocateVirtualMemory @ 0x" << std::hex << reinterpret_cast<uintptr_t>(NtAllocateVirtualMemory) << std::endl;
        std::cout << "syscall : NtFreeVirtualMemory     @ 0x" << std::hex << reinterpret_cast<uintptr_t>(NtFreeVirtualMemory) << std::endl;
        std::cout << "syscall : NtReadVirtualMemory     @ 0x" << std::hex << reinterpret_cast<uintptr_t>(NtReadVirtualMemory) << std::endl;
        std::cout << "================================\n" << std::endl;
    }   

    HANDLE RemoteThread = nullptr;
    NTSTATUS Status = NtCreateThreadEx(&RemoteThread, THREAD_ALL_ACCESS, nullptr, Process, RemoteShellcode, RemoteBase, 0, 0, 0, 0, nullptr);
    if (Status != 0 || !RemoteThread) {
		NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteBase), 0, MEM_RELEASE);
		NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
       /* VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);*/
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

    if (custom::is_dev()) {
		std::cout << "====== injected module ======" << std::endl;
        std::cout << "dll base address \t @ 0x" << std::hex << reinterpret_cast<uintptr_t>(CheckModule) << std::endl;
		std::cout << "entry point      \t @ 0x" << std::hex << reinterpret_cast<uintptr_t>(CheckModule) + opthead->AddressOfEntryPoint << std::endl;
		std::cout << "size of image    \t @ 0x" << std::hex << opthead->SizeOfImage << std::endl;
        //todo: maybe add more info here later
		std::cout << "==============================\n" << std::endl;
    }
  
    if (Stealth){
        uintptr_t CheckModuleAddr = reinterpret_cast<uintptr_t>(CheckModule);
        ApplyStealth(Process, RemoteBase, RemoteShellcode, CheckModuleAddr);
	}
    std::cout << "injection successful!" << std::endl;
	NtFreeVirtualMemory(Process, reinterpret_cast<PVOID*>(&RemoteShellcode), 0, MEM_RELEASE);
    // VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);

    return true;
}


bool CInjector::ApplyStealth(HANDLE Process, BYTE* RemoteBase, void* RemoteShellcode, uintptr_t DllBase) {
    if (!Process || !RemoteBase || !RemoteShellcode) return false;

    bool success = true;

	WORD zeromz = 0; 
    if (custom::is_dev())
		std::cout << "=========== stealth ==========" << std::endl;

    if (!WriteProcessMemory(Process, RemoteBase, &zeromz, sizeof(WORD), nullptr)) {
        if (custom::is_dev())
            std::cout << "failed to patch DOS header" << std::endl;
    }
    else if (custom::is_dev()) {
        std::cout << "DOS header patched @ 0x" << std::hex << reinterpret_cast<uintptr_t>(RemoteBase) << std::endl;
    }

    if (DllBase) {
        // write random value to module name pointer (doesn't affect functionality)
		BYTE randomName[] = "svchost\x00"; // todo: randomize name correctly instead of using svchost
		// we *could use the process name and allocate under the same name
        // which would result in hiding under the legit module of "proc.exe"
        
		// there is defintely a *better* way to do this as in getting the e_lfanew offset from the dos header itself
        WriteProcessMemory(Process, (BYTE*)DllBase + 0x3C /*e_lfanew*/, randomName, 8, nullptr);
        // doesnt show in system informer?!?
        if (custom::is_dev()) std::cout << "module name spoofed" << std::endl;
	
    }
    
    if (custom::is_dev())
        std::cout << "cleanup complete!" << std::endl;
	if (custom::is_dev())
	std::cout << "==============================\n" << std::endl;
    return success;
}


void WINAPI CInjector::Shellcode(LPVOID dataptr) { 
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
					// could add error checking here but meh
                }
            }
            ++ImportDesc;
        }
    }
	
    // tls
    if (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* TLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* Callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TLS->AddressOfCallBacks);

        while (Callback && *Callback) {
			(*Callback)(base, DLL_PROCESS_ATTACH, nullptr); // tls callbacks are always called with PROCESS_ATTACH
            ++Callback;
        }
    }
	
    // call entry point
    DllMain(base, DLL_PROCESS_ATTACH, nullptr);
	data->ModuleHandle = reinterpret_cast<HINSTANCE>(base);
}