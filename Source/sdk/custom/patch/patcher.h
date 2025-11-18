#pragma once
#include <windows.h>
#include <cstdint>
enum class opcodes_t : BYTE {    
    // asm opcodes
    JMP = 0xE9,
    JMP_SHORT = 0xEB,
    JE = 0x84,       
    JNE = 0x85,      
    JG = 0x8F,       
    JL = 0x8C,       
    JGE = 0x8D,      
    JLE = 0x8E,      
    CALL = 0xE8,     
    RET = 0xC3,      
    NOP = 0x90,       
    INT = 0xCD,       
    HLT = 0xF4        
};
class c_patch { 
    // asm helper library that helps you patch functions 
    // if you're woried about detections do NOT use this 
    // this is only meant to be a simple showcase of how we can patch bytes in functions
    // todo: use safer functions
private:
    void* func_addr; // the address of the function that we're patchingg
    BYTE original_bytes[5]; // save first 5 bytes for jmp patching
    bool patched; // if the patch was successfull
    size_t patch_size; // size of the patch we're creating.

public:
    c_patch() : func_addr(nullptr), patched(false), patch_size(0) {
        memset(original_bytes, 0, sizeof(original_bytes));
    }

    void set_func(void* addr) {
        func_addr = addr;
        patched = false;
        patch_size = 0;
        memset(original_bytes, 0, sizeof(original_bytes));
    }

    bool patch_byte(BYTE new_byte) { 
        if (!func_addr) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        if (!patched) {
            original_bytes[0] = *(BYTE*)func_addr;
            patched = true;
            patch_size = 1;
        }

        *(BYTE*)func_addr = new_byte;

        VirtualProtect(func_addr, 1, oldProtect, &oldProtect);
        return true;
    }

    // patch with ret (0xC3)
    __forceinline bool patch_ret() {
        return patch_byte((BYTE)opcodes_t::RET);
    }

    // patch with jmp to target addr (relative jump, 5 bytes)
    __forceinline bool patch_jmp(void* target) {
        if (!func_addr || !target) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        if (!patched) {
            memcpy(original_bytes, func_addr, 5);
            patched = true;
            patch_size = 5;
        }

        uintptr_t src = (uintptr_t)func_addr;
        uintptr_t dst = (uintptr_t)target;
        intptr_t rel_addr = dst - (src + 5); // relative offset from next instruction

        BYTE patch[5];
        patch[0] = (BYTE)opcodes_t::JMP; 
        *(int32_t*)(patch + 1) = (int32_t)rel_addr;

        memcpy(func_addr, patch, 5);

        VirtualProtect(func_addr, 5, oldProtect, &oldProtect);
        return true;
    }

    // restore original bytes (1 or 5 bytes depending on patch)
    bool restore() {
        if (!func_addr || !patched) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, patch_size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        memcpy(func_addr, original_bytes, patch_size);

        VirtualProtect(func_addr, patch_size, oldProtect, &oldProtect);
        patched = false;
        patch_size = 0;
        memset(original_bytes, 0, sizeof(original_bytes));
        return true;
    }

    // fetch function address from dll + func name
    static void* fetch_func(const char* dll_name, const char* func_name) {
        HMODULE mod = (HMODULE)fetch_module(dll_name, false);
        return (void*)GetProcAddress(mod, func_name);
    }

    static uintptr_t fetch_module(const char* module_name, bool should_load = true) {
        HMODULE mod = GetModuleHandleA(module_name);
        if (!mod && should_load) {
            mod = LoadLibraryA(module_name); 
            // if module isnt loaded and should_load = true then load it
            if (!mod) // if we couldnt load it just return null
                return NULL;
        }
        return reinterpret_cast<uintptr_t>(mod);
    }
};
