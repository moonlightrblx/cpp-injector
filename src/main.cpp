#define _CRT_SECURE_NO_WARNINGS
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include <sdk/includes.h>

#include "lib/inject.hpp"

/*
! injector created by ellii <3
! based on https://github.com/TheCruZ/Simple-Manual-Map-Injector/blob/master/Manual%20Map%20Injector/injector.cpp
! with lots of changes and additions by me

credits:
- thecruz for the original manual map injector
- conspiracy for help with the asm parts and some of the shellcode
- https://ntdoc.m417z.com/ best syscall docs site huge thx to the creator m417z :D
- myself for spending the time on actually creating this injector
- all the people who helped test and debug this injector <3
*/


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
    
    con.set_title("elli's public injector <3 | " + custom::random_string(15));
  
    // i wouldn't recomend using this protection in a public injector 
    // it was meant only to bypass simple usermode anticheats

    con.print("welcome to the injector!");

    if (!std::filesystem::exists(dllPath)) {
        con.print("dll path does not exist.", 1);
        con.print("usage : injector.exe <full path to dll> <process>", 1);
        std::cin.get();
        exit(1);
    }

    LPCTSTR targetProcess;

    if (argc > 2) {
        targetProcess = argv[2];
    }
    else {
		targetProcess = "FortniteClient-Win64-Shipping.exe";
        // targetProcess = "cs2.exe";
    }

    DWORD pid = windows::get_pid(targetProcess);
   
    if (pid == 0) {
        con.print("couldn't find process.", 1);
        std::cin.get();
        exit(1);
    }

    con.printf("found process pid : %d", 0, pid);

    auto handle = windows::OpenHandle(pid);

    con.printf("window handle : 0x%p", 0, handle);

    if (!injector->inject(handle, dllPath.c_str(), INJ_METHOD_MANUALMAP))
        con.print("injection failed.", 1);

    std::cout << "press any key to exit..." << std::endl;
    
    std::cin.get();

    /*system("pause > nul");*/
	return 0;
}