#include <Windows.h>
#include <iostream>
// #include <d3d9.h>
#include <string>
#include <vector>
// #include <d3dx9.h>
#include <TlHelp32.h>
#include <fstream>

void LogInjection() {
    std::ofstream log("C:\\injection_log.txt", std::ios::app);
    log << "[INFO] DLL Injected successfully." << std::endl;
    log.close();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    MessageBoxA(NULL, "DLL Injected!", "Debug", MB_OK);

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        LogInjection();
    }
    return TRUE;
}

