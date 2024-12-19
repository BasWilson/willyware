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

bool is_injected = false;

DWORD WINAPI ListenForEscape(LPVOID lpParam) {
    while (true) {
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            std::ofstream log("C:\\injection_log.txt", std::ios::app);
            log << "[INFO] Escape key detected. Unloading DLL." << std::endl;
            log.close();

            HMODULE hModule = static_cast<HMODULE>(lpParam);
            MessageBoxA(NULL, "WILLYWARE UNLOADED", "Debug", MB_OK);
            is_injected = false;
            FreeLibraryAndExitThread(hModule, 0);
        }
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        if (!is_injected) {
            MessageBoxA(NULL, "WILLYWARE INJECTED", "Debug", MB_OK);
            LogInjection();
            is_injected = true;

            // Start the listener in a new thread
            HANDLE hThread = CreateThread(
                NULL,
                0,
                ListenForEscape,
                hModule,
                0,
                NULL);

            if (hThread == NULL) {
                LogInjection();
            } else {
                CloseHandle(hThread);
            }
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

