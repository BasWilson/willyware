#include <Windows.h>
#include <iostream>
#include <d3d9.h>
#include <string>
#include <vector>
#include <d3dx9.h>
#include <TlHelp32.h>

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

#define ENTITY_LIST_OFFSET 0x19F2488
#define LOCAL_PLAYER_OFFSET 0x1A41FD0
#define VIEW_ANGLES_OFFSET 0x1A5E650
#define HEALTH_OFFSET 0x20
#define SPOTTED_OFFSET 0x93D

typedef HRESULT(APIENTRY* EndScene_t)(LPDIRECT3DDEVICE9 pDevice);
EndScene_t oEndScene;
LPDIRECT3DDEVICE9 pDevice;

DWORD_PTR clientBase = 0;
DWORD_PTR localPlayer = 0;
bool triggerBotActive = false;

struct EntityData {
    int id;
    int health;
};

std::vector<EntityData> entities;
ID3DXFont* pFont = nullptr;

void InitializeD3DFont(LPDIRECT3DDEVICE9 device) {
    D3DXCreateFont(device, 14, 0, FW_BOLD, 1, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Arial", &pFont);
}

template <typename T>
T ReadMemory(DWORD_PTR address) {
    return *(T*)address;
}

DWORD_PTR PatternScan(HANDLE processHandle, DWORD_PTR baseAddress, size_t size, const char* pattern, const char* mask) {
    BYTE* buffer = new BYTE[size];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(processHandle, (LPCVOID)baseAddress, buffer, size, &bytesRead)) {
        delete[] buffer;
        return 0;
    }

    for (size_t i = 0; i < size - strlen(mask); i++) {
        bool found = true;
        for (size_t j = 0; j < strlen(mask); j++) {
            if (mask[j] != '?' && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            delete[] buffer;
            return baseAddress + i;
        }
    }

    delete[] buffer;
    return 0;
}

DWORD_PTR GetModuleBaseAddress(const char* moduleName, DWORD processID) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 moduleEntry = { 0 };
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            if (strcmp(moduleEntry.szModule, moduleName) == 0) {
                CloseHandle(hSnapshot);
                return (DWORD_PTR)moduleEntry.modBaseAddr;
            }
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

std::vector<EntityData> FetchEntityData() {
    std::vector<EntityData> entityList;

    for (int i = 0; i < 64; i++) {
        DWORD_PTR entityAddr = ReadMemory<DWORD_PTR>(clientBase + ENTITY_LIST_OFFSET + (i * 0x10));
        if (entityAddr == 0) continue;

        int health = ReadMemory<int>(entityAddr + HEALTH_OFFSET);
        if (health <= 0) continue;

        EntityData entity;
        entity.id = i + 1;
        entity.health = health;
        entityList.push_back(entity);
    }

    return entityList;
}

D3DCOLOR GetHealthColor(int health) {
    if (health < 50) {
        return D3DCOLOR_XRGB(255, 0, 0); // Red
    }
    else if (health < 75) {
        return D3DCOLOR_XRGB(255, 255, 0); // Yellow
    }
    return D3DCOLOR_XRGB(0, 255, 0); // Green
}

void TriggerBot() {
    if (!localPlayer) return;

    int crosshairID = ReadMemory<int>(localPlayer + VIEW_ANGLES_OFFSET);
    if (crosshairID > 0 && crosshairID <= 64) {
        DWORD_PTR entity = ReadMemory<DWORD_PTR>(clientBase + ENTITY_LIST_OFFSET + (crosshairID - 1) * 0x10);
        if (entity) {
            int health = ReadMemory<int>(entity + HEALTH_OFFSET);
            if (health > 0) {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                Sleep(10);
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
        }
    }
}

void ForceSpotted() {
    for (int i = 0; i < 64; i++) {
        DWORD_PTR entityAddr = ReadMemory<DWORD_PTR>(clientBase + ENTITY_LIST_OFFSET + (i * 0x10));
        if (entityAddr == 0) continue;

        int health = ReadMemory<int>(entityAddr + HEALTH_OFFSET);
        if (health <= 0) continue;

        *(bool*)(entityAddr + SPOTTED_OFFSET) = true;
    }
}

DWORD WINAPI SpottedThread(LPVOID lpReserved) {
    while (true) {
        ForceSpotted();
        Sleep(5);
    }
    return 0;
}

HRESULT APIENTRY hkEndScene(LPDIRECT3DDEVICE9 pDevice) {
    if (!pFont) {
        InitializeD3DFont(pDevice);
    }

    entities = FetchEntityData();

    int yOffset = 50;
    for (const auto& entity : entities) {
        if (entity.health > 0) {
            std::string text = "ID: " + std::to_string(entity.id) + ", Health: " + std::to_string(entity.health);
            RECT textRect = { 20, yOffset, 200, yOffset + 20 };
            D3DCOLOR color = GetHealthColor(entity.health);
            pFont->DrawTextA(NULL, text.c_str(), -1, &textRect, DT_NOCLIP, color);
            yOffset += 20;
        }
    }

    if (triggerBotActive) TriggerBot();
    return oEndScene(pDevice);
}

DWORD WINAPI HookDirect3D(LPVOID lpReserved) {
    DWORD_PTR* pVTable = *(DWORD_PTR**)pDevice;
    oEndScene = (EndScene_t)pVTable[42];
    pVTable[42] = (DWORD_PTR)hkEndScene;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        clientBase = GetModuleBaseAddress("client.dll", GetCurrentProcessId());
        if (!clientBase) {
            MessageBox(NULL, L"Failed to find client.dll", L"Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }
        CreateThread(NULL, 0, HookDirect3D, NULL, 0, NULL);
        CreateThread(NULL, 0, SpottedThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        if (pFont) {
            pFont->Release();
            pFont = nullptr;
        }
        break;
    }
    return TRUE;
}