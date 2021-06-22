// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "hook.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LOG(INFO) << "Initializing file loader. Module base: 0x" << GetModuleHandle(NULL);
        wchar_t modulePath[MAX_PATH];
        GetModuleFileName(hModule, modulePath, MAX_PATH);
        ff10::FileLoader::setModulePath(std::filesystem::path(modulePath).remove_filename());
        ff10::FileLoader::setModuleBase((intptr_t)GetModuleHandle(NULL));
        ff10::FileLoader::readConfig();
        ff10::FileLoader::initPatchesHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

