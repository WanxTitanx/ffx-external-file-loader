// Jarvis-HOOK: only bounded bootstrap in DllMain; filesystem/crypto/patches run on a worker.
#include "pch.h"
#include "hook.h"
static DWORD WINAPI LoaderWorker(void* parameter) {
    wchar_t path[32768]{};
    const auto size=GetModuleFileNameW(static_cast<HMODULE>(parameter),path,static_cast<DWORD>(_countof(path)));
    if(!size || size>=_countof(path)) return 0;
    try {
        ff10::FileLoader::setModulePath(std::filesystem::path(path).remove_filename());
        ff10::FileLoader::setModuleBase(reinterpret_cast<intptr_t>(GetModuleHandleW(nullptr)));
        ff10::FileLoader::readConfig();
        ff10::FileLoader::initPatchesHooks();
    } catch(...) { LOG(ERR) << "File loader startup failed; no unsupported profile admitted."; }
    return 0;
}
BOOL APIENTRY DllMain(HMODULE module,DWORD reason,LPVOID) {
    if(reason==DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HMODULE pinned=nullptr;
        // Pin before dispatch to close the dispatch/unload race. No IO or patching here.
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&LoaderWorker),&pinned)) return FALSE;
        HANDLE worker=CreateThread(nullptr,0,LoaderWorker,module,0,nullptr);
        if(!worker) return FALSE;
        CloseHandle(worker);
    }
    // Process-lifetime pin keeps callbacks resident; detach never waits or mutates game code.
    return TRUE;
}
