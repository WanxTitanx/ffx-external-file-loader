// Private PE fixtures are arguments. Their entrypoints/import initialization are never run.
#include "../ff10-file-loader/pch.h"
#include "../ff10-file-loader/hook.h"
#include "../ff10-file-loader/profile_runtime.h"
#include <cstdio>
#include <cstdlib>
#include <array>
namespace ff10 {
struct FileLoaderTestAccess {
    static void setup(std::uintptr_t base,const std::filesystem::path& path) {
        FileLoader::setModuleBase(static_cast<intptr_t>(base));
        FileLoader::setModulePath(path);
        FileLoader::readConfig();
    }
    static void options(bool enabled,bool noVbf,const std::filesystem::path& mods) {
        FileLoader::enabled=enabled;FileLoader::allowNoVbf=noVbf;FileLoader::modsPaths={mods};
    }
    static int exists(char* path){return FileLoader::openCheckExistsHook(nullptr,path);}
    static int open(int* result,char* path){return FileLoader::openVBFHook(nullptr,1,result,path);}
};
}
static unsigned checks=0;
static void check(bool ok,const char* note) {
    ++checks;if(!ok){std::fprintf(stderr,"FAIL #%u %s error=%lu\n",checks,note,GetLastError());std::exit(1);}
}
static void bytes(std::uintptr_t at,const void* data,std::size_t count) {
    DWORD protection=0,unused=0;check(VirtualProtect(reinterpret_cast<void*>(at),count,PAGE_EXECUTE_READWRITE,&protection)!=FALSE,"test image writable");
    std::memcpy(reinterpret_cast<void*>(at),data,count);
    check(VirtualProtect(reinterpret_cast<void*>(at),count,protection,&unused)!=FALSE,"test protection restored");
    check(FlushInstructionCache(GetCurrentProcess(),reinterpret_cast<void*>(at),count)!=FALSE,"test instruction cache");
}
int wmain(int argc,wchar_t** argv) {
    check(argc==3,"fixture and disposable directory arguments");
    const std::filesystem::path root=argv[2];check(!std::filesystem::exists(root),"fresh private test directory");
    std::filesystem::create_directories(root/"config");std::filesystem::create_directories(root/"overrides");
    std::ofstream(root/"config/ff10-file-loader.ini") << "[General]\nenabled=1\nallowNoVbf=false\n";
    std::ofstream(root/"overrides/ff10-test.bin",std::ios::binary) << "JARVIS_FILE_LOADER_RT1";
    HMODULE image=LoadLibraryExW(argv[1],nullptr,DONT_RESOLVE_DLL_REFERENCES);
    check(image!=nullptr,"map actual PE without entrypoint/import initialization");
    const auto base=reinterpret_cast<std::uintptr_t>(image);
    ff10::FileLoaderTestAccess::setup(base,root);
    check(ff10::FileLoader::isEnabled(),"explicit config opt-in");
    const auto* p=ff10::SelectVerifiedProfile(base);check(p!=nullptr,"exact file hash/header/native witnesses admitted");
    std::array<std::array<unsigned char,5>,5> original{};
    for(unsigned i=0;i<5;++i)std::memcpy(original[i].data(),reinterpret_cast<void*>(base+p->sites[i].rva),p->sites[i].length);
    ff10::FileLoaderTestAccess::options(false,false,root/"overrides");
    check(!ff10::FileLoader::initPatchesHooks(),"disabled loader owns no patches");
    for(unsigned i=0;i<5;++i)check(!std::memcmp(original[i].data(),reinterpret_cast<void*>(base+p->sites[i].rva),p->sites[i].length),"off preserves each site");
    ff10::FileLoaderTestAccess::options(true,false,root/"overrides");
    unsigned char changed=original[4][0]^1;bytes(base+p->sites[4].rva,&changed,1);
    const ff10::PatchWrite attempted{p->sites[0].rva,4,{0x53,0xFF,0x75,0x0C,0}};
    check(!ff10::ApplyPatchTransaction(base,*p,&attempted,1),"post-admission foreign write revalidated under thread barrier");
    check(!std::memcmp(original[0].data(),reinterpret_cast<void*>(base+p->sites[0].rva),4),"foreign race cannot acquire an earlier span");
    check(!ff10::FileLoader::initPatchesHooks(),"foreign-site mutation rejects whole installation");
    for(unsigned i=0;i<4;++i)check(!std::memcmp(original[i].data(),reinterpret_cast<void*>(base+p->sites[i].rva),p->sites[i].length),"rejection owns no earlier sites");
    bytes(base+p->sites[4].rva,original[4].data(),1);
    MEMORY_BASIC_INFORMATION protectionBefore{},protectionAfter{};
    check(VirtualQuery(reinterpret_cast<void*>(base+p->sites[0].rva),&protectionBefore,sizeof(protectionBefore))!=0,"capture native page protection");
    ff10::FailNextProtectionRestoreForTest();
    check(!ff10::ApplyPatchTransaction(base,*p,&attempted,1),"failed protection restore rolls back the touched span");
    check(!std::memcmp(original[0].data(),reinterpret_cast<void*>(base+p->sites[0].rva),4),"failed transaction restores original bytes");
    check(VirtualQuery(reinterpret_cast<void*>(base+p->sites[0].rva),&protectionAfter,sizeof(protectionAfter))!=0 && protectionAfter.Protect==protectionBefore.Protect,"rollback restores pre-transaction protection, not intermediate RWX");
    check(ff10::FileLoader::initPatchesHooks(),"bounded native patch transaction");
    for(unsigned i=0;i<4;++i)check(std::memcmp(original[i].data(),reinterpret_cast<void*>(base+p->sites[i].rva),p->sites[i].length)!=0,"selected patch changed");
    check(!std::memcmp(original[4].data(),reinterpret_cast<void*>(base+p->sites[4].rva),p->sites[4].length),"archive-required default unchanged");
    char external[]="../../../ff10-test.bin";
    check(ff10::FileLoaderTestAccess::exists(external)==1,"external existence routing");
    int result[2]={-1,-1};check(ff10::FileLoaderTestAccess::open(result,external)==0,"external file open routing");
    check(result[0]!=-1 && result[1]==0,"direct file handle and no archive entry");
    char payload[64]{};DWORD got=0;
    check(ReadFile(reinterpret_cast<HANDLE>(static_cast<intptr_t>(result[0])),payload,sizeof(payload),&got,nullptr)!=FALSE,"read direct handle");
    check(std::string(payload,got)=="JARVIS_FILE_LOADER_RT1","actual external payload");
    CloseHandle(reinterpret_cast<HANDLE>(static_cast<intptr_t>(result[0])));
    check(ff10::FileLoaderTestAccess::exists(nullptr)==0,"null lookup rejected");
    check(ff10::FileLoaderTestAccess::open(result,nullptr)==10,"null open rejected");
    // Fake only the native archive endpoints in this disposable mapped image.
    // Their ret 4 preserves the original thiscall stack contract.
    const unsigned char stub[]={0xB8,0x4D,0,0,0,0xC2,4,0};
    std::array<unsigned char,8> oldOpen{},oldExists{};
    std::memcpy(oldOpen.data(),reinterpret_cast<void*>(base+p->openVbf),8);
    std::memcpy(oldExists.data(),reinterpret_cast<void*>(base+p->checkExists),8);
    bytes(base+p->openVbf,stub,sizeof(stub));bytes(base+p->checkExists,stub,sizeof(stub));
    char missing[]="../../../no-override.bin";
    check(ff10::FileLoaderTestAccess::exists(missing)==77,"archive existence fallback uses selected native address/ABI");
    result[0]=-1;result[1]=-1;
    check(ff10::FileLoaderTestAccess::open(result,missing)==0 && result[1]==77,"archive open fallback uses selected native address/ABI");
    bytes(base+p->openVbf,oldOpen.data(),8);bytes(base+p->checkExists,oldExists.data(),8);
    for(unsigned i=0;i<5;++i)bytes(base+p->sites[i].rva,original[i].data(),p->sites[i].length);
    ff10::FileLoaderTestAccess::options(true,true,root/"overrides");
    check(ff10::FileLoader::initPatchesHooks(),"optional no-archive mode explicit opt-in");
    check(*reinterpret_cast<const unsigned char*>(base+p->sites[4].rva)==0xEB,"optional archive check owns only requested span");
    for(unsigned i=0;i<5;++i)bytes(base+p->sites[i].rva,original[i].data(),p->sites[i].length);
    check(ff10::SelectVerifiedProfile(base)==p,"all native bytes restored in private image");
    FreeLibrary(image);
    const auto tampered=root/"same-header-tampered.exe";
    std::filesystem::copy_file(argv[1],tampered);
    {
        std::fstream file(tampered,std::ios::in|std::ios::out|std::ios::binary);
        file.seekg(-1,std::ios::end);char byte=0;file.read(&byte,1);byte^=1;
        file.seekp(-1,std::ios::end);file.write(&byte,1);
    }
    HMODULE modified=LoadLibraryExW(tampered.c_str(),nullptr,DONT_RESOLVE_DLL_REFERENCES);
    check(modified!=nullptr,"tampered copy still maps with original PE headers");
    const auto changedBase=reinterpret_cast<std::uintptr_t>(modified);
    ff10::FileLoaderTestAccess::setup(changedBase,root);
    check(ff10::SelectVerifiedProfile(changedBase)==nullptr,"same header/size with changed file hash rejected");
    check(!ff10::FileLoader::initPatchesHooks(),"tampered executable owns no patches");
    for(unsigned i=0;i<5;++i)check(!std::memcmp(original[i].data(),reinterpret_cast<void*>(changedBase+p->sites[i].rva),p->sites[i].length),"tampered rejection preserves every native site");
    FreeLibrary(modified);
    std::printf("NATIVE_RT1 %s %u/%u passed; game entrypoint not executed\n",p->name,checks,checks);
}
