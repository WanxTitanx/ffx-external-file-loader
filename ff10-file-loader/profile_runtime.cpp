// Jarvis-HOOK: verify before writing; stop other threads for the bounded patch transaction.
#include "pch.h"
#include "profile_runtime.h"
#include <bcrypt.h>
#include <tlhelp32.h>
#include <array>
#include <cstring>

namespace ff10 {
#ifdef FF10_LOADER_TESTING
static volatile LONG failNextRestore=0;
void FailNextProtectionRestoreForTest() noexcept { InterlockedExchange(&failNextRestore,1); }
#endif
namespace {
bool readable(std::uintptr_t start,std::size_t size) noexcept {
    if(!start || size>UINTPTR_MAX-start) return false;
    const auto end=start+size;
    while(start<end) {
        MEMORY_BASIC_INFORMATION m{};
        if(!VirtualQuery(reinterpret_cast<void*>(start),&m,sizeof(m)) || m.State!=MEM_COMMIT ||
           (m.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return false;
        const auto next=reinterpret_cast<std::uintptr_t>(m.BaseAddress)+m.RegionSize;
        if(next<=start) return false;
        start=next;
    }
    return true;
}
bool fileHashMatches(HMODULE module,const profiles::Profile& p) noexcept {
    std::array<wchar_t,32768> path{};
    const auto length=GetModuleFileNameW(module,path.data(),static_cast<DWORD>(path.size()));
    if(!length || length>=path.size()) return false;
    HANDLE file=CreateFileW(path.data(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(file==INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    bool ok=GetFileSizeEx(file,&size) && size.QuadPart==p.fileBytes;
    BCRYPT_ALG_HANDLE algorithm=nullptr;
    BCRYPT_HASH_HANDLE hash=nullptr;
    // The object buffer stays alive until the BCrypt hash has been destroyed.
    std::array<unsigned char,4096> object{};
    std::array<unsigned char,65536> buffer{};
    std::array<unsigned char,32> result{};
    ULONG objectLength=0,returned=0;
    if(ok) ok=BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0;
    if(ok) ok=BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&objectLength),sizeof(objectLength),&returned,0)>=0 &&
              objectLength<=object.size() && returned==sizeof(objectLength);
    if(ok) ok=BCryptCreateHash(algorithm,&hash,object.data(),objectLength,nullptr,0,0)>=0;
    std::uint64_t total=0;
    while(ok) {
        DWORD got=0;
        if(!ReadFile(file,buffer.data(),static_cast<DWORD>(buffer.size()),&got,nullptr)){ok=false;break;}
        if(!got) break;
        total+=got;
        if(total>p.fileBytes || BCryptHashData(hash,buffer.data(),got,0)<0){ok=false;break;}
    }
    if(ok) ok=total==p.fileBytes && BCryptFinishHash(hash,result.data(),static_cast<ULONG>(result.size()),0)>=0;
    if(hash) BCryptDestroyHash(hash);
    if(algorithm) BCryptCloseAlgorithmProvider(algorithm,0);
    CloseHandle(file);
    if(!ok) return false;
    static constexpr char hex[]="0123456789abcdef";
    for(std::size_t i=0;i<result.size();++i)
        if(hex[result[i]>>4]!=p.sha256[i*2] || hex[result[i]&15]!=p.sha256[i*2+1]) return false;
    return true;
}
struct ThreadBarrier {
    std::array<HANDLE,128> handles{};
    std::size_t count=0;
    ~ThreadBarrier(){ for(std::size_t i=count;i>0;--i){ResumeThread(handles[i-1]);CloseHandle(handles[i-1]);} }
    static bool intersects(std::uintptr_t pc,std::uintptr_t base,const PatchWrite* writes,std::size_t length) noexcept {
        for(std::size_t i=0;i<length;++i)
            if(pc>=base+writes[i].rva && pc<base+writes[i].rva+writes[i].length) return true;
        return false;
    }
    bool acquire(std::uintptr_t base,const PatchWrite* writes,std::size_t length) noexcept {
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        if(snapshot==INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 entry{};entry.dwSize=sizeof(entry);
        bool ok=Thread32First(snapshot,&entry)!=FALSE;
        while(ok) {
            if(entry.th32OwnerProcessID==GetCurrentProcessId() && entry.th32ThreadID!=GetCurrentThreadId()) {
                if(count==handles.size()){ok=false;break;}
                HANDLE thread=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,entry.th32ThreadID);
                if(!thread){ok=false;break;}
                if(SuspendThread(thread)==static_cast<DWORD>(-1)){CloseHandle(thread);ok=false;break;}
                handles[count++]=thread;
                CONTEXT context{};context.ContextFlags=CONTEXT_CONTROL;
                if(!GetThreadContext(thread,&context)){ok=false;break;}
                if(intersects(context.Eip,base,writes,length)){ok=false;break;}
                // A thread can be inside the original callee with a return into a
                // rewritten span. Its current EIP alone does not make patching safe.
                if(readable(context.Esp,4) && intersects(*reinterpret_cast<const DWORD*>(context.Esp),base,writes,length)){ok=false;break;}
                std::uintptr_t frame=context.Ebp;
                for(unsigned level=0;level<128 && frame>=context.Esp && readable(frame,8);++level) {
                    const auto* words=reinterpret_cast<const DWORD*>(frame);
                    if(intersects(words[1],base,writes,length)){ok=false;break;}
                    const auto next=static_cast<std::uintptr_t>(words[0]);
                    if(next<=frame || next-frame>65536) break;
                    frame=next;
                }
                if(!ok) break;
            }
            entry.dwSize=sizeof(entry);
            if(!Thread32Next(snapshot,&entry)){ok=GetLastError()==ERROR_NO_MORE_FILES;break;}
        }
        CloseHandle(snapshot);
        return ok;
    }
};
bool put(std::uintptr_t destination,const unsigned char* bytes,std::size_t size,DWORD finalProtection) noexcept {
    DWORD original=0;
    if(!VirtualProtect(reinterpret_cast<void*>(destination),size,PAGE_EXECUTE_READWRITE,&original)) return false;
    SIZE_T written=0;
    const bool copied=WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(destination),bytes,size,&written)!=FALSE && written==size;
#ifdef FF10_LOADER_TESTING
    if(InterlockedExchange(&failNextRestore,0)){SetLastError(ERROR_ACCESS_DENIED);return false;}
#endif
    DWORD unused=0;
    const bool protectedAgain=VirtualProtect(reinterpret_cast<void*>(destination),size,finalProtection,&unused)!=FALSE;
    return copied && protectedAgain && FlushInstructionCache(GetCurrentProcess(),reinterpret_cast<void*>(destination),size)!=FALSE;
}
}
const profiles::Profile* SelectVerifiedProfile(std::uintptr_t base) noexcept {
    if(!readable(base,4096)) return nullptr;
    const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<static_cast<LONG>(sizeof(*dos)) ||
       static_cast<unsigned long>(dos->e_lfanew)>4096-sizeof(IMAGE_NT_HEADERS32)) return nullptr;
    const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(base+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC) return nullptr;
    const auto* p=profiles::HeaderMatch(nt->FileHeader.Machine,nt->FileHeader.TimeDateStamp,nt->OptionalHeader.SizeOfImage);
    if(!p || !fileHashMatches(reinterpret_cast<HMODULE>(base),*p)) return nullptr;
    for(const auto& site:p->sites) if(!readable(base+site.rva,site.length)) return nullptr;
    return profiles::WitnessMatch(*p,reinterpret_cast<const std::uint8_t*>(base),p->imageBytes) ? p : nullptr;
}
bool ApplyPatchTransaction(std::uintptr_t base,const profiles::Profile& profile,const PatchWrite* writes,std::size_t count) noexcept {
    if(!writes || !count || count>5) return false;
    std::array<std::array<unsigned char,5>,5> originals{};
    std::array<DWORD,5> originalProtection{};
    for(std::size_t i=0;i<count;++i) {
        if(!writes[i].length || writes[i].length>5 || !readable(base+writes[i].rva,writes[i].length)) return false;
        std::memcpy(originals[i].data(),reinterpret_cast<void*>(base+writes[i].rva),writes[i].length);
        MEMORY_BASIC_INFORMATION m{};
        if(!VirtualQuery(reinterpret_cast<void*>(base+writes[i].rva),&m,sizeof(m))) return false;
        originalProtection[i]=m.Protect;
    }
    ThreadBarrier barrier;
    if(!barrier.acquire(base,writes,count)) return false;
    // Revalidate after suspending peers. A foreign writer could have changed a
    // different witness between profile admission and the pre-barrier snapshot.
    if(!profiles::WitnessMatch(profile,reinterpret_cast<const std::uint8_t*>(base),profile.imageBytes)) return false;
    for(std::size_t i=0;i<count;++i)
        if(std::memcmp(originals[i].data(),reinterpret_cast<void*>(base+writes[i].rva),writes[i].length)) return false;
    for(std::size_t i=0;i<count;++i)
        if(!put(base+writes[i].rva,writes[i].replacement.data(),writes[i].length,originalProtection[i])) {
            // Include the failing span: a partial write/protection failure can have changed it.
            bool restored=true;
            for(std::size_t j=i+1;j>0;--j) restored=put(base+writes[j-1].rva,originals[j-1].data(),writes[j-1].length,originalProtection[j-1]) && restored;
            if(!restored) TerminateProcess(GetCurrentProcess(),ERROR_WRITE_FAULT);
            return false;
        }
    return true;
}
}
