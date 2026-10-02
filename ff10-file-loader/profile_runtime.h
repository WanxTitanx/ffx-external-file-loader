#pragma once
#include "profiles.h"
#include <windows.h>
namespace ff10 {
struct PatchWrite {
    std::uint32_t rva;
    std::uint8_t length;
    std::array<std::uint8_t,5> replacement;
};
const profiles::Profile* SelectVerifiedProfile(std::uintptr_t base) noexcept;
bool ApplyPatchTransaction(std::uintptr_t base,const profiles::Profile& profile,const PatchWrite* writes,std::size_t count) noexcept;
#ifdef FF10_LOADER_TESTING
void FailNextProtectionRestoreForTest() noexcept;
#endif
}
