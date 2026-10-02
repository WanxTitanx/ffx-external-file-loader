// Jarvis-HOOK: exact executable identities and bounded native-site witnesses.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ff10::profiles {
struct Site {
    std::uint32_t rva;
    std::array<std::uint8_t, 5> bytes;
    std::uint8_t length;
};
struct Profile {
    const char* name;
    bool x2;
    std::uint32_t timestamp, imageBytes, fileBytes;
    const char* sha256;
    std::uint32_t openVbf, checkExists;
    // before/open-hook/after/exists-hook/optional archive check, in that order.
    std::array<Site, 5> sites;
};
inline constexpr Profile all[] = {
    {"FFX legacy", false, 0x55D2F3CC, 0x237D000, 10675712,
     "78ce34397da5e6f49b72c2aebadedaf4cd3f6720e1949d46a1b8ed67d3db5ced",
     0x21C0D0, 0x21C000,
     {{{0x2081AF,{0xE8,0x1C,0x3F,0x01,0},4},{0x2081B3,{0,0x89,0x43,4,0x85},5},
       {0x2081B8,{0xC0,0x75,0,0,0},2},{0x20805F,{0xE8,0x9C,0x3F,1,0},5},{0x2797AE,{0x75,0x70,0,0,0},2}}}},
    {"FFX Steam 25501027", false, 0x6AA2219C, 0x237D000, 10687744,
     "0537b2a1047f3266e73495cd4e35f63f0777f4231d417699f979954686da686d",
     0x21BF10, 0x21BE40,
     {{{0x207FEF,{0xE8,0x1C,0x3F,0x01,0},4},{0x207FF3,{0,0x89,0x43,4,0x85},5},
       {0x207FF8,{0xC0,0x75,0,0,0},2},{0x207E9F,{0xE8,0x9C,0x3F,1,0},5},{0x2795FE,{0x75,0x70,0,0,0},2}}}},
    {"FFX-2 legacy LAA-unaware reference", true, 0x55D433A4, 0x1C14000, 12271104,
     "d7f08cda89dbcd6f429814e9523ce7a63a094417442a025573afbbef3251ef20",
     0x542BA0, 0x542AD0,
     {{{0x49134F,{0xE8,0x4C,0x18,0x0B,0},4},{0x491353,{0,0x89,0x43,4,0x85},5},
       {0x491358,{0xC0,0x75,0,0,0},2},{0x4911EF,{0xE8,0xDC,0x18,0x0B,0},5},{0x94C6E,{0x75,0x70,0,0,0},2}}}},
    {"FFX-2 Steam 25501027", true, 0x6AA2217B, 0x1C13000, 12281600,
     "6ea7f142f129a43bdaea7eaabda4477a9057e60d12fdae367530c63e9a14cd69",
     0x542A00, 0x542930,
     {{{0x49124F,{0xE8,0xAC,0x17,0x0B,0},4},{0x491253,{0,0x89,0x43,4,0x85},5},
       {0x491258,{0xC0,0x75,0,0,0},2},{0x4910EF,{0xE8,0x3C,0x18,0x0B,0},5},{0x94CEE,{0x75,0x70,0,0,0},2}}}},
};
inline const Profile* HeaderMatch(std::uint16_t machine, std::uint32_t stamp,
                                  std::uint32_t imageBytes) noexcept {
    if (machine != 0x14C) return nullptr;
    for (const auto& p : all)
        if (p.timestamp == stamp && p.imageBytes == imageBytes) return &p;
    return nullptr;
}
inline bool WitnessMatch(const Profile& p, const std::uint8_t* image,
                         std::size_t size) noexcept {
    if (!image || size < p.imageBytes) return false;
    for (const auto& s : p.sites)
        if (!s.length || s.length > s.bytes.size() || s.rva > size || s.length > size-s.rva ||
            std::memcmp(image+s.rva,s.bytes.data(),s.length)) return false;
    constexpr std::uint8_t entry[]={0x55,0x8B,0xEC,0x83,0xEC,0x1C};
    for(const auto rva:{p.openVbf,p.checkExists})
        if(rva>size || sizeof(entry)>size-rva || std::memcmp(image+rva,entry,sizeof(entry))) return false;
    const auto target = [image](std::uint32_t rva) {
        std::int32_t delta=0; std::memcpy(&delta,image+rva+1,4);
        return static_cast<std::uint32_t>(rva+5+delta);
    };
    // The displaced native calls must reach the independently mapped routines.
    return image[p.sites[0].rva] == 0xE8 && target(p.sites[0].rva) == p.openVbf &&
           image[p.sites[3].rva] == 0xE8 && target(p.sites[3].rva) == p.checkExists;
}
}
