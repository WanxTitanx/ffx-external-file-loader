#include "../ff10-file-loader/profiles.h"
#include <cstdio>
#include <vector>
#include <cstdlib>
static unsigned checks=0;
static void check(bool ok) { ++checks; if (!ok) {std::fprintf(stderr,"FAIL check %u\n",checks);std::exit(1);} }
int main() {
    using namespace ff10::profiles;
    // Independent coordinates from whole-body/callsite proof, not copies read from the table.
    check(all[1].openVbf==0x21BF10 && all[1].checkExists==0x21BE40);
    check(all[3].openVbf==0x542A00 && all[3].checkExists==0x542930);
    check(all[1].sites[0].rva==0x207FEF && all[3].sites[0].rva==0x49124F);
    for (const auto& p : all) {
        check(HeaderMatch(0x14C,p.timestamp,p.imageBytes)==&p);
        check(!HeaderMatch(0x8664,p.timestamp,p.imageBytes));
        check(!HeaderMatch(0x14C,p.timestamp^1,p.imageBytes));
        check(!HeaderMatch(0x14C,p.timestamp,p.imageBytes-0x1000));
        std::vector<std::uint8_t> image(p.imageBytes);
        for (const auto& s:p.sites) std::memcpy(image.data()+s.rva,s.bytes.data(),s.length);
        const unsigned char entry[]={0x55,0x8B,0xEC,0x83,0xEC,0x1C};
        for(const auto rva:{p.openVbf,p.checkExists}) std::memcpy(image.data()+rva,entry,sizeof(entry));
        check(WitnessMatch(p,image.data(),image.size()));
        check(!WitnessMatch(p,nullptr,image.size()));
        check(!WitnessMatch(p,image.data(),image.size()-1));
        for (const auto& s:p.sites) for (unsigned n=0;n<s.length;++n) {
            image[s.rva+n]^=1;check(!WitnessMatch(p,image.data(),image.size()));image[s.rva+n]^=1;
        }
        // Original native call's last byte crosses from before-patch into hook-patch.
        image[p.sites[0].rva+4]^=1;check(!WitnessMatch(p,image.data(),image.size()));
        image[p.sites[0].rva+4]^=1;
        for(const auto rva:{p.openVbf,p.checkExists}) {
            image[rva]^=1;check(!WitnessMatch(p,image.data(),image.size()));image[rva]^=1;
        }
    }
    std::printf("PROFILE_RT0 %u/%u passed\n",checks,checks);
}
