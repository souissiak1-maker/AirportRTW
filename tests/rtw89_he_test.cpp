#include "../rtw80211/openbsd/net80211/ieee80211_he_policy.hpp"
#include "../include/HAL/RealtekPhyMode.hpp"
#include <cassert>
int main()
{
    using namespace Net80211HE;
    assert(intersect(0xfffa, 0xfffe) == 0xfffe);
    assert(ratesValid(0xfffa, 0xfffa, 0xfffe, 0xfffe, 0xfffc));
    assert(!ratesValid(0xfffa, 0xfffa, 0xffff, 0xfffe, 0xfffc));
    assert(!ratesValid(0xfffe, 0xfffe, 0xfffa, 0xfffa, 0xfffa));
    assert(ratesValid(0xfffe, 0xfffe, 0xfffe, 0xfffe, 0));
    assert(streams(0xfffa) == 2 && streams(0xfffe) == 1);
    assert(center80(5180) == 5210 && center80(5240) == 5210);
    assert(center80(5745) == 5775 && center80(5805) == 5775);
    assert(center80(2412) == 0 && center80(5350) == 0);
    uint8_t exactCap[21] = {};
    assert(validCapabilities(exactCap, sizeof(exactCap)));
    for (unsigned len = 0; len < sizeof(exactCap); ++len)
        assert(!validCapabilities(exactCap, len));
    uint8_t cap[54] = {};
    assert(!validCapabilities(nullptr, 21));
    assert(!validCapabilities(cap, 20));
    assert(validCapabilities(cap, 21)); // no PPE: do not read byte 21
    cap[6] = 0x18;
    assert(!validCapabilities(cap, 28));
    assert(validCapabilities(cap, 29));
    cap[6] = 0; cap[12] = 0x80; cap[21] = 0x19; // 2 streams, 2 RU sizes: 4 bytes
    assert(!validCapabilities(cap, 21));
    assert(!validCapabilities(cap, 24));
    assert(validCapabilities(cap, 25));
    uint8_t op[15] = {};
    assert(!validOperation(op, 5) && validOperation(op, 6));
    op[1] = 0x40;
    assert(!validOperation(op, 8) && validOperation(op, 9));
    op[1] = 0xc0; op[2] = 2;
    assert(!validOperation(op, 14) && validOperation(op, 15));
    using RealtekPhy::Mode;
    assert(RealtekPhy::active(false, true, true, true) == Mode::Auto);
    assert(RealtekPhy::active(true, true, true, true) == Mode::HE);
    assert(RealtekPhy::active(true, false, true, true) == Mode::VHT);
    assert(RealtekPhy::active(true, false, false, true) == Mode::HT);
    assert(RealtekPhy::active(true, false, false, false) == Mode::Legacy);
}
