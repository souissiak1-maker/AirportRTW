#include "../rtw/hal_rtw88/Rtw88RxLayout.hpp"
#include "../rtw/hal_rtw88/Rtw88LinkPolicy.hpp"
#include "../include/HAL/RealtekPciIds.hpp"
#include <assert.h>
int main()
{
    using RealtekHal::Family;
    const uint16_t rtw88[] = {0xc822, 0xc82f, 0xb822, 0xc821, 0xb821, 0xd723, 0x8813};
    for (auto id : rtw88)
        assert(RealtekHal::family(0x10ec, id) == Family::RTW88);
    const uint16_t rtw89[] = {0x8852, 0xa85a, 0xb852, 0xb85b, 0xb851, 0xb520, 0xc852, 0x8922, 0x892b};
    for (auto id : rtw89) assert(RealtekHal::family(0x10ec, id) == Family::RTW89);
    assert(RealtekHal::family(0x8086, 0xc822) == Family::None);
    assert(RealtekHal::family(0x10ec, 0xffff) == Family::None);
    uint8_t streams[10] = {0xff, 0, 0, 0, 1};
    assert(Rtw88Link::htStreams(streams, sizeof(streams)) == 1);
    streams[1] = 0xff;
    assert(Rtw88Link::htStreams(streams, sizeof(streams)) == 2);
    streams[2] = 0xff;
    assert(Rtw88Link::htStreams(streams, sizeof(streams)) == 3);
    streams[3] = 0xff;
    assert(Rtw88Link::htStreams(streams, sizeof(streams)) == 4);
    assert(Rtw88Link::htStreams(nullptr, 0) == 1);
    uint8_t frame[64] = {};
    Rtw88Rx::CCMPLayout layout;
    frame[0] = 0x88; // QoS data
    frame[1] = 0x42; // downlink, protected
    frame[29] = 0x20; // extended CCMP IV, pairwise key zero
    assert(Rtw88Rx::ccmpLayout(frame, 42, layout));
    assert(layout.headerLength == 26 && layout.keyIndex == 0 && !layout.multicast);
    assert(!Rtw88Rx::ccmpLayout(frame, 41, layout));
    frame[4] = 1; frame[29] = 0xa0;
    assert(Rtw88Rx::ccmpLayout(frame, 42, layout));
    assert(layout.multicast && layout.keyIndex == 2);
    frame[29] = 0x80;
    assert(!Rtw88Rx::ccmpLayout(frame, 42, layout));
    assert(!Rtw88Rx::ccmpLayout(nullptr, 42, layout));
    assert(Rtw88Link::validChannel(5180, 5210, 80));
    assert(!Rtw88Link::validChannel(2412, 2442, 80));
    assert(!Rtw88Link::validChannel(5180, 5180, 40));
    // A one-stream card must not acquire the AP's second stream.
    assert(Rtw88Link::intersectMCS(0xfffe, 0xfffa) == 0xfffe);
    assert(Rtw88Link::vhtStreams(0xffff) == 0);
    assert(Rtw88Link::vhtStreams(0xfffe) == 1);
    assert(Rtw88Link::vhtStreams(0xfffa) == 2);
    assert(Rtw88Link::vhtStreams(0xffea) == 3);
    assert(Rtw88Link::vhtStreams(Rtw88Link::intersectMCS(0xffea, 0xfffa)) == 2);
}
