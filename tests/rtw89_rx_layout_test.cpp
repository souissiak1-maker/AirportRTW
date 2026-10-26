#include "../rtw/hal_rtw89/Rtw89RxLayout.hpp"
#include <assert.h>
#include <initializer_list>
#include <string.h>
int main()
{
    uint8_t frame[80] = {};
    frame[0] = 0x08; frame[1] = 0x42; frame[27] = 0x20;
    Rtw89Rx::CCMPLayout layout;
    assert(Rtw89Rx::ccmpLayout(frame, 40, layout));
    assert(layout.headerLength == 24 && layout.keyIndex == 0 && !layout.multicast);
    assert(!Rtw89Rx::ccmpLayout(frame, 39, layout));
    frame[4] = 1; frame[27] = 0xa0;
    assert(Rtw89Rx::ccmpLayout(frame, 40, layout));
    assert(layout.keyIndex == 2 && layout.multicast);
    frame[0] = 0x88; frame[1] = 0xc3; frame[39] = 0xe0;
    assert(Rtw89Rx::ccmpLayout(frame, 52, layout));
    assert(layout.headerLength == 36 && layout.keyIndex == 3);
    assert(!Rtw89Rx::ccmpLayout(frame, 51, layout));
    frame[39] = 0;
    assert(!Rtw89Rx::ccmpLayout(frame, 80, layout));
    frame[0] = 0x80;
    assert(!Rtw89Rx::ccmpLayout(frame, 80, layout));
    assert(!Rtw89Rx::ccmpLayout(nullptr, 80, layout));
    // Classify readable EAPOL without exposing or interpreting key data.
    memset(frame, 0, sizeof(frame));
    frame[0]=0x88; frame[1]=0x82; // QoS + HT control, FromDS, 30-byte header.
    const uint8_t llc[]={0xaa,0xaa,3,0,0,0,0x88,0x8e};
    memcpy(frame+30,llc,8);
    auto h=Rtw89Rx::handshakeHeader(frame,38,false,false);
    assert(h.control==0x8288 && h.etherType==0x888e && h.length==38);
    assert(Rtw89Rx::handshakeHeader(frame,37,false,false).etherType==0xffffffffu);
    frame[0]=0xc8; // QoS null: even LLC-looking bytes must not count as EAPOL.
    assert(Rtw89Rx::handshakeHeader(frame,38,false,false).etherType==0xffffffffu);
    frame[0]=0x88; frame[1]|=0x40;
    assert(Rtw89Rx::handshakeHeader(frame,38,false,false).etherType==0xffffffffu);
    assert(Rtw89Rx::handshakeHeader(frame,38,true,true).etherType==0x888e);
    memset(frame+30,0,8); memcpy(frame+38,llc,8);
    assert(Rtw89Rx::handshakeHeader(frame,46,true,false).etherType==0x888e);
    frame[1]|=4;
    assert(Rtw89Rx::handshakeHeader(frame,46,true,false).etherType==0xffffffffu);
    assert(Rtw89Rx::handshakeHeader(nullptr,80,false,false).etherType==0xffffffffu);
    // The direct association path must not accept another client's response.
    memset(frame, 0, sizeof(frame));
    const uint8_t station[6]={2,1,2,3,4,5}, peer[6]={2,6,7,8,9,10};
    frame[0]=0x10;
    memcpy(frame+4,station,6); memcpy(frame+10,peer,6); memcpy(frame+16,peer,6);
    assert(Rtw89Rx::associationResponse(frame,30,station,peer));
    frame[1]=8; // A valid retransmission is still an association response.
    assert(Rtw89Rx::associationResponse(frame,30,station,peer));
    frame[0]=0x30;
    assert(Rtw89Rx::associationResponse(frame,30,station,peer));
    for (unsigned offset : {4u,10u,16u}) {
        frame[offset]^=1;
        assert(!Rtw89Rx::associationResponse(frame,30,station,peer));
        frame[offset]^=1;
    }
    for (unsigned flag : {1u,2u,4u,0x40u,0x80u}) {
        frame[1]=flag;
        assert(!Rtw89Rx::associationResponse(frame,30,station,peer));
    }
    frame[1]=0; frame[22]=1;
    assert(!Rtw89Rx::associationResponse(frame,30,station,peer));
    frame[22]=0;
    assert(!Rtw89Rx::associationResponse(frame,29,station,peer));
    frame[0]=0x11; // Unsupported protocol version.
    assert(!Rtw89Rx::associationResponse(frame,30,station,peer));
    assert(!Rtw89Rx::associationResponse(nullptr,30,station,peer));

}
