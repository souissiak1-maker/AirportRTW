/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlTxTemplate.hpp>
#include <AWDL/RTWAwdlRadioCoordinator.hpp>
#include <assert.h>
#include <string.h>
#include <stdio.h>
using namespace RTWAwdl;
static void templates() {
    TxTemplate t;
    uint8_t body[20] {127, 0, 0x17, 0xf2, 8, 0x10, 3};
    body[16] = 4; body[17] = 1; body[19] = 0xa5;
    assert(t.replace(body, sizeof(body)));
    body[19] = 0;
    uint8_t dst[6] {0x33,0x33,0,0,0,1}, src[6] {2,1,2,3,4,5}, bssid[6] {0,1,2,3,4,5};
    uint8_t out[4120]; memset(out, 0xcc, sizeof(out));
    size_t n = 99;
    assert(!t.build(out, 43, dst, src, bssid, 1, 2, 3, n));
    assert(n == 0 && out[0] == 0xcc);
    assert(t.build(out, sizeof(out), dst, src, bssid, 0xffff, 0x12345678, 0x90abcdef, n));
    assert(n == 44 && out[22] == 0xf0 && out[23] == 0xff && out[43] == 0xa5);
    assert(memcmp(out+4,dst,6)==0 && memcmp(out+10,src,6)==0 && memcmp(out+16,bssid,6)==0);
    assert(out[32] == 0x78 && out[35] == 0x12 && out[36] == 0xef && out[39] == 0x90);
    ActionInfo info;
    assert(parseFrame(out, n, info) == ParseResult::Valid && info.subtype == 3);
    for (size_t len=0; len<16; ++len) assert(!t.replace(body,len));
    body[6] = 1;
    assert(!t.replace(body,sizeof(body)) && t.size()==20);
    body[6] = 0; body[17] = 2;
    assert(!t.replace(body,sizeof(body)) && t.size()==20);
    assert(t.build(out,sizeof(out),dst,src,bssid,0,0,0,n) && out[43]==0xa5);
    src[0] = 1;
    assert(!t.build(out,sizeof(out),dst,src,bssid,0,0,0,n) && n==0);
    memset(src,0,6);
    assert(!t.build(out,sizeof(out),dst,src,bssid,0,0,0,n));
    uint8_t maximum[4097] {127,0,0x17,0xf2,8,1,0};
    // One TLV fills the entire maximum body.
    maximum[16]=42; maximum[17]=0xed; maximum[18]=0x0f;
    assert(t.replace(maximum,4096));
    assert(!t.replace(maximum,4097) && t.size()==4096);
    src[0]=2;
    assert(t.build(out,sizeof(out),dst,src,bssid,0,0,0,n) && n==4120);
    t.clear();
    assert(t.size()==0 && !t.build(out,sizeof(out),dst,src,bssid,0,0,0,n));
}
static void leases() {
    RadioCoordinator radio;
    RadioCoordinator::Request req {}, home {};
    using State=RadioCoordinator::State;
    assert(!radio.request(6,1000,0,true,false,req));
    assert(!radio.start(0,1000,false));
    assert(!radio.start(2,100001,false));
    assert(radio.start(2,40000,false));
    assert(!radio.start(2,40000,false));
    assert(!radio.request(6,1000,0,true,true,req));
    assert(!radio.request(6,1000,0,false,false,req));
    assert(!radio.request(6,0,0,true,false,req));
    assert(!radio.request(6,40001,0,true,false,req));
    assert(!radio.request(6,100,UINT64_MAX-50,true,false,req));
    assert(radio.request(6,1000,100,true,false,req));
    auto first=req.token;
    assert(!radio.request(44,100,101,true,false,req));
    assert(!radio.switched(first-1,true,101));
    assert(radio.switched(first,true,102) && radio.state()==State::Away);
    assert(!radio.due(1099) && radio.due(1100));
    assert(radio.beginReturn(home) && home.channel==2 && home.token!=first);
    assert(!radio.switched(first,true,1101));
    assert(radio.switched(home.token,false,1102) && radio.state()==State::Failed);
    assert(!radio.request(44,100,1103,true,false,req));
    assert(radio.beginReturn(home));
    assert(radio.switched(home.token,true,1104) && radio.state()==State::Home);
    assert(radio.request(44,100,1200,true,false,req));
    assert(radio.switched(req.token,true,1300) && radio.state()==State::Failed);
    assert(radio.beginReturn(home));
    radio.stop();
    assert(!radio.switched(home.token,true,1301) && radio.state()==State::Stopped);
    assert(radio.start(2,10000,true));
    assert(radio.request(149,1000,2000,true,true,req));
    assert(radio.switched(req.token,false,2001) && radio.state()==State::Failed);
    assert(radio.beginReturn(home));
    assert(radio.switched(home.token,true,2002));
    assert(!radio.switched(home.token,true,2003));
    radio.stop();
}
int main() { templates(); leases(); puts("AWDL template and radio ownership tests passed"); }
