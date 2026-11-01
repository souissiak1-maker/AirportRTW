/* SPDX-License-Identifier: GPL-2.0-only */
#include <AWDL/RTWAwdlNativeAction.hpp>
#include <cassert>
#include <cstdio>
using namespace RTWAwdl;
int main() {
    Election::State state{};Election::Sequence plan{};plan.count=16;plan.step=3;
    for(auto &c:plan.channels)c=6;
    const uint8_t local[6]={2,1,2,3,4,5};
    assert(state.init(local,plan,1000000,42,true));
    // Native identity is retained, but its stale election/tree are replaced.
    uint8_t tlvs[3+4+3+21+3+40+3+6]{};size_t n=0;
    auto add=[&](uint8_t type,unsigned size){auto *p=tlvs+n;p[0]=type;Election::put16(p+1,uint16_t(size));n+=3+size;return p+3;};
    auto *identity=add(25,4);memcpy(identity,"test",4);
    auto *legacy=add(5,21);memset(legacy,0xaa,21);
    add(24,40);add(20,6);
    assert(NativeAction::valid(tlvs,n));TxTemplate native;
    assert(native.replaceTlvs(tlvs,n,0x10,0));
    memset(tlvs,0,sizeof(tlvs)); // request ownership ended
    uint8_t frame[4096]{};const uint16_t counter=state.frameCounter;
    assert(!NativeAction::build(state,native,frame,4,1000001,1,0));
    assert(state.frameCounter==counter);
    const size_t size=NativeAction::build(state,native,frame,sizeof(frame),1000001,123,3);
    assert(size && state.frameCounter==uint16_t(counter+1));
    assert(!memcmp(frame+10,local,6));Election::Advertisement a{};
    assert(Election::parseAdvertisement(frame,size,a));assert(a.metric==42);
    TlvCursor cursor(frame+40,size-40);Tlv t{};unsigned elections=0,identities=0,legacies=0;
    while(cursor.next(t)) {
        assert(t.type!=20);
        if(t.type==24)++elections;
        if(t.type==25){++identities;assert(t.length==4 && !memcmp(t.data,"test",4));}
        if(t.type==5){++legacies;assert(t.data[3]==0 && !memcmp(t.data+5,local,6));assert(t.data[15]==42 && !t.data[16] && !t.data[17] && !t.data[18]);}
    }
    assert(!cursor.failed() && elections==1 && identities==1 && legacies==1);
    uint8_t invalid[]={4,0,0};assert(!NativeAction::valid(invalid,sizeof(invalid)));
    invalid[0]=18;assert(!NativeAction::valid(invalid,sizeof(invalid)));
    invalid[0]=5;assert(!NativeAction::valid(invalid,sizeof(invalid)));
    invalid[0]=20;invalid[1]=1;assert(!NativeAction::valid(invalid,sizeof(invalid)));
    assert(!NativeAction::valid(nullptr,0));
    puts("PASS: native TLV ownership, fresh election, identity preservation and atomic capacity rejection");
}
