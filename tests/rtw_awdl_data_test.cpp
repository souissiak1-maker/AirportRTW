/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlData.hpp>
#include <assert.h>
#include <string.h>
#include <stdio.h>
using namespace RTWAwdl;
int main() {
    uint8_t eth[14 + DataCodec::mtu] {}, wire[DataCodec::maximumFrame], decoded[sizeof(eth)];
    eth[0]=0x33; eth[1]=0x33; eth[6]=2; eth[11]=1;
    eth[12]=0x86; eth[13]=0xdd; eth[14]=0x60;
    size_t n=0, m=0; uint16_t seq=0;
    assert(DataCodec::encode(eth,54,wire,sizeof(wire),0xffff,0x1234,n));
    assert(n==82 && wire[22]==0xf0 && wire[23]==0xff && wire[36]==0x34 && wire[37]==0x12);
    assert(DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq) && m==54 && seq==0x1234);
    assert(memcmp(decoded,eth,m)==0);
    for (size_t cut=0;cut<n;++cut) assert(!DataCodec::decode(wire,cut,decoded,sizeof(decoded),m,seq));
    // Every fixed LLC/AWDL byte is checked, excluding the varying sequence.
    for (size_t i=26;i<42;++i) {
        if (i==36 || i==37) continue;
        wire[i]^=1;
        assert(!DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq));
        wire[i]^=1;
    }
    const uint8_t flags[] {1,2,4,0x40,0x80};
    for (uint8_t flag : flags) {
        wire[1]=flag;
        assert(!DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq));
    }
    wire[1]=0; wire[24]=0x80;
    assert(!DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq));
    wire[24]=0; wire[22]|=1;
    assert(!DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq));
    wire[22]&=0xf0;
    assert(!DataCodec::decode(wire,n,decoded,53,m,seq));
    assert(!DataCodec::encode(eth,54,wire,81,0,0,n));
    eth[6]=1;
    assert(!DataCodec::encode(eth,54,wire,sizeof(wire),0,0,n));
    eth[6]=2;
    const size_t ipPayload=DataCodec::mtu-40;
    eth[18]=uint8_t(ipPayload>>8); eth[19]=uint8_t(ipPayload);
    for(size_t i=54;i<sizeof(eth);++i) eth[i]=uint8_t(i);
    assert(DataCodec::encode(eth,sizeof(eth),wire,sizeof(wire),1,0xffff,n));
    assert(n==sizeof(wire));
    assert(DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq) && seq==0xffff);
    assert(m==sizeof(eth) && memcmp(decoded,eth,m)==0);
    // Deterministic malformed input stress under address/undefined sanitizers.
    uint32_t r=0x7823;
    for (unsigned iteration=0;iteration<20000;++iteration) {
        for (auto &b:wire) {r=r*1664525+1013904223; b=uint8_t(r>>24);}
        DataCodec::decode(wire,r%sizeof(wire),decoded,sizeof(decoded),m,seq);
    }
    puts("PASS: AWDL IPv6 data framing, bounds and malformed frames");
}
