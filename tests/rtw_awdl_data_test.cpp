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
    assert(n==DataCodec::maximumFrame);
    assert(DataCodec::decode(wire,n,decoded,sizeof(decoded),m,seq) && seq==0xffff);
    assert(m==sizeof(eth) && memcmp(decoded,eth,m)==0);
    // Exact RFC1042 envelopes at every supported IPv6 length. The format
    // observation comes from MtkWireless's iOS 27 capture; no parser imported.
    uint8_t wrapped[DataCodec::maximumReceiveFrame] {};
    for (size_t ipLength=40; ipLength<=DataCodec::mtu; ++ipLength) {
        eth[18]=uint8_t((ipLength-40)>>8); eth[19]=uint8_t(ipLength-40);
        assert(DataCodec::encode(eth,14+ipLength,wire,sizeof(wire),1,77,n));
        memcpy(wrapped,wire,26);
        const uint8_t envelope[6]={0xaa,0xaa,3,0,0,0};
        memcpy(wrapped+26,envelope,6);
        wrapped[32]=uint8_t((n-26)>>8); wrapped[33]=uint8_t(n-26);
        memcpy(wrapped+34,wire+26,n-26);
        assert(DataCodec::decode(wrapped,n+8,decoded,sizeof(decoded),m,seq));
        assert(m==14+ipLength && seq==77 && !memcmp(decoded,eth,m));
        wrapped[33]^=1;
        assert(!DataCodec::decode(wrapped,n+8,decoded,sizeof(decoded),m,seq));
        wrapped[33]^=1;
        for (size_t cut=26;cut<42;++cut)
            assert(!DataCodec::decode(wrapped,cut,decoded,sizeof(decoded),m,seq));
        // Envelope is restricted to QoS; do not discover signatures by scanning.
        wrapped[0]=0x08;
        assert(!DataCodec::decode(wrapped,n+8,decoded,sizeof(decoded),m,seq));
    }
    // Mixed plain/wrapped aggregate. Reject malformed tails before exposing
    // any prefix, including a source-spoofed second MSDU.
    eth[18]=eth[19]=0;
    assert(DataCodec::encode(eth,54,wire,sizeof(wire),1,42,n));
    uint8_t aggregate[256]{};
    memcpy(aggregate,wire,26); aggregate[24]=0x80;
    size_t end=26;
    for (unsigned sub=0;sub<2;++sub) {
        memcpy(aggregate+end,eth,12);
        size_t body=56+(sub ? 8:0);
        aggregate[end+12]=uint8_t(body>>8); aggregate[end+13]=uint8_t(body);
        size_t at=end+14;
        if(sub) {
            const uint8_t prefix[8]={0xaa,0xaa,3,0,0,0,0,56};
            memcpy(aggregate+at,prefix,8); at+=8;
        }
        memcpy(aggregate+at,wire+26,56);
        end+=14+body;
        if(!sub) end+=(4-((14+body)&3))&3;
    }
    DataCodec::View views[2]{}; size_t count=99;
    assert(DataCodec::inspectAggregate(aggregate,end,views,2,count) && count==2);
    assert(views[0].sequence==42 && views[1].sequence==42);
    assert(views[0].payloadLength==40 && views[1].payloadLength==40);
    assert(!DataCodec::inspectAggregate(aggregate,end,views,1,count) && count==0);
    views[0]={};
    aggregate[end-1]^=1; // IPv6 payload length mismatch needs a header edit.
    aggregate[end-40+5]=1;
    assert(!DataCodec::inspectAggregate(aggregate,end,views,2,count) && count==0);
    assert(views[0].payload==nullptr);
    aggregate[end-40+5]=0; aggregate[end-1]^=1;
    const size_t second=26+72;
    aggregate[second+6]^=2;
    assert(!DataCodec::inspectAggregate(aggregate,end,views,2,count) && count==0);
    aggregate[second+6]^=2;
    assert(!DataCodec::inspectAggregate(aggregate,end+1,views,2,count) && count==0);
    // Deterministic malformed input stress under address/undefined sanitizers.
    uint32_t r=0x7823;
    for (unsigned iteration=0;iteration<20000;++iteration) {
        for (auto &b:wire) {r=r*1664525+1013904223; b=uint8_t(r>>24);}
        DataCodec::decode(wire,r%sizeof(wire),decoded,sizeof(decoded),m,seq);
    }
    puts("PASS: AWDL IPv6 data framing, bounds and malformed frames");
}
