// SPDX-License-Identifier: GPL-2.0-only
#include <AWDL/RTWAwdlSync.hpp>
#include <AWDL/RTWAwdlObserver.hpp>
#include <cassert>
#include <cstdio>
#include <vector>
using namespace RTWAwdl;
static void put16(uint8_t *p,unsigned n) {p[0]=uint8_t(n);p[1]=uint8_t(n>>8);}
static void put32(uint8_t *p,uint32_t n) {put16(p,n);put16(p+2,n>>16);}
static void tlv(std::vector<uint8_t> &body,uint8_t kind,const std::vector<uint8_t> &data) {
    body.push_back(kind);body.push_back(uint8_t(data.size()));body.push_back(uint8_t(data.size()>>8));
    body.insert(body.end(),data.begin(),data.end());
}
static std::vector<uint8_t> sequence(unsigned encoding=3) {
    unsigned width=encoding==0?1:2;
    std::vector<uint8_t> s(6+16*width);s[0]=15;s[1]=encoding;s[3]=3;put16(s.data()+4,65535);
    for(unsigned i=0;i<16;++i) {
        unsigned base=6+i*width;
        s[base+(encoding==1?1:0)]=i<8?149:6;
        if(width==2) s[base+(encoding==1?0:1)]=i<8?128:81;
    }
    return s;
}
static std::vector<uint8_t> fixed() {
    std::vector<uint8_t> s(33);s[0]=149;s[3]=6;s[4]=3;
    put16(s.data()+1,32);put16(s.data()+5,16);put16(s.data()+7,100);
    put16(s.data()+13,16);put16(s.data()+15,8);
    s[21]=2;s[26]=1;s[27]=4;put16(s.data()+29,65535);put16(s.data()+31,0xaabb);
    return s;
}
static std::vector<uint8_t> envelope() {
    std::vector<uint8_t> b(16);uint8_t h[]={127,0,0x17,0xf2,8,0x10,3};
    for(unsigned i=0;i<7;++i)b[i]=h[i];
    put32(b.data()+8,0x12345678);put32(b.data()+12,0x87654321);return b;
}
int main() {
    for(unsigned encoding : {0U,1U,3U}) {
        auto bytes=sequence(encoding);ChannelSequence s;
        assert(decodeChannelSequence(bytes.data(),bytes.size(),s)==SyncDecode::Valid);
        assert(s.count==16 && s.stride==4 && s.channel[0]==149 && s.channel[8]==6);
        if(encoding!=0)assert(s.auxiliary[0]==128);
        for(size_t n=0;n<bytes.size();++n)
            assert(decodeChannelSequence(bytes.data(),n,s)==SyncDecode::Malformed);
        bytes[6+(encoding==1?1:0)]=255;
        assert(decodeChannelSequence(bytes.data(),bytes.size(),s)==SyncDecode::Unsupported);
        assert(!s.count);
    }
    auto seq=sequence(),sync=fixed(),body=envelope();
    sync.insert(sync.end(),seq.begin(),seq.end());sync.resize(sync.size()+2);
    tlv(body,4,sync);tlv(body,18,seq);
    std::vector<uint8_t> election(40);election[0]=election[6]=2;election[5]=election[11]=1;
    put32(election.data()+12,100);put32(election.data()+16,1);put32(election.data()+20,900);
    put32(election.data()+24,800);put32(election.data()+36,77);
    tlv(body,24,election);tlv(body,21,{0x34,1});
    SyncMessage decoded;
    assert(decodeSyncAction(body.data(),body.size(),decoded)==SyncDecode::Valid);
    assert(decoded.counter==65535 && decoded.apAlignment==0xaabb && decoded.periodTu==16);
    assert(decoded.phyTxTime==0x12345678 && decoded.targetTxTime==0x87654321);
    assert(decoded.electionPresent && decoded.masterCounter==100 && decoded.selfCounter==77);
    assert(decoded.masterMetric==900 && decoded.selfMetric==800 && decoded.height==1);
    assert(decoded.versionPresent && decoded.version==0x34 && decoded.deviceClass==1);
#ifdef RTW_REFERENCE_CHECK
    RTW88AWDL::Action reference;
    assert(RTW88AWDL::parseAction(body.data(),body.size(),reference));
    assert(reference.awCounter==decoded.counter && reference.awPeriod==decoded.periodTu);
    assert(reference.presence==decoded.presence && reference.sequence.stride==decoded.sequence.stride);
    for(unsigned i=0;i<16;++i) assert(reference.sequence.channel[i]==decoded.sequence.channel[i]);
#endif
    std::vector<uint8_t> radio(24);radio[0]=0xd0;radio.insert(radio.end(),body.begin(),body.end());
    Observer observer;observer.observe(radio.data(),radio.size(),2437);
    assert(observer.syncDecoded==1 && observer.syncDecodeFailures==0);
    radio[29]=0x20;observer.observe(radio.data(),radio.size(),2437);
    assert(observer.syncDecoded==1 && observer.syncDecodeFailures==1);
    auto invalid=body;invalid[5]=0x20;
    assert(decodeSyncAction(invalid.data(),invalid.size(),decoded)==SyncDecode::Unsupported);
    auto duplicate=body;tlv(duplicate,4,sync);
    assert(decodeSyncAction(duplicate.data(),duplicate.size(),decoded)==SyncDecode::Malformed);
    duplicate=body;tlv(duplicate,21,{1,1});
    assert(decodeSyncAction(duplicate.data(),duplicate.size(),decoded)==SyncDecode::Malformed);
    duplicate=body;tlv(duplicate,24,election);
    assert(decodeSyncAction(duplicate.data(),duplicate.size(),decoded)==SyncDecode::Malformed);
    auto conflicting=envelope();auto other=seq;other[6]=44;
    tlv(conflicting,4,sync);tlv(conflicting,18,other);
    assert(decodeSyncAction(conflicting.data(),conflicting.size(),decoded)==SyncDecode::Malformed);
    auto noEmbedded=envelope();tlv(noEmbedded,4,fixed());tlv(noEmbedded,18,seq);
    assert(decodeSyncAction(noEmbedded.data(),noEmbedded.size(),decoded)==SyncDecode::Valid);
    auto onlyEmbedded=envelope();tlv(onlyEmbedded,4,sync);
    assert(decodeSyncAction(onlyEmbedded.data(),onlyEmbedded.size(),decoded)==SyncDecode::Valid);
    auto noSequence=envelope();tlv(noSequence,4,fixed());
    assert(decodeSyncAction(noSequence.data(),noSequence.size(),decoded)==SyncDecode::Unsupported);
    auto wrongMaster=envelope();tlv(wrongMaster,4,sync);election[5]=3;tlv(wrongMaster,24,election);
    assert(decodeSyncAction(wrongMaster.data(),wrongMaster.size(),decoded)==SyncDecode::Malformed);
    for(unsigned presence : {0U,3U,17U}) {
        auto bad=sync;bad[27]=presence;auto msg=envelope();tlv(msg,4,bad);
        assert(decodeSyncAction(msg.data(),msg.size(),decoded)==SyncDecode::Malformed);
    }
    for(size_t n=0;n<body.size();++n) {
        ActionInfo info;
        if(parseAction(body.data(),n,info)==ParseResult::Malformed)
            assert(decodeSyncAction(body.data(),n,decoded)!=SyncDecode::Valid);
    }
    uint32_t random=17;
    for(unsigned trial=0;trial<20000;++trial) {
        random=random*1664525+1013904223;std::vector<uint8_t> fuzz(random%512);
        for(auto &byte:fuzz) {random=random*1664525+1013904223;byte=uint8_t(random>>24);}
        if(trial & 1) {
            fuzz=body;
            for(unsigned edit=0;edit<4;++edit) {
                random=random*1664525+1013904223;
                size_t offset=random%fuzz.size();
                random=random*1664525+1013904223;fuzz[offset]^=uint8_t(random>>24);
            }
        }
        decodeSyncAction(fuzz.data(),fuzz.size(),decoded);
        ChannelSequence sequenceView;decodeChannelSequence(fuzz.data(),fuzz.size(),sequenceView);
    }
    puts("PASS: AWDL sync/channel/election decoding, owned fields and malformed inputs");
}
