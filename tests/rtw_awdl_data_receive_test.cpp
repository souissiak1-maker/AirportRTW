/* SPDX-License-Identifier: GPL-2.0-only */
#include <AWDL/RTWAwdlDataReceive.hpp>
#include <AWDL/RTWAwdlDataReplay.hpp>
#include <cassert>
#include <cstring>
#include <vector>
#include <cstdio>
using namespace RTWAwdl;
static const uint8_t local[6]={2,1,2,3,4,5},remote[6]={2,1,2,3,4,6};
struct Peers {
 bool live=true;DataReplayWindow windows[17];
 bool authorized(const uint8_t*p)const{return live&&!memcmp(p,remote,6);}
 bool acceptData(const uint8_t*p,unsigned stream,uint16_t seq,uint64_t now){return authorized(p)&&stream<17&&windows[stream].accept(seq,now);}
};
static std::vector<uint8_t> wire(uint16_t sequence){
 uint8_t eth[54]={};memcpy(eth,local,6);memcpy(eth+6,remote,6);
 eth[12]=0x86;eth[13]=0xdd;eth[14]=0x60;eth[20]=59;eth[38]=0xfe;eth[39]=0x80;eth[53]=1;
 std::vector<uint8_t> out(82);size_t n=0;assert(DataCodec::encode(eth,sizeof(eth),out.data(),out.size(),0,sequence,n));return out;
}
static std::vector<uint8_t> aggregate(unsigned count){
 auto first=wire(1);std::vector<uint8_t> out(first.begin(),first.begin()+26);out[24]=0x80;
 for(unsigned i=0;i<count;++i){auto w=wire(uint16_t(i+1));
  out.insert(out.end(),w.begin()+4,w.begin()+16);out.push_back(0);out.push_back(56);
  out.insert(out.end(),w.begin()+26,w.end());
  if(i+1<count){out.push_back(0);out.push_back(0);}
 }
 return out;
}
int main(){
 {DataReplayWindow w;assert(w.accept(100,1));assert(!w.accept(100,2));assert(w.accept(99,3));
  assert(!w.accept(99,4));assert(w.accept(164,5));assert(!w.accept(100,6));
  assert(w.accept(0,3000007));assert(!w.accept(0,3000008));}
 {DataReplayWindow w;assert(w.accept(4094,1));assert(w.accept(4095,2));assert(w.accept(0,3));
  assert(w.sequenceBits==12&&w.accept(1,4)&&!w.accept(4095,5));
  assert(w.accept(4096,6)&&w.sequenceBits==16);}
 {DataReplayWindow w;assert(w.accept(65535,1));assert(w.accept(0,2));assert(w.sequenceBits==16&&!w.accept(65535,3));}
 {DataReceive engine;Peers peers;unsigned calls=0;auto f=wire(7);
  auto sink=[&](const uint8_t*b,size_t n){assert(n==54&&!memcmp(b,local,6)&&!memcmp(b+6,remote,6));++calls;return true;};
  assert(engine.deliver(f.data(),f.size(),local,100,peers,sink)==1);
  assert(engine.deliver(f.data(),f.size(),local,101,peers,sink)==0&&calls==1);
  f[24]=1;assert(engine.deliver(f.data(),f.size(),local,102,peers,sink)==1&&calls==2);
  peers.live=false;f=wire(8);assert(!engine.deliver(f.data(),f.size(),local,103,peers,sink));}
 {DataReceive engine;Peers peers;auto f=aggregate(2);unsigned calls=0;
  auto sink=[&](const uint8_t*,size_t){++calls;return true;};
  assert(DataCodec::validAggregate(f.data(),f.size()));
  // A malformed tail and a wrong subframe destination must not deliver a
  // prefix or advance its duplicate state.
  auto bad=f;bad[128]=0x50;assert(!engine.deliver(bad.data(),bad.size(),local,1,peers,sink)&&!calls);
  bad=f;bad[98+5]^=1;assert(!engine.deliver(bad.data(),bad.size(),local,2,peers,sink)&&!calls);
  assert(engine.deliver(f.data(),f.size(),local,3,peers,sink)==2&&calls==2);
  assert(!engine.deliver(f.data(),f.size(),local,4,peers,sink));}
 {DataReceive engine;Peers peers;auto f=aggregate(2);unsigned calls=0;
  assert(engine.deliver(f.data(),f.size(),local,1,peers,[&](const uint8_t*,size_t){++calls;peers.live=false;return true;})==1&&calls==1);}
 {DataReceive engine;Peers peers;auto f=aggregate(2);unsigned calls=0;
  auto inner=wire(99);
  assert(engine.deliver(f.data(),f.size(),local,1,peers,[&](const uint8_t*,size_t){
    ++calls;engine.reset();
    assert(!engine.deliver(inner.data(),inner.size(),local,2,peers,[](const uint8_t*,size_t){assert(false);return true;}));
    return true;
  })==1&&calls==1);
  assert(engine.deliver(inner.data(),inner.size(),local,3,peers,[](const uint8_t*,size_t){return true;})==1);}
 {DataReceive engine;Peers peers;auto f=aggregate(32);
  assert(engine.deliver(f.data(),f.size(),local,1,peers,[](const uint8_t*,size_t){return true;})==32);
  f=aggregate(33);assert(!DataCodec::validAggregate(f.data(),f.size()));}
 puts("PASS: native RX codec admission, per-TID duplicate windows, rollover, aggregate atomicity and reentrant reset");
}
