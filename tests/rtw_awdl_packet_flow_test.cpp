/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlPacketFlow.hpp>
#include <assert.h>
#include <vector>
#include <stdio.h>
using namespace RTWAwdl;
struct Packet {uint8_t bytes[14] {};bool valid=true;unsigned completed=0,released=0;};
struct Adapter {
    bool active=true, completionFailure=false;
    unsigned budget=1000,sent=0,invalidCount=0;
    std::vector<unsigned> batches;
    std::vector<uint8_t> copies;
    bool enabled() {return active;}
    bool view(void *raw,const uint8_t *&data,size_t &length) {
        auto *p=static_cast<Packet*>(raw);data=p->bytes;length=14;return p->valid;
    }
    bool send(const uint8_t *data,size_t length) {
        assert(length==14);
        if(sent==budget) return false;
        ++sent;copies.push_back(data[0]);return true;
    }
    void invalid() {++invalidCount;}
    bool complete(void *const *packets,uint32_t count) {
        assert(count>0 && count<=64);batches.push_back(count);
        if(completionFailure) return false;
        for(unsigned i=0;i<count;++i) ++static_cast<Packet*>(packets[i])->completed;
        return true;
    }
    void release(void *p) {++static_cast<Packet*>(p)->released;}
};
int main() {
    Packet storage[130];void *packets[130];
    for(unsigned i=0;i<130;++i) {storage[i].bytes[0]=uint8_t(i);packets[i]=&storage[i];}
    Adapter disabled;disabled.active=false;
    assert(PacketFlow::transmit(disabled,packets,130)==0 && disabled.batches.empty());
    Adapter full;
    assert(PacketFlow::transmit(full,packets,130)==130);
    assert((full.batches==std::vector<unsigned>{64,64,2}));
    for(auto &p:storage) {assert(p.completed==1 && p.released==0);p.completed=0;}
    Adapter busy;busy.budget=5;
    assert(PacketFlow::transmit(busy,packets,10)==5 && busy.sent==5);
    for(unsigned i=0;i<10;++i) assert(storage[i].completed==(i<5));
    busy.budget=10;
    assert(PacketFlow::transmit(busy,packets+5,5)==5);
    for(unsigned i=0;i<10;++i) {assert(storage[i].completed==1);storage[i].completed=0;}
    Adapter failure;failure.completionFailure=true;
    assert(PacketFlow::transmit(failure,packets,10)==10);
    for(unsigned i=0;i<10;++i) {assert(storage[i].released==1 && storage[i].completed==0);storage[i].released=0;}
    Adapter malformed;storage[0].valid=false;packets[1]=nullptr;
    assert(PacketFlow::transmit(malformed,packets,3)==3);
    assert(malformed.invalidCount==2 && malformed.sent==1);
    assert(storage[0].completed==1 && storage[1].completed==0 && storage[2].completed==1);
    assert(!PacketFlow::validView(0,1,2048,0,14));
    assert(!PacketFlow::validView(2,1,2048,0,14));
    assert(!PacketFlow::validView(1,0,2048,0,14));
    assert(!PacketFlow::validView(1,1,100,101,14));
    assert(!PacketFlow::validView(1,1,100,90,14));
    assert(!PacketFlow::validView(1,UINT64_MAX,2048,1,14));
    assert(!PacketFlow::validView(1,UINT64_MAX-10,2048,0,14));
    assert(!PacketFlow::validView(1,1,2048,0,13));
    assert(!PacketFlow::validView(1,1,2048,0,1443));
    assert(PacketFlow::validView(1,1,2048,64,1442));
    assert(PacketFlow::transmit(full,nullptr,1)==0);
    puts("PASS: native TX completion ownership, backpressure, bounds and failed completion");
}
