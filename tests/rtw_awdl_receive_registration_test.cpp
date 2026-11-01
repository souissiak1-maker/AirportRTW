/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <cassert>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
using IOLock=std::mutex;
static bool failLock;
static unsigned lockEntries;
static IOLock *IOLockAlloc() { return failLock?nullptr:new IOLock; }
static void IOLockFree(IOLock *p) { delete p; }
static void IOLockLock(IOLock *p) { p->lock(); ++lockEntries; }
static void IOLockUnlock(IOLock *p) { p->unlock(); }
class OSObject {
public:
    std::atomic<unsigned> refs{1};
    IOLock *destructionLock=nullptr;
    bool destroyed=false;
    void retain() { assert(refs.fetch_add(1)); }
    void release() {
        unsigned old=refs.fetch_sub(1); assert(old);
        if(old==1) {
            if(destructionLock) {
                assert(destructionLock->try_lock()); destructionLock->unlock();
            }
            destroyed=true;
        }
    }
};
#include <AWDL/RTWAwdlReceiveRegistration.hpp>
struct Sink : OSObject {
    std::vector<uint8_t> frame;
    RTWAwdl::ReceiveMetadata metadata={};
    unsigned calls=0;
    std::atomic<bool> entered{false},resume{true};
};
static void receive(OSObject *p,const uint8_t *bytes,size_t length,
                    const RTWAwdl::ReceiveMetadata &metadata) {
    auto *sink=static_cast<Sink *>(p);
    assert(sink->refs.load()>=2);
    sink->entered.store(true);
    while(!sink->resume.load()) std::this_thread::yield();
    sink->frame.assign(bytes,bytes+length); sink->metadata=metadata; ++sink->calls;
}
int main() {
    using namespace RTWAwdl;
    ReceiveRegistration registration={};
    uint8_t mac[]={2,1,2,3,4,5},peer[]={2,1,2,3,4,6};
    Sink sink,other;
    failLock=true; assert(!initializeReceiver(registration)); failLock=false;
    assert(initializeReceiver(registration)); assert(!initializeReceiver(registration));
    assert(!bindReceiver(registration,&sink,receive) && sink.refs.load()==1);
    assert(openReceiver(registration,mac)); assert(!openReceiver(registration,mac));
    assert(!bindReceiver(registration,&sink,nullptr));
    assert(bindReceiver(registration,&sink,receive) && sink.refs.load()==2);
    uint8_t frame[40]={0xd0}; memcpy(frame+4,mac,6); memcpy(frame+10,peer,6);
    const uint8_t bssid[]={0,0x25,0,0xff,0x94,0x73}; memcpy(frame+16,bssid,6);
    const uint8_t body[]={127,0,0x17,0xf2,8,0x10,0}; memcpy(frame+24,body,7);
    auto dispatch=[&]{return dispatchReceiver(registration,frame,sizeof(frame),-41,2437,0,true);};
    assert(dispatch()); assert(sink.calls==1 && sink.metadata.kind==FrameKind::Action);
    assert(sink.metadata.radioTimestamp==0 && sink.metadata.radioTimestampValid);
    assert(sink.metadata.rssi==-41 && sink.metadata.frequency==2437);
    frame[25]=1; assert(sink.frame[25]==0); assert(!dispatch()); frame[25]=0;
    for(unsigned at : {4U,16U}) { frame[at]^=2; assert(!dispatch()); frame[at]^=2; }
    memcpy(frame+10,mac,6); assert(!dispatch()); memcpy(frame+10,peer,6);
    frame[10]|=1; assert(!dispatch()); frame[10]&=~1;
    frame[1]=0x40; assert(!dispatch()); frame[1]=0;
    frame[30]=7; assert(!dispatch()); frame[30]=0;
    for(size_t n=0;n<40;++n) assert(!dispatchReceiver(registration,frame,n,0,0,0,false));
    // Decode-free IPv6 classification uses the same validation as decapsulation.
    uint8_t ethernet[54]={}; memcpy(ethernet,mac,6); memcpy(ethernet+6,peer,6);
    ethernet[12]=0x86;ethernet[13]=0xdd;ethernet[14]=0x60;
    uint8_t data[100]={};size_t written=0;
    assert(DataCodec::encode(ethernet,sizeof(ethernet),data,sizeof(data),1,2,written));
    assert(dispatchReceiver(registration,data,written,-50,5180,123,false));
    assert(sink.metadata.kind==FrameKind::IPv6 && !sink.metadata.radioTimestampValid);
    data[26]=0; assert(!dispatchReceiver(registration,data,written,0,5180,0,false));
    std::vector<uint8_t> largeEthernet(14+DataCodec::mtu),largeWire(DataCodec::maximumFrame);
    memcpy(largeEthernet.data(),mac,6);memcpy(largeEthernet.data()+6,peer,6);
    largeEthernet[12]=0x86;largeEthernet[13]=0xdd;largeEthernet[14]=0x60;
    largeEthernet[18]=uint8_t((DataCodec::mtu-40)>>8);largeEthernet[19]=uint8_t(DataCodec::mtu-40);
    assert(DataCodec::encode(largeEthernet.data(),largeEthernet.size(),largeWire.data(),largeWire.size(),1,2,written));
    std::vector<uint8_t> aggregate(largeWire.begin(),largeWire.begin()+26);aggregate[24]=0x80;
    for(unsigned j=0;j<4;++j){
     aggregate.insert(aggregate.end(),largeWire.begin()+4,largeWire.begin()+16);
     size_t body=largeWire.size()-26;aggregate.push_back(uint8_t(body>>8));aggregate.push_back(uint8_t(body));
     aggregate.insert(aggregate.end(),largeWire.begin()+26,largeWire.end());
     if(j<3){aggregate.push_back(0);aggregate.push_back(0);}
    }
    assert(aggregate.size()>4120&&DataCodec::validAggregate(aggregate.data(),aggregate.size()));
    assert(dispatchReceiver(registration,aggregate.data(),aggregate.size(),-50,5180,123,false));
    assert(sink.metadata.kind==FrameKind::IPv6&&sink.frame.size()==aggregate.size());
    aggregate.back()^=1; // legal payload data, then break the final body's IPv6 version
    size_t lastSub=26+3*(14+largeWire.size()-26+2);
    aggregate[lastSub+14+16]^=0x10;
    unsigned before=sink.calls;
    assert(!dispatchReceiver(registration,aggregate.data(),aggregate.size(),-50,5180,123,false)&&sink.calls==before);
    assert(bindReceiver(registration,&other,receive));
    assert(sink.refs.load()==1 && other.refs.load()==2);
    assert(bindReceiver(registration,nullptr,nullptr)); assert(other.refs.load()==1);
    assert(!dispatch());
    assert(bindReceiver(registration,&sink,receive));
    sink.entered.store(false);sink.resume.store(false);
    std::thread reader([&]{assert(dispatch());});
    while(!sink.entered.load()) std::this_thread::yield();
    std::atomic<bool> closeStarted{false},closed{false};
    std::thread closer([&]{closeStarted.store(true);closeReceiver(registration);closed.store(true);});
    while(!closeStarted.load()) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!closed.load() && sink.refs.load()==2);
    sink.resume.store(true); reader.join();closer.join();
    assert(closed.load() && sink.refs.load()==1);
    unsigned locks=lockEntries;
    assert(!dispatch()); assert(locks==lockEntries); // Disabled fast path avoids RX lock.
    assert(!bindReceiver(registration,&sink,receive));
    assert(openReceiver(registration,mac));
    Sink finalOwner; finalOwner.destructionLock=registration.lock;
    assert(bindReceiver(registration,&finalOwner,receive)); finalOwner.release();
    closeReceiver(registration); assert(finalOwner.destroyed);
    destroyReceiver(registration); destroyReceiver(registration);
    assert(!registration.lock && !registration.owner);
}
