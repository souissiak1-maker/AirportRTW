#include <HAL/RTWAwdlReceive.hpp>
#ifndef OSDynamicCast
#define OSDynamicCast(T,p) dynamic_cast<T*>(p)
#endif
#ifndef APPLE80211_VERSION
#define APPLE80211_VERSION 1
#endif
constexpr unsigned APPLE80211_C_FLAG_20MHZ=1,APPLE80211_C_FLAG_2GHZ=2,APPLE80211_C_FLAG_5GHZ=4;
// IOKit/family lifecycle adapters; real ABI layout is checked by the kernel build.
#include <cassert>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <vector>
#include <algorithm>
using IOReturn=int;using UInt=unsigned;using UInt64=uint64_t;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnError=2,kIOReturnBadArgument=3;
enum {kIOReturnBusy=4,kIOReturnUnsupported=5,kIOReturnNoMemory=6,kIOReturnNoResources=7};
constexpr unsigned kIOServiceRequired=1,kIOServiceSynchronous=2;
struct ether_addr{uint8_t octet[6];};
struct apple80211_channel{uint32_t version,channel,flags;};
enum IO80211LinkState{Down=1,Up=2};enum apple80211_wme_ac:unsigned int;
static uint64_t nativeHostUs=1000000;
static uint64_t mach_absolute_time(){return nativeHostUs*1000;}
static void absolutetime_to_nanoseconds(uint64_t ticks,uint64_t*ns){*ns=ticks;}
static unsigned objects=0,baseStarts=0,baseStops=0,services=0,addressUpdates=0;
static unsigned failAt=0;
using IORecursiveLock=std::recursive_mutex;
static unsigned controlLocks=0;
static IORecursiveLock*IORecursiveLockAlloc(){if(failAt==15)return nullptr;++controlLocks;return new IORecursiveLock;}
static void IORecursiveLockFree(IORecursiveLock*p){assert(controlLocks);--controlLocks;delete p;}
static void IORecursiveLockLock(IORecursiveLock*p){p->lock();}
static void IORecursiveLockUnlock(IORecursiveLock*p){p->unlock();}

class OSObject{public:
    std::atomic<unsigned> refs{1};OSObject(){++objects;}virtual~OSObject(){--objects;}
    virtual bool init(){return true;}virtual void free(){delete this;}
    void retain(){++refs;}void release(){assert(refs);if(!--refs)free();}
};
#define OSDeclareDefaultStructors(C) public:C()=default;~C()override=default;
#define OSDefineMetaClassAndStructors(C,B)
struct IOService:OSObject{
    IOService*parent=nullptr;
    virtual bool start(IOService*){return true;}virtual void stop(IOService*){}
    virtual bool attach(IOService*p){if(failAt==3)return false;parent=p;p->retain();return true;}
    virtual void detach(IOService*p){assert(parent==p);parent=nullptr;p->release();}
    void registerService(unsigned){++services;}
    bool terminate(unsigned){auto*p=parent;stop(p);if(parent)detach(p);return true;}
};
struct IOTimerEventSource;
struct IOWorkLoop:OSObject{
    std::vector<IOTimerEventSource*>timers;
    IOReturn addEventSource(IOTimerEventSource*);
    void removeEventSource(IOTimerEventSource*);
    std::recursive_mutex gate;
    using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
    IOReturn runAction(Action action,OSObject*owner,void*a=nullptr){std::lock_guard<std::recursive_mutex>lock(gate);return action(owner,a,nullptr,nullptr,nullptr);}
};
struct IOTimerEventSource:OSObject{
    using Action=void(*)(OSObject*,IOTimerEventSource*);
    OSObject*owner;Action action;bool armed=false;uint32_t delay=0;
    static IOTimerEventSource*last;
    IOTimerEventSource(OSObject*o,Action a):owner(o),action(a){owner->retain();last=this;}
    ~IOTimerEventSource()override{last=nullptr;owner->release();}
    static IOTimerEventSource*timerEventSource(OSObject*o,Action a){return failAt==12?nullptr:new IOTimerEventSource(o,a);}
    IOReturn setTimeoutUS(uint32_t us){if(failAt==14)return kIOReturnError;delay=us;armed=true;return 0;}
    void cancelTimeout(){armed=false;}
    void fire(){if(!armed)return;retain();auto*o=owner;o->retain();armed=false;action(o,this);o->release();release();}
};
IOTimerEventSource*IOTimerEventSource::last=nullptr;
IOReturn IOWorkLoop::addEventSource(IOTimerEventSource*t){if(failAt==13)return kIOReturnError;t->retain();timers.push_back(t);return 0;}
void IOWorkLoop::removeEventSource(IOTimerEventSource*t){
    auto i=std::find(timers.begin(),timers.end(),t);assert(i!=timers.end());timers.erase(i);t->release();}
struct PostedEvent{unsigned id;std::vector<uint8_t>bytes;};
static std::vector<PostedEvent>messages;
static void(*eventHook)(OSObject*,unsigned)=nullptr;
#define APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START 41
#define APPLE80211_M_AWDL_AVAILABILITY_WINDOW_EXTENSIONS_END 43
struct IO80211VirtualInterface;
struct IO80211Controller:IOService{IO80211VirtualInterface*current=nullptr;};
struct IOSkywalkEthernetInterface{struct RegistrationInfo{uint8_t bytes[0x130];};};
constexpr unsigned IFCAP_HWCSUM=3,IFCAP_TSO=0x60,IFCAP_LRO=0x80,IFCAP_CSUM_PARTIAL=0x2000,IFCAP_CSUM_ZERO_INVERT=0x4000;
struct __ifnet {unsigned offload=0xffff,supported=0xffff,enabled=0xffff;};
static int ifnet_set_offload(__ifnet*p,unsigned value){if(failAt==17)return 1;p->offload=value;return 0;}
static int ifnet_set_capabilities_enabled(__ifnet*p,unsigned value,unsigned mask){if(failAt!=18)p->enabled=(p->enabled&~mask)|(value&mask);return 0;}
static int ifnet_set_capabilities_supported(__ifnet*p,unsigned value,unsigned mask){if(failAt==19)return 1;p->supported=(p->supported&~mask)|(value&mask);return 0;}
static unsigned ifnet_offload(__ifnet*p){return p->offload;}
static unsigned ifnet_capabilities_supported(__ifnet*p){return p->supported;}
static unsigned ifnet_capabilities_enabled(__ifnet*p){return p->enabled;}
struct IO80211SkywalkInterface:IOService{
    IOWorkLoop*baseLoop=nullptr;unsigned link=0,assists=0xffff;bool deferred=false;
    virtual UInt getHardwareAssists(){return assists;}
    virtual void setHardwareAssists(unsigned value,unsigned mask){assists=(assists&~mask)|(value&mask);}
    virtual IOReturn prepareBSDInterface(__ifnet*,unsigned){return failAt==16?kIOReturnError:0;}
    void deferBSDAttach(bool value){deferred=value;}
    OSObject*getProperty(const char*name){assert(!strcmp(name,"IODeferBSDAttach"));return deferred?this:nullptr;}
    bool init()override{if(failAt==1)return false;baseLoop=new IOWorkLoop;return true;}
    void free()override{if(baseLoop)baseLoop->release();assert(!parent);OSObject::free();}
    virtual IOReturn enable(unsigned){return 0;}virtual IOReturn disable(unsigned){return 0;}
    virtual uintptr_t setMacAddress(ether_addr&)=0;
    virtual IOReturn getHardwareAddress(ether_addr*){return 0;}
    ether_addr nativeAddress{};
    IOReturn setHardwareAddress(ether_addr*p){if(failAt==20)return kIOReturnError;
        auto result=setMacAddress(*p);if(!result)nativeAddress=*p;return IOReturn(result);}
    ether_addr getSelfMacAddr(){auto result=nativeAddress;if(failAt==21)result.octet[5]^=1;return result;}

    virtual const char*getBSDNamePrefix(){return "en";}virtual UInt getMaxTransferUnit(){return 1500;}
    virtual bool isChipInterfaceReady(){return false;}
    virtual void*getTxSubQueue(apple80211_wme_ac){return nullptr;}
    virtual void*getTxCompQueue(){return nullptr;}virtual void*getRxCompQueue(){return nullptr;}
    virtual void*getTxPacketPool(){return nullptr;}virtual void*getRxPacketPool(){return nullptr;}
    virtual int getNumTxQueues(){return 0;}virtual int getTxHeadroom(){return 0;}
    virtual UInt64 getRxQueueCapacity(){return 0;}
    virtual void enableDatapath(){}virtual void disableDatapath(){}
    virtual void postMessage(unsigned id,void*p,unsigned long n,bool wcl){
        assert(wcl);messages.push_back({id,std::vector<uint8_t>((uint8_t*)p,(uint8_t*)p+n)});
        if(eventHook)eventHook(this,id);}
    void setLinkLayerAddress(ether_addr*){++addressUpdates;}
    bool initRegistrationInfo(IOSkywalkEthernetInterface::RegistrationInfo*p,unsigned version,size_t n){assert(version==1&&n==0x130);memset(p,0,n);return failAt!=8;}
    void setInterfaceId(unsigned id){assert(id==2);}
};
static void(*virtualInitHook)(OSObject*)=nullptr;
struct IO80211VirtualInterface:IO80211SkywalkInterface{
    using IO80211SkywalkInterface::init;
    bool init(IO80211Controller*,ether_addr*,unsigned role,const char*name){assert(role==6&&!strcmp(name,"awdl"));if(virtualInitHook)virtualInitHook(this);return failAt!=2;}
    bool start(IOService*)override{++baseStarts;assert(isChipInterfaceReady() && deferred);return failAt!=5;}
    void stop(IOService*)override{++baseStops;if(baseLoop){baseLoop->release();baseLoop=nullptr;}}
    void free()override{IO80211SkywalkInterface::free();}
    uintptr_t setLinkState(IO80211LinkState state,unsigned flags){assert(flags==1);link=state;return 0;}
};
struct AirportRTWAwdlDatapath:OSObject{
    using Sender=bool(*)(OSObject*,const uint8_t*,size_t);
    using ActionReceiver=bool(*)(OSObject*,const uint8_t*,size_t,const uint8_t*,size_t);
    ActionReceiver dataReceiver=nullptr;std::vector<uint8_t>dataBytes,dataMetadata;
    ActionReceiver actionReceiver=nullptr;std::vector<uint8_t>actionBytes,actionMetadata;
    IOWorkLoop*loop;OSObject*owner;Sender sender;bool active=false;unsigned stops=0;
    static AirportRTWAwdlDatapath*last;
    AirportRTWAwdlDatapath(IOWorkLoop*l,OSObject*o,Sender s,ActionReceiver a,ActionReceiver d):dataReceiver(d),actionReceiver(a),loop(l),owner(o),sender(s){l->retain();last=this;}
    ~AirportRTWAwdlDatapath()override{loop->release();last=nullptr;}
    static AirportRTWAwdlDatapath*withWorkLoop(IOWorkLoop*l,OSObject*o,Sender s,ActionReceiver a=nullptr,ActionReceiver d=nullptr){return failAt==7?nullptr:new AirportRTWAwdlDatapath(l,o,s,a,d);}
    bool setEnabled(bool value){active=value;return true;}void stop(){active=false;++stops;}
    unsigned received=0;std::vector<uint8_t>ethernetBytes;
    bool receive(const uint8_t*p,size_t n){if(!active||!p)return false;++received;ethernetBytes.assign(p,p+n);return true;}void resumeTransmit(){}
    bool queueAction(const uint8_t*p,size_t n,const uint8_t*m,size_t z){
        if(!active||!actionReceiver)return false;actionBytes.assign(p,p+n);actionMetadata.assign(m,m+z);return true;}
    bool queueData(const uint8_t*p,size_t n,const uint8_t*m,size_t z){
        if(!active||!dataReceiver)return false;dataBytes.assign(p,p+n);dataMetadata.assign(m,m+z);return true;}
    bool pumpData(){assert(dataReceiver);return dataReceiver(owner,dataBytes.data(),dataBytes.size(),dataMetadata.data(),dataMetadata.size());}
    void pumpAction(){assert(actionReceiver);actionReceiver(owner,actionBytes.data(),actionBytes.size(),actionMetadata.data(),actionMetadata.size());}

    void*txSubmission(){return this;}void*txCompletion(){return this;}void*rxCompletion(){return this;}
    void*txPool(){return this;}void*rxPool(){return this;}
};
AirportRTWAwdlDatapath*AirportRTWAwdlDatapath::last=nullptr;
namespace AirportRTWAwdlActionInput{
static unsigned inputs=0;
static bool deliver(IO80211VirtualInterface*,const uint8_t*,size_t,const uint8_t*,size_t){++inputs;return true;}
}
