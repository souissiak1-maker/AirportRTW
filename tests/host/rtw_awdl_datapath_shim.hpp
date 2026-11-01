// Native packet transport host adapters; no Apple kernel objects are loaded.
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <atomic>
using IOReturn=int;using IOInterruptState=unsigned;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnError=1,kIOReturnNoMemory=2,kIOReturnNotReady=3;
static unsigned objects=0, allocations=0, faultAt=0, attempts=0;
static bool failNow() {return ++attempts==faultAt;}
struct OSObject {
    unsigned refs=1;
    OSObject(){++objects;}virtual ~OSObject(){--objects;}
    virtual bool init(){return true;}
    virtual void free(){delete this;}
    void retain(){++refs;}void release(){assert(refs);if(!--refs)free();}
};
#define OSDeclareDefaultStructors(C) public:C()=default;~C() override=default;
#define OSDefineMetaClassAndStructors(C,B)
#define OSSafeReleaseNULL(p) do{if(p){(p)->release();(p)=nullptr;}}while(0)
struct IOSimpleLock {std::mutex mutex;};
static IOSimpleLock *IOSimpleLockAlloc(){return failNow()?nullptr:new IOSimpleLock;}
static void IOSimpleLockFree(IOSimpleLock*p){delete p;}
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock*p){p->mutex.lock();return 0;}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock*p,IOInterruptState){p->mutex.unlock();}
static void *IOMalloc(size_t n){if(failNow())return nullptr;++allocations;return malloc(n);}
static void IOFree(void*p,size_t){assert(allocations);--allocations;free(p);}
struct IOService;
struct IOEventSource:OSObject {
    OSObject*owner;bool active=false;
    explicit IOEventSource(OSObject*o):owner(o){o->retain();}
    ~IOEventSource()override{owner->release();}
    void enable(){active=true;}void disable(){active=false;}
};
struct IOInterruptEventSource:IOEventSource {
    using Action=void(*)(OSObject*,IOInterruptEventSource*,int);
    Action action;bool signaled=false;
    IOInterruptEventSource(OSObject*o,Action a):IOEventSource(o),action(a){}
    static IOInterruptEventSource*interruptEventSource(OSObject*o,Action a){return failNow()?nullptr:new IOInterruptEventSource(o,a);}
    void interruptOccurred(void*,IOService*,int){signaled=true;}
};
struct IOWorkLoop:OSObject {
    std::recursive_mutex gate;std::vector<IOEventSource*>sources;unsigned failAdd=0,adds=0;
    using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
    IOReturn runAction(Action f,OSObject*o,void*a=nullptr,void*b=nullptr,void*c=nullptr,void*d=nullptr){std::lock_guard<std::recursive_mutex>lock(gate);return f(o,a,b,c,d);}
    IOReturn addEventSource(IOEventSource*s){if(++adds==failAdd)return kIOReturnError;s->retain();sources.push_back(s);return 0;}
    void removeEventSource(IOEventSource*s){auto i=std::find(sources.begin(),sources.end(),s);assert(i!=sources.end());sources.erase(i);s->release();}
    bool pumping=false;
    void pump(){std::lock_guard<std::recursive_mutex>lock(gate);auto snapshot=sources;
        for(auto*s:snapshot)s->retain();pumping=true;
        for(auto*s:snapshot)if(auto*i=dynamic_cast<IOInterruptEventSource*>(s))if(i->active&&i->signaled){i->signaled=false;i->action(i->owner,i,1);}
        pumping=false;for(auto*s:snapshot)s->release();}
};
struct FakePool:OSObject {
    OSObject*owner;unsigned packets=0;
    explicit FakePool(OSObject*o):owner(o){o->retain();}
    ~FakePool()override{assert(!packets);owner->release();}
};
struct FakePacket {FakePool*pool;uint8_t bytes[2048]{};uint32_t length=0;uint16_t offset=64;uint8_t header=0;};
struct FakeQueue:IOEventSource {
    using TxAction=uint32_t(*)(OSObject*,void*,void*const*,uint32_t,void*);
    TxAction action;
    explicit FakeQueue(OSObject*o,TxAction a=nullptr):IOEventSource(o),action(a){}
};
static bool allocationFails=false,prepareFails=false,lengthFails=false,enqueueFails=false;
static unsigned packets=0,delivered=0,requests=0;
static std::vector<uint8_t>lastReceived;

static bool senderReady=false,txCompletionFails=false;
static unsigned sent=0,txCompleted=0;
