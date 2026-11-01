#!/usr/bin/env python3
"""Exercise production Tahoe creation/publication/owned-provider teardown."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
ns={'__file__':str(ROOT/'tests/rtw_awdl_backend_test.py')}
script=(ROOT/'tests/rtw_awdl_backend_test.py').read_text()
exec(compile(script.split("source+=r'''",1)[0],str(ROOT/'tests/rtw_awdl_backend_test.py'),'exec'),ns)
source=ns['source']
source=source.replace('struct IOService:OSObject{','''struct IOService:OSObject{
    static OSObject*resourceMatching(const char*){return new OSObject;}
    static IOService*copyMatchingService(OSObject*){return new IOService;}
''')
source+=r'''
#include <condition_variable>
#include <cerrno>
struct IOLock {std::mutex mutex;std::condition_variable condition;};
static IOLock *IOLockAlloc(){return new IOLock;}
static void IOLockFree(IOLock*p){delete p;}
static void IOLockLock(IOLock*p){p->mutex.lock();}
static void IOLockUnlock(IOLock*p){p->mutex.unlock();}
static bool IOLockTryLock(IOLock*p){return p->mutex.try_lock();}
static void IOLockSleep(IOLock*p,void*,int){std::unique_lock<std::mutex> lock(p->mutex,std::adopt_lock);p->condition.wait(lock);lock.release();}
static void IOLockWakeup(IOLock*p,void*,bool){p->condition.notify_all();}
#define THREAD_UNINT 0
#define OSSafeReleaseNULL(p) do{if(p){p->release();p=nullptr;}}while(0)
using SInt32=int;using thread_t=void*;
static thread_t current_thread(){return reinterpret_cast<void*>(std::hash<std::thread::id>{}(std::this_thread::get_id())|1);}
struct apple80211_virt_if_create_data {uint32_t version;uint8_t mac[6];uint32_t role;char bsd_name[16];};
struct AirportRTW:IO80211Controller {
 RTWCore *fHalService;void*fNetIf=this,*bsdInterface=this;
 IOLock*nativeAwdlLock_=IOLockAlloc();AirportRTWAwdlInterface*nativeAwdlInterface_=nullptr;
 AirportRTWAwdl::Runtime*nativeAwdlRuntime_=nullptr;
 bool nativeAwdlEnabled_=true,nativeAwdlShutdown_=false,nativeAwdlStopping_=false;
 thread_t nativeAwdlStopThread_=nullptr;
 explicit AirportRTW(RTWCore &hal):fHalService(&hal){}
 ~AirportRTW(){IOLockFree(nativeAwdlLock_);}
 template<class...Args>void setProperty(Args...){}
 bool nativeAwdlAvailable()const;
 IOReturn createNativeAwdl(apple80211_virt_if_create_data*);
 IO80211VirtualInterface*createVirtualInterface(ether_addr*,unsigned);
 SInt32 enableVirtualInterface(IO80211VirtualInterface*);
 SInt32 disableVirtualInterface(IO80211VirtualInterface*);
 void stopNativeAwdl();
};
'''
source+=ns['strip']((ROOT/'AirportRTW/WCL/AirportRTWAwdlController.cpp.inc').read_text())
source+=r'''
int main(){
 RTWCore hal;auto*controller=new AirportRTW(hal);
 apple80211_virt_if_create_data request{};request.version=1;request.role=6;
 const uint8_t mac[6]={2,1,2,3,4,5};memcpy(request.mac,mac,6);
 assert(!controller->nativeAwdlAvailable());assert(controller->createNativeAwdl(&request)==kIOReturnUnsupported);
 hal.support=15;assert(controller->nativeAwdlAvailable());
 assert(!controller->createNativeAwdl(&request));assert(!strcmp(request.bsd_name,"awdl0"));
 auto*interface=controller->nativeAwdlInterface_;assert(interface && hal.adds==1);
 assert(controller->createNativeAwdl(&request)==EEXIST && hal.adds==1);
 assert(!controller->enableVirtualInterface(interface));assert(hal.receiver);
 assert(!controller->disableVirtualInterface(interface));assert(!hal.receiver);
 controller->stopNativeAwdl();assert(!controller->current && !controller->nativeAwdlRuntime_ && hal.closes==1);
 // Recreate after Wi-Fi power cycle; a native completion can re-enter teardown.
 assert(!controller->createNativeAwdl(&request));interface=controller->nativeAwdlInterface_;
 assert(!controller->enableVirtualInterface(interface));
 static AirportRTW*owner;owner=controller;
 eventHook=[](OSObject*,unsigned event){if(event==51)owner->stopNativeAwdl();};
 uint8_t cache[0x1d0]{};cache[0]=1;cache[8]=2;cache[13]=9;
 (void)interface->setPEER_CACHE_CONTROL(reinterpret_cast<apple80211_peer_cache_control*>(cache));
 eventHook=nullptr;assert(!controller->current && hal.closes==2);
 controller->nativeAwdlShutdown_=true;
 assert(!controller->nativeAwdlAvailable());assert(controller->createNativeAwdl(&request)==kIOReturnUnsupported);
 controller->release();assert(objects==0);
 puts("PASS: opt-in and HAL gate, real native registration, duplicate recovery, recreation and reentrant provider lifetime");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-controller-')as tmp:
    cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(source)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function',
        '-DAIRPORT_WCL','-D__MAC_26_0=260000','-D__IO80211_TARGET=260000','-fsanitize=address,undefined',
        '-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
