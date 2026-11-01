/* SPDX-License-Identifier: GPL-2.0-only
 * Native role-6 request flow informed by MtkWireless Wi-Fi 98d9442076939dd3.
 * This file is compiled only by the native Tahoe controller translation unit.
 */
#include "AirportRTWAwdlBackend.hpp"
#include <sys/errno.h>
extern "C" const char *rtw_awdl_interface_name(void *)
    __asm__("__ZN23IO80211SkywalkInterface10getBSDNameEv");
bool AirportRTW::nativeAwdlAvailable() const
{
    auto *hal=OSDynamicCast(RTWCore,fHalService);
    const uint32_t required=RTWAwdl::FrameTransport|RTWAwdl::ManualVisits|
        RTWAwdl::PeerStations|RTWAwdl::QuiescentRemoval;
    return nativeAwdlEnabled_ && !__atomic_load_n(&nativeAwdlShutdown_,__ATOMIC_ACQUIRE) && !__atomic_load_n(&nativeAwdlStopping_,__ATOMIC_ACQUIRE) &&
        hal && (hal->awdlHardwareSupport()&required)==required;
}
IOReturn AirportRTW::createNativeAwdl(apple80211_virt_if_create_data *request)
{
    if(!request || request->version>APPLE80211_VERSION)return kIOReturnBadArgument;
    if(request->role!=6 || !nativeAwdlAvailable())return kIOReturnUnsupported;
    if(!nativeAwdlLock_ || !IOLockTryLock(nativeAwdlLock_))return kIOReturnBusy;
    IOReturn result=kIOReturnNotReady;
    setProperty("RTWAwdlCreateStage","requested");
    if(nativeAwdlInterface_)result=EEXIST;
    else if(nativeAwdlAvailable() && fNetIf && bsdInterface &&
            RTWAwdl::Election::unicast(request->mac)) {
        // The native factory can otherwise wait for IOBSD indefinitely.
        auto *matching=IOService::resourceMatching("IOBSD");
        auto *bsd=matching ? IOService::copyMatchingService(matching) : nullptr;
        OSSafeReleaseNULL(matching);
        auto *hal=OSDynamicCast(RTWCore,fHalService);
        if(bsd && hal) {
            auto *backend=new AirportRTWAwdl::NativeBackend(*hal);
            auto *runtime=AirportRTWAwdl::Runtime::withOwnedBackend(backend);
            if(!runtime){delete backend;result=kIOReturnNoMemory;}
            else {
                setProperty("RTWAwdlCreateStage","initializing");
                auto *interface=AirportRTWAwdlInterface::withController(this,runtime,request->mac);
                if(interface){nativeAwdlInterface_=interface;nativeAwdlRuntime_=runtime;result=kIOReturnSuccess;}
                else {runtime->shutdown();runtime->releaseProvider();result=kIOReturnNotReady;}
            }
        }
        OSSafeReleaseNULL(bsd);
    } else if(!RTWAwdl::Election::unicast(request->mac))result=kIOReturnBadArgument;
    if(result==kIOReturnSuccess || result==EEXIST) {
        const char *name=rtw_awdl_interface_name(nativeAwdlInterface_);
        memset(request->bsd_name,0,sizeof(request->bsd_name));
        if(name)strlcpy(reinterpret_cast<char *>(request->bsd_name),name,sizeof(request->bsd_name));
    }
    setProperty("RTWAwdlCreateStage",nativeAwdlInterface_ ? "registered" : "not-ready");
    setProperty("RTWAwdlCreateStatus",uint64_t(uint32_t(result)),32);
    setProperty("RTWAwdlInterfaceReady",nativeAwdlInterface_!=nullptr);
    IOLockUnlock(nativeAwdlLock_);return result;
}
IO80211VirtualInterface *AirportRTW::createVirtualInterface(ether_addr *address,unsigned int role)
{
    if(!address || role!=6)return nullptr;
    apple80211_virt_if_create_data request{};request.version=APPLE80211_VERSION;request.role=role;
    memcpy(request.mac,address,6);
    const IOReturn result=createNativeAwdl(&request);
    return result==kIOReturnSuccess || result==EEXIST ? nativeAwdlInterface_ : nullptr;
}
SInt32 AirportRTW::enableVirtualInterface(IO80211VirtualInterface *interface)
{
    auto *native=OSDynamicCast(AirportRTWAwdlInterface,interface);
    return native && native==nativeAwdlInterface_ ? native->enable(0) : kIOReturnUnsupported;
}
SInt32 AirportRTW::disableVirtualInterface(IO80211VirtualInterface *interface)
{
    auto *native=OSDynamicCast(AirportRTWAwdlInterface,interface);
    return native && native==nativeAwdlInterface_ ? native->disable(0) : kIOReturnUnsupported;
}
void AirportRTW::stopNativeAwdl()
{
    if(!nativeAwdlLock_)return;
    IOLockLock(nativeAwdlLock_);
    while(nativeAwdlStopping_) {
        if(nativeAwdlStopThread_==current_thread()){IOLockUnlock(nativeAwdlLock_);return;}
        IOLockSleep(nativeAwdlLock_,&nativeAwdlStopping_,THREAD_UNINT);
    }
    __atomic_store_n(&nativeAwdlStopping_,true,__ATOMIC_RELEASE);
    nativeAwdlStopThread_=current_thread();
    auto *interface=nativeAwdlInterface_;auto *runtime=nativeAwdlRuntime_;
    nativeAwdlInterface_=nullptr;nativeAwdlRuntime_=nullptr;
    IOLockUnlock(nativeAwdlLock_);
    // Never hold the controller lifecycle lock while entering the native gate.
    if(interface){interface->terminate(kIOServiceRequired|kIOServiceSynchronous);interface->release();}
    if(runtime){runtime->shutdown();runtime->releaseProvider();}
    setProperty("RTWAwdlInterfaceReady",false);
    IOLockLock(nativeAwdlLock_);nativeAwdlStopThread_=nullptr;
    __atomic_store_n(&nativeAwdlStopping_,false,__ATOMIC_RELEASE);
    IOLockWakeup(nativeAwdlLock_,&nativeAwdlStopping_,false);IOLockUnlock(nativeAwdlLock_);
}
