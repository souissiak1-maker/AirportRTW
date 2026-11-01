/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Native role-6 registration research: RTL8814Native (DrogaBox, GPL-2.0).
 */
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include "AirportRTWAwdlInterface.hpp"
#include "AirportRTWAwdlActionInput.hpp"
#include "AirportRTWAwdlRuntime.hpp"
#include "AirportRTWAwdlBackend.hpp"
#include <net/ethernet.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <Airport/apple80211_var.h>
#include <AWDL/RTWAwdlNativeRxMetadata.hpp>
#include <AWDL/RTWAwdlNativeEvents.hpp>
#include <kern/clock.h>
#include <mach/mach_time.h>

extern "C" {
IOWorkLoop *rtw_awdl_interface_workloop(void *)
    __asm__("__ZN23IO80211SkywalkInterface12getWorkQueueEv");
const char *rtw_awdl_interface_name(void *)
    __asm__("__ZN23IO80211SkywalkInterface10getBSDNameEv");
IO80211VirtualInterface *rtw_awdl_controller_interface(IO80211Controller *)
    __asm__("__ZN17IO80211Controller16getAwdlInterfaceEv");
void rtw_awdl_controller_publish(IO80211Controller *, IO80211VirtualInterface *)
    __asm__("__ZN17IO80211Controller16setAwdlInterfaceEP23IO80211VirtualInterface");
IOReturn rtw_awdl_register_interface(void *, const void *, void **, uint32_t, void *, void *, uint32_t)
    __asm__("__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEPP20IOSkywalkPacketQueuejP25IOSkywalkPacketBufferPoolS7_j");
}

OSDefineMetaClassAndStructors(AirportRTWAwdlInterface, IO80211AWDLProtocol)

AirportRTWAwdlInterface *AirportRTWAwdlInterface::withController(IO80211Controller *controller,
    AirportRTWAwdl::Control *control, const uint8_t mac[6],CreationResult *result)
{
    if(result)*result={"invalid-factory-arguments",kIOReturnBadArgument};
    if(!controller || !control || !mac)return nullptr;
    if(result)*result={"provider-readiness",kIOReturnNotReady};
    if(!control->ready())return nullptr;
    if(result)*result={"provider-capabilities",kIOReturnUnsupported};
    if((control->capabilities()&AirportRTWAwdl::Control::requiredCapabilities)!=AirportRTWAwdl::Control::requiredCapabilities)return nullptr;
    if(result)*result={"existing-native-interface",kIOReturnBusy};
    if(rtw_awdl_controller_interface(controller))return nullptr;
    if(result)*result={"invalid-mac",kIOReturnBadArgument};
    uint8_t bits = 0; for (unsigned i = 0; i < 6; ++i) bits |= mac[i];
    if (!bits || (mac[0] & 1)) return nullptr;
    if(result)*result={"interface-allocation",kIOReturnNoMemory};
    auto *object = new AirportRTWAwdlInterface;
    if (!object) return nullptr;
    object->creation_=result;
    if (!object->initialize(controller,control,mac) || !object->start(controller) || !object->publish()) {
        object->creation_=nullptr; // preserve the failure across shutdown
        if (object->servicePublished_) {
            object->terminate(kIOServiceRequired | kIOServiceSynchronous);
        } else {
            object->stop(controller);
            if (object->attached_) { object->detach(controller); object->attached_ = false; }
        }
        object->release(); return nullptr;
    }
    object->creation_=nullptr;
    return object;
}

bool AirportRTWAwdlInterface::initialize(IO80211Controller *controller,
    AirportRTWAwdl::Control *control, const uint8_t *mac)
{
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= mac[i];
    if (!bits || (mac[0] & 1)) return false;
    controller_ = controller; control_ = control;control_->retainProvider();providerHeld_=true;memcpy(mac_,mac,6);
    creationStage("skywalk-init");
    if (!IO80211SkywalkInterface::init()) return false;
    creationStage("control-lock",kIOReturnNoMemory);
    controlLock_=IORecursiveLockAlloc();
    if (!controlLock_) return false;
    // Native base initialization can query AWDL limits and election state.
    // Bind validated state before that call; prepare must not use its workqueue.
    prepareAttempted_ = true;
    creationStage("runtime-prepare",kIOReturnNotReady);
    const IOReturn preparation=control_->prepare(this,mac_);
    if(preparation!=kIOReturnSuccess){creationStage("runtime-prepare",preparation);return false;}
    prepared_ = true;
    ether_addr address; memcpy(address.octet,mac_,6);
    virtualInitAttempted_ = true;
    creationStage("virtual-init");
    if (!IO80211VirtualInterface::init(controller,&address,6,"awdl")) return false;
    setInterfaceId(2);
    creationStage("provider-attach");
    attached_ = attach(controller);
    return attached_;
}

bool AirportRTWAwdlInterface::start(IOService *provider)
{
    creationStage("start-state",kIOReturnNotReady);
    if (stopping_ || baseStarted_ || !prepared_ || !control_) return false;
    // Native base start can publish the service before queues are registered.
    creationStage("bsd-deferral",kIOReturnNoMemory);
    deferBSDAttach(true);
    if (!getProperty("IODeferBSDAttach")) return false;
    creationStage("virtual-start");
    if (!IO80211VirtualInterface::start(provider)) return false;
    baseStarted_ = true;
    // Populate the native MAC agent as well as our HAL's address. Its setter
    // calls setMacAddress; an unchanged address is an idempotent transaction.
    ether_addr nativeAddress;memcpy(nativeAddress.octet,mac_,6);
    creationStage("native-mac-set");
    const IOReturn macStatus=IO80211SkywalkInterface::setHardwareAddress(&nativeAddress);
    if(macStatus!=kIOReturnSuccess){creationStage("native-mac-set",macStatus);return false;}
    creationStage("native-mac-readback");
    const ether_addr reported=IO80211SkywalkInterface::getSelfMacAddr();
    if(memcmp(reported.octet,mac_,6))return false;
    creationStage("native-workqueue",kIOReturnNotReady);
    loop_ = rtw_awdl_interface_workloop(this);
    if (!loop_) return false;
    creationStage("datapath-allocation",kIOReturnNoMemory);
    datapath_ = AirportRTWAwdlDatapath::withWorkLoop(loop_,this,transmit,deliverAction,deliverData);
    if (!datapath_) return false;
    creationStage("registration-info");
    if (!initRegistrationInfo(reinterpret_cast<IOSkywalkEthernetInterface::RegistrationInfo *>(registration_),1,sizeof(registration_)))
        return false;
    // Native role-6 RegistrationInfo, kept alive for the service's lifetime.
    const uint32_t wifiSubfamily = 3, role = 6, mediaCount = 2, medium = 0x80, zero = 0;
    const uint32_t mtu = RTWAwdl::DataCodec::mtu;
    const uint16_t headroom = 64;
    const char *prefix = "awdl";
    memcpy(registration_+0x0c,&wifiSubfamily,4); memcpy(registration_+0x10,&role,4);
    memcpy(registration_+0x14,&mediaCount,4); memcpy(registration_+0x24,&medium,4);
    memcpy(registration_+0x28,&medium,4); memcpy(registration_+0x30,&prefix,sizeof(prefix));
    memcpy(registration_+0x38,&zero,4); memcpy(registration_+0x3c,&headroom,2);
    memcpy(registration_+0x40,&zero,4); memcpy(registration_+0x48,&mtu,4);
    memcpy(registration_+0x4c,&mtu,4); memcpy(registration_+0x108,mac_,6);
    void *queues[3] {datapath_->txSubmission(),datapath_->txCompletion(),datapath_->rxCompletion()};
    creationStage("queue-registration");
    const IOReturn registration=rtw_awdl_register_interface(this,registration_,queues,3,datapath_->txPool(),datapath_->rxPool(),0);
    if(registration!=kIOReturnSuccess){creationStage("queue-registration",registration);return false;}
    registered_ = true;
    return true;
}

bool AirportRTWAwdlInterface::publish()
{
    creationStage("controller-publication",kIOReturnBusy);
    if (!registered_) return false;
    auto *current=rtw_awdl_controller_interface(controller_);
    if(current && current!=this)return false;
    // The native initializer may already have installed this same object.
    if(!current)rtw_awdl_controller_publish(controller_,this);
    controllerPublished_ = rtw_awdl_controller_interface(controller_) == this;
    if (!controllerPublished_) return false;
    // Controller ownership and native queue registration precede BSD matching.
    deferBSDAttach(false);
    servicePublished_ = true;
    registerService(kIOServiceSynchronous);
    creationStage("bsd-name",kIOReturnNotReady);
    const char *name = rtw_awdl_interface_name(this);
    if(!name || strncmp(name,"awdl",4))return false;
    creationStage("registered",kIOReturnSuccess);return true;
}

void AirportRTWAwdlInterface::setHardwareAssists(unsigned int,unsigned int)
{
    // Raw AWDL transport neither segments TCP nor completes partial checksums.
    IO80211AWDLProtocol::setHardwareAssists(0,~0u);
}

IOReturn AirportRTWAwdlInterface::prepareBSDInterface(struct __ifnet *interface,unsigned int options)
{
    if (!interface) return kIOReturnBadArgument;
    setHardwareAssists(0,~0u);
    const IOReturn result=IO80211AWDLProtocol::prepareBSDInterface(interface,options);
    if (result!=kIOReturnSuccess) return result;
    // On Tahoe, setting zero offloads alone can leave enabled capability bits.
    // Preserve unrelated capabilities, then verify both advertised masks.
    const unsigned mask=IFCAP_HWCSUM|IFCAP_TSO|IFCAP_LRO|IFCAP_CSUM_PARTIAL|IFCAP_CSUM_ZERO_INVERT;
    int error=ifnet_set_offload(interface,0);
    if (!error) error=ifnet_set_capabilities_enabled(interface,0,mask);
    if (!error) error=ifnet_set_capabilities_supported(interface,0,mask);
    if (error || ifnet_offload(interface) ||
        ((ifnet_capabilities_supported(interface)|ifnet_capabilities_enabled(interface))&mask))
        return kIOReturnError;
    return kIOReturnSuccess;
}

IOReturn AirportRTWAwdlInterface::enableImpl(unsigned int)
{
    if (stopping_ || !registered_ || !prepared_ || !control_ || !datapath_ || !isChipInterfaceReady())
        return kIOReturnNotReady;
    if (enabled_) return kIOReturnSuccess;
    const IOReturn result = control_->enable(true);
    if (result != kIOReturnSuccess) { cancelWindowTimer(); return result; }
    if (!datapath_->setEnabled(true)) { cancelWindowTimer(); control_->enable(false); return kIOReturnError; }
    enabled_ = true;
    setLinkState(static_cast<IO80211LinkState>(2),1);
    return kIOReturnSuccess;
}

IOReturn AirportRTWAwdlInterface::disableImpl(unsigned int)
{
    enabled_ = false;
    cancelWindowTimer();
    if (baseStarted_) setLinkState(static_cast<IO80211LinkState>(1),1);
    if (datapath_) datapath_->setEnabled(false);
    return prepared_ && control_ ? control_->enable(false) : kIOReturnSuccess;
}

void AirportRTWAwdlInterface::stop(IOService *provider)
{
    (void)gatedAction(stopGated,provider);
}

IOReturn AirportRTWAwdlInterface::stopGated(OSObject *owner, void *provider, void *, void *, void *)
{
    static_cast<AirportRTWAwdlInterface *>(owner)->stopImpl(static_cast<IOService *>(provider));
    return kIOReturnSuccess;
}

void AirportRTWAwdlInterface::stopImpl(IOService *provider)
{
    if (stopping_) return;
    stopping_ = true;
    disable(0);
    if (prepareAttempted_ && control_) { control_->shutdown(); prepareAttempted_ = false; prepared_ = false; }
    releaseWindowTimer();
    windowOpen_ = false;
    if (datapath_) datapath_->stop();
    // Also retract publication done by a partially successful native init.
    if(controller_ && rtw_awdl_controller_interface(controller_)==this)
        rtw_awdl_controller_publish(controller_,nullptr);
    controllerPublished_=false;
    if (baseStarted_) { IO80211VirtualInterface::stop(provider); baseStarted_ = false; }
    registered_=false;
    if(controlLock_)IORecursiveLockLock(controlLock_);
    loop_=nullptr;
    if(controlLock_)IORecursiveLockUnlock(controlLock_);
}

void AirportRTWAwdlInterface::free()
{
    releaseWindowTimer();
    if (datapath_) { datapath_->stop(); datapath_->release(); datapath_ = nullptr; }
    if(controlLock_){auto *lock=controlLock_;controlLock_=nullptr;IORecursiveLockFree(lock);}
    auto *provider=providerHeld_ ? control_ : nullptr;
    providerHeld_=false;
    if (virtualInitAttempted_) IO80211VirtualInterface::free();
    else IO80211SkywalkInterface::free();
    // Only locals after base free: host adapters and OSObject may delete this.
    if(provider)provider->releaseProvider();
}

IOReturn AirportRTWAwdlInterface::gatedAction(NativeAction action,void *context)
{
    // Pin the workloop while holding the lifecycle lock, before stop can clear
    // it and release the native base. Never wait on its gate with this lock held.
    retain();
    auto *lock=controlLock_;
    if(lock)IORecursiveLockLock(lock);
    auto *loop=loop_;
    if (!loop) {
        const IOReturn result=action(this,context,nullptr,nullptr,nullptr);
        if(lock)IORecursiveLockUnlock(lock);
        release();return result;
    }
    loop->retain();
    if(lock)IORecursiveLockUnlock(lock);
    const IOReturn result=loop->runAction(action,this,context);
    release();loop->release();return result;
}

IOReturn AirportRTWAwdlInterface::dispatch(AirportRTWAwdl::Request request,bool set,void *payload)
{
    if (!payload) return kIOReturnBadArgument;
    ControlRequest context {request,set,payload};
    return gatedAction(dispatchGated,&context);
}

IOReturn AirportRTWAwdlInterface::dispatchGated(OSObject *owner,void *request,void *,void *,void *)
{
    auto *me=static_cast<AirportRTWAwdlInterface *>(owner);
    const auto &context=*static_cast<ControlRequest *>(request);
    if (!me->control_ || !me->prepared_ || me->stopping_) return kIOReturnNotReady;
    return me->control_->request(context.request,context.set,context.payload);
}

IOReturn AirportRTWAwdlInterface::enable(unsigned int flags)
{
    ToggleRequest context {true,flags};return gatedAction(toggleGated,&context);
}

IOReturn AirportRTWAwdlInterface::disable(unsigned int flags)
{
    ToggleRequest context {false,flags};return gatedAction(toggleGated,&context);
}

IOReturn AirportRTWAwdlInterface::toggleGated(OSObject *owner,void *request,void *,void *,void *)
{
    auto *me=static_cast<AirportRTWAwdlInterface *>(owner);
    const auto &context=*static_cast<ToggleRequest *>(request);
    return context.enable ? me->enableImpl(context.flags) : me->disableImpl(context.flags);
}

uintptr_t AirportRTWAwdlInterface::setMacAddress(ether_addr &address)
{
    AddressRequest context {&address,static_cast<uint32_t>(kIOReturnNotReady)};
    const IOReturn result=gatedAction(addressGated,&context);
    return result==kIOReturnSuccess ? context.result : static_cast<uint32_t>(result);
}

IOReturn AirportRTWAwdlInterface::addressGated(OSObject *owner,void *request,void *,void *,void *)
{
    auto &context=*static_cast<AddressRequest *>(request);
    context.result=static_cast<AirportRTWAwdlInterface *>(owner)->setMacAddressImpl(*context.address);
    return kIOReturnSuccess;
}

uintptr_t AirportRTWAwdlInterface::setMacAddressImpl(ether_addr &address)
{
    uint8_t bits = 0; for (unsigned i = 0; i < 6; ++i) bits |= address.octet[i];
    if (!bits || (address.octet[0] & 1)) return static_cast<uint32_t>(kIOReturnBadArgument);
    if (!memcmp(mac_,address.octet,6)) return kIOReturnSuccess;
    if (!control_ || !prepared_ || stopping_) return static_cast<uint32_t>(kIOReturnNotReady);
    const IOReturn result = control_->setAddress(address.octet);
    if (result == kIOReturnSuccess) {
        memcpy(mac_,address.octet,6);
        if (registered_) setLinkLayerAddress(&address);
    }
    return static_cast<uint32_t>(result);
}

IOReturn AirportRTWAwdlInterface::getHardwareAddress(ether_addr *address)
{
    if (!address) return kIOReturnBadArgument;
    memcpy(address->octet,mac_,6); return kIOReturnSuccess;
}

bool AirportRTWAwdlInterface::isChipInterfaceReady()
{
    return control_ && prepared_ && !stopping_ && control_->ready() &&
        (control_->capabilities() & AirportRTWAwdl::Control::requiredCapabilities) == AirportRTWAwdl::Control::requiredCapabilities;
}

void *AirportRTWAwdlInterface::getTxSubQueue(apple80211_wme_ac) { return datapath_ ? datapath_->txSubmission() : nullptr; }
void *AirportRTWAwdlInterface::getTxCompQueue() { return datapath_ ? datapath_->txCompletion() : nullptr; }
void *AirportRTWAwdlInterface::getRxCompQueue() { return datapath_ ? datapath_->rxCompletion() : nullptr; }
void *AirportRTWAwdlInterface::getTxPacketPool() { return datapath_ ? datapath_->txPool() : nullptr; }
void *AirportRTWAwdlInterface::getRxPacketPool() { return datapath_ ? datapath_->rxPool() : nullptr; }
void AirportRTWAwdlInterface::enableDatapath() { if (datapath_) datapath_->setEnabled(enabled_); }
void AirportRTWAwdlInterface::disableDatapath() { if (datapath_) datapath_->setEnabled(false); }
bool AirportRTWAwdlInterface::transmit(OSObject *owner, const uint8_t *bytes, size_t length)
{
    auto *me = static_cast<AirportRTWAwdlInterface *>(owner);
    return me->enabled_ && !me->stopping_ && me->control_->transmitEthernet(bytes,length);
}

bool AirportRTWAwdlInterface::receiveEthernet(const uint8_t *bytes, size_t length) { return datapath_ && datapath_->receive(bytes,length); }
void AirportRTWAwdlInterface::resumeTransmit() { if (datapath_) datapath_->resumeTransmit(); }
bool AirportRTWAwdlInterface::queueAction(const uint8_t *frame, size_t length,
                                         const uint8_t *metadata, size_t metadataLength)
{
    return datapath_ && datapath_->queueAction(frame,length,metadata,metadataLength);
}

bool AirportRTWAwdlInterface::queueRadioAction(const uint8_t *frame, size_t length,
                                              const apple80211_channel &channel,
                                              int32_t rssi, uint32_t wireRxTime,
                                              bool wireRxTimeValid)
{
    static_assert(sizeof(apple80211_channel) == RTWAwdl::NativeRxMetadata::channelSize,
                  "native action channel descriptor layout");
    if (!frame || length < 24) return false;
    uint8_t metadata[RTWAwdl::NativeRxMetadata::size];
    if (!RTWAwdl::NativeRxMetadata::build(frame + 10,
            reinterpret_cast<const uint8_t *>(&channel), sizeof(channel), rssi,
            metadata, sizeof(metadata), wireRxTime, wireRxTimeValid)) return false;
    return queueAction(frame,length,metadata,sizeof(metadata));
}

namespace AirportRTWAwdl {
uint64_t runtimeNowUs() {
    uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);return ns/1000;
}
bool deliverRuntimeEthernet(IO80211VirtualInterface *interface,const uint8_t *bytes,size_t length) {
    auto *native=OSDynamicCast(AirportRTWAwdlInterface,interface);
    return native && native->receiveEthernet(bytes,length);
}
}

bool AirportRTWAwdlInterface::queueRadioData(const uint8_t *frame,size_t length,
    const apple80211_channel &channel,int32_t rssi,uint32_t wireRxTime)
{
    if(!frame || length<24 || !datapath_)return false;
    uint8_t metadata[RTWAwdl::NativeRxMetadata::size];
    if(!RTWAwdl::NativeRxMetadata::build(frame+10,reinterpret_cast<const uint8_t *>(&channel),
        sizeof(channel),rssi,metadata,sizeof(metadata),wireRxTime,true))return false;
    return datapath_->queueData(frame,length,metadata,sizeof(metadata));
}

void AirportRTWAwdlInterface::receiveRadio(OSObject *owner,const uint8_t *frame,size_t length,
                                           const RTWAwdl::ReceiveMetadata &metadata)
{
    auto *me=static_cast<AirportRTWAwdlInterface *>(owner);
    // Frequency-to-channel conversion only; RX does not grant TX permission.
    const uint16_t f=metadata.frequency;
    const uint8_t number=f>=2412 && f<=2472 && (f-2407)%5==0 ? uint8_t((f-2407)/5) :
        f>=5180 && f<=5885 && f%5==0 ? uint8_t((f-5000)/5) : 0;
    if(!number)return;
    apple80211_channel channel{};channel.version=APPLE80211_VERSION;channel.channel=number;
    channel.flags=APPLE80211_C_FLAG_20MHZ |
        (number<=13 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ);
    const uint32_t wire=uint32_t(AirportRTWAwdl::runtimeNowUs());
    // No HAL calls, blocking gate, family calls or raw TSF casts on NAPI.
    if(metadata.kind==RTWAwdl::FrameKind::Action)
        me->queueRadioAction(frame,length,channel,metadata.rssi,wire,true);
    else me->queueRadioData(frame,length,channel,metadata.rssi,wire);
}


bool AirportRTWAwdlInterface::postWindowStart(uint16_t counter,uint32_t role,
    const uint8_t parent[6],const uint8_t root[6],const apple80211_channel &channel,uint32_t wireTime)
{
    static_assert(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START==RTWAwdl::NativeEvents::startEvent,
                  "native AWDL start event ID");
    if (!enabled_ || stopping_ || !registered_ || windowOpen_) return false;
    uint8_t payload[RTWAwdl::NativeEvents::startSize];
    if (!RTWAwdl::NativeEvents::start(counter,role,parent,root,
            reinterpret_cast<const uint8_t *>(&channel),sizeof(channel),wireTime,payload,sizeof(payload)))
        return false;
    // Publish state before synchronous/reentrant native dispatch.
    windowOpen_=true;
    retain();
    postMessage(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START,payload,sizeof(payload),true);
    release();
    return true;
}

bool AirportRTWAwdlInterface::postWindowEnd(uint32_t wireTime)
{
    static_assert(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_EXTENSIONS_END==RTWAwdl::NativeEvents::endEvent,
                  "native AWDL end event ID");
    // Disable/stop may balance an existing start before the native base stops.
    if (!windowOpen_ || !baseStarted_ || !registered_) return false;
    uint8_t payload[RTWAwdl::NativeEvents::endSize];
    if (!RTWAwdl::NativeEvents::end(wireTime,payload,sizeof(payload))) return false;
    windowOpen_=false;
    retain();
    postMessage(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_EXTENSIONS_END,payload,sizeof(payload),true);
    release();
    return true;
}

bool AirportRTWAwdlInterface::postPeerCacheCompletion(const uint8_t address[6],bool present)
{
    if (!canPostPeerCacheCompletion()) return false;
    uint8_t payload[RTWAwdl::NativeEvents::cacheSize];
    if (!RTWAwdl::NativeEvents::cache(address,present,payload,sizeof(payload))) return false;
    retain();
    postMessage(RTWAwdl::NativeEvents::cacheEvent,payload,sizeof(payload),true);
    release();
    return true; // Handoff only; the native peer manager owns semantic acceptance.
}

bool AirportRTWAwdlInterface::armWindowTimer(uint64_t deadlineUs,uint64_t nowUs)
{
    if (!loop_ || !registered_ || !prepared_ || stopping_) return false;
    if (!windowTimer_) {
        windowTimer_=IOTimerEventSource::timerEventSource(this,windowTimerFired);
        if (!windowTimer_) return false;
        if (loop_->addEventSource(windowTimer_)!=kIOReturnSuccess) {
            auto *timer=windowTimer_;windowTimer_=nullptr;timer->release();return false;
        }
        windowTimerAdded_=true;
    }
    uint64_t delay=deadlineUs>nowUs ? deadlineUs-nowUs : 1;
    if (delay>UINT32_MAX) delay=UINT32_MAX;
    const bool armed=windowTimer_->setTimeoutUS(static_cast<uint32_t>(delay))==kIOReturnSuccess;
    if (!armed) windowTimer_->cancelTimeout();
    return armed;
}

void AirportRTWAwdlInterface::cancelWindowTimer()
{
    if (windowTimer_) windowTimer_->cancelTimeout();
}

void AirportRTWAwdlInterface::releaseWindowTimer()
{
    auto *timer=windowTimer_;
    if (!timer) return;
    windowTimer_=nullptr;
    timer->cancelTimeout();
    if (windowTimerAdded_ && loop_) loop_->removeEventSource(timer);
    windowTimerAdded_=false;
    timer->release();
}

void AirportRTWAwdlInterface::windowTimerFired(OSObject *owner,IOTimerEventSource *timer)
{
    auto *me=static_cast<AirportRTWAwdlInterface *>(owner);
    if (timer!=me->windowTimer_ || !me->enabled_ || me->stopping_ || !me->control_) return;
    timer->retain();me->retain();
    me->control_->timerFired();
    me->release();timer->release();
}

bool AirportRTWAwdlInterface::deliverAction(OSObject *owner, const uint8_t *frame,
    size_t length, const uint8_t *metadata, size_t metadataLength)
{
    auto *me = static_cast<AirportRTWAwdlInterface *>(owner);
    me->retain();
    if(me->enabled_ && !me->stopping_ && me->control_)
        me->control_->observeRadioAction(frame,length,metadata,metadataLength);
    const bool handedOff = me->receiveAction(frame,length,metadata,metadataLength);
    me->release();
    return handedOff;
}

bool AirportRTWAwdlInterface::deliverData(OSObject *owner,const uint8_t *frame,size_t length,
                                          const uint8_t *metadata,size_t metadataLength)
{
    auto *me=static_cast<AirportRTWAwdlInterface *>(owner);me->retain();
    const bool accepted=me->enabled_ && !me->stopping_ && me->control_ &&
        me->control_->receiveRadioData(frame,length,metadata,metadataLength);
    me->release();return accepted;
}

bool AirportRTWAwdlInterface::receiveAction(const uint8_t *frame, size_t length, const uint8_t *metadata, size_t metadataLength)
{
    return enabled_ && !stopping_ && AirportRTWAwdlActionInput::deliver(this,frame,length,metadata,metadataLength);
}

IOReturn AirportRTWAwdlInterface::getSSID(apple80211_ssid_data *payload)
{ return dispatch(AirportRTWAwdl::Request::SSID,false,payload); }
IOReturn AirportRTWAwdlInterface::getCHANNEL(apple80211_channel_data *payload)
{ return dispatch(AirportRTWAwdl::Request::CHANNEL,false,payload); }
IOReturn AirportRTWAwdlInterface::getBSSID(apple80211_bssid_data *payload)
{ return dispatch(AirportRTWAwdl::Request::BSSID,false,payload); }
IOReturn AirportRTWAwdlInterface::getSTATE(apple80211_state_data *payload)
{ return dispatch(AirportRTWAwdl::Request::STATE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_PARAMS,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_ENABLED,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_EXTENSION_STATE_MACHINE_PARAMETERS,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_ELECTION_ID(apple80211_awdl_election_id *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_ID,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_METRIC,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,false,payload); }
IOReturn AirportRTWAwdlInterface::getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *payload)
{ return dispatch(AirportRTWAwdl::Request::PEER_CACHE_MAXIMUM_SIZE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_MASTER_CHANNEL,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_SYNC_STATE(apple80211_awdl_sync_state *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_STATE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_RSSI_THRESHOLDS,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_PRESENCE_MODE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_PARAMS,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_DEVICE_CAPABILITIES(apple80211_awdl_device_capabilities *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_DEVICE_CAPABILITIES,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SECONDARY_MASTER_CHANNEL,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_AF_TX_MODE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_MIN_RATE(apple80211_awdl_min_rate *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_MIN_RATE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ENCRYPTION_TYPE,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_TXCAL_PERIOD,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_DEV_STATS(apple80211_awdl_dev_stats *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_DEV_STATS,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_DFSP_CONFIG,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_CCA(apple80211_awdl_cca *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_CCA,false,payload); }
IOReturn AirportRTWAwdlInterface::getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(apple80211_awdl_cap *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES,false,payload); }
IOReturn AirportRTWAwdlInterface::getLLW_PARAMS(apple80211_llw_params *payload)
{ return dispatch(AirportRTWAwdl::Request::LLW_PARAMS,false,payload); }
IOReturn AirportRTWAwdlInterface::setSSID(apple80211_ssid_data *payload)
{ return dispatch(AirportRTWAwdl::Request::SSID,true,payload); }
IOReturn AirportRTWAwdlInterface::setCHANNEL(apple80211_channel_data *payload)
{ return dispatch(AirportRTWAwdl::Request::CHANNEL,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_PARAMS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_ENABLED,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_EXTENSION_STATE_MACHINE_PARAMETERS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ELECTION_ID(apple80211_awdl_election_id *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_ID,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_BSSID(apple80211_awdl_bssid *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_BSSID,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_METRIC,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_MASTER_CHANNEL,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SYNC_STATE(apple80211_awdl_sync_state *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_STATE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_RSSI_THRESHOLDS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_PRESENCE_MODE,true,payload); }
IOReturn AirportRTWAwdlInterface::setPEER_CACHE_CONTROL(apple80211_peer_cache_control *payload)
{ return dispatch(AirportRTWAwdl::Request::PEER_CACHE_CONTROL,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_OOB_REQUEST,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SYNC_FRAME_TEMPLATE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ELECTION_PARAMS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_PEER_TRAFFIC_REGISTRATION(apple80211_awdl_peer_traffic_registration *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_PEER_TRAFFIC_REGISTRATION,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_SECONDARY_MASTER_CHANNEL,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_AF_TX_MODE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_MIN_RATE(apple80211_awdl_min_rate *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_MIN_RATE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ENCRYPTION_KEYS(apple80211_key *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ENCRYPTION_KEYS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_ENCRYPTION_TYPE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_OOB_AUTO_REQUEST,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_TXCAL_PERIOD,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_AWDL_ADVERTISERS,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_DFSP_CONFIG,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_DFSP_UCSA_CONFIG,true,payload); }
IOReturn AirportRTWAwdlInterface::setCOMPANION_SKYWALK_IF_CREATE(apple80211_companion_skywalk_if_create *payload)
{ return dispatch(AirportRTWAwdl::Request::COMPANION_SKYWALK_IF_CREATE,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_OOB_SEC_PAYLOAD_REQUEST,true,payload); }
IOReturn AirportRTWAwdlInterface::setLLW_PARAMS(apple80211_llw_params *payload)
{ return dispatch(AirportRTWAwdl::Request::LLW_PARAMS,true,payload); }
IOReturn AirportRTWAwdlInterface::setTX_RATE(apple80211_tx_rate *payload)
{ return dispatch(AirportRTWAwdl::Request::TX_RATE,true,payload); }
IOReturn AirportRTWAwdlInterface::setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *payload)
{ return dispatch(AirportRTWAwdl::Request::P2P_COEX_PROTECTION,true,payload); }
IOReturn AirportRTWAwdlInterface::setPSF_DWELL(apple80211_awdl_psf_dwell_params *payload)
{ return dispatch(AirportRTWAwdl::Request::PSF_DWELL,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_CONFIG(apple80211_awdl_config_request *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_CONFIG,true,payload); }
IOReturn AirportRTWAwdlInterface::setAWDL_RTG_PEER_STATS_CONFIG(apple80211_rtg_peer_stats_cfg *payload)
{ return dispatch(AirportRTWAwdl::Request::AWDL_RTG_PEER_STATS_CONFIG,true,payload); }
#endif
