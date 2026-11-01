/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Native queue API research: RTL8814Native, Copyright (c) 2026 DrogaBox (GPL-2.0).
 * Ownership, bounded staging and backpressure implementation are independent.
 */
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include "AirportRTWAwdlDatapath.hpp"
#include <AWDL/RTWAwdlFrame.hpp>
#include <AWDL/RTWAwdlPacketFlow.hpp>

// Nonvirtual exported family APIs. No guessed object/vtable offsets.
extern "C" {
void *rtw_awdl_pool(const char *, OSObject *, uint32_t, const void *)
    __asm__("__ZN25IOSkywalkPacketBufferPool8withNameEPKcP8OSObjectjPKNS_11PoolOptionsE");
void *rtw_awdl_txsub(void *, uint32_t, uint32_t, OSObject *,
    uint32_t (*)(OSObject *, void *, void *const *, uint32_t, void *), void *, uint32_t)
    __asm__("__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PKP15IOSkywalkPacketjPvES9_j");
void *rtw_awdl_txcomp(void *, uint32_t, uint32_t, OSObject *,
    uint32_t (*)(OSObject *, void *, void **, uint32_t, void *), void *, uint32_t)
    __asm__("__ZN26IOSkywalkTxCompletionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PP15IOSkywalkPacketjPvES8_j");
void *rtw_awdl_rxcomp(void *, uint32_t, uint32_t, OSObject *,
    uint32_t (*)(OSObject *, void *, void **, uint32_t, void *), void *, uint32_t)
    __asm__("__ZN26IOSkywalkRxCompletionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PP15IOSkywalkPacketjPvES8_j");
IOReturn rtw_awdl_tx_complete(void *, void *const *, uint32_t, uint32_t)
    __asm__("__ZN26IOSkywalkTxCompletionQueue14enqueuePacketsEPKP15IOSkywalkPacketjj");
IOReturn rtw_awdl_rx_complete(void *, void *const *, uint32_t, uint32_t)
    __asm__("__ZN26IOSkywalkRxCompletionQueue14enqueuePacketsEPKP15IOSkywalkPacketjj");
IOReturn rtw_awdl_allocate(void *, void **, uint32_t)
    __asm__("__ZN25IOSkywalkPacketBufferPool14allocatePacketEPP15IOSkywalkPacketj");
void rtw_awdl_release(void *, void *)
    __asm__("__ZN25IOSkywalkPacketBufferPool16deallocatePacketEP15IOSkywalkPacket");
IOReturn rtw_awdl_prepare(void *, void *, uint64_t, uint32_t)
    __asm__("__ZN15IOSkywalkPacket7prepareEP20IOSkywalkPacketQueueyj");
IOReturn rtw_awdl_set_length(void *, uint16_t, uint32_t)
    __asm__("__ZN15IOSkywalkPacket22setDataOffsetAndLengthEtj");
void rtw_awdl_set_header(void *, uint8_t)
    __asm__("__ZN22IOSkywalkNetworkPacket19setLinkHeaderLengthEh");
uint64_t rtw_awdl_base(const void *)
    __asm__("__ZNK15IOSkywalkPacket21getDataVirtualAddressEv");
uint32_t rtw_awdl_length(const void *)
    __asm__("__ZNK15IOSkywalkPacket13getDataLengthEv");
uint16_t rtw_awdl_offset(const void *)
    __asm__("__ZNK15IOSkywalkPacket13getDataOffsetEv");
uint32_t rtw_awdl_buffer_size(const void *)
    __asm__("__ZNK15IOSkywalkPacket13getBufferSizeEv");
uint32_t rtw_awdl_buffer_count(const void *)
    __asm__("__ZNK15IOSkywalkPacket20getPacketBufferCountEv");
void rtw_awdl_request_dequeue(void *, void *, uint32_t)
    __asm__("__ZN26IOSkywalkTxSubmissionQueue14requestDequeueEPvj");
}

OSDefineMetaClassAndStructors(AirportRTWAwdlDatapath, OSObject)

AirportRTWAwdlDatapath *AirportRTWAwdlDatapath::withWorkLoop(IOWorkLoop *loop, OSObject *owner, Sender sender, ActionReceiver actionReceiver, DataReceiver dataReceiver)
{
    auto *object = new AirportRTWAwdlDatapath;
    if (object && !object->initialize(loop, owner, sender, actionReceiver, dataReceiver)) {
        object->stop(); object->release(); object = nullptr;
    }
    return object;
}

bool AirportRTWAwdlDatapath::initialize(IOWorkLoop *loop, OSObject *owner, Sender sender, ActionReceiver actionReceiver, DataReceiver dataReceiver)
{
    if (!loop || !owner || !sender || !OSObject::init()) return false;
    loop_ = loop; loop_->retain(); senderOwner_ = owner; sender_ = sender;
    rxLock_ = IOSimpleLockAlloc();
    rxRing_ = static_cast<RxSlot *>(IOMalloc(sizeof(RxSlot) * ringCapacity));
    if (!rxLock_ || !rxRing_) return false;
    actionReceiver_ = actionReceiver;
    if (actionReceiver_) {
        actionRing_ = static_cast<ActionSlot *>(IOMalloc(sizeof(ActionSlot) * actionCapacity));
        actionScratch_ = static_cast<ActionSlot *>(IOMalloc(sizeof(ActionSlot)));
        if (!actionRing_ || !actionScratch_) return false;
    }
    dataReceiver_=dataReceiver;
    if(dataReceiver_) {
        dataRing_=static_cast<DataSlot *>(IOMalloc(sizeof(DataSlot)*actionCapacity));
        dataScratch_=static_cast<DataSlot *>(IOMalloc(sizeof(DataSlot)));
        if(!dataRing_ || !dataScratch_)return false;
    }
    return loop_->runAction(createGated, this) == kIOReturnSuccess;
}

IOReturn AirportRTWAwdlDatapath::createGated(OSObject *owner, void *, void *, void *, void *)
{
    auto *me = static_cast<AirportRTWAwdlDatapath *>(owner);
    struct Options {
        uint32_t packets, buffers, size, buffersPerPacket, segmentSize, flags;
        void *dma;
        uint64_t reserved;
    };
    static_assert(sizeof(Options) == 40, "native pool options");
    const Options options {256,256,2048,1,0,1,nullptr,0};
    me->txPool_ = rtw_awdl_pool("AirportRTW.awdl.tx", me, 1, &options);
    me->rxPool_ = rtw_awdl_pool("AirportRTW.awdl.rx", me, 1, &options);
    if (!me->txPool_ || !me->rxPool_) return kIOReturnNoMemory;
    me->queues_[0] = static_cast<IOEventSource *>(rtw_awdl_txsub(me->txPool_,128,0,me,transmit,nullptr,0));
    me->queues_[1] = static_cast<IOEventSource *>(rtw_awdl_txcomp(me->txPool_,128,0,me,completed,nullptr,0));
    me->queues_[2] = static_cast<IOEventSource *>(rtw_awdl_rxcomp(me->rxPool_,128,0,me,completed,nullptr,0));
    for (unsigned i = 0; i < 3; ++i) {
        if (!me->queues_[i]) return kIOReturnNoMemory;
        me->queues_[i]->disable();
        if (me->loop_->addEventSource(me->queues_[i]) != kIOReturnSuccess) return kIOReturnError;
        me->added_[i] = true;
    }
    me->rxSource_ = IOInterruptEventSource::interruptEventSource(me, receiveReady);
    if (!me->rxSource_) return kIOReturnNoMemory;
    me->rxSource_->disable();
    if (me->loop_->addEventSource(me->rxSource_) != kIOReturnSuccess) return kIOReturnError;
    me->rxSourceAdded_ = true;
    return kIOReturnSuccess;
}

bool AirportRTWAwdlDatapath::setEnabled(bool value)
{
    if (!loop_) return false;
    return loop_->runAction(enableGated, this, value ? this : nullptr) == kIOReturnSuccess;
}

IOReturn AirportRTWAwdlDatapath::enableGated(OSObject *owner, void *value, void *, void *, void *)
{
    auto *me = static_cast<AirportRTWAwdlDatapath *>(owner);
    if (value && (!me->rxSourceAdded_ || !me->added_[0] || !me->added_[1] || !me->added_[2]))
        return kIOReturnNotReady;
    me->enabled_ = value != nullptr;
    const IOInterruptState state = IOSimpleLockLockDisableInterrupt(me->rxLock_);
    me->rxEnabled_ = me->enabled_;
    if (!me->enabled_) {
        me->rxCount_ = me->rxRead_ = me->rxWrite_ = 0;
        me->actionCount_ = me->actionRead_ = me->actionWrite_ = 0;
        me->dataCount_=me->dataRead_=me->dataWrite_=0;
    }
    IOSimpleLockUnlockEnableInterrupt(me->rxLock_, state);
    for (auto *queue : me->queues_)
        if (queue) { if (me->enabled_) queue->enable(); else queue->disable(); }
    if (me->rxSource_) { if (me->enabled_) me->rxSource_->enable(); else me->rxSource_->disable(); }
    if (me->enabled_) rtw_awdl_request_dequeue(me->queues_[0],nullptr,0);
    return kIOReturnSuccess;
}

struct AirportRTWAwdlDatapath::TxAdapter {
    AirportRTWAwdlDatapath *me;
    bool enabled() const { return me->enabled_; }
    bool view(void *packet, const uint8_t *&bytes, size_t &length) const {
        if (!packet || rtw_awdl_buffer_count(packet) != 1) return false;
        const uint32_t capacity = rtw_awdl_buffer_size(packet);
        const uint16_t offset = rtw_awdl_offset(packet);
        length = rtw_awdl_length(packet);
        const uint64_t base = rtw_awdl_base(packet);
        if (!RTWAwdl::PacketFlow::validView(1,base,capacity,offset,length)) return false;
        bytes = reinterpret_cast<const uint8_t *>(uintptr_t(base + offset));
        // Invalid/unsupported Ethernet packets are consumed as drops, not
        // reported as radio backpressure which would stall later IPv6 frames.
        return RTWAwdl::DataCodec::validEthernet(bytes,length);
    }
    bool send(const uint8_t *bytes, size_t length) const { return me->sender_(me->senderOwner_,bytes,length); }
    void invalid() const {}
    bool complete(void *const *packets, uint32_t count) const {
        return rtw_awdl_tx_complete(me->queues_[1],packets,count,0) == kIOReturnSuccess;
    }
    void release(void *packet) const { if (packet) rtw_awdl_release(me->txPool_,packet); }
};

uint32_t AirportRTWAwdlDatapath::transmit(OSObject *owner, void *, void *const *packets, uint32_t count, void *)
{
    TxAdapter adapter {static_cast<AirportRTWAwdlDatapath *>(owner)};
    return RTWAwdl::PacketFlow::transmit(adapter,packets,count);
}

uint32_t AirportRTWAwdlDatapath::completed(OSObject *, void *, void **, uint32_t, void *)
{
    // Completion queues perform their own packet completion. No callback-owned
    // packet is taken or freed here.
    return 0;
}

bool AirportRTWAwdlDatapath::receive(const uint8_t *bytes, size_t length)
{
    if (!RTWAwdl::DataCodec::validEthernet(bytes,length) || !rxLock_) return false;
    const IOInterruptState state = IOSimpleLockLockDisableInterrupt(rxLock_);
    bool accepted = rxEnabled_ && rxRing_ && rxSource_ && rxCount_ < ringCapacity;
    if (accepted) {
        RxSlot &slot = rxRing_[rxWrite_];
        slot.length = uint16_t(length); memcpy(slot.bytes,bytes,length);
        rxWrite_ = (rxWrite_ + 1) % ringCapacity; ++rxCount_;
        // This interrupt-safe signal does not enter the workqueue gate.
        rxSource_->interruptOccurred(nullptr,nullptr,0);
    }
    IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
    return accepted;
}

bool AirportRTWAwdlDatapath::queueAction(const uint8_t *frame, size_t length,
                                         const uint8_t *metadata, size_t metadataLength)
{
    RTWAwdl::ActionInfo info;
    if (!rxLock_ || !metadata || metadataLength != 72 || length > 4120 ||
        RTWAwdl::parseFrame(frame,length,info) != RTWAwdl::ParseResult::Valid ||
        (info.subtype != 0 && info.subtype != 3) || (frame[10] & 1) ||
        memcmp(frame+10,metadata,6)) return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= frame[10+i];
    if (!bits) return false;
    const IOInterruptState state = IOSimpleLockLockDisableInterrupt(rxLock_);
    bool accepted = rxEnabled_ && rxSource_ && actionReceiver_ && actionRing_ &&
        actionCount_ < actionCapacity;
    if (accepted) {
        ActionSlot &slot = actionRing_[actionWrite_];
        slot.length = uint16_t(length);
        memcpy(slot.bytes,frame,length); memcpy(slot.metadata,metadata,72);
        actionWrite_ = (actionWrite_ + 1) % actionCapacity; ++actionCount_;
        rxSource_->interruptOccurred(nullptr,nullptr,0);
    }
    IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
    return accepted;
}

bool AirportRTWAwdlDatapath::queueData(const uint8_t *frame,size_t length,
                                       const uint8_t *metadata,size_t metadataLength)
{
    RTWAwdl::DataCodec::View view;
    if (!rxLock_ || !frame || length<24 || length>RTWAwdl::DataCodec::maximumAggregateFrame ||
        !metadata || metadataLength!=72 || memcmp(frame+10,metadata,6) ||
        (!RTWAwdl::DataCodec::inspect(frame,length,view) &&
         !RTWAwdl::DataCodec::validAggregate(frame,length))) return false;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(rxLock_);
    const bool accepted=rxEnabled_ && rxSource_ && dataReceiver_ && dataRing_ && dataCount_<actionCapacity;
    if(accepted) {
        auto &slot=dataRing_[dataWrite_];slot.length=uint16_t(length);
        memcpy(slot.bytes,frame,length);memcpy(slot.metadata,metadata,72);
        dataWrite_=(dataWrite_+1)%actionCapacity;++dataCount_;
        rxSource_->interruptOccurred(nullptr,nullptr,0);
    }
    IOSimpleLockUnlockEnableInterrupt(rxLock_,state);return accepted;
}

void AirportRTWAwdlDatapath::receiveReady(OSObject *owner, IOInterruptEventSource *, int)
{
    auto *me = static_cast<AirportRTWAwdlDatapath *>(owner);
    // A native callback may disable/stop the parent. Keep this object alive
    // until the event completes, including removal of owner-retaining sources.
    me->retain();
    me->drainActions(); // Control/synchronization frames precede bulk data.
    me->drainRadioData();
    me->drainReceive();
    if (me->enabled_ && me->queues_[0]) rtw_awdl_request_dequeue(me->queues_[0],nullptr,0);
    me->release();
}

void AirportRTWAwdlDatapath::drainReceive()
{
    if (!enabled_) return;
    void *packets[32]; uint32_t count = 0;
    // Bounded per callback; arrivals have signaled the source for another pass.
    for (unsigned i = 0; i < ringCapacity; ++i) {
        RxSlot slot;
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(rxLock_);
        const bool present = rxCount_ != 0;
        if (present) {
            const RxSlot &source = rxRing_[rxRead_];
            slot.length = source.length; memcpy(slot.bytes,source.bytes,slot.length);
            rxRead_ = (rxRead_ + 1) % ringCapacity; --rxCount_;
        }
        IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
        if (!present) break;
        void *packet = nullptr;
        if (rtw_awdl_allocate(rxPool_,&packet,1) != kIOReturnSuccess || !packet) continue;
        const bool prepared = rtw_awdl_prepare(packet,nullptr,0,0) == kIOReturnSuccess;
        if (prepared && rtw_awdl_buffer_count(packet) == 1 &&
            rtw_awdl_buffer_size(packet) >= slot.length && rtw_awdl_base(packet)) {
            memcpy(reinterpret_cast<void *>(uintptr_t(rtw_awdl_base(packet))),slot.bytes,slot.length);
            if (rtw_awdl_set_length(packet,0,slot.length) == kIOReturnSuccess) {
                rtw_awdl_set_header(packet,14); packets[count++] = packet; packet = nullptr;
            }
        }
        if (packet) rtw_awdl_release(rxPool_,packet);
        if (count == 32) {
            if (rtw_awdl_rx_complete(queues_[2],packets,count,0) != kIOReturnSuccess)
                for (uint32_t j = 0; j < count; ++j) rtw_awdl_release(rxPool_,packets[j]);
            count = 0;
        }
    }
    if (count && rtw_awdl_rx_complete(queues_[2],packets,count,0) != kIOReturnSuccess)
        for (uint32_t j = 0; j < count; ++j) rtw_awdl_release(rxPool_,packets[j]);
}

void AirportRTWAwdlDatapath::drainActions()
{
    // Heap scratch avoids placing a 4 KiB radio frame above the native parser's
    // stack. No spin/HAL lock is held during native-family calls.
    for (unsigned i = 0; i < actionCapacity && enabled_ && actionReceiver_; ++i) {
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(rxLock_);
        const bool present = actionCount_ && actionRing_ && actionScratch_;
        if (present) {
            const ActionSlot &source = actionRing_[actionRead_];
            actionScratch_->length = source.length;
            memcpy(actionScratch_->bytes,source.bytes,source.length);
            memcpy(actionScratch_->metadata,source.metadata,72);
            actionRead_ = (actionRead_ + 1) % actionCapacity; --actionCount_;
        }
        IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
        if (!present) break;
        actionReceiver_(senderOwner_,actionScratch_->bytes,actionScratch_->length,
                        actionScratch_->metadata,72);
    }
}

void AirportRTWAwdlDatapath::drainRadioData()
{
    for(unsigned i=0;i<actionCapacity && enabled_ && dataReceiver_;++i) {
        const IOInterruptState state=IOSimpleLockLockDisableInterrupt(rxLock_);
        const bool present=dataCount_ && dataRing_ && dataScratch_;
        if(present) {
            const auto &slot=dataRing_[dataRead_];dataScratch_->length=slot.length;
            memcpy(dataScratch_->bytes,slot.bytes,slot.length);memcpy(dataScratch_->metadata,slot.metadata,72);
            dataRead_=(dataRead_+1)%actionCapacity;--dataCount_;
        }
        IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
        if(!present)break;
        dataReceiver_(senderOwner_,dataScratch_->bytes,dataScratch_->length,dataScratch_->metadata,72);
    }
}

void AirportRTWAwdlDatapath::resumeTransmit()
{
    if (!rxLock_) return;
    const IOInterruptState state = IOSimpleLockLockDisableInterrupt(rxLock_);
    if (rxEnabled_ && rxSource_) rxSource_->interruptOccurred(nullptr,nullptr,0);
    IOSimpleLockUnlockEnableInterrupt(rxLock_,state);
}

void AirportRTWAwdlDatapath::stop()
{
    if (loop_) loop_->runAction(stopGated,this);
}

IOReturn AirportRTWAwdlDatapath::stopGated(OSObject *owner, void *, void *, void *, void *)
{
    auto *me = static_cast<AirportRTWAwdlDatapath *>(owner);
    me->enabled_ = false;
    if (me->rxLock_) {
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(me->rxLock_);
        me->rxEnabled_ = false; me->rxCount_ = 0;
        me->actionCount_ = me->actionRead_ = me->actionWrite_ = 0;
        me->dataCount_=me->dataRead_=me->dataWrite_=0;
        IOSimpleLockUnlockEnableInterrupt(me->rxLock_,state);
    }
    if (me->rxSource_) {
        me->rxSource_->disable();
        if (me->rxSourceAdded_) me->loop_->removeEventSource(me->rxSource_);
        me->rxSourceAdded_ = false;
        me->rxSource_->release(); me->rxSource_ = nullptr;
    }
    for (unsigned i = 0; i < 3; ++i) {
        if (!me->queues_[i]) continue;
        me->queues_[i]->disable();
        if (me->added_[i]) me->loop_->removeEventSource(me->queues_[i]);
        me->added_[i] = false; me->queues_[i]->release(); me->queues_[i] = nullptr;
    }
    // Release owner-retaining pools while the caller still owns this object;
    // leaving these until free() could create an owner/pool reference cycle.
    if (me->txPool_) { static_cast<OSObject *>(me->txPool_)->release(); me->txPool_ = nullptr; }
    if (me->rxPool_) { static_cast<OSObject *>(me->rxPool_)->release(); me->rxPool_ = nullptr; }
    return kIOReturnSuccess;
}

void AirportRTWAwdlDatapath::free()
{
    stop();
    if (txPool_) static_cast<OSObject *>(txPool_)->release();
    if (rxPool_) static_cast<OSObject *>(rxPool_)->release();
    if (rxRing_) IOFree(rxRing_,sizeof(RxSlot) * ringCapacity);
    if (actionRing_) IOFree(actionRing_,sizeof(ActionSlot) * actionCapacity);
    if (actionScratch_) IOFree(actionScratch_,sizeof(ActionSlot));
    if(dataRing_)IOFree(dataRing_,sizeof(DataSlot)*actionCapacity);
    if(dataScratch_)IOFree(dataScratch_,sizeof(DataSlot));
    if (rxLock_) IOSimpleLockFree(rxLock_);
    OSSafeReleaseNULL(loop_);
    OSObject::free();
}
#endif
