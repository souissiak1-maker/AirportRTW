/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_DATAPATH_HPP
#define AIRPORTRTW_AWDL_DATAPATH_HPP
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOInterruptEventSource.h>
#include <AWDL/RTWAwdlData.hpp>

// Resource/ownership layer only. The concrete AWDL protocol interface must
// register these queues with the family, attach the radio transport, and then
// enable them. No interface or AWDL capability is published by this object.
class AirportRTWAwdlDatapath : public OSObject {
    OSDeclareDefaultStructors(AirportRTWAwdlDatapath)
public:
    // The sender copies Ethernet bytes into its bounded radio queue on success.
    // False means busy/off-channel: retain native submission queue ownership.
    using Sender = bool (*)(OSObject *, const uint8_t *, size_t);
    // Action metadata must follow the verified native source/channel/RSSI layout.
    // Callback runs on the native workloop; false drops the frame, not retry.
    using ActionReceiver = bool (*)(OSObject *, const uint8_t *, size_t, const uint8_t *, size_t);
    using DataReceiver = ActionReceiver;
    static AirportRTWAwdlDatapath *withWorkLoop(IOWorkLoop *, OSObject *, Sender, ActionReceiver = nullptr, DataReceiver = nullptr);
    bool setEnabled(bool);
    void stop();
    // NAPI-safe bounded copy. No native queue calls or blocking gates here.
    bool receive(const uint8_t *, size_t);
    bool queueAction(const uint8_t *, size_t, const uint8_t *, size_t);
    bool queueData(const uint8_t *, size_t, const uint8_t *, size_t);
    // NAPI-safe signal after radio becomes writable; never enters native gate.
    void resumeTransmit();
    void *txSubmission() const { return queues_[0]; }
    void *txCompletion() const { return queues_[1]; }
    void *rxCompletion() const { return queues_[2]; }
    void *txPool() const { return txPool_; }
    void *rxPool() const { return rxPool_; }
    void free() override;
private:
    struct RxSlot { uint16_t length; uint8_t bytes[14 + RTWAwdl::DataCodec::mtu]; };
    struct ActionSlot { uint16_t length; uint8_t metadata[72]; uint8_t bytes[4120]; };
    struct DataSlot { uint16_t length; uint8_t metadata[72]; uint8_t bytes[RTWAwdl::DataCodec::maximumAggregateFrame]; };
    static constexpr unsigned ringCapacity = 64;
    static constexpr unsigned actionCapacity = 16;
    static IOReturn createGated(OSObject *, void *, void *, void *, void *);
    static IOReturn enableGated(OSObject *, void *, void *, void *, void *);
    static IOReturn stopGated(OSObject *, void *, void *, void *, void *);
    static uint32_t transmit(OSObject *, void *, void *const *, uint32_t, void *);
    static uint32_t completed(OSObject *, void *, void **, uint32_t, void *);
    static void receiveReady(OSObject *, IOInterruptEventSource *, int);
    bool initialize(IOWorkLoop *, OSObject *, Sender, ActionReceiver, DataReceiver);
    void drainReceive();
    void drainActions();
    void drainRadioData();
    struct TxAdapter;
    IOWorkLoop *loop_ {nullptr};
    OSObject *senderOwner_ {nullptr}; // Weak: parent must stop before releasing.
    Sender sender_ {nullptr};
    ActionReceiver actionReceiver_ {nullptr};
    DataReceiver dataReceiver_ {nullptr};
    void *txPool_ {nullptr}, *rxPool_ {nullptr};
    IOEventSource *queues_[3] {};
    bool added_[3] {};
    IOInterruptEventSource *rxSource_ {nullptr};
    bool rxSourceAdded_ {false}, enabled_ {false};
    IOSimpleLock *rxLock_ {nullptr};
    RxSlot *rxRing_ {nullptr};
    ActionSlot *actionRing_ {nullptr}, *actionScratch_ {nullptr};
    unsigned actionRead_ {0}, actionWrite_ {0}, actionCount_ {0};
    DataSlot *dataRing_{nullptr}, *dataScratch_{nullptr};
    unsigned dataRead_{0},dataWrite_{0},dataCount_{0};
    unsigned rxRead_ {0}, rxWrite_ {0}, rxCount_ {0};
    bool rxEnabled_ {false};
};
#endif
#endif
