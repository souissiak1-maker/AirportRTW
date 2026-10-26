/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTWCore88_hpp
#define RTWCore88_hpp

#include <compat.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOTimerEventSource.h>

#include "../RTWCore.hpp"

#include "if_rtw88var.h"
#include "Rtw88LinuxBridge.hpp"

class Rtw88PciTransport;


/*
 * Realtek RTW88 PCIe HAL.  This class deliberately has the same public shape as the
 * Intel HALs.  sc.sc_ic is the sole owner of scan, node, MLME and key state.
 * The imported rtw88/mac80211 objects are used only to operate hardware.
 */
class RTWCore88 : public RTWCore {
    OSDeclareDefaultStructors(RTWCore88)

public:
    static bool rtw88_match(IOPCIDevice *device);
    static bool rtw_match(IOPCIDevice *device) { return rtw88_match(device); }

    bool attach(IOPCIDevice *device) override;
    void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *interface) override;
    IOReturn disable(IONetworkInterface *interface) override;
    void free() override;

    struct ieee80211com *get80211Controller() override { return &sc.sc_ic; }

    int getTxNSS() override;
    bool is5GBandSupport() override;
    const char *getFirmwareName() override;
    const char *getFirmwareCountryCode() override;
    uint32_t getTxQueueSize() override;

    void clearScanningFlags() override;
    IOReturn setMulticastList(IOEthernetAddress *addresses, int count) override;

private:
    /* net80211 -> rtw88 hardware callbacks. */
    static int newstate(struct ieee80211com *, enum ieee80211_state, int);
    static void start(struct _ifnet *);
    static void watchdog(struct _ifnet *);
    static void scanDwellExpired(OSObject *, IOTimerEventSource *);
    static void associationRecoveryExpired(OSObject *, IOTimerEventSource *);
    static void receive(void *, const uint8_t *, size_t, int32_t, uint16_t,
                        bool, bool);
    static void resumeTransmit(void *);
    static int setKey(struct ieee80211com *, struct ieee80211_node *,
                      struct ieee80211_key *);
    static void deleteKey(struct ieee80211com *, struct ieee80211_node *,
                          struct ieee80211_key *);
    static void updateSlot(struct ieee80211com *);
    static void updateEdca(struct ieee80211com *);
    static int ampduRxStart(struct ieee80211com *, struct ieee80211_node *,
                            uint8_t);
    static void ampduRxStop(struct ieee80211com *, struct ieee80211_node *,
                            uint8_t);
    static int ampduTxStart(struct ieee80211com *, struct ieee80211_node *,
                            uint8_t);
    static void ampduTxStop(struct ieee80211com *, struct ieee80211_node *,
                            uint8_t);

    bool attachNet80211();
    void detachNet80211();

    struct rtw88_softc sc {};
    IOPCIDevice *pciDevice {nullptr};
    Rtw88PciTransport *transport {nullptr};
    IOTimerEventSource *scanDwellTimer {nullptr};
    IOTimerEventSource *associationRecoveryTimer {nullptr};
    Rtw88LinuxContext linuxContext {};
    volatile UInt64 scanChannelCount {0};
    volatile UInt64 rawReceiveCount {0};
    volatile UInt64 acceptedReceiveCount {0};
    volatile UInt64 beaconProbeCount {0};
    volatile UInt64 startCallCount {0};
    volatile UInt64 txBackpressureCount {0};
    volatile UInt32 lastReceiveFrequency {0};
    volatile UInt32 lastReceiveSignalRaw {0};
    volatile UInt32 lastAssocResponseLength {0};
    volatile UInt32 lastAssocResponseStatus {0xffff};
    volatile UInt32 lastAssocResponseAid {0};
    volatile UInt32 lastAssocResponseFirstIE {0xffff};
    volatile UInt32 lastAssocResponseFC1 {0};
    volatile UInt32 lastAssocResponseSequence {0};
    volatile UInt32 assocStateBeforeInput {0};
    volatile UInt32 assocStateAfterInput {0};
    volatile UInt32 assocStatusAfterInput {0xffff};
    volatile UInt32 associationRunWatchdogTicks {0};
    volatile UInt32 associationRecoveryPending {0};
    volatile UInt32 associationRecoveryAttempted {0};
    volatile UInt32 associationRecoveryAttemptActive {0};
    volatile UInt64 associationRecoveryTriggerCount {0};
    volatile UInt64 associationRecoveryAttemptCount {0};
    volatile UInt64 associationRecoverySuccessCount {0};
};

#endif /* RTWCore88_hpp */
