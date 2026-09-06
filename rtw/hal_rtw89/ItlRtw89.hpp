/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef ItlRtw89_hpp
#define ItlRtw89_hpp

#include <compat.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOTimerEventSource.h>

#include <HAL/ItlDriverController.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlHalService.hpp>

#include "if_rtw89var.h"
#include "Rtw89LinuxBridge.hpp"

class Rtw89PciTransport;

constexpr int RTW89_MIN_DBM = -100;

/*
 * Realtek RTW89 PCIe HAL.  This class deliberately has the same public shape as the
 * Intel HALs.  sc.sc_ic is the sole owner of scan, node, MLME and key state.
 * The imported rtw89/mac80211 objects are used only to operate hardware.
 */
class ItlRtw89 : public ItlHalService,
                 public ItlDriverInfo,
                 public ItlDriverController {
    OSDeclareDefaultStructors(ItlRtw89)

public:
    static bool rtw89_match(IOPCIDevice *device);

    bool attach(IOPCIDevice *device) override;
    void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *interface) override;
    IOReturn disable(IONetworkInterface *interface) override;
    void free() override;

    struct ieee80211com *get80211Controller() override { return &sc.sc_ic; }
    ItlDriverInfo *getDriverInfo() override { return this; }
    ItlDriverController *getDriverController() override { return this; }

    const char *getFirmwareVersion() override;
    int16_t getBSSNoise() override;
    bool is5GBandSupport() override { return true; }
    int getTxNSS() override { return 2; }
    const char *getFirmwareName() override;
    UInt32 supportedFeatures() override;
    const char *getFirmwareCountryCode() override;
    uint32_t getTxQueueSize() override;

    void clearScanningFlags() override;
    IOReturn setMulticastList(IOEthernetAddress *addresses, int count) override;

private:
    /* net80211 -> rtw89 hardware callbacks. */
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

    struct rtw89_softc sc {};
    IOPCIDevice *pciDevice {nullptr};
    Rtw89PciTransport *transport {nullptr};
    IOTimerEventSource *scanDwellTimer {nullptr};
    IOTimerEventSource *associationRecoveryTimer {nullptr};
    Rtw89LinuxContext linuxContext {};
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

#endif /* ItlRtw89_hpp */
